"""
underpressure – private Blutdruck-App.

Der Server sieht nie Messwerte im Klartext: Werte, Tags, Zeit und Ort werden im Browser
mit einem Schlüssel verschlüsselt, der aus dem Passkey (Face ID, WebAuthn-PRF) abgeleitet wird.
Hier liegen nur verschlüsselte Blöcke, die öffentlichen Passkey-Schlüssel und Sitzungen.

Einzige Ausnahme: Für die Display-Erkennung reicht der Server ein verkleinertes Foto ohne
Metadaten an die Anthropic-API weiter. Das Foto wird dabei weder gespeichert noch geloggt.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

DB_PATH = os.environ.get("UP_DB", "/var/lib/underpressure/underpressure.db")
RP_ID = os.environ.get("UP_RP_ID", "localhost")
ORIGIN = os.environ.get("UP_ORIGIN", "http://localhost:8090")
SETUP_CODE = os.environ.get("UP_SETUP_CODE", "")
API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
MODEL = os.environ.get("UP_MODEL", "claude-haiku-5-5")
SESSION_SECONDS = 12 * 3600
RECOVERY_SECONDS = 15 * 60
COOKIE = "up_session"
SECURE_COOKIE = ORIGIN.startswith("https://")
MAX_BLOB = 64 * 1024
MAX_IMAGE = 6 * 1024 * 1024

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
_lock = threading.Lock()
_challenges = {}  # challenge -> (expires, purpose)
_recovery_fails = []  # Zeitstempel fehlgeschlagener Wiederherstellungsversuche


# ---------- Hilfsfunktionen ----------

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def ub64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with db() as con:
        con.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS credentials(
              id TEXT PRIMARY KEY, public_key BLOB NOT NULL, alg INTEGER NOT NULL,
              sign_count INTEGER NOT NULL DEFAULT 0, wrapped_key TEXT,
              created_at INTEGER NOT NULL, last_used INTEGER);
            CREATE TABLE IF NOT EXISTS vault(
              id INTEGER PRIMARY KEY CHECK(id=1), user_handle TEXT NOT NULL,
              recovery_wrapped TEXT, recovery_auth TEXT, settings TEXT);
            CREATE TABLE IF NOT EXISTS entries(id TEXT PRIMARY KEY, blob TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions(
              token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL, expires INTEGER NOT NULL);
            """
        )
        if not con.execute("SELECT 1 FROM vault").fetchone():
            con.execute("INSERT INTO vault(id, user_handle) VALUES(1, ?)", (b64u(secrets.token_bytes(16)),))


init_db()


def err(status: int, msg: str):
    raise HTTPException(status_code=status, detail=msg)


def new_challenge(purpose: str) -> str:
    c = b64u(secrets.token_bytes(32))
    now = time.time()
    with _lock:
        for k in [k for k, (exp, _) in _challenges.items() if exp < now]:
            del _challenges[k]
        _challenges[c] = (now + 300, purpose)
    return c


def take_challenge(c: str, purpose: str):
    with _lock:
        item = _challenges.pop(c, None)
    if not item or item[0] < time.time() or item[1] != purpose:
        err(400, "Die Anfrage ist abgelaufen. Bitte noch einmal versuchen.")


def session_kind(request: Request):
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    h = sha256(token.encode()).hex()
    with db() as con:
        con.execute("DELETE FROM sessions WHERE expires < ?", (int(time.time()),))
        row = con.execute("SELECT kind FROM sessions WHERE token_hash=?", (h,)).fetchone()
    return row["kind"] if row else None


def require_full(request: Request):
    if session_kind(request) != "full":
        err(401, "Gesperrt. Bitte mit Face ID entsperren.")


def start_session(resp: JSONResponse, kind: str, seconds: int):
    token = secrets.token_urlsafe(32)
    with db() as con:
        con.execute(
            "INSERT INTO sessions(token_hash, kind, expires) VALUES(?,?,?)",
            (sha256(token.encode()).hex(), kind, int(time.time()) + seconds),
        )
    resp.set_cookie(COOKIE, token, max_age=seconds, httponly=True, secure=SECURE_COOKIE,
                    samesite="strict", path="/")


async def body(request: Request, limit: int = MAX_BLOB) -> dict:
    raw = await request.body()
    if len(raw) > limit:
        err(413, "Anfrage zu groß.")
    try:
        data = json.loads(raw or b"{}")
    except ValueError:
        err(400, "Ungültige Anfrage.")
    if not isinstance(data, dict):
        err(400, "Ungültige Anfrage.")
    return data


def check_client_data(client_data_b64: str, typ: str, challenge: str):
    try:
        cd = json.loads(ub64u(client_data_b64))
    except Exception:
        err(400, "Ungültige Passkey-Antwort.")
    if cd.get("type") != typ or cd.get("challenge") != challenge:
        err(400, "Passkey-Antwort passt nicht zur Anfrage.")
    if cd.get("origin") != ORIGIN:
        err(400, "Falsche Adresse für diesen Passkey.")


def check_auth_data(auth_data: bytes) -> int:
    if len(auth_data) < 37 or auth_data[:32] != sha256(RP_ID.encode()):
        err(400, "Passkey gehört zu einer anderen Domain.")
    flags = auth_data[32]
    if not flags & 0x01 or not flags & 0x04:
        err(400, "Face ID wurde nicht bestätigt.")
    return int.from_bytes(auth_data[33:37], "big")


def valid_blob(v) -> str:
    if not isinstance(v, str) or not v.startswith("v1.") or len(v) > MAX_BLOB:
        err(400, "Ungültiger verschlüsselter Datensatz.")
    return v


@app.exception_handler(HTTPException)
async def http_error(_request, exc: HTTPException):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


# ---------- Status ----------

@app.get("/api/state")
def state(request: Request):
    with db() as con:
        n = con.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
        v = con.execute("SELECT recovery_wrapped FROM vault").fetchone()
    return {"registered": n > 0, "vault": bool(v["recovery_wrapped"]), "ocr": bool(API_KEY),
            "session": session_kind(request), "rpId": RP_ID}


# ---------- Passkey registrieren ----------

@app.post("/api/register/options")
async def register_options(request: Request):
    data = await body(request)
    with db() as con:
        n = con.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
        handle = con.execute("SELECT user_handle FROM vault").fetchone()["user_handle"]
        existing = [r["id"] for r in con.execute("SELECT id FROM credentials")]
    kind = session_kind(request)
    if n == 0:
        code = str(data.get("setupCode", "")).strip()
        if not SETUP_CODE or not hmac.compare_digest(code, SETUP_CODE):
            err(403, "Der Einrichtungscode stimmt nicht.")
    elif kind not in ("recovery", "full"):
        err(403, "Ein Passkey ist schon eingerichtet. Zum Ersetzen den Wiederherstellungscode verwenden.")
    return {"challenge": new_challenge("register"), "userId": handle, "rpId": RP_ID, "exclude": existing}


@app.post("/api/register/verify")
async def register_verify(request: Request):
    data = await body(request)
    challenge = str(data.get("challenge", ""))
    take_challenge(challenge, "register")
    with db() as con:
        n = con.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    if n > 0 and session_kind(request) not in ("recovery", "full"):
        err(403, "Nicht erlaubt.")
    check_client_data(data.get("clientDataJSON", ""), "webauthn.create", challenge)
    count = check_auth_data(ub64u(data.get("authenticatorData", "")))
    alg = int(data.get("alg", 0))
    if alg not in (-7, -257):
        err(400, "Dieser Passkey-Typ wird nicht unterstützt.")
    spki = ub64u(data.get("publicKey", ""))
    try:
        serialization.load_der_public_key(spki)
    except Exception:
        err(400, "Öffentlicher Schlüssel ist ungültig.")
    cred_id = str(data.get("credentialId", ""))
    if not cred_id or len(cred_id) > 512:
        err(400, "Ungültige Passkey-ID.")
    with db() as con:
        con.execute(
            "INSERT OR REPLACE INTO credentials(id, public_key, alg, sign_count, created_at) VALUES(?,?,?,?,?)",
            (cred_id, spki, alg, count, int(time.time())),
        )
    return {"ok": True}


# ---------- Entsperren ----------

@app.post("/api/login/options")
def login_options():
    with db() as con:
        ids = [r["id"] for r in con.execute("SELECT id FROM credentials")]
    if not ids:
        err(400, "Noch kein Passkey eingerichtet.")
    return {"challenge": new_challenge("login"), "rpId": RP_ID, "allow": ids}


@app.post("/api/login/verify")
async def login_verify(request: Request):
    data = await body(request)
    challenge = str(data.get("challenge", ""))
    take_challenge(challenge, "login")
    cred_id = str(data.get("credentialId", ""))
    with db() as con:
        row = con.execute("SELECT * FROM credentials WHERE id=?", (cred_id,)).fetchone()
    if not row:
        err(400, "Dieser Passkey ist hier nicht bekannt.")
    check_client_data(data.get("clientDataJSON", ""), "webauthn.get", challenge)
    auth_data = ub64u(data.get("authenticatorData", ""))
    count = check_auth_data(auth_data)
    signed = auth_data + sha256(ub64u(data.get("clientDataJSON", "")))
    sig = ub64u(data.get("signature", ""))
    key = serialization.load_der_public_key(row["public_key"])
    try:
        if row["alg"] == -7:
            key.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        err(400, "Passkey-Signatur ist ungültig.")
    if count and row["sign_count"] and count <= row["sign_count"]:
        err(400, "Passkey-Zähler stimmt nicht. Möglicherweise wurde der Passkey kopiert.")
    with db() as con:
        con.execute("UPDATE credentials SET sign_count=?, last_used=? WHERE id=?",
                    (count, int(time.time()), cred_id))
        v = con.execute("SELECT recovery_wrapped FROM vault").fetchone()
    resp = JSONResponse({"wrappedKey": row["wrapped_key"], "vault": bool(v["recovery_wrapped"])})
    start_session(resp, "full", SESSION_SECONDS)
    return resp


@app.post("/api/logout")
def logout(request: Request):
    token = request.cookies.get(COOKIE)
    if token:
        with db() as con:
            con.execute("DELETE FROM sessions WHERE token_hash=?", (sha256(token.encode()).hex(),))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE, path="/")
    return resp


# ---------- Schlüsselablage (nur verschlüsselt) ----------

@app.put("/api/vault")
async def put_vault(request: Request):
    require_full(request)
    data = await body(request)
    wrapped = valid_blob(data.get("recoveryWrapped"))
    auth = str(data.get("recoveryAuth", ""))
    if len(auth) < 32:
        err(400, "Ungültiger Wiederherstellungsschlüssel.")
    with db() as con:
        con.execute("UPDATE vault SET recovery_wrapped=?, recovery_auth=?",
                    (wrapped, sha256(auth.encode()).hex()))
    return {"ok": True}


@app.put("/api/credentials/{cred_id}/key")
async def put_cred_key(cred_id: str, request: Request):
    require_full(request)
    data = await body(request)
    wrapped = valid_blob(data.get("wrappedKey"))
    with db() as con:
        cur = con.execute("UPDATE credentials SET wrapped_key=? WHERE id=?", (wrapped, cred_id))
    if cur.rowcount != 1:
        err(404, "Passkey nicht gefunden.")
    return {"ok": True}


@app.post("/api/recover")
async def recover(request: Request):
    data = await body(request)
    now = time.time()
    with _lock:
        _recovery_fails[:] = [t for t in _recovery_fails if t > now - 900]
        if len(_recovery_fails) >= 5:
            err(429, "Zu viele Versuche. Bitte in 15 Minuten noch einmal.")
    auth = str(data.get("recoveryAuth", ""))
    with db() as con:
        v = con.execute("SELECT recovery_wrapped, recovery_auth FROM vault").fetchone()
    if not v["recovery_auth"] or not hmac.compare_digest(sha256(auth.encode()).hex(), v["recovery_auth"]):
        with _lock:
            _recovery_fails.append(now)
        err(403, "Der Wiederherstellungscode stimmt nicht.")
    resp = JSONResponse({"recoveryWrapped": v["recovery_wrapped"]})
    start_session(resp, "recovery", RECOVERY_SECONDS)
    return resp


# ---------- Messungen und Einstellungen (verschlüsselt) ----------

@app.get("/api/entries")
def list_entries(request: Request):
    require_full(request)
    with db() as con:
        rows = con.execute("SELECT id, blob FROM entries").fetchall()
    return {"entries": [{"id": r["id"], "blob": r["blob"]} for r in rows]}


@app.put("/api/entries/{entry_id}")
async def put_entry(entry_id: str, request: Request):
    require_full(request)
    if not (8 <= len(entry_id) <= 64) or not entry_id.replace("-", "").isalnum():
        err(400, "Ungültige ID.")
    data = await body(request)
    blob = valid_blob(data.get("blob"))
    with db() as con:
        con.execute("INSERT OR REPLACE INTO entries(id, blob) VALUES(?,?)", (entry_id, blob))
    return {"ok": True}


@app.delete("/api/entries/{entry_id}")
def delete_entry(entry_id: str, request: Request):
    require_full(request)
    with db() as con:
        con.execute("DELETE FROM entries WHERE id=?", (entry_id,))
    return {"ok": True}


@app.get("/api/settings")
def get_settings(request: Request):
    require_full(request)
    with db() as con:
        v = con.execute("SELECT settings FROM vault").fetchone()
    return {"blob": v["settings"]}


@app.put("/api/settings")
async def put_settings(request: Request):
    require_full(request)
    data = await body(request)
    blob = valid_blob(data.get("blob"))
    with db() as con:
        con.execute("UPDATE vault SET settings=?", (blob,))
    return {"ok": True}


@app.get("/api/backup")
def backup(request: Request):
    require_full(request)
    with db() as con:
        v = con.execute("SELECT recovery_wrapped, settings FROM vault").fetchone()
        rows = con.execute("SELECT id, blob FROM entries").fetchall()
    return {"format": "underpressure-backup-v1", "created": int(time.time()),
            "recoveryWrapped": v["recovery_wrapped"], "settings": v["settings"],
            "entries": [{"id": r["id"], "blob": r["blob"]} for r in rows]}


# ---------- Display-Erkennung ----------

OCR_PROMPT = (
    "Auf dem Foto ist das Display eines Blutdruckmessgeräts. Lies den oberen Wert (SYS), "
    "den unteren Wert (DIA) und den Puls ab. Ignoriere Datum, Uhrzeit und Speichernummern auf dem Display. "
    "Antworte ausschließlich mit JSON, ohne weiteren Text: "
    '{"systolisch": Zahl oder null, "diastolisch": Zahl oder null, "puls": Zahl oder null, '
    '"hinweis": "kurzer Hinweis auf Deutsch, falls etwas unsicher oder unlesbar ist, sonst leer"}'
)


def _num(v, lo, hi):
    try:
        n = int(round(float(v)))
    except (TypeError, ValueError):
        return None
    return n if lo <= n <= hi else None


@app.post("/api/ocr")
async def ocr(request: Request):
    require_full(request)
    if not API_KEY:
        err(503, "Die Display-Erkennung ist nicht eingerichtet. Werte bitte eintippen.")
    data = await body(request, MAX_IMAGE)
    image = str(data.get("image", ""))
    if not image or len(image) > MAX_IMAGE:
        err(400, "Kein Foto erhalten.")
    payload = {
        "model": MODEL,
        "max_tokens": 200,
        "messages": [{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": image}},
            {"type": "text", "text": OCR_PROMPT},
        ]}],
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=json.dumps(payload).encode(), method="POST",
        headers={"x-api-key": API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            res = json.loads(r.read())
    except urllib.error.HTTPError as e:
        reason = ""
        try:
            reason = json.loads(e.read()).get("error", {}).get("message", "")
        except Exception:
            pass
        print(f"OCR-API-Fehler {e.code}: {reason}", flush=True)
        err(502, f"Display-Erkennung fehlgeschlagen ({e.code}). {reason}".strip())
    except Exception as e:
        print(f"OCR-Verbindung fehlgeschlagen: {type(e).__name__}: {e}", flush=True)
        err(502, f"Display-Erkennung nicht erreichbar ({type(e).__name__}). Werte bitte eintippen.")
    text = "".join(b.get("text", "") for b in res.get("content", []) if b.get("type") == "text")
    text = text.replace("```json", "").replace("```", "").strip()
    try:
        parsed = json.loads(text[text.index("{"): text.rindex("}") + 1])
    except ValueError:
        err(502, "Die Werte konnten nicht gelesen werden. Bitte eintippen.")
    return {
        "sys": _num(parsed.get("systolisch"), 50, 300),
        "dia": _num(parsed.get("diastolisch"), 30, 200),
        "pulse": _num(parsed.get("puls"), 25, 250),
        "hint": str(parsed.get("hinweis") or "")[:200],
    }
