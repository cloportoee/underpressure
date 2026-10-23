"use strict";
/*
 * underpressure – alles, was mit Klartext zu tun hat, passiert hier im Browser.
 * Schlüsselkette:
 *   Face ID (Passkey, WebAuthn-PRF) -> KEK -> entschlüsselt den Datenschlüssel (DEK)
 *   Wiederherstellungscode          -> KEK -> entschlüsselt denselben DEK (Notfall)
 *   DEK (AES-256-GCM) verschlüsselt jede Messung und die Einstellungen.
 * Der Server bekommt nur verschlüsselte Blöcke.
 */

const $ = (sel, root = document) => root.querySelector(sel);
const app = $("#app");
const enc = new TextEncoder();
const dec = new TextDecoder();
const PRF_SALT = enc.encode("underpressure/prf/v1");
const AUTOLOCK_MS = 5 * 60 * 1000;
const DEFAULT_TAGS = ["Kaffee", "Stress", "Sport", "Wenig Schlaf", "Alkohol", "Salzig gegessen", "Unruhe"];

const S = {
  state: null, dek: null, entries: [], settings: null,
  view: "lock", draft: null, error: "", busy: false,
  pendingRaw: null, newRecoveryCode: null, period: 30, hiddenAt: 0,
};

/* ---------- Kleinkram ---------- */

function b64u(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function ub64u(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const pad = (n) => String(n).padStart(2, "0");
const fmtTime = (d) => `${pad(d.getHours())}:${pad(d.getMinutes())}`;
const fmtDate = (d) => d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit", year: "numeric" });
const fmtDay = (d) => d.toLocaleDateString("de-DE", { weekday: "long", day: "numeric", month: "long" });
const toLocalInput = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
const avg = (a) => (a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : null);

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => (t.hidden = true), 2600);
}

async function api(path, opts = {}) {
  const o = { method: opts.method || (opts.body !== undefined ? "POST" : "GET"), headers: {}, credentials: "same-origin" };
  if (opts.body !== undefined) {
    o.headers["Content-Type"] = "application/json";
    o.body = JSON.stringify(opts.body);
  }
  const r = await fetch(path, o);
  let data = {};
  try { data = await r.json(); } catch (_) { /* leer */ }
  if (r.status === 401 && S.dek) lock("Die Sitzung ist abgelaufen. Bitte neu entsperren.");
  if (!r.ok) throw new Error(data.error || `Serverfehler ${r.status}`);
  return data;
}

/* ---------- Verschlüsselung ---------- */

async function hkdfBase(material) {
  return crypto.subtle.importKey("raw", material, "HKDF", false, ["deriveKey", "deriveBits"]);
}
async function hkdfKey(material, info) {
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: enc.encode(info) },
    await hkdfBase(material), { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function hkdfBits(material, info) {
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: enc.encode(info) }, await hkdfBase(material), 256));
}
async function seal(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
  return `v1.${b64u(iv)}.${b64u(ct)}`;
}
async function unseal(key, blob) {
  const [v, iv, ct] = String(blob).split(".");
  if (v !== "v1") throw new Error("Unbekanntes Datenformat.");
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: ub64u(iv) }, key, ub64u(ct)));
}
const sealJSON = (obj) => seal(S.dek, enc.encode(JSON.stringify(obj)));
const unsealJSON = async (blob) => JSON.parse(dec.decode(await unseal(S.dek, blob)));

/* Wiederherstellungscode: 20 Zufallsbytes als 32 Zeichen Crockford-Base32 */
const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function encodeRecovery(bytes) {
  let bits = 0, val = 0, out = "";
  for (const b of bytes) {
    val = (val << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return out.match(/.{4}/g).join(" ");
}
function decodeRecovery(str) {
  const s = str.toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
  if (s.length !== 32) return null;
  const out = [];
  let bits = 0, val = 0;
  for (const ch of s) {
    const i = B32.indexOf(ch);
    if (i < 0) return null;
    val = ((val << 5) | i) & 0xffff; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}

/* ---------- Face ID / Passkey ---------- */

async function createPasskey(opts) {
  let cred;
  try {
    cred = await navigator.credentials.create({
      publicKey: {
        rp: { id: opts.rpId, name: "underpressure" },
        user: { id: ub64u(opts.userId), name: "underpressure", displayName: "underpressure" },
        challenge: ub64u(opts.challenge),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        excludeCredentials: (opts.exclude || []).map((id) => ({ type: "public-key", id: ub64u(id) })),
        authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
        attestation: "none",
        timeout: 120000,
        extensions: { prf: {} },
      },
    });
  } catch (e) {
    if (e.name === "InvalidStateError") throw new Error("Auf diesem Gerät gibt es den Passkey schon. Entsperre einfach mit Face ID.");
    throw passkeyError(e);
  }
  const ext = cred.getClientExtensionResults();
  if (ext.prf && ext.prf.enabled === false) {
    throw new Error("Dieser Passkey kann keinen Schlüssel liefern. Bitte Safari mit dem iCloud-Schlüsselbund verwenden.");
  }
  const r = cred.response;
  await api("/api/register/verify", {
    body: {
      challenge: opts.challenge, credentialId: b64u(cred.rawId), publicKey: b64u(r.getPublicKey()),
      alg: r.getPublicKeyAlgorithm(), clientDataJSON: b64u(r.clientDataJSON), authenticatorData: b64u(r.getAuthenticatorData()),
    },
  });
}

function passkeyError(e) {
  if (e && e.name === "NotAllowedError") return new Error("Face ID wurde abgebrochen.");
  return e instanceof Error ? e : new Error(String(e));
}

async function unlock() {
  const o = await api("/api/login/options", { body: {} });
  let a;
  try {
    a = await navigator.credentials.get({
      publicKey: {
        challenge: ub64u(o.challenge), rpId: o.rpId, userVerification: "required", timeout: 120000,
        allowCredentials: o.allow.map((id) => ({ type: "public-key", id: ub64u(id) })),
        extensions: { prf: { eval: { first: PRF_SALT } } },
      },
    });
  } catch (e) { throw passkeyError(e); }
  const prf = a.getClientExtensionResults().prf?.results?.first;
  if (!prf) throw new Error("Face ID hat keinen Schlüssel geliefert. Die App braucht Safari ab iOS 18 und einen Passkey im iCloud-Schlüsselbund.");
  const r = a.response;
  const credId = b64u(a.rawId);
  const res = await api("/api/login/verify", {
    body: {
      challenge: o.challenge, credentialId: credId, clientDataJSON: b64u(r.clientDataJSON),
      authenticatorData: b64u(r.authenticatorData), signature: b64u(r.signature),
    },
  });
  const kek = await hkdfKey(new Uint8Array(prf), "underpressure/kek/v1");
  let raw;
  if (res.wrappedKey) {
    try { raw = await unseal(kek, res.wrappedKey); } catch (_) { throw new Error("Der Schlüssel passt nicht zu diesem Passkey."); }
  } else if (S.pendingRaw) {
    raw = S.pendingRaw;
    await api(`/api/credentials/${credId}/key`, { method: "PUT", body: { wrappedKey: await seal(kek, raw) } });
  } else if (!res.vault) {
    // Erste Einrichtung: Datenschlüssel und Wiederherstellungscode erzeugen
    raw = crypto.getRandomValues(new Uint8Array(32));
    const code = crypto.getRandomValues(new Uint8Array(20));
    const rk = await hkdfKey(code, "underpressure/recovery-kek/v1");
    const auth = b64u(await hkdfBits(code, "underpressure/recovery-auth/v1"));
    await api(`/api/credentials/${credId}/key`, { method: "PUT", body: { wrappedKey: await seal(kek, raw) } });
    await api("/api/vault", { method: "PUT", body: { recoveryWrapped: await seal(rk, raw), recoveryAuth: auth } });
    S.newRecoveryCode = encodeRecovery(code);
  } else {
    throw new Error("Für diesen Passkey ist kein Schlüssel hinterlegt. Bitte den Wiederherstellungscode verwenden.");
  }
  S.dek = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  raw.fill(0);
  S.pendingRaw = null;
  S.typed = "";
  await loadData();
}

async function setup(code) {
  const o = await api("/api/register/options", { body: { setupCode: code } });
  await createPasskey(o);
  await unlock();
}

async function recover(codeStr) {
  const bytes = decodeRecovery(codeStr);
  if (!bytes) throw new Error("Der Code hat 32 Zeichen. Bitte noch einmal prüfen.");
  const auth = b64u(await hkdfBits(bytes, "underpressure/recovery-auth/v1"));
  const res = await api("/api/recover", { body: { recoveryAuth: auth } });
  const rk = await hkdfKey(bytes, "underpressure/recovery-kek/v1");
  S.pendingRaw = await unseal(rk, res.recoveryWrapped);
  const o = await api("/api/register/options", { body: {} });
  await createPasskey(o);
  await unlock();
}

function lock(msg) {
  S.dek = null; S.entries = []; S.settings = null; S.draft = null;
  S.view = "lock"; S.error = msg || "";
  fetch("/api/logout", { method: "POST", credentials: "same-origin" }).catch(() => {});
  render();
}

/* ---------- Daten ---------- */

async function loadData() {
  const [e, s] = await Promise.all([api("/api/entries"), api("/api/settings")]);
  const list = [];
  for (const x of e.entries) {
    try { const d = await unsealJSON(x.blob); d.id = x.id; list.push(d); } catch (_) { /* nicht lesbar, überspringen */ }
  }
  S.entries = list.sort((a, b) => new Date(b.takenAt) - new Date(a.takenAt));
  S.settings = Object.assign({ tags: DEFAULT_TAGS.slice(), location: true, name: "" }, s.blob ? await unsealJSON(s.blob) : {});
}

async function saveEntry(e) {
  const id = e.id || crypto.randomUUID();
  const data = { v: 1, sys: e.sys, dia: e.dia, pulse: e.pulse, takenAt: e.takenAt, timeSource: e.timeSource,
    lat: e.lat ?? null, lon: e.lon ?? null, locSource: e.locSource || null, tags: e.tags || [], note: e.note || "" };
  await api(`/api/entries/${id}`, { method: "PUT", body: { blob: await sealJSON(data) } });
  data.id = id;
  S.entries = S.entries.filter((x) => x.id !== id).concat(data).sort((a, b) => new Date(b.takenAt) - new Date(a.takenAt));
  return data;
}

async function saveSettings() {
  await api("/api/settings", { method: "PUT", body: { blob: await sealJSON(S.settings) } });
}

function level(e) {
  if (e.sys >= 180 || e.dia >= 110) return "crit";
  if (e.sys >= 135 || e.dia >= 85) return "warn";
  return "ok";
}
const VERDICT = {
  ok: "Im Zielbereich für zu Hause (unter 135/85)",
  warn: "Über dem Zielwert für zu Hause (135/85)",
  crit: "Sehr hoch (ab 180/110)",
};
const slot = (d) => { const h = d.getHours(); return h >= 4 && h < 12 ? "morgens" : h >= 17 ? "abends" : "tags"; };

function inPeriod(days) {
  const from = Date.now() - days * 864e5;
  return S.entries.filter((e) => new Date(e.takenAt).getTime() >= from);
}

function stats(list) {
  const pair = (l) => (l.length ? `${avg(l.map((e) => e.sys))}/${avg(l.map((e) => e.dia))}` : "–");
  const morning = list.filter((e) => slot(new Date(e.takenAt)) === "morgens");
  const evening = list.filter((e) => slot(new Date(e.takenAt)) === "abends");
  const top = list.reduce((m, e) => (!m || e.sys > m.sys ? e : m), null);
  const over = list.filter((e) => level(e) !== "ok").length;
  return {
    n: list.length, all: pair(list), morning: pair(morning), evening: pair(evening),
    nMorning: morning.length, nEvening: evening.length,
    top: top ? `${top.sys}/${top.dia}` : "–", topDate: top ? new Date(top.takenAt) : null,
    over: list.length ? Math.round((over / list.length) * 100) : null,
    pulse: avg(list.filter((e) => e.pulse).map((e) => e.pulse)),
  };
}

function tagEffects(list) {
  const tags = new Set();
  list.forEach((e) => (e.tags || []).forEach((t) => tags.add(t)));
  const rows = [];
  for (const t of tags) {
    const w = list.filter((e) => (e.tags || []).includes(t));
    const wo = list.filter((e) => !(e.tags || []).includes(t));
    if (w.length < 3 || wo.length < 3) continue;
    const a = avg(w.map((e) => e.sys)), b = avg(wo.map((e) => e.sys));
    const c = avg(w.map((e) => e.dia)), d = avg(wo.map((e) => e.dia));
    rows.push({ tag: t, n: w.length, with: `${a}/${c}`, without: `${b}/${d}`, diff: a - b });
  }
  return rows.sort((x, y) => Math.abs(y.diff) - Math.abs(x.diff));
}

/* ---------- Foto: Metadaten und Verkleinerung ---------- */

function readExif(buf) {
  try {
    const v = new DataView(buf);
    if (v.getUint16(0) !== 0xffd8) return {};
    let o = 2;
    while (o < v.byteLength - 10) {
      const marker = v.getUint16(o);
      if ((marker & 0xff00) !== 0xff00) break;
      const len = v.getUint16(o + 2);
      if (marker === 0xffe1 && v.getUint32(o + 4) === 0x45786966) return parseTiff(v, o + 10);
      if (marker === 0xffda) break;
      o += 2 + len;
    }
  } catch (_) { /* keine verwertbaren Metadaten */ }
  return {};
}

function parseTiff(v, t) {
  const le = v.getUint16(t) === 0x4949;
  const u16 = (p) => v.getUint16(p, le);
  const u32 = (p) => v.getUint32(p, le);
  const ifd = (off) => {
    const tags = {};
    const p = t + off;
    const n = u16(p);
    for (let i = 0; i < n; i++) {
      const e = p + 2 + i * 12;
      tags[u16(e)] = { count: u32(e + 4), at: e + 8 };
    }
    return tags;
  };
  const str = (tag) => {
    const p = tag.count > 4 ? t + u32(tag.at) : tag.at;
    let s = "";
    for (let i = 0; i < tag.count; i++) { const c = v.getUint8(p + i); if (!c) break; s += String.fromCharCode(c); }
    return s;
  };
  const rats = (tag) => {
    const p = t + u32(tag.at);
    const out = [];
    for (let i = 0; i < tag.count; i++) out.push(u32(p + i * 8) / (u32(p + i * 8 + 4) || 1));
    return out;
  };
  const out = {};
  const i0 = ifd(u32(t + 4));
  if (i0[0x8769]) {
    const ex = ifd(u32(i0[0x8769].at));
    const dt = ex[0x9003] || ex[0x9004];
    if (dt) out.date = str(dt);
    if (ex[0x9011]) out.offset = str(ex[0x9011]);
  }
  if (!out.date && i0[0x0132]) out.date = str(i0[0x0132]);
  if (i0[0x8825]) {
    const g = ifd(u32(i0[0x8825].at));
    if (g[2] && g[4]) {
      const la = rats(g[2]), lo = rats(g[4]);
      let lat = la[0] + la[1] / 60 + la[2] / 3600;
      let lon = lo[0] + lo[1] / 60 + lo[2] / 3600;
      if (g[1] && str(g[1]) === "S") lat = -lat;
      if (g[3] && str(g[3]) === "W") lon = -lon;
      if (isFinite(lat) && isFinite(lon) && (lat || lon)) { out.lat = lat; out.lon = lon; }
    }
  }
  return out;
}

function exifDate(x) {
  const m = /^(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})/.exec(x.date || "");
  if (!m) return null;
  const off = /^[+-]\d{2}:\d{2}$/.test(x.offset || "") ? x.offset : "";
  const d = new Date(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${off}`);
  return isNaN(d) ? null : d;
}

async function shrink(file) {
  const url = URL.createObjectURL(file);
  try {
    const img = await new Promise((res, rej) => {
      const i = new Image();
      i.onload = () => res(i);
      i.onerror = () => rej(new Error("Das Foto konnte nicht geöffnet werden."));
      i.src = url;
    });
    const k = Math.min(1, 1400 / Math.max(img.naturalWidth, img.naturalHeight));
    const c = document.createElement("canvas");
    c.width = Math.round(img.naturalWidth * k);
    c.height = Math.round(img.naturalHeight * k);
    c.getContext("2d").drawImage(img, 0, 0, c.width, c.height);
    return c.toDataURL("image/jpeg", 0.85); // neu kodiert, damit ohne Metadaten
  } finally {
    URL.revokeObjectURL(url);
  }
}

function currentPosition() {
  return new Promise((res) => {
    if (!navigator.geolocation) return res(null);
    navigator.geolocation.getCurrentPosition(
      (p) => res({ lat: p.coords.latitude, lon: p.coords.longitude }),
      () => res(null), { timeout: 8000, maximumAge: 120000, enableHighAccuracy: false });
  });
}

async function onPhoto(file) {
  if (!file) return;
  const exif = readExif(await file.arrayBuffer());
  const when = exifDate(exif);
  S.draft = {
    sys: null, dia: null, pulse: null, tags: [], note: "",
    takenAt: (when || new Date()).toISOString(), timeSource: when ? "foto" : "jetzt",
    lat: exif.lat ?? null, lon: exif.lon ?? null, locSource: exif.lat != null ? "foto" : null,
    photo: null, status: "Foto wird vorbereitet …",
  };
  S.view = "capture";
  render();
  try {
    S.draft.photo = await shrink(file);
  } catch (e) {
    S.draft.status = e.message;
    render();
    return;
  }
  if (S.draft.lat == null && S.settings.location) {
    currentPosition().then((p) => {
      if (p && S.draft && S.draft.lat == null) { Object.assign(S.draft, p, { locSource: "gerät" }); updateLocation(); }
    });
  }
  if (!S.state.ocr) {
    S.draft.status = "Display-Erkennung ist nicht eingerichtet. Bitte Werte eintippen.";
    render();
    return;
  }
  S.draft.status = "Werte werden vom Display gelesen …";
  render();
  const draft = S.draft;
  try {
    const r = await api("/api/ocr", { body: { image: draft.photo.split(",")[1] } });
    if (S.draft !== draft) return;
    readInputs();
    for (const k of ["sys", "dia", "pulse"]) if (draft[k] == null && r[k] != null) draft[k] = r[k];
    draft.status = r.sys && r.dia ? "Erkannt. Bitte mit dem Display vergleichen." : "Nicht alle Werte erkannt. Bitte ergänzen.";
    draft.hint = r.hint || "";
  } catch (e) {
    if (S.draft !== draft) return;
    readInputs();
    draft.status = e.message;
  }
  render();
}

function manualEntry() {
  S.draft = { sys: null, dia: null, pulse: null, tags: [], note: "", takenAt: new Date().toISOString(),
    timeSource: "jetzt", lat: null, lon: null, locSource: null, photo: null, status: "" };
  S.view = "capture";
  render();
  if (S.settings.location) {
    currentPosition().then((p) => {
      if (p && S.draft && S.draft.lat == null) { Object.assign(S.draft, p, { locSource: "gerät" }); updateLocation(); }
    });
  }
}

function readInputs() {
  if (S.view !== "capture" || !S.draft) return;
  const num = (id) => { const v = parseInt(($(`#${id}`)?.value || "").replace(/\D/g, ""), 10); return isNaN(v) ? null : v; };
  S.draft.sys = num("in-sys");
  S.draft.dia = num("in-dia");
  S.draft.pulse = num("in-pulse");
  const t = $("#in-time")?.value;
  if (t) {
    const d = new Date(t);
    if (!isNaN(d) && toLocalInput(d) !== toLocalInput(new Date(S.draft.takenAt))) { S.draft.takenAt = d.toISOString(); S.draft.timeSource = "manuell"; }
  }
  S.draft.note = $("#in-note")?.value || "";
}

/* ---------- Ansichten ---------- */

function lcd(e, fresh) {
  const ghost = (n) => "8".repeat(n);
  const num = (v, n, cls) => `<div class="lcd-num ${cls}" data-ghost="${ghost(n)}"><span>${v ?? ghost(n)}</span></div>`;
  const d = e ? new Date(e.takenAt) : null;
  return `<div class="lcd${e ? "" : " empty"}${fresh ? " fresh" : ""}" role="img" aria-label="${e ? `Letzte Messung ${e.sys} zu ${e.dia}, Puls ${e.pulse ?? "unbekannt"}` : "Noch keine Messung"}">
    <div class="lcd-row"><div class="lcd-label">SYS<br>mmHg</div>${num(e?.sys, 3, "lcd-big")}</div>
    <div class="lcd-row"><div class="lcd-label">DIA<br>mmHg</div>${num(e?.dia, 3, "lcd-mid")}</div>
    <div class="lcd-row"><div class="lcd-label">PULS<br>/min</div>${num(e?.pulse, 3, "lcd-small")}</div>
    <div class="lcd-foot"><span>${d ? fmtDay(d) : "Noch keine Messung"}</span><span>${d ? fmtTime(d) : ""}</span></div>
  </div>`;
}

function chart(list, days) {
  const W = 600, H = 230, L = 34, R = 10, T = 12, B = 26;
  const pts = list.slice().sort((a, b) => new Date(a.takenAt) - new Date(b.takenAt));
  const end = Date.now(), start = end - days * 864e5;
  const maxV = Math.max(190, ...pts.map((e) => e.sys + 10));
  const minV = Math.min(50, ...pts.map((e) => e.dia - 10));
  const x = (t) => L + ((t - start) / (end - start)) * (W - L - R);
  const y = (v) => T + (1 - (v - minV) / (maxV - minV)) * (H - T - B);
  const ref = [85, 135, 180].map((v) =>
    `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line)" stroke-dasharray="${v === 180 ? "2 4" : "6 5"}"/>
     <text x="${L - 6}" y="${y(v) + 4}" text-anchor="end">${v}</text>`).join("");
  const line = (k, color) => {
    if (!pts.length) return "";
    const p = pts.map((e) => `${x(new Date(e.takenAt)).toFixed(1)},${y(e[k]).toFixed(1)}`);
    return `<polyline points="${p.join(" ")}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round"/>` +
      p.map((c) => { const [cx, cy] = c.split(","); return `<circle cx="${cx}" cy="${cy}" r="3" fill="${color}"/>`; }).join("");
  };
  const lab = [start, (start + end) / 2, end].map((t, i) =>
    `<text x="${x(t)}" y="${H - 8}" text-anchor="${["start", "middle", "end"][i]}">${new Date(t).toLocaleDateString("de-DE", { day: "numeric", month: "short" })}</text>`).join("");
  const empty = pts.length ? "" : `<text x="${W / 2}" y="${H / 2}" text-anchor="middle">Noch keine Messungen in diesem Zeitraum</text>`;
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Verlauf der Blutdruckwerte">${ref}${line("dia", "var(--dia)")}${line("sys", "var(--sys)")}${lab}${empty}</svg>
    <div class="legend"><span><i style="background:var(--sys)"></i>oberer Wert</span><span><i style="background:var(--dia)"></i>unterer Wert</span><span>Grenzlinien 85, 135, 180</span></div>`;
}

function statGrid(s) {
  return `<div class="stats">
    <div class="stat"><b>${s.morning}</b><small>morgens (${s.nMorning}×)</small></div>
    <div class="stat"><b>${s.evening}</b><small>abends (${s.nEvening}×)</small></div>
    <div class="stat"><b>${s.all}</b><small>Mittelwert aus ${s.n} Messungen</small></div>
    <div class="stat"><b>${s.top}</b><small>höchster Wert${s.topDate ? `, ${fmtDate(s.topDate)}` : ""}</small></div>
  </div>`;
}

function viewLock() {
  const st = S.state;
  const supported = window.PublicKeyCredential && navigator.credentials;
  let body;
  if (!supported) {
    body = `<p>Dieser Browser kann keine Passkeys. Bitte die Seite in Safari auf dem iPhone öffnen.</p>`;
  } else if (S.view === "recover") {
    body = `<h2>Wiederherstellen</h2>
      <p>Mit dem Wiederherstellungscode richtest du Face ID auf diesem Gerät neu ein. Deine Messungen bleiben erhalten.</p>
      <div class="field"><label for="in-code">Wiederherstellungscode</label>
      <input id="in-code" type="text" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX" value="${esc(S.typed || "")}"></div>
      <div class="actions"><button class="primary" data-act="recover" ${S.busy ? "disabled" : ""}>Face ID neu einrichten</button>
      <button class="link" data-act="to-lock">Zurück</button></div>`;
  } else if (!st.registered) {
    body = `<p>Richte Face ID ein. Daraus entsteht der Schlüssel, mit dem deine Werte verschlüsselt werden. Nur dein Gerät kann sie lesen.</p>
      <div class="field"><label for="in-setup">Einrichtungscode vom Server</label>
      <input id="in-setup" type="text" autocomplete="off" autocapitalize="off" spellcheck="false" value="${esc(S.typed || "")}"></div>
      <div class="actions"><button class="primary" data-act="setup" ${S.busy ? "disabled" : ""}>Mit Face ID einrichten</button></div>`;
  } else {
    body = `<div class="actions"><button class="primary" data-act="unlock" ${S.busy ? "disabled" : ""}>Mit Face ID entsperren</button>
      <button class="link" data-act="to-recover">Wiederherstellungscode verwenden</button></div>`;
  }
  return `<div class="lock">
    <div class="wordmark">underpressure</div>
    ${lcd(null)}
    ${body}
    ${S.error ? `<p class="status hint" role="alert">${esc(S.error)}</p>` : ""}
  </div>`;
}

function viewRecoveryCode() {
  return `<h1>Dein Wiederherstellungscode</h1>
    <p style="margin-top:12px">Wenn Face ID oder dein iCloud-Schlüsselbund einmal nicht verfügbar sind, kommst du nur mit diesem Code wieder an deine Messungen. Niemand sonst kann ihn dir zurückgeben.</p>
    <div class="code">${esc(S.newRecoveryCode)}</div>
    <p class="muted" style="margin-top:10px">Schreib ihn ab oder druck ihn aus und bewahre ihn an einem sicheren Ort auf. Nicht als Foto in der Mediathek speichern.</p>
    <div class="field"><label class="check"><input id="in-saved" type="checkbox"> Ich habe den Code sicher aufbewahrt.</label></div>
    <div class="actions"><button class="primary" data-act="code-done">Weiter</button></div>`;
}

function viewHome() {
  const last = S.entries[0];
  const week = stats(inPeriod(7));
  return `<div class="topbar"><div class="wordmark">underpressure</div><button class="link" data-act="lock">Sperren</button></div>
    ${lcd(last, S.fresh)}
    ${last ? `<p class="verdict ${level(last)}">${VERDICT[level(last)]}</p>` : `<p class="verdict">Mach ein Foto vom Display deines Messgeräts.</p>`}
    <div class="actions">
      <button class="primary" data-act="camera">Messung fotografieren</button>
      <button class="secondary" data-act="manual">Werte eintippen</button>
      <button class="link" data-act="library">Foto aus der Mediathek wählen</button>
    </div>
    <section><h2>Letzte 7 Tage</h2>${statGrid(week)}</section>
    <section><h2>Letzte 30 Tage</h2>${chart(inPeriod(30), 30)}</section>`;
}

function viewCapture() {
  const d = S.draft;
  const when = new Date(d.takenAt);
  const timeNote = { foto: "Aus dem Foto übernommen.", jetzt: "Zeitpunkt der Eingabe.", manuell: "Von dir geändert." }[d.timeSource] || "";
  const tags = Array.from(new Set([...(S.settings.tags || []), ...(d.tags || [])]));
  return `<div class="topbar"><button class="link" data-act="cancel">Verwerfen</button>${d.id ? `<button class="link danger" data-act="delete">Löschen</button>` : ""}</div>
    <h1>${d.id ? "Messung bearbeiten" : "Neue Messung"}</h1>
    ${d.photo ? `<img class="photo" src="${d.photo}" alt="Foto vom Display" style="margin-top:14px">` : ""}
    ${d.status ? `<p class="status">${esc(d.status)}</p>` : ""}
    ${d.hint ? `<p class="hint">${esc(d.hint)}</p>` : ""}
    <div class="values field">
      <div><label for="in-sys">SYS</label><input id="in-sys" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="3" value="${d.sys ?? ""}"></div>
      <div><label for="in-dia">DIA</label><input id="in-dia" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="3" value="${d.dia ?? ""}"></div>
      <div><label for="in-pulse">Puls</label><input id="in-pulse" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="3" value="${d.pulse ?? ""}"></div>
    </div>
    <div class="field"><label for="in-time">Zeitpunkt</label><input id="in-time" type="datetime-local" value="${toLocalInput(when)}"><small>${timeNote}</small></div>
    <div class="field"><label>Ort</label><p id="loc" class="muted">${locationText(d)}</p></div>
    <div class="field"><label>Was trifft gerade zu?</label><div class="chips">
      ${tags.map((t) => `<button class="chip" data-act="tag" data-tag="${esc(t)}" aria-pressed="${d.tags.includes(t)}">${esc(t)}</button>`).join("")}
    </div></div>
    <div class="field"><label for="in-note">Notiz</label><textarea id="in-note">${esc(d.note)}</textarea></div>
    <div class="actions"><button class="primary" data-act="save" ${S.busy ? "disabled" : ""}>Messung speichern</button></div>`;
}

function locationText(d) {
  if (d.lat == null) return S.settings.location ? "Kein Ort im Foto. Gerätestandort wird abgefragt …" : "Ohne Ort.";
  const src = d.locSource === "foto" ? "aus dem Foto" : "vom Gerät";
  const link = `https://www.openstreetmap.org/?mlat=${d.lat.toFixed(5)}&mlon=${d.lon.toFixed(5)}#map=15/${d.lat.toFixed(5)}/${d.lon.toFixed(5)}`;
  return `${d.lat.toFixed(4)}, ${d.lon.toFixed(4)} (${src})<br><a href="${link}" target="_blank" rel="noopener">Auf der Karte zeigen</a><br><button class="link" data-act="drop-loc">Ort entfernen</button>`;
}
function updateLocation() { const el = $("#loc"); if (el && S.draft) el.innerHTML = locationText(S.draft); }

function viewAlert() {
  const e = S.alertEntry;
  return `<h1>${e.sys}/${e.dia}</h1>
    <div class="alert" role="alert">
      <h2>Sehr hoher Blutdruck</h2>
      <p>Setz dich hin, atme ruhig und miss in 5 Minuten noch einmal.</p>
      <p><b>Ruf sofort die 112</b>, wenn eines davon dazukommt:</p>
      <ul><li>Brustschmerzen oder Engegefühl</li><li>Atemnot</li><li>starke Kopfschmerzen</li><li>Sehstörungen</li>
      <li>Lähmung, Taubheit oder Sprachprobleme</li><li>Verwirrtheit</li></ul>
      <p>Ohne diese Beschwerden: heute noch die Hausarztpraxis oder den ärztlichen Bereitschaftsdienst unter 116 117 anrufen.</p>
    </div>
    <div class="actions"><button class="primary" data-act="camera">Noch einmal messen</button>
    <button class="secondary" data-act="nav" data-view="home">Zur Übersicht</button></div>`;
}

function viewHistory() {
  if (!S.entries.length) return `<h1>Verlauf</h1><p style="margin-top:12px">Noch keine Messungen. Deine erste Messung erscheint hier.</p>
    <div class="actions"><button class="primary" data-act="camera">Messung fotografieren</button></div>`;
  const groups = new Map();
  for (const e of S.entries) {
    const d = new Date(e.takenAt);
    const k = d.toDateString();
    if (!groups.has(k)) groups.set(k, { d, items: [] });
    groups.get(k).items.push(e);
  }
  let html = `<h1>Verlauf</h1>`;
  for (const { d, items } of groups.values()) {
    html += `<div class="day"><h3>${fmtDay(d)}</h3>` + items.map((e) => {
      const meta = [...(e.tags || []), e.note].filter(Boolean).join(", ");
      return `<button class="entry" data-act="edit" data-id="${e.id}">
        <span class="time">${fmtTime(new Date(e.takenAt))}</span>
        <span><span class="bp ${level(e)}">${e.sys}/${e.dia}</span>${meta ? `<br><span class="meta">${esc(meta)}</span>` : ""}</span>
        <span class="pulse">${e.pulse ? `♥ ${e.pulse}` : ""}</span></button>`;
    }).join("") + `</div>`;
  }
  return html;
}

function pdfButtons(list) {
  if (!list.length) return `<button class="primary" disabled>Als PDF sichern</button>`;
  const p = S.pdf;
  if (p?.error) return `<button class="primary" disabled>PDF konnte nicht erstellt werden</button>`;
  if (!p?.file) return `<button class="primary" disabled>PDF wird vorbereitet …</button>`;
  return `<button class="primary" data-act="print">Als PDF sichern oder senden</button>
      <a class="button secondary" style="text-align:center;text-decoration:none;box-sizing:border-box" href="${p.url}" target="_blank" rel="noopener" download="${p.name}">PDF öffnen</a>
      <small>Im Teilen-Menü „In Dateien sichern“ wählen oder direkt per Mail an die Praxis schicken.</small>`;
}

function viewReport() {
  const days = S.period;
  const list = inPeriod(days);
  const s = stats(list);
  const fx = tagEffects(list);
  const from = new Date(Date.now() - days * 864e5);
  const rows = list.map((e) => {
    const d = new Date(e.takenAt);
    return `<tr><td>${fmtDate(d)}</td><td>${fmtTime(d)}</td><td>${e.sys}</td><td>${e.dia}</td><td>${e.pulse ?? ""}</td><td>${esc([...(e.tags || []), e.note].filter(Boolean).join(", "))}</td></tr>`;
  }).join("");
  return `<div class="no-print">
      <h1>Bericht</h1>
      <div class="field"><label for="in-period">Zeitraum</label><select id="in-period">
        ${[7, 14, 30, 90].map((n) => `<option value="${n}" ${n === days ? "selected" : ""}>Letzte ${n} Tage</option>`).join("")}
      </select></div>
      <div class="actions">${pdfButtons(list)}</div>
    </div>
    <div class="print-only">
      <h1>Blutdruckprotokoll${S.settings.name ? ` – ${esc(S.settings.name)}` : ""}</h1>
      <p>Selbstmessung zu Hause, ${fmtDate(from)} bis ${fmtDate(new Date())}. Erstellt am ${fmtDate(new Date())}.</p>
    </div>
    <section><h2>Übersicht</h2>${statGrid(s)}
      <p class="muted" style="margin-top:10px">${s.n ? `${s.over} % der Messungen ab 135/85.${s.pulse ? ` Puls im Mittel ${s.pulse}/min.` : ""} Morgens: 4 bis 12 Uhr, abends: ab 17 Uhr.` : "Keine Messungen in diesem Zeitraum."}</p></section>
    <section><h2>Verlauf</h2>${chart(list, days)}</section>
    ${fx.length ? `<section><h2>Mit und ohne Markierung</h2><div class="table-wrap"><table>
      <tr><th>Markierung</th><th>mit</th><th>ohne</th><th>Unterschied oben</th></tr>
      ${fx.map((r) => `<tr><td>${esc(r.tag)} (${r.n}×)</td><td>${r.with}</td><td>${r.without}</td><td>${r.diff > 0 ? "+" : ""}${r.diff}</td></tr>`).join("")}
      </table></div><p class="muted" style="margin-top:8px">Mittelwerte; berücksichtigt ab 3 Messungen mit und ohne Markierung.</p></section>` : ""}
    <section><h2>Alle Messungen</h2>${list.length ? `<div class="table-wrap"><table>
      <tr><th>Datum</th><th>Uhrzeit</th><th>SYS</th><th>DIA</th><th>Puls</th><th>Markierungen, Notiz</th></tr>${rows}</table></div>` : `<p>Keine Messungen in diesem Zeitraum.</p>`}
      <p class="muted" style="margin-top:10px">Zielwert für die Selbstmessung zu Hause: unter 135/85 mmHg.</p></section>`;
}

function viewSettings() {
  const st = S.settings;
  return `<h1>Einstellungen</h1>
    <section><h2>Markierungen</h2>
      <p class="muted">Erscheinen beim Speichern einer Messung zum Antippen.</p>
      <div class="chips">${st.tags.map((t, i) => `<button class="chip" data-act="rm-tag" data-i="${i}" aria-label="${esc(t)} entfernen">${esc(t)}<span class="x">×</span></button>`).join("")}</div>
      <div class="field" style="display:flex;gap:8px"><input id="in-newtag" type="text" placeholder="Neue Markierung" maxlength="30">
      <button class="secondary" style="width:auto;margin:0" data-act="add-tag">Hinzufügen</button></div>
    </section>
    <section><h2>Messung</h2>
      <label class="check"><input id="in-loc" type="checkbox" ${st.location ? "checked" : ""}> Ort vom Gerät speichern, wenn das Foto keinen enthält</label>
      <div class="field"><label for="in-name">Name im Arztbericht</label><input id="in-name" type="text" value="${esc(st.name)}" placeholder="z. B. dein vollständiger Name"></div>
      <div class="actions"><button class="primary" data-act="save-settings">Einstellungen speichern</button></div>
    </section>
    <section><h2>Daten</h2>
      <p class="muted">${S.entries.length} Messungen, auf dem Server nur verschlüsselt gespeichert.</p>
      <button class="secondary" data-act="backup">Verschlüsselte Sicherung herunterladen</button>
      <button class="secondary" data-act="csv">Tabelle herunterladen (CSV, unverschlüsselt)</button>
      <p class="muted" style="margin-top:10px">Die Sicherung enthält alles verschlüsselt. Öffnen lässt sie sich nur mit deinem Wiederherstellungscode.</p>
    </section>
    <section><h2>Sicherheit</h2>
      <p class="muted">Die App sperrt sich, wenn sie 5 Minuten im Hintergrund war.</p>
      <button class="secondary" data-act="lock">Jetzt sperren</button>
    </section>`;
}

function render() {
  const unlocked = !!S.dek;
  $("#nav").hidden = !unlocked || ["capture", "code", "alert"].includes(S.view);
  document.querySelectorAll("#nav button").forEach((b) => b.setAttribute("aria-current", b.dataset.view === S.view ? "page" : "false"));
  if (!unlocked) { app.innerHTML = viewLock(); return; }
  const views = { home: viewHome, capture: viewCapture, history: viewHistory, report: viewReport,
    settings: viewSettings, code: viewRecoveryCode, alert: viewAlert };
  app.innerHTML = (views[S.view] || viewHome)();
  S.fresh = false;
  if (S.view === "report") preparePDF();
}

async function preparePDF() {
  const list = inPeriod(S.period);
  const key = [S.period, S.settings.name, new Date().toDateString(), ...list.map((e) => [e.id, e.takenAt, e.sys, e.dia, e.pulse, (e.tags || []).join(","), e.note].join(":"))].join("|");
  if (!list.length || (S.pdf && S.pdf.key === key)) return;
  if (S.pdf?.url) URL.revokeObjectURL(S.pdf.url);
  S.pdf = { key };
  try {
    const blob = await buildReportPDF({ list, days: S.period, name: S.settings.name, stats: stats(list), effects: tagEffects(list), fmtDate, fmtTime });
    if (S.pdf.key !== key) return;
    const fname = `Blutdruck_${new Date().toISOString().slice(0, 10)}.pdf`;
    S.pdf = { key, file: new File([blob], fname, { type: "application/pdf" }), url: URL.createObjectURL(blob), name: fname };
  } catch (e) {
    S.pdf = { key, error: true };
  }
  if (S.view === "report") render();
}

/* ---------- Aktionen ---------- */

async function run(fn) {
  if (S.busy) return;
  S.busy = true; S.error = ""; render();
  try { await fn(); } catch (e) { S.error = e.message || String(e); if (S.dek) toast(S.error); }
  S.busy = false;
  render();
}

function download(name, text, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

const actions = {
  unlock: () => run(async () => { await unlock(); S.view = S.newRecoveryCode ? "code" : "home"; }),
  setup: () => {
    const code = $("#in-setup").value.trim();
    S.typed = code;
    if (!code) { S.error = "Bitte den Einrichtungscode eingeben."; return render(); }
    run(async () => { await setup(code); S.view = "code"; S.state.registered = true; });
  },
  recover: () => {
    const code = $("#in-code").value;
    S.typed = code;
    run(async () => { await recover(code); S.view = "home"; toast("Face ID ist neu eingerichtet."); });
  },
  "to-recover": () => { S.view = "recover"; S.error = ""; S.typed = ""; render(); },
  "to-lock": () => { S.view = "lock"; S.error = ""; S.typed = ""; render(); },
  "code-done": () => {
    if (!$("#in-saved").checked) return toast("Bitte bestätigen, dass du den Code aufbewahrt hast.");
    S.newRecoveryCode = null; S.view = "home"; render();
  },
  lock: () => lock(),
  camera: () => $("#camera").click(),
  library: () => $("#library").click(),
  manual: () => manualEntry(),
  cancel: () => { S.draft = null; S.view = S.backTo || "home"; S.backTo = null; render(); },
  tag: (el) => {
    readInputs();
    const t = el.dataset.tag;
    const tags = S.draft.tags;
    const i = tags.indexOf(t);
    if (i >= 0) tags.splice(i, 1); else tags.push(t);
    el.setAttribute("aria-pressed", String(i < 0));
  },
  "drop-loc": () => { Object.assign(S.draft, { lat: null, lon: null, locSource: "entfernt" }); $("#loc").textContent = "Ohne Ort."; },
  save: () => {
    readInputs();
    const d = S.draft;
    if (!d.sys || !d.dia) return toast("Bitte oberen und unteren Wert eintragen.");
    if (d.sys < 50 || d.sys > 300 || d.dia < 30 || d.dia > 200 || d.sys <= d.dia) return toast("Die Werte wirken unplausibel. Bitte prüfen.");
    if (d.pulse != null && (d.pulse < 25 || d.pulse > 250)) return toast("Der Puls wirkt unplausibel. Bitte prüfen.");
    run(async () => {
      const saved = await saveEntry(d);
      S.draft = null;
      if (level(saved) === "crit") { S.alertEntry = saved; S.view = "alert"; }
      else { S.view = S.backTo || "home"; S.fresh = S.view === "home"; toast("Messung gespeichert"); }
      S.backTo = null;
    });
  },
  edit: (el) => {
    const e = S.entries.find((x) => x.id === el.dataset.id);
    if (!e) return;
    S.draft = { ...e, tags: [...(e.tags || [])], photo: null, status: "" };
    S.backTo = S.view;
    S.view = "capture";
    render();
  },
  delete: () => {
    if (!confirm("Diese Messung löschen?")) return;
    run(async () => {
      await api(`/api/entries/${S.draft.id}`, { method: "DELETE" });
      S.entries = S.entries.filter((x) => x.id !== S.draft.id);
      S.draft = null; S.view = S.backTo || "history"; S.backTo = null;
      toast("Messung gelöscht");
    });
  },
  nav: (el) => { S.view = el.dataset.view; render(); window.scrollTo(0, 0); },
  print: () => {
    // Kein await vor navigator.share: Safari erlaubt das Teilen nur direkt nach dem Tippen.
    const pdf = S.pdf;
    if (!pdf || !pdf.file) return;
    if (navigator.canShare && navigator.canShare({ files: [pdf.file] })) {
      navigator.share({ files: [pdf.file], title: "Blutdruckprotokoll" }).catch((e) => {
        if (e.name !== "AbortError") toast("Teilen nicht möglich. Tipp auf „PDF öffnen“.");
      });
    } else {
      window.open(pdf.url, "_blank");
    }
  },
  "rm-tag": (el) => { S.settings.tags.splice(Number(el.dataset.i), 1); run(saveSettings); },
  "add-tag": () => {
    const v = $("#in-newtag").value.trim();
    if (!v) return;
    if (!S.settings.tags.includes(v)) S.settings.tags.push(v);
    run(saveSettings);
  },
  "save-settings": () => {
    S.settings.location = $("#in-loc").checked;
    S.settings.name = $("#in-name").value.trim();
    run(async () => { await saveSettings(); toast("Einstellungen gespeichert"); });
  },
  backup: () => run(async () => {
    const b = await api("/api/backup");
    download(`underpressure-sicherung-${toLocalInput(new Date()).slice(0, 10)}.json`, JSON.stringify(b), "application/json");
  }),
  csv: () => {
    const q = (s) => `"${String(s ?? "").replace(/"/g, '""')}"`;
    const lines = ["Datum;Uhrzeit;SYS;DIA;Puls;Markierungen;Notiz;Breite;Laenge"];
    for (const e of S.entries.slice().reverse()) {
      const d = new Date(e.takenAt);
      lines.push([fmtDate(d), fmtTime(d), e.sys, e.dia, e.pulse ?? "", q((e.tags || []).join(", ")), q(e.note), e.lat ?? "", e.lon ?? ""].join(";"));
    }
    download(`underpressure-${toLocalInput(new Date()).slice(0, 10)}.csv`, "\ufeff" + lines.join("\n"), "text/csv");
  },
};

document.addEventListener("click", (ev) => {
  const el = ev.target.closest("[data-act], #nav button");
  if (!el) return;
  if (el.closest("#nav")) { ev.preventDefault(); actions.nav(el); return; }
  const fn = actions[el.dataset.act];
  if (fn) { ev.preventDefault(); fn(el); }
});
document.addEventListener("change", (ev) => {
  if (ev.target.id === "in-period") { S.period = Number(ev.target.value); render(); }
});
document.addEventListener("keydown", (ev) => {
  if (ev.key !== "Enter") return;
  if (ev.target.id === "in-setup") actions.setup();
  if (ev.target.id === "in-code") actions.recover();
  if (ev.target.id === "in-newtag") actions["add-tag"]();
});
for (const id of ["camera", "library"]) {
  $(`#${id}`).addEventListener("change", (ev) => {
    const f = ev.target.files[0];
    ev.target.value = "";
    onPhoto(f).catch((e) => toast(e.message));
  });
}
document.addEventListener("visibilitychange", () => {
  if (document.hidden) S.hiddenAt = Date.now();
  else if (S.dek && S.hiddenAt && Date.now() - S.hiddenAt > AUTOLOCK_MS) lock("Automatisch gesperrt.");
});

(async function start() {
  try {
    S.state = await api("/api/state");
  } catch (e) {
    app.innerHTML = `<div class="lock"><div class="wordmark">underpressure</div><p class="status hint">Server nicht erreichbar: ${esc(e.message)}</p></div>`;
    return;
  }
  render();
})();
