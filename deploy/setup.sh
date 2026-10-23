#!/usr/bin/env bash
# Einmalige Einrichtung von underpressure auf dem Songprint-Server.
#   sudo bash /opt/underpressure/deploy/setup.sh [domain]
set -euo pipefail
DOMAIN="${1:-underpressure.songprint.de}"
APP=/opt/underpressure
ENV=/etc/underpressure.env
[ "$(id -u)" = 0 ] || { echo "Bitte mit sudo ausfuehren."; exit 1; }
[ -f "$APP/app/main.py" ] || { echo "$APP fehlt - erst das Repo klonen."; exit 1; }

echo "==> Pakete"
apt-get update -qq
apt-get install -y -q python3-fastapi python3-uvicorn python3-cryptography sqlite3 >/dev/null

echo "==> Benutzer und Datenverzeichnis"
id underpressure >/dev/null 2>&1 || useradd --system --home /var/lib/underpressure --shell /usr/sbin/nologin underpressure
install -d -o underpressure -g underpressure -m 700 /var/lib/underpressure

echo "==> Konfiguration"
touch "$ENV"
chown root:underpressure "$ENV"
chmod 640 "$ENV"
setvar() {  # Eintrag ergaenzen, falls er fehlt oder leer ist (vorhandene Werte bleiben)
  if grep -q "^$1=." "$ENV"; then return; fi
  sed -i "/^$1=/d" "$ENV"
  echo "$1=$2" >> "$ENV"
  echo "   $1 eingetragen"
}
setvar UP_DB /var/lib/underpressure/underpressure.db
setvar UP_RP_ID "$DOMAIN"
setvar UP_ORIGIN "https://$DOMAIN"
setvar UP_SETUP_CODE "$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
setvar UP_MODEL claude-haiku-5-5
if ! grep -q "^ANTHROPIC_API_KEY=." "$ENV"; then
  echo
  read -r -s -p "Anthropic-API-Schluessel fuer die Display-Erkennung (Enter = ohne, Werte nur eintippen): " AKEY || AKEY=""
  echo
  sed -i "/^ANTHROPIC_API_KEY=/d" "$ENV"
  echo "ANTHROPIC_API_KEY=${AKEY}" >> "$ENV"
else
  echo "   API-Schluessel vorhanden"
fi

echo "==> Port 8090 pruefen"
if ss -tlnp | grep -q ':8090 ' && ! systemctl is-active --quiet underpressure; then
  echo "   Port 8090 ist schon belegt:"; ss -tlnp | grep ':8090 '; exit 1
fi

echo "==> Dienst"
install -m 644 "$APP/deploy/underpressure.service" /etc/systemd/system/underpressure.service
install -m 755 "$APP/deploy/underpressure-update" /usr/local/bin/underpressure-update
systemctl daemon-reload
systemctl enable --now underpressure >/dev/null 2>&1
systemctl restart underpressure
sleep 1
systemctl is-active --quiet underpressure || { journalctl -u underpressure -n 30 --no-pager; exit 1; }

echo "==> DNS pruefen"
SERVER_IPS=" $(hostname -I 2>/dev/null) "
IP=$(getent ahostsv4 "$DOMAIN" | awk '{print $1; exit}' || true)
if [ -z "$IP" ]; then
  echo "   $DOMAIN hat noch keinen DNS-Eintrag (A-Record auf diesen Server setzen)."
elif echo "$SERVER_IPS" | grep -q " $IP "; then
  echo "   $DOMAIN -> $IP (zeigt auf diesen Server)"
else
  echo "   ACHTUNG: $DOMAIN zeigt auf $IP, nicht auf diesen Server ($SERVER_IPS)"
fi

echo "==> Caddy"
mkdir -p /etc/caddy/sites
sed "s/__DOMAIN__/$DOMAIN/" "$APP/deploy/underpressure.caddy" > /etc/caddy/sites/underpressure.caddy
cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.vor-underpressure
grep -q 'import /etc/caddy/sites/\*.caddy' /etc/caddy/Caddyfile || printf '\nimport /etc/caddy/sites/*.caddy\n' >> /etc/caddy/Caddyfile
if ! caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
  echo "   Caddy-Konfiguration fehlerhaft, stelle alten Stand wieder her."
  cp /etc/caddy/Caddyfile.vor-underpressure /etc/caddy/Caddyfile
  rm -f /etc/caddy/sites/underpressure.caddy
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile || true
  exit 1
fi
systemctl reload caddy || systemctl restart caddy

set -a; . "$ENV"; set +a
echo
echo "================ FERTIG ================"
echo "Adresse:          https://$DOMAIN"
echo "Einrichtungscode: ${UP_SETUP_CODE:-}"
[ -n "${ANTHROPIC_API_KEY:-}" ] && echo "Display-Erkennung: an" || echo "Display-Erkennung: aus (Schluessel spaeter in $ENV eintragen, dann: sudo systemctl restart underpressure)"
echo "Updates:          sudo underpressure-update"
