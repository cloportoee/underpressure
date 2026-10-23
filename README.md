# underpressure

Private Blutdruck-App: Foto vom Display des Messgeräts machen, Werte werden erkannt, mit Zeit, Ort und Markierungen gespeichert und für den Arztbericht ausgewertet.

## Datenschutz

- Entsperren mit Face ID (Passkey). Aus dem Passkey leitet der Browser über die WebAuthn-PRF-Erweiterung einen Schlüssel ab, der das Gerät nie verlässt.
- Jede Messung (Werte, Zeit, Ort, Markierungen, Notiz) und die Einstellungen werden im Browser mit AES-256-GCM verschlüsselt. In der SQLite-Datenbank liegen nur unlesbare Blöcke.
- Wiederherstellungscode (32 Zeichen) als zweiter Schlüssel für den Notfall. Ohne Passkey und ohne Code sind die Daten nicht wiederherstellbar – auch nicht durch den Server-Betreiber.
- Einzige Ausnahme: Für die Display-Erkennung geht ein verkleinertes Foto ohne Metadaten einmal über den Server an die Anthropic-API. Es wird nicht gespeichert und nicht geloggt.
- Zeit und Ort kommen aus den EXIF-Daten des Fotos. Fehlen sie (bei Kamerafotos im Browser üblich), nimmt die App die Gerätezeit und optional den Gerätestandort.

## Aufbau

```
web/      statische App (HTML, CSS, JS), von Caddy ausgeliefert
app/      FastAPI-Server (Passkey-Prüfung, verschlüsselte Ablage, Display-Erkennung), Port 8090
deploy/   Einrichtung auf dem Server (systemd, Caddy, Skripte)
```

Voraussetzung auf dem iPhone: Safari ab iOS 18, Passkey im iCloud-Schlüsselbund.

## Einrichtung auf dem Server

Siehe `deploy/setup.sh`. Danach Updates mit `sudo underpressure-update`.

Konfiguration in `/etc/underpressure.env`: Domain, Einrichtungscode für den ersten Passkey, `ANTHROPIC_API_KEY`, Modell (`UP_MODEL`, Standard `claude-haiku-5-5`).

Schrift der Anzeige: DSEG7 Classic von keshikan, SIL Open Font License (`web/fonts/DSEG-LICENSE.txt`).
