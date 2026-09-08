# 🛡️ Safeer Control

**Safeer Control** je modularno, varno in visoko-odzivno lokalno vozlišče za upravljanje pametnih naprav, televizorja, avdio sistemov ter ekosistema **Safeer Browser**.

Deluje kot ločen orkestrator (4. steber Safeer ekosistema), ki omogoča oddaljen nadzor, avtomatizirane scene (npr. Kino način) ter varno povezavo z AI asistenti.

---

## 🏛️ Modularna Struktura Repozitorija

```
safeer-control/
├── app/                      # Aplikacijska plast (FastAPI, Web UI, CLI)
│   ├── server.py             # REST API & WebSocket zaledje
│   ├── cli.py                # Ukazna vrstica za terminal
│   └── static/               # Spletni in mobilni vmesnik (HTML/CSS/JS)
├── core/                     # Jedro sistema
│   ├── config.py             # Varno branje nastavitev (.env)
│   ├── devices/              # Modeli naprav, DeviceRegistry in mDNS/port discovery
│   ├── actions/              # Tipizirana dejanja in ActionEngine
│   ├── security/             # PolicyEngine (varnostni filter, allowlist)
│   └── pairing/              # Varno seznanjanje naprav (PIN / Token)
├── providers/                # Gonilniki naprav (DeviceProviders)
│   ├── base.py               # Abstraktni osnovni razred
│   ├── androidtv/            # Android TV ADB & Safeer Broadcast most
│   ├── upnp/                 # UPnP SOAP (JBL Bar 300)
│   ├── android/              # Standardni Android telefon nadzor
│   ├── shizuku/              # Privilegirani Shizuku nadzor
│   └── cast/                 # Google Cast / Chromecast predvajanje
├── scenes/                   # Scenski orkestrator (Kino, Glasba, Izklop)
│   ├── models.py
│   └── engine.py
├── docs/                     # Arhitekturna in varnostna dokumentacija
└── tests/                    # Samodejni testi (pytest)
```

---

## 🚀 Hitri Začetek

### 1. Namestitev odvisnosti
```bash
git clone https://github.com/memelandfaner/safeer-control.git
cd safeer-control
pip install -e .
```

### 2. Konfiguracija okolja
Kopirajte vzorec `.env.example` v `.env` in nastavite IP naslove vaših naprav:
```bash
cp .env.example .env
nano .env
```

Primer vsebine `.env`:
```ini
SAFEER_TV_HOST=192.168.1.100
SAFEER_TV_PORT=5555
SAFEER_TV_NAME=Living Room TV

SAFEER_AUDIO_HOST=192.168.1.101
SAFEER_AUDIO_PORT=49152
SAFEER_AUDIO_NAME=JBL Bar 300
```

---

## 💻 Uporaba prek Ukazne Vrstice (CLI)

### Zagon spletnega in mobilnega strežnika:
```bash
python3 -m app.cli serve 8990
```
Dostop na telefonu / računalniku: `http://<IP_RACUNALNIKA>:8990`

### Pregled stanja naprav:
```bash
python3 -m app.cli status
```

### Nadzor Televizorja:
```bash
# Vklop / Izklop
python3 -m app.cli tv power

# Zagon Safeer Browserja
python3 -m app.cli tv browser

# Odpiranje povezave na TV
python3 -m app.cli tv url "https://example.com"

# Iskanje videa na SmartTube (YouTube)
python3 -m app.cli tv smarttube "Linkin Park"

# Preklop vhoda na PC ali PS5
python3 -m app.cli tv pc
python3 -m app.cli tv ps5
```

### Nadzor Avdio Sistema (JBL Bar 300):
```bash
# Nastavitev glasnosti (0 - 100)
python3 -m app.cli audio volume 40

# Vklop zvoka (Unmute)
python3 -m app.cli audio unmute
```

### Scene:
```bash
# Seznam scen
python3 -m app.cli scene

# Zagon Kinematografskega načina
python3 -m app.cli scene cinema
```

---

## 🧪 Testiranje

Zagon enotnih testov:
```bash
pytest tests/
```

---

## 📜 Licenca
MIT License — Safeer Ekosistem.
