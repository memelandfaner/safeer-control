# 🏛️ Safeer Control — Arhitektura Sistema

Safeer Control je modularni orkestrator za varno povezovanje in upravljanje naprav, avdio sistemov ter spletnih vsebin v Safeer ekosistemu.

## Drevo Projekta

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

## Tok Izvajanja Ukazov

```
[ AI / Mobilni UI / CLI ]
           │
           ▼
   [ ActionEngine ]
           │
           ▼
   [ 🛡️ PolicyEngine ]  ──(Zavrnjeno ob nevarnem ukazu)──> ❌ Varnostna blokada
           │
      (Odobreno)
           │
           ▼
   [ DeviceRegistry ]
           │
           ▼
   [ DeviceProvider ] ──> [ Fizična naprava (TV / JBL / Telefon) ]
```
