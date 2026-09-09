# Changelog

Vse opazne spremembe tega projekta so dokumentirane v tej datoteki.

Format temelji na [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
projekt sledi [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] — 2026-09-09

### Dodano
- Safeer ekosistem stran na `safeer.si` (dvojezična SL/EN)
- `/console` pot za upravljalni vmesnik, `/` za uvodno stran
- Preusmeritveni endpointi: `/browser`, `/ecosystem`, `/security`, `/docs`
- Cloudflare Named Tunnel integracija (`safeer` tunel, safeer.si domena)
- `gh-pages` veja za GitHub Pages
- Dodano `scenes*` v `pyproject.toml` pakete
- `LICENSE` (MIT) datoteka

### Spremenjeno
- Download endpointi zdaj preusmerjajo na GitHub Releases namesto binarjev iz repozitorija
- Enotna verzija `0.3.0` v `pyproject.toml` in `server.py`
- CORS regex razširjen na `*.safeer.si`
- `.gitignore` razširjen: binarne datoteke in APK izključeni iz git sledenja

### Odstranjeno
- Binarne datoteke iz `app/static/downloads/`, `docs/downloads/`, `companion/bin/`

---

## [0.2.1] — 2026-09-08

### Dodano
- Security Hardening: kratkotrajne seje, enokratne WebSocket vstopnice
- Android APK companion (SafeerCompanion)
- Go native companion binarji (ARM64 + AMD64)
- CI pipeline: pytest 3.10/3.11/3.12 + Go cross-kompilacija

---

## [0.1.0] — 2026-08-01

### Dodano
- Začetna izdaja Safeer Control
- FastAPI strežnik z device registry, akcijami in scenami
