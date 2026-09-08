# 🛡️ Safeer Control

**Safeer Control** je modularno, varno in visoko-odzivno lokalno vozlišče za upravljanje pametnih naprav, televizorja, avdio sistemov ter ekosistema **Safeer Browser**.

Deluje kot ločen orkestrator (4. steber Safeer ekosistema), ki omogoča oddaljen nadzor, avtomatizirane scene (npr. Kino način) ter varno povezavo z AI asistenti.

---

## 🏛️ Arhitektura

```
                         [ AI / Glasovni Asistent / Spletni UI ]
                                            │
                                            ▼
                                [ Safeer Action Engine ]
                                            │
                                            ▼
                             [ 🛡️ Policy Engine (Varnost) ]
                           (Allowlist, validacija parametrov,
                            preprečevanje vbrizgavanja ukazov)
                                            │
                                            ▼
                                   [ Device Registry ]
                                            │
                 ┌──────────────────────────┼──────────────────────────┐
                 │                          │                          │
                 ▼                          ▼                          ▼
      [ AndroidTVProvider ]         [ JBLAudioProvider ]      [ AndroidProvider ]
       • ADB & Keyevents             • UPnP / SOAP             • Normal / Shizuku
       • Safeer Broadcast most       • Brez CEC utripanja      • Advanced Control
       • Preklop vhodov (PC/PS5)     • Nadzor glasnosti
```

### Glavne komponente:

1. **PolicyEngine**:
   - Stroga ločitev med uporabniškimi/AI zahtevami in nizkonivojskimi klici.
   - **AI nima neposrednega dostopa do `adb shell` ali sistemske lupine.** Vsa dejanja so vnaprej definirana v dovoljenem seznamu (`allowlist`) z validiranimi parametri.
2. **DeviceProvider**:
   - `AndroidTVProvider`: Upravljanje Android TV (Philips 4K TV) ter neposredna povezava s Safeer Browserjem (`ACTION_PLAY_PAUSE`, `ACTION_SEEK`, `ACTION_CHANNEL_TUNE`, `ACTION_SEARCH`).
   - `JBLAudioProvider`: Hardware-aware UPnP SOAP nadzor (JBL Bar 300) z zaščito pred utripanjem HDMI-CEC / eARC zvoka (brez ponavljajočih se `unmute` zank).
3. **SceneEngine**:
   - Enostavno proženje sestavljenih scenarijev (npr. `cinema`, `music`, `power_off`).
4. **Zero Token & Zero Hardcoded IP Politika**:
   - V repozitorij se **nikoli ne zapišejo** trdo kodirani zasebni IP naslovi ali žetoni. Vsi podatki se berejo iz lokalne `.env` datoteke, ki je v `.gitignore`.

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

### Pregled stanja naprav:
```bash
python3 -m safeer_control.cli status
```

### Nadzor Televizorja:
```bash
# Vklop / Izklop
python3 -m safeer_control.cli tv power

# Zagon Safeer Browserja
python3 -m safeer_control.cli tv browser

# Odpiranje povezave na TV
python3 -m safeer_control.cli tv url "https://example.com"

# Iskanje videa na SmartTube (YouTube)
python3 -m safeer_control.cli tv smarttube "Linkin Park"

# Preklop vhoda na PC ali PS5
python3 -m safeer_control.cli tv pc
python3 -m safeer_control.cli tv ps5
```

### Nadzor Avdio Sistema (JBL Bar 300):
```bash
# Nastavitev glasnosti (0 - 100)
python3 -m safeer_control.cli audio volume 40

# Vklop zvoka (Unmute)
python3 -m safeer_control.cli audio unmute
```

### Scene:
```bash
# Seznam scen
python3 -m safeer_control.cli scene

# Zagon Kinematografskega načina (prebudi TV, odklene JBL, nastavi 45% glasnost, odpre Safeer)
python3 -m safeer_control.cli scene cinema
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
