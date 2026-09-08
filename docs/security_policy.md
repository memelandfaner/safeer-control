# 🛡️ Safeer Control — Varnostna Politika (Security Policy)

Varnost je osrednji temelj sistema Safeer Control. AI model ali zunanji klicatelj **nikoli** ne dobi neposrednega dostopa do `adb shell` ali operacijskega sistema.

## 1. Načelo Belega Seznama (Allowlist Only)
Izvajajo se lahko izključno vnaprej odobrena dejanja za posamezen tip naprave:
- **Android TV**: `power`, `wake`, `sleep`, `key`, `open_url`, `open_browser`, `open_smarttube`, `open_xplore_tv`, `open_streamtv`, `launch_app`, `tune_channel`, `play_pause`, `seek`, `search`, `switch_input`, `type_text`, `screenshot`.
- **Zvok (JBL)**: `set_volume`, `unmute`, `mute`, `status`.

## 2. Zaščita pred vbrizgavanjem ukazov (Command Injection Prevention)
Vsa besedilna polja (iskanje, vnos besedila) se preverijo s filtrom `INJECTION_PATTERN = re.compile(r"[;&|`$<>]")`. Če zahtevek vsebuje prepovedane znake, je takoj zavrnjen.

## 3. Validacija URL-jev
Dovoljeni sta izključno shemi `http://` in `https://`. Sheme kot so `javascript:`, `file:`, `intent:` ali `data:` so strogo blokirane.

## 4. Omejitve aplikacij
Zagon aplikacij je omejen na vnaprej potrjene pakete (`ALLOWED_PACKAGES`), kot so Safeer Browser, SmartTube, StreamTV in sistemski predvajalnik.

## 5. Zero Token & Zero Hardcoded IP Politika
Noben osebni žeton ali zasebni IP naslov se ne zapiše v sledene datoteke repozitorija. Vse konfiguracije se berejo iz lokalne `.env` datoteke.
