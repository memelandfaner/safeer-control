#!/usr/bin/env bash
# ==============================================================================
# Safeer Control - Svetovni Spletni Strežnik & Cloudflare HTTPS Tunel
# ==============================================================================
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="${HOME}/.safeer_control_tunnel.log"
PORT="8990"

echo "=========================================================="
echo "🛡️ SAFEER CONTROL - SVETOVNI SPLETNI STREŽNIK"
echo "=========================================================="

# 1. Preveri, če teče lokalni Safeer Control strežnik
if ! curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:${PORT}/ | grep -q "200"; then
    echo "⚙️ Zaganjam lokalni Safeer Control strežnik (port ${PORT})..."
    cd "${DIR}"
    nohup python3 -m app.cli serve ${PORT} >/dev/null 2>&1 &
    sleep 3
fi

# 2. Zaženi varen svetovni Cloudflare HTTPS tunel
CLOUDFLARED_BIN=""
if command -v cloudflared >/dev/null 2>&1; then
    CLOUDFLARED_BIN="cloudflared"
elif [ -f "${HOME}/.local/bin/cloudflared" ]; then
    CLOUDFLARED_BIN="${HOME}/.local/bin/cloudflared"
fi

if [ -n "$CLOUDFLARED_BIN" ]; then
    if ! pgrep -f "cloudflared.*${PORT}" >/dev/null; then
        echo "🌐 Zaganjam varen svetovni HTTPS tunel..."
        nohup "$CLOUDFLARED_BIN" tunnel --url "http://127.0.0.1:${PORT}" --logfile "$LOG_FILE" >/dev/null 2>&1 &
        sleep 4
    fi

    # Izvleci javni URL
    PUBLIC_URL=""
    if [ -f "$LOG_FILE" ]; then
        PUBLIC_URL="$(grep -o 'https://[-a-zA-Z0-9@:%._\+~#=]\+\.trycloudflare\.com' "$LOG_FILE" | tail -n 1 || true)"
    fi
fi

LOCAL_IP="$(ip -4 addr show 2>/dev/null | grep inet | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -n 1 || echo "127.0.0.1")"

echo ""
echo "✅ SAFEER CONTROL JE AKTIVEN IN DOSEGLJIV!"
echo "----------------------------------------------------------"
if [ -n "$PUBLIC_URL" ]; then
    echo "🌍 JAVNI SVETOVNI NASLOV (Kjerkoli na svetu):"
    echo "   👉 Predstavitveni portal & prenosi:  ${PUBLIC_URL}/portal"
    echo "   👉 Mobilni APK prenos:               ${PUBLIC_URL}/downloads/SafeerCompanion.apk"
    echo "   👉 Enovrstična namestitev:          curl -sSL ${PUBLIC_URL}/install.sh | bash"
    echo ""
fi

echo "🏠 Domače lokalno omrežje (Wi-Fi/LAN):"
echo "   👉 http://${LOCAL_IP}:${PORT}/portal"
echo ""
echo "💻 Na tem računalniku:"
echo "   👉 http://localhost:${PORT}/portal"
echo "=========================================================="
