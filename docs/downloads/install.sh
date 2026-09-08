#!/usr/bin/env bash
# ==============================================================================
# Safeer Control — Enovrstični Namestitveni Skript za Linux / macOS
# Namesti in konfigurira Safeer Control v varnem izoliranem okolju (~/.local).
# ==============================================================================
set -euo pipefail

INSTALL_DIR="${HOME}/.local/share/safeer-control"
BIN_DIR="${HOME}/.local/bin"
REPO_URL="https://github.com/memelandfaner/safeer-control.git"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "================================================================================"
echo "🛡️  SAFEER CONTROL — LOKALNO, ZASEBNO IN KRIPTOGRAFSKO VOZLIŠČE ZA NAPRAVE"
echo "================================================================================"
echo -e "${NC}"

echo -e "=== [1/5] Preverjanje sistemskih zahtev ==="
if ! command -v git >/dev/null 2>&1; then
    echo -e "${RED}NAPAKA: 'git' ni nameščen na vašem sistemu.${NC}" >&2
    echo "Namestite git z: sudo apt install git" >&2
    exit 1
fi

PYTHON_BIN=""
for py in python3 python3.12 python3.11 python3.10; do
    if command -v "$py" >/dev/null 2>&1; then
        VER=$($py -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        MAJOR=$(echo "$VER" | cut -d. -f1)
        MINOR=$(echo "$VER" | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
            PYTHON_BIN="$py"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}NAPAKA: Zahtevan je Python 3.10 ali novejši.${NC}" >&2
    exit 1
fi
echo -e "${GREEN}✓ Zaznan primeren Python: $PYTHON_BIN ($($PYTHON_BIN --version))${NC}"

echo -e "\n=== [2/5] Priprava namestitvene mape ==="
mkdir -p "${INSTALL_DIR}"
mkdir -p "${BIN_DIR}"

if [ -d "${INSTALL_DIR}/.git" ]; then
    echo "Posodabljam obstoječo namestitev v ${INSTALL_DIR}..."
    git -C "${INSTALL_DIR}" pull origin main --ff-only
else
    echo "Prenašam Safeer Control repozitorij v ${INSTALL_DIR}..."
    git clone "${REPO_URL}" "${INSTALL_DIR}"
fi

echo -e "\n=== [3/5] Ustvarjanje izoliranega Python okolja (venv) ==="
VENV_DIR="${INSTALL_DIR}/venv"
if [ ! -d "${VENV_DIR}" ]; then
    "$PYTHON_BIN" -m venv "${VENV_DIR}"
fi

echo -e "\n=== [4/5] Namestitev odvisnosti ==="
"${VENV_DIR}/bin/pip" install --upgrade pip --quiet
"${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" --quiet

echo -e "\n=== [5/5] Ustvarjanje izvršljivega ukaza v ${BIN_DIR}/safeer-control ==="
cat << 'EOF' > "${BIN_DIR}/safeer-control"
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/.local/share/safeer-control"
PYTHONPATH="${INSTALL_DIR}" "${INSTALL_DIR}/venv/bin/python3" -m app.cli "$@"
EOF
chmod +x "${BIN_DIR}/safeer-control"

# Preveri PATH
PATH_NOTICE=""
if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
    PATH_NOTICE="OPOZORILO: ${BIN_DIR} še ni v vaši spremenljivki \$PATH. Dodajte vrstico v ~/.bashrc ali ~/.zshrc:\n  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo -e "${GREEN}"
echo "================================================================================"
echo "🎉 SAFEER CONTROL JE BIL USPEŠNO NAMEŠČEN!"
echo "================================================================================"
echo -e "${NC}"
if [ -n "$PATH_NOTICE" ]; then
    echo -e "${YELLOW}${PATH_NOTICE}${NC}\n"
fi

echo -e "Hitri začetek:"
echo -e "  • Preverite stanje sistema:      ${CYAN}safeer-control status${NC}"
echo -e "  • Zaženite nadzorni strežnik:     ${CYAN}safeer-control serve${NC}"
echo -e "  • Zagon FPS merilnika zaslona:    ${CYAN}safeer-control observer fps --device <ip:port>${NC}"
echo -e "  • Spletni nadzorni vmesnik:       ${CYAN}http://localhost:8990${NC}"
echo ""
