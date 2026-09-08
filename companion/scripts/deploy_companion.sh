#!/usr/bin/env bash
# ==============================================================================
# Safeer Companion Automated Deployment Script for Android (ADB / Shizuku)
# Namesti in konfigurira Safeer Companion (APK ali samostojno binarno datoteko)
# z uveljavitvijo 0700/0600 dovoljenj in preverjanjem zdravja.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TARGET_DEVICE="${1:-}"
DEPLOY_MODE="${2:-apk}"  # "apk" ali "native"

echo "=== [1/4] Preverjanje povezave z Android napravo (ADB) ==="
if ! command -v adb >/dev/null 2>&1; then
    echo "NAPAKA: 'adb' ni nameščen na sistemu!" >&2
    exit 1
fi

ADB_CMD="adb"
if [[ -n "$TARGET_DEVICE" ]]; then
    ADB_CMD="adb -s ${TARGET_DEVICE}"
fi

DEVICES=$(${ADB_CMD} devices | grep -v "List of devices" | grep "device$" || true)
if [[ -z "$DEVICES" ]]; then
    echo "OPOZORILO: Nobena aktivna ADB naprava ni bila zaznana." >&2
    echo "Povežite napravo z: adb connect <ip>:<port>" >&2
    exit 1
fi
echo "Zaznana ciljna naprava:"
echo "$DEVICES"

if [[ "$DEPLOY_MODE" == "apk" ]]; then
    echo "=== [2/4] Priprava in namestitev Safeer Companion APK ==="
    APK_FILE="${ROOT_DIR}/companion/android/build/SafeerCompanion.apk"
    if [[ ! -f "$APK_FILE" ]]; then
        echo "APK še ni zgrajen. Zaganjam build_companion_apk.sh..."
        bash "${ROOT_DIR}/companion/android/build_companion_apk.sh"
    fi

    echo "Nameščam APK na napravo..."
    ${ADB_CMD} install -r "$APK_FILE"

    echo "=== [3/4] Konfiguracija Shizuku dovoljenj in zagon storitve ==="
    echo "Dodeljujem Shizuku API v23 dovoljenje..."
    ${ADB_CMD} shell pm grant com.safeer.companion moe.shizuku.manager.permission.API_V23 2>/dev/null || true

    echo "Zaganjam SafeerCompanionService Foreground storitev..."
    ${ADB_CMD} shell am start-foreground-service com.safeer.companion/.SafeerCompanionService

else
    echo "=== [2/4] Priprava in prenos ARM64 nativnega programa ==="
    BIN_FILE="/tmp/safeer-companion"
    if [[ ! -f "$BIN_FILE" ]]; then
        echo "Prevajam ARM64 binarni program..."
        GOCACHE=/tmp/gocache GOPATH=/tmp/gopath CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
            go build -ldflags="-s -w" -o "$BIN_FILE" "${ROOT_DIR}/companion/native/main.go"
    fi

    echo "Prenašam v /data/local/tmp/safeer-companion..."
    ${ADB_CMD} push "$BIN_FILE" /data/local/tmp/safeer-companion
    ${ADB_CMD} shell chmod 0700 /data/local/tmp/safeer-companion

    echo "Prenašam nadzornika safeer-companion-watchdog.sh..."
    ${ADB_CMD} push "${SCRIPT_DIR}/safeer-companion-watchdog.sh" /data/local/tmp/safeer-companion-watchdog.sh
    ${ADB_CMD} shell chmod 0700 /data/local/tmp/safeer-companion-watchdog.sh

    echo "=== [3/4] Zagon nadzorovanega demona ==="
    ${ADB_CMD} shell "nohup /data/local/tmp/safeer-companion-watchdog.sh >/dev/null 2>&1 &"
fi

echo "=== [4/4] Preverjanje delovanja (Health Check) ==="
sleep 1.5
if ${ADB_CMD} shell "curl -s http://127.0.0.1:8995/api/companion/health" 2>/dev/null; then
    echo ""
    echo "=========================================================="
    echo "✅ Safeer Companion uspešno nameščen in aktiven!"
    echo "=========================================================="
else
    echo "OPOZORILO: Demon se še zaganja ali curl na napravi ni na voljo. Preverite loge z 'adb logcat -s SafeerCompanionSvc'."
fi
