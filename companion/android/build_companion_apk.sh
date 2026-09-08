#!/usr/bin/env bash
# ==============================================================================
# Safeer Companion Android APK Builder (Cursor Protocol / Zero-Gradle Standard)
# Prevede SafeerCompanion.apk z vgrajenim ARM64 Go Companionom
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
SRC_DIR="${SCRIPT_DIR}/src"
MANIFEST="${SCRIPT_DIR}/AndroidManifest.xml"
ASSETS_DIR="${BUILD_DIR}/assets"

echo "=== [1/6] Nastavitev orodij za prevajanje Android APK ==="

IS_RELEASE_BUILD=0
for arg in "$@"; do
    if [[ "$arg" == "--release" ]]; then
        IS_RELEASE_BUILD=1
    fi
done
if [[ "${REQUIRE_RELEASE_KEY:-0}" == "1" ]]; then
    IS_RELEASE_BUILD=1
fi

# 1. Konfiguracija Android SDK preko okoljskih spremenljivk s standardnimi fallback lokacijami
SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "${SDK_ROOT}" || ! -d "${SDK_ROOT}" ]]; then
    CANDIDATE_PATHS=(
        "${HOME}/Android/Sdk"
        "/opt/android-sdk"
        "/usr/lib/android-sdk"
        "${ROOT_DIR}/../Neimenovana mapa/tv-browser-2/.android-sdk"
    )
    for cand in "${CANDIDATE_PATHS[@]}"; do
        if [[ -d "${cand}/build-tools" && -d "${cand}/platforms" ]]; then
            SDK_ROOT="${cand}"
            break
        fi
    done
fi

if [[ -z "${SDK_ROOT}" || ! -d "${SDK_ROOT}" ]]; then
    echo "NAPAKA: Android SDK ni bil najden. Nastavite okoljsko spremenljivko ANDROID_HOME ali ANDROID_SDK_ROOT."
    exit 1
fi

# Poišči najnovejšo različico build-tools
BUILD_TOOLS_DIR=""
if [[ -d "${SDK_ROOT}/build-tools" ]]; then
    BUILD_TOOLS_DIR=$(find "${SDK_ROOT}/build-tools" -maxdepth 1 -mindepth 1 -type d | sort -V | tail -n 1)
fi

# Poišči najnovejšo Android platformo (android.jar)
PLATFORM_DIR=""
if [[ -d "${SDK_ROOT}/platforms" ]]; then
    PLATFORM_DIR=$(find "${SDK_ROOT}/platforms" -maxdepth 1 -mindepth 1 -type d -name "android-*" | sort -V | tail -n 1)
fi

AAPT2="${BUILD_TOOLS_DIR}/aapt2"
D8="${BUILD_TOOLS_DIR}/d8"
ZIPALIGN="${BUILD_TOOLS_DIR}/zipalign"
APKSIGNER="${BUILD_TOOLS_DIR}/apksigner"
ANDROID_JAR="${PLATFORM_DIR}/android.jar"

if [[ ! -f "$AAPT2" || ! -f "$D8" || ! -f "$ZIPALIGN" || ! -f "$APKSIGNER" || ! -f "$ANDROID_JAR" ]]; then
    echo "NAPAKA: Manjkajoča SDK orodja v ${SDK_ROOT}."
    echo "Preverite, da so na voljo aapt2, d8, zipalign, apksigner ter android.jar."
    exit 1
fi
echo "Uporabljam Android SDK: ${SDK_ROOT}"
echo "Build-tools: ${BUILD_TOOLS_DIR}"
echo "Platforma:   ${PLATFORM_DIR}"

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/gen" "${BUILD_DIR}/obj" "${BUILD_DIR}/apk" "${ASSETS_DIR}"

echo "=== [2/6] Priprava ARM64 nativne binarne datoteke ==="
ARM64_BIN="/tmp/safeer-companion"
if [[ ! -f "$ARM64_BIN" ]]; then
    echo "Prevajam ARM64 Go Companion binarni program..."
    GOCACHE=/tmp/gocache GOPATH=/tmp/gopath CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
        go build -ldflags="-s -w" -o "$ARM64_BIN" "${ROOT_DIR}/companion/native/main.go"
fi
cp "$ARM64_BIN" "${ASSETS_DIR}/safeer-companion"
chmod 0755 "${ASSETS_DIR}/safeer-companion"

echo "=== [3/6] AAPT2 Link in generiranje R.java ==="
mkdir -p "${BUILD_DIR}/res"
"${AAPT2}" link -o "${BUILD_DIR}/unaligned.apk" \
    -I "${ANDROID_JAR}" \
    --manifest "${MANIFEST}" \
    --java "${BUILD_DIR}/gen" \
    --auto-add-overlay

echo "=== [4/6] Prevajanje Java kode (javac) ==="
JAVA_SOURCES=$(find "${SRC_DIR}" -name "*.java")
GEN_SOURCES=$(find "${BUILD_DIR}/gen" -name "*.java" 2>/dev/null || true)

javac -source 8 -target 8 \
    -bootclasspath "${ANDROID_JAR}" \
    -d "${BUILD_DIR}/obj" \
    ${JAVA_SOURCES} ${GEN_SOURCES}

echo "=== [5/6] Pretvorba v DEX (d8) ==="
CLASS_FILES=$(find "${BUILD_DIR}/obj" -name "*.class")
"${D8}" --output "${BUILD_DIR}" --min-api 21 --lib "${ANDROID_JAR}" ${CLASS_FILES}

# Dodaj classes.dex in assets v unaligned.apk
(cd "${BUILD_DIR}" && zip -u unaligned.apk classes.dex)
(cd "${BUILD_DIR}" && zip -r -u unaligned.apk assets/)

echo "=== [6/6] Zipalign in podpis APK ==="
"${ZIPALIGN}" -f -p 4 "${BUILD_DIR}/unaligned.apk" "${BUILD_DIR}/SafeerCompanion-aligned.apk"

if [[ -n "${RELEASE_KEYSTORE:-}" && -f "${RELEASE_KEYSTORE}" ]]; then
    echo "Podpisovanje z uradnim produkcijskim ključem..."
    KS_ALIAS="${RELEASE_KEY_ALIAS:-safeer-companion}"
    KS_PASS="${RELEASE_KEYSTORE_PASS:?NAPAKA: Okoljska spremenljivka RELEASE_KEYSTORE_PASS je obvezna za produkcijski podpis}"
    K_PASS="${RELEASE_KEY_PASS:-${KS_PASS}}"

    "${APKSIGNER}" sign \
        --ks "${RELEASE_KEYSTORE}" \
        --ks-pass "pass:${KS_PASS}" \
        --ks-key-alias "${KS_ALIAS}" \
        --key-pass "pass:${K_PASS}" \
        --out "${BUILD_DIR}/SafeerCompanion.apk" \
        "${BUILD_DIR}/SafeerCompanion-aligned.apk"
    echo "✅ Uspešno podpisano s produkcijskim ključem (${KS_ALIAS})."
else
    if [[ "$IS_RELEASE_BUILD" == "1" ]]; then
        echo "NAPAKA (Fail-Closed): Zahtevana je produkcijska gradnja (--release ali REQUIRE_RELEASE_KEY=1), vendar RELEASE_KEYSTORE ni določen ali ne obstaja!"
        exit 1
    fi
    echo "OPOZORILO: RELEASE_KEYSTORE ni nastavljen. Uporabljam lokalni debug ključ za razvoj."
    DEBUG_KEYSTORE="${BUILD_DIR}/debug.keystore"
    if [[ ! -f "$DEBUG_KEYSTORE" ]]; then
        keytool -genkeypair -v \
            -keystore "${DEBUG_KEYSTORE}" \
            -storepass android -keypass android \
            -alias androiddebugkey \
            -keyalg RSA -keysize 2048 -validity 10000 \
            -dname "CN=Android Debug,O=Android,C=US" 2>/dev/null
    fi

    "${APKSIGNER}" sign \
        --ks "${DEBUG_KEYSTORE}" \
        --ks-pass pass:android \
        --key-pass pass:android \
        --out "${BUILD_DIR}/SafeerCompanion.apk" \
        "${BUILD_DIR}/SafeerCompanion-aligned.apk"
    echo "⚠️  Podpisano z DEBUG ključem (samo za lokalni razvoj)."
fi

echo "=========================================================="
echo "✅ SafeerCompanion.apk uspešno zgrajen!"
echo "Pot: ${BUILD_DIR}/SafeerCompanion.apk"
echo "Velikost: $(du -h "${BUILD_DIR}/SafeerCompanion.apk" | cut -f1)"
echo "=========================================================="
