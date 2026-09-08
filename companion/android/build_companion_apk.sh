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

# Poišči Android SDK orodja
SDK_ROOT="/home/janez/Namizje/Neimenovana mapa/tv-browser-2/.android-sdk"
BUILD_TOOLS="${SDK_ROOT}/build-tools/34.0.0"
PLATFORM_DIR="${SDK_ROOT}/platforms/android-34"

AAPT2="${BUILD_TOOLS}/aapt2"
D8="${BUILD_TOOLS}/d8"
ZIPALIGN="${BUILD_TOOLS}/zipalign"
APKSIGNER="${BUILD_TOOLS}/apksigner"
ANDROID_JAR="${PLATFORM_DIR}/android.jar"

if [[ ! -f "$ANDROID_JAR" ]]; then
    # Poskusi najti katerikoli android.jar na sistemu
    ANDROID_JAR="$(find /home/janez -name "android.jar" 2>/dev/null | head -n 1 || true)"
fi

if [[ ! -f "$AAPT2" || ! -f "$D8" || ! -f "$ANDROID_JAR" ]]; then
    echo "OPOZORILO: Popolna Android SDK orodja niso na voljo. Preveri poti do AAPT2/D8."
    exit 1
fi

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

echo "=== [6/6] Zipalign in podpis z debug ključem ==="
DEBUG_KEYSTORE="${BUILD_DIR}/debug.keystore"
if [[ ! -f "$DEBUG_KEYSTORE" ]]; then
    keytool -genkeypair -v \
        -keystore "${DEBUG_KEYSTORE}" \
        -storepass android -keypass android \
        -alias androiddebugkey \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=Android Debug,O=Android,C=US" 2>/dev/null
fi

"${ZIPALIGN}" -f -p 4 "${BUILD_DIR}/unaligned.apk" "${BUILD_DIR}/SafeerCompanion-aligned.apk"

"${APKSIGNER}" sign \
    --ks "${DEBUG_KEYSTORE}" \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "${BUILD_DIR}/SafeerCompanion.apk" \
    "${BUILD_DIR}/SafeerCompanion-aligned.apk"

echo "=========================================================="
echo "✅ SafeerCompanion.apk uspešno zgrajen!"
echo "Pot: ${BUILD_DIR}/SafeerCompanion.apk"
echo "Velikost: $(du -h "${BUILD_DIR}/SafeerCompanion.apk" | cut -f1)"
echo "=========================================================="
