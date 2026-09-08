#!/bin/sh
# ==============================================================================
# Safeer Companion Standalone Watchdog Supervisor (POSIX sh / Android toybox)
# Zagotavlja neprekinjeno delovanje, PID zaklepanje, samodejno okrevanje
# in zaščito pred zankami sesutja (crash loop quarantine).
# ==============================================================================

COMPANION_BIN="${COMPANION_BIN:-/data/local/tmp/safeer-companion}"
COMPANION_PORT="${COMPANION_PORT:-8995}"
SECRET_FILE="${SECRET_FILE:-/data/local/tmp/companion.key}"
RISH_PATH="${RISH_PATH:-/data/local/tmp/rish}"
PID_FILE="${PID_FILE:-/data/local/tmp/safeer-companion.pid}"
LOG_FILE="${LOG_FILE:-/data/local/tmp/safeer-companion.log}"

# Preveri obstoj binarne datoteke
if [ ! -x "$COMPANION_BIN" ]; then
    echo "[Watchdog] NAPAKA: Binarni program $COMPANION_BIN ne obstaja ali ni izvršljiv (0700 required)!" >&2
    exit 1
fi

# Preveri Singleton tek (PID file)
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE" 2>/dev/null)
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        echo "[Watchdog] Safeer Companion že teče (PID: $OLD_PID). Izhod."
        exit 0
    fi
fi

echo $$ > "$PID_FILE"

cleanup() {
    echo "[Watchdog] Prejet signal za zaustavitev. Ustavljam podrejeni proces..."
    if [ -n "$CHILD_PID" ] && kill -0 "$CHILD_PID" 2>/dev/null; then
        kill "$CHILD_PID" 2>/dev/null
        wait "$CHILD_PID" 2>/dev/null
    fi
    rm -f "$PID_FILE"
    exit 0
}

trap cleanup INT TERM HUP

echo "[Watchdog] Zagon nadzornika za $COMPANION_BIN (Vrata: $COMPANION_PORT)..." >> "$LOG_FILE"

BACKOFF=1
CRASH_COUNT=0
WINDOW_START=$(date +%s 2>/dev/null || echo 0)

while true; do
    NOW=$(date +%s 2>/dev/null || echo 0)
    
    # Preveri crash-loop okno (več kot 5 zrušitev v 60s)
    if [ "$WINDOW_START" -gt 0 ] && [ $((NOW - WINDOW_START)) -gt 60 ]; then
        CRASH_COUNT=0
        WINDOW_START=$NOW
    fi

    if [ "$CRASH_COUNT" -ge 5 ]; then
        echo "[Watchdog] OPOZORILO: Zaznana zanka sesutij (> 5 v 60s). Karantena 60s..." >> "$LOG_FILE"
        sleep 60
        CRASH_COUNT=0
        WINDOW_START=$(date +%s 2>/dev/null || echo 0)
        BACKOFF=1
    fi

    START_TIME=$(date +%s 2>/dev/null || echo 0)
    
    # Zagon Companiona v ozadju z nadzorom
    "$COMPANION_BIN" \
        -port="$COMPANION_PORT" \
        -secret-file="$SECRET_FILE" \
        -rish-path="$RISH_PATH" ${COMPANION_EXTRA_ARGS:-} >> "$LOG_FILE" 2>&1 &
    
    CHILD_PID=$!
    wait "$CHILD_PID"
    EXIT_CODE=$?

    END_TIME=$(date +%s 2>/dev/null || echo 0)
    RUN_TIME=$((END_TIME - START_TIME))

    echo "[Watchdog] Companion proces (PID $CHILD_PID) se je končal (koda: $EXIT_CODE, čas: ${RUN_TIME}s)" >> "$LOG_FILE"

    if [ "$RUN_TIME" -lt 5 ]; then
        CRASH_COUNT=$((CRASH_COUNT + 1))
    else
        BACKOFF=1
    fi

    echo "[Watchdog] Ponovni zagon čez ${BACKOFF}s..." >> "$LOG_FILE"
    sleep "$BACKOFF"

    # Eksponentni odlog (1s, 2s, 4s ... max 30s)
    BACKOFF=$((BACKOFF * 2))
    if [ "$BACKOFF" -gt 30 ]; then
        BACKOFF=30
    fi
done
