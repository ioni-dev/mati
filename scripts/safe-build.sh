#!/usr/bin/env bash
#
# safe-build.sh — drop-in cargo wrapper that mitigates logd kernel panics
# observed during heavy parallel rustc on M3 Apple Silicon.
#
# What it does:
#   1. Refuses to start if logd is already not responding (avoids piling on).
#   2. Re-signs existing proc-macro dylibs to silence AMFI noise.
#   3. Caps -j based on RAM and physical-cores headroom.
#   4. Runs cargo under macOS background QoS (`taskpolicy -b`) + `nice -n 5`
#      so logd / WindowServer always win the scheduler.
#   5. Streams the kernel log in the background. If kernel log rate exceeds
#      a threshold, the build is SIGSTOPped to let logd drain, then SIGCONTed.
#      (Pause, not kill — much safer than a hard abort mid-link.)
#
# Usage:
#   ./scripts/safe-build.sh cargo build --release
#   ./scripts/safe-build.sh cargo test --no-run
#   ./scripts/safe-build.sh cargo clippy --workspace
#
# Knobs (env vars):
#   SAFE_BUILD_RATE_THRESHOLD   pause when kernel log lines/sec exceeds this
#                               (default 1500; ANE chatter alone is ~10/sec)
#   SAFE_BUILD_PAUSE_SEC        seconds to keep build paused on threshold hit
#                               (default 10)
#   SAFE_BUILD_JOBS             override -j (default: computed from RAM)
#   SAFE_BUILD_NO_RESIGN        set to 1 to skip the codesign-proc-macros pass
#   SAFE_BUILD_DRY_RUN          set to 1 to print what would run and exit

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <command> [args...]" >&2
    echo "       $0 cargo build --release" >&2
    exit 64
fi

if ! ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi
cd "$ROOT"

# ---- 1. preflight: is logd healthy? ----
# `log stream` with --timeout doesn't exist; instead we ask `log show` for the
# last 30s of logd activity. If it returns nothing, logd is hung.
preflight_logd() {
    local out
    out=$(log show --last 30s --predicate 'process == "logd"' --style compact 2>/dev/null \
          | head -3 || true)
    if [ -z "$out" ]; then
        echo "safe-build: logd is unresponsive (no output in 30s window). Refusing to start." >&2
        echo "safe-build: try waiting a few minutes, then re-running. If it persists, reboot." >&2
        return 1
    fi
}
preflight_logd

# ---- 2. re-sign proc-macro dylibs from previous build ----
if [ "${SAFE_BUILD_NO_RESIGN:-0}" != "1" ] && [ -x "$ROOT/scripts/codesign-proc-macros.sh" ]; then
    "$ROOT/scripts/codesign-proc-macros.sh" >/dev/null 2>&1 || true
fi

# ---- 3. compute -j ----
TOTAL_MEM_GB=$(($(sysctl -n hw.memsize) / 1024 / 1024 / 1024))
PHYS_CORES=$(sysctl -n hw.physicalcpu)
# 1 rustc per ~3 GB of RAM, capped to physical_cores - 2 (leave headroom for
# logd, WindowServer, kernel). Floor of 1.
JOBS_BY_RAM=$((TOTAL_MEM_GB / 3))
JOBS_CAP=$((PHYS_CORES - 2))
JOBS=$(( JOBS_BY_RAM < JOBS_CAP ? JOBS_BY_RAM : JOBS_CAP ))
[ "$JOBS" -lt 1 ] && JOBS=1
JOBS="${SAFE_BUILD_JOBS:-$JOBS}"

# ---- 4. assemble the command ----
cmd=("$@")
# Inject -j only for cargo and only if not already specified.
inject_j=1
if [ "${cmd[0]}" = "cargo" ]; then
    for a in "${cmd[@]}"; do
        case "$a" in
            -j|--jobs|-j*|--jobs=*) inject_j=0 ;;
        esac
    done
    [ "$inject_j" = 1 ] && cmd+=(-j "$JOBS")
fi

THRESH="${SAFE_BUILD_RATE_THRESHOLD:-1500}"
PAUSE_SEC="${SAFE_BUILD_PAUSE_SEC:-10}"

echo "safe-build: -j $JOBS  threshold ${THRESH} lines/sec  pause ${PAUSE_SEC}s on breach"
echo "safe-build: cmd: ${cmd[*]}"

if [ "${SAFE_BUILD_DRY_RUN:-0}" = "1" ]; then
    echo "safe-build: dry run — exiting"
    exit 0
fi

# ---- 5. background log streamer ----
LOG_FILE="$(mktemp -t mati-safebuild-kernel-XXXXXX)"
log stream --predicate 'process == "kernel"' --style compact > "$LOG_FILE" 2>/dev/null &
LOG_PID=$!
sleep 1

# ---- 6. launch cargo in its own process group ----
# `set -m` enables job control in the subshell so cargo gets its own pgid.
(set -m; exec taskpolicy -b nice -n 5 "${cmd[@]}") &
BUILD_PID=$!

cleanup() {
    kill "$LOG_PID" 2>/dev/null || true
    wait "$LOG_PID" 2>/dev/null || true
    rm -f "$LOG_FILE"
}
trap cleanup EXIT

# ---- 7. watcher: pause the build group when log rate spikes ----
PREV_LINES=0
while kill -0 "$BUILD_PID" 2>/dev/null; do
    sleep 5
    NOW_LINES=$(wc -l < "$LOG_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    DELTA=$(( (NOW_LINES - PREV_LINES) / 5 ))
    PREV_LINES=$NOW_LINES
    if [ "$DELTA" -gt "$THRESH" ]; then
        echo "safe-build: kernel log ${DELTA}/sec > ${THRESH}/sec — SIGSTOP for ${PAUSE_SEC}s" >&2
        kill -STOP -- -"$BUILD_PID" 2>/dev/null || kill -STOP "$BUILD_PID" 2>/dev/null || true
        sleep "$PAUSE_SEC"
        kill -CONT -- -"$BUILD_PID" 2>/dev/null || kill -CONT "$BUILD_PID" 2>/dev/null || true
        # Reset baseline so the post-pause reading isn't compared against pre-pause.
        PREV_LINES=$(wc -l < "$LOG_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    fi
done

wait "$BUILD_PID" 2>/dev/null
RC=$?

# ---- 8. report ----
TOTAL=$(wc -l < "$LOG_FILE" | tr -d ' ')
AMFI=$(grep -c -i 'AMFI' "$LOG_FILE" 2>/dev/null || true)
echo "safe-build: done — exit $RC, $TOTAL kernel lines captured ($AMFI AMFI)"

# Re-sign anything we built this run, too.
if [ "${SAFE_BUILD_NO_RESIGN:-0}" != "1" ] && [ -x "$ROOT/scripts/codesign-proc-macros.sh" ]; then
    "$ROOT/scripts/codesign-proc-macros.sh" >/dev/null 2>&1 || true
fi

exit "$RC"
