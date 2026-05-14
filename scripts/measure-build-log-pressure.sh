#!/usr/bin/env bash
#
# measure-build-log-pressure.sh — quantify kernel log volume during a build.
#
# Streams `log stream --predicate 'process == "kernel"'` into a file while the
# given command runs, then reports total / per-second / peak rates and breaks
# out the two log producers we care about: AMFI (proc-macro dylib loads with
# no CMS blob) and ANE NO_ACCESS errors.
#
# Usage:
#   ./scripts/measure-build-log-pressure.sh cargo check
#   ./scripts/measure-build-log-pressure.sh cargo build --release
#   ./scripts/measure-build-log-pressure.sh cargo test --no-run
#
# Output goes to /tmp/mati-log-pressure/kernel-<timestamp>.log so you can
# diff successive runs.

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 64
fi

if ! ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi
cd "$ROOT"

OUT_DIR="${OUT_DIR:-/tmp/mati-log-pressure}"
mkdir -p "$OUT_DIR"
TS=$(date +%Y%m%d-%H%M%S)
LOG="$OUT_DIR/kernel-$TS.log"

cleanup() {
    if [ -n "${LOG_PID:-}" ] && kill -0 "$LOG_PID" 2>/dev/null; then
        kill "$LOG_PID" 2>/dev/null || true
        wait "$LOG_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "→ kernel log capture: $LOG"
log stream --predicate 'process == "kernel"' --style compact > "$LOG" 2>/dev/null &
LOG_PID=$!
sleep 1

START=$(date +%s)
echo "→ running: $*"
set +e
"$@"
RC=$?
set -e
END=$(date +%s)
DUR=$((END - START))
[ "$DUR" -lt 1 ] && DUR=1

cleanup

TOTAL=$(wc -l < "$LOG" | tr -d ' ')
AMFI=$(grep -c -i 'AMFI' "$LOG" 2>/dev/null || true)
AMFI_CMS=$(grep -c 'has no CMS blob\|Unrecoverable CT signature' "$LOG" 2>/dev/null || true)
ANE=$(grep -c 'NO_ACCESS\|niGeneral' "$LOG" 2>/dev/null || true)

# Per-second peak: bucket by HH:MM:SS prefix of timestamp column 2
PEAK=$(awk '/^[0-9]{4}-[0-9]{2}-[0-9]{2}/ {
    n = split($2, t, ".")
    bucket = t[1]
    seen[bucket]++
}
END {
    max = 0
    for (b in seen) if (seen[b] > max) max = seen[b]
    print max + 0
}' "$LOG")

cat <<EOF

=== log pressure report (duration ${DUR}s) ===
total kernel lines        $TOTAL
  AMFI lines              $AMFI
    └ proc-macro CMS      $AMFI_CMS
  ANE NO_ACCESS / NI0     $ANE
average rate              $((TOTAL / DUR)) lines/sec
peak rate (any 1s)        ${PEAK} lines/sec

capture                   $LOG
build exit code           $RC
EOF

exit $RC
