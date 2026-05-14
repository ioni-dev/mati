#!/usr/bin/env bash
#
# codesign-proc-macros.sh — re-sign Rust proc-macro dylibs so AMFI stops
# logging "has no CMS blob?" warnings on every load.
#
# Background:
#   rustc's macOS link step emits an ad-hoc signature with the "linker-signed"
#   shortcut, which omits the CMS special slot. AMFI logs two kernel warnings
#   per dylib load when that slot is missing. Running `codesign -s - --force`
#   replaces the linker shortcut with a full ad-hoc signature that includes
#   the CMS slot, silencing the warning. Output dylib is functionally
#   identical (same hashes, same load addresses).
#
# Usage:
#   ./scripts/codesign-proc-macros.sh             # signs target/{debug,release}/deps
#   ./scripts/codesign-proc-macros.sh --check     # dry-run, exits non-zero if any need signing
#
# This is idempotent — already-signed dylibs are skipped.

set -euo pipefail
if ! ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi
cd "$ROOT"

CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

SIGNED=0
SKIPPED=0
NEEDS=0

shopt -s nullglob
for dylib in target/debug/deps/*.dylib target/release/deps/*.dylib; do
    flags=$(codesign -dvv "$dylib" 2>&1 | awk '/CodeDirectory/ {sub(/.*flags=/, ""); print; exit}')
    if printf '%s' "$flags" | grep -q 'linker-signed'; then
        if [ "$CHECK_ONLY" = 1 ]; then
            NEEDS=$((NEEDS + 1))
            echo "needs signing: $dylib"
        else
            codesign -s - --force "$dylib" >/dev/null 2>&1 && SIGNED=$((SIGNED + 1))
        fi
    else
        SKIPPED=$((SKIPPED + 1))
    fi
done

if [ "$CHECK_ONLY" = 1 ]; then
    echo "$NEEDS dylib(s) need re-signing, $SKIPPED already signed"
    [ "$NEEDS" -gt 0 ] && exit 1
    exit 0
fi

echo "re-signed $SIGNED, skipped $SKIPPED already-signed dylib(s)"
