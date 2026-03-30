/// Codex PreToolUse(Bash) hook.
///
/// This is the hard-enforcement path available on Codex today.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"

INPUT=$(cat)

if ! command -v jq >/dev/null 2>&1 || ! command -v awk >/dev/null 2>&1; then
  exit 0
fi

TTL_SECS=900

CMD=$(echo "$INPUT" | jq -r '.tool_input.command // .command // ""' 2>/dev/null || echo "")
[ -z "$CMD" ] && exit 0

if echo "$CMD" | grep -qE '^\s*(cat|less|head|tail|bat)\s+'; then
  FILE_PATH=$(echo "$CMD" | grep -oE '"[^"]+"' | head -1 | tr -d '"' || true)
  if [ -z "$FILE_PATH" ]; then
    FILE_PATH=$(echo "$CMD" | grep -oE '^\s*(cat|less|head|tail|bat)\s+[^|;&]+' | awk '{for(i=2;i<=NF;i++){if($i !~ /^-/){print $i; exit}}}' || true)
  fi
elif echo "$CMD" | grep -qE '^\s*(grep|rg|sed|awk)\s+'; then
  FILE_PATH=$(echo "$CMD" | grep -oE '"[^"]+"' | tail -1 | tr -d '"' || true)
  if [ -z "$FILE_PATH" ]; then
    FILE_PATH=$(echo "$CMD" | grep -oE '^\s*(grep|rg|sed|awk)\s+[^|;&]+' | awk '{last=""; for(i=2;i<=NF;i++){if($i !~ /^-/){last=$i}}; print last}' || true)
    FILE_PATH=$(echo "$FILE_PATH" | sed "s/^'//;s/'$//" || true)
  fi
else
  FILE_PATH=""
fi

[ -z "$FILE_PATH" ] && exit 0

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "")
if [ -n "$REPO_ROOT" ]; then
  REL_PATH="${FILE_PATH#$REPO_ROOT/}"
else
  REL_PATH="$FILE_PATH"
fi

SAFE_PATH=$(echo "$REL_PATH" | sed 's/\\/\\\\/g; s/"/\\"/g')

if ! mati ping >/dev/null 2>&1; then
  exit 0
fi

RECORD=$(mati get "file:$REL_PATH" 2>/dev/null || echo "null")
if [ "$RECORD" = "null" ] || [ -z "$RECORD" ]; then
  mati log-miss "file:$REL_PATH" >/dev/null 2>&1 || true
  exit 0
fi

if ! echo "$RECORD" | jq -e 'type == "object"' >/dev/null 2>&1; then
  exit 0
fi

CONFIDENCE=$(echo "$RECORD" | jq -r '.confidence.value // 0')
QUALITY=$(echo "$RECORD" | jq -r '.quality.value // 0')
STALENESS=$(echo "$RECORD" | jq -r '.staleness.value // 0')
STALENESS_TIER=$(echo "$RECORD" | jq -r '.staleness.tier // "fresh"')
IS_HOTSPOT=$(echo "$RECORD" | jq -r '.payload.is_hotspot // false')

[ "$STALENESS_TIER" = "tombstone" ] && exit 0

if [ "$STALENESS_TIER" = "liability" ]; then
  exit 0
fi

RECENT=$(mati session-check-consulted-recent "file:$REL_PATH" --ttl-secs "$TTL_SECS" 2>/dev/null || echo "false")

DENY_SIGNAL=false
GOTCHA_KEYS=$(echo "$RECORD" | jq -r '.payload.gotcha_keys[]? // empty' 2>/dev/null || true)
while IFS= read -r gkey; do
  [ -z "$gkey" ] && continue
  GREC=$(mati get "$gkey" 2>/dev/null || echo "null")
  [ "$GREC" = "null" ] || [ -z "$GREC" ] && continue
  if ! echo "$GREC" | jq -e 'type == "object"' >/dev/null 2>&1; then
    continue
  fi
  GCONFIRMED=$(echo "$GREC" | jq -r '.payload.confirmed // false')
  GCONFIDENCE=$(echo "$GREC" | jq -r '.confidence.value // 0')
  GQUALITY=$(echo "$GREC" | jq -r '.quality.value // 0')
  if [ "$GCONFIRMED" = "true" ] && \
     awk "BEGIN { exit !($GCONFIDENCE >= 0.6) }" && \
     awk "BEGIN { exit !($GQUALITY >= 0.4) }"; then
    DENY_SIGNAL=true
  fi
done <<< "$GOTCHA_KEYS"

if [ "$DENY_SIGNAL" = "true" ] && [ "$RECENT" != "true" ]; then
  mati log-codex-shell-miss "file:$REL_PATH" >/dev/null 2>&1 || true
  STALE_NOTE=""
  if awk "BEGIN { exit !($STALENESS >= 0.4) }"; then
    STALE_NOTE=" Verify critical details because the cached record is stale."
  fi
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[mati] Confirmed gotcha on %s. Call mem_get(\\"file:%s\\") before shell inspection.%s"}}\n' "$SAFE_PATH" "$SAFE_PATH" "$STALE_NOTE"
  exit 0
fi

if [ "$RECENT" != "true" ] && \
   { [ "$IS_HOTSPOT" = "true" ] || \
     { awk "BEGIN { exit !($CONFIDENCE >= 0.3) }" && awk "BEGIN { exit !($QUALITY >= 0.4) }"; }; }; then
  printf '{"systemMessage":"[mati] Before shell-inspecting %s, call mem_get(\\"file:%s\\") so Codex has the project memory first."}\n' "$SAFE_PATH" "$SAFE_PATH"
fi
"#;
