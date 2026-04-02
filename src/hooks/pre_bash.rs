/// pre-bash.sh — catch cat/less/head/tail/bat/grep/rg file reads (M-09-B, M-13-D).
///
/// Detects common file-reading Bash commands and delegates to the same gotcha-based
/// decision logic as pre-read.sh. 2-5% miss rate accepted (C9 in ARCHITECTURE.md).
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati pre-bash hook — file-reading command detection (M-09-B, M-13-D staleness)
#
# Enforcement decision matrix:
#   confirmed + confidence >= 0.6 + quality >= 0.4  ->  DENY read (must call mem_get first)
#   file record + confidence 0.3-0.6 + quality >= 0.4  ->  ALLOW + attach context hint
#   no record or below threshold  ->  ALLOW + log gap for detection
#   agent already consulted (receipt valid)  ->  ALLOW (context already injected)
#   mati daemon unreachable  ->  ALLOW (fail-open)
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"

INPUT=$(cat)

# ── Guards ─────────────────────────────────────────────────────────────────
if ! command -v jq &>/dev/null || ! command -v awk &>/dev/null; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi


# ── Extract command ───────────────────────────────────────────────────────
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null || echo "")
if [ -z "$CMD" ]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

# ── Detect file-reading commands ──────────────────────────────────────────
# cat/less/head/tail/bat: file path is first non-flag arg.
# grep/rg: file path is LAST non-flag arg (pattern comes first).
# Handle both quoted paths (with spaces) and bare paths.
if echo "$CMD" | grep -qE '^\s*(cat|less|head|tail|bat)\s+'; then
  # Prefer quoted path (handles spaces in directory names)
  # Use || true: grep exits 1 when no match, which would kill script under pipefail
  FILE_PATH=$(echo "$CMD" | grep -oE '"[^"]+"' | head -1 | tr -d '"' || true)
  if [ -z "$FILE_PATH" ]; then
    # Fallback: first non-flag word after command name
    FILE_PATH=$(echo "$CMD" | grep -oE '^\s*(cat|less|head|tail|bat)\s+[^|;&]+' | awk '{for(i=2;i<=NF;i++){if($i !~ /^-/){print $i; exit}}}' || true)
  fi
elif echo "$CMD" | grep -qE '^\s*(grep|rg)\s+'; then
  # For grep/rg: file is the LAST non-flag argument (pattern precedes it).
  # Use || true to prevent pipefail exit when no quoted path found.
  FILE_PATH=$(echo "$CMD" | grep -oE '"[^"]+"' | tail -1 | tr -d '"' || true)
  if [ -z "$FILE_PATH" ]; then
    FILE_PATH=$(echo "$CMD" | grep -oE '^\s*(grep|rg)\s+[^|;&]+' | awk '{last=""; for(i=2;i<=NF;i++){if($i !~ /^-/){last=$i}}; print last}' || true)
    # Strip surrounding single-quotes (grep pattern like 'pattern' -> bare word)
    FILE_PATH=$(echo "$FILE_PATH" | sed "s/^'//;s/'$//" || true)
  fi
else
  FILE_PATH=""
fi

if [ -z "$FILE_PATH" ]; then
  # No file-reading pattern detected — allow unconditionally
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

# ── Convert absolute path to repo-relative path ───────────────────────────
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "")
if [ -n "$REPO_ROOT" ]; then
  REL_PATH="${FILE_PATH#$REPO_ROOT/}"
else
  REL_PATH="$FILE_PATH"
fi

# ── Safe path escaping for JSON output ────────────────────────────────────
SAFE_PATH=$(echo "$REL_PATH" | sed 's/\\/\\\\/g; s/"/\\"/g')

# ── Delegate to pre-read decision logic ───────────────────────────────────

# Graceful degradation
if ! mati ping &>/dev/null; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

RECORD=$(mati get "file:$REL_PATH" 2>/dev/null || echo "null")

if [ "$RECORD" = "null" ] || [ -z "$RECORD" ]; then
  mati log-miss "file:$REL_PATH" &>/dev/null &
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

if ! echo "$RECORD" | jq -e 'type == "object"' >/dev/null 2>&1; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

CONFIDENCE=$(echo "$RECORD" | jq -r '.confidence.value // 0')
QUALITY=$(echo "$RECORD" | jq -r '.quality.value // 0')
STALENESS=$(echo "$RECORD" | jq -r '.staleness.value // 0')
STALENESS_TIER=$(echo "$RECORD" | jq -r '.staleness.tier // "fresh"')

# ── M-13-D: Tombstone early-exit ─────────────────────────────────────────
if [ "$STALENESS_TIER" = "tombstone" ]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

# ── M-13-D: Liability downgrade ──────────────────────────────────────────
if [ "$STALENESS_TIER" = "liability" ]; then
  mati log-hit "file:$REL_PATH" &>/dev/null &
  cat <<LIABILITY_EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"[mati] WARNING: STALE record for $SAFE_PATH is a liability (staleness $(printf '%.2f' "$STALENESS")). Read the file directly — the cached record is too stale to trust."}}
LIABILITY_EOF
  exit 0
fi

# ── Decision matrix (mirrors pre-read.sh) ────────────────────────────────
# One pass over gotcha_keys: check deny signal + build context simultaneously.
PURPOSE=$(echo "$RECORD" | jq -r '.value // ""')
CONTEXT_LINES=""
[ -n "$PURPOSE" ] && CONTEXT_LINES="Purpose: $PURPOSE"

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
  GRULE=$(echo "$GREC" | jq -r '.value // ""')

  if [ "$GCONFIRMED" = "true" ] && \
     awk "BEGIN { exit !($GCONFIDENCE >= 0.6) }" && \
     awk "BEGIN { exit !($GQUALITY >= 0.4) }"; then
    DENY_SIGNAL=true
  fi

  [ -n "$GRULE" ] && CONTEXT_LINES="${CONTEXT_LINES:+$CONTEXT_LINES\n}⚠ $GRULE"
done <<< "$GOTCHA_KEYS"

if [ "$DENY_SIGNAL" = "true" ]; then
  mati log-hit "file:$REL_PATH" &>/dev/null &

  # If already consulted via mem_get this session, downgrade deny → allow+context.
  ALREADY_CONSULTED=$(mati session-check-consulted "file:$REL_PATH" 2>/dev/null || echo "false")
  if [ "$ALREADY_CONSULTED" = "true" ]; then
    CONTEXT_BODY="${CONTEXT_LINES:-Gotcha exists for $SAFE_PATH — proceed with awareness}"
    SAFE_CONTEXT=$(printf '%s' "$CONTEXT_BODY" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' ' | sed 's/\\n/\\n/g')
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"[mati] Record already consulted. %s"}}\n' "$SAFE_CONTEXT"
    exit 0
  fi

  STALE_NOTE=""
  if awk "BEGIN { exit !($STALENESS >= 0.4) }"; then
    STALE_NOTE=" (staleness $(printf '%.2f' "$STALENESS") — verify critical details)"
  fi

  cat <<DENY_EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[mati] Confirmed gotcha on $SAFE_PATH — call mem_get(\"file:$SAFE_PATH\") and read the record before accessing this file.${STALE_NOTE}"}}
DENY_EOF
  exit 0
fi

if awk "BEGIN { exit !($CONFIDENCE >= 0.3) }" && \
   awk "BEGIN { exit !($QUALITY >= 0.4) }"; then
  if awk "BEGIN { exit !($STALENESS >= 0.4) }"; then
    CONTEXT_LINES="${CONTEXT_LINES:+$CONTEXT_LINES\n}Warning: record staleness $(printf '%.2f' "$STALENESS") — verify critical details."
  fi

  mati log-hit "file:$REL_PATH" &>/dev/null &

  CONTEXT_BODY="${CONTEXT_LINES:-Record exists for $SAFE_PATH — confidence $(printf '%.2f' "$CONFIDENCE")}"
  SAFE_CONTEXT=$(printf '%s' "$CONTEXT_BODY" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' ' | sed 's/\\n/\\n/g')
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"[mati] %s"}}\n' "$SAFE_CONTEXT"
  exit 0
fi

echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
"#;
