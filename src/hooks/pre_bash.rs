/// pre-bash.sh — catch cat/less/head/tail/bat file reads (M-09-B, M-13-D).
///
/// Detects `cat|less|head|tail|bat <file>` from the command field in stdin JSON.
/// If a file pattern is found, delegates to the same decision logic as pre-read.
/// 2-5% miss rate is accepted (C9).
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati pre-bash hook — cat/less/head/tail/bat detection (M-09-B, M-13-D staleness)
set -euo pipefail

INPUT=$(cat)

# ── Guards ─────────────────────────────────────────────────────────────────
if ! command -v jq &>/dev/null; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi


# ── Extract command ───────────────────────────────────────────────────────
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // ""')
if [ -z "$CMD" ]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

# ── Detect file-reading commands ──────────────────────────────────────────
# Match: cat/less/head/tail/bat followed by optional flags then a file path.
# Skip words starting with - (flags like -n, -5, -f).
FILE_PATH=$(echo "$CMD" | grep -oE '^\s*(cat|less|head|tail|bat)\s+[^|;&]+' | awk '{for(i=2;i<=NF;i++){if($i !~ /^-/){print $i; exit}}}' || true)

if [ -z "$FILE_PATH" ]; then
  # No file-reading pattern detected — allow unconditionally
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

# ── Safe path escaping for JSON output ────────────────────────────────────
SAFE_PATH=$(echo "$FILE_PATH" | sed 's/\\/\\\\/g; s/"/\\"/g')

# ── Delegate to pre-read decision logic ───────────────────────────────────

# Graceful degradation
if ! mati ping &>/dev/null; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

RECORD=$(mati get "file:$FILE_PATH" 2>/dev/null || echo "null")

if [ "$RECORD" = "null" ] || [ -z "$RECORD" ]; then
  mati log-miss "file:$FILE_PATH" &>/dev/null &
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

CONFIDENCE=$(echo "$RECORD" | jq -r '.confidence.value // 0')
QUALITY=$(echo "$RECORD" | jq -r '.quality.value // 0')
CONFIRMED=$(echo "$RECORD" | jq -r '.confirmed // false')
STALENESS=$(echo "$RECORD" | jq -r '.staleness.value // 0')
STALENESS_TIER=$(echo "$RECORD" | jq -r '.staleness.tier // "fresh"')

# ── M-13-D: Tombstone early-exit ─────────────────────────────────────────
if [ "$STALENESS_TIER" = "tombstone" ]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

# ── M-13-D: Liability downgrade ──────────────────────────────────────────
if [ "$STALENESS_TIER" = "liability" ]; then
  mati log-hit "file:$FILE_PATH" &>/dev/null &
  cat <<LIABILITY_EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"[mati] WARNING: STALE record for $SAFE_PATH is a liability (staleness $(printf '%.2f' "$STALENESS")). Read the file directly — the cached record is too stale to trust."}}
LIABILITY_EOF
  exit 0
fi

if [ "$CONFIRMED" = "true" ] && \
   awk "BEGIN { exit !($CONFIDENCE >= 0.6) }" && \
   awk "BEGIN { exit !($QUALITY >= 0.4) }"; then
  mati log-hit "file:$FILE_PATH" &>/dev/null &

  # M-13-D: medium-confidence stale note
  STALE_NOTE=""
  if awk "BEGIN { exit !($STALENESS >= 0.4) }"; then
    STALE_NOTE=" (staleness $(printf '%.2f' "$STALENESS") — verify critical details)"
  fi

  cat <<DENY_EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[mati] Knowledge record exists for $SAFE_PATH. Use mem_get(\"file:$SAFE_PATH\") instead of reading the file directly.${STALE_NOTE}"}}
DENY_EOF
  exit 0
fi

if awk "BEGIN { exit !($CONFIDENCE >= 0.3) }" && \
   awk "BEGIN { exit !($QUALITY >= 0.4) }"; then
  mati log-hit "file:$FILE_PATH" &>/dev/null &

  # M-13-D: medium-confidence stale note
  STALE_NOTE=""
  if awk "BEGIN { exit !($STALENESS >= 0.4) }"; then
    STALE_NOTE=" Warning: staleness $(printf '%.2f' "$STALENESS") — cached knowledge may be outdated."
  fi

  cat <<CTX_EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"[mati] Record available for $SAFE_PATH (confidence $(printf '%.2f' "$CONFIDENCE")). Consider mem_get(\"file:$SAFE_PATH\") for cached knowledge.${STALE_NOTE}"}}
CTX_EOF
  exit 0
fi

echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
"#;
