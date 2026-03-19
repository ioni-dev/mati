/// pre-bash.sh — catch cat/less/head/tail/bat file reads (M-09-B).
///
/// Detects `cat|less|head|tail|bat <file>` from the command field in stdin JSON.
/// If a file pattern is found, delegates to the same decision logic as pre-read.
/// 2-5% miss rate is accepted (C9).
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati pre-bash hook — cat/less/head/tail/bat detection (M-09-B)
set -euo pipefail

INPUT=$(cat)

# ── Guards ─────────────────────────────────────────────────────────────────
if ! command -v jq &>/dev/null; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

if ! command -v bc &>/dev/null; then
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

if [ "$CONFIRMED" = "true" ] && \
   [ "$(echo "$CONFIDENCE >= 0.6" | bc -l)" = "1" ] && \
   [ "$(echo "$QUALITY >= 0.4" | bc -l)" = "1" ]; then
  mati log-hit "file:$FILE_PATH" &>/dev/null &
  cat <<DENY_EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[mati] Knowledge record exists for $FILE_PATH. Use mem_get(\"file:$FILE_PATH\") instead of reading the file directly."}}
DENY_EOF
  exit 0
fi

if [ "$(echo "$CONFIDENCE >= 0.3" | bc -l)" = "1" ] && \
   [ "$(echo "$QUALITY >= 0.4" | bc -l)" = "1" ]; then
  mati log-hit "file:$FILE_PATH" &>/dev/null &
  cat <<CTX_EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"[mati] Record available for $FILE_PATH (confidence $(printf '%.2f' "$CONFIDENCE")). Consider mem_get(\"file:$FILE_PATH\") for cached knowledge."}}
CTX_EOF
  exit 0
fi

echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
"#;
