/// pre-read.sh — core hook for file read interception (M-09-A).
///
/// Receives tool input JSON on stdin. Decides allow/deny based on
/// confidence, quality, and confirmed status of the file record.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati pre-read hook — file read interception (M-09-A)
# Receives tool input JSON on stdin from Claude Code PreToolUse hook.
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

# ── Extract file path ─────────────────────────────────────────────────────
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // ""')
if [ -z "$FILE_PATH" ]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

# ── Graceful degradation: mati must be reachable ──────────────────────────
if ! mati ping &>/dev/null; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

# ── Lookup record ─────────────────────────────────────────────────────────
RECORD=$(mati get "file:$FILE_PATH" 2>/dev/null || echo "null")

if [ "$RECORD" = "null" ] || [ -z "$RECORD" ]; then
  # No record — allow + log miss in background
  mati log-miss "file:$FILE_PATH" &>/dev/null &
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

# ── Parse scores ──────────────────────────────────────────────────────────
CONFIDENCE=$(echo "$RECORD" | jq -r '.confidence.value // 0')
QUALITY=$(echo "$RECORD" | jq -r '.quality.value // 0')
CONFIRMED=$(echo "$RECORD" | jq -r '.confirmed // false')

# ── Decision matrix (ARCHITECTURE.md §10.1) ──────────────────────────────
# confirmed=true + confidence >= 0.6 + quality >= 0.4 → DENY + inject
# confidence >= 0.3 + quality >= 0.4 → allow + additionalContext
# else → allow, no injection

if [ "$CONFIRMED" = "true" ] && \
   [ "$(echo "$CONFIDENCE >= 0.6" | bc -l)" = "1" ] && \
   [ "$(echo "$QUALITY >= 0.4" | bc -l)" = "1" ]; then
  # DENY — inject record as reason
  mati log-hit "file:$FILE_PATH" &>/dev/null &
  cat <<DENY_EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[mati] Knowledge record exists for $FILE_PATH. Use mem_get(\"file:$FILE_PATH\") instead of reading the file directly."}}
DENY_EOF
  exit 0
fi

if [ "$(echo "$CONFIDENCE >= 0.3" | bc -l)" = "1" ] && \
   [ "$(echo "$QUALITY >= 0.4" | bc -l)" = "1" ]; then
  # ALLOW + additionalContext
  mati log-hit "file:$FILE_PATH" &>/dev/null &
  cat <<CTX_EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"[mati] Record available for $FILE_PATH (confidence $(printf '%.2f' "$CONFIDENCE")). Consider mem_get(\"file:$FILE_PATH\") for cached knowledge."}}
CTX_EOF
  exit 0
fi

# Default: allow, no injection
echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
"#;
