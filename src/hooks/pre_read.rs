/// pre-read.sh — core hook for file read interception (M-09-A, M-13-D).
///
/// Receives tool input JSON on stdin. Decides allow/deny based on
/// confidence, quality, confirmed status, and staleness tier of the file record.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati pre-read hook — file read interception (M-09-A, M-13-D staleness)
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

# ── Safe path escaping for JSON output ────────────────────────────────────
SAFE_PATH=$(echo "$FILE_PATH" | sed 's/\\/\\\\/g; s/"/\\"/g')

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
STALENESS=$(echo "$RECORD" | jq -r '.staleness.value // 0')
STALENESS_TIER=$(echo "$RECORD" | jq -r '.staleness.tier // "fresh"')

# ── M-13-D: Tombstone early-exit ─────────────────────────────────────────
# Tombstone records are fully excluded. Allow file read unconditionally.
if [ "$STALENESS_TIER" = "tombstone" ]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

# ── M-13-D: Liability downgrade ──────────────────────────────────────────
# Liability-tier records are too stale to trust. Downgrade deny to allow
# with a warning, regardless of confidence/quality.
if [ "$STALENESS_TIER" = "liability" ]; then
  mati log-hit "file:$FILE_PATH" &>/dev/null &
  cat <<LIABILITY_EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"[mati] WARNING: STALE record for $SAFE_PATH is a liability (staleness $(printf '%.2f' "$STALENESS")). Read the file directly — the cached record is too stale to trust."}}
LIABILITY_EOF
  exit 0
fi

# ── Decision matrix (ARCHITECTURE.md §10.1) ──────────────────────────────
# confirmed=true + confidence >= 0.6 + quality >= 0.4 → DENY + inject
# confidence >= 0.3 + quality >= 0.4 → allow + additionalContext
# else → allow, no injection

if [ "$CONFIRMED" = "true" ] && \
   [ "$(echo "$CONFIDENCE >= 0.6" | bc -l)" = "1" ] && \
   [ "$(echo "$QUALITY >= 0.4" | bc -l)" = "1" ]; then
  # DENY — inject record as reason
  mati log-hit "file:$FILE_PATH" &>/dev/null &

  # M-13-D: medium-confidence stale note
  STALE_NOTE=""
  if [ "$(echo "$STALENESS >= 0.4" | bc -l)" = "1" ]; then
    STALE_NOTE=" (staleness $(printf '%.2f' "$STALENESS") — verify critical details)"
  fi

  cat <<DENY_EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[mati] Knowledge record exists for $SAFE_PATH. Use mem_get(\"file:$SAFE_PATH\") instead of reading the file directly.${STALE_NOTE}"}}
DENY_EOF
  exit 0
fi

if [ "$(echo "$CONFIDENCE >= 0.3" | bc -l)" = "1" ] && \
   [ "$(echo "$QUALITY >= 0.4" | bc -l)" = "1" ]; then
  # ALLOW + additionalContext
  mati log-hit "file:$FILE_PATH" &>/dev/null &

  # M-13-D: medium-confidence stale note
  STALE_NOTE=""
  if [ "$(echo "$STALENESS >= 0.4" | bc -l)" = "1" ]; then
    STALE_NOTE=" Warning: staleness $(printf '%.2f' "$STALENESS") — cached knowledge may be outdated."
  fi

  cat <<CTX_EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"[mati] Record available for $SAFE_PATH (confidence $(printf '%.2f' "$CONFIDENCE")). Consider mem_get(\"file:$SAFE_PATH\") for cached knowledge.${STALE_NOTE}"}}
CTX_EOF
  exit 0
fi

# Default: allow, no injection
echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
"#;
