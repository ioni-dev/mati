/// pre-read.sh — core hook for file read interception (M-09-A, M-13-D).
///
/// Receives tool input JSON on stdin. Decides allow/deny based on confirmed
/// gotcha records linked to the file, staleness tier, and session consulted state.
/// Once a file has been consulted via mem_get, deny is downgraded to allow+context.
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


# ── Extract file path ─────────────────────────────────────────────────────
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // ""')
if [ -z "$FILE_PATH" ]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

# ── Convert absolute path to repo-relative path ───────────────────────────
# Claude Code always passes absolute paths; mati store keys use relative paths.
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "")
if [ -n "$REPO_ROOT" ]; then
  REL_PATH="${FILE_PATH#$REPO_ROOT/}"
else
  REL_PATH="$FILE_PATH"
fi

# ── Safe path escaping for JSON output ────────────────────────────────────
SAFE_PATH=$(echo "$REL_PATH" | sed 's/\\/\\\\/g; s/"/\\"/g')

# ── Graceful degradation: mati must be reachable ──────────────────────────
if ! mati ping &>/dev/null; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

# ── Lookup record ─────────────────────────────────────────────────────────
RECORD=$(mati get "file:$REL_PATH" 2>/dev/null || echo "null")

if [ "$RECORD" = "null" ] || [ -z "$RECORD" ]; then
  # No record — allow + log miss in background
  mati log-miss "file:$REL_PATH" &>/dev/null &
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
  exit 0
fi

# ── Parse scores ──────────────────────────────────────────────────────────
CONFIDENCE=$(echo "$RECORD" | jq -r '.confidence.value // 0')
QUALITY=$(echo "$RECORD" | jq -r '.quality.value // 0')
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
  mati log-hit "file:$REL_PATH" &>/dev/null &
  cat <<LIABILITY_EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"[mati] WARNING: STALE record for $SAFE_PATH is a liability (staleness $(printf '%.2f' "$STALENESS")). Read the file directly — the cached record is too stale to trust."}}
LIABILITY_EOF
  exit 0
fi

# ── Decision matrix (ARCHITECTURE.md §10.1) ──────────────────────────────
# deny:              any linked gotcha is confirmed=true + confidence >= 0.6 + quality >= 0.4
# additionalContext: file confidence >= 0.3 + quality >= 0.4
# else:              allow, no injection
#
# The deny signal comes from linked gotcha records (not the file record itself,
# which has no confirmed field). One pass over gotcha_keys serves both the
# deny check and the additionalContext context building.

PURPOSE=$(echo "$RECORD" | jq -r '.value // ""')
CONTEXT_LINES=""
[ -n "$PURPOSE" ] && CONTEXT_LINES="Purpose: $PURPOSE"

DENY_SIGNAL=false
GOTCHA_KEYS=$(echo "$RECORD" | jq -r '.payload.gotcha_keys[]? // empty' 2>/dev/null || true)
while IFS= read -r gkey; do
  [ -z "$gkey" ] && continue
  GREC=$(mati get "$gkey" 2>/dev/null || echo "null")
  [ "$GREC" = "null" ] || [ -z "$GREC" ] && continue

  GCONFIRMED=$(echo "$GREC" | jq -r '.payload.confirmed // false')
  GCONFIDENCE=$(echo "$GREC" | jq -r '.confidence.value // 0')
  GQUALITY=$(echo "$GREC" | jq -r '.quality.value // 0')
  GRULE=$(echo "$GREC" | jq -r '.value // ""')

  # Strong confirmed gotcha → deny signal
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
  # This lets Claude read the file after reviewing gotchas via mem_get.
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
  # ALLOW + additionalContext

  # M-13-D: stale warning
  if awk "BEGIN { exit !($STALENESS >= 0.4) }"; then
    CONTEXT_LINES="${CONTEXT_LINES:+$CONTEXT_LINES\n}Warning: record staleness $(printf '%.2f' "$STALENESS") — verify critical details."
  fi

  mati log-hit "file:$REL_PATH" &>/dev/null &

  CONTEXT_BODY="${CONTEXT_LINES:-Record exists for $SAFE_PATH — confidence $(printf '%.2f' "$CONFIDENCE")}"
  SAFE_CONTEXT=$(printf '%s' "$CONTEXT_BODY" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' ' | sed 's/\\n/\\n/g')
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"[mati] %s"}}\n' "$SAFE_CONTEXT"
  exit 0
fi

# Default: allow, no injection
echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
"#;
