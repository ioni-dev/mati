/// Codex PostToolUse(Bash) hook.
///
/// Logs shell-read compliance and adds a corrective reminder after misses.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"

INPUT=$(cat)

if ! command -v jq >/dev/null 2>&1 || ! command -v awk >/dev/null 2>&1; then
  echo "[mati] missing jq or awk — enforcement bypassed" >&2
  { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) FAIL_OPEN hook=$(basename "$0") reason=missing_deps" >> "${HOME}/.mati/fail_open.log"; } 2>/dev/null || true
  exit 0
fi

TTL_SECS=900

CMD=$(printf '%s\n' "$INPUT" | jq -r '.tool_input.command // .command // ""' 2>/dev/null || echo "")
[ -z "$CMD" ] && exit 0

if printf '%s\n' "$CMD" | grep -qE '^\s*(cat|less|head|tail|bat)\s+'; then
  FILE_PATH=$(printf '%s\n' "$CMD" | grep -oE '"[^"]+"' | head -1 | tr -d '"' || true)
  if [ -z "$FILE_PATH" ]; then
    FILE_PATH=$(printf '%s\n' "$CMD" | grep -oE '^\s*(cat|less|head|tail|bat)\s+[^|;&]+' | awk '{for(i=2;i<=NF;i++){if($i !~ /^-/){print $i; exit}}}' || true)
  fi
elif printf '%s\n' "$CMD" | grep -qE '^\s*(grep|rg|sed|awk)\s+'; then
  FILE_PATH=$(printf '%s\n' "$CMD" | grep -oE '"[^"]+"' | tail -1 | tr -d '"' || true)
  if [ -z "$FILE_PATH" ]; then
    FILE_PATH=$(printf '%s\n' "$CMD" | grep -oE '^\s*(grep|rg|sed|awk)\s+[^|;&]+' | awk '{last=""; for(i=2;i<=NF;i++){if($i !~ /^-/){last=$i}}; print last}' || true)
    FILE_PATH=$(printf '%s\n' "$FILE_PATH" | sed "s/^'//;s/'$//" || true)
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

SAFE_PATH=$(printf '%s\n' "$REL_PATH" | sed 's/\\/\\\\/g; s/"/\\"/g')

if ! mati ping >/dev/null 2>&1; then
  echo "[mati] daemon unreachable — enforcement bypassed" >&2
  { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) FAIL_OPEN hook=$(basename "$0") file=${REL_PATH:-unknown}" >> "${HOME}/.mati/fail_open.log"; } 2>/dev/null || true
  exit 0
fi

RECENT=$(mati session-check-consulted-recent "file:$REL_PATH" --ttl-secs "$TTL_SECS" 2>/dev/null || echo "false")
if [ "$RECENT" = "true" ]; then
  mati log-compliance-hit "file:$REL_PATH" >/dev/null 2>&1 || true
else
  mati log-codex-shell-miss "file:$REL_PATH" >/dev/null 2>&1 || true
  printf '{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"[mati] Shell inspection of %s happened without a recent consultation receipt. Call mem_get(\\"file:%s\\") before the next Bash-based file read."}}\n' "$SAFE_PATH" "$SAFE_PATH"
fi
"#;
