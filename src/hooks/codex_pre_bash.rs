/// Codex PreToolUse(Bash) hook — hard enforcement via exit 2 + stderr.
///
/// Confirmed working in Codex 0.118.0: exit 2 blocks the tool call.
/// stdout is not used for blocking — only stderr + exit code matter.
///
/// Enforcement decision matrix:
///   confirmed + confidence >= 0.6 + quality >= 0.4  ->  DENY (exit 2 + stderr)
///   agent already consulted (receipt valid within 15min)  ->  ALLOW
///   no record or below threshold  ->  ALLOW + log gap
///   mati daemon unreachable  ->  ALLOW (fail-open)
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati Codex pre-bash hook — file-reading command enforcement
#
# Blocking mechanism: exit 2 + stderr message (confirmed Codex 0.118.0).
# Codex does NOT read stdout from PreToolUse hooks for blocking decisions.
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"

INPUT=$(cat)

if ! command -v jq >/dev/null 2>&1 || ! command -v awk >/dev/null 2>&1; then
  { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) FAIL_OPEN hook=$(basename "$0") reason=missing_deps" >> "${HOME}/.mati/fail_open.log"; } 2>/dev/null || true
  exit 0
fi

TTL_SECS=900

# Codex 0.118.0 sends: {"arguments":"{\"cmd\":\"...\",\"shell\":\"zsh\",\"workdir\":\"...\"}"}
CMD=$(printf '%s\n' "$INPUT" | jq -r '
  if (.arguments | type) == "string"
  then (.arguments | fromjson | .cmd // empty)
  else empty
  end
' 2>/dev/null || echo "")
[ -z "$CMD" ] && exit 0

# Scope to file-reading commands only — never reach mati lookup for pwd, ls, etc.
if printf '%s\n' "$CMD" | grep -qE '^\s*(cat|less|head|tail|bat)\s+'; then
  FILE_PATH=$(printf '%s\n' "$CMD" | grep -oE '"[^"]+"' | head -1 | tr -d '"' || true)
  if [ -z "$FILE_PATH" ]; then
    FILE_PATH=$(printf '%s\n' "$CMD" | sed "s/.*'\([^']*\)'.*/\1/" 2>/dev/null || true)
    [ "$FILE_PATH" = "$CMD" ] && FILE_PATH=""
  fi
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
  exit 0
fi

[ -z "$FILE_PATH" ] && exit 0

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "")
if [ -n "$REPO_ROOT" ]; then
  REL_PATH="${FILE_PATH#$REPO_ROOT/}"
else
  REL_PATH="$FILE_PATH"
fi

SAFE_PATH=$(printf '%s\n' "$REL_PATH" | sed 's/\\/\\\\/g; s/"/\\"/g')

# Fail open — never block when daemon is unreachable
if ! mati ping --daemon-only >/dev/null 2>&1; then
  mati daemon start </dev/null >/dev/null 2>&1 &
  sleep 0.3
  if ! mati ping --daemon-only >/dev/null 2>&1; then
    echo "[mati] WARNING: daemon not running — enforcement bypassed for ${REL_PATH:-unknown file}" >&2
    { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) FAIL_OPEN hook=$(basename "$0") file=${REL_PATH:-unknown}" >> "${HOME}/.mati/fail_open.log"; } 2>/dev/null || true
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
    exit 0
  fi
  # Daemon recovered — fall through to enforcement
fi

RECORD=$(mati get "file:$REL_PATH" 2>/dev/null || echo "null")
if [ "$RECORD" = "null" ] || [ -z "$RECORD" ]; then
  mati log-miss "file:$REL_PATH" >/dev/null 2>&1 || true
  exit 0
fi

if ! printf '%s\n' "$RECORD" | jq -e 'type == "object"' >/dev/null 2>&1; then
  exit 0
fi

CONFIDENCE=$(printf '%s\n' "$RECORD" | jq -r '.confidence.value // 0')
QUALITY=$(printf '%s\n' "$RECORD" | jq -r '.quality.value // 0')
STALENESS=$(printf '%s\n' "$RECORD" | jq -r '.staleness.value // 0')
STALENESS_TIER=$(printf '%s\n' "$RECORD" | jq -r '.staleness.tier // "fresh"')
IS_HOTSPOT=$(printf '%s\n' "$RECORD" | jq -r '.payload.is_hotspot // false')
case "$CONFIDENCE" in ''|*[!0-9.]*) CONFIDENCE=0 ;; esac
case "$QUALITY" in ''|*[!0-9.]*) QUALITY=0 ;; esac
case "$STALENESS" in ''|*[!0-9.]*) STALENESS=0 ;; esac

[ "$STALENESS_TIER" = "tombstone" ] && exit 0
[ "$STALENESS_TIER" = "liability" ] && exit 0

RECENT=$(mati session-check-consulted-recent "file:$REL_PATH" --ttl-secs "$TTL_SECS" 2>/dev/null || echo "false")

DENY_SIGNAL=false
GOTCHA_KEYS=$(printf '%s\n' "$RECORD" | jq -r '.payload.gotcha_keys[]? // empty' 2>/dev/null || true)
while IFS= read -r gkey; do
  [ -z "$gkey" ] && continue
  GREC=$(mati get "$gkey" 2>/dev/null || echo "null")
  [ "$GREC" = "null" ] || [ -z "$GREC" ] && continue
  if ! printf '%s\n' "$GREC" | jq -e 'type == "object"' >/dev/null 2>&1; then
    continue
  fi
  GCONFIRMED=$(printf '%s\n' "$GREC" | jq -r '.payload.confirmed // false')
  GCONFIDENCE=$(printf '%s\n' "$GREC" | jq -r '.confidence.value // 0')
  GQUALITY=$(printf '%s\n' "$GREC" | jq -r '.quality.value // 0')
  case "$GCONFIDENCE" in ''|*[!0-9.]*) GCONFIDENCE=0 ;; esac
  case "$GQUALITY" in ''|*[!0-9.]*) GQUALITY=0 ;; esac
  if [ "$GCONFIRMED" = "true" ] && \
     awk "BEGIN { exit !($GCONFIDENCE >= 0.6) }" && \
     awk "BEGIN { exit !($GQUALITY >= 0.4) }"; then
    DENY_SIGNAL=true
  fi
done <<< "$GOTCHA_KEYS"

if [ "$DENY_SIGNAL" = "true" ] && [ "$RECENT" != "true" ]; then
  mati log-codex-shell-miss "file:$REL_PATH" >/dev/null 2>&1 || true
  echo "mati: call mem_get(\"file:$SAFE_PATH\") first" >&2
  exit 2
fi

if [ "$RECENT" != "true" ] && \
   { [ "$IS_HOTSPOT" = "true" ] || \
     { awk "BEGIN { exit !($CONFIDENCE >= 0.3) }" && awk "BEGIN { exit !($QUALITY >= 0.4) }"; }; }; then
  printf '{"systemMessage":"[mati] Before shell-inspecting %s, call mem_get(\\"file:%s\\") so Codex has the project memory first."}\n' "$SAFE_PATH" "$SAFE_PATH"
fi
"#;
