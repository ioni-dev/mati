/// Codex SessionStart hook — project knowledge injection at session start.
///
/// Injects a compact summary of confirmed gotcha count, hotspot count, and
/// the enforcement model so the agent starts with awareness of the knowledge
/// layer from turn one. Also logs the bootstrap event for analytics.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"

if ! mati ping --daemon-only >/dev/null 2>&1; then
  # Auto-start the daemon — fails silently if MCP server already holds the lock
  mati daemon start </dev/null >/dev/null 2>&1 &
  sleep 0.3
  if mati ping --daemon-only >/dev/null 2>&1; then
    echo "[mati] daemon was not running — started automatically. Enforcement active." >&2
  else
    echo "[mati] WARNING: daemon not running and auto-start failed — enforcement bypassed this session." >&2
  fi
  { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) AUTO_START hook=session-start" >> "${HOME}/.mati/fail_open.log"; } 2>/dev/null || true
  exit 0
fi

# Count confirmed gotchas and hotspot files for a compact summary
GOTCHA_COUNT=0
HOTSPOT_COUNT=0

if command -v jq >/dev/null 2>&1; then
  GOTCHAS=$(mati get "analytics:knowledge_snapshot" 2>/dev/null || echo "null")
  if [ "$GOTCHAS" != "null" ] && [ -n "$GOTCHAS" ]; then
    GOTCHA_COUNT=$(printf '%s\n' "$GOTCHAS" | jq -r '.payload.confirmed_gotchas // 0' 2>/dev/null || echo "0")
    HOTSPOT_COUNT=$(printf '%s\n' "$GOTCHAS" | jq -r '.payload.hotspot_files // 0' 2>/dev/null || echo "0")
  fi
fi

mati log-bootstrap "__codex_session__" >/dev/null 2>&1 || true

MSG="[mati] ${GOTCHA_COUNT} confirmed gotchas, ${HOTSPOT_COUNT} hotspot files tracked. Call mem_bootstrap() for full context. Before editing any file, call mem_get(\"file:<path>\") -- gotchas will be injected via UserPromptSubmit hook. Bash file inspection is enforced via prompt context (UserPromptSubmit); call mem_get before any file read."
printf '%s' "$MSG" | jq -Rs '{hookSpecificOutput:{hookEventName:"SessionStart",additionalContext:.}}'
"#;
