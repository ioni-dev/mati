/// Codex SessionStart hook — project knowledge injection at session start.
///
/// Injects a compact summary of confirmed gotcha count, hotspot count, and
/// the enforcement model so the agent starts with awareness of the knowledge
/// layer from turn one. Also logs the bootstrap event for analytics.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"

if ! mati ping >/dev/null 2>&1; then
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

MSG="[mati] ${GOTCHA_COUNT} confirmed gotchas, ${HOTSPOT_COUNT} hotspot files tracked. Call mem_bootstrap() for full context. Before editing any file, call mem_get(\"file:<path>\") -- gotchas will be injected via UserPromptSubmit hook. Bash file inspection is structurally enforced (denied until consulted)."
printf '%s' "$MSG" | jq -Rs '{hookSpecificOutput:{hookEventName:"SessionStart",additionalContext:.}}'
"#;
