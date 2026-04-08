/// Codex SessionStart hook — daemon health check + compact sentinel.
///
/// Auto-starts the daemon if needed, logs a bootstrap event for analytics,
/// and emits a ~5-token sentinel. All workflow instructions live in SKILL.md
/// (loaded once by the platform) — the hook does not repeat them.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
mkdir -p "${HOME}/.mati" 2>/dev/null || true

if ! mati ping --daemon-only >/dev/null 2>&1; then
  mati daemon start </dev/null >/dev/null 2>&1 &
  READY=false
  for _attempt in 1 2 3; do
    sleep 0.15
    if mati ping --daemon-only >/dev/null 2>&1; then READY=true; break; fi
  done
  if [ "$READY" = "false" ]; then
    echo "[mati] WARNING: daemon bootstrap failed — PreToolUse hooks will retry independently." >&2
    { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) AUTO_START hook=session-start result=failed" >> "${HOME}/.mati/fail_open.log"; } 2>/dev/null || true
    exit 0
  fi
  { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) AUTO_START hook=session-start result=ok" >> "${HOME}/.mati/fail_open.log"; } 2>/dev/null || true
fi

mati log-bootstrap "__codex_session__" >/dev/null 2>&1 || true

printf '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"[mati] active"}}\n'
"#;
