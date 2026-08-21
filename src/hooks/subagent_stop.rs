/// subagent-stop.sh — harvest a finished subagent's summary (F5).
///
/// SubagentStop fires when a Task subagent finishes. Its `last_assistant_message`
/// is the subagent's own prose summary of its work; capture it into
/// `session:summary:latest` so `mem_bootstrap` can surface it as `recent_session`.
/// Unlike stop/subagent-start, this pipes the payload INTO mati — the summary
/// lives in stdin. Fail-open; must not delay turn-end.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati subagent-stop hook — harvest subagent summary (fail-open)
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
mati subagent-harvest 2>/dev/null || true
"#;
