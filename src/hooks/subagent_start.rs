/// subagent-start.sh — record subagent presence + inject mati awareness.
///
/// SubagentStart fires before a subagent's first turn. Two jobs, both fail-open:
/// record the spawn as a `SubagentSpawned` enforcement event (so the audit can
/// attribute a subagent that spawns and never consults), then surface the gotcha
/// count + how to consult. The payload arrives once on stdin, so capture it, pipe
/// it to the recorder, then run the (stdin-less) awareness command.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati subagent-start hook — record presence + inject awareness (fail-open)
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
PAYLOAD="$(cat)"
printf '%s' "$PAYLOAD" | mati subagent-record 2>/dev/null || true
mati subagent-context 2>/dev/null || true
"#;
