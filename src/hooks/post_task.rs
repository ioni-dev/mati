/// Claude PostToolUse(Task) hook — record a nested subagent→subagent spawn edge.
/// Fires after a Task/Agent tool call returns; the payload's top-level `agent_id`
/// is the spawner and `tool_response.agentId` is the child. Only nested spawns
/// (spawner is itself a subagent) are recorded — a root spawn is already covered
/// by the SubagentStart hook. Fire-and-forget, fail-open.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
exec mati hook-decide claude-post-task
"#;
