/// Claude PostToolUse(mcp__mati__mem_get) hook — record an ACTOR-SCOPED consult receipt.
/// Fires after a successful mem_get; the payload carries session_id, agent_id (subagent),
/// and tool_input.key. Captures the consult per-actor (the MCP handler is actor-blind).
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
exec mati hook-decide claude-post-memget
"#;
