/// Codex UserPromptSubmit hook — zero injection.
///
/// All context delivery flows through mem_get (agent-initiated, per SKILL.md)
/// and PreToolUse exit 2 (hard block on unconsulted reads). This hook is a
/// no-op to achieve zero per-prompt token overhead.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
exit 0
"#;
