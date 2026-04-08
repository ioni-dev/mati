/// Codex PreToolUse(Bash) hook — hard enforcement via exit 2 + stderr.
///
/// Thin wrapper that delegates to `mati hook-decide codex-pre-bash`.
/// All enforcement logic lives in Rust (`hooks::decide` + `cli::hook_decide`).
///
/// Codex hook protocol (developers.openai.com/codex/hooks#pretooluse):
///   - Matcher must be "Bash" (Codex normalizes exec_command → Bash in hooks)
///   - Input JSON uses `tool_input.command` (same schema as Claude Code)
///   - Blocking: exit 2 + stderr message
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
exec mati hook-decide codex-pre-bash
"#;
