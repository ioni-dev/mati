/// Codex PostToolUse(Bash) hook.
///
/// Thin wrapper that delegates to `mati hook-decide codex-post-bash`.
/// Logs shell-read compliance for analytics. No content injection —
/// context delivery is handled by mem_get (agent-initiated) and
/// PreToolUse exit 2 (hard block on unconsulted reads).
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
exec mati hook-decide codex-post-bash
"#;
