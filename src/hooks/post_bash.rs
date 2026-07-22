/// Claude PostToolUse(Bash) hook — schema consultation receipt adapter.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
exec mati hook-decide claude-post-bash
"#;
