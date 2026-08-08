/// InstructionsLoaded hook — record the exact ambient instruction payload.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati InstructionsLoaded hook — pure audit recording (fail-open)
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
exec mati hook-decide claude-instructions-loaded
"#;
