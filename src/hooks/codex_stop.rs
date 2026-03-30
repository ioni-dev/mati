/// Codex Stop hook.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"

mati session-flush >/dev/null 2>&1 || true
mati session-harvest >/dev/null 2>&1 || true
echo '{}'
"#;
