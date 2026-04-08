/// pre-read.sh — core hook for file read interception (M-09-A, M-13-D).
///
/// Thin wrapper that delegates to `mati hook-decide claude-pre-read`.
/// All enforcement logic lives in Rust (`hooks::decide` + `cli::hook_decide`).
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
exec mati hook-decide claude-pre-read
"#;
