/// pre-bash.sh — catch cat/less/head/tail/bat/grep/rg file reads (M-09-B, M-13-D).
///
/// Thin wrapper that delegates to `mati hook-decide claude-pre-bash`.
/// All enforcement logic lives in Rust (`hooks::decide` + `cli::hook_decide`).
/// 2-5% miss rate accepted (C9 in ARCHITECTURE.md §24).
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
exec mati hook-decide claude-pre-bash
"#;
