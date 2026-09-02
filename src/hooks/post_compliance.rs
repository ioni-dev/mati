/// post-read-compliance.sh — compliance monitoring (M-09-C).
///
/// PostToolUse — fires after Read/Glob/Grep (not Bash; pre-bash hook covers that).
/// Thin wrapper that delegates to `mati hook-decide claude-post-read-compliance`.
/// All logic lives in Rust (`cli::hook_decide::run_post_read_compliance`).
/// No JSON output: PostToolUse carries no permission decision.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
exec mati hook-decide claude-post-read-compliance
"#;
