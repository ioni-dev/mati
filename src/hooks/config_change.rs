/// config-change.sh — anti-tamper guard for Claude Code settings changes.
///
/// Claude Code has already written the new file when this hook runs. The Rust
/// adapter checks mati's registrations in that new content and can stop this
/// session from adopting a tampered configuration. The file remains changed
/// on disk: quitting and restarting Claude Code adopts it, so this is an
/// in-session guard plus an audit record, not a durable file rollback.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
exec mati hook-decide claude-config-change
"#;
