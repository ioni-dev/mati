/// session-end.sh — session harvest on exit (M-09-F).
///
/// SessionEnd — calls harvest to write permanent session summary.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati session-end hook — session harvest (M-09-F)
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
mati session-harvest 2>/dev/null || true
"#;
