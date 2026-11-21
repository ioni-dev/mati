/// post-edit.sh — edit activity tracking (M-09-D) + doc comment capture (2.3).
///
/// PostToolUse — fires after Edit/Write/MultiEdit. Thin wrapper that
/// delegates to `mati post-edit`, which parses the payload in Rust.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
# Backgrounded: the two daemon calls take ~190ms and nothing waits on them.
INPUT=$(cat)
printf '%s' "$INPUT" | mati post-edit >/dev/null 2>&1 &
"#;
