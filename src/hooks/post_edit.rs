/// post-edit.sh — edit activity tracking (M-09-D).
///
/// PostToolUse — fires after Edit/Write/MultiEdit. Tracks file modifications
/// by logging a hit. Full staleness triggering deferred to M-12.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati post-edit hook — edit activity tracking (M-09-D)
set -euo pipefail

INPUT=$(cat)

# Guard: jq required
command -v jq &>/dev/null || exit 0

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')
[ -z "$FILE_PATH" ] && exit 0

mati edit-hook "$FILE_PATH" &>/dev/null &
"#;
