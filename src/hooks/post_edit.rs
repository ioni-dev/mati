/// post-edit.sh — edit activity tracking (M-09-D) + doc comment capture (2.3).
///
/// PostToolUse — fires after Edit/Write/MultiEdit. Tracks file modifications
/// and captures canonical doc comments Claude authors as file purpose
/// (confidence 0.65, no API calls needed).
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati post-edit hook — edit activity tracking + doc comment capture
set -euo pipefail

INPUT=$(cat)

# Guard: jq required
command -v jq &>/dev/null || exit 0

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')
[ -z "$FILE_PATH" ] && exit 0

# 2.3: Capture canonical doc comment from new content.
# Write: tool_input.content  |  Edit: tool_input.new_string
# Only the first 15 lines — doc comments live at the top of the file.
CONTENT_HEAD=$(echo "$INPUT" | jq -r '(.tool_input.content // .tool_input.new_string // "") | split("\n")[:15] | join("\n")')
if [ -n "$CONTENT_HEAD" ]; then
    printf '%s' "$CONTENT_HEAD" | mati doc-capture "$FILE_PATH" &>/dev/null &
fi

mati edit-hook "$FILE_PATH" &>/dev/null &
"#;
