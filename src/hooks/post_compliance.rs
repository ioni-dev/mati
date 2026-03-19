/// post-read-compliance.sh — compliance monitoring (M-09-C).
///
/// PostToolUse — fires after every Read/Glob/Grep/Bash. Checks if the file
/// was consulted via mati before being read. No JSON output required.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati post-read compliance monitor (M-09-C)
set -euo pipefail

INPUT=$(cat)

# Guard: jq required
command -v jq &>/dev/null || exit 0

# Extract file path from tool input
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // ""')
[ -z "$FILE_PATH" ] && exit 0

# Check if this file was consulted via mati before being read
CONSULTED=$(mati session-check-consulted "file:$FILE_PATH" 2>/dev/null || echo "false")
if [ "$CONSULTED" = "false" ]; then
  mati log-compliance-miss "file:$FILE_PATH" &>/dev/null &
fi
"#;
