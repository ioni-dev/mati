/// post-read-compliance.sh — compliance monitoring (M-09-C).
///
/// PostToolUse — fires after Read/Glob/Grep (not Bash; pre-bash hook covers that).
/// Checks if the file was consulted via mati before being read. No JSON output required.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati post-read compliance monitor (M-09-C)
# Fires for Read/Glob/Grep only — Bash is covered by the pre-bash PreToolUse hook.
set -euo pipefail

INPUT=$(cat)

# Guard: jq required
command -v jq &>/dev/null || exit 0

# Extract file path from tool input (Read/Glob/Grep have file_path or path)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // ""' 2>/dev/null || true)
[ -z "$FILE_PATH" ] && exit 0

# Skip non-file paths (pattern strings, bare words, etc.)
case "$FILE_PATH" in
  *.*) ;;  # has extension — likely a file
  */*)  ;;  # has directory separator — treat as path
  *)    exit 0 ;;  # bare word (regex pattern, etc.) — skip
esac

# Convert absolute path to repo-relative (same as pre-read.sh)
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "")
if [ -n "$REPO_ROOT" ]; then
  REL_PATH="${FILE_PATH#$REPO_ROOT/}"
else
  REL_PATH="$FILE_PATH"
fi

# Guard: mati must be reachable
mati ping &>/dev/null || exit 0

# Check if this file was consulted via mati before being read
CONSULTED=$(mati session-check-consulted "file:$REL_PATH" 2>/dev/null || echo "false")
if [ "$CONSULTED" = "false" ]; then
  mati log-compliance-miss "file:$REL_PATH" &>/dev/null &
fi
"#;
