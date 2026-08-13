/// post-edit.sh — edit activity tracking (M-09-D) + doc comment capture (2.3).
///
/// PostToolUse — fires after Edit/Write/MultiEdit. Tracks file modifications
/// and captures canonical doc comments Claude authors as file purpose
/// (confidence 0.65, no API calls needed).
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati post-edit hook — edit activity tracking + doc comment capture
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
# The root mati_home_opt() resolves — $MATI_HOME wins, ~/.mati is the default.
# Writing to a different root than the reader would make every fail-open
# record below invisible to `mati stats`.
MATI_DIR="${MATI_HOME:-${HOME}/.mati}"
mkdir -p "$MATI_DIR" 2>/dev/null || true

# Record a bypass in the same shape cli::hook_decide::log_fail_open_named
# writes, so shell and Rust fail-opens read back as one series.
# Args: hook, file, reason.
mati_fail_open() {
  echo "[mati] WARNING: enforcement bypassed for $2 — $3" >&2
  { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) FAIL_OPEN hook=$1 file=$2 reason=$3" >> "$MATI_DIR/fail_open.log"; } 2>/dev/null || true
}

INPUT=$(cat)

# Guard: jq required
if ! command -v jq >/dev/null 2>&1; then
  mati_fail_open "$(basename "$0")" "<unparsed>" "jq not on PATH - edit tracking and doc capture skipped"
  exit 0
fi

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')
[ -z "$FILE_PATH" ] && exit 0

# Convert absolute path to repo-relative path.
# Claude Code always passes absolute paths; mati store keys use relative paths.
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "")
if [ -n "$REPO_ROOT" ]; then
  FILE_PATH="${FILE_PATH#$REPO_ROOT/}"
fi

# 2.3: Capture canonical doc comment from new content.
# Write: tool_input.content  |  Edit: tool_input.new_string
# Only the first 15 lines — doc comments live at the top of the file.
CONTENT_HEAD=$(echo "$INPUT" | jq -r '(.tool_input.content // .tool_input.new_string // "") | split("\n")[:15] | join("\n")')
if [ -n "$CONTENT_HEAD" ]; then
    printf '%s' "$CONTENT_HEAD" | mati doc-capture "$FILE_PATH" &>/dev/null &
fi

mati edit-hook "$FILE_PATH" &>/dev/null &
"#;
