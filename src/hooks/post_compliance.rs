/// post-read-compliance.sh — compliance monitoring (M-09-C).
///
/// PostToolUse — fires after Read/Glob/Grep (not Bash; pre-bash hook covers that).
/// Checks if the file was consulted via mati before being read. No JSON output required.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati post-read compliance monitor (M-09-C)
# Fires for Read/Glob/Grep only — Bash is covered by the pre-bash PreToolUse hook.
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
  mati_fail_open "$(basename "$0")" "<unparsed>" "jq not on PATH - compliance monitoring skipped"
  exit 0
fi

# Extract file path from tool input (Read/Glob/Grep have file_path or path)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // ""' 2>/dev/null || echo "")
[ -z "$FILE_PATH" ] && exit 0

# Convert absolute path to repo-relative (same as pre-read.sh). The strip is
# lexical and fails when the two sides disagree about symlinks (macOS
# /private/tmp vs /tmp); `mati` canonicalizes an absolute key it is handed, so
# do not re-fix this here — see repo_relative_key in src/cli/hooks.rs.
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "")
if [ -n "$REPO_ROOT" ]; then
  REL_PATH="${FILE_PATH#$REPO_ROOT/}"
else
  REL_PATH="$FILE_PATH"
fi

# Skip obvious non-file paths, but keep extensionless real files like Dockerfile.
case "$REL_PATH" in
  *.*|*/*) ;;  # extension or directory separator — likely a file path
  *)
    if [ -e "$FILE_PATH" ]; then
      :
    elif [ -n "$REPO_ROOT" ] && [ -e "$REPO_ROOT/$REL_PATH" ]; then
      :
    else
      exit 0
    fi
    ;;
esac

# Guard: mati must be reachable
if ! mati ping --daemon-only &>/dev/null; then
  mati_fail_open "$(basename "$0")" "${REL_PATH:-unknown}" "daemon not running"
  exit 0
fi

# Was this file consulted before the read? One command decides and records:
# it logs a plain Miss, never the gate's ComplianceMiss (that one records an
# EnforcementEventType::Deny and arms the Tier 1 lockdown — a block that did
# not occur here, since PostToolUse only fires for a read that was allowed),
# and it stays silent for a file with no record at all, which the pre-read gate
# already counted. The worktree half of the receipt scope is resolved by mati
# itself; only the subagent id lives in the payload, so forward it. Without the
# scope the check asks about a receipt key the gate never writes and answers
# "false" for every read.
AGENT_ID=$(echo "$INPUT" | jq -r '.agent_id // ""' 2>/dev/null || echo "")
if [ -n "$AGENT_ID" ]; then
  mati post-read-compliance "file:$REL_PATH" --agent-id "$AGENT_ID" &>/dev/null || true
else
  mati post-read-compliance "file:$REL_PATH" &>/dev/null || true
fi
"#;
