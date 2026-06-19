/// pre-edit.sh — core hook for file EDIT interception (WI-01, L1).
///
/// Thin wrapper that delegates to `mati hook-decide claude-pre-edit`. PreToolUse
/// on Edit/Write/NotebookEdit: denies an edit to a file carrying an unconsulted
/// confirmed gotcha until the agent calls `mem_get`. Because Claude Code's own
/// read-before-edit rule forces a prior read (which the read-gate already gates),
/// this only fires on *blind* edits — closing the residual shell-read→edit hole
/// and emitting an explicit edit-time enforcement event.
///
/// Non-deny outcomes DEFER to the normal permission flow (empty stdout, exit 0)
/// rather than emitting `permissionDecision: "allow"`. Edits are
/// permission-required tools, so force-allowing would suppress the user's own
/// edit-approval prompt on every non-gotcha file — unlike reads, which are
/// no-permission tools where force-allow is a harmless no-op. All enforcement
/// logic lives in Rust (`hooks::decide` + `cli::hook_decide`).
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
exec mati hook-decide claude-pre-edit
"#;
