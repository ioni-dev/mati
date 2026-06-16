/// Codex PreToolUse(apply_patch) hook — hard edit enforcement via exit 2 + stderr.
///
/// Delegates to `mati hook-decide codex-pre-apply-patch`. Codex delivers the
/// raw patch envelope in `tool_input.command` (`*** Update File: <path>` /
/// `*** Add File:` / `*** Delete File:` / `*** Move to:`); the Rust side parses
/// the target paths and evaluates each against the gotcha store.
///
/// Unlike the pre-bash wrapper (which `exec`s mati), this one deliberately does
/// NOT exec: it captures mati's output so it can tell a real DENY (exit 2 + a
/// line starting `mati:`) apart from a mati *fault* — most importantly an older
/// binary that doesn't know this variant, which clap also reports with exit 2.
/// Any fault fails OPEN. Wrongly blocking *every* edit on a mati error would be
/// far worse than missing one gotcha, so the edit path is biased to allow on
/// uncertainty (mirrors the parser's fail-open contract).
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -uo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
out="$(mati hook-decide codex-pre-apply-patch 2>&1)"; rc=$?
# exit 2 AND a "mati:" message == deliberate deny. Anything else (allow, or a
# mati/clap fault that also exits 2) fails OPEN so edits never block on a fault.
if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -q '^mati:'; then
  printf '%s\n' "$out" >&2
  exit 2
fi
exit 0
"#;
