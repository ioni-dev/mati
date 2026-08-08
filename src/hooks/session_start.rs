/// SessionStart hook — register the files whose changes mati wants to hear about.
///
/// Claude Code starts no file watcher until a SessionStart hook returns
/// `hookSpecificOutput.watchPaths`; every later `FileChanged` event depends on
/// this one call. Fail-open: no output means no watcher, never a blocked session.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati SessionStart hook — register FileChanged watch paths (fail-open)
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
cat > /dev/null
mati watch-paths 2>/dev/null || true
"#;
