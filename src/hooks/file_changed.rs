/// FileChanged hook — incremental freshness for a watched file.
///
/// Fires only for paths the SessionStart hook handed back in `watchPaths`.
/// Reparses the file so `content_hash` and staleness follow the edit instead
/// of waiting for the next `mati init`. No decision, no stdout. Fail-open.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati FileChanged hook — incremental freshness (fail-open)
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
exec mati hook-decide claude-file-changed
"#;
