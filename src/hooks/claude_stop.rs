/// stop.sh — session flush at end of every turn (Claude `Stop`).
///
/// Keeps `session:current` fresh so SessionEnd's harvest always has a complete
/// snapshot (on Claude, flush otherwise runs only at PreCompact, so a session
/// with no compaction would harvest nothing). Flush only — NOT harvest, which
/// would delete consult receipts and re-block the agent every turn. Async +
/// fail-open: never delays or breaks turn-end.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati stop hook — session flush (snapshot consulted keys each turn)
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
cat > /dev/null
mati session-flush 2>/dev/null || true
"#;
