/// post-compact.sh — clear consult receipts after compaction.
///
/// PostCompact — SYNCHRONOUS. Compaction wipes the agent's working memory of
/// gotcha content, but daemon-side consult receipts survive (read-time TTL), so
/// PreToolUse would not re-block. Clearing receipts forces a fresh mem_get on the
/// next access to a gotcha'd file, restoring the "consulted ⇒ knows" invariant.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati post-compact hook — clear consult receipts (restore re-block after compaction)
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
cat > /dev/null
mati session-clear-consults 2>/dev/null || true
"#;
