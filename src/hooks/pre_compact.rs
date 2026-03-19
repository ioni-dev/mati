/// pre-compact.sh — session flush before compaction (M-09-E).
///
/// PreCompact — SYNCHRONOUS (must complete before returning).
/// Flushes session state so it survives context compaction.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati pre-compact hook — session flush (M-09-E)
cat > /dev/null
mati session-flush 2>/dev/null || true
"#;
