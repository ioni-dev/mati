/// subagent-start.sh — inject mati awareness into a freshly-spawned subagent.
///
/// SubagentStart fires before a subagent's first turn. Subagents are fresh
/// contexts blind to mati; this surfaces the gotcha count + how to consult.
/// Awareness only (enforcement already fires on subagent tool calls). Fail-open.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
# mati subagent-start hook — inject codebase-memory awareness (fail-open)
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
command -v mati >/dev/null 2>&1 || exit 0
cat > /dev/null
mati subagent-context 2>/dev/null || true
"#;
