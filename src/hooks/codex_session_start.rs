/// Codex SessionStart hook.
///
/// Codex cannot hard-block native file reads, so the session-start surface is
/// used to establish the MCP-first workflow immediately.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"

if ! mati ping >/dev/null 2>&1; then
  exit 0
fi

cat <<'EOF'
[mati] Session start: call mem_bootstrap before exploring the repo. Before editing or shell-inspecting a risky file, call mem_get("file:<path>"). Codex mode enforces Bash inspection, not native read tools.
EOF
"#;
