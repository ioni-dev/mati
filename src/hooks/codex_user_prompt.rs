/// Codex UserPromptSubmit hook.
///
/// Adds a lightweight reminder when the prompt looks like code-inspection or
/// edit intent, but does not pretend native read denial exists.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"

INPUT=$(cat)

if ! command -v jq >/dev/null 2>&1; then
  exit 0
fi

PROMPT=$(echo "$INPUT" | jq -r '.prompt // .user_prompt // .input // ""' 2>/dev/null || echo "")
[ -z "$PROMPT" ] && exit 0

if ! mati ping >/dev/null 2>&1; then
  exit 0
fi

if printf '%s' "$PROMPT" | grep -qiE '\b(edit|change|modify|fix|debug|inspect|review|refactor|read|open|trace|investigate)\b|[A-Za-z0-9_/.-]+\.(rs|ts|tsx|js|jsx|py|go|java|rb|kt|scala|c|cpp|h)$|(^|[[:space:]])(src/|app/|internal/|lib/|tests?/)' ; then
  mati log-prompt-nudge "__codex_prompt__" >/dev/null 2>&1 || true
  cat <<'EOF'
[mati] Prompt suggests code inspection or editing. Call mem_bootstrap if you have not yet, then call mem_get("file:<path>") before changing unfamiliar or hotspot files.
EOF
fi
"#;
