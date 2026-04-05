/// Codex UserPromptSubmit hook — knowledge-aware context injection.
///
/// Extracts file paths from the user's prompt and fetches their gotchas via
/// a single `mati prompt-context` call (one process fork, one daemon socket
/// round-trip). The daemon runs `assemble_context_packet` which handles all
/// confidence/quality/tombstone filtering internally.
///
/// This is the Codex equivalent of Claude Code's pre-read deny hook — it can't
/// structurally block file access, but it ensures the model sees the gotchas
/// at decision time rather than after it's already committed to a plan.
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"

INPUT=$(cat)

if ! command -v jq >/dev/null 2>&1; then
  echo "[mati] missing jq — enforcement bypassed" >&2
  { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) FAIL_OPEN hook=$(basename "$0") reason=missing_deps" >> "${HOME}/.mati/fail_open.log"; } 2>/dev/null || true
  exit 0
fi

PROMPT=$(printf '%s' "$INPUT" | jq -r '.prompt // ""' 2>/dev/null || echo "")
[ -z "$PROMPT" ] && exit 0

# ── Graceful degradation: daemon must be reachable ──────────────────────
if ! mati ping --daemon-only >/dev/null 2>&1; then
  echo "[mati] WARNING: daemon not running — enforcement bypassed" >&2
  { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) FAIL_OPEN hook=$(basename "$0") file=prompt" >> "${HOME}/.mati/fail_open.log"; } 2>/dev/null || true
  exit 0
fi

# ── Extract file paths from the prompt ──────────────────────────────────
PATHS=$(printf '%s' "$PROMPT" | grep -oE '[A-Za-z0-9_./-]+\.(rs|ts|tsx|js|jsx|py|go|java|rb|kt|scala|c|cpp|h|toml|yaml|yml|json|md|lock|sh|sql|proto|css|html)' | sort -u || true)
EXTRA=$(printf '%s' "$PROMPT" | grep -oE '(Makefile|Dockerfile|\.gitignore|\.env)' | sort -u || true)
if [ -n "$EXTRA" ]; then
  PATHS=$(printf '%s\n%s' "$PATHS" "$EXTRA" | sort -u)
fi

# If no file paths found, check for code-intent keywords and give a generic nudge
if [ -z "$PATHS" ]; then
  if printf '%s' "$PROMPT" | grep -qiE '\b(edit|change|modify|fix|debug|refactor|investigate)\b'; then
    mati log-prompt-nudge "__codex_prompt__" >/dev/null 2>&1 || true
    cat <<'NUDGE_EOF'
{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"[mati] Before editing files, call mem_get(\"file:<path>\") to check for gotchas. Call mem_bootstrap() if you haven't yet."}}
NUDGE_EOF
  fi
  exit 0
fi

# ── Single-call context fetch ───────────────────────────────────────────
# One process fork, one daemon socket round-trip. The daemon runs
# assemble_context_packet which handles confidence/quality/tombstone
# filtering, graph traversal, and token budgeting internally.
CONTEXT=$(mati prompt-context $PATHS 2>/dev/null || echo "")

if [ -n "$CONTEXT" ]; then
  mati log-prompt-nudge "__codex_prompt_gotcha__" >/dev/null 2>&1 || true
  printf '%s' "$CONTEXT" | jq -Rs '{hookSpecificOutput:{hookEventName:"UserPromptSubmit",additionalContext:.}}' 2>/dev/null
elif printf '%s' "$PROMPT" | grep -qiE '\b(edit|change|modify|fix|debug|refactor)\b'; then
  mati log-prompt-nudge "__codex_prompt__" >/dev/null 2>&1 || true
  cat <<'NUDGE_EOF'
{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"[mati] Before editing files, call mem_get(\"file:<path>\") to check for gotchas and understand file purpose."}}
NUDGE_EOF
fi
"#;
