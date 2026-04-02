/// Codex UserPromptSubmit hook — knowledge-aware context injection.
///
/// Extracts file paths from the user's prompt, looks up their gotchas via the
/// daemon socket, and injects confirmed gotchas as `additionalContext` so the
/// model has the institutional knowledge BEFORE it plans any changes.
///
/// This is the Codex equivalent of Claude Code's pre-read deny hook — it can't
/// structurally block file access, but it ensures the model sees the gotchas
/// at decision time rather than after it's already committed to a plan.
///
/// Applies the same thresholds as the pre-read hook decision matrix:
/// - confirmed=true + confidence >= 0.6 + quality >= 0.4 → inject gotcha
/// - Tombstoned/liability file records → skip entirely
pub const SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"

INPUT=$(cat)

if ! command -v jq >/dev/null 2>&1 || ! command -v awk >/dev/null 2>&1; then
  exit 0
fi

PROMPT=$(printf '%s' "$INPUT" | jq -r '.prompt // ""' 2>/dev/null || echo "")
[ -z "$PROMPT" ] && exit 0

# ── Graceful degradation: daemon must be reachable ──────────────────────
if ! mati ping >/dev/null 2>&1; then
  exit 0
fi

# ── Extract file paths from the prompt ──────────────────────────────────
# Match patterns: src/foo/bar.rs, Makefile, Dockerfile, Cargo.lock, etc.
PATHS=$(printf '%s' "$PROMPT" | grep -oE '[A-Za-z0-9_./-]+\.(rs|ts|tsx|js|jsx|py|go|java|rb|kt|scala|c|cpp|h|toml|yaml|yml|json|md|lock|sh|sql|proto|css|html)' | sort -u || true)
# Also match common extensionless files
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

# ── Look up gotchas for each file path ──────────────────────────────────
GOTCHA_LINES=""
GOTCHA_COUNT=0

while IFS= read -r fpath; do
  [ -z "$fpath" ] && continue

  RECORD=$(mati get "file:$fpath" 2>/dev/null || echo "null")
  [ "$RECORD" = "null" ] || [ -z "$RECORD" ] && continue
  if ! printf '%s\n' "$RECORD" | jq -e 'type == "object"' >/dev/null 2>&1; then
    continue
  fi

  # Skip tombstoned/liability file records
  STALENESS_TIER=$(printf '%s\n' "$RECORD" | jq -r '.staleness.tier // "fresh"' 2>/dev/null || echo "fresh")
  [ "$STALENESS_TIER" = "tombstone" ] && continue
  [ "$STALENESS_TIER" = "liability" ] && continue

  GOTCHA_KEYS=$(printf '%s\n' "$RECORD" | jq -r '.payload.gotcha_keys[]? // empty' 2>/dev/null || true)
  [ -z "$GOTCHA_KEYS" ] && continue

  while IFS= read -r gkey; do
    [ -z "$gkey" ] && continue
    GREC=$(mati get "$gkey" 2>/dev/null || echo "null")
    [ "$GREC" = "null" ] || [ -z "$GREC" ] && continue
    if ! printf '%s\n' "$GREC" | jq -e 'type == "object"' >/dev/null 2>&1; then
      continue
    fi

    # Apply the same decision matrix as pre-read hook:
    # confirmed=true + confidence >= 0.6 + quality >= 0.4
    GCONFIRMED=$(printf '%s\n' "$GREC" | jq -r '.payload.confirmed // false' 2>/dev/null || echo "false")
    [ "$GCONFIRMED" != "true" ] && continue

    GCONFIDENCE=$(printf '%s\n' "$GREC" | jq -r '.confidence.value // 0' 2>/dev/null || echo "0")
    GQUALITY=$(printf '%s\n' "$GREC" | jq -r '.quality.value // 0' 2>/dev/null || echo "0")
    # Sanitize to numeric — empty or non-numeric → 0 (fail-closed: gotcha skipped)
    case "$GCONFIDENCE" in ''|*[!0-9.]*) GCONFIDENCE=0 ;; esac
    case "$GQUALITY" in ''|*[!0-9.]*) GQUALITY=0 ;; esac
    awk "BEGIN { exit !($GCONFIDENCE >= 0.6) }" || continue
    awk "BEGIN { exit !($GQUALITY >= 0.4) }" || continue

    GRULE=$(printf '%s\n' "$GREC" | jq -r '.payload.rule // .value // ""' 2>/dev/null || echo "")
    GREASON=$(printf '%s\n' "$GREC" | jq -r '.payload.reason // ""' 2>/dev/null || echo "")
    GSEVERITY=$(printf '%s\n' "$GREC" | jq -r '.payload.severity // "normal"' 2>/dev/null || echo "normal")
    [ -z "$GRULE" ] && continue

    if [ -n "$GREASON" ]; then
      GOTCHA_LINES="${GOTCHA_LINES}[${GSEVERITY}] ${fpath}: ${GRULE} because ${GREASON}. "
    else
      GOTCHA_LINES="${GOTCHA_LINES}[${GSEVERITY}] ${fpath}: ${GRULE}. "
    fi
    GOTCHA_COUNT=$((GOTCHA_COUNT + 1))
    # Cap at 15 gotchas to avoid exceeding hook output limits
    [ "$GOTCHA_COUNT" -ge 15 ] && break 2
  done <<< "$GOTCHA_KEYS"
done <<< "$PATHS"

# ── Inject gotchas as additionalContext ─────────────────────────────────
if [ "$GOTCHA_COUNT" -gt 0 ]; then
  mati log-prompt-nudge "__codex_prompt_gotcha__" >/dev/null 2>&1 || true
  # Use jq for safe JSON escaping — handles all special characters
  HEADER="[mati] ${GOTCHA_COUNT} confirmed gotcha(s) affect files in this prompt."
  FULL_MSG="${HEADER} ${GOTCHA_LINES}Call mem_get(\"file:<path>\") for full details."
  printf '%s' "$FULL_MSG" | jq -Rs '{hookSpecificOutput:{hookEventName:"UserPromptSubmit",additionalContext:.}}' 2>/dev/null
elif printf '%s' "$PROMPT" | grep -qiE '\b(edit|change|modify|fix|debug|refactor)\b'; then
  mati log-prompt-nudge "__codex_prompt__" >/dev/null 2>&1 || true
  cat <<'NUDGE_EOF'
{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"[mati] Before editing files, call mem_get(\"file:<path>\") to check for gotchas and understand file purpose."}}
NUDGE_EOF
fi
"#;
