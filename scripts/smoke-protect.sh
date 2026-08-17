#!/usr/bin/env bash
#
# End-to-end acceptance test for break-glass resource protection.
#
# Drives the real binary, a real daemon, and the REAL hook wrappers that
# `mati init` scaffolds (.claude/hooks/*, .codex/hooks/*) — the same scripts
# Claude Code and Codex invoke. Unit tests cover the classifier; smoke-policy.sh
# covers the policy engine; this proves `mati protect` / `mati guard` and the
# PathMutating classifier enforce through both agents' wrappers.
#
# What it asserts:
#   Claude  read gate denies a confirmed-gotcha read; guard denies a matching
#           command; protect denies an rm and an Edit; controls pass through.
#   Codex   has no read hook (reads ungated by design); guard/protect deny via
#           pre-bash (exit 2); the apply_patch edit gate denies a gotcha'd or
#           protected file and allows an unrelated one.
#
# Usage:  ./scripts/smoke-protect.sh
# Exit:   0 all passed, 1 a failure, 77 skipped (no Unix domain socket here).

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
export MATI_HOME="$WORK/mati-home"   # isolate off the real ~/.mati
PROJECT="$WORK/project"
MATI="$REPO_ROOT/target/debug/mati"

cargo build --quiet --bin mati || exit 1
[ -x "$MATI" ] || { echo "binary not found at $MATI" >&2; exit 1; }

PASS=0; FAIL=0
# cd into $PROJECT: daemon stop's slug comes from the repo root of cwd.
cleanup() { ( cd "$PROJECT" 2>/dev/null && "$MATI" daemon stop ) >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
pass() { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n       got: %s\n' "$1" "${2:-<empty>}"; }

mkdir -p "$PROJECT"
cd "$PROJECT" || exit 1
git init -q; git config user.email t@t.t; git config user.name tester
printf 'fn main() {\n    let _v = risky(true, 0);\n}\n\nfn risky(_a: bool, _b: i32) -> i32 {\n    0\n}\n' > app.rs
printf 'seed\n' > data.txt
printf 'readme\n' > README.md
git add -A; git commit -qm init >/dev/null

"$MATI" init --claude --codex >/dev/null 2>&1

# UDS guard. Some sandboxes forbid binding a Unix domain socket; the daemon then
# never comes up and every hook fails open. That is an environment limitation,
# not a protection failure, so exit 77 (skip).
if [ -z "$(find "$MATI_HOME" -name 'mati.sock' 2>/dev/null | head -1)" ]; then
  # give the first hook call a chance to spawn the daemon
  printf '{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"true"}}' \
    | bash .claude/hooks/pre-bash.sh >/dev/null 2>&1 || true
  if [ -z "$(find "$MATI_HOME" -name 'mati.sock' 2>/dev/null | head -1)" ]; then
    echo "SKIP: this environment cannot bind a Unix domain socket." >&2
    exit 77
  fi
fi

# ── Fixture: a confirmed gotcha on app.rs, a guard, and a protect on data.txt.
# data.txt is kept gotcha-free so the protect deny is isolated from the gotcha
# gate (which runs first and would otherwise mask it).
"$MATI" gotcha add app.rs -r "Never pass 0 as risky()'s second arg; 0 means indefinite retention and unbounded growth" -m "0 is not off; it retains every version forever" -s high >/dev/null 2>&1
SLUG="never-pass-0-as-risky-s-second-arg-0-mea"
"$MATI" gotcha confirm "$SLUG" >/dev/null 2>&1
"$MATI" guard 'git reset --hard*' --enable --reason "history rewrite is destructive" >/dev/null 2>&1
"$MATI" protect data.txt --enable --reason "protected fixture" >/dev/null 2>&1

# Payload builders.
pre_bash()   { printf '{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"%s"}}' "$1"; }
pre_read()   { printf '{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"%s"}}' "$1"; }
pre_edit()   { printf '{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"%s","old_string":"seed","new_string":"x"}}' "$1"; }
apply_patch(){ printf '{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"*** Update File: %s\\n@@\\n-a\\n+b\\n"}}' "$1"; }
# Run a wrapper: OUT=combined output, RC=exit code.
run() { OUT="$(printf '%s' "$2" | bash "$1" 2>&1)"; RC=$?; }

DENY='permissionDecision":"deny"'

step "Claude — read gate"
run .claude/hooks/pre-read.sh "$(pre_read "$PROJECT/app.rs")"
case "$OUT" in *"$DENY"*) pass "confirmed-gotcha read denied";; *) fail "read gate deny" "$OUT";; esac

step "Claude — command guard"
run .claude/hooks/pre-bash.sh "$(pre_bash 'git reset --hard HEAD~1')"
{ case "$OUT" in *"$DENY"*guard-git-reset-hard*|*guard-git-reset-hard*"$DENY"*) true;; *) false;; esac; } \
  && pass "git reset --hard denied, names guard" || fail "guard deny" "$OUT"
run .claude/hooks/pre-bash.sh "$(pre_bash 'git status')"
case "$OUT" in *"$DENY"*) fail "control git status allowed" "$OUT";; *) pass "git status not denied";; esac

step "Claude — path protect"
run .claude/hooks/pre-bash.sh "$(pre_bash 'rm data.txt')"
{ case "$OUT" in *protect-data-txt*) true;; *) false;; esac; } \
  && pass "rm data.txt denied, names protect" || fail "protect rm deny" "$OUT"
run .claude/hooks/pre-bash.sh "$(pre_bash 'rm README.md')"
case "$OUT" in *"$DENY"*) fail "control rm README allowed" "$OUT";; *) pass "rm README.md not denied";; esac
run .claude/hooks/pre-edit.sh "$(pre_edit "$PROJECT/data.txt")"
{ case "$OUT" in *protect-data-txt*) true;; *) false;; esac; } \
  && pass "Edit data.txt denied, names protect" || fail "protect edit deny" "$OUT"

step "Codex — no read hook (reads ungated by design)"
[ -f .codex/hooks/pre-read.sh ] && fail "codex read hook exists" ".codex/hooks/pre-read.sh present" \
  || pass "no .codex/hooks/pre-read.sh"

step "Codex — command guard + path protect via pre-bash (deny == exit 2)"
run .codex/hooks/pre-bash.sh "$(pre_bash 'git reset --hard HEAD~1')"
{ [ "$RC" -eq 2 ] && case "$OUT" in *guard-git-reset-hard*) true;; *) false;; esac; } \
  && pass "git reset --hard denied (rc=2)" || fail "codex guard deny" "rc=$RC out=$OUT"
run .codex/hooks/pre-bash.sh "$(pre_bash 'rm data.txt')"
{ [ "$RC" -eq 2 ] && case "$OUT" in *protect-data-txt*) true;; *) false;; esac; } \
  && pass "rm data.txt denied (rc=2)" || fail "codex protect deny" "rc=$RC out=$OUT"
run .codex/hooks/pre-bash.sh "$(pre_bash 'git status')"
[ "$RC" -eq 0 ] && pass "git status not denied (rc=0)" || fail "codex control" "rc=$RC out=$OUT"

step "Codex — apply_patch edit gate (deny == exit 2 + mati:)"
run .codex/hooks/pre-apply-patch.sh "$(apply_patch 'app.rs')"
{ [ "$RC" -eq 2 ] && case "$OUT" in mati:*) true;; *) false;; esac; } \
  && pass "gotcha'd app.rs patch denied (rc=2)" || fail "codex apply_patch gotcha" "rc=$RC out=$OUT"
run .codex/hooks/pre-apply-patch.sh "$(apply_patch 'data.txt')"
{ [ "$RC" -eq 2 ] && case "$OUT" in mati:*) true;; *) false;; esac; } \
  && pass "protected data.txt patch denied (rc=2)" || fail "codex apply_patch protect" "rc=$RC out=$OUT"
printf 'clean\n' > unrelated.txt
run .codex/hooks/pre-apply-patch.sh "$(apply_patch 'unrelated.txt')"
[ "$RC" -eq 0 ] && pass "unrelated patch allowed (rc=0)" || fail "codex apply_patch allow" "rc=$RC out=$OUT"

printf '\n== Summary ==\n  passed: %d\n  failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
printf '\n\033[32mResource protection verified end to end (Claude + Codex).\033[0m\n'
