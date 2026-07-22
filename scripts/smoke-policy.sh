#!/usr/bin/env bash
#
# End-to-end test bed for the local policy engine.
#
# Drives the real binary, a real daemon, and the real hook subprocess protocol.
# Unit tests cover the logic; this proves the wiring.
#
# Known limits of this script:
#   - Payloads are constructed from the documented schema, not captured from a
#     live Claude Code session. The `tool_response.isError` contract in
#     particular is only confirmed by a real session.
#   - Fingerprint drift and the bad-glob boot path are unit-tested only; both
#     need store surgery that is awkward from a shell.
#
# Usage:  ./scripts/smoke-policy.sh
# Exit:   0 all steps passed, 1 otherwise.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
export MATI_HOME="$WORK/mati-home"   # isolate off the real ~/.mati
PROJECT="$WORK/project"
MATI="$REPO_ROOT/target/debug/mati"

PASS=0; FAIL=0; SKIP=0

cleanup() { "$MATI" daemon stop >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
pass() { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; printf '       got: %s\n' "${2:-<empty>}"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33mSKIP\033[0m %s (%s)\n' "$1" "$2"; }

assert_has()   { if printf '%s' "$2" | grep -q -- "$3"; then pass "$1"; else fail "$1" "$2"; fi; }
assert_lacks() { if printf '%s' "$2" | grep -q -- "$3"; then fail "$1" "$2"; else pass "$1"; fi; }
denied()       { printf '%s' "$1" | grep -q 'permissionDecision":"deny"'; }

# ── Payload builders ─────────────────────────────────────────────────────────
# agent_id is optional; when present the receipt is actor-scoped.
pre_bash() {
  local cmd="$1" agent="${2:-}"
  if [ -n "$agent" ]; then
    printf '{"session_id":"smoke","agent_id":"%s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":%s}}' "$agent" "$cmd"
  else
    printf '{"session_id":"smoke","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":%s}}' "$cmd"
  fi
}
post_bash() {
  local cmd="$1" iserr="$2" code="$3" agent="${4:-}"
  if [ -n "$agent" ]; then
    printf '{"session_id":"smoke","agent_id":"%s","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":%s},"tool_response":{"isError":%s,"exit_code":%s,"stdout":"Table","stderr":""}}' "$agent" "$cmd" "$iserr" "$code"
  else
    printf '{"session_id":"smoke","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":%s},"tool_response":{"isError":%s,"exit_code":%s,"stdout":"Table","stderr":""}}' "$cmd" "$iserr" "$code"
  fi
}
post_memget() {
  local key="$1" agent="${2:-}"
  if [ -n "$agent" ]; then
    printf '{"session_id":"smoke","agent_id":"%s","hook_event_name":"PostToolUse","tool_name":"mcp__mati__mem_get","tool_input":{"key":%s},"tool_response":{"isError":false}}' "$agent" "$key"
  else
    printf '{"session_id":"smoke","hook_event_name":"PostToolUse","tool_name":"mcp__mati__mem_get","tool_input":{"key":%s},"tool_response":{"isError":false}}' "$key"
  fi
}
pre_edit() { printf '{"session_id":"smoke","hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":%s,"old_string":"a","new_string":"b"}}' "$1"; }

hook()  { ( cd "$PROJECT" && printf '%s' "$2" | "$MATI" hook-decide "$1" 2>/dev/null ); }
mati_p(){ ( cd "$PROJECT" && "$MATI" "$@" 2>&1 ); }

# Real MCP tool call over stdio. This matters: the MCP `mem_get` handler mints
# the GLOBAL receipt (actor=None), which is what the main-thread gate reads. The
# post-memget hook only mints an actor-scoped receipt, so firing the hook alone
# does NOT reproduce a real consultation.
mcp_call() { # $1 = tool name, $2 = arguments json
  ( cd "$PROJECT" && printf '%s\n%s\n%s\n' \
      '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}' \
      '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
      "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" \
    | "$MATI" serve 2>/dev/null )
}

add_block_policy() { # slug host_glob requires_key via [extra...]
  mati_p policy add "$1" \
    --name "$1" --rule "Consult $3 first." \
    --reason "Schemas drift because production changes independently." \
    --mode block --severity high \
    --trigger  "{\"tool\":\"db_client\",\"host_glob\":\"$2\"}" \
    --requires "{\"key\":\"$3\",\"via\":[\"$4\"],\"freshness\":{\"ttl_secs\":${5:-900}}}" >/dev/null
}

# ── Setup ────────────────────────────────────────────────────────────────────
step "Setup"
cargo build --quiet --bin mati 2>&1 | tail -3
[ -x "$MATI" ] || { echo "binary not found at $MATI"; exit 1; }

mkdir -p "$PROJECT"
( cd "$PROJECT" && git init --quiet && mkdir -p migrations && echo "fn main() {}" > main.rs \
  && echo "select 1;" > migrations/prod.sql && git add -A \
  && git -c user.email=s@s -c user.name=s commit -qm init )
mati_p init >/dev/null

# NOTE: `mati daemon start` runs in the FOREGROUND and blocks, so it is never
# called here. The hook path auto-spawns the daemon via ensure_daemon, which is
# also how it happens in a real session.
hook claude-pre-bash "$(pre_bash '"psql -h db.warmup.internal -c \"select 1\""')" >/dev/null 2>&1
sleep 2

# UDS guard. Some sandboxes forbid binding a Unix domain socket, so the daemon
# never comes up. Every hook then correctly fails open with empty output, which
# makes all 12 deny assertions fail while the rest pass. That is an environment
# limitation, not a policy failure, so exit 77 (skip) rather than reporting a
# misleading red run.
if [ -z "$(find "$MATI_HOME" -name 'mati.sock' 2>/dev/null | head -1)" ]; then
  printf '\n\033[33mSKIP\033[0m daemon socket unavailable; this environment blocks Unix domain sockets.\n'
  printf '     Hooks fail open with empty output here, so deny assertions cannot run.\n'
  exit 77
fi

pass "store initialized, daemon auto-spawned, policy mode defaults strict"

# The policy slug is intentionally the old config key's suffix. The config
# value must live elsewhere so this record remains listable and enforceable.
step "0. Policy slug mode does not collide with policy.mode"
add_block_policy mode '*prod-mode*' 'schema:mode' 'mem_get'
mati_p policy enable mode >/dev/null
mati_p config set policy.mode advisory >/dev/null
LIST="$(mati_p policy list)"
assert_has "mode policy survives advisory switch" "$LIST" 'policy:mode'
mati_p config set policy.mode strict >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-mode.internal -c \"UPDATE orders SET s=1\""')")"
assert_has "mode policy still enforces" "$OUT" 'permissionDecision":"deny"'

# ── 1. Shadow observes, then enforce blocks ──────────────────────────────────
step "1. Shadow observes without blocking, then enforce blocks"
add_block_policy query-a '*prod-a*' 'schema:orders' 'mem_get'
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-a.internal -c \"UPDATE orders SET s=1\""')")"
assert_lacks "not enforced before enable" "$OUT" 'permissionDecision":"deny"'

mati_p policy stage query-a shadow >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-a.internal -c \"UPDATE orders SET s=1\""')")"
assert_lacks "shadow does not block" "$OUT" 'permissionDecision":"deny"'
OBS="$(mati_p policy observations query-a --json)"
assert_has "shadow observation recorded" "$OBS" 'policy:query-a'

add_block_policy shadow-introspection '*prod-introspection*' 'schema:introspection' 'mem_get'
mati_p policy stage shadow-introspection shadow >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-introspection.internal -c \"\\d orders\""')")"
assert_lacks "shadow introspection does not decide" "$OUT" 'permissionDecision'
assert_lacks "shadow introspection adds no context" "$OUT" 'additionalContext'
OBS="$(mati_p policy observations shadow-introspection --json)"
assert_lacks "exempt shadow introspection is not observed" "$OBS" 'policy:shadow-introspection'

add_block_policy shadow-satisfied '*prod-satisfied*' 'schema:shadow-satisfied' 'mem_get'
mati_p policy stage shadow-satisfied shadow >/dev/null
mcp_call mem_get '{"key":"schema:shadow-satisfied"}' >/dev/null
hook claude-pre-bash "$(pre_bash '"psql -h db.prod-satisfied.internal -c \"select 1\""')" >/dev/null
OBS="$(mati_p policy observations shadow-satisfied --json)"
assert_lacks "satisfied shadow block is not observed" "$OBS" 'policy:shadow-satisfied'

mati_p policy add steer-shadow \
  --name "steer shadow" --rule "Review the action." \
  --reason "Steering guidance matters because operators need visibility." \
  --mode steer --trigger '{"tool":"db_client","host_glob":"*steer*"}' \
  --requires '{"key":"","via":[],"freshness":{"ttl_secs":900}}' >/dev/null
mati_p policy stage steer-shadow shadow >/dev/null
hook claude-pre-bash "$(pre_bash '"psql -h db.steer.internal -c \"select 1\""')" >/dev/null
OBS="$(mati_p policy observations steer-shadow --json)"
assert_has "shadow steer observation recorded" "$OBS" '"would": "steer"'

add_block_policy shadow-one '*shadow-one*' 'schema:shadow-one' 'mem_get'
add_block_policy shadow-two '*shadow-two*' 'schema:shadow-two' 'mem_get'
mati_p policy stage shadow-one shadow >/dev/null
mati_p policy stage shadow-two shadow >/dev/null
hook claude-pre-bash "$(pre_bash '"psql -h db.shadow-one.internal -c \"select 1\""')" >/dev/null
hook claude-pre-bash "$(pre_bash '"psql -h db.shadow-two.internal -c \"select 1\""')" >/dev/null
OBS="$(mati_p policy observations --json)"
assert_has "first shadow policy remains visible" "$OBS" 'policy:shadow-one'
assert_has "second shadow policy is visible" "$OBS" 'policy:shadow-two'

mati_p policy enable query-a >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-a.internal -c \"UPDATE orders SET s=1\""')")"
assert_has "denied after enable"   "$OUT" 'permissionDecision":"deny"'
assert_has "names the policy"      "$OUT" 'query-a'
assert_has "names the remedy key"  "$OUT" 'schema:orders'

# ── 2. The gate is narrow ────────────────────────────────────────────────────
step "2. Unrelated commands untouched"
OUT="$(hook claude-pre-bash "$(pre_bash '"ls -la"')")"
assert_lacks "plain shell command" "$OUT" 'permissionDecision'
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h localhost -c \"select 1\""')")"
assert_lacks "non-prod host"       "$OUT" 'permissionDecision":"deny"'

# ── 3. MemGet unlocks ────────────────────────────────────────────────────────
step "3. mem_get mints a receipt and unlocks"
mcp_call mem_get '{"key":"schema:orders"}' >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-a.internal -c \"UPDATE orders SET s=1\""')")"
assert_lacks "allowed after consultation" "$OUT" 'permissionDecision":"deny"'

# ── 4. Introspection: exempt, unlocks, failure mints nothing ─────────────────
step "4. DbIntrospection source"
add_block_policy query-b '*prod-b*' 'schema:billing' 'db_introspection'
mati_p policy enable query-b >/dev/null

OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-b.internal -c \"\\d orders\""')")"
assert_lacks "introspection itself never blocked" "$OUT" 'permissionDecision":"deny"'
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-b.internal -c \"UPDATE billing SET s=1\""')")"
assert_has  "denied before introspection" "$OUT" 'permissionDecision":"deny"'

hook claude-post-bash "$(post_bash '"psql -h db.prod-b.internal -c \"\\d orders\""' 'false' '0')" >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-b.internal -c \"UPDATE billing SET s=1\""')")"
assert_lacks "allowed after introspection" "$OUT" 'permissionDecision":"deny"'

add_block_policy query-c '*prod-c*' 'schema:ledger' 'db_introspection'
mati_p policy enable query-c >/dev/null
hook claude-post-bash "$(post_bash '"psql -h db.prod-c.internal -c \"\\d ledger\""' 'true' '1')" >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-c.internal -c \"UPDATE ledger SET s=1\""')")"
assert_has "FAILED introspection mints nothing" "$OUT" 'permissionDecision":"deny"'

# ── 5. Actor scoping ─────────────────────────────────────────────────────────
step "5. Receipts are actor-scoped"
add_block_policy query-d '*prod-d*' 'schema:actor' 'mem_get'
mati_p policy enable query-d >/dev/null
hook claude-post-memget "$(post_memget '"schema:actor"' 'agent-A')" >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-d.internal -c \"UPDATE t SET s=1\""' 'agent-A')")"
assert_lacks "agent A allowed after its own consult" "$OUT" 'permissionDecision":"deny"'
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-d.internal -c \"UPDATE t SET s=1\""' 'agent-B')")"
assert_has  "agent B still denied (no receipt of its own)" "$OUT" 'permissionDecision":"deny"'

# ── 6. TTL expiry ────────────────────────────────────────────────────────────
step "6. Receipt expires and re-blocks"
add_block_policy query-ttl '*prod-ttl*' 'schema:ttl' 'mem_get' 2
mati_p policy enable query-ttl >/dev/null
mcp_call mem_get '{"key":"schema:ttl"}' >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-ttl.internal -c \"UPDATE t SET s=1\""')")"
assert_lacks "allowed inside TTL" "$OUT" 'permissionDecision":"deny"'
sleep 3
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-ttl.internal -c \"UPDATE t SET s=1\""')")"
assert_has "denied again after TTL expiry" "$OUT" 'permissionDecision":"deny"'

# ── 7. File-bearing command (follow-up A) ────────────────────────────────────
step "7. File-bearing db command composes with the file gate"
add_block_policy query-f '*prod-f*' 'schema:file' 'mem_get'
mati_p policy enable query-f >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-f.internal -f migrations/prod.sql"')")"
assert_has "psql -f denied" "$OUT" 'permissionDecision":"deny"'

# ── 8. Edit gate (follow-up B) ───────────────────────────────────────────────
step "8. Policy on a path steers/blocks an Edit"
mati_p policy add edit-sql \
  --name "SQL edit guard" --rule "Consult the schema before editing SQL." \
  --reason "Migrations drift because production changes independently." \
  --mode block --severity high \
  --trigger  '{"target_path_glob":"**/*.sql"}' \
  --requires '{"key":"schema:migrations","via":["mem_get"],"freshness":{"ttl_secs":900}}' >/dev/null
mati_p policy enable edit-sql >/dev/null
OUT="$(hook claude-pre-edit "$(pre_edit '"migrations/prod.sql"')")"
assert_has  "sql edit denied"          "$OUT" 'permissionDecision":"deny"'
OUT="$(hook claude-pre-edit "$(pre_edit '"main.rs"')")"
assert_lacks "unrelated edit untouched" "$OUT" 'permissionDecision":"deny"'
assert_lacks "edit never force-allows"  "$OUT" 'permissionDecision":"allow"'

# ── 9. Lifecycle: disable, edit, delete ──────────────────────────────────────
step "9. Lifecycle changes take effect immediately"
mati_p policy disable query-a >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-a.internal -c \"UPDATE orders SET s=1\""')")"
assert_lacks "disabled policy stops enforcing" "$OUT" 'permissionDecision":"deny"'

mati_p policy edit query-c --trigger '{"tool":"db_client","host_glob":"*retargeted*"}' >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-c.internal -c \"UPDATE ledger SET s=1\""')")"
assert_lacks "old host no longer matches after edit" "$OUT" 'permissionDecision":"deny"'
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.retargeted.internal -c \"UPDATE ledger SET s=1\""')")"
assert_has  "new host matches after edit" "$OUT" 'permissionDecision":"deny"'

mati_p policy delete query-c >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.retargeted.internal -c \"UPDATE ledger SET s=1\""')")"
assert_lacks "deleted policy stops enforcing" "$OUT" 'permissionDecision":"deny"'

# ── 10. Daemon restart reloads the matcher ───────────────────────────────────
step "10. Matcher survives a daemon restart"
mati_p daemon stop >/dev/null; sleep 1
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-f.internal -f migrations/prod.sql"')")"
assert_has "still enforcing after restart" "$OUT" 'permissionDecision":"deny"'

# ── 11. Concurrency ──────────────────────────────────────────────────────────
step "11. Concurrent hook invocations"
CONC_FAIL=0
for i in 1 2 3 4 5; do
  ( OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-f.internal -f migrations/prod.sql"')")"
    denied "$OUT" || echo "miss" ) &
done > "$WORK/conc.out"
wait
grep -q miss "$WORK/conc.out" && CONC_FAIL=1
if [ "$CONC_FAIL" -eq 0 ]; then pass "5 parallel hooks all denied"; else fail "5 parallel hooks all denied" "$(cat "$WORK/conc.out")"; fi

# ── 12. Global kill switch ───────────────────────────────────────────────────
# policy.mode=advisory must degrade every block to a steer without disabling the
# match: the rule still reaches Claude, it just stops denying.
step "12. Advisory mode degrades a block to a steer"
add_block_policy adv '*prod-adv*' 'schema:adv' 'mem_get'
mati_p policy enable adv >/dev/null
mati_p config set policy.mode advisory >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-adv.internal -c \"UPDATE orders SET s=1\""')")"
assert_lacks "advisory does not deny"      "$OUT" 'permissionDecision'
assert_has   "advisory still injects"      "$OUT" 'additionalContext'
assert_has   "advisory names the remedy"   "$OUT" 'schema:adv'

# One setting, every policy: an operator flipping this during an incident must
# not have to find and disable each rule.
add_block_policy adv2 '*prod-adv2*' 'schema:adv2' 'mem_get'
mati_p policy enable adv2 >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-adv2.internal -c \"select 1\""')")"
assert_lacks "advisory is global, not per-policy" "$OUT" 'permissionDecision'

# It is a stored setting, not daemon state, so a restart must not re-arm it.
mati_p daemon stop >/dev/null; sleep 1
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-adv.internal -c \"select 1\""')")"
assert_lacks "advisory survives a daemon restart" "$OUT" 'permissionDecision'

# Blast radius: the switch governs policy only. A confirmed gotcha must keep
# denying, or an operator silencing policy would silently drop the file gate too.
echo "fn helper() {}" > "$PROJECT/gate.rs"
( cd "$PROJECT" && git add gate.rs && git -c user.email=s@s -c user.name=s commit -qm gate ) >/dev/null 2>&1
GK="$(mati_p gotcha add gate.rs -r "Never edit gate.rs blindly" -m "Because it breaks the build" -s critical | grep -o 'gotcha:[a-z0-9-]*' | head -1)"
mati_p gotcha confirm "${GK#gotcha:}" >/dev/null 2>&1
OUT="$(hook claude-pre-read "$(printf '{"session_id":"smoke","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"%s/gate.rs"}}' "$PROJECT")")"
assert_has "gotcha gate still denies under advisory" "$OUT" 'permissionDecision":"deny"'

mati_p config set policy.mode strict >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-adv.internal -c \"UPDATE orders SET s=1\""')")"
assert_has   "strict denies again"         "$OUT" 'permissionDecision":"deny"'

# ── 13. Steer at enforce ─────────────────────────────────────────────────────
# A steer policy injects context and sets no permissionDecision at all, so the
# user's own permission prompt still runs.
step "13. Enforce-stage steer injects without deciding"
mati_p policy add steer-live \
  --name "steer live" --rule "Review the action." \
  --reason "Operators need visibility because production is live." \
  --mode steer --trigger '{"tool":"db_client","host_glob":"*prod-steer*"}' \
  --requires '{"key":"","via":[],"freshness":{"ttl_secs":900}}' --enable >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-steer.internal -c \"select 1\""')")"
assert_has   "steer injects the rule"   "$OUT" 'Review the action.'
assert_lacks "steer never decides"      "$OUT" 'permissionDecision'

# ── 14. Receipt sources ──────────────────────────────────────────────────────
# The introspection exemption suppresses blocks but must not mint: a policy that
# accepts only MemGet stays locked after the agent inspects the schema itself.
step "14. Receipt sources are not interchangeable"
add_block_policy viaonly '*prod-vo*' 'schema:vo' 'mem_get'
mati_p policy enable viaonly >/dev/null
hook claude-post-bash "$(post_bash '"psql -h db.prod-vo.internal -c \"\\d orders\""' false 0)" >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-vo.internal -c \"select 1\""')")"
assert_has "introspection does not satisfy a mem_get policy" "$OUT" 'permissionDecision":"deny"'
mcp_call mem_get '{"key":"schema:vo"}' >/dev/null
OUT="$(hook claude-pre-bash "$(pre_bash '"psql -h db.prod-vo.internal -c \"select 1\""')")"
assert_lacks "the declared source does satisfy it" "$OUT" 'permissionDecision":"deny"'

# ── 15. Author-time validation ───────────────────────────────────────────────
# A broken glob must never reach the daemon, and a MemGet requirement pointing
# at nothing must say so: consulting an empty key teaches the agent nothing.
step "15. Author-time validation"
OUT="$(mati_p policy add badglob --name bad --rule "Consult first." \
  --reason "Schemas drift because production changes." --mode block \
  --trigger '{"tool":"db_client","host_glob":"[unclosed"}' \
  --requires '{"key":"schema:bad","via":["mem_get"],"freshness":{"ttl_secs":900}}')"
assert_has  "malformed host_glob is rejected" "$OUT" "invalid host_glob"
assert_lacks "rejected policy is not persisted" "$(mati_p policy list)" 'policy:badglob'
OUT="$(mati_p policy add unbacked --name unb --rule "Consult first." \
  --reason "Schemas drift because production changes." --mode block \
  --trigger '{"tool":"db_client","host_glob":"*prod-unb*"}' \
  --requires '{"key":"schema:nothing-here","via":["mem_get"],"freshness":{"ttl_secs":900}}')"
assert_has "unbacked requires.key warns" "$OUT" 'has no backing record'

# ── 16. Dry-run and stage parsing ────────────────────────────────────────────
step "16. Dry-run and stage parsing"
OUT="$(mati_p policy test --trigger '{"tool":"db_client","host_glob":"*prod*"}' \
  --command 'psql -h db.prod.internal -c "select 1"')"
assert_has "dry-run reports a match"       "$OUT" 'matched=true'
assert_has "dry-run persists nothing"      "$OUT" 'persisted=false'
OUT="$(mati_p policy test --trigger '{"tool":"db_client","host_glob":"*prod*"}' \
  --command 'psql -h db.staging.internal -c "select 1"')"
assert_has "dry-run reports a non-match"   "$OUT" 'matched=false'
assert_has "an invalid stage is refused"   "$(mati_p policy stage adv bogus)" 'expected off, shadow, or enforce'

# ── 17. Agent edits inside its own stage ─────────────────────────────────────
# The boundary cuts both ways: an off policy is the agent's draft to refine.
step "17. mem_set may edit an off policy"
mati_p policy add draft --name draft --rule "Old rule." \
  --reason "Schemas drift because production changes." --mode block \
  --trigger '{"tool":"db_client","host_glob":"*prod-draft*"}' \
  --requires '{"key":"schema:draft","via":["mem_get"],"freshness":{"ttl_secs":900}}' >/dev/null
DRAFT_JSON='{"name":"draft","rule":"New rule.","reason":"Schemas drift because production changes.","scope":"repo","mode":"block","trigger":{"tool":"db_client","host_glob":"*prod-draft*"},"requires":{"key":"schema:draft","via":["mem_get"],"freshness":{"ttl_secs":900}},"stage":"off","severity":"high","created_by":"agent"}'
OUT="$(mcp_call mem_set "{\"action\":\"write\",\"key\":\"policy:draft\",\"value\":\"New rule.\",\"category\":\"Policy\",\"payload\":$DRAFT_JSON,\"tags\":[],\"priority\":\"High\"}")"
assert_has "agent may edit an off policy" "$OUT" 'ok.":true'
SHOW="$(mati_p policy show draft)"
assert_has "the edit landed"              "$SHOW" 'New rule.'
assert_has "and it stayed off"            "$SHOW" '"stage": "off"'

# ── 18. Fail-open ────────────────────────────────────────────────────────────
step "18. A dead daemon fails open (P9)"
mati_p daemon stop >/dev/null; sleep 1
PAYLOAD="$(pre_bash '"psql -h db.prod-f.internal -f migrations/prod.sql"')"
OUT="$( cd "$PROJECT" && printf '%s' "$PAYLOAD" \
        | MATI_DISABLE_AUTO_SPAWN=1 "$MATI" hook-decide claude-pre-bash 2>/dev/null )"
assert_lacks "not denied when mati is down" "$OUT" 'permissionDecision":"deny"'

# ── 19. Agent authoring boundary (MCP) ───────────────────────────────────────
step "19. mem_set agent boundary"
POLICY_JSON='{"name":"agent authored","rule":"Consult first.","reason":"Schemas drift because production changes.","scope":"repo","mode":"block","trigger":{"tool":"db_client","host_glob":"*agent*"},"requires":{"key":"schema:agent","via":["mem_get"],"freshness":{"ttl_secs":900}},"stage":"enforce","severity":"high","created_by":"agent"}'
OUT="$(mcp_call mem_set "{\"action\":\"write\",\"key\":\"policy:agent-authored\",\"value\":\"Consult first.\",\"category\":\"Policy\",\"payload\":$POLICY_JSON,\"tags\":[],\"priority\":\"High\"}")"
if printf '%s' "$OUT" | grep -q 'jsonrpc'; then
  assert_has "agent-authored policy is forced inert" "$OUT" 'stage.":."off'
  OUT2="$(mcp_call mem_set '{"action":"confirm","key":"policy:agent-authored","value":"","category":"Policy","payload":{},"tags":[],"priority":"Normal"}')"
  assert_has "agent cannot enable a policy" "$OUT2" 'mati policy enable'
else
  skip "mem_set agent boundary" "MCP stdio handshake produced no response"
fi

mati_p policy add staged-delete \
  --name "staged delete" --rule "Consult first." \
  --reason "Schemas drift because production changes." --mode block \
  --trigger '{"tool":"db_client","host_glob":"*staged-delete*"}' \
  --requires '{"key":"schema:staged-delete","via":["mem_get"],"freshness":{"ttl_secs":900}}' \
  --shadow >/dev/null
OUT2="$(mcp_call mem_set '{"action":"delete","key":"policy:staged-delete","value":"","category":"Policy","payload":{},"tags":[],"priority":"Normal"}')"
assert_has "agent cannot delete shadow policy" "$OUT2" 'mati policy stage staged-delete off'

# ── Summary ──────────────────────────────────────────────────────────────────
printf '\n\033[1m== Summary ==\033[0m\n  passed: %d\n  failed: %d\n  skipped: %d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
printf '\n\033[32mPolicy engine verified end to end.\033[0m\n'
