#!/usr/bin/env bash
#
# Set up a throwaway project wired for a REAL Claude Code session.
#
# smoke-policy.sh proves the wiring against payloads we construct from the
# documented schema. It cannot prove the contracts that only Claude Code itself
# produces:
#
#   1. `tool_response.isError` on PostToolUse — gates DbIntrospection minting.
#      If Claude changes the field name or shape, minting stops silently and a
#      policy never unlocks.
#   2. That `permissionDecision: "deny"` and `additionalContext` actually reach
#      the model, rather than being emitted into a shape Claude ignores.
#   3. That a symlinked target resolves BEFORE the policy gate runs, against the
#      real paths a session sends. This is new enforcement behavior — mati now
#      denies edits and commands it previously allowed — and a synthetic payload
#      cannot prove the resolution happens on the path Claude actually reports.
#
# NOT covered here: the Codex `apply_patch` policy surfaces (deny wording,
# symlink resolution, miss recording). This fixture drives Claude Code, which
# never emits `apply_patch`, so those stay smoke-only until a Codex fixture
# exists. Stated so the gap is known rather than assumed closed.
#
# This script only builds the fixture. The checks are run by pasting the prompt
# printed at the end into a Claude Code session opened in the fixture directory.
#
# Usage:  ./scripts/policy-live-session.sh [dir]
#         default dir: $TMPDIR/mati-policy-live
#
# The default lives outside the repo on purpose. macOS caps a Unix socket path
# at SUN_LEN (104 bytes) and the daemon binds $MATI_HOME/<slug>/mati.sock, so a
# fixture nested under target/ fails to bind and every hook then fails open.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${1:-${TMPDIR:-/tmp}/mati-policy-live}"
MATI="$REPO_ROOT/target/debug/mati"

cargo build --quiet --bin mati || exit 1
[ -x "$MATI" ] || { echo "binary not found at $MATI"; exit 1; }

# The store lives in $MATI_HOME/<slug>, not in the project, so deleting the
# project alone leaves stale policies and receipts behind and the fixture is not
# reproducible. Keep the whole thing self-contained under $DEST instead. The
# session must export the same MATI_HOME; the launch line below does that.
export MATI_HOME="$DEST/.mati-home"

# A daemon from an earlier run still holds the store lock, and removing the
# directory out from under it does not release it.
if [ -d "$DEST" ]; then
  ( cd "$DEST" && "$MATI" daemon stop >/dev/null 2>&1 )
fi
rm -rf "$DEST"
mkdir -p "$DEST/migrations" "$DEST/vault"
cd "$DEST" || exit 1

cat > main.rs <<'RS'
fn main() {
    println!("fixture");
}
RS
echo "select 1;" > migrations/prod.sql
echo "// generated; do not edit by hand" > model.gen.rs

# Symlink bypass fixtures. The governed files live under vault/; the symlinks
# sit at the repo root with names no policy glob matches. Only the RESOLVED
# target matches, so a gate that reads the lexical path lets the write through
# to a governed file. Both are committed with everything else, so the fixture
# reproduces from a clean checkout.
echo "api_key = REDACTED" > vault/keys.txt
echo "select * from vault_audit;" > vault/query.sql
ln -s vault/keys.txt notes.txt
ln -s vault/query.sql report.sql

# A stub psql. Without a real client on PATH the command fails to spawn, Claude
# reports tool_response.isError: true, and DbIntrospection correctly refuses to
# mint — which looks identical to a broken minting contract. The stub exits 0 so
# the receipt step actually exercises the contract instead of the error path.
# Nothing connects anywhere; the hook decision is the whole point.
mkdir -p bin
cat > bin/psql <<'SH'
#!/usr/bin/env bash
# fixture stub: never connects, always succeeds. Echo the query back so two
# different commands produce different output; a canned response makes a payload
# log useless for telling one command's result from another.
QUERY=""
while [ $# -gt 0 ]; do
  case "$1" in
    -c|--command) QUERY="$2"; shift 2 ;;
    *) shift ;;
  esac
done
case "$QUERY" in
  *'\d'*|*DESCRIBE*|*describe*)
    echo "Table \"public.inventory\""
    echo " sku | warehouse | on_hand | reserved" ;;
  "") echo "psql (fixture stub)" ;;
  *)  echo "query: $QUERY"
      echo " sku-001 | west | 42 | 3" ;;
esac
exit 0
SH
chmod +x bin/psql
git init --quiet
git add -A
git -c user.email=fixture@local -c user.name=fixture commit -qm "fixture" >/dev/null

# --claude is required on a fresh project: the integration is auto-detected only
# when .claude/ already exists, so without it the fixture has no hooks and no MCP
# server, and every step in the prompt below would pass without firing anything.
"$MATI" init --claude >/dev/null || exit 1

# Warm the daemon the way a real session does — fire one hook, which brings up a
# single detached daemon through ensure_daemon (flock-serialized, so it can't
# race a concurrent spawn) and then poll for its socket. Do NOT background
# `mati daemon start` here: that bypasses the ensure_daemon spawn lock, and a
# foreground daemon tied to this shell can be left holding the store lock in an
# unreachable state when the script exits, after which every session read spawns
# a doomed competitor and falls back to a locked direct open.
printf '%s' '{"session_id":"fixture","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"psql -h db.warmup.internal -c \"select 1\""}}' \
  | "$MATI" hook-decide claude-pre-bash >/dev/null 2>&1
for _ in $(seq 1 15); do
  [ -n "$(find "$MATI_HOME" -name mati.sock 2>/dev/null | head -1)" ] && break
  sleep 1
done
[ -n "$(find "$MATI_HOME" -name mati.sock 2>/dev/null | head -1)" ] || {
  echo "daemon socket never appeared; Unix sockets may be blocked" >&2; exit 1; }

# A substantive record behind requires.key, so the MemGet receipt is not hollow
# (ARCHITECTURE section 10a.5). Each policy gets its OWN requires.key. Sharing one key would let the single
# mem_get in step 2 satisfy every policy at once, and the later steps would pass
# without proving anything.
write_record() { # key summary
  printf '%s\n%s\n%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"mem_set\",\"arguments\":{\"action\":\"write\",\"key\":\"$1\",\"value\":\"$1\",\"category\":\"Decision\",\"payload\":{\"summary\":\"$2\",\"rationale\":\"Pinned so a production query policy has something substantive to consult.\"},\"tags\":[\"schema\"],\"priority\":\"High\"}}}" \
    | "$MATI" serve >/dev/null 2>&1
}

# `mem_set` accepts only gotcha:/decision:/dev_note:/policy: prefixes and there
# is no CLI writer for an arbitrary key, so the `schema:orders` used as an
# illustration elsewhere cannot actually be created. decision: is the stand-in.
write_record decision:orders-schema    "orders(id bigint pk, customer_id bigint, status text, total_cents bigint)."
write_record decision:inventory-schema "inventory(sku text pk, warehouse text, on_hand int, reserved int)."
write_record decision:ledger-schema    "ledger(entry_id bigint pk, account text, amount_cents bigint, posted_at timestamptz)."
write_record decision:audit-schema     "audit_log(id bigint pk, actor text, action text, at timestamptz)."
write_record decision:migrations-schema "migrations are applied in filename order and are never edited after being applied to production."
write_record decision:vault-edit       "vault/keys.txt holds credentials; rotate through the secrets pipeline, never by hand."
write_record decision:vault-query      "vault/query.sql reads the credential audit table and is reviewed before every change."

add_policy() { # slug host_glob requires_key via
  "$MATI" policy add "$1" \
    --name "$1" --rule "Consult $3 before querying production." \
    --reason "Schemas drift because production changes independently." \
    --mode block --severity high \
    --trigger  "{\"tool\":\"db_client\",\"host_glob\":\"$2\"}" \
    --requires "{\"key\":\"$3\",\"via\":[\"$4\"],\"freshness\":{\"ttl_secs\":900}}" >/dev/null
}

add_policy live-memget     '*prod-memget*'     'decision:orders-schema'    'mem_get'
add_policy live-introspect '*prod-introspect*' 'decision:inventory-schema' 'db_introspection'
add_policy live-killswitch '*prod-switch*'     'decision:audit-schema'     'mem_get'
"$MATI" policy enable live-memget >/dev/null
"$MATI" policy enable live-introspect >/dev/null
"$MATI" policy enable live-killswitch >/dev/null

"$MATI" policy add live-shadow \
  --name live-shadow --rule "Consult decision:ledger-schema before querying production." \
  --reason "Schemas drift because production changes independently." \
  --mode block --severity high \
  --trigger '{"tool":"db_client","host_glob":"*prod-shadow*"}' \
  --requires '{"key":"decision:ledger-schema","via":["mem_get"],"freshness":{"ttl_secs":900}}' >/dev/null
"$MATI" policy stage live-shadow shadow >/dev/null

# The edit gate is the third enforcement path and the one smoke has only ever
# checked against payloads we wrote ourselves. A path policy matches
# target_path_glob against Edit/Write/NotebookEdit instead of a bash command.
"$MATI" policy add live-editblock \
  --name live-editblock --rule "Consult decision:migrations-schema before editing SQL." \
  --reason "Migrations drift because production changes independently." \
  --mode block --severity high \
  --trigger '{"target_path_glob":"**/*.sql"}' \
  --requires '{"key":"decision:migrations-schema","via":["mem_get"],"freshness":{"ttl_secs":900}}' >/dev/null
"$MATI" policy enable live-editblock >/dev/null

# A steer-mode path policy must inject context and set no permissionDecision at
# all, so the user's own edit prompt still runs.
"$MATI" policy add live-editsteer \
  --name live-editsteer --rule "Prefer editing the generator, not the generated file." \
  --reason "Hand edits are lost because the file is regenerated on build." \
  --mode steer --severity normal \
  --trigger '{"target_path_glob":"**/*.gen.rs"}' \
  --requires '{"key":"","via":[],"freshness":{"ttl_secs":900}}' >/dev/null
"$MATI" policy enable live-editsteer >/dev/null

# Symlink resolution, one policy per enforcement path. `tool` is pinned on each
# so they cannot cross-fire: the edit policy must not match the `psql -f` action
# and vice versa, or a pass would not say which gate resolved the target.
# Neither glob touches migrations/prod.sql, model.gen.rs, or main.rs, so the
# earlier steps are unaffected.
#
# `vault/**`, not `**/vault/**`: the leading `**/` would have to match ZERO
# directories for a root-level vault/ to match, and nothing in the suite proves
# globset does that. A glob that quietly fails to match makes both symlink steps
# report a false pass — the exact failure this fixture exists to catch.
# `migrations/**` is already proven against a real command in smoke-policy.sh.
#
# These get their OWN requires keys rather than reusing live-editblock's. By the
# time the symlink steps run, the edit-gate step has already consulted
# decision:migrations-schema and left a 900s receipt — a shared key would make
# these pass without the symlink ever being resolved.
"$MATI" policy add live-editsymlink \
  --name live-editsymlink --rule "Consult decision:vault-edit before editing vault files." \
  --reason "Credentials rotate out of band because the secrets pipeline owns them." \
  --mode block --severity high \
  --trigger  '{"tool":"path","target_path_glob":"vault/**"}' \
  --requires '{"key":"decision:vault-edit","via":["mem_get"],"freshness":{"ttl_secs":900}}' >/dev/null
"$MATI" policy enable live-editsymlink >/dev/null

"$MATI" policy add live-bashsymlink \
  --name live-bashsymlink --rule "Consult decision:vault-query before running vault SQL." \
  --reason "The credential audit table changes because rotation writes to it." \
  --mode block --severity high \
  --trigger  '{"tool":"db_client","target_path_glob":"vault/**"}' \
  --requires '{"key":"decision:vault-query","via":["mem_get"],"freshness":{"ttl_secs":900}}' >/dev/null
"$MATI" policy enable live-bashsymlink >/dev/null

# Capture the raw PostToolUse Bash payload. smoke-policy.sh builds this payload
# from the documented schema, so a mismatch with what Claude Code actually sends
# is invisible to it. Tee it to a file so the real shape can be read directly.
cat > .claude/hooks/post-bash.sh <<'SH'
#!/usr/bin/env bash
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
PAYLOAD="$(cat)"
# Only record payloads from a real session. transcript_path is present on every
# Claude Code payload and absent from a hand-authored one, so a local probe
# piping into this script cannot pollute the capture and be mistaken for
# evidence later.
case "$PAYLOAD" in
  *'"transcript_path"'*) printf '%s\n' "$PAYLOAD" >> "${MATI_HOME:-/tmp}/post-bash-payloads.jsonl" ;;
esac
command -v mati >/dev/null 2>&1 || exit 0
printf '%s' "$PAYLOAD" | exec mati hook-decide claude-post-bash
SH
chmod +x .claude/hooks/post-bash.sh

for f in .claude/settings.json .mcp.json; do
  [ -f "$DEST/$f" ] || { echo "fixture is not wired: $f missing" >&2; exit 1; }
done

printf '\n\033[1mFixture ready:\033[0m %s\n' "$DEST"
"$MATI" policy list
printf '\nPolicy mode: %s\n' "$("$MATI" config get policy.mode 2>/dev/null || echo strict)"

cat <<EOF

────────────────────────────────────────────────────────────────────────────
Open a Claude Code session in the fixture, then paste the prompt below.
Both exports are required. Each hook checks for mati on PATH and exits silently
if absent; without MATI_HOME the session reads a different store.
Either mistake makes EVERY step pass without enforcing anything.

  cd $DEST
  export MATI_HOME=$DEST/.mati-home
  export PATH=$DEST/bin:$REPO_ROOT/target/debug:\$PATH
  claude

Claude Code will ask you to trust the folder. Hooks do not run until you do.

Nothing here touches a real database. Every command is against a hostname
that does not resolve; only the hook decision matters, not the query result.
────────────────────────────────────────────────────────────────────────────

PROMPT TO PASTE:

You run every step yourself, in this session, using your Bash tool and your
mati MCP tools. Nothing here is for the human to run.

Run each step in order. Report PASS or FAIL with the actual output you saw.
Do not skip a step because an earlier one failed. Do not call mem_get unless a
step tells you to: an unasked-for consultation will unlock a later step and
make it pass for the wrong reason.

Each policy has its own consult key, so satisfying one does not satisfy another.

0. Run with your Bash tool: command -v mati
   EXPECT: a path ending in target/debug/mati. If it is anything else, or empty,
   STOP and report it. The hooks exit silently when mati is not on PATH.

1. Run: psql -h db.prod-memget.internal -c "UPDATE orders SET status='x'"
   EXPECT: blocked before it runs, naming policy live-memget and telling you to
   consult decision:orders-schema.
   PASS if you were blocked. FAIL if the command executed.
   This step is the canary. If it does NOT block, STOP: the wiring is broken and
   every later step would pass for the wrong reason. Report that instead.

2. Call the mem_get MCP tool with key "decision:orders-schema".
   EXPECT: the orders schema summary comes back.

3. Run the exact command from step 1 again.
   EXPECT: not blocked. It will fail to resolve the host; that is fine, the
   hook decision is what matters.
   PASS proves deny -> consult -> allow end to end.

4. Run: psql -h db.prod-introspect.internal -c "\\d inventory"
   Report the exit status of this command explicitly. The fixture ships a stub
   psql on PATH that always exits 0. If this command fails to spawn, step 5
   cannot mean anything, because minting is supposed to refuse after a failed
   introspection.
   EXPECT: never blocked. Introspection is exempt from policy blocks. You may
   still be given the policy rule as context; that is expected. The exemption
   suppresses the block only, so the verdict falls through to steering.

5. Run: psql -h db.prod-introspect.internal -c "SELECT * FROM inventory LIMIT 1"
   EXPECT: NOT blocked, because step 4 minted the receipt for
   decision:inventory-schema.
   This is the contract only a live session can prove: minting depends on Claude
   reporting tool_response.isError as false.
   If you ARE blocked here, quote the exact block message, then say which of
   these two it is:
     (a) step 4 exited 0 and you were still blocked -> the minting contract is
         broken, which is the finding this fixture exists to surface;
     (b) step 4 did not exit 0 -> inconclusive, because refusing to mint after a
         failed introspection is correct behavior.

6. Run: psql -h db.prod-shadow.internal -c "UPDATE ledger SET amount_cents=1"
   EXPECT: NOT blocked, and no policy text injected. live-shadow is staged
   shadow, so it observes without acting.

7. Run with your Bash tool: mati policy observations live-shadow --json
   EXPECT: one observation with "would": "block".
   This is what a developer would read before promoting the policy.

8. Run: psql -h db.prod-switch.internal -c "UPDATE audit_log SET actor='x'"
   EXPECT: blocked by live-killswitch.

9. Run with your Bash tool: mati config set policy.mode advisory
   Then run the step 8 command again in a NEW message.
   EXPECT: not blocked, but you are given the policy rule as context.
   PASS only if BOTH are true: no block, and you saw the rule text.

10. Run with your Bash tool: mati config set policy.mode strict
    Then run the step 8 command again in a NEW message.
    EXPECT: blocked again. The switch re-arms with no restart.

11. Use mem_set to write a policy record at key policy:live-agent with
    stage "enforce" and any valid trigger and requires.
    EXPECT: accepted, but forced to stage "off". Then run
    mati policy list and confirm live-agent shows off.
    PASS if an agent could not create an enforcing policy.

12. Use mem_set to delete key policy:live-shadow.
    EXPECT: refused, because live-shadow is staged and staged policies are
    developer-controlled.

13. Read migrations/prod.sql with your Read tool, then use your Edit tool to
    change "select 1;" to "select 2;".
    Read it first: Claude Code's own read-before-edit rule would stop a blind
    edit before any hook runs, and that is not what this step is testing.
    EXPECT: the edit is DENIED by policy live-editblock, naming
    decision:migrations-schema. Reading the file does not satisfy it; the
    policy requires a mem_get on that key.

14. Call the mem_get MCP tool with key "decision:migrations-schema", then retry
    the same edit.
    EXPECT: no longer denied.

15. Read model.gen.rs, then use your Edit tool to change the comment text.
    EXPECT: NOT denied. live-editsteer is a steer policy, so you should receive
    "Prefer editing the generator, not the generated file." as context with no
    permission decision attached.
    Report whether you saw the rule text, and whether the edit was blocked.

16. Read main.rs, then use your Edit tool to change "fixture" to "fixture2".
    EXPECT: untouched by policy. No deny, and no policy rule injected.
    Confirm specifically that mati did not force-allow it either: a forced
    allow would suppress your own permission prompt, which mati must never do
    for an edit.

17. Read notes.txt with your Read tool, then use your Edit tool to change
    REDACTED to ROTATED.
    notes.txt is a symlink to vault/keys.txt. No policy glob matches the name
    "notes.txt"; only the resolved target matches. So this step passes ONLY if
    the gate resolved the symlink before deciding.
    EXPECT: DENIED by live-editsymlink, naming decision:vault-edit.
    If the edit went through, the write landed on a governed file through a
    name nothing was watching — report that as the finding, not as a skip.

18. Call the mem_get MCP tool with key "decision:vault-edit", then retry the
    same edit to notes.txt.
    EXPECT: no longer denied. A deny that cannot be cleared by the key it names
    is worse than no deny at all, so this half matters as much as step 17.

19. Run: psql -f report.sql
    report.sql is a symlink to vault/query.sql — the same bypass on the bash
    path instead of the edit path.
    EXPECT: DENIED by live-bashsymlink, naming decision:vault-query.
    The fixture's stub psql ignores -f and exits 0, so if the gate did not fire
    the command SUCCEEDS. A success here is a real FAIL, not an inconclusive
    result — say which you saw.

20. Run with your Bash tool: mati policy activity live-editsteer --json
    EXPECT: "state": "fired", with "steer" among "sources".
    Step 15 steered a real edit; this checks the trace survived the live hook
    path rather than only the synthetic one. Other policies may also show steer
    activity — step 9 set policy.mode advisory, which degrades a block to a
    steer — so that is expected, not a failure. Only live-editsteer matters.

Report a table: step -> PASS/FAIL -> what you actually observed.
Then state plainly whether step 5 and step 17 passed. Step 5 is the minting
contract this fixture was built for; step 17 is the newest enforcement behavior
and the one no live session has ever exercised.
EOF
