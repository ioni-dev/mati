#!/usr/bin/env bash
# Build a throwaway fixture for a REAL Codex session.
# smoke-policy.sh uses documented payloads; this captures Codex's real shapes.
set -uo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
TMPBASE=$(printenv TMPDIR || true); [ -n "$TMPBASE" ] || TMPBASE=/tmp
if [ $# -gt 0 ]; then DEST="$1"; else DEST="$TMPBASE/mati-policy-live-codex"; fi
MATI="$REPO_ROOT/target/debug/mati"
cargo build --quiet --bin mati || exit 1
[ -x "$MATI" ] || { echo "binary not found at $MATI" >&2; exit 1; }
# The store must live beside the fixture, not in the project: removing the
# project otherwise leaves policies/receipts behind and breaks reproducibility.
MATI_HOME="$DEST/.mati-home"; export MATI_HOME
if [ -d "$DEST" ]; then ( cd "$DEST" && "$MATI" daemon stop >/dev/null 2>&1 ); fi
rm -rf "$DEST"; mkdir -p "$DEST/migrations" "$DEST/vault" "$DEST/bin"; cd "$DEST" || exit 1
echo "select 1;" > migrations/prod.sql; echo "fixture" > main.rs
echo "api_key = REDACTED" > vault/keys.txt; ln -s vault/keys.txt governed.txt
echo "probe" > probe.txt

# A successful stub is required: a missing client makes introspection fail and
# correctly refuse to mint. This stub never connects to a real database.
cat > bin/psql <<'SH'
#!/usr/bin/env bash
QUERY=""
while [ $# -gt 0 ]; do case "$1" in -c|--command) QUERY="$2"; shift 2;; *) shift;; esac; done
case "$QUERY" in *'\d'*|*DESCRIBE*|*describe*) echo 'Table "public.inventory"'; echo ' sku | warehouse | on_hand | reserved';; *) echo "query: $QUERY";; esac
exit 0
SH
chmod +x bin/psql

"$MATI" init --codex >/dev/null || exit 1
# init owns the generated wrappers, so install the capture adapters after it
# finishes writing them. Codex has no safe transcript_path equivalent: every
# line is captured, and step 0 creates the first lines through real tools.
cat > .codex/hooks/pre-apply-patch.sh <<'SH'
#!/usr/bin/env bash
set -uo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
PAYLOAD="$(cat)"
if [ -n "${MATI_HOME:-}" ]; then
  printf '%s\n' "$PAYLOAD" >> "$MATI_HOME/codex-pre-apply-patch-payloads.jsonl"
fi
command -v mati >/dev/null 2>&1 || exit 0
out="$(printf '%s' "$PAYLOAD" | mati hook-decide codex-pre-apply-patch 2>&1)"; rc=$?
if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -q '^mati:'; then printf '%s\n' "$out" >&2; exit 2; fi
exit 0
SH
cat > .codex/hooks/post-bash.sh <<'SH'
#!/usr/bin/env bash
set -uo pipefail
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)" && export PATH="$HOOKS_DIR:$PATH"
PAYLOAD="$(cat)"
if [ -n "${MATI_HOME:-}" ]; then
  printf '%s\n' "$PAYLOAD" >> "$MATI_HOME/codex-post-bash-payloads.jsonl"
fi
command -v mati >/dev/null 2>&1 || exit 0
printf '%s' "$PAYLOAD" | exec mati hook-decide codex-post-bash
SH
chmod +x .codex/hooks/pre-apply-patch.sh .codex/hooks/post-bash.sh
for f in .codex/hooks.json .codex/config.toml .codex/hooks/session-start.sh .codex/hooks/user-prompt-submit.sh .codex/hooks/pre-bash.sh .codex/hooks/pre-apply-patch.sh .codex/hooks/post-bash.sh .codex/hooks/stop.sh; do
  [ -f "$f" ] || { echo "fixture is not wired: $f missing" >&2; exit 1; }
done
grep -Eq '"Bash"|"apply_patch"' .codex/hooks.json || { echo "Codex matchers missing" >&2; exit 1; }
grep -Eq 'mcp_servers\.mati|\[mcp_servers\.mati\]' .codex/config.toml || { echo "mati MCP server missing" >&2; exit 1; }

# Warm the daemon the way a real session does — fire one hook, which brings up a
# single detached daemon through ensure_daemon (flock-serialized, so it can't
# race a concurrent spawn) and then poll for its socket. Do NOT background
# `mati daemon start` here: that bypasses the ensure_daemon spawn lock, and a
# foreground daemon tied to this shell can be left holding the store lock in an
# unreachable state when the script exits, after which every session read spawns
# a doomed competitor and falls back to a locked direct open.
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"psql -h db.warmup.internal -c \"select 1\""}}' \
  | "$MATI" hook-decide codex-pre-bash >/dev/null 2>&1
for _ in $(seq 1 15); do
  [ -n "$(find "$MATI_HOME" -name mati.sock 2>/dev/null | head -1)" ] && break
  sleep 1
done
[ -n "$(find "$MATI_HOME" -name mati.sock 2>/dev/null | head -1)" ] || {
  echo "daemon socket never appeared; Unix sockets may be blocked" >&2; exit 1; }

write_record() {
  printf '%s\n%s\n%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"mem_set\",\"arguments\":{\"action\":\"write\",\"key\":\"$1\",\"value\":\"$1\",\"category\":\"Decision\",\"payload\":{\"summary\":\"$2\",\"rationale\":\"Pinned so this live policy has substantive knowledge behind its receipt.\"},\"tags\":[\"schema\"],\"priority\":\"High\"}}}" | "$MATI" serve >/dev/null 2>&1
}
# Each policy gets a distinct requires key. Sharing one key would let an early
# mem_get satisfy later policies and make a false pass look like enforcement.
write_record decision:codex-migrations "migrations/prod.sql is production-controlled and requires review."
write_record decision:codex-vault "vault/keys.txt holds credentials; rotate through the secrets pipeline."
write_record decision:codex-shadow "migrations require review before production changes."
write_record decision:codex-inventory "inventory(sku text pk, warehouse text, on_hand int, reserved int)."

add_policy() {
  "$MATI" policy add "$1" --name "$1" --rule "$2" --reason "$3" --mode block --severity high --trigger "$4" --requires "$5" >/dev/null
  if [ "$6" = enable ]; then
    "$MATI" policy enable "$1" >/dev/null
  fi
}
add_policy codex-apply-block "Consult decision:codex-migrations before editing migrations." "Migrations drift because production changes independently." '{"tool":"path","target_path_glob":"migrations/**"}' '{"key":"decision:codex-migrations","via":["mem_get"],"freshness":{"ttl_secs":900}}' enable
add_policy codex-symlink "Consult decision:codex-vault before editing vault files." "Credentials rotate out of band because the secrets pipeline owns them." '{"tool":"path","target_path_glob":"vault/**"}' '{"key":"decision:codex-vault","via":["mem_get"],"freshness":{"ttl_secs":900}}' enable
add_policy codex-shadow "Consult decision:codex-shadow before editing migrations." "Migrations drift because production changes independently." '{"tool":"path","target_path_glob":"migrations/**"}' '{"key":"decision:codex-shadow","via":["mem_get"],"freshness":{"ttl_secs":900}}' stage
"$MATI" policy stage codex-shadow shadow >/dev/null
# via is mem_get, not db_introspection. Codex's PostToolUse payload carries no
# exit status, so codex-post-bash never mints a DbIntrospection receipt, and a
# block policy accepting only sources outside CODEX_PRODUCIBLE_SOURCES degrades
# to steering — this policy would never deny. The introspect-then-query path is
# validated on Claude by policy-live-session.sh (live-introspect).
add_policy codex-db "Consult decision:codex-inventory before querying production." "Schemas drift because production changes independently." '{"tool":"db_client","host_glob":"*prod-codex*"}' '{"key":"decision:codex-inventory","via":["mem_get"],"freshness":{"ttl_secs":900}}' enable

git init --quiet; git add -A; git -c user.email=fixture@local -c user.name=fixture commit -qm fixture >/dev/null
printf '\n\033[1mFixture ready:\033[0m %s\n' "$DEST"; "$MATI" policy list
printf '\nPolicy mode: %s\n' "$("$MATI" config get policy.mode 2>/dev/null || echo strict)"
cat <<EOF
Before starting, confirm no Codex PreToolUse hook rewrites commands (for example, 'psql' to 'rtk psql'). The pre hook sees the typed command while post sees the rewritten command; no receipt mints and the policy becomes unsatisfiable. This is ARCHITECTURE.md section 10a.2.

Open a REAL Codex session; both exports are mandatory:
  cd $DEST
  export MATI_HOME=$DEST/.mati-home
  export PATH=$DEST/bin:$REPO_ROOT/target/debug:\$PATH
  codex

Hooks run `command -v mati` and silently exit if it is absent; without both
exports, the session can use a different store or fail open without mati.

PROMPT TO PASTE:
You run every step yourself using Bash, apply_patch, and mati MCP tools.
Report PASS/FAIL with actual output and status. Do not call mem_get unless told.
0. FIRST, perform exactly these two ungoverned probes, then report the captures:
   use apply_patch to change probe.txt from "probe" to "probe2". It matches no
   policy glob, so it must succeed. Then use Bash to run: printf 'codex-live\n'
   These real tool calls create the first capture lines; the fixture never
   seeds them. Now report exact key sets:
   jq -c 'keys|sort' "\$MATI_HOME/codex-pre-apply-patch-payloads.jsonl" | tail -1
   jq -c 'keys|sort' "\$MATI_HOME/codex-post-bash-payloads.jsonl" | tail -1
   jq -c '.["tool_input"]|keys|sort' "\$MATI_HOME/codex-pre-apply-patch-payloads.jsonl" | tail -1
   jq -c '.["tool_input"]|keys|sort' "\$MATI_HOME/codex-post-bash-payloads.jsonl" | tail -1
   Each file must have AT LEAST ONE line. The post-bash file will normally have
   several, because every Bash command you run (including these report commands)
   is captured — that is expected, NOT a failure; do not stop on the line count.
   Report each top-level key set and tool_input key set verbatim. STOP ONLY if a
   file is genuinely absent or empty, or if tool_input has no "command" key.
   mati reads the patch text from tool_input.command (src/cli/hook_decide/flows.rs:333-339);
   without that key run_apply_patch fails open and every patch is ungated, and
   that finding outranks every later result. Observing tool_input keys
   ["command"] is the EXPECTED shape — it matches smoke-policy.sh's
   pre_apply_patch(). Report it and CONTINUE to step 1.
1. CANARY apply_patch migrations/prod.sql "select 1;" -> "select 2;". Expect exit 2, mati: naming decision:codex-migrations, and content unchanged; otherwise STOP.
2. mem_get decision:codex-migrations. If Codex cannot call mati MCP mem_get, STOP: deny is unsatisfiable.
3. Retry patch; expect success and "select 2;".
4. Reset to "select 1;"; apply_patch governed.txt REDACTED -> ROTATED. Expect exit 2, mati: decision:codex-vault, vault/keys.txt unchanged.
5. mem_get decision:codex-vault; retry; confirm ROTATED.
6. apply_patch migrations/prod.sql -> "select 3;"; expect no deny from shadow;
   then call the mati MCP tool mem_query with
   {"mode":"policy_observations","query":"codex-shadow"} and report "would":
   "block". Do NOT use the 'mati policy observations' CLI here: your sandboxed
   shell cannot reach the daemon socket, but the MCP tool runs outside it.
7. apply_patch main.rs "fixture" -> "control"; expect success and content changed (positive control).
8. First run this Bash command for today's date: date -u +%F. Then call the mati
   MCP tool mem_query with {"mode":"analytics","query":"miss_<TODAY>"} (substitute
   that date, e.g. "miss_2026-07-24") so you read exactly today's aggregate, not
   an older day's frozen count. Record that record's payload.count (treat an empty
   result as 0). Then use apply_patch to add unindexed.txt with content "miss". It
   matches no policy and has no record. Call the same mem_query again. Expect
   payload.count to increase, proving codex-pre-apply-patch records a Miss for an
   allowed unrecorded target. Do NOT use 'mati show' here: your sandboxed shell
   cannot reach the daemon socket; read the aggregate through the MCP tool, which
   runs outside it.
9. Bash psql -h db.prod-codex.internal -c "SELECT * FROM inventory". Expect exit 2, mati: decision:codex-inventory; stub must not run.
10. Bash psql -h db.prod-codex.internal -c "\d inventory"; report status. Expect 0/no
    block: schema introspection is exempt from the block so you can inspect before
    consulting. This does NOT satisfy the policy here.
11. In a new message rerun step 9. Expect exit 2 AGAIN. Codex's PostToolUse payload
    carries no exit status, so mati cannot tell a successful introspection from one
    that exited 127 and never mints a db_introspection receipt on this platform.
    Introspection alone cannot clear a policy here. An allow is a FAIL, and so is a
    deny naming any key other than decision:codex-inventory.
12. Call the mati MCP tool mem_get with key decision:codex-inventory, then rerun
    step 9. Expect allowed and stub output, proving deny -> mem_get -> allow on a
    db_client trigger. Use the MCP tool, not 'mati show': your sandboxed shell
    cannot reach the daemon socket, but the MCP tool runs outside it.
Report a table and state whether payload shapes, apply_patch deny, symlink deny, shadow observation, mem_get, fileless deny, the db_client deny -> mem_get -> allow loop, and introspection NOT minting on Codex were live-validated.
EOF
