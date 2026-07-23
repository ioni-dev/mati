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
add_policy codex-db "Consult decision:codex-inventory before querying production." "Schemas drift because production changes independently." '{"tool":"db_client","host_glob":"*prod-codex*"}' '{"key":"decision:codex-inventory","via":["db_introspection"],"freshness":{"ttl_secs":900}}' enable

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
   There must now be one line in each file. Report each top-level key set and
   tool_input key set verbatim. If either is absent/empty, STOP. If the shape
   differs from smoke-policy.sh's pre_apply_patch() payload, that finding
   outranks every later result: without tool_input.command,
   decide::extract_apply_patch_files returns nothing, run_apply_patch fails
   open, and every patch is ungated.
1. CANARY apply_patch migrations/prod.sql "select 1;" -> "select 2;". Expect exit 2, mati: naming decision:codex-migrations, and content unchanged; otherwise STOP.
2. mem_get decision:codex-migrations. If Codex cannot call mati MCP mem_get, STOP: deny is unsatisfiable.
3. Retry patch; expect success and "select 2;".
4. Reset to "select 1;"; apply_patch governed.txt REDACTED -> ROTATED. Expect exit 2, mati: decision:codex-vault, vault/keys.txt unchanged.
5. mem_get decision:codex-vault; retry; confirm ROTATED.
6. apply_patch migrations/prod.sql -> "select 3;"; expect no deny from shadow; run mati policy observations codex-shadow --json and report "would": "block".
7. apply_patch main.rs "fixture" -> "control"; expect success and content changed (positive control).
8. With Bash, record the current value of mati show
   analytics:miss_$(date -u +%F), then use apply_patch to add unindexed.txt
   with content "miss". It matches no policy and has no record. Read the same
   daily aggregate again. Expect its count to increase, proving
   codex-pre-apply-patch records a Miss for an allowed unrecorded target.
9. Bash psql -h db.prod-codex.internal -c "SELECT * FROM inventory". Expect exit 2, mati: decision:codex-inventory; stub must not run.
10. Bash psql -h db.prod-codex.internal -c "\d inventory"; report status. Expect 0/no block; introspection must mint.
11. In a new message rerun step 9. Expect allowed/stub output, proving introspect-then-query.
Report a table and state whether payload shapes, apply_patch deny, symlink deny, shadow observation, mem_get, fileless deny, and minting pair were live-validated.
EOF
