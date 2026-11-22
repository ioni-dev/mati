#!/usr/bin/env bash
# Gotcha pack for mati's own repo. Each rule comes from CLAUDE.md "Known gotchas".
# Run from the repo root after `mati init --claude`. Each gotcha is confirmed on add.
set -euo pipefail

mati gotcha add src/store/db/tree.rs -s high \
  -r "Keep with_versioning(true, 0) on knowledge.db only; sessions.db uses SESSIONS_RETENTION_NS." \
  -m "0 means retain every version forever, not disabled. Changing it drops knowledge history; copying it to sessions.db grows that store without bound."

mati gotcha add src/store/db/mod.rs -s high \
  -r "Route every store write through commit_blind. Never open a write transaction anywhere else." \
  -m "surrealkv 1.x rejects overlapping commits to one key, and commit_blind is what serializes them."

mati gotcha add src/graph/edges.rs -s high \
  -r "Write every graph mutation back to SurrealKV in the same operation." \
  -m "petgraph is in-memory only. Edges load from graph:edge:* at startup, so an edge that was never persisted is gone after a restart."

mati gotcha add src/cli/hook_decide/entry.rs -s high \
  -r "Do not add blocking I/O to the hook path, and do not raise HOOK_DEADLINE_MS." \
  -m "The 2500 ms deadline sits inside the 4 s scaffold timeout, and process spawn plus runtime init land before it (about 1050 ms on a cold binary). A hook that overruns fails open."

mati gotcha add src/hooks/pre_edit.rs -s high \
  -r "Never emit permissionDecision allow for an edit; defer with empty stdout instead." \
  -m "Edits are permission-required tools, so a forced allow suppresses the user's edit prompt."

mati gotcha add src/mcp/tools/mod.rs -s high \
  -r "Keep exactly four MCP tools. Add a parameter to an existing tool instead of a fifth." \
  -m "Every tool definition costs tokens on every call; four is a hard constraint in CLAUDE.md."
