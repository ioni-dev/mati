# CLAUDE.md — mati

> Engineering knowledge that survives turnover.
> Single Rust binary. MCP stdio server. Claude Code plugin.

---

## What mati is

mati is a persistent, queryable knowledge store for codebases, exposed as a
Claude Code plugin via MCP stdio. It accumulates per-file gotchas, architectural
decisions, and project state, and surfaces them to Claude on demand. It is
**institutional memory** — token savings is a bonus metric, not the goal.

---

## Current stage & v0.1 scope

**v0.1 — Foundation.** Core binary: storage layer, data model, MCP server
(4 tools), Layer 0 static analysis, CLI. Do **not** build the following — they
are v0.2 or out of scope:

- Sync / multi-device — v0.2 (paid layer); no conflict resolution exists yet
- Web UI or dashboard — CLI only
- Semantic search in the default build — opt-in via `--features semantic`
- Cloud storage — everything is local in `~/.mati/<slug>/`
- Multi-project views — one project per CLI invocation
- Auto-enrichment without an explicit `mati enrich`

---

## Repository layout

Single binary (`mati`) + library (`mati_core`). Full annotated tree in
ARCHITECTURE.md §3.

```
src/
  main.rs / lib.rs   CLI dispatch + mati_core root
  cli/        clap commands (init, enrich, status, repair, daemon, doctor, …)
  mcp/        rmcp stdio server + UDS daemon bridge (server, tools, daemon_lifecycle)
  store/      SurrealKV layer (db, record, durability, gotcha_ops, enforcement)
  graph/      petgraph layer — in-memory, edges persisted to SurrealKV
  search/     tantivy BM25 index
  analysis/   Layer 0 static analysis (tree-sitter parser, git, blast_radius, clusters)
  health/     confidence / quality / staleness / gaps / onboarding scoring
  hooks/      pure enforcement decision (decide.rs) + per-agent adapters
  scaffold/   files written by `mati init`
```

---

## Stack — locked

Do not swap an alternative in for any of these:
**surrealkv** (KV store — not redb/sled), **petgraph** (graph), **tantivy**
(BM25), **rmcp** (MCP SDK), **tree-sitter** (parsing), **ignore** (repo walk),
**rayon** (parallelism), **git2** (history), **clap** + **comfy-table** (CLI —
no TUI). Pinned versions in `Cargo.toml` are the source of truth. The semantic
layer (`candle` + `usearch`) is feature-gated behind `--features semantic`; the
default binary has zero ML dependencies.

---

## Hard constraints — never violate

**MCP tools: exactly 4** — `mem_get`, `mem_query`, `mem_bootstrap`, `mem_set`
(`mem_set` is the write tool used during enrichment). A 5th tool must be
redesigned as a parameter on an existing one. Every tool definition costs tokens
on every call.

**No external CRDT crates.** Sync conflict resolution will use an internal
`MergeEngine` (planned, v0.2 — not yet implemented). Never add `automerge`,
`yrs`, or any CRDT dependency.

**No TUI framework.** `clap` + `comfy-table` only — no `ratatui`/`tui`/`crossterm`.

**Semantic layer is feature-gated.** `candle` + `usearch` compile only with
`--features semantic`. The default binary has zero ML dependencies.

**Single binary.** No runtime dependencies — no Node, Python, or shell-script
runtime. `mati` ships as one statically-linked binary.

**Durability is split — never mix:**
- `Immediate` (fsync): `gotcha:* decision:* file:* stage:* dev_note:* dep:*`
  (plus `enforcement:event:*`, which defaults to Immediate)
- `Eventual` (OS buffer): `session:* analytics:* hook_event:* compliance:*
  graph:edge:* health:* parse:* audit:session:*`

**Gotcha mutations are centralized.** All create/edit/tombstone paths go through
`store::gotcha_ops`. The canonical `gotcha:*` record is the source of truth
(written first, fails hard); `file:*` `gotcha_keys` and `HasGotcha` edges are
derived indexes (best-effort, dirty-marker on failure). `mati repair` rebuilds
and verifies; `--check` detects drift (CI, exits non-zero); `--fast` drains the
dirty queue only.

**Hook output protocol is strict.** Hooks write JSON to stdout with a
`hookSpecificOutput` wrapper. `permissionDecision` must be `"allow"` or
`"deny"` — nothing else. Hook timeout is 3000ms; all logic must finish within it.

---

## What this repo must NEVER include

Enterprise features that live exclusively in mati-cloud. The canonical,
contributor-facing version of this boundary is `CONTRIBUTING.md`; the list below
is the operational copy. Reject if proposed here:

- License validation / checking of any kind (lives in mati-cloud's `mati_license`).
- Signed audit PDF export (`mati audit export --signed` is enterprise; this repo
  only *records* events — mati-cloud reads and reports them).
- Multi-repo sync or cross-repo gotcha registry.
- SSO, SAML, OIDC, RBAC, SCIM.
- Managed Slack/Teams/PagerDuty integration (OSS may emit webhook-compatible
  stdout; the managed, authenticated, routed integration is enterprise).
- Curated compliance packs (HIPAA, SOC 2, PCI) — OSS ships the `--pack`
  loader/format only; the maintained pack content is enterprise.
- Policy-as-code continuous sync; centralized governance dashboard / web UI;
  air-gapped installer with signed release artifacts.
- **Any network call in the enforcement path.** DENY/ALLOW/receipt is local,
  zero network, always — a core invariant, not just a feature boundary.
- **Telemetry / analytics / usage metering to any external service.** The OSS
  binary never phones home. Period.

---

## What this repo DOES include that enterprise depends on

- **Enforcement event recording** — hash-chained, append-only, 8 event types.
  mati-cloud reads these to generate signed audit PDFs. Recording here, reporting there.
- **Store API** (`store::Store`, CRUD, graph, search) — mati-cloud opens the same store.
- **All CLI commands** — mati-cloud shells out; it doesn't reimplement them.

Rule: this repo is the complete, free product for a solo developer. Enterprise
adds signed evidence, license management, and governance at scale on top.

---

## Key data types & namespacing

Types (`Record`, `FileRecord`, `GotchaRecord`, `ConfidenceScore`, `QualityScore`,
`StalenessScore`, `ContextPacket`) are defined in `src/store/record.rs` —
canonical reference in ARCHITECTURE.md §5. Never redefine them elsewhere.

Key namespacing convention:

```
gotcha:<slug>   file:<path>   decision:<slug>   stage:current
dep:<ecosystem>:<name>   dev_note:<slug>   session:<timestamp>
analytics:<type>_<date>   graph:edge:<from>:<kind>:<to>   enforcement:event:<seq_no>
```

---

## Hook decision matrix

Do not change these thresholds without updating ARCHITECTURE.md §10.1.

```
gotcha: confirmed=true + confidence >= 0.6 + quality >= 0.4  → deny, inject record
file:   confidence >= 0.3 + quality >= 0.4                   → allow + additionalContext
no record                                                     → allow, log miss
confidence < 0.3 OR quality < 0.4                            → allow, no injection
```

Design principles (full set in ARCHITECTURE.md §2): hook enforcement is primary
(P1); inject nothing by default, pull on demand (P2); four MCP tools max (P3);
never block Claude on a mati outage — hooks fail open (P9).

---

## Known gotchas

- **`with_versioning(true, 0)` means indefinite retention.** `0` is not
  "disabled" — it retains all versions forever. Intentional for `knowledge.db`;
  `sessions.db` uses the 90-day value.
- **petgraph is in-memory only.** Edges load from a `graph:edge:*` scan at
  startup; mutations must write back to SurrealKV immediately or they are lost on
  restart.
- **tree-sitter grammars must be ABI-compatible with the parser**, not
  necessarily the same crate version. Most pin to `0.23`, but e.g.
  `tree-sitter-elixir = "0.3"` is compatible. A mismatch is a silent parse
  failure, not an error.
- **The hook fast-path checks reachability via `ensure_daemon`** (which pings
  internally), not a literal `mati ping`. If the daemon is unreachable, hooks
  pass through unconditionally (P9). `HOOK_DEADLINE_MS = 2500` leaves a 500ms
  buffer before Claude Code's 3000ms SIGKILL — never add blocking I/O that could
  exceed it.
- **The bash `cat` bypass is a known, accepted miss (~2–5%).** `pre-bash.sh`
  catches `cat <file>` but not variable expansion, process substitution, or
  unusual quoting (C9 in ARCHITECTURE.md §24). Do not chase 100%.
- **Codex `apply_patch` edits are gated** by the `codex-pre-apply-patch` hook
  (ARCHITECTURE.md §10.3): editing a file with an unconsulted confirmed gotcha
  is denied (exit 2) until `mem_get`. It parses the patch envelope for exact
  paths, so unlike the `cat` path it is immune to the wrapper/quoting bypass
  above. Codex fires `PreToolUse` for `apply_patch` but not native reads;
  Claude edits are not gated. Fails open on any fault (parse/daemon/version).
- **`confirmed: false` records are Layer 0 stubs** — graph nodes and gap signals
  only, never injected. Only `confirmed: true` with `confidence >= 0.6` and
  `quality >= 0.4` can deny a read.
- **`mati repair --fast` is not a full integrity proof** — it only drains the
  dirty-marker queue. Use `mati repair` (full scan) for authoritative verification.
- **Gotcha file links and graph edges are derived, not authoritative.**
  `file:*.gotcha_keys` and `graph:edge:*:has_gotcha:*` are rebuilt from canonical
  `gotcha:*` records. If they disagree with the gotcha's `affected_files`, the
  gotcha record wins.

CLI color palette is defined in `src/cli/colors.rs` (GitHub-style hex semantics).

---

## Runtime architecture

After the γ process-split, mati runs as two processes (full diagram +
`daemon stop` semantics in ARCHITECTURE.md §4):

- **`mati serve`** — thin MCP-stdio↔UDS proxy (~80 lines). Does not open the
  store, bind a socket, or manage signals. Calls `ensure_daemon` on startup, then
  forwards every tool call over the Unix socket (`~/.mati/<slug>/mati.sock`).
- **`mati daemon`** — data plane. Owns the SurrealKV lock, serves UDS requests,
  handles signals, and idle-shuts-down only when `now - last_wall >= 30min` AND
  `active_connections == 0`.
- **`ensure_daemon`** (`src/mcp/daemon_lifecycle.rs`) returns a `bool`; internally
  `wait_for_ready` tails `lifecycle.log` and returns `Ready` / `Failed` (on a
  `serve_failed` or `panic` event) / `Wedged` (15s) / `HardCap` (60s).

---

## Running the tests

**Supported runner: `cargo-nextest`.** Vanilla `cargo test` works but is pinned
to single-threaded by `.cargo/config.toml` (`RUST_TEST_THREADS=1`): the
shared-binary model accumulates tokio/SurrealKV/`fseventsd` state across hundreds
of tests in one process — enough to trip the macOS `logd` kernel watchdog and
panic the kernel on Apple Silicon. Nextest runs each test in its own subprocess,
so state is reclaimed at exit.

```bash
cargo install cargo-nextest --locked   # one-time
cargo nt --lib                         # alias for `cargo nextest run`
cargo nextest run --lib --profile ci   # match CI behavior locally
```

Profiles and the resource-bound test groups (`mcp`, `hook-compliance`,
`cli-daemon`) are defined in `.config/nextest.toml`. Doc tests still run under
`cargo test --doc` (nextest cannot run rustdoc examples).

---

## References

- Full architecture, data model, decision matrices, and process lifecycle:
  `ARCHITECTURE.md`
