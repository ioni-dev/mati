# ARCHITECTURE.md: mati

Code comments and other docs cross-reference these sections by number, for example `section 10.1`. Those numbers point to the section headings in this document.

---

## 1. Overview

mati is an enforcement layer for what a team knows about its own codebase. Not just a passive memory store that an agent might consult if it happens to ask.

When Claude Code reads a file, mati can require the relevant institutional knowledge to be surfaced first. On Codex, the same idea applies to `apply_patch` edits through the pre-edit hook. In those enforced paths, if the agent has not consulted the attached knowledge yet, mati can stop the operation until it does.

That distinction is the point. Most “memory for AI” tools are opt-in. They store context, and the model may or may not retrieve it. mati works differently. The decision happens at the hook layer, deterministically, outside the model’s discretion. If a file has a confirmed, high-confidence gotcha attached and the agent has not consulted it, the hook denies the read, or the Codex patch edit, until the consultation happens.

Anthropic’s Global Workspace research provides independent support for this architectural rationale. In a study of Claude, the authors report that some task-relevant internal processing can influence reasoning without appearing in the model’s visible response, while also describing limits to the method and its coverage ([research summary](https://www.anthropic.com/research/global-workspace), [technical paper](https://transformer-circuits.pub/2026/workspace/index.html)). Mati does not inspect those internal representations. It operates at the observable engineering boundary instead: surfacing durable codebase knowledge, recording relevant tool events, and applying deterministic hook-level enforcement outside the model’s discretion. Visible explanations and completion claims are therefore evidence to corroborate with external records and controls, not a complete engineering record.

So the captured knowledge cannot be quietly skipped.

What mati enforces is the stuff developers usually carry around in their heads: per-file gotchas, architectural decisions, weird project state, and the implementation details that never make it into comments. It captures those records, lets developers confirm them, then makes them queryable, measurable, and, where it matters, mandatory.

It also leaves a local audit trail. Deny decisions, allow-after-receipt decisions, and consultation receipts are written to a hash-chained event log, so there is a record that the knowledge was actually put in front of the agent.

The larger purpose is institutional memory that survives turnover. The kind of knowledge that otherwise lives in Slack, in a half-remembered incident, or nowhere useful at all. Enforcement is what keeps that memory from being ignored the moment it becomes inconvenient.

There is a side benefit: a high-confidence record can sometimes replace a full file read and reduce token usage. Useful. But not the reason mati exists.

---

## 2. Design Principles

**P1: Hook enforcement comes first. Prompt injection is secondary.**

The pre-read hook’s DENY/ALLOW/advisory decision is the canonical enforcement path. Whatever Claude receives through the MCP tool result is extra context, not the authority.

**P2: Inject nothing by default. Context is pulled only when asked for.**

mati does not push records into Claude’s context at session start. `mem_bootstrap` is an explicit call. Hook injection happens because a file was accessed, not because a session began.

There is one deliberate exception: the passive “Suggested Actions” nudge appended to MCP tool results in `mcp/tools.rs`. It surfaces possible next steps, but it does not inject record content.

**P3: Four MCP tools, no more.**

The exposed tools are `mem_get`, `mem_query`, `mem_bootstrap`, and `mem_set`.

Every tool definition costs tokens on every Claude call. If a fifth tool feels necessary, redesign the feature as a parameter on an existing tool first. This is a hard code-review constraint.

**P4: Memory must reflect developer intent.**

Unconfirmed gotcha records never influence hook enforcement. They exist in the graph and can show up in `mem_bootstrap` as review candidates, but they cannot trigger Deny, and they cannot trigger the gotcha-based context injection path in section 10.1 step 3.

The Advisory path in section 10.1 step 6 is separate. It uses the file record’s own confidence and quality scores. Those are not tied to any gotcha’s confirmation state.

_(P5 and P6 are intentionally unassigned. They were removed during the v0.1 scope reduction. The gaps remain so existing code-comment cross-references do not break.)_

**P7: Layer 0 must be useful with zero LLM calls.**

tree-sitter parsing, import graph construction, and co-change clustering run from static analysis and git history only. No network calls. No model calls.

**P8: Knowledge health is the main metric. Token savings is a bonus.**

`mati doctor` and `mati stats` measure coverage, confidence, and staleness. Token savings is just a side effect.

**P9: Degrade gracefully. Never block Claude because mati is down.**

If the daemon is unreachable, every hook passes through unconditionally. A mati failure must not block a development session.

**P10: User-facing strings lead with the problem, not the mechanism.**

Error messages should say what went wrong first. Tool names, module names, and internal keys come after.

---

## 3. Repository Layout

```text
mati/
├── src/
│   ├── main.rs              # binary entry point, CLI dispatch (Commands enum)
│   ├── lib.rs               # mati_core library root
│   ├── policy.rs            # policy-engine core types (evaluation, floors)
│   ├── invariants.rs        # cross-cutting runtime invariant checks
│   ├── eval.rs              # enforcement regression corpus model
│   ├── cli/                 # clap commands, comfy_table output
│   ├── scaffold/            # files written by `mati init` / `mati hooks`
│   │   ├── claude_md.rs     # CLAUDE.md scaffold
│   │   ├── codex.rs         # Codex AGENTS.md + hook wiring
│   │   ├── commands.rs      # slash-command scaffolds
│   │   └── settings.rs      # .claude/settings.json hooks + 4s timeout
│   ├── mcp/                 # MCP stdio server (rmcp) + daemon socket bridge
│   │   ├── server/          # serve(), socket loop, dispatch, promotion, proxy
│   │   ├── tools/           # mem_get, mem_query, mem_bootstrap, mem_set
│   │   │   ├── mod.rs             # MatiServer + #[tool_router] impl (4 tools)
│   │   │   ├── context_packet.rs  # mem_bootstrap assembly, shared with handlers/
│   │   │   └── mem_set_command.rs # mem_set -> typed Command mapping
│   │   ├── types.rs         # ContextPacket, MCP response types
│   │   ├── protocol/        # v2 typed Request/Response/Command + v1/v2 mapper
│   │   ├── dispatch_v2/     # v2 typed Command to handler dispatch
│   │   │   ├── mod.rs       # entry point, request context, audit helpers
│   │   │   ├── reads.rs     # MemQuery + side-effecting reads + v1 bridge
│   │   │   ├── knowledge.rs # knowledge-side mutations + policy write/evaluate
│   │   │   ├── compound.rs  # FileEditHook (per-tree atomic substeps)
│   │   │   └── session.rs   # session-side mutations
│   │   ├── handlers/        # handler bodies (gotcha, file, decision/devnote, reads, ...)
│   │   ├── daemon_lifecycle.rs # ensure_daemon, lifecycle.log readiness (section 4.2)
│   │   ├── daemon_log.rs    # daemon.log writer + tracing directives
│   │   ├── metrics.rs       # MCP-side counters
│   │   └── metadata.rs      # DaemonMetadata, panic hook, peer cred, lifecycle log
│   ├── store/               # SurrealKV layer
│   │   ├── db/              # knowledge.db + sessions.db init (crud, history, slug, tree)
│   │   ├── record.rs        # Record struct + all sub-types
│   │   ├── durability.rs    # Immediate vs Eventual write paths
│   │   ├── gotcha_ops/      # centralized gotcha mutations (edges, links, mutation, ...)
│   │   ├── policy_ops.rs    # policy:* read/write path
│   │   ├── repair.rs        # gotcha index reconciliation engine
│   │   ├── enforcement/     # hash-chained event log (models_chain, recording, retention, ...)
│   │   ├── device.rs        # stable DeviceId (~/.mati/device_id)
│   │   ├── extraction.rs    # extraction bookkeeping
│   │   ├── migrations.rs    # on-open record migrations
│   │   ├── negative_exemplar.rs # tombstoned-rule exemplars for enrichment
│   │   ├── observability.rs # internal metrics surface (mati doctor --internal)
│   │   └── session.rs       # session:* markers, harvest, consultation
│   ├── graph/               # petgraph layer
│   │   ├── graph.rs         # in-memory graph, load/persist
│   │   └── edges.rs         # EdgeKind, traversal
│   ├── search/              # tantivy layer
│   │   └── index.rs         # schema, index/rebuild, BM25 query
│   ├── analysis/            # Layer 0 static analysis
│   │   ├── walker.rs        # ignore + rayon parallel walk
│   │   ├── parser/          # tree-sitter multi-language parsing (12 languages)
│   │   ├── resolvers/       # per-language import resolvers
│   │   ├── enrich_signals/  # AST signal extraction for `extract-signals` (12 languages)
│   │   ├── edges.rs         # edge derivation from parsed files
│   │   ├── deps.rs          # Cargo.toml / package.json / go.mod
│   │   ├── git.rs           # git2 history mining
│   │   ├── blast_radius.rs  # direct/transitive importer count
│   │   ├── clusters.rs      # co-change clustering
│   │   ├── propagation.rs   # staleness propagation through import graph
│   │   ├── reparse.rs       # single-file Layer 0 re-parse
│   │   ├── auto_memory.rs   # auto-memory extraction
│   │   ├── claude_md.rs     # CLAUDE.md parsing/import
│   │   └── onboarding.rs    # onboarding-signal mining
│   ├── health/              # knowledge health system
│   │   ├── confidence.rs    # ConfidenceScore computation
│   │   ├── quality.rs       # QualityScore + RecordQualityAnalyzer
│   │   ├── staleness/       # StalenessScore + StalenessAnalyzer (analyzer, git, reparse, ...)
│   │   ├── gaps.rs          # KnowledgeGapAnalyzer
│   │   ├── drift.rs         # knowledge drift scoring
│   │   ├── enrichment.rs    # enrichment-depth hint
│   │   └── onboarding.rs    # OnboardingScore
│   ├── hooks/               # hook decision engine + per-agent adapters
│   │   ├── decide/          # pure enforcement decision, no I/O
│   │   │   ├── mod.rs              # Types + Core Decision Engine (evaluate)
│   │   │   ├── classification.rs   # command classification
│   │   │   ├── path_extraction.rs  # file-path extraction from shell commands
│   │   │   ├── path_normalize.rs   # lexical path normalization
│   │   │   ├── envelope.rs         # apply_patch envelope parsing
│   │   │   ├── json_helpers.rs     # payload readers used by evaluate()
│   │   │   ├── config_change.rs    # ConfigChange invariant checks
│   │   │   ├── file_changed.rs     # FileChanged signal decision
│   │   │   └── instructions_loaded.rs # instructions-loaded decision
│   │   ├── pre_read.rs      # Claude PreToolUse read gate
│   │   ├── pre_bash.rs / post_bash.rs       # bash read-intercept + receipt
│   │   ├── pre_edit.rs / post_edit.rs       # Claude edit backstop + receipt
│   │   ├── pre_compact.rs / post_compact.rs # compaction hooks
│   │   ├── session_start.rs / session_end.rs # session lifecycle
│   │   ├── subagent_start.rs # inject mati awareness into subagents
│   │   ├── claude_stop.rs   # Claude Stop hook
│   │   ├── config_change.rs # ConfigChange anti-tamper adapter
│   │   ├── compliance.rs / post_compliance.rs # compliance event recording
│   │   ├── post_memget.rs   # consultation receipt after mem_get
│   │   ├── file_changed.rs  # FileChanged adapter
│   │   ├── instructions_loaded.rs # instructions-loaded adapter
│   │   ├── policy_match.rs  # policy-trigger adapter
│   │   └── codex_*.rs       # Codex adapters (pre_bash, post_bash, pre_apply_patch,
│   │                        #   session_start, stop, user_prompt)
│   └── bin/
│       └── bench_real/      # second binary: real-repo benchmark harness
```

---

## 4. Runtime Architecture

After the gamma refactor, mati runs as two separate processes.

```text
   Codex / Claude Code
            | stdio (rmcp)
   +----------------+         +----------------------+
   |  mati serve    |   UDS   |  mati daemon         |
   |  (thin proxy)  |<------->|  (data plane)        |
   |  ~80 lines     |         |  - SurrealKV lock    |
   |  - rmcp stdio  |         |  - Graph + Tantivy   |
   |  - UDS client  |         |  - socket listener   |
   |  - ensure_     |         |  - idle-shutdown     |
   |    daemon      |         |  - signal handling   |
   +----------------+         +----------------------+
```

**`mati serve`** is a thin MCP-stdio forwarder. It does not open the store, bind a socket, or manage signals. At startup, it calls `ensure_daemon` to make sure the daemon is running before it accepts MCP traffic. After that, every tool call is proxied over a Unix domain socket.

**`mati daemon`** is the data plane. It owns the SurrealKV lock, serves UDS requests, and runs idle shutdown. The idle shutdown condition is deliberately conservative: it fires only when `now - last_wall >= 30min` and `active_connections == 0`. A long MCP session that pauses between calls should not lose its daemon.

**Sole ownership is enforced, not just intended.** SurrealKV is single-writer with an exclusive lock, so exactly one process per slug may open the store — the daemon — and every other process reaches it over the socket. `StoreProxy` (all CLI reads) therefore never opens the store directly while a daemon can exist: it brings one up via `ensure_daemon` and proxies, checks for a live daemon PID before any direct-open fallback (a live daemon holds the lock, so a direct open cannot succeed and must not be attempted), and reserves direct open for the genuinely daemonless case (tests, `MATI_DISABLE_AUTO_SPAWN`, spawn failure with no daemon alive). `ensure_daemon` serializes concurrent cold-starts with a `flock` on `spawn.lock` so a session's SessionStart hook and its MCP server cannot both spawn a daemon and leave the loser wedged.

**The MCP server must open the same store as the hooks.** Hooks inherit the session environment, but a client may spawn `mati serve` with a clean one — Codex, notably, spawns MCP servers with `CWD=/` and no inherited env. A non-default `MATI_HOME` that reaches the hooks but not `serve` splits the two across different stores under the same slug, and every `mem_get` reads an empty store. `mati init` therefore writes `MATI_HOME` into the MCP server's `env` (Codex `config.toml`, Claude `.mcp.json`) whenever it is set at init time, so the MCP server and the hooks agree on the store.

**Sandboxed shells cannot reach the socket, and that is not a mati fault.** An AI agent's shell tool may run inside an OS sandbox (macOS Seatbelt) that blocks connecting to Unix domain sockets. Hooks and `mati serve` run outside that sandbox and are unaffected, but `mati` CLI commands invoked from the sandboxed shell get `EACCES` on the socket connect. The store, daemon, and MCP tools all work; only the sandboxed CLI is blocked, and it says so (`DaemonResult::PermissionDenied` surfaces an accurate message rather than a spurious lock or busy error). An agent should read through the MCP tools, or run the command in an unsandboxed shell.

**The daemon logs to `<root>/daemon.log`.** It is detached, so its stderr goes wherever the spawner pointed it — `~/.mati/daemon_start.log` under `ensure_daemon`, `/dev/null` otherwise — at a `warn` default that filters out everything worth reading. `mati daemon start` therefore redirects its own tracing to a per-store `daemon.log` at INFO (mati targets only), rotating at 1 MiB with one previous generation kept, so lifecycle and outcome lines (`mati daemon listening`, `staleness analysis complete scanned=… updated=…`) are readable without setting `RUST_LOG`. `mati daemon status` prints the path. Local file, no network, not a store record.

### 4.1 `mati daemon stop` semantics

| Flag                    | Effect                                                                                         |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| default                 | Sends SIGTERM, then escalates to SIGKILL on timeout. Serve proxies auto-respawn transparently. |
| `--force`               | Sends SIGKILL directly, with no SIGTERM grace. Serve proxies still auto-respawn.               |
| `--include-mcp`         | Also kills the `mati serve` processes attached to this store. Their MCP sessions die.          |
| `--force --include-mcp` | Sends SIGKILL to the daemon, then SIGKILL to this store's serves.                              |

A stop is not an enforcement hold. Every hook path calls `ensure_daemon`, so the daemon is back within one tool call. There is no stay-down flag, because a hold is a deliberate enforcement outage. `mati daemon stop` says so on every path that signals a process.

`--include-mcp` is scoped to the target store. `pgrep -f "mati serve"` enumerates candidates, but a proxy's command line is a bare `mati serve`, its CWD may be `/` (Codex), and it holds no long-lived socket — nothing on the process identifies the store. The association only exists where the proxy wrote it: `serve_start pid=<n> owner=proxy` in that store's `lifecycle.log`. The kill list is the intersection of that record with the running set, and skipped processes are reported. Under-inclusive on purpose — a truncated log means a proxy survives, which is the right way to fail.

### 4.2 State-aware daemon readiness

`ensure_daemon`, in `src/mcp/daemon_lifecycle.rs`, checks daemon readiness by polling `lifecycle.log` for startup events. It does not rely on timer-based polling.

The public function returns a `bool`. Internally, it calls `wait_for_ready`, which returns the more detailed `ReadinessOutcome` listed below. `ensure_daemon` then collapses that to `true` for `Ready`, and `false` for everything else.

| `ReadinessOutcome` | Condition                                              |
| ------------------ | ------------------------------------------------------ |
| `Ready`            | `startup phase=ready` event received and ping succeeds |
| `Failed`           | `serve_failed` or `panic` event received               |
| `Wedged`           | No new event for 15 seconds                            |
| `HardCap`          | Absolute 60-second budget elapsed                      |

### 4.3 Durability split

Write durability is assigned by key namespace. Do not mix the paths. `durability.rs` treats this table as canonical.

| Durability           | Namespaces                                                                                                    |
| -------------------- | ------------------------------------------------------------------------------------------------------------- |
| Immediate (fsync)    | `gotcha:*` `decision:*` `file:*` `stage:*` `dev_note:*` `dep:*` `policy:*`                                     |
| Eventual (OS buffer) | `session:*` `analytics:*` `hook_event:*` `compliance:*` `graph:edge:*` `health:*` `parse:*` `audit:session:*` |

Unknown prefixes default to Immediate. See section 21 for the rationale.

---

## 5. Data Model

All types live in `src/store/record.rs`. Do not redefine them somewhere else because they look “simple enough.” That drift gets expensive.

### 5.1 Record

`Record` is the universal store entry. Every category uses this struct.

| Field                | Type                | Notes                                                                              |
| -------------------- | ------------------- | ---------------------------------------------------------------------------------- |
| `key`                | `String`            | Namespaced primary key and graph node key                                          |
| `value`              | `String`            | Human-readable content: rule, purpose, body. Indexed by tantivy.                   |
| `category`           | `Category`          | Gotcha, File, Decision, Stage, Dependency, DevNote, Session, Analytics, Policy      |
| `priority`           | `Priority`          | Low < Normal < High < Critical. Do not reorder variants because `Ord` is derived.  |
| `tags`               | `Vec<String>`       | Free-form. Used for search and filtering.                                          |
| `created_at`         | `u64`               | Unix seconds                                                                       |
| `updated_at`         | `u64`               | Unix seconds                                                                       |
| `ref_url`            | `Option<String>`    | PR, issue, doc, or incident link. Boosts confidence 1.5x when set.                 |
| `staleness`          | `StalenessScore`    | See section 17                                                                            |
| `lifecycle`          | `RecordLifecycle`   | Active, Tombstoned, Superseded                                                     |
| `version`            | `RecordVersion`     | Lamport clock + device ID. See section 20.                                                |
| `quality`            | `QualityScore`      | See section 13.2                                                                          |
| `access_count`       | `u32`               | Total reads through `mem_get` or hooks                                             |
| `last_accessed`      | `u64`               | Unix seconds                                                                       |
| `source`             | `RecordSource`      | StaticAnalysis, ClaudeEnrich, SessionHook, DeveloperManual, Import                 |
| `confidence`         | `ConfidenceScore`   | See section 13.1                                                                          |
| `gap_analysis_score` | `f32`               | `change_frequency * (1 - coverage_score)`                                          |
| `payload`            | `Option<JsonValue>` | Typed per-category data, such as FileRecord or GotchaRecord, stored as MessagePack |

### 5.2 FileRecord

Stored under `file:<path>`. The `FileRecord` is attached to the base `Record` through `payload`.

| Field                  | Notes                                                                                     |
| ---------------------- | ----------------------------------------------------------------------------------------- |
| `path`                 | Repo-relative file path                                                                   |
| `purpose`              | One-sentence summary. Empty at Layer 0, filled by Layer 1 enrichment.                     |
| `entry_points`         | Public functions and types visible from other modules                                     |
| `imports`              | Import/use paths found by tree-sitter                                                     |
| `gotcha_keys`          | Keys of associated `gotcha:*` records. Derived index; see section 22.                            |
| `decision_keys`        | Keys of associated `decision:*` records                                                   |
| `todos`                | TodoComment structs: text, line, kind (Todo/Fixme/Hack/Note/Deprecated)                   |
| `unsafe_count`         | Count of `unsafe` blocks                                                                  |
| `unwrap_count`         | Count of `.unwrap()` calls                                                                |
| `line_count`           | Newline count at last scan, used as an approximate line count. 0 for non-parseable files. |
| `change_frequency`     | Commit count, capped at 5,000 non-merge commits through git2                              |
| `is_hotspot`           | True when `change_frequency` is in the top 10% of the repo                                |
| `token_cost_estimate`  | Rough token count for `mem_bootstrap` budget enforcement                                  |
| `blast_radius`         | Direct and transitive importer count, computed during `mati init`                         |
| `propagated_staleness` | Staleness inherited from upstream stale sources through Imports edges                     |
| `content_hash`         | SHA-256 of file content at the last Layer 0 scan                                          |
| `last_author`          | Last commit author for the file, from git2 history. `None` when unavailable.              |
| `last_modified_session` | Logical clock of the session that last wrote this record                                  |

### 5.3 GotchaRecord

Stored under `gotcha:<slug>`. Like `FileRecord`, it is attached to the base `Record` through `payload`.

| Field            | Notes                                                                                   |
| ---------------- | --------------------------------------------------------------------------------------- |
| `rule`           | Actionable statement. For Good quality, it must start with an imperative verb.          |
| `reason`         | Why the rule exists. Must include a causality word such as “because”, “since”, or “as”. |
| `severity`       | Priority enum: Low, Normal, High, Critical                                              |
| `affected_files` | Canonical source of truth for which files this gotcha applies to                        |
| `ref_url`        | Optional link to the incident or PR that produced this rule                             |
| `confirmed`      | `false` means Layer 0 candidate stub, never injected. `true` means developer-validated. |
| `confirmed_content` | SHA-256 of each affected file **on disk** at the moment the rule was last confirmed (`<path>` -> hex). Baseline for content drift; see section 17.1. |
| `discovered_session` | Logical clock of the session that first created this gotcha                            |

`confirmed: false` records exist as graph nodes and gap signals. They are not used in hook enforcement. A gotcha can trigger a deny only when `confirmed: true`, `confidence >= 0.6`, and `quality >= 0.4`.

### 5.3a PolicyRecord

Stored under `policy:<slug>` as the typed payload on the universal `Record`.
Milestone 1 persists the developer-authored fields `name`, `rule`, `reason`,
`scope`, `mode`, structured `trigger`, structured `requires`, `stage`,
`severity`, and `created_by`. The trigger and receipt requirements are data only
until the later policy-matching milestone.

### 5.4 Quality Score formula

```text
quality =
  has_imperative_verb  x 0.20
  + has_causality      x 0.25
  + has_severity       x 0.10
  + has_reference      x 0.15
  + length_score       x 0.15
  + specificity_score  x 0.15

penalties (multiplicative):
  vague_phrase_detected -> x 0.5
  no_reason             -> x 0.6   (gotcha records only)
  too_short             -> x 0.4
```

Layer 0 `StaticAnalysis` records default to `0.10`, which puts them in the Suppressed tier. `RecordQualityAnalyzer` recomputes quality on every write.

---

## 6. Context Packet (`mem_bootstrap`)

`ContextPacket` is the struct returned by `mem_bootstrap`. The assembled packet is budgeted to 2,000 tokens.

Assembly order:

1. Resolve `context_files` to graph nodes.
2. Traverse `HasGotcha` edges to get direct gotchas for each file.
3. Traverse `Imports` one hop to get gotchas for directly imported files.
4. Traverse `AffectedBy` edges to collect relevant architectural decisions.
5. Apply the 2,000-token budget.
6. Sort gotchas by `confidence * priority_weight(severity)`, where Low/Normal/High/Critical map to 0.25/0.50/0.75/1.00.

Returned fields:

| Field                    | Content                                                                                      |
| ------------------------ | -------------------------------------------------------------------------------------------- |
| `stage`                  | Current `stage:current` record, if set                                                       |
| `critical_gotchas`       | Confirmed gotchas sorted by `confidence * priority_weight(severity)`                         |
| `file_records`           | FileRecords for the requested context files                                                  |
| `related_decisions`      | Decisions reached through `AffectedBy` traversal                                             |
| `recent_session`         | Plain-text summary of the last session. Currently always `None`; assembler is not wired yet. |
| `stale_warnings`         | Records approaching Liability tier                                                           |
| `unconfirmed_candidates` | Keys of `confirmed: false` Layer 0 stubs for developer review                                |
| `knowledge_gaps`         | Top gaps ranked by risk score. Currently always empty; assembler is not wired yet.           |
| `compliance_rate`        | Last 7-day compliance rate. Currently always `None`; not populated yet.                      |
| `injection_string`       | Pre-formatted markdown returned as the MCP tool result text                                  |
| `token_estimate`         | Estimated token size of the assembled packet, used for budget accounting                     |

---

## 7. Key Namespacing

Store keys follow this convention:

```text
gotcha:<slug>          file:<path>           decision:<slug>
stage:current          dep:<ecosystem>:<name> dev_note:<slug>
policy:<slug>          session:<timestamp>    analytics:<type>_<date>
graph:edge:<from>:<kind>:<to>
enforcement:event:<seq_no>
```

`file:<path>` uses repo-relative paths, normalized lexically. The store key itself does not resolve symlinks; on case-insensitive filesystems, case-folding is applied. Enforcement adds a canonical-key fallback (section 24) so a read or edit routed through an in-repo symlink to a gotcha'd file still trips the gate.

---

## 8. Storage Layer

Each project gets two SurrealKV trees under `~/.mati/<slug>/`.

The `~/.mati` root is overridable with the `MATI_HOME` environment variable — one lever that relocates every project store, the daemon socket, logs, and the device id. It is the single source of truth resolved by `store::mati_home()`; every path-building site goes through it (a stray `dirs::home_dir().join(".mati")` would silently escape the override). Used by CI, sandboxes, users with a non-standard layout, and the test harness (which points it at a per-process temp dir so unit tests never write into the developer's real `~/.mati`).

Slug derivation uses the first 8 hex characters of `SHA-256(git remote URL)`. If the repo has no remote, it falls back to `SHA-256(canonicalized repo root path)`.

| Tree        | Path           | Durability           | Retention                               |
| ----------- | -------------- | -------------------- | --------------------------------------- |
| `knowledge` | `knowledge.db` | Immediate (fsync)    | Indefinite (`with_versioning(true, 0)`) |
| `sessions`  | `sessions.db`  | Eventual (OS buffer) | 90 days                                 |

Important detail: **`with_versioning(true, 0)` means indefinite retention.** The `0` argument does not mean “disabled.” It means keep all versions forever. That is intentional for `knowledge.db`. Sessions use the 90-day value.

Serialization uses MessagePack through `rmp-serde`. JSON (`serde_json::Value`) is used only for the typed `payload` field and hook I/O.

Knowledge namespaces, written on the Immediate path:

```text
gotcha:
decision:
file:
stage:
dev_note:
dep:
```

Session namespaces, written on the Eventual path:

```text
session:
analytics:
hook_event:
compliance:
graph:edge:
health:
parse:
audit:session:
```

`enforcement:event:*` is not part of `SESSION_NAMESPACES`, so it defaults to Immediate. Enforcement events are written to `knowledge.db` and are crash-safe by design.

After a crash, startup checks for `search_sync_pending` and `search_stale` markers. If either exists, mati rebuilds the tantivy index.

---

## 9. Graph Layer

petgraph is the in-memory graph. Edges are persisted in SurrealKV as keys shaped like this:

```text
graph:edge:<from>:<kind>:<to>
```

The daemon loads them at startup using a full key scan. If a mutation does not write back to SurrealKV immediately, it disappears on restart. That is easy to miss in tests, so treat it as a rule.

There are 10 edge kinds:

| Kind                | Meaning                                                                  |
| ------------------- | ------------------------------------------------------------------------ |
| `HasGotcha`         | A file has a gotcha record attached                                      |
| `Imports`           | A file imports another file, from static analysis                        |
| `AffectedBy`        | A file or gotcha is affected by an architectural decision                |
| `HasNote`           | A file or record has a developer note                                    |
| `DiscoveredIn`      | A gotcha or decision was found in a specific session                     |
| `CausedBy`          | One gotcha or issue was caused by another                                |
| `Supersedes`        | A decision or gotcha supersedes an older one                             |
| `Touched`           | A file was accessed in a session, used for passive learning              |
| `DependencyAffects` | A dependency change affects a file or module                             |
| `CoChanges`         | Two files are frequently committed together, from git co-change analysis |

Edge keys use the slugified kind name: `has_gotcha`, `imports`, `affected_by`, and so on.

---

## 10. Hook Pipeline

Hooks are shell scripts installed by `mati hooks` into the project’s `.claude/settings.json`. The command writes files under `.claude/` inside the repository root. Hooks run on `PreToolUse`, before Claude reads a file or runs a bash command, and on `PostToolUse`, after the tool call.

The decision engine in `src/hooks/decide/` is pure. No I/O, no daemon calls. The adapter layer in `src/cli/hook_decide/` maps semantic decisions to protocol output:

- JSON for Claude Code, which runs the hook as a shell subprocess and reads stdout
- exit codes for environments that support the Codex hook protocol

Hook-based enforcement, meaning the Deny/Advisory path in section 10.1, requires the host environment to install and execute the hook scripts. Claude Code does this natively.

Codex hook execution depends on the agent configuration. If hooks are not running, enforcement falls back to MCP-only behavior: `mem_get` still mints consultation receipts, but no file reads are blocked. Other MCP-compatible agents that do not run hooks get tool access only.

### 10.1 Decision Matrix

Decisions are evaluated in this order:

```text
1. file_record is None
   -> NoRecord: log miss, allow unconditionally

2. staleness.signals contains FileDeleted AND input.file_exists != Some(true)
   -> Tombstone: allow unconditionally, no injection. The one enforcement
      bypass — keyed on the literal signal, not the tier, since the source
      file is gone and there is nothing left to enforce against.
      The signal is a stale snapshot (cleared only by the staleness sweep,
      which can be many sessions behind); `file_exists` is the caller's own
      fresher on-disk observation, populated ONLY by stat-ing the path when
      this signal is present. `Some(true)` (path is back — delete-then-
      restore, branch switch, `git stash pop`) skips this step and falls
      through to step 3 instead of bypassing on stale information. `None`
      (caller did not check) and `Some(false)` (confirmed gone) both bypass
      as before. If a qualifying gotcha (step 3) would have denied and
      `file_exists == Some(false)`, the bypass logs `BypassDetected`
      (`tombstone_file_deleted`) instead of the ordinary `Miss` — enforcement
      was suppressed, not merely a cache miss.

3. any attached gotcha has (confirmed=true AND confidence >= 0.6 AND quality >= 0.4):
     a. already_consulted == true
        -> AlreadyConsulted: allow + inject context, log ComplianceHit
     b. already_consulted == false
        -> Deny: block read, inject mem_get() instruction, log BlockedUnconsultedRead
   Runs regardless of staleness_tier — staleness gates injection (steps 4-5
   below), not enforcement. A qualifying gotcha denies even at Liability or
   Tombstone.

4. staleness_tier == "tombstone" (no gotcha qualified in step 3)
   -> Tombstone: allow unconditionally, no injection

5. staleness_tier == "liability" (no gotcha qualified in step 3)
   -> Liability: allow + inject WARNING (staleness value shown), log hit

6. file_record.confidence >= 0.3 AND file_record.quality >= 0.4
   (checks the file record's own scores; unconfirmed gotchas do not factor in here)
   -> Advisory: allow + inject context as additionalContext, log hit

7. default
   -> Allow: pass through, no injection
```

`confidence < 0.3` or `quality < 0.4` always allows without injection, no matter what the `confirmed` state says.

### 10.2 Command Classification (pre-bash)

The pre-bash hook classifies shell commands before they run.

- **CatLike**: `cat`, `less`, `head`, `tail`, `bat`. The file path is extracted from the first non-flag argument.
- **GrepLike**: `grep`, `rg`, `sed`, `awk`. The file path is extracted from the last non-flag argument.
- **PathMutating**: `rm`, `mv`, `rmdir`, `shred`. Every non-flag argument is a target path. Normalizes to `tool=path`, so a `target_path_glob` policy gates a delete or move the same way it gates an edit (section 10a.1).
- Anything else is not treated as a governed operation and passes through unconditionally.

On Claude Code, the Bash gate never emits `permissionDecision: "allow"`. Bash is a permission-required tool, so a force-allow would suppress the user's permission prompt for every command mati does not deny. Non-deny outcomes defer (empty stdout, exit 0); advisory/consulted context is injected via `additionalContext` *without* a `permissionDecision`, which Claude Code treats as "inject context, permission flow proceeds normally." Only the read gate (`Read`/`Glob`/`Grep` — no-permission tools) emits the no-op `allow`. This invariant is pinned by the `only_pre_read_force_allows` test in `cli::hook_decide`.

#### Layering against permission rules

Hooks and permission rules are separate layers, and the precedence runs in both directions:

- **A hook block precedes permission rules.** A hook that exits 2 stops the call before rules are evaluated, so the block holds even where an allow rule would have let it through.
- **A hook allow does not bypass permission rules.** Deny and ask rules are evaluated regardless of what the hook returned: a matching deny rule blocks the call, and a matching ask rule still prompts even after `"allow"`.

Both directions favour mati. The deny path is the strong one, and it is the path enforcement depends on. The allow path is deliberately weak, which is why emitting `allow` on a permission-required tool is a bug rather than a shortcut: it cannot grant anything a rule forbids, and its only reachable effect is to skip the prompt the user wanted. That is the same conclusion the invariant above reaches from the Bash side, arriving from the platform side instead.

Known limitation: `cat` with variable expansion, process substitution, or unusual quoting is not caught. The accepted miss rate is 2-5%. See section 24.

### 10.3 Edit Gating (Codex `apply_patch`)

On Codex, the `apply_patch` `PreToolUse` hook (`codex-pre-apply-patch`) gates file edits the same way pre-bash gates reads.

The payload is the raw patch envelope in `tool_input.command`. `decide::extract_apply_patch_files` parses the column-0 markers:

```text
*** Update File:
*** Add File:
*** Delete File:
*** Move to:
```

Those markers become the touched paths. Each path is then run through the same section 10.1 decision matrix. If any touched file has an unconsulted confirmed gotcha, the edit is denied with exit 2 and stderr. A `mem_get` consultation receipt clears it, just like reads.

Because the envelope gives mati the exact target path, edit gating is not affected by the shell-wrapper obfuscation that limits pre-bash read detection in section 10.2 and section 24. There is no command string to misparse.

It fails open on every uncertainty: unparseable patch, unreachable daemon, per-file lookup error, more than `MAX_APPLY_PATCH_FILES = 50` touched files, or an older binary that does not recognize the variant. Blocking all edits by mistake would be worse than missing one gotcha. The wrapper script in `codex_pre_apply_patch.rs` enforces that bias by treating only `exit 2` with a `mati:` message as a real deny.

Coverage depends on platform support. `apply_patch` gating rests on a documented Codex contract, not on an implementation quirk: Codex's `PreToolUse` "can intercept Bash, file edits performed through `apply_patch`, MCP tool calls, and other local function tools," and reports `tool_name: "apply_patch"` for patch operations (matchers also accept `Edit` and `Write` as aliases). Codex now carries near-full hook parity with Claude Code — `SessionStart`, `SessionEnd`, `SubagentStart`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `UserPromptSubmit`, `SubagentStop`, `Stop` — and supports `updatedInput` for rewriting a Bash or `apply_patch` call without blocking it. mati does not use `updatedInput`: silently rewriting a call the agent believes it issued is a correctness hazard, and the gates here are meant to deny or defer, never to substitute. Codex reads are gated only through the shell path, but the reason is sharper than "no hook on its read tool" and was measured on codex-cli 0.147.0 (2026-08-12). Codex appears to have no built-in text-file read tool at all — asked for one in a live session it answered "no built-in text-file reading tool is available," and a single session that both read a file and ran a shell command produced `PreToolUse` payloads for only `list_mcp_resources` and `Bash`. Yet in an earlier run the file's contents reached the model with ZERO `PreToolUse` payloads, against a fixture proven live by a Bash control. So some path — most likely automatic context gathering rather than a tool call — delivers file content outside the tool surface entirely. This is not C9: no amount of shell-command parsing closes it, because no shell command is involved. Only the host can close it. Claude Code edits are covered primarily by the read gate, transitively: Claude Code's own read-before-edit rule forces a prior read, which the read gate gates — and a *naive* blind edit is stopped by Claude Code's "File must be read first" guard *before any PreToolUse hook runs* (confirmed by live test 2026-06-18: a blind Edit yielded Claude Code's built-in guard, not a mati deny; enforcement came from the read gate). The `claude-pre-edit` hook (the `ClaudePreEdit` adapter, PreToolUse on `Edit`/`Write`/`NotebookEdit`) is therefore a BACKSTOP, not the primary blocker: keyed on `consulted_recent` (TTL, like the Codex `apply_patch` edit gate), it denies via `permissionDecision: deny` only an edit whose consultation has gone stale, or one that satisfied read-before-edit via a shell read the best-effort pre-bash path missed (e.g. `cat "$VAR"`; `egrep`/`fgrep` are now detected). Non-deny outcomes defer to the normal permission flow (edits are permission-required, unlike reads, so emitting `allow` would suppress the user's edit prompt). The `consulted_recent` keying is load-bearing: with the read gate's persistent `consulted`, the edit gate would never fire, since the forced read always consults first.

### 10.4 ConfigChange enforcement self-integrity (F1)

Claude Code sends `ConfigChange` after it has written the proposed new settings
file. The payload is deliberately small and carries no old value and no diff:

```json
{
  "session_id": "…",
  "transcript_path": "…",
  "cwd": "…",
  "prompt_id": "…",
  "hook_event_name": "ConfigChange",
  "source": "project_settings",
  "file_path": "/repo/.claude/settings.json"
}
```

`claude-config-change` reads `file_path` and performs an invariant check over
the new JSON. For the exact project `.claude/settings.json` path it compares
mati's command registrations against the scaffold template, including the
guard's own `ConfigChange` entry. It requires the registered command, event
matcher, hook type, and timeout; a timeout at least the scaffold's 4-second
value is accepted, so a legitimate increase remains valid. For the exact local
`.claude/settings.local.json` path it compares every surface the sandbox
compiler writes — `sandbox.filesystem.denyRead`/`denyWrite`,
`sandbox.credentials.files`, and `sandbox.network.deniedDomains` — and leaves
unrelated user entries alone. A credential entry is checked on mode as well as
path, since downgrading `deny` to `mask` leaves the path in place and weakens
the protection. A missing or repointed entry, an empty `hooks` object, or a
removed event array yields a block. Each violation records the existing
`EnforcementConfigChanged` event with `subject_kind: Config`; no ninth event
type is introduced.

Ownership decides what the guard may require and what it may name. Filesystem
denies and credential files carry a path, so containment under the canonical
repo root decides. A denied domain carries none, so the `db_client` host-glob
universe — every glob the policy corpus has authored, enforcing or not — stands
in for it, the same boundary `mati sandbox compile` uses to merge and clear that
array. Ownership also bounds the reported `new_value`: when mati's entry is gone
the guard names another mati-owned entry if one is there and `<removed>`
otherwise, never a user entry the user did not touch. The audit log is
hash-chained and mati-cloud reports on it, so a violation must not assert a
change that did not happen.

The output is a top-level `{"decision":"block","reason":"…"}` or
`{"decision":"allow"}` object. It is not the older
`hookSpecificOutput.permissionDecision` wrapper. `user_settings` and `skills`
are allowed without project-entry checks. `policy_settings` is recorded and
allowed because Claude Code does not permit this hook to block that source.
An unrelated path is allowed even when its source name is `project_settings` or
`local_settings`. Malformed JSON, unreadable files, and other I/O errors fail
open and are logged; `NotFound` is distinct and is treated as removal of a
mati-owned settings file. The check is stateless, so successive changes have
no ordering assumption.

This guard acts only on in-session adoption. Claude Code has already written the
new file, and a block does not roll that write back; quitting and restarting
adopts the changed file. The result is “not adopted this session, and
recorded,” not durable file protection.

### 10.5 Live freshness (F4)

Staleness is computed at `mati init` time. `FileChanged` gives the health system the event it is otherwise starved of: an edit updates `content_hash` and staleness incrementally, in the daemon, with no rescan. Drift needs no event at all — it hashes the working tree on demand — so `mati stale` reports a confirmed gotcha as drifted the moment its file changes.

Claude Code starts no file watcher until a `SessionStart` hook returns `hookSpecificOutput.watchPaths`. `mati watch-paths` supplies it: the absolute path of every existing file named by an Active gotcha. That scope is the point — those are the files whose content can invalidate a rule that denies a read. A `file:*` record with no gotcha attached keeps its `mati init` freshness. Absolute paths, `..` escapes, and glob entries such as `src/payments/**` drop out; the set is capped at 512 with a warning naming what was dropped.

The `matcher` field on a `FileChanged` hook entry is a second, static source of watch paths, resolved against the cwd. mati sets none. Matchers do not filter execution for this event — every registered `FileChanged` hook runs for every watched-file event — so a store-driven `watchPaths` and an unmatched hook entry give exact scoping.

The payload, captured live from Claude Code 2.1.223:

```json
{
  "session_id": "…",
  "transcript_path": "…",
  "cwd": "/private/tmp/repo",
  "prompt_id": "…",
  "hook_event_name": "FileChanged",
  "file_path": "/tmp/repo/src/main.rs",
  "event": "change"
}
```

`file_path` is echoed back in the exact spelling mati handed to `watchPaths` and is *not* canonicalized, while `cwd` is. Comparing the two lexically is the F1 `/tmp` vs `/private/tmp` trap; `watched_rel_path` resolves both sides through `canonicalize_lenient` before stripping the root, with a lexical strip as the fallback. A path outside the repo has no `file:*` key and is dropped.

`event` is a chokidar event: `add`, `change`, or `unlink`. Only `add` and `change` drive a reparse. `unlink` is deliberately ignored — it would set the `FileDeleted` staleness signal and pin the record at the `Tombstone` tier, and `apply_reparse_staleness` only saturates upward, so a save that lands as delete-then-create would suppress that file's context injection for good. Real deletions are still caught by `mati init` and `mati repair`, and step 2 of the decision matrix stats the file live before honouring the signal.

The adapter reuses the existing `FileReparse` command, so the write keeps its audit entry and stays atomic. It emits no stdout: `FileChanged` carries no permission decision. Every failure — unparseable payload, missing mati root, unreachable daemon, rejected reparse — logs one `fail_open.log` entry and exits 0.

### Sandbox floor (L3, opt-in)

The hook gates above cover the agent's *tool* surface; they cannot reach the shell's *subprocess* surface beyond best-effort command parsing (`cat "$VAR"`, a `python` script, a symlink). For a small crown-jewel tier, `mati sandbox` compiles an **OS-level floor** that closes that gap: confirmed gotchas tagged `crown-jewel` (and `sandbox-deny-read` for secrets) become `sandbox.filesystem.denyWrite`/`denyRead` entries in `.claude/settings.local.json`, enforced by Claude Code's sandbox (Seatbelt on macOS, bubblewrap on Linux/WSL2) across the shell *and every subprocess it spawns*. For a crown-jewel file the shell path is then denied at the OS level, leaving the consultation-gated Read/Edit tools as the only way the agent can touch it (L1 + L3 compose to "reachable only via the gate").

Design invariants (each verified — see `MATI-SOTA-ARCHITECTURE.md` L3): explicit-tag-only, never severity-derived; **absolute canonical paths** (CC's `./` resolution is undocumented, so a relative deny could silently fail to match — a live Seatbelt + Claude Code test confirmed absolute paths enforce and resist symlink bypass); mati owns only the `denyRead`/`denyWrite` entries under the repo root, preserving the user's `~/`/out-of-repo denies via CC's documented array-union + deny-wins across scopes; out-of-repo paths are skipped so a gotcha can never deny `~`/`/etc`; preview-default and reversible (`clear`/`unprotect`); a drift guard refuses to silently remove a protection whose tag was dropped. mati never writes `sandbox.enabled` — enablement is the user's (`/sandbox`) or the Enterprise managed-settings tier's. Commands: `mati sandbox protect <file> [--read] [--secret deny|mask]`, `unprotect <file>`, `compile [--apply]`, `clear`.

The Codex target is preparation only, not an active L3 floor. Verified against the installed `codex-cli 0.146.0`, `[permissions.mati].deny_read` and `[permissions.mati].deny_write` parse, but Codex does not currently enforce them: a path listed in `deny_write` could still be written and a path listed in `deny_read` could still be read. `mati sandbox compile --codex` therefore states plainly that the entries are not active protection and are written only for a future enforcing runtime. Applying them requires the separate `--acknowledge-codex-non-enforcement` opt-in. Codex's coarse network switch is a separate capability and is not part of this filesystem preparation target.

The optional Claude `mcp_tool` transport is a prototype, enabled only by `mati init --claude --claude-mcp-tool` or `mati hooks --claude --claude-mcp-tool`. It adds a `PreToolUse` Read/Glob/Grep registration that calls the existing `mem_get` tool with its `decision` and `agent_id` parameters; the tool result body is the normal Claude hook JSON. Both parameters are scaffold-only — `#[schemars(skip)]` keeps them out of `mem_get`'s public tool schema, since mati's own hook `input` writes them and the model has no reason to call either. The shell `pre-read.sh` registration remains alongside it and remains the startup-independent enforcement path. This is deliberate: an `mcp_tool` hook cannot fire until the MCP server is connected, so it is not suitable as the sole path for Read, Bash, Edit, SessionStart, or ConfigChange while the server or daemon is down. The prototype is fail-open and uses the existing UDS daemon bridge; it does not add an HTTP handler or a ninth enforcement event.

Receipt scoping on this path matches the shell hook. `${agent_id}` is a real interpolation token in the `mcp_tool` handler's `input` — confirmed live: a probe MCP server logging what it received showed `"agent_id": ""` for a main-thread Read and a real subagent id for a Task-spawned subagent's Read, the same field `cli::hook_decide::entry` already reads from the shell payload. The scaffold's `input` now sends `"agent_id": "${agent_id}"` alongside `"decision": true`, and `MatiServer::decision_actor` combines it with the worktree tag through the same `combined_actor_scope` the shell path uses, treating an interpolated empty string as no agent rather than a literal actor. Before this fix the handler sent `self.worktree_tag` alone: reproduced live, a main-thread consultation then let an uninvolved subagent's `decision:true` call return `allow` with no receipt of its own. With the fix, the same scenario denies that subagent while the shell path and the mcp_tool path agree on every case (main thread, consulting subagent, non-consulting subagent) — verified by running both against the same store with the same actor.


Two later surfaces extend the same floor and the same ownership rule. A gotcha tagged `secret-deny`/`secret-mask` compiles into `sandbox.credentials.files` as `{mode, path}`, still owned by repo-root containment. An enforcing (`stage: enforce`, `mode: block`) `db_client` policy with a `host_glob` compiles into `sandbox.network.deniedDomains`, owned instead by membership in the `db_client` host-glob universe, because a domain has no path. `clear` therefore needs the policy corpus to remove a domain: with the store unreachable it leaves the domains in place, and when any remain it reports a partial clear naming how many and exits 1, rather than reporting a clear it did not perform. No domain left behind means nothing was missed, so that case still reports a full clear and exits 0.

Every `mati sandbox` mutation — `protect`, `unprotect`, `compile --apply`, `clear` — records an `EnforcementConfigChanged` event under `sandbox.floor` with reason `sandbox_<action>`. This works in both store modes: direct mode writes the event, and socket mode sends `Command::SandboxAudit` so a daemon holding the store records it. `clear` is the one exception, and only when the store is unreachable: no store, no event.

---

## 10a. Local Policy Engine

A gotcha attaches knowledge to a file. A local policy attaches a rule to an *action*: "before running a production query, consult the schema first." Policies are developer-authored, repository-scoped, and enforced in the same hook path as gotchas.

"Policy" in mati means one concept at two levels of authority.

| Layer | Authored by | Signed | Distributed | Weakenable |
| ------------- | ------------------- | ------------- | ------------------- | ------------------------------------------ |
| Local policy | the local developer | no | no | yes, the author edits or disables it freely |
| Signed floor | the org | yes (Ed25519) | yes, by mati Enterprise | no, a repo may strengthen it but never weaken it |

Both produce a consult-required deny at hook time. They stay distinguishable in the audit log by reason code: `policy_consult_required` for a local policy, `floor_consult_required` for the signed floor. `mati policy verify` checks an inherited signed bundle; `mati policy add` authors a local rule. The two layers share receipts but not matchers.

### 10a.1 Records and mutations

A policy is a `policy:<slug>` record carrying a `PolicyRecord` payload (section 5.3a). It is developer-authored source of truth, so it writes at `Immediate` durability (section 21).

A policy has one rollout stage. `off` is never evaluated. `shadow` is evaluated and recorded but changes no decision. `enforce` acts on `mode`, steering or blocking. The `policy.mode` kill switch applies at `enforce`, degrading a block to a steer. New policies start at `off`. Staging one to `shadow` first shows what it would catch before it can stop anything.

Every create, edit, stage change, and tombstone path goes through `store::policy_ops`, mirroring the gotcha discipline in section 22: the canonical record is written first and fails hard, and the `ControlChanged` event follows best-effort. `mati policy enable` and `disable` are aliases for setting the stage to `enforce` and `off`. Policies have no derived index, so they need no dirty-marker or repair reconciliation.

`mati protect <glob>` is sugar over this authoring path for the common case of guarding a repo path. It writes a `policy:protect-<slug>` (trigger `{ tool: "path", target_path_glob }`, `mode: block`, `via: [mem_get]`) plus the backing `decision:protect-<slug>` the agent consults to unlock one, in a single command. It defaults to `shadow` (`--enable` promotes to `enforce`, `--steer` warns instead of blocks) and upserts on re-run. A plain path or a `<base>/**` glob expands to `{ <base>, <base>/** }` so the policy gates deleting the directory itself, not only its contents, without over-matching a sibling; a glob with its own metacharacters is used verbatim.

The approval control depends on Bash remaining permission-required; blanket-allowlisting `mati` in Bash permissions removes that human approval step and lets an agent run `mati policy stage <slug> enforce` directly. Every lifecycle change still writes a `ControlChanged` event to the hash-chained log, so removal remains detectable even when it is not prevented.

`off` is the only stage an agent can write. `shadow` and `enforce` belong to the developer. `mem_set` forces any other stage in an agent payload down to `off`, and refuses to edit or delete a policy that is not already `off`. An agent can draft a policy but cannot make one act, and cannot quietly rewrite one the developer is midway through reviewing. That holds for `mem_set` only. The Bash caveat above still applies to the CLI.

Glob predicates are validated at author time. A malformed `host_glob` or `target_path_glob` is rejected before it can be persisted, so a broken pattern never reaches the daemon.

Policy records are deliberately excluded from `mati stale`, for a structural reason rather than a philosophical one.

For a `policy:<slug>` key every staleness factor collapses. `git_factor` resolves a blob at the literal path `policy:<slug>` (the `strip_prefix("file:")` is a no-op) and the HEAD tree returns nothing, so 0.0. `dep_factor` needs a parsed `FileRecord`, so 0.0. `cascade_factor` matches on `record.category` and `Policy` falls to the `_ => 0.0` arm. `semantic_factor` is a v0.1 constant 0.0. Only `time_factor` survives, weighted `TIME_WEIGHT = 0.20`, so the score asymptotes at 0.20. `tier_from_value(0.20)` is `Aging`, and `mati stale` reports only `Stale`, `Liability`, and `Tombstone`. Adding `policy:` to `STALENESS_PREFIXES` would therefore produce a record that can never appear in the report it feeds, at the cost of a full scan against the 2s `ANALYZE_TIME_BUDGET_MS`.

The tiers also mean the wrong thing here. They carry injection semantics — warn in bootstrap, blocks injection, excluded entirely — while policy enforcement gates on `RecordLifecycle::Active` and `PolicyStage` and never reads staleness at all. A policy shown as "excluded entirely" while it still denies every matching action would be a false statement on the operator's dashboard.

Matches are recorded in three eventual activity sources. A `block` policy at
`enforce` writes `enforcement:event:*` with `subject_kind: Control` and reason
`policy_consult_required` or `policy_receipt_valid`; a `shadow` policy writes
`analytics:policy_shadow_<date>`; and an enforcing `steer` policy writes
`analytics:policy_steer_<date>`. `mati policy activity` aggregates those traces
on read, reports `fired`, `no activity in <N> days`, or `not measurable`, and
states the 365-day enforcement retention bound. It deliberately keeps no
derived per-policy index: `mati repair` can therefore continue to rebuild and
verify every index this repository owns.

The steer key is a normal `analytics:*` `Record`, not raw bytes, and therefore
uses the existing `Eventual` durability class. No exact-key durability
exception is needed; the keyspace encoding remains the invariant.

Activity is an under-count when a satisfied block policy and a different denying policy match the same action: the satisfied policy's `PolicyConsulted` event is dropped because writing `AllowAfterReceipt` for an action that was denied would falsify the hash-chained enforcement audit, and the same decision suppresses a steer trace for that denied action. It can also over-report. Manual hook invocations send real `SessionLog` events through the daemon and inflate the aggregate; the live run reported three steering matches for `live-editsteer` when exactly one steering edit occurred, because the agent replayed hooks while inspecting raw decisions. `scripts/policy-live-session.sh` filters its post-bash tee on `transcript_path` for this reason, but the analytics path has no equivalent guard, so a count is evidence of liveness only when the author has not been replaying hooks. A steer policy's `last_fired_at` is only day-granular because it comes from the daily aggregate's `updated_at`; its per-key `count` is exact. Shadow timestamps use the maximum of per-observation timestamps and enforcement timestamps come from each event, so those sources are precise. The activity help text therefore points authors to `mati policy test`: the count is the load-bearing activity signal, a steer-only last timestamp is a hint, and the test answers whether the rule would still fire.

`mem_bootstrap` also does not preload policies. This is intentional under P2:
inject nothing by default and pull on demand. A policy deny names the required
consultation key and closes the loop without adding a field to every
`ContextPacket` or spending tokens on policies unrelated to the current task.
The four-tool MCP surface remains unchanged.

Codex `codex-pre-apply-patch` is a policy enforcement path. Its patch envelope provides exact target paths, which are normalized into `Action { tool: "path" }` and evaluated with `target_path_glob` policies after the existing gotcha gate. As with other Codex gates, a policy deny is reported as exit 2 with a `mati:` stderr instruction; uncertainty still fails open.

`scripts/policy-live-codex.sh` is the live-session fixture for this adapter. It
captures raw Codex `apply_patch` PreToolUse and Bash PostToolUse payloads,
verifies the Codex hook and MCP wiring, and prompts a session to exercise the
apply-patch deny/consult path, symlink resolution, shadow observations, the
fileless Bash deny, and the `db_client` deny → `mem_get` → allow loop. Its
`db_client` policy requires `MemGet`, not `DbIntrospection`: a Codex session
cannot mint the latter (section 10a.5), so a policy accepting only it would
steer rather than deny and the check would test nothing. The fixture asserts
that limit directly instead — introspecting first must leave the deny standing.
The introspect-then-query path is validated on Claude by
`scripts/policy-live-session.sh`. These Codex paths remain unvalidated until a
real Codex session has run the fixture; the synthetic assertions in
`scripts/smoke-policy.sh` do not close that gap.

Event collection on this path is not conditional on denying. A patch that is allowed still fires whatever the gates produced: a shadow observation, a receipt-backed allow, and a `Miss` for any touched file with no record. That last one makes `codex-pre-apply-patch` a miss-recording surface, which it was not before — previously it fired nothing unless it denied, so multi-file patches under-counted misses. `fire_events` is one sequential daemon round trip per event and `MAX_APPLY_PATCH_FILES` is 50; a measured 50-file no-record patch costs ~105ms against the 2500ms `HOOK_DEADLINE_MS`, so the sequential shape stands. If that ever becomes material the fix is a batched command preserving order, not concurrency: enforcement events allocate a durable monotonic `seq_no` into a hash chain, and concurrent writes would make the order of a log whose purpose is replayable tamper-evidence non-deterministic.

The path policy gate is symlink-safe. The canonical target is resolved once per path, before any gate runs, and both the gotcha gate and the policy gate evaluate the lexical key and the canonical one under the same escalate-only rule: the first deny wins and a non-deny canonical outcome never lowers the lexical decision. Editing or patching a symlink that points at a governed file therefore trips `target_path_glob` on the real target. Claude Code also refuses to write through a symlink after the policy deny has been cleared; that defense-in-depth behavior was verified against Claude Code in the live run, but it is vendor behavior that mati does not control. Codex `apply_patch` has no such guard and parses exact target paths, while the Bash path has no such guard either: a `psql -f` command naming a symlink into a governed directory is denied only because mati resolves the target. Resolving once is therefore load-bearing outside the Claude edit path and must remain there. `canonical_rel_path` returns `None` for a non-symlink, so the common path costs nothing extra.

The policy adapter scope is intentional. `db_client` actions are governed on both Claude and Codex Bash, fileless and file-bearing; schema introspection is exempt so it can steer toward the consultation that remedies the policy. `path` actions are governed on Claude edits, Codex `apply_patch`, and — via the `PathMutating` class — `rm`/`mv`/`rmdir`/`shred` on the Bash path, so a `target_path_glob` policy gates deletes and moves like edits. Each Bash action is governed by its own category: `evaluate_governed_policy` keys on the action's tool, so a `db_client` action gates on `db_client` and a `path` action on `path`. `file_read` actions from `cat`/`grep`-class Bash commands are not policy-governed; the gotcha read gate already owns that surface under P1, and a stored `file_read` policy receives an author/doctor warning instead of silently pretending it can enforce. Codex denies exit 2 with a `mati:` instruction on stderr, while Claude denies remain `permissionDecision` JSON.

Determinism differs by category, and the boundary must be stated honestly rather than sold as a blanket guarantee:

| Governed action | Determinism |
| --- | --- |
| Edit/Write, Codex `apply_patch` | exact (structured target path) |
| DB client → host | exact (parsed host) |
| `rm`/`mv`/`rmdir`/`shred` literal path | read-gate level — the 2-5% shell-bypass miss applies (section 24) |
| pathless verbs (`dd`, `mkfs`, `terraform destroy`, `git reset --hard`) | not governed; normalize to no path and no category |

A block on a literal-path delete is a strong tripwire backed by the audit chain, not a guarantee: an unexpanded variable or process substitution slips it at the same rate `cat` does. Governing the pathless verbs is future work — a `command_glob` predicate plus verb classification, which also has to widen the pre-bash fileless path beyond `db_client`.

This closes the Codex asymmetry in which `codex-post-bash` could mint
db-introspection receipts for a `db_client` policy category that
`codex-pre-bash` did not previously enforce.

### 10a.2 Matching

Matching is two layers, and the split is deliberate.

**Normalization is code.** `decide::normalize_action` turns a raw invocation into an `Action`: `{ tool, target_path, host, argv, files }`. For bash this extends the classifier in section 10.2 with a `DbClientLike` class (`psql`, `mysql`, `redis-cli`, `mongosh`, `sqlite3`, and peers) and a `PathMutating` class (`rm`, `mv`, `rmdir`, `shred`), reusing the same prefix stripping and basename reduction, so `sudo /usr/bin/psql` normalizes like `psql` and `sudo rm -rf x` like `rm`. The host comes from `-h`/`--host` or a `PGHOST=`/`DATABASE_URL=` assignment. `db_client` files come from a `-f`/`--file` grammar arm; `PathMutating` files are every positional (a flag cluster like `-rf` is skipped), normalized to `tool=path`. The governable categories (`db_client`, `file_read`, `path`) are a bounded set in code, guarded by `is_known_action_tool`. Adding a category is a reviewed change.

**Matching is data.** A policy's `trigger` is a declarative predicate over the `Action`, for example `{ tool: "db_client", host_glob: "*prod*" }` or `{ target_path_glob: "**/*.sql" }`. Absent fields are wildcards; present fields must all match. Adding or tuning a policy never touches the decision core. That is what keeps the engine from growing a match arm per rule.

Matching never inspects intent. It gates on the client invocation, not on whether the SQL is a `SELECT` or an `UPDATE`. The bash normalizer inherits the known gaps in section 10.2 and section 24 at the same accepted miss rate.

One gap is worse than a miss and worth calling out separately. The pre- and post-bash hooks assume they see the same command text, and `effective_command` strips only a fixed wrapper list (`sudo`, `env`, `nice`, and peers). Another `PreToolUse` hook that rewrites the command breaks that assumption: the pre hook sees what the user typed and blocks on it, while the post hook sees the rewritten form, fails to recognize a database client, and never mints. The policy then demands a consultation that cannot be satisfied, which is a hard failure rather than the accepted miss the classifier gaps produce. This was observed live with a token-proxy hook that rewrote `psql …` to `rtk psql …`. Nothing detects the mismatch; the fix is to exclude database clients from the rewriting hook, or to add the wrapper to `PREFIX_WORDS` when it is genuinely a transparent proxy.

### 10a.3 Where evaluation runs

The hook process is ephemeral and holds no policies. The daemon holds a compiled `PolicyMatcherSet`, loaded from a `policy:*` scan at boot and refreshed after each `policy_write`. A record with an invalid glob is skipped and logged rather than failing the whole set.

Evaluation splits across the two processes:

```text
hook    normalize the invocation into an Action          (no I/O)
hook    is the action in a governed category?            (gate, no I/O)
          no  -> prior behavior, zero round trips
          yes -> one policy_evaluate call over the socket
daemon  match the Action, check receipts, return verdicts (no decision)
hook    compute the decision, emit output, fire events
```

Shadow observations are bounded daily aggregates in the eventual `analytics:` namespace, capped per policy so a noisy one cannot crowd out a quiet one. Each entry records the policy key, the normalized action, a timestamp, and whether the policy would have blocked or steered. `mati policy observations` reads them back and prints the full count next to the retained sample, so a truncated sample is visible rather than silent. The same read is exposed over MCP as `mem_query mode="policy_observations"` (with `policy_activity` and `analytics` alongside), because an agent's sandboxed shell cannot reach the daemon socket the CLI proxies through, while `mati serve` runs outside that sandbox. They stay out of the hash-chained enforcement log: a shadow policy denied nothing, so a `Deny` event would falsify the audit chain mati-cloud reads.

A policy is observed only where `enforce` would have acted on it. A shadow block holding a valid receipt records nothing, because at `enforce` it would have allowed. Neither does one exempted as schema introspection (section 10a.5). Without that, a policy would look more disruptive than promoting it would actually be.

The gate is what keeps this cheap. A bash command that is not a database client makes no policy call at all, so the common path costs what it cost before. Only a governed action pays one local round trip, well inside `HOOK_DEADLINE_MS`.

The daemon returns data, not decisions. It reports which policies matched and whether each blocking policy's receipt is currently valid. The hook computes the outcome, preserving the same "daemon serves records, the ephemeral process decides" split used elsewhere in the enforcement path.

### 10a.4 Outcomes

A policy is `steer` or `block`. `steer` injects the policy's rule as context. `block` denies until the required consultation receipt exists. Shadow policies never inject context or deny; they record whether the matched policy would steer or block. Whether an enforce-stage block actually denies is controlled by the dedicated `policy.mode` setting: it defaults to `strict`, while explicit `advisory` is a global kill switch that degrades every block to a steer. A failure to read the setting also defaults to strict, so an unreadable setting never silently disables policy enforcement. `audit.write_durability` remains independent and controls only enforcement-event writes.

Three paths enforce policies: a bash command with no file (`psql -c "..."`), a bash command carrying one (`psql -f x.sql`), and an edit to a matching path (`Edit`, `Write`, `NotebookEdit`). All three share one output shape. A deny sets `permissionDecision: "deny"`. A steer injects `additionalContext` with no `permissionDecision` field at all.

The permission invariant from section 10.2 holds throughout. Neither the bash gate nor the edit gate ever emits `permissionDecision: "allow"`, because both tools are permission-required and a force-allow would suppress the user's prompt for everything mati does not deny.

That invariant is also what bounds a steer on an edit. Because a steer sets no decision, the rule text arrives alongside the tool's normal permission flow, so it reaches the developer before the write only when that flow actually prompts. Under an auto-approving permission mode the edit lands first and the rule reads as an after-the-fact note. A steer is guidance, not a gate, and on edits it is only a pre-write signal when edits are not auto-approved. A rule that must stop a write has to be `block`.

A file-bearing database command runs through the gotcha file gate and the policy engine both. The two decisions merge escalate-only: a policy can raise an outcome to deny or add context, and can never lower a gotcha deny. When the file gate already denies, the policy round trip is skipped, since deny is already the maximum.

Every policy failure path allows. An unreachable daemon, an error response, or an unparseable payload leaves the pre-existing decision untouched and never denies. A policy must not block because mati itself failed (P9).

### 10a.5 Consultation receipts

A block policy names what unlocks it: `requires.key` (for example `decision:orders-schema`), the sources that may satisfy it, and its freshness. The receipt is the existing `session:consulted:*` primitive from section 15, actor-scoped and TTL-bound.

Three named sources can mint it:

- **`MemGet`.** The agent calls `mem_get("decision:orders-schema")` and the post-memget hook mints the receipt. Minting is key-agnostic, so a key with no stored record would mint a receipt for a consultation that taught the agent nothing. `mati policy add` warns when a `MemGet` requirement points at an unbacked key. The key must also be one `mem_set` can write, which is a `gotcha:`, `decision:`, `dev_note:`, or `policy:` prefix. Nothing writes an arbitrary namespace, so a requirement on something like `schema:orders` can never be backed and the warning says so rather than suggesting a step the author cannot take.
- **`DbIntrospection`.** The agent's own schema inspection satisfies the policy. A `PostToolUse` bash hook recognizes an allowlisted inspection command (`information_schema`, `\d`, `DESCRIBE`, `SHOW TABLES`, and equivalents) and mints the receipt for each matched policy that accepts this source. The hook treats an absent `isError` as success because Claude Code omits that field on successful Bash payloads; an explicit `isError: true`, interruption, or nonzero exit field prevents minting. The more conservative rule — requiring `isError: false` and rejecting an unrecognized shape — was not shipped because it made every observed successful Claude introspection look like a failure and made this source impossible to mint. Codex's hook payload uses a plain-string `tool_response` with no status, so Codex does not mint `DbIntrospection`; that is a platform limit, not a defect in mati to repair here. A block policy accepting only sources Codex cannot mint is unsatisfiable there, so on the Codex pre-bash and apply-patch paths it degrades to steering and its rule is replaced by a diagnostic naming the sources it accepts. `CODEX_PRODUCIBLE_SOURCES` in `src/store/record.rs` is the one list both that degrade and the `mati policy add` author warning read, so the two cannot disagree.
- **`HookContext`.** A file-gate hit can inject the cached record into the agent's context. That event records the consultation as hook context, a genuine channel distinct from `MemGet` and database introspection.

The generic `mati log-hit` and `StoreProxy::log_hit` paths still mint receipts, but their provenance is intentionally `None`; those receipts do not satisfy a policy that names accepted sources. Receipts written before provenance existed also deserialize as `None` and have the same result.

Introspection commands are exempt from policy blocks. Without that exemption, a policy triggering on `psql -h *prod*` would block the very `psql -h prod -c "\d orders"` that satisfies it, and the agent could never comply. The exemption suppresses blocks only. It does not touch the gotcha file gate or minting. Satisfaction instead compares the receipt's recorded source with `requires.via`, so a policy that accepts only `MemGet` is satisfied only by a `MemGet` receipt, not merely by an introspection command being exempt.

Freshness is a TTL by default. Setting `freshness.fingerprint` also binds the receipt to the content of the consulted record, so a schema that drifts between the consultation and the governed action invalidates the receipt inside its TTL window and the action is blocked again. The fingerprint covers the record's knowledge-bearing fields and excludes access counters and timestamps. Including them would make a receipt invalidate itself, since minting bumps the record's own access metadata.

### 10a.6 Audit trail

Policy decisions reuse the event types in section 18. No new event type or subject kind was introduced.

| Outcome | Event | Reason code |
| ------------------------------------ | -------------------- | ---------------------------------------------------- |
| Blocked, no valid receipt | `Deny` | `policy_consult_required` |
| Allowed on a valid receipt | `AllowAfterReceipt` | `policy_receipt_valid` |
| Receipt minted | `ReceiptMinted` | `consultation_requested` |
| Created, staged, deleted | `ControlChanged` | `control_created` / `control_updated` / `control_deleted` |

Policy events carry `subject_kind = Control` and `subject_key = <policy key>`. That is what separates them from the file-subject gotcha and floor denies sharing the same log.

Only `enforce` policies reach this table. A `shadow` policy writes no enforcement event, not a `Deny` and not an `AllowAfterReceipt`, because it decided nothing. Its only trace is the observation in section 10a.3. Changing a stage is a lifecycle mutation and still writes `ControlChanged`, so a promotion to `enforce` stays in the chain.

---

## 11. MCP Server

The MCP server lives in `src/mcp/`. It uses the `rmcp` crate, the Rust MCP SDK, for stdio transport.

Exactly four tools are exposed. This is a hard constraint from P3. Every tool definition costs tokens on every Claude call.

| Tool            | Description                                                                                                        |
| --------------- | ------------------------------------------------------------------------------------------------------------------ |
| `mem_bootstrap` | Returns a `ContextPacket` for the current session. Token-budgeted to 2,000 tokens.                                 |
| `mem_get`       | Looks up a single record by key. Returns the full `Record` JSON. Mints a consultation receipt.                     |
| `mem_query`     | Read tool. Knowledge modes: `text` (BM25 through tantivy), `tag`, `graph` (1-hop traversal); `semantic` is gated behind `--features semantic`. Enforcement-telemetry modes: `policy_observations`, `policy_activity`, `analytics`. All pure reads, no receipt. |
| `mem_set`       | Writes a record. Triggers quality recomputation, graph edge updates, and search index update.                      |

`mati serve` runs the rmcp stdio loop and proxies every tool call to `mati daemon` over a Unix domain socket. The daemon handles the call and returns the result.

---

## 12. Static Analysis (Layer 0)

`mati init` runs a Layer 0 scan with no LLM calls. It produces `file:*` record stubs and graph edges from source code only.

**Supported languages (12):** Rust, TypeScript, JavaScript, Python, Go, Java, C, C++, Ruby, Scala, Elixir, Haskell.

Each grammar crate must expose a tree-sitter ABI compatible with the `tree-sitter = "0.23"` runtime. It does not have to use the exact same crate version. Most grammars pin to `"0.23"`, for example `tree-sitter-rust = "0.23"`, but some compatible grammars carry a different crate version, such as `tree-sitter-elixir = "0.3"`. If a grammar is ABI-incompatible, parsing fails silently. No error. No panic.

**What Layer 0 produces per file:**

- Entry points: public functions, types, exports
- Import graph, resolved to repo-relative paths where possible
- TODO/FIXME/HACK/NOTE comments with line, text, and kind
- `unsafe_count`, `unwrap_count`, `line_count`
- `change_frequency` and `last_author` from git2, capped at 5,000 non-merge commits
- `is_hotspot`, true for the top 10% by change frequency
- `blast_radius`, meaning direct and transitive importer count
- Co-change edges between files whose co-commit ratio is at least 70%, where the ratio is `shared_commits / min(commit_count_a, commit_count_b)` and `CO_CHANGE_THRESHOLD = 0.70`

**What Layer 0 does not produce:**

- `purpose`, which stays empty until Layer 1 enrichment
- `gotcha_keys`, which stay empty until enrichment or `mati gotcha add`
- `confirmed: true` gotchas

Layer 0 file records start with `quality = 0.10`, which is Suppressed tier, and `confidence = 0.10`, the StaticAnalysis base. Hooks never inject them until enrichment raises those scores.

---

## 13. Health System

### 13.1 Confidence Score

Confidence measures how much the system trusts a record’s accuracy.

```text
base_score by source:
  DeveloperManual -> 0.80
  Import          -> 0.70
  ClaudeEnrich    -> 0.60
  SessionHook     -> 0.50
  StaticAnalysis  -> 0.10

confidence = base_score
  x log2(confirmation_count + 2)     capped at 2.0
  x contributor_factor               1.0 + 0.1 per contributor past the first, capped at 3
  x recency_weight(last_accessed)    90-day half-life
  x ref_boost                        1.5x if ref_url is set
```

The contributor factor is a bonus, never a penalty. It was `min(contributor_count, 3) / 3` until it was found to scale a solo developer's record to a third of its base: a confirmed `DeveloperManual` gotcha with one contributor and no `ref_url` recomputed to 0.42, below the 0.6 deny threshold in section 10.1. Since mati is the complete product for a solo developer, one contributor is the normal case and scores 1.0. Corroboration still helps, capped at 1.2x.

Recomputation is implemented as a pure function, `health::confidence::recompute`, but it is **not wired into the `mem_get` path yet**. Right now, `mem_get` only bumps `access_count`. Automatic recomputation on access is planned.

One small but important note: `file:*` records are written on the Immediate path, not the Eventual path.

Confidence feeds into two different paths in section 10.1.

| Path                    | Condition                                                                                | Behavior                                           |
| ----------------------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------- |
| Deny (section 10.1 step 3)     | attached gotcha: `confirmed = true`, `confidence >= 0.6`, `quality >= 0.4`               | Block file read; require `mem_get` consultation    |
| Advisory (section 10.1 step 6) | file record: `confidence >= 0.3`, `quality >= 0.4`, with no gotcha confirmation required | Allow read + attach context as `additionalContext` |
| No injection            | file record: `confidence < 0.3` or `quality < 0.4`                                       | Allow read unconditionally                         |

### 13.2 Quality Score

Quality tiers use half-open intervals.

| Tier       | Range      | Injection behavior                                          |
| ---------- | ---------- | ----------------------------------------------------------- |
| Suppressed | [0.0, 0.2) | Never injected                                              |
| Poor       | [0.2, 0.4) | Injected with `[mati] LOW QUALITY - verify` warning         |
| Acceptable | [0.4, 0.7) | Injected normally                                           |
| Good       | [0.7, 0.9) | Prioritized in `mem_bootstrap`                              |
| Excellent  | [0.9, 1.0] | Prioritized for template reuse, planned under `mati garden` |

See section 5.4 for the formula.

### 13.3 Onboarding Score

This estimates how long a new developer would need to reach productive understanding, given the current knowledge coverage. The base time and weights are design targets. They are not universal measurements.

```text
base_time = 22 minutes

reduction_factors:
  hotspot_coverage  x 0.40   (fraction of hotspot files with non-empty purpose)
  gotcha_coverage   x 0.25   (fraction of hotspot files with at least 1 attached gotcha)
  decision_coverage x 0.15   (fraction of decisions documented)
  confidence_weight x 0.20   (average confidence across confirmed records)

estimated_minutes = base_time x (1 - weighted_reduction)
```

`mati stats` computes this on demand. It is not persisted yet. Persistence as `analytics:onboarding_score` on the Eventual path is planned.

---

## 14. Enrichment (Layer 1)

`mati enrich [path]` runs a four-stage per-file pipeline using Claude.

**Stage 1 (Setup):** Query existing confirmed gotchas for the directory and use them as positive examples. Call `mem_get("file:<path>")` to mint a consultation receipt and retrieve the `enrichment_depth_hint`: fast, standard, or deep. For the deep tier, also retrieve recently tombstoned gotchas as negative examples.

**Stage 2 (Enumeration):** Read the file. Extract gotcha candidates and rank them by signal tier:

- HIGH: WARNING/FIXME/HACK/SAFETY comments, `panic!` and `assert!` messages
- MEDIUM: defensive guards, non-obvious literals
- LOW: raw API usage

Specificity — specific, enforceable, non-obvious, causal — is drafting guidance here, not a filter. Stage 2 maximizes recall; filtering is deterministic and happens later.

**Stage 3 (Evidence verification):** One pass, every tier. Call `mati verify-evidence`, a deterministic CLI, to confirm that each candidate’s file line and quote are real. Discard the ones that fail. The CLI is the source of truth; there is no self-critique round and no re-run, because a repeat call on the same candidate returns the same verdict. It reads a ±5-line window, so it proves the citation is real, not that the rule follows from it — a rule whose claim spans more of the file than that window passes unverified.

**Stage 4 (Write):** For each verified candidate, tighten the rule and drop any that stays vague, verify causality language, assign severity, then call `mem_set`.

Severity classification works like this:

- Semantic pass sets the severity, using LLM judgment against the rubric: critical for data loss, corruption, security, unbounded growth; high for a wrong result, silent failure, race, or broken invariant; normal for performance and workflow blockers; low for everything informational.
- A deterministic keyword floor can only raise that verdict. “data loss”, “corrupt”, “security”, or “unbounded” floors at critical. “silent”, “race”, “wrong result”, or “lost” floors at high.
- Tag `severity-disputed` only when the floor raised the semantic verdict. An earlier design ran the keyword pass as a peer and tagged every disagreement, which fired on 69% of candidates because natural prose rarely contains the exact literals — the pass fell through to low and disagreed by default.

After batch enrichment, run `mati review` to confirm candidates and activate enforcement. Single-file enrichment confirms each gotcha immediately through `mati gotcha confirm <key>`.

---

## 15. Session Model

Sessions use three layers of state in `sessions.db`, with Eventual durability.

**During the session:**

Each `mem_get` call writes a consultation receipt: proof that the agent read the record for that key. The TTL is 15 minutes, set by `CONSULTED_RECENT_TTL_SECS = 900`.

The hook decision engine checks for that receipt before choosing between Deny and AlreadyConsulted. See section 10.1.

**Receipt scope.** The receipt key is `session:consulted:<actor>:<key>` when the hook payload carries an `agent_id`, and `session:consulted:<key>` when it does not. The actor is the agent, never the session: `cli::hook_decide::receipt_actor` takes `agent_id` and discards `session_id`, because the gate reads the global key on the main thread and scoping by session would mint receipts nothing ever checks. Lookup is strictly key-equal — there is no actor-to-global fallback in either direction. One subagent cannot ride another's receipt, a subagent cannot ride the main thread's, and the main thread cannot ride a subagent's. Pinned by `store::session::tests::gate_requires_actor_scoped_receipt_for_subagent` and `cli::hook_decide::tests::subagent_receipt_stays_actor_scoped`.

The `session:` prefix names the tree and the lifetime, not the scope. Receipts live in `sessions.db` and are wiped three times: at daemon startup, on PostCompact (compaction erases the agent's memory of what it read, so the receipt has to go with it), and at session end. They are not keyed by session id, so two agent sessions sharing a repo and a daemon share the main-thread receipt namespace until one of those sweeps runs.

**What may mint one.** Only a read. `mem_get` mints through the post-memget hook, and an allowlisted schema-introspection command mints through post-bash for policies that accept `DbIntrospection` (section 10a.5). Editing a file mints nothing: `FileEditHook` records edit activity and reparses, but a write is not evidence the agent saw the record, and minting there would let an edit that slipped through a fail-open suppress every later deny on that file.

**On session flush:**

`session:current` is written with the full list of consulted keys from `session:consulted:*` markers. This interim record is used by harvest if the session ends without an explicit flush.

**On session end (`session_harvest`):**

The harvester reads `session:current`, then writes a final `session:<timestamp>` record summarizing files touched, gotchas encountered, and compliance rate. It also cleans up all `session:consulted:*` markers and runs staleness re-scoring on touched files.

The most recent session summary is meant to appear in the `ContextPacket` returned by `mem_bootstrap` as `recent_session`. Right now that field is always `None` because the assembler is not wired yet. See section 6.

---

## 16. Search Layer

tantivy provides BM25 full-text search over the `value` field of all knowledge records. That field is the human-readable content: rule, purpose, body, and similar text.

The tantivy index lives next to the SurrealKV store under `~/.mati/<slug>/`.

It is rebuilt from the `knowledge.db` key scan in three cases:

- First startup after `mati init`, through the deferred indexing path
- Startup when the `search_stale` marker is present
- Startup when the `search_sync_pending` marker is present, for crash recovery

`mem_query mode="text"` runs a BM25 query and returns ranked records; `mode="tag"` filters by tag; `mode="graph"` traverses the petgraph edges from a starting node; `mode="semantic"` is gated behind `--features semantic`. The enforcement-telemetry modes (`policy_observations`, `policy_activity`, `analytics`) do not touch the index — they scan the store directly and are covered with the policy engine in section 10a.

---

## 17. Staleness

Staleness is scored with this formula:

```text
staleness =
  time_factor       x 0.20   (days since last confirmation)
  + git_factor      x 0.35   (commits since last confirmation)
  + semantic_factor x 0.25   (entry points, imports, unsafe, unwrap counts changed)
  + dep_factor      x 0.10   (dependency version bumps)
  + cascade_factor  x 0.10   (upstream decisions or gotchas changed)
```

`semantic_factor` is currently a `0.0` stub in `StalenessAnalyzer`, so that 0.25-weighted term contributes nothing for now. Full semantic-delta scoring is planned for v0.2. The entry-point/import/unsafe/unwrap delta detection described here currently runs only in the `mati reparse` path. The other four factors are live.

Hard overrides bypass the formula:

- `FileDeleted` signal: Tombstone (1.0)
- `FileRenamed` signal: Liability (0.85) until the path is corrected

Staleness tiers use half-open intervals.

| Tier      | Range      | Hook behavior                                                                      |
| --------- | ---------- | ------------------------------------------------------------------------------------- |
| Fresh     | [0.0, 0.2) | Normal injection                                                                   |
| Aging     | [0.2, 0.4) | Normal injection                                                                   |
| Stale     | [0.4, 0.7) | Injected with staleness warning                                                    |
| Liability | [0.7, 0.9) | Injection degrades to a warning to read the file directly; enforcement unaffected  |
| Tombstone | [0.9, 1.0] | Injection fully excluded; enforcement unaffected unless the file was deleted       |

At Tombstone, the file record's own content is excluded from injection — injecting a wrong purpose blurb silently is worse than a cache miss. That is an injection rule, not an enforcement one: a confirmed gotcha still denies at both Liability and Tombstone (section 10.1). The sole pass-through is the `FileDeleted` signal — the source file is gone, so there is nothing left to enforce — but it is not unconditional: the signal is a stale snapshot, cleared only by the staleness sweep, so a caller that confirms the path exists again (`file_exists: Some(true)`, section 10.1 step 2) is not bypassed on it.

The `mati reparse` path adds staleness per pass, capped at 0.4 per pass by `MAX_REPARSE_INCREMENT`. Across passes it saturates at `MAX_REPARSE_STALENESS` (0.69) — inside Stale, below the Liability floor. Reparse never lowers a value another factor set, and the 24h preservation window in `compute_staleness` holds a recent reparse score up only as far as the same ceiling. Without that bound, editing one file a few times in a session pushed the file record to Tombstone — before section 10.1's reorder, that silently disabled enforcement of every confirmed gotcha on the file, with no event logged. Enforcement is unaffected today (the gotcha loop runs ahead of the tier check); the ceiling still matters because Tombstone still suppresses injection, and a file edited a lot in one session was never abandoned. The other four factors reach Liability on their own but cannot reach Tombstone: with `semantic_factor` stubbed, their combined maximum is 0.75. Only the `FileDeleted` override reaches Tombstone; `FileRenamed` stops at Liability.

`StalenessAnalyzer::analyze_all` runs on the SessionEnd harvest, so it is bounded by `ANALYZE_TIME_BUDGET_MS` (2000). That budget sits close to its ceiling already: the hook's own timeout is 4 seconds, and process spawn, the socket round trip, and the rest of the harvest account for roughly another 300ms — more on a cold binary, where startup alone is ~1s. Raising it means raising the scaffold timeout too; the scan has to be fair inside it. SessionEnd also has no equivalent of `HOOK_DEADLINE_MS`, so unlike the read gate it degrades by being killed rather than by failing open on its own terms.

The scan walks `STALENESS_PREFIXES` in order and each prefix in key order, so an expiring budget always expires in the same place — inside `file:`, the largest prefix and the only one paying git cost. `gotcha:`, `decision:`, `dep:` and `dev_note:` sit behind it and recompute only on a pass that happens to finish `file:` — luck, not a bound. A truncated pass therefore parks its position in `health:staleness_cursor` (Eventual durability — derived scheduling state, recomputable) and the next pass resumes there, so coverage advances every harvest instead of restarting. A pass that reaches the end clears the cursor. Every cursor operation is best-effort: a lost or unreadable cursor restarts the sweep at `file:`, which is exactly the behaviour that preceded it.

The budget bounds when the scan *starts* a record, not how long one takes. A single `count_commits_since` revwalk can run to `GIT_REVWALK_LIMIT` (2000 commits), so a pass can overshoot the budget by one record's cost — measured at up to ~800ms on a 493-commit repo. Bounding per-record git cost is the open follow-up.

A pass that newly tombstones more than `MAX_TOMBSTONE_RATIO` (0.5) of what it scanned is discarded whole: nothing is written, the cursor stays put, and the report returns zeros so it still describes persisted reality. Passes under `MIN_TOMBSTONE_SAMPLE` (20) records skip the check, since at that size a genuine cleanup and a broken pass are the same shape. The whole pass is discarded rather than the deletions alone, because a root that cannot be trusted for an existence check cannot be trusted for the git factor either.

The shape it guards against is reproducible: a daemon whose CWD sits inside a submodule opens the parent's store while resolving record paths against the child's tree, and tombstones every record — 43 of 43, measured against a shipped 0.1.3 binary. The grounding check in `open_at` (below) is the real fix for that; the ratio is the backstop for whatever else produces the same signature.

The ratio is deliberately blunt, and it has a known false positive: a store already carrying records keyed to the wrong root will tombstone most of them on the first pass that notices, which is *correct* cleanup that the ratio will nonetheless discard. That happened on this repo — a `mati init` rooted at `tests/fixtures/real_world/hcl` wrote 365 fixture-relative `file:` records into mati's own store, and the 2026-08-04 pass that tombstoned 368 of 387 was right to do so. Discarding a correct cleanup costs a stale metric; permitting a wrong one switches injection off repo-wide. The asymmetry is the argument for erring loud.

Sync merge rule, planned for v0.2: `Tombstone > Liability > Stale > Aging > Fresh`, meaning higher severity wins. There is no sync or conflict resolution in v0.1.

Staleness propagation happens during `mati init`. Staleness scores are propagated through `Imports` edges. A file whose upstream dependency has high staleness inherits partial staleness through `propagated_staleness` in `FileRecord`.

### 17.1 Content drift

Staleness answers *how old* a record is. Content drift answers a different
question: has the code this rule describes changed since a human last confirmed
the rule? A stale gotcha is dusty; a drifted one may be wrong.

The confirm paths (`gotcha_ops::apply_gotcha_confirm` for direct-store runs,
`mcp::handlers::handle_gotcha_confirm` for the daemon) stamp
`GotchaRecord.confirmed_content` with the SHA-256 each affected file hashes to
**on disk**. A gotcha is drifted when a stamped path hashes differently later.
Both sides read the working tree, never the `file:*` index: the index refreshes
only on a rescan, so stamping from it would baseline a developer who edits a
file and then confirms against the pre-edit code, and report drift the human
already resolved. `health::drift::disk_content_hashes` hashes only the files a
confirmed, stamped gotcha names — a few hundred at most — and
`detect_drift` stays a pure comparison over that map.

Drift is **reported, never enforced**. It is not a `StalenessSignal` and carries
no weight in the formula above, deliberately:

- A drifted gotcha's own staleness feeds `cascade_factor` on every file that
  links it. Weight added here would raise that factor and could push a
  linked file's tier into `Liability` or `Tombstone`, which degrades what
  `hooks::decide::evaluate` injects for it (section 10.1) even though the
  gotcha itself keeps denying — the gotcha loop runs ahead of the tier
  checks, so enforcement is unaffected, but the linked files' context would
  go dark for a fact that says nothing about them.
- `StalenessAnalyzer::compute_staleness` rebuilds `staleness.signals` on every
  pass, so a drift signal parked there would be erased by the next `mati init`.

A drifted gotcha keeps denying reads. Re-confirming (`mati gotcha confirm
<key>`) re-stamps against the current content and clears the drift; that is the
curation loop. `mati stale` lists drifted gotchas in their own block, and
`mati doctor`'s `knowledge/freshness` check appends the count.

Absence of a digest on either side — a record confirmed before the field
existed, a glob entry, a path with nothing readable on disk — reads as
*unknown*, never as drifted. A deleted file is the staleness analyzer's
`FileDeleted` signal, not drift.

---

## 18. Enforcement Event Log

Every hook decision is recorded in a hash-chained, monotonically sequenced event log. The log is persisted in `knowledge.db` under keys like this:

```text
enforcement:event:<seq_no>
```

**Chain structure:**

- Each event carries a SHA-256 `event_hash` of its own canonical serialization.
- Each event carries `prev_hash`, which is the `event_hash` of the immediately preceding event. The first event uses an empty string.
- `seq_no` is globally unique, monotonically increasing, and persisted before the event that uses it.
- Gaps in `seq_no` are acceptable after a crash — a seq is persisted before the event that uses it, so a crash in between leaves a hole. Nothing detects a seq hole today; `RecordingGap` is written on a time gap instead (section 18.1). Hash chain breaks indicate tampering or corruption.
- The canonical form is frozen per `schema_version`. `SCHEMA_VERSION` is 2 (v2 appends `agent_session`); v1 events still hash under the original 14-field form (the v2 `CanonicalEvent` serializes 15 fields). Do not change field order or serialization without incrementing the version — every stored hash would recompute differently and the chain would read as tampered.

There are 9 event types:

| Event                      | Trigger                                                                                                          |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `Deny`                     | A pre hook blocked an unconsulted access — Claude read or edit, or a Codex shell read or `apply_patch`           |
| `AllowAfterReceipt`        | Pre-read hook allowed a read because a valid consultation receipt exists                                         |
| `ReceiptMinted`            | A one-time-use read receipt was created by `mem_get`                                                             |
| `BypassDetected`           | A hook bypass was detected after the fact — `codex-post-bash`, or the `FileDeleted` tombstone bypass suppressing a would-have-denied gotcha; nothing was denied |
| `ControlChanged`           | A gotcha was created, confirmed, updated, or deleted                                                             |
| `EnforcementConfigChanged` | A configuration setting changed. Records old and new value.                                                      |
| `RecordingGap`             | The event log was quiet for longer than `STARTUP_GAP_THRESHOLD_MS` when the daemon came up. Records the window, cause, enforcement mode during the gap, and certainty. Written by `mati daemon start` (section 18.1) |
| `RetentionPruned`          | An oldest-first prefix of the event log was deleted past `enforcement.retention`. Records the count and the seq range. Written by `mati repair`'s full scan, after the deletion |
| `CleanShutdown`            | The daemon exited gracefully. Records the shutdown reason. Written by `mati daemon start` as the last event of its run, after the drain and before the store closes (section 18.2) |

Each event also carries:

```text
installation_id
actor_local
agent_type
subject_kind
subject_key
canonical_subject_hash
receipt_id
decision_reason_code
decision_basis_hash
agent_session
```

`installation_id` is the stable UUID generated at `mati init`. `actor_local` includes OS username and uid, and is explicitly labeled unverified. `decision_basis_hash` is the SHA-256 of the gotcha state in force at decision time — key, rule text, and confidence per gotcha, sorted by key. It is computed hook-side, where the decision is made, and only ever holds a digest of stored knowledge, never the command or tool input that triggered the gate.

`receipt_id` is the `ConsultationReceipt::id` minted with the receipt: `ReceiptMinted` carries the id it minted, and the `AllowAfterReceipt` that receipt later authorizes carries the same one. `agent_session` is the Claude Code `session_id`, added in schema_version 2. Both are absent where the emitter has neither: an MCP `mem_get` carries no session id, and a deny has no receipt.

All three are optional and were part of the v2 canonical layout before anything wrote them, so filling them in needs no schema bump — an event written when they were null still hashes under the layout it recorded, and both eras verify in one chain.

The enforcement event log is local and owned by the developer. The enterprise tier reads it to generate signed audit artifacts. It does not add events to the log.

### 18.1 Recording gaps

Only a running daemon writes enforcement events. Every window in which no daemon ran — a crash, `mati daemon stop`, a wedge, an ordinary P9 fail-open — is a window the log says nothing about. A signed artifact asserting completeness over such a window is a false attestation, so the gap has to be in the log.

`detect_startup_gap` (`src/store/enforcement/retention.rs`) runs on `mati daemon start`, right after the store opens and before the graph loads. It compares the newest event's `recorded_at_ms` against the wall clock and writes a `RecordingGap` when the difference exceeds `STARTUP_GAP_THRESHOLD_MS`. Until this was wired up, `RecordingGap` was never written in production at all.

- **Threshold: 24 hours.** The daemon idles out after `IDLE_SHUTDOWN_SECS` (30 min), so every restart after a break already looks like 30+ minutes of silence. A shorter threshold records a gap on an overnight break, and a log of those buries the outages worth finding. A day of silence on an active repo is worth a reviewer's eye; on a dormant repo it costs one event per dormant period, not one per restart. The tradeoff is under-reporting, and it now applies only to logs with no terminator in them: there, a three-hour crash mid-workday still writes nothing. Past that point the threshold governs the explained case only (section 18.2).
- **Cause is `Unknown` unless a terminator licenses better, certainty is `Inferred`, missed count is `Unknown`.** What the event asserts on its own is "no enforcement event was written between T1 and T2", which is equally true of a crash and of a quiet weekend. In a log with no `CleanShutdown` in it, nothing tells them apart and no other `GapCause` can be claimed honestly. In a log that has one, absence of a terminator at the tail is a crash, and the cause is `UncleanShutdown` (section 18.2).
- **The mode is read, not assumed.** `enforcement_mode_during_gap` is `get_enforcement_mode` at gap end. Changing the mode writes an `EnforcementConfigChanged` event, and a gap is by definition a window with no event in it, so the mode read at gap end is the mode that held across the window. The one hole is a change whose event write failed, which advisory mode swallows. Reconstructing the mode from the log instead would mean scanning back to the last `EnforcementConfigChanged` — and most stores have none, so the common case is the full scan the tail read exists to avoid.
- **Reads the tail, not the chain.** One `scan_keys` plus one `get_raw_bytes` on the newest key. Measured on a 3161-event store: 0.35ms, against 9–20ms for the full `scan_enforcement_events` it used to run. This sits on the cold-start path that `ensure_daemon` blocks every hook on, and the log is unbounded. The one exception is the terminator backscan, which is why it is gated to the path where the tail is not a terminator (section 18.2).
- **Best-effort.** A failure is logged to `daemon.log` and startup continues. A daemon that refuses to start because it could not write an audit event is strictly worse than the missing event (P9).

Not addressed: nothing detects a `seq_no` hole. Correlating the gap against `lifecycle.log` would narrow the cause, and is rejected — see 18.2.

### 18.2 Shutdown terminator

The 24-hour threshold buys quiet at the cost of coverage, and every gap it writes says `GapCause::Unknown`. Both follow from the same hole: the log records what the daemon did while running, never how it stopped. A clean stop and a crash leave the same silence, so the threshold has to be set high enough that ordinary stops do not drown the crashes, which is exactly what lets a three-hour mid-workday crash write nothing.

**Decision: the daemon writes a terminator event on every graceful exit.** A start that finds a terminator at the tail knows the quiet window is explained, at any duration. A start that finds an ordinary event at the tail knows the daemon died. Absence is the crash signal, and that is what makes the design cheap: a dying daemon cannot be relied on to report anything, so it is never asked to.

Consequences:

- **The threshold drops out for terminated logs.** A weekend of silence behind a terminator needs no `RecordingGap` at all, and a three-hour crash writes one. Coverage and noise stop trading against each other.
- **The cause comes from the chain.** Absence of a terminator is a crash claim grounded in hashed, append-only evidence rather than in a side file. `missed_event_count` stays `Unknown` — a dead daemon counts nothing — and certainty stays `Inferred`, because the gap start is still the last recorded event's timestamp, not the moment the process died.
- **The clean window needs no `RecordingGap` of its own.** The terminator marks where recording stopped and the next event marks where it resumed, both in the chain. A reader can bound the window from the log alone, which is all the gap event ever provided — plus a cause it could not state.
- **The 24-hour threshold survives as the fallback for pre-terminator logs.** No store in the field has terminators, so "no terminator at the tail" cannot mean "crashed" until the log is known to be from a writer that emits them. `detect_startup_gap` resolves that from the chain, not from a flag: if the tail is a terminator, take the cheap path; otherwise scan back for one. Finding a terminator establishes the era, so the absence at the tail is a crash. Finding none means a pre-change log, and the 24-hour threshold with `GapCause::Unknown` applies exactly as it does today. The backscan is the full read this function was written to avoid, so it is gated to the path where the tail is not a terminator — once per store at upgrade, and once per genuine crash. A healthy store never pays it.
- **Retention can prune the era away.** `enforce_retention` deletes an oldest-first prefix, so a log whose only terminators fall inside it reverts to `GapCause::Unknown` under the threshold until the next clean stop writes a fresh one. It under-claims rather than over-claims, so it is left alone.
- **`mati daemon stop --force` records an unexplained gap.** It SIGKILLs. Not worth suppressing: force-killing a wedged daemon *is* an enforcement outage and should read as one.
- **Cost: two additive enum variants, no `SCHEMA_VERSION` bump.** The canonical form holds `event_type` as one opaque serialized field, so a new `EnforcementEventType` variant changes no field order and no layout — v1 and v2 events keep byte-identical hashes with no v3 branch to write. `GapCause` gains `UncleanShutdown` on the same argument. The compatibility cost is real but unavoidable and unrelated to the version number: an older binary cannot deserialize either variant, so it reports the event as `UnknownSchema` and its `is_valid()` returns false. Downgrading past this change makes a sound chain read as unverifiable.

**Rejected: narrowing `GapCause` from `lifecycle.log`.** The principle is that an unsigned local source never substantiates a hashed audit claim. `lifecycle.log` is plain text, appendable by any process on the machine, trimmed by line count with no age filter, and wiped unread above 64MB. It corroborates for a human reading two files side by side. It does not populate a chain field.

Two objections were tested against the code and refuted:

- **"A new event type makes older binaries report tampering."** It does not. An unknown enum variant fails whole-`EnforcementEvent` deserialization exactly like corrupt bytes: the seq lands in `skipped_seqs` and reports as `ChainBreakKind::UnknownSchema`, never `Tampered`. That path is the same one every `schema_version` newer than the reading binary already takes.
- **"`mati daemon stop` could write the terminator on the daemon's behalf."** It cannot. The daemon holds the SurrealKV lock for as long as it is alive, and `StoreProxy` refuses a direct open while `daemon_pid_alive` is true. Before the kill there is no writer but the daemon; after it, no process has standing to certify that another process's exit was clean.

Feasibility is established. The store is open and writable on all five graceful shutdown paths (`signal_sigint`, `signal_sigterm`, `signal_sighup`, `idle_timeout`, `serve_loop_exit`): `run_daemon_start` records `serve_shutdown` to `lifecycle.log` before it reclaims and closes the store, so a terminator write fits in the same window. `EnforcementEventWriter::detect_and_record_gap` already takes an arbitrary `GapCause`; `gap_detection_on_recovery` passes `DaemonUnreachable` through it today.

Measured on one macOS machine, throwaway `MATI_HOME`, socket bind and ping verified before each trial, daemon idle:

| Measurement                            | Result                                     |
| -------------------------------------- | ------------------------------------------ |
| SIGTERM to process exit                | 93ms (7 trials, 91.8–94.3ms)               |
| `serve_shutdown reason=signal_sigterm` | landed 7/7                                 |
| One fsync'd enforcement write          | 5.9–9.8ms, median 8.0ms (30 samples)       |
| Smallest grace period that sufficed    | 1s — every trial finished unaided          |

The 5s `DRAIN_TIMEOUT` and its 1s abort grace in `serve_loop_graceful` engage only with handlers in flight, so they contributed roughly 0ms to every trial above. That is also the limit of the measurement: the busy case is unmeasured. A daemon draining a live handler can approach 6s before it reaches the terminator write and may be killed first, producing a false gap. That fails in the safe direction — a missing terminator over-reports a crash, it never hides one — but it adds noise. Two related unknowns: macOS's grace period on logout or restart is not established from a primary source (`man 5 launchd.plist` says `ExitTimeOut` defaults to "system-defined", and the generated plist does not set it), and every number here comes from one machine, one disk, one idle system.

**Ordering: the terminator is written after the drain**, in `run_daemon_start`, alongside the `serve_shutdown` lifecycle record and before the store is reclaimed and closed. The alternative — writing it before the drain, to shrink the window in which the process can be killed first — is unsound. `serve_loop_graceful` stops accepting once shutdown is signaled, but in-flight handlers keep running, and a handler serving a `mem_get` or a hook decision writes enforcement events. Those land after the terminator and leave an ordinary event at the tail, so the next start reads a clean stop as a crash. Worse, the terminator itself becomes false: it claims recording stopped at a point that recording demonstrably continued past.

The cost of writing after the drain is bounded and fails in the safe direction. The drain ceiling is 5s plus a 1s abort grace, then the write costs ~8ms. A process killed inside that window writes no terminator and is read as a crash, which is the same outcome as a real crash and never the reverse. A false crash report is noise; a false clean-stop report is a false attestation.

---

## 19. CLI

All CLI commands write to stdout using `comfy-table` for structured output. There is no TUI framework.

| Command                            | Description                                                                                                                        |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `mati init`                        | Layer 0 scan and project scaffold                                                                                                  |
| `mati enrich [path]`               | Layer 1 enrichment through Claude                                                                                                  |
| `mati suggest`                     | Propose gotcha candidates from existing repo artifacts (CODEOWNERS, markers)                                                        |
| `mati gotcha add`                  | Add a gotcha interactively                                                                                                         |
| `mati gotcha confirm <key>`        | Confirm a candidate and activate enforcement                                                                                       |
| `mati note <text>`                 | Add a quick developer note                                                                                                          |
| `mati review`                      | Batch confirm or tombstone candidates                                                                                              |
| `mati status`                      | Knowledge health dashboard                                                                                                         |
| `mati stats`                       | Coverage and onboarding score                                                                                                      |
| `mati gaps`                        | Files with no records or low confidence                                                                                            |
| `mati stale`                       | Records that have not been touched since a file changed                                                                            |
| `mati explain <file>`              | File briefing: gotchas, blast radius, co-change partners, cluster membership                                                       |
| `mati search <query>`              | Keyword search across gotchas, decisions, notes, and files                                                                         |
| `mati clusters`                    | Co-change clusters from git history                                                                                                |
| `mati diff [range]`                | Pre-merge check: surface gotchas for files in a git diff range, such as `main..feature`                                            |
| `mati show <key>` / `mati ls`      | Browse records. `mati history` is an alias for time-ordered listing.                                                               |
| `mati repair`                      | Reconcile derived indexes against canonical records, and prune enforcement events past `enforcement.retention` (section 25.3)       |
| `mati repair --check`              | Detect index drift without writing. CI-safe, exits non-zero. Also counts orphaned file records (section 22).                       |
| `mati repair --fast`               | Drain dirty-marker queue only. Not a full integrity proof.                                                                         |
| `mati repair --purge-orphans`      | Tombstone file records whose path is no longer in the repo (section 22)                                                            |
| `mati doctor`                      | Aggregated health check and CI gate command                                                                                        |
| `mati quality-check`               | List records by quality tier                                                                                                        |
| `mati improve <key>`               | Re-open a record for improvement                                                                                                    |
| `mati eval`                        | Run the enforcement regression corpus: detection/decision recall + false-positive rate against a baseline                          |
| `mati verify-chain`                | Verify the enforcement audit chain — recompute every event hash and check `prev_hash` linkage. Exits non-zero on any break.        |
| `mati policy <sub>`                | Author and manage local repository policies (add/edit/list/stage/enable/disable/test) and verify signed policy-floor bundles       |
| `mati serve [--path <dir>]`        | Run as MCP stdio server for Claude/Codex agent integration. `--path` sets the project root when the host cwd differs.              |
| `mati daemon start/stop/status`    | Manage the background daemon                                                                                                       |
| `mati ping [--daemon-only]`        | Check daemon reachability and latency                                                                                              |
| `mati check`                       | Environment self-test                                                                                                              |
| `mati hooks`                       | Install pre-read and pre-bash hooks into `.claude/settings.json`, with `--claude` / `--codex` flags                                |
| `mati sandbox <file>`              | Compile Claude denies / prepare Codex entries for a file                                                                            |
| `mati verify-evidence`             | Verify a candidate gotcha's evidence quote and pattern (`/mati-enrich` Stage 3). Outputs JSON.                                      |
| `mati extract-signals`             | Extract enrichment signals from a source file via tree-sitter (`/mati-enrich` Stage 1). Outputs JSON.                              |
| `mati import <file>`               | Import records from a file. The `--pack` compliance-pack loader is planned/enterprise and is not in this repo.                     |
| `mati export`                      | Export knowledge records                                                                                                           |
| `mati enable-semantic` _(planned)_ | Not implemented as a subcommand yet. The semantic/vector search layer is currently a build-time opt-in with `--features semantic`. |
| `mati config`                      | Show or update runtime configuration                                                                                               |
| `mati supervisor`                  | Generate a launchd or systemd unit for the daemon                                                                                  |

`mati reparse <file>` exists but is hidden from `--help` (internal; the daemon
re-parses changed files automatically). Other internal, hidden subcommands
(`hook-decide`, `session-*`, `log-*`, `subagent-context`, `watch-paths`,
`prompt-context`, …) back the hook scripts and are not part of the user CLI.

Color semantics:

| Color            | Meaning                             |
| ---------------- | ----------------------------------- |
| Red `#f85149`    | Critical errors, blocked saves      |
| Yellow `#d29922` | Warnings, stale, low confidence     |
| Green `#3fb950`  | Success, confirmed, healthy         |
| Blue `#58a6ff`   | Informational, section headers      |
| Purple `#bc8cff` | Decisions, architectural items      |
| Gray `#8b949e`   | Metadata, timestamps, internal keys |
| Cyan `#39d353`   | File paths                          |
| White `#e6edf3`  | Primary content                     |

`mati doctor` is the CI gate command. It runs all health checks and exits non-zero on any failure. `mati repair --check` detects index drift without writing and is also CI-safe.

---

## 20. Versioning (Lamport Clock)

Each record carries a `RecordVersion`.

```rust
pub struct RecordVersion {
    pub device_id: DeviceId,  // UUID v7, stable per user+machine (~/.mati/device_id)
    pub logical_clock: u64,   // Lamport clock, incremented on every local write
    pub wall_clock: u64,      // Display only, never used for conflict ordering
}
```

Wall clock is display-only. It is never used for conflict ordering. Ordering uses `logical_clock`.

The intended conflict-resolution rule is simple: when two writes conflict, meaning the same key from different devices, the higher `logical_clock` wins. That rule is not implemented in v0.1. There is no sync path and no `MergeEngine`, so conflict resolution does not run yet.

`DeviceId` is a UUID v7 generated once on first use and persisted at `~/.mati/device_id` (`store::device::stable_device_id`, first-writer-wins on concurrent creation, self-repairing on corruption, process-lifetime fallback if the home directory is unavailable). Every production record write stamps it. Records written by older binaries carry the historical per-record v4 placeholders; the `MergeEngine` (v0.2) must treat those as attribution-unknown rather than as distinct devices.

---

## 21. Durability

Write durability is split by key namespace. Do not mix the paths.

**Immediate, fsync before commit:**

```text
gotcha:*
decision:*
file:*
stage:*
dev_note:*
dep:*
policy:*             (default, not in SESSION_NAMESPACES)
enforcement:event:*  (default, not in SESSION_NAMESPACES)
```

`policy:*` and `enforcement:event:*` reach Immediate through the unknown-prefix
default, not an explicit branch. If an explicit `policy:` branch is ever added,
it must stay Immediate.

**Eventual, OS write buffer:**

```text
session:*
analytics:*
hook_event:*
compliance:*
graph:edge:*
health:*
parse:*
audit:session:*
```

The rationale is practical. Knowledge records, such as gotchas, files, and decisions, must survive crashes. A partially written gotcha with no file link is worse than no gotcha. Session and analytics records are reconstructible or disposable.

---

## 22. Gotcha Mutations

All gotcha create, edit, and tombstone paths go through `store::gotcha_ops`. A direct write to a gotcha record that bypasses this module is a bug.

**Write order, partially atomic:**

1. Write the canonical `gotcha:<slug>` record. This fails hard. If this step fails, nothing else is attempted.
2. Update the `file:*` record’s `gotcha_keys` list. Best effort; failure sets a dirty marker.
3. Write the `HasGotcha` graph edge. Best effort; failure sets a dirty marker.

The canonical `gotcha:*` record is the source of truth. `file:*` `gotcha_keys` and `HasGotcha` graph edges are derived indexes.

The daemon's v2 protocol handlers (`mcp::handlers`) are the exception to the rule above: they stage the gotcha record, the file-link updates, and the audit entry in a single atomic `transact_knowledge` call rather than calling `gotcha_ops`. Anything `gotcha_ops` enforces at write time has to be mirrored there — `handle_gotcha_upsert` carries its own copy. It is reachable from both the MCP `mem_set` tool and `StoreProxy`'s `Socket` arm (`mati gotcha` CLI commands, when a daemon owns the store).

The second live write path is `StoreProxy`'s `Direct` arm, used only when no daemon owns the store: `gotcha_write` calls `gotcha_ops::apply_gotcha_write` directly, so there is no duplicate validation to keep in sync. The two paths still diverge on tombstone handling: `handle_gotcha_upsert` treats an existing `Tombstoned` record as `is_new` and forces `lifecycle: Active`, reviving it. `apply_gotcha_write` never inspects or resets `lifecycle` — it persists whatever the caller passed in. A `Direct`-mode edit of a tombstoned key therefore reports success but leaves the record invisible to `mem_get` and the hook gate, unlike the same edit over a daemon socket.

(`apply_mem_set_write` / `apply_mem_set_confirm` / `apply_mem_set_delete`, formerly in `mcp::handlers` behind `handle_mem_set`, were unreachable from the wire protocol — the daemon connection handler is v2-only and no `Command` variant ever produced the "mem_set" v1 op string — and have been removed. `invariants.rs` no longer lists them.)

**Reviving a tombstoned gotcha:**

A `mem_set` write to a tombstoned `gotcha:<slug>` key revives it as `Active`, with `confirmed` reset to `false` and `confirmation_count` reset to 0 (deliberate: commit `b0eac6d`, "mem_set revives tombstoned records on write"). Re-adding a previously deleted gotcha is a supported workflow, not an accident — a plain write is not distinguished from a fresh create in its response, and it does not log that the key was previously tombstoned. Because `mem_set` writes always land unconfirmed (P4 — only a developer-sourced action can assert confirmation), a revived record cannot deny a read until a developer runs `mati gotcha confirm` again. `confirm`, by contrast, explicitly rejects a `Tombstoned` key with an error (commit `eca993e`) — a deleted gotcha cannot be silently reactivated without going through `write` first.

**Path normalization:**

`affected_files` joins to `file:<rel_path>` by exact string equality, and the read gate normalizes its side with `hooks::decide::normalize_path`. Every write path normalizes with the same function and against an explicit `RepoIdent::slug_root` — never the process cwd — so `./src/a.rs`, an absolute path inside the repo, and `src//a.rs` all store as `src/a.rs`. Globs such as `src/payments/**` pass through untouched. A write that stores a path the gate would never produce is a silent non-enforcement bug, not a cosmetic one.

The root is a parameter (`gotcha_ops::normalize_affected_files(files, repo_root)`), threaded from the same place the caller's other root-relative work resolves: `ctx.repo_root` in the daemon handlers, `StoreProxy::repo_root()` in the CLI, `slug_root` in `mati repair`. It used to be discovered from the process cwd while `confirm_content_stamp` took a threaded root, and when the two disagreed the record came out confirmed, enforcing, and permanently drift-blind — the stamp joined a root the path was not keyed to, and read nothing. Sharing one root makes that agreement structural.

**Recovery:**

- `mati repair` re-keys `affected_files` that are not in normalized form, then rebuilds derived state from canonical records and verifies consistency.
- `mati repair --check` detects drift without writing. It is CI-ready and exits non-zero on drift.
- `mati repair --fast` drains only the dirty-marker queue. It is not a full integrity proof, and it does not scan for unnormalized paths.
- `mati status` surfaces dirty-state warnings when drift is detected.

If `gotcha_keys` and `HasGotcha` graph edges disagree with the canonical `gotcha:*` record’s `affected_files`, the gotcha record wins.

**Orphaned file records:**

A `file:*` record whose path is no longer in the repo is not drift — the derived indexes agree with the canonical records, the file is simply gone. Nothing removed them before, so they accumulated: this repo's own store reached 856 active `file:*` records of which 412 (48%) pointed at paths that do not exist, most of them a second repository that a `src/bin/bench_real` run indexed into it. Every one inflates the coverage denominators in `mati stats` and `mati doctor`, which `retain(Active)` their file scan.

`mati repair`'s full scan and `--check` now count them (`find_orphaned_files`, `src/store/repair.rs`), split by what the path means:

| Kind | What it is |
|------|------------|
| `outside_repo` | Absolute, escapes the root, or sits under a top-level directory this repo does not have. Another tree's paths. |
| `deleted_in_repo` | Repo-relative and plausible, but gone from the working tree. This project's own history. |

Removal is opt-in and deliberately narrow, because a wrong repo root would destroy the store:

- **Reported by default, removed only by `--purge-orphans`.** `--check` returns before the write path and `--fast` runs `RepairMode::Fast`, so neither touches them. The flag `conflicts_with` both.
- **One root, and it is `slug_root`.** Paths resolve against `RepoIdent::slug_root` — git's own `workdir`, the same field the store's slug hashes and the same root `StalenessAnalyzer`, `StoreProxy` and `mati init` resolve against. Not the process cwd.
- **No git working tree, no purge.** The purge bails when `RepoIdent::workdir` is `None`, the same grounding `StalenessAnalyzer` requires before it asserts `FileDeleted`. Without a real working tree, "the file is missing" cannot be told from "the root is wrong".
- **Mass-tombstone guard.** It refuses when orphans exceed `ORPHAN_PURGE_MAX_SHARE` (90%) of active `file:*` records. A root naming the wrong tree fails *every* path, so the wrong-root signature is ~100%; the worst rate measured on a real store is the 48% above. 90% sits between them.
- **Above that share, `--check` says re-init, not purge.** The same threshold means the store's keys no longer describe this tree — an `init --path <subdir>` from before the root fix, a store shared with a foreign checkout, a wholesale rename. The three are indistinguishable from the orphan set alone, so the message names the condition, not the cause, and points at `mati init`. Proving specifically that the keys are subtree-relative — a single directory prefix that rescues every orphan — needs a repo walk and is not built. Orphans still are not drift, so the exit code does not change.
- **Soft delete.** The record is tombstoned with `TombstoneReason::FileDeleted`, not deleted, and its `gotcha_keys` and `HasGotcha` edges are dropped. The gotchas themselves are untouched, still naming the path in `affected_files`. `derive_desired_state` drops link targets whose file record is tombstoned — the mirror of it skipping tombstoned gotchas as link sources — so a purged orphan does not read as missing-link drift on the next check.

---

## 23. Daemon Lifecycle

The daemon writes structured events to `lifecycle.log` throughout its lifetime. `ensure_daemon`, in `src/mcp/daemon_lifecycle.rs`, reads that log to determine readiness. It does not use timer-based polling.

Daemon lifecycle phases:

```text
startup phase=opening_store
startup phase=store_opened
startup phase=ready
```

The serve proxy logs `startup phase=ensure_daemon` before spawning the daemon. Then it logs its own `startup phase=ready` once the proxy is accepting MCP traffic. `serve_failed` is logged on any fatal error in either process.

The daemon registers a `panic_hook` that writes a `panic` event before unwinding. Handled fatal errors write `serve_failed` instead, which `ensure_daemon` maps to `Failed`. This lets `ensure_daemon` distinguish a daemon that died from one that is merely wedged.

Unix socket path:

```text
~/.mati/<slug>/mati.sock
```

Peer credentials are checked through `SO_PEERCRED` on Linux and `LOCAL_PEERCRED` on macOS, via tokio’s `peer_cred()`. The daemon accepts only connections from the same UID. This same-UID check is the primary access control mechanism for the socket.

---

## 24. Known Limitations

**C9: bash `cat` bypass, around 2-5% miss rate.**

`pre-bash.sh` catches `cat <file>`, but not every variant. Variable expansion (`cat "$FILE"`), process substitution, piped input, and unusual quoting are not caught. This is known and accepted. The compliance monitor tracks and reports it. Do not chase 100% coverage here; the false positives are not worth the marginal gain.

**In-repo symlink access resolves to the real target for enforcement (WI-20).**

A gotcha is keyed by the lexical repo-relative path, so an agent could route around the gate by reading or editing a gotcha'd file through a symlink whose key differs. The read/edit decision path — including Codex `apply_patch` patch targets — adds an escalate-only canonical-key fallback: when the lexical gate does not deny, it resolves the accessed path through symlinks (shared with the L3 sandbox's `canonicalize_lenient`), strips the canonicalized repo root, and evaluates the real target's key too — adopting that result only when it denies. It is fully fail-open (no repo root, a `canonicalize` failure, an out-of-repo target, or an identical key all leave the lexical decision intact) and costs one extra `realpath` plus one daemon round-trip, only on the non-deny path. This closes the in-repo symlink bypass at the hook level (L1). It does not change the lexical store key. Hardlink aliases (which `canonicalize` does not resolve) and out-of-tree targets remain out of scope for the hook tier; the L3 OS floor (`mati sandbox`) is what denies crown-jewel files across the shell and its subprocesses.

**petgraph is in-memory only.**

Edges are loaded from SurrealKV at daemon startup through a full `graph:edge:*` key scan. Every mutation must write back to SurrealKV immediately. If an edge is not written to SurrealKV, it is gone after restart.

**tree-sitter grammar crates must be ABI-compatible with the parser runtime.**

Each grammar must expose an ABI compatible with `tree-sitter = "0.23"`. It does not need to use the exact same crate version. Most grammars pin to `"0.23"`, for example `tree-sitter-rust = "0.23"`, while some compatible grammars use another crate version, such as `tree-sitter-elixir = "0.3"`. An ABI-incompatible grammar causes silent parse failures, not errors or panics.

**`mati repair --fast` is not a full integrity guarantee.**

It only drains the dirty-marker queue: gotcha keys explicitly flagged during a partial-write failure. It cannot detect drift caused by manual store edits, bugs in other write paths, or failures that were never flagged. Use full `mati repair` for authoritative verification.

**`confirmed: false` records are Layer 0 stubs.**

They exist as graph nodes and gap signals, but they are never injected into hooks or `mem_bootstrap` critical paths. A `confirmed: false` record with `confidence >= 0.6` still does not trigger enforcement. `confirmed` is checked first.

**The hook fast-path checks daemon reachability before enforcing.**

It calls `ensure_daemon`, which pings the daemon internally, instead of invoking `mati ping` directly. If the daemon is unreachable, hooks pass through unconditionally, per P9.

mati sets an internal deadline of 2,500ms with `HOOK_DEADLINE_MS`, inside a 4-second hook timeout. Do not add blocking I/O to the hook fast-path if it could exceed that budget.

The 4 seconds is mati's own budget, not a platform limit. Claude Code's `timeout` field is in seconds and defaults to 600 for command hooks; `src/scaffold/settings.rs` writes `"timeout": 4` on the three blocking `PreToolUse` hooks and on `SessionEnd`. It exists because `HOOK_DEADLINE_MS` is a `tokio::time::timeout`, which can only fire at an await point — a blocking call outside one would otherwise run unbounded. The scaffold timeout is the backstop for that case.

The 1,500ms between the two numbers is sized, not spare. `HOOK_DEADLINE_MS` starts counting inside `run()`, so process spawn, dynamic linking, and runtime init all elapse before it: measured at ~115ms with the binary in the page cache and ~1,050ms without, which is the first call after an install or a reboot. At a 3-second ceiling that cold case put the internal deadline at ~3.5s — past the ceiling, so the host killed the process before it could write the fail-open entry the deadline exists to produce, losing the evidence in exactly the case worth observing. Changing either number without the other breaks that relationship, and nothing currently enforces it.

**`with_versioning(true, 0)` on `knowledge.db` means indefinite retention.**

The `0` argument is not “disabled.” It means retain all versions forever. This is intentional for knowledge records. Sessions use the 90-day retention value. Do not change the `knowledge.db` versioning config unless you understand the storage implications.

---

## 25. Scale Budget

Numbers on when this stops being "just a KV store on disk." Ground truth where it exists; everything else is labeled as derived or assumed.

### 25.1 Store size

`knowledge.db` uses `with_versioning(true, 0)` — indefinite retention, never compacted away (section 21, section 24). Growth has two shapes in the same tree:

- **Mutable keys** (`gotcha:*` `file:*` `decision:*` `stage:*` `dev_note:*` `dep:*` `policy:*`): every write is a new full version. Growth is proportional to edit churn on the keys actually touched, not to repo size — a file nobody edits after `mati init` stays at one version forever.
- **`enforcement:event:*`**: append-only, one unique key per event, no version multiplication — but no prune path either (section 25.3).

| Measurement | Value | Basis |
| --- | --- | --- |
| Fresh init, zero history, rust repo (58,378 source files, 58,736 records) | 182.3MB | measured, `BENCHMARKS.md` |
| → average bytes per record-version | ~3.2KB | derived (182.3MB / 58,736) |
| This repo's live store (`~/.mati/<slug>`), ~13h of one active dev session | knowledge.db 2.4MB + sessions.db 1.0MB + search_index 192KB ≈ 3.6MB total | measured, `du -sh` |
| Same session's write rate | 426 new record-versions in a 30-day window (effectively one day) | measured, `mati stats` |

At ~3.2KB/version and this session's rate, one heavily tool-driven dev-day adds on the order of 1-2MB. That's an upper bound, not a typical pace — most of those 426 writes came from automated tooling, not a human at a keyboard. "MB/week per real developer" is the right order of magnitude, not "MB/day."

What "a problem" means concretely here is not disk space — a multi-GB store is nothing on modern hardware — it's linear-scan latency. `mati export --format json` took 226ms on the 182.3MB fresh store (`BENCHMARKS.md`); most other commands (`stats`, `gaps`, `status`) are cache-backed via `health_write_seq` and stay near O(1) regardless of store size (`BENCHMARKS.md` Phase 2/3), but export and any other full-scan path don't get that shield. Scaling the export figure linearly — **assumption**, no larger store has been measured — puts a 2GB store's export around 2.5s and a 20GB store around 25s: uncomfortable for an interactive CLI, self-inflicted only by commands that still do a full scan. **Unmeasured**: SurrealKV compaction behavior once the live (non-collectible, because retention is indefinite) data volume is itself multi-GB. Nothing in this repo exercises that.

### 25.2 Graph edges

`Graph::load` (`src/graph/graph.rs:47-65`) does one `scan_keys("graph:edge:")` — a key-only range scan, no value bytes read (`src/store/db/crud.rs:626-641`) — then one `Edge::from_key` parse plus one petgraph insert (HashMap + HashSet + `DiGraph`) per edge, entirely in memory.

The real ceiling isn't FLOPs, it's the daemon readiness watchdog. `Graph::load` runs inside `mati daemon`'s startup (`src/cli/daemon/start.rs:145`), between the `phase=store_opened` and `phase=ready` lifecycle events — and **no intermediate event is emitted** for graph load, the dirty-queue auto-drain, or the policy-matcher load that follow it in the same window (`src/cli/daemon/start.rs:124-287`). `wait_for_ready` calls the daemon `Wedged` if `lifecycle.log` stops growing for 15s (`READINESS_WEDGE_THRESHOLD`, `src/mcp/daemon_lifecycle.rs:67`) and gives up entirely (`HardCap`) at 60s (line 61) — regardless of whether the daemon is still silently making progress. A graph load slow enough to blow through 15s reads as a hung daemon, not a big one.

Edge-count sources are all structurally bounded, which is why this is unlikely to bite soon:

- `HasGotcha` — one per confirmed gotcha. Confirmation is a manual step (`mati gotcha confirm` / developer review), so this scales with review throughput, not repo size.
- `CoChanges` — capped per commit by `MAX_COMMIT_FILES = 50` (`src/analysis/git.rs:44`) → ≤1,225 pairs/commit, further cut by a co-change ratio threshold (`src/analysis/git.rs:313-318`). Linear in commit count at worst, not combinatorial in file count.
- `Imports` — bounded by files × imports/file, recomputed (not accumulated) on every `mati init`.

The measured init on the 58k-file rust repo produced only 80 edges (dependency edges at that init depth), so it says nothing about load time at high edge counts — that's unmeasured territory. **Assumption**, labeled: a HashMap insert + HashSet insert + `DiGraph` edge add for a short string key runs on the order of 1-2μs in Rust. On that basis: 100k edges ≈ 0.1-0.2s (no issue), 1M edges ≈ 1-2s (comfortably inside Wedged), 5-10M edges ≈ 5-20s (starts to cross the 15s Wedged threshold, especially stacked with the separate 10s `AUTO_DRAIN_TIMEOUT` budget for the dirty-queue drain running in the same gap, `src/mcp/server/socket.rs:28`). Reaching millions of edges needs a genuinely large, long-lived monorepo with a dense import graph — not a near-term risk for a single-repo instance, but real for very large ones.

### 25.3 Event log length

`enforcement:event:*` is append-only and hash-chained, stored in `knowledge.db` (Immediate durability by default — `src/store/durability.rs`). `enforce_retention` (`src/store/enforcement/retention.rs`) is the only prune logic that exists. It ran nowhere in production until it was wired into `mati repair`'s full scan (`prune_expired_events`, `src/cli/repair.rs`); before that the log grew without bound.

The prune is deliberately narrow, because the thing it deletes is audit evidence:

- **Prefix only.** It walks event keys in seq order and stops at the first event still inside the window — and also at the first key it cannot read or parse, so every deleted key is individually proven expired. `verify_chain` ignores the earliest survivor's dangling `prev_hash` (`src/store/enforcement/models_chain.rs`), so a pruned prefix verifies clean. A hole anywhere else is a `ChainBreakKind::Linkage` — the tamper signal. Selecting by timestamp alone, which the original code did, punches that hole the first time the wall clock steps backwards.
- **Full scan only.** `mati repair --check` returns before the write path and `--fast` runs `RepairMode::Fast`; neither deletes anything. `mati repair` (full) also refuses to run while the daemon holds the store, so no writer is appending during the prune.
- **Never on a read or hook path.** Hooks run under `HOOK_DEADLINE_MS` and fail open; a deletion pass there would be both slow and unreviewable.
- **Zero disables it.** `get_retention_days` returns the 365-day default for an unset or unparseable setting, never 0, and a retention of 0 is read as "do not prune" rather than "prune everything".
- **The deletion is attested.** A `RetentionPruned` event is recorded after the deletion, so it links to the newest surviving event. A pruned prefix is invisible to `verify_chain` by design, which makes that event the only trace the prune happened — so `enforce_retention` fails loudly rather than returning success if it cannot be written (advisory mode otherwise swallows event-write failures).

Not addressed: deletion is one `Store::delete` per key at Immediate durability, so a very long expired prefix costs one fsync per event. `mati repair` is an offline maintenance command, so this is latency, not a correctness problem.

Both consumers that need the full chain call `scan_enforcement_events(store, 0, u64::MAX)` unconditionally (`src/store/enforcement/seq_writer.rs:387-431`): `mati verify-chain` (`src/cli/verify_chain.rs:37`) and `mati history --enforcement`, even with `--limit` (`src/cli/show/history.rs:41`). That's one key scan, then one separate `get_raw_bytes` call per event — each opens its own read-only transaction (`src/store/db/crud.rs:439-446`) — one JSON deserialize per event, and, for `verify-chain`, one SHA-256 recompute per event to check tamper and linkage (`src/store/enforcement/models_chain.rs:407-449`). `--limit N` on `mati history --enforcement` filters *after* loading everything (`src/cli/show/history.rs:20-123`); it does not bound the scan.

This is the one place in the codebase that never got the equivalent of the fix already applied to `StalenessAnalyzer::analyze_all`: a resumable cursor plus a hard 2000ms deadline (`ANALYZE_TIME_BUDGET_MS`, `src/health/staleness/analyzer.rs:37-39`, `src/health/staleness/analyzer.rs:130-228` onward), added specifically because an unbounded full scan doesn't hold up at scale. The enforcement scan path never got that treatment.

Measured: this repo's live store recorded 204 enforcement events in a 30-day window that's effectively one active dev-day (`mati stats`) — a burst rate from heavy tool use, an upper bound rather than a steady-state number. **Unmeasured** beyond that: nothing in this repo has run `verify-chain` or `mati history --enforcement` against a chain with more than a few hundred events, so the point where the per-event transaction-plus-JSON-plus-SHA-256 cost turns into seconds rather than milliseconds is a derived guess, not a benchmark. The prune now bounds the log, but only as far back as the retention window and only when someone runs `mati repair`; the scan paths still have no cursor and no deadline.

### 25.4 What breaks first

1. **Event log** breaks first. It has no natural throttle (unlike `HasGotcha` edges, gated by human confirmation), no cache shield (unlike `stats`/`status`), and no resumable-scan fix (unlike staleness analysis). The prune (section 25.3) caps it at the retention window, but only on a manual `mati repair`, so a store nobody maintains still grows without bound.
2. **Store size** is next. Growth is real and permanent (no compaction under indefinite retention), but self-limited by edit churn rather than repo size, and most day-to-day commands are cache-backed and stay fast regardless of store size.
3. **Graph edges** last. All three edge-generating paths are structurally bounded — by commit size, by file/import count, or by a manual confirmation step — so reaching a count that threatens the 15s/60s daemon-readiness ceiling needs a scale of monorepo this tool hasn't been pointed at yet.
