# ARCHITECTURE.md: mati

Cross-references in code comments and other docs use the `§N` shorthand (e.g., `§10.1`). Numbers correspond to section headings below.

---

## §1: Overview

mati sits between Claude Code and the codebase as a persistent, queryable knowledge store. When Claude opens a file, the pre-read hook checks whether mati has context for it. If a high-confidence confirmed gotcha is attached, the hook can inject that context; if the gotcha has not yet been consulted, the hook blocks the read and requires consultation first. The store accumulates what developers know: per-file gotchas, architectural decisions, and project state.

The underlying goal is institutional memory: knowledge that would otherwise live in someone's head, a Slack thread, or nowhere. mati makes it queryable, measurable, and enforceable. A secondary benefit is that high-confidence records can replace file reads entirely, reducing token consumption. That is a useful property, not the design goal.

---

## §2: Design Principles

**P1: Hook enforcement is primary; prompt injection is secondary.**
The pre-read hook's DENY/ALLOW/advisory decision is the canonical enforcement path. What Claude receives in the MCP tool result is supplementary context.

**P2: Inject nothing by default. All context is pulled on demand.**
mati never pushes records into Claude's context unprompted. `mem_bootstrap` is an explicit call. Hook injection is triggered by file access, not by session start. The one deliberate exception is the passive "Suggested Actions" nudge appended to MCP tool results (`mcp/tools.rs`), which surfaces next-step hints without injecting record content.

**P3: Four MCP tools, no more.**
`mem_get`, `mem_query`, `mem_bootstrap`, `mem_set`. Every tool definition costs tokens on every call. Adding a fifth tool requires redesigning the new capability as a parameter on an existing tool. This is a hard code-review constraint.

**P4: Developer-intentional memory.**
Unconfirmed gotcha records never influence hook enforcement. They exist in the graph and surface in `mem_bootstrap` as candidates for review, but they cannot trigger Deny or the gotcha-based context injection path (§10.1 step 4). The Advisory path (§10.1 step 5) is separate: it fires on the file record's own confidence and quality scores, which are not tied to any gotcha's confirmation state.

_(P5 and P6 are intentionally unassigned. They were removed during v0.1 scope reduction. The gaps are preserved to avoid invalidating existing code-comment cross-references.)_

**P7: Layer 0 produces value with zero LLM calls.**
tree-sitter parsing, import graph construction, and co-change clustering run entirely from static analysis and git history. No network calls, no model calls.

**P8: Knowledge health is the primary metric. Token savings is a bonus.**
`mati doctor` and `mati stats` measure coverage, confidence, and staleness. Token savings is a side effect.

**P9: Graceful degradation. Never block Claude on a mati outage.**
If the daemon is unreachable, all hooks pass through unconditionally. A mati failure must never block a development session.

**P10: User-facing strings lead with the problem, not the mechanism.**
Error messages describe what went wrong first. Tool names, module names, and internal keys come after.

---

## §3: Repository Layout

```
mati/
├── src/
│   ├── main.rs              # binary entry point, CLI dispatch
│   ├── lib.rs               # mati_core library root
│   ├── cli/                 # clap commands, comfy_table output
│   ├── mcp/                 # MCP stdio server (rmcp) + daemon socket bridge
│   │   ├── server.rs        # serve(), socket loop, policy consts
│   │   ├── tools.rs         # mem_get, mem_query, mem_bootstrap, mem_set
│   │   ├── types.rs         # ContextPacket, MCP response types
│   │   ├── protocol.rs      # v2 typed Request/Response/Command + v1/v2 mapper
│   │   ├── dispatch_v2.rs   # v2 typed Command to handler dispatch
│   │   ├── handlers.rs      # handler bodies
│   │   ├── daemon_lifecycle.rs # ensure_daemon, lifecycle.log readiness (§4.2)
│   │   └── metadata.rs      # DaemonMetadata, panic hook, peer cred, lifecycle log
│   ├── store/               # SurrealKV layer
│   │   ├── db.rs            # knowledge.db + sessions.db init
│   │   ├── record.rs        # Record struct + all sub-types
│   │   ├── durability.rs    # Immediate vs Eventual write paths
│   │   ├── gotcha_ops.rs    # centralized gotcha mutations
│   │   ├── repair.rs        # gotcha index reconciliation engine
│   │   ├── enforcement.rs   # EnforcementEvent log
│   │   └── session.rs       # session:* markers, harvest, consultation
│   ├── graph/               # petgraph layer
│   │   └── edges.rs         # EdgeKind, load/persist, traversal
│   ├── search/              # tantivy layer
│   │   └── index.rs         # schema, index/rebuild, BM25 query
│   ├── analysis/            # Layer 0 static analysis
│   │   ├── walker.rs        # ignore + rayon parallel walk
│   │   ├── parser/          # tree-sitter multi-language parsing
│   │   ├── resolvers/       # per-language import resolvers
│   │   ├── edges.rs         # edge derivation from parsed files
│   │   ├── deps.rs          # Cargo.toml / package.json / go.mod
│   │   ├── git.rs           # git2 history mining
│   │   ├── blast_radius.rs  # direct/transitive importer count
│   │   ├── clusters.rs      # co-change clustering
│   │   └── propagation.rs   # staleness propagation through import graph
│   ├── health/              # knowledge health system
│   │   ├── confidence.rs    # ConfidenceScore computation
│   │   ├── quality.rs       # QualityScore + RecordQualityAnalyzer
│   │   ├── staleness.rs     # StalenessScore + StalenessAnalyzer
│   │   ├── gaps.rs          # KnowledgeGapAnalyzer
│   │   └── onboarding.rs    # OnboardingScore
│   └── hooks/               # hook decision engine
│       ├── decide.rs        # pure enforcement decision (no I/O)
│       ├── pre_read.rs      # pre-read hook adapter
│       ├── pre_bash.rs      # pre-bash hook adapter
│       └── compliance.rs    # compliance event recording
```

---

## §4: Runtime Architecture

mati runs as two separated processes after the gamma refactor.

```
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

**`mati serve`** is a thin MCP-stdio forwarder. It does not open the store, does not bind a socket, and does not manage signals. On startup it calls `ensure_daemon` to confirm the daemon is running before accepting MCP traffic, then proxies every tool call over a Unix domain socket.

**`mati daemon`** is the data plane. It owns the SurrealKV lock, serves UDS requests, and runs the idle-shutdown loop. Idle shutdown fires only when `now - last_wall >= 30min` AND `active_connections == 0`, so a long MCP session that pauses between calls does not lose its daemon.

### §4.1: `mati daemon stop` semantics

| Flag | Effect |
|---|---|
| (default) | SIGTERM; escalates to SIGKILL on timeout. Serve proxies auto-respawn transparently. |
| `--force` | SIGKILL directly, no SIGTERM grace. Serve proxies still auto-respawn. |
| `--include-mcp` | Also kills all `mati serve` processes. MCP sessions die. |
| `--force --include-mcp` | SIGKILL daemon, then SIGKILL all serves. |

### §4.2: State-aware daemon readiness

`ensure_daemon` (in `src/mcp/daemon_lifecycle.rs`) confirms the daemon is reachable by polling `lifecycle.log` for startup events rather than using timer-based polling. It returns a `bool`; internally it calls `wait_for_ready`, which returns the `ReadinessOutcome` below, and `ensure_daemon` collapses that to `true` (`Ready`) / `false` (anything else):

| `ReadinessOutcome` | Condition |
|---|---|
| `Ready` | `startup phase=ready` event received and ping succeeds |
| `Failed` | `serve_failed` or `panic` event received |
| `Wedged` | No new event for 15 seconds |
| `HardCap` | Absolute 60-second budget elapsed |

### §4.3: Durability split

Write durability is assigned by key namespace. Never mix the two paths. `durability.rs` treats this section as the canonical assignment table.

| Durability | Namespaces |
|---|---|
| Immediate (fsync) | `gotcha:*` `decision:*` `file:*` `stage:*` `dev_note:*` `dep:*` |
| Eventual (OS buffer) | `session:*` `analytics:*` `hook_event:*` `compliance:*` `graph:edge:*` `health:*` `parse:*` `audit:session:*` |

Unknown prefixes default to Immediate. See §21 for rationale.

---

## §5: Data Model

All types are defined in `src/store/record.rs`. Do not redefine them elsewhere.

### §5.1: Record

The universal store entry. All categories share this struct.

| Field | Type | Notes |
|---|---|---|
| `key` | `String` | Namespaced primary key and graph node key |
| `value` | `String` | Human-readable content: rule, purpose, body. Indexed by tantivy. |
| `category` | `Category` | Gotcha, File, Decision, Stage, Dependency, DevNote, Session, Analytics |
| `priority` | `Priority` | Low < Normal < High < Critical. Do not reorder variants (derived `Ord`). |
| `tags` | `Vec<String>` | Free-form, used for search and filtering |
| `created_at` | `u64` | Unix seconds |
| `updated_at` | `u64` | Unix seconds |
| `ref_url` | `Option<String>` | PR, issue, doc, or incident link. Boosts confidence 1.5x when set. |
| `staleness` | `StalenessScore` | See §17 |
| `lifecycle` | `RecordLifecycle` | Active, Tombstoned, Superseded |
| `version` | `RecordVersion` | Lamport clock + device ID. See §20. |
| `quality` | `QualityScore` | See §13.2 |
| `access_count` | `u32` | Total reads via `mem_get` or hooks |
| `last_accessed` | `u64` | Unix seconds |
| `source` | `RecordSource` | StaticAnalysis, ClaudeEnrich, SessionHook, DeveloperManual, Import |
| `confidence` | `ConfidenceScore` | See §13.1 |
| `gap_analysis_score` | `f32` | `change_frequency * (1 - coverage_score)` |
| `payload` | `Option<JsonValue>` | Typed per-category data (FileRecord, GotchaRecord, etc.) stored as MessagePack |

### §5.2: FileRecord

Stored under `file:<path>`. Attached to the base `Record` via `payload`.

| Field | Notes |
|---|---|
| `path` | Repo-relative file path |
| `purpose` | One-sentence summary. Empty at Layer 0, filled by Layer 1 enrichment. |
| `entry_points` | Public functions and types visible from other modules |
| `imports` | Import/use paths found by tree-sitter |
| `gotcha_keys` | Keys of associated `gotcha:*` records (derived index; see §22) |
| `decision_keys` | Keys of associated `decision:*` records |
| `todos` | TodoComment structs: text, line, kind (Todo/Fixme/Hack/Note/Deprecated) |
| `unsafe_count` | Count of `unsafe` blocks |
| `unwrap_count` | Count of `.unwrap()` calls |
| `line_count` | Newline count at last scan (approx line count). 0 for non-parseable files. |
| `change_frequency` | Commit count (capped at 5,000 non-merge commits via git2) |
| `is_hotspot` | True when `change_frequency` is in the top 10% of the repo |
| `token_cost_estimate` | Rough token count for `mem_bootstrap` budget enforcement |
| `blast_radius` | Direct and transitive importer count (computed during `mati init`) |
| `propagated_staleness` | Staleness inherited from upstream stale sources via Imports edges |
| `content_hash` | SHA-256 of file content at last Layer 0 scan |

### §5.3: GotchaRecord

Stored under `gotcha:<slug>`. Attached to the base `Record` via `payload`.

| Field | Notes |
|---|---|
| `rule` | Actionable statement. Must start with an imperative verb for Good quality. |
| `reason` | Why the rule exists. Must contain a causality word ("because", "since", "as"). |
| `severity` | Priority enum: Low, Normal, High, Critical |
| `affected_files` | Canonical source of truth for which files this gotcha applies to |
| `ref_url` | Optional link to the incident or PR that prompted this rule |
| `confirmed` | `false` = Layer 0 candidate stub, never injected. `true` = developer-validated. |

`confirmed: false` records exist as graph nodes and gap signals. They are never used in hook enforcement. Only `confirmed: true` records with `confidence >= 0.6` and `quality >= 0.4` can trigger a deny.

### §5.4: Quality Score formula

```
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

Layer 0 `StaticAnalysis` records default to `0.10` (Suppressed tier). Recomputed by `RecordQualityAnalyzer` on every write.

---

## §6: Context Packet (mem_bootstrap)

`ContextPacket` is the struct returned by `mem_bootstrap`. Token-budgeted to 2,000 tokens.

Assembly order:

1. Resolve `context_files` to graph nodes
2. Traverse `HasGotcha` edges: direct gotchas for each file
3. Traverse `Imports` one hop: gotchas for directly imported files
4. Traverse `AffectedBy` edges: relevant architectural decisions
5. Token-budget the result to 2,000 tokens
6. Sort gotchas by `confidence * priority_weight(severity)` (Low/Normal/High/Critical -> 0.25/0.50/0.75/1.00)

Fields returned:

| Field | Content |
|---|---|
| `stage` | Current `stage:current` record, if set |
| `critical_gotchas` | Confirmed gotchas sorted by `confidence * priority_weight(severity)` |
| `file_records` | FileRecords for the requested context files |
| `related_decisions` | Decisions reached via `AffectedBy` traversal |
| `recent_session` | Plain-text summary of last session. Currently always `None` (assembler not yet wired). |
| `stale_warnings` | Records approaching Liability tier |
| `unconfirmed_candidates` | Keys of `confirmed: false` Layer 0 stubs for developer review |
| `knowledge_gaps` | Top gaps ranked by risk score. Currently always empty (assembler not yet wired). |
| `compliance_rate` | Last 7-day compliance rate. Currently always `None` (not yet populated). |
| `injection_string` | Pre-formatted markdown returned as the MCP tool result text |
| `token_estimate` | Estimated token size of the assembled packet (budget accounting) |

---

## §7: Key Namespacing

All store keys follow this convention:

```
gotcha:<slug>          file:<path>           decision:<slug>
stage:current          dep:<ecosystem>:<name> dev_note:<slug>
session:<timestamp>    analytics:<type>_<date>
graph:edge:<from>:<kind>:<to>
enforcement:event:<seq_no>
```

`file:<path>` uses repo-relative paths, normalized lexically (no symlink resolution). Case-folding is applied where the OS filesystem is case-insensitive.

---

## §8: Storage Layer

Two SurrealKV trees per project, stored at `~/.mati/<slug>/`.

**Slug derivation:** first 8 hex characters of `SHA-256(git remote URL)`. Falls back to `SHA-256(canonicalized repo root path)` when no remote is set.

| Tree | Path | Durability | Retention |
|---|---|---|---|
| `knowledge` | `knowledge.db` | Immediate (fsync) | Indefinite (`with_versioning(true, 0)`) |
| `sessions` | `sessions.db` | Eventual (OS buffer) | 90 days |

**`with_versioning(true, 0)` means indefinite retention.** The `0` argument is not "disabled". It means retain all versions forever. This is intentional for `knowledge.db`. Sessions use the 90-day value.

Serialization: MessagePack via `rmp-serde`. JSON (`serde_json::Value`) is used only for the typed `payload` field and hook I/O.

Knowledge namespaces (Immediate path): `gotcha:`, `decision:`, `file:`, `stage:`, `dev_note:`, `dep:`

Session namespaces (Eventual path): `session:`, `analytics:`, `hook_event:`, `compliance:`, `graph:edge:`, `health:`, `parse:`, `audit:session:`

`enforcement:event:*` is not in `SESSION_NAMESPACES` and defaults to Immediate. Enforcement events are written to `knowledge.db` and are crash-safe by design.

On startup after a crash, the store checks for `search_sync_pending` and `search_stale` markers and rebuilds the tantivy index if needed.

---

## §9: Graph Layer

petgraph is the in-memory graph. Edges are persisted in SurrealKV as `graph:edge:<from>:<kind>:<to>` keys and loaded at daemon startup via a full key scan. Mutations must write back to SurrealKV immediately or they are lost on restart.

**10 edge kinds:**

| Kind | Meaning |
|---|---|
| `HasGotcha` | A file has a gotcha record attached |
| `Imports` | A file imports another file (from static analysis) |
| `AffectedBy` | A file or gotcha is affected by an architectural decision |
| `HasNote` | A file or record has a developer note |
| `DiscoveredIn` | A gotcha or decision was found in a specific session |
| `CausedBy` | One gotcha or issue was caused by another |
| `Supersedes` | A decision or gotcha supersedes an older one |
| `Touched` | A file was accessed in a session (passive learning) |
| `DependencyAffects` | A dependency change affects a file or module |
| `CoChanges` | Two files are frequently committed together (git co-change) |

Edge keys use the slugified kind name: `has_gotcha`, `imports`, `affected_by`, etc.

---

## §10: Hook Pipeline

Hooks are shell scripts installed into the project's `.claude/settings.json` by `mati hooks`. This command writes files inside the repository root under `.claude/`. Hooks run on `PreToolUse` (before Claude reads a file or runs a bash command) and `PostToolUse` (after).

The decision engine in `src/hooks/decide.rs` is pure: no I/O, no daemon calls. The adapter layer in `src/cli/hook_decide.rs` maps semantic decisions to protocol output: JSON for Claude Code (which runs the hook as a shell subprocess and reads its stdout), or exit codes for environments that support the Codex hook protocol.

Hook-based enforcement (the Deny/Advisory path in §10.1) requires the host environment to install and execute the hook scripts. Claude Code does this natively. Codex hook execution depends on how the agent is configured; if hooks are not running, enforcement falls back to MCP-only behavior, where `mem_get` still mints consultation receipts but no reads are blocked. Other MCP-compatible agents that do not run hooks get tool access only.

### §10.1: Decision Matrix

Evaluated in order:

```
1. file_record is None
   -> NoRecord: log miss, allow unconditionally

2. staleness_tier == "tombstone"
   -> Tombstone: allow unconditionally, no injection

3. staleness_tier == "liability"
   -> Liability: allow + inject WARNING (staleness value shown), log hit

4. any attached gotcha has (confirmed=true AND confidence >= 0.6 AND quality >= 0.4):
     a. already_consulted == true
        -> AlreadyConsulted: allow + inject context, log ComplianceHit
     b. already_consulted == false
        -> Deny: block read, inject mem_get() instruction, log BlockedUnconsultedRead

5. file_record.confidence >= 0.3 AND file_record.quality >= 0.4
   (checks the file record's own scores; unconfirmed gotchas do not factor in here)
   -> Advisory: allow + inject context as additionalContext, log hit

6. (default)
   -> Allow: pass through, no injection
```

`confidence < 0.3` or `quality < 0.4` always allows without injection, regardless of `confirmed` state.

### §10.2: Command Classification (pre-bash)

The pre-bash hook classifies shell commands before they run:

- **CatLike** (`cat`, `less`, `head`, `tail`, `bat`): file path extracted from first non-flag argument.
- **GrepLike** (`grep`, `rg`, `sed`, `awk`): file path extracted from last non-flag argument.
- Anything else: not treated as a file-read operation; passes through unconditionally.

Known limitation: `cat` called with variable expansion, process substitution, or unusual quoting is not caught. The accepted miss rate is 2-5%. See §24.

### §10.3: Edit Gating (Codex `apply_patch`)

On Codex, the `apply_patch` PreToolUse hook (`codex-pre-apply-patch`) gates file *edits* the same way pre-bash gates reads. The payload is the raw patch envelope in `tool_input.command`; `decide::extract_apply_patch_files` parses the column-0 markers (`*** Update File:` / `*** Add File:` / `*** Delete File:` / `*** Move to:`) into the touched paths, and each is run through the same §10.1 decision matrix. If any touched file has an unconsulted confirmed gotcha, the edit is denied (exit 2 + stderr); a `mem_get` consultation receipt clears it, exactly like reads.

Because the envelope hands mati the exact target path, edit gating is immune to the shell-wrapper obfuscation that limits pre-bash read detection (§10.2, §24) — there is no command string to misparse. It fails open on every uncertainty (unparseable patch, unreachable daemon, per-file lookup error, more than `MAX_APPLY_PATCH_FILES = 50` touched files, or an older binary that does not recognize the variant): wrongly blocking all edits would be worse than missing one gotcha. The wrapper script (`codex_pre_apply_patch.rs`) enforces that fail-open bias by treating only `exit 2` with a `mati:` message as a real deny.

Coverage is platform-dependent: Codex fires `PreToolUse` for `apply_patch` (since openai/codex PR #18391) but not for its native file-*read* tool, so reads are gated only via the shell path. Claude Code edits are not yet gated (a separate `ClaudePreEdit` adapter would be required).

---

## §11: MCP Server

The MCP server is in `src/mcp/`. It uses the `rmcp` crate (Rust MCP SDK) for stdio transport.

Exactly four tools are exposed. This is a hard constraint (P3). Every tool definition costs tokens on every call from Claude.

| Tool | Description |
|---|---|
| `mem_bootstrap` | Returns a `ContextPacket` for the current session. Token-budgeted to 2,000 tokens. |
| `mem_get` | Looks up a single record by key. Returns the full `Record` JSON. Mints a consultation receipt. |
| `mem_query` | Text search (BM25 via tantivy) plus optional graph traversal. Supports `mode="text"` and `mode="graph"`. |
| `mem_set` | Writes a record. Triggers quality recomputation, graph edge updates, and search index update. |

`mati serve` runs the rmcp stdio loop and proxies every tool call to `mati daemon` over a Unix domain socket. The daemon processes the call and returns the result.

---

## §12: Static Analysis (Layer 0)

`mati init` runs a Layer 0 scan with no LLM calls. It produces `file:*` record stubs and graph edges from source code alone.

**Supported languages (12):** Rust, TypeScript, JavaScript, Python, Go, Java, C, C++, Ruby, Scala, Elixir, Haskell.

Each grammar crate must expose a tree-sitter ABI compatible with the `tree-sitter = "0.23"` runtime — not necessarily the same crate version. Most grammars pin to `"0.23"` (e.g. `tree-sitter-rust = "0.23"`), but some compatible grammars carry a different crate version (e.g. `tree-sitter-elixir = "0.3"`). An ABI-incompatible grammar causes silent parse failures, not errors or panics.

**What Layer 0 produces per file:**
- Entry points (public functions, types, exports)
- Import graph (resolved to repo-relative paths where possible)
- TODO/FIXME/HACK/NOTE comments (line, text, kind)
- `unsafe_count`, `unwrap_count`, `line_count`
- `change_frequency` and `last_author` from git2 (capped at 5,000 non-merge commits)
- `is_hotspot` flag (top 10% by change frequency)
- `blast_radius` (direct and transitive importer count)
- Co-change edges between files whose co-commit ratio is at least 70%, where the ratio is `shared_commits / min(commit_count_a, commit_count_b)` (`CO_CHANGE_THRESHOLD = 0.70`)

**What Layer 0 does not produce:**
- `purpose` (empty string until Layer 1 enrichment)
- `gotcha_keys` (empty until enrichment or `mati gotcha add`)
- `confirmed: true` gotchas

Layer 0 file records start with `quality = 0.10` (Suppressed tier) and `confidence = 0.10` (StaticAnalysis base). They are never injected by hooks until enrichment raises their scores.

---

## §13: Health System

### §13.1: Confidence Score

How much the system trusts a record's accuracy.

```
base_score by source:
  DeveloperManual -> 0.80
  Import          -> 0.70
  ClaudeEnrich    -> 0.60
  SessionHook     -> 0.50
  StaticAnalysis  -> 0.10

confidence = base_score
  x log2(confirmation_count + 2)
  x min(contributor_count, 3) / 3
  x recency_weight(last_accessed)    90-day half-life
  x ref_boost                        1.5x if ref_url is set
```

The recomputation is implemented as a pure function (`health::confidence::recompute`), but is **not yet wired into the `mem_get` path** — currently `mem_get` only bumps `access_count`. Automatic recomputation-on-access is planned. (Note: `file:*` records are written on the Immediate path, not Eventual.)

The confidence score feeds into two distinct paths in §10.1. The table below summarizes them; see §10.1 for the full decision matrix.

| Path | Condition | Behavior |
|---|---|---|
| Deny (§10.1 step 4) | attached gotcha: `confirmed = true`, `confidence >= 0.6`, `quality >= 0.4` | Block file read; require `mem_get` consultation |
| Advisory (§10.1 step 5) | file record: `confidence >= 0.3`, `quality >= 0.4` (no gotcha confirmation required) | Allow read + attach context as `additionalContext` |
| No injection | file record: `confidence < 0.3` or `quality < 0.4` | Allow read unconditionally |

### §13.2: Quality Score

Quality tiers (half-open intervals):

| Tier | Range | Injection behavior |
|---|---|---|
| Suppressed | [0.0, 0.2) | Never injected |
| Poor | [0.2, 0.4) | Injected with `[mati] LOW QUALITY - verify` warning |
| Acceptable | [0.4, 0.7) | Injected normally |
| Good | [0.7, 0.9) | Prioritized in `mem_bootstrap` |
| Excellent | [0.9, 1.0] | Prioritized for template reuse (planned: `mati garden`) |

See §5.4 for the computation formula.

### §13.3: Onboarding Score

An estimate of how long a new developer would take to reach productive understanding, given current knowledge coverage. The base time and weights are design targets, not universally measured values.

```
base_time = 22 minutes

reduction_factors:
  hotspot_coverage  x 0.40   (fraction of hotspot files with non-empty purpose)
  gotcha_coverage   x 0.25   (fraction of hotspot files with at least 1 attached gotcha)
  decision_coverage x 0.15   (fraction of decisions documented)
  confidence_weight x 0.20   (average confidence across confirmed records)

estimated_minutes = base_time x (1 - weighted_reduction)
```

Computed on demand by `mati stats`; not currently persisted. (Persistence as `analytics:onboarding_score` on the Eventual path is planned.)

---

## §14: Enrichment (Layer 1)

`mati enrich [path]` runs a four-stage per-file pipeline using Claude.

**Stage 1 (Setup):** Query existing confirmed gotchas for the directory as positive exemplars. Call `mem_get("file:<path>")` to mint a consultation receipt and retrieve the `enrichment_depth_hint` (fast / standard / deep). For deep tier, retrieve recently tombstoned gotchas as negative exemplars.

**Stage 2 (Enumeration):** Read the file. Extract gotcha candidates ranked by signal tier (HIGH: WARNING/FIXME/HACK/SAFETY comments, panic!/assert! messages; MEDIUM: defensive guards, non-obvious literals; LOW: raw API usage).

**Stage 3 (Critique loop):** Three bounded rounds:
1. Specificity filter: discard candidates that are not specific, enforceable, non-obvious, and causal.
2. Cross-reference verification: call `mati verify-evidence` (deterministic CLI) to confirm each candidate's file line and quote are real.
3. Stability check: repeat round 2 if round 2 discarded items (cascading discard, max 3 iterations).

**Stage 4 (Write):** For each verified candidate, tighten the rule, verify causality language, assign severity via a hybrid keyword and semantic classifier, and call `mem_set`.

Severity classifier:

- Keyword pass first: "panic"/"data loss"/"corruption" becomes critical; "race"/"silent failure" becomes high; "performance"/"stale state" becomes normal.
- Semantic pass second (LLM judgment using the same rubric).
- If they agree, use that severity. If they disagree, use the higher and tag `severity-disputed`.

After batch enrichment, run `mati review` to confirm candidates and activate enforcement. Single-file enrichment confirms each gotcha immediately via `mati gotcha confirm <key>`.

---

## §15: Session Model

Sessions use three layers of state in `sessions.db` (Eventual durability).

**During the session:**
Each `mem_get` call writes `session:consulted:<key>`: a consultation receipt proving Claude read the record for that file. TTL is 15 minutes (`CONSULTED_RECENT_TTL_SECS = 900`). The hook decision engine checks for this key before deciding between Deny and AlreadyConsulted (see §10.1).

**On session flush:**
`session:current` is written with the full list of consulted keys from `session:consulted:*` markers. This interim record is used by harvest if the session ends without an explicit flush.

**On session end (`session_harvest`):**
Reads `session:current`, writes a final `session:<timestamp>` record summarizing files touched, gotchas encountered, and compliance rate. Cleans up all `session:consulted:*` markers. Runs staleness re-scoring on touched files.

The most recent session summary is intended to be included in the `ContextPacket` returned by `mem_bootstrap` as `recent_session`; that field is currently always `None` (the assembler is not yet wired — see §6).

---

## §16: Search Layer

tantivy provides BM25 full-text search over the `value` field (human-readable content) of all knowledge records.

The tantivy index lives alongside the SurrealKV store at `~/.mati/<slug>/`. It is rebuilt from the `knowledge.db` key scan on:
- First startup after `mati init` (deferred indexing path)
- Startup when `search_stale` marker is present
- Startup when `search_sync_pending` marker is present (crash recovery)

`mem_query mode="text"` runs a BM25 query and returns ranked records. `mem_query mode="graph"` traverses the petgraph edges from a starting node.

---

## §17: Staleness

Staleness score formula:

```
staleness =
  time_factor       x 0.20   (days since last confirmation)
  + git_factor      x 0.35   (commits since last confirmation)
  + semantic_factor x 0.25   (entry points, imports, unsafe, unwrap counts changed)
  + dep_factor      x 0.10   (dependency version bumps)
  + cascade_factor  x 0.10   (upstream decisions or gotchas changed)
```

`semantic_factor` is currently a `0.0` stub in `StalenessAnalyzer`, so its 0.25-weighted term contributes nothing yet; full semantic-delta scoring is planned for v0.2. The entry-point/import/unsafe/unwrap delta detection it describes currently runs only in the `mati reparse` path. The other four factors are live.

Hard overrides (bypass the formula):
- `FileDeleted` signal: Tombstone (1.0)
- `FileRenamed` signal: Liability (0.85) until the path is corrected

Staleness tiers (half-open intervals):

| Tier | Range | Hook behavior |
|---|---|---|
| Fresh | [0.0, 0.2) | Normal injection |
| Aging | [0.2, 0.4) | Normal injection |
| Stale | [0.4, 0.7) | Injected with staleness warning |
| Liability | [0.7, 0.9) | Hook passes through; injects warning to read the file directly |
| Tombstone | [0.9, 1.0] | Hook passes through unconditionally; record excluded from all injection |

At Tombstone, the record is fully excluded. A wrong record injected silently is a worse failure mode than a cache miss.

Sync merge rule (planned, v0.2 — no sync or conflict resolution exists in v0.1): `Tombstone > Liability > Stale > Aging > Fresh` (higher severity wins).

Staleness propagation: `mati init` propagates staleness scores through `Imports` edges. A file whose upstream dependency has high staleness inherits partial staleness via `propagated_staleness` in `FileRecord`.

---

## §18: Enforcement Event Log

Every hook decision is recorded in a hash-chained, monotonically sequenced event log persisted in `knowledge.db` under `enforcement:event:<seq_no>` keys.

**Chain structure:**
- Each event carries a SHA-256 `event_hash` of its own canonical serialization.
- Each event carries `prev_hash`: the `event_hash` of the immediately preceding event. Empty string for the first event.
- `seq_no` is globally unique, monotonically increasing, and persisted before the event that uses it.
- Gaps in `seq_no` are acceptable after a crash (produces a `RecordingGap` event on recovery). Hash chain breaks indicate tampering or corruption.
- `schema_version = 1` is frozen. Do not change field order or serialization without incrementing it.

**8 event types:**

| Event | Trigger |
|---|---|
| `Deny` | Pre-read hook blocked an unconsulted file read |
| `AllowAfterReceipt` | Pre-read hook allowed a read because a valid consultation receipt exists |
| `ReceiptMinted` | A one-time-use read receipt was created by `mem_get` |
| `BypassDetected` | A hook bypass was detected post-hoc |
| `ControlChanged` | A gotcha was created, confirmed, updated, or deleted |
| `EnforcementConfigChanged` | A configuration setting changed (records old and new value) |
| `RecordingGap` | Crash/restart gap detected on recovery; records cause, duration, enforcement mode during gap, and certainty |
| `RetentionPruned` | Events were pruned (enterprise retention policy) |

Each event also carries: `installation_id` (stable UUID generated at `mati init`), `actor_local` (OS username and uid, explicitly labeled unverified), `agent_type`, `subject_kind`, `subject_key`, `decision_reason_code`, and `decision_basis_hash` (hash of the gotcha/config state in force at decision time).

The enforcement event log is local and owned by the developer. The enterprise tier reads this log to generate signed audit artifacts; it does not add events to it.

---

## §19: CLI

All CLI commands write to stdout using `comfy-table` for structured output. No TUI framework.

| Command | Description |
|---|---|
| `mati init` | Layer 0 scan and project scaffold |
| `mati enrich [path]` | Layer 1 enrichment via Claude |
| `mati gotcha add` | Add a gotcha interactively |
| `mati gotcha confirm <key>` | Confirm a candidate and activate enforcement |
| `mati review` | Batch confirm or tombstone candidates |
| `mati status` | Knowledge health dashboard |
| `mati stats` | Coverage and onboarding score |
| `mati gaps` | Files with no records or low confidence |
| `mati stale` | Records that have not been touched since a file changed |
| `mati explain <file>` | File briefing: gotchas, blast radius, co-change partners, cluster membership |
| `mati clusters` | Co-change clusters from git history |
| `mati diff [range]` | Pre-merge check: surface gotchas for files in a git diff range (e.g. `main..feature`) |
| `mati show <key>` / `mati ls` | Browse records; `mati history` is an alias for time-ordered listing |
| `mati repair` | Reconcile derived indexes against canonical records |
| `mati repair --check` | Detect index drift without writing (CI-safe, exits non-zero) |
| `mati repair --fast` | Drain dirty-marker queue only (not a full integrity proof) |
| `mati doctor` | Aggregated health check; CI gate command |
| `mati daemon start/stop/status` | Manage the background daemon |
| `mati check` | Environment self-test |
| `mati hooks` | Install pre-read and pre-bash hooks into `.claude/settings.json` (`--claude`/`--codex` flags) |
| `mati reparse <file>` | Rebuild Layer 0 record for a single file |
| `mati import <file>` | Import records from a file (the `--pack` compliance-pack loader is a planned/enterprise feature, not in this repo) |
| `mati export` | Export knowledge records |
| `mati enable-semantic` _(planned)_ | Not yet implemented as a subcommand. The semantic/vector search layer is currently a build-time opt-in (`--features semantic`). |
| `mati config` | Show or update runtime configuration |
| `mati supervisor` | Generate a launchd or systemd unit for the daemon |

Color semantics:

| Color | Meaning |
|---|---|
| Red `#f85149` | Critical errors, blocked saves |
| Yellow `#d29922` | Warnings, stale, low confidence |
| Green `#3fb950` | Success, confirmed, healthy |
| Blue `#58a6ff` | Informational, section headers |
| Purple `#bc8cff` | Decisions, architectural items |
| Gray `#8b949e` | Metadata, timestamps, internal keys |
| Cyan `#39d353` | File paths |
| White `#e6edf3` | Primary content |

`mati doctor` is the CI gate command. It runs all health checks and exits non-zero on any failure. `mati repair --check` detects index drift without writing and is also CI-safe.

---

## §20: Versioning (Lamport Clock)

Each record carries a `RecordVersion`:

```rust
pub struct RecordVersion {
    pub device_id: DeviceId,  // UUID (currently v4 placeholder; v7 planned for mati init M-05)
    pub logical_clock: u64,   // Lamport clock, incremented on every local write
    pub wall_clock: u64,      // Display only, never used for conflict ordering
}
```

Wall clock is never used for conflict ordering. All ordering uses `logical_clock`. The intended conflict-resolution rule is that the higher `logical_clock` wins when two writes conflict (same key, different devices) — but this is unimplemented in v0.1: there is no sync path and no `MergeEngine`, so no conflict resolution runs yet.

`DeviceId` is intended to be a UUID generated once and stored in `~/.mati/config.toml`, stamping every record write for attribution and conflict resolution. The current implementation does **not** yet persist it: each command mints a fresh `Uuid::new_v4()` inline, so it is not stable across invocations. Stable persistence in `~/.mati/config.toml` and v7 generation (time-ordered, monotonic) are deferred to `mati init` M-05.

---

## §21: Durability

Write durability is split by key namespace. Never mix the two paths.

**Immediate (fsync before commit):**
`gotcha:*`, `decision:*`, `file:*`, `stage:*`, `dev_note:*`, `dep:*`, `enforcement:event:*` (default, not in SESSION_NAMESPACES)

**Eventual (OS write buffer):**
`session:*`, `analytics:*`, `hook_event:*`, `compliance:*`, `graph:edge:*`, `health:*`, `parse:*`, `audit:session:*`

Rationale: knowledge records (gotchas, files, decisions) must survive crashes because a partially-written gotcha with no file link is worse than no gotcha. Session and analytics records are reconstructible or disposable.

---

## §22: Gotcha Mutations

All gotcha create, edit, and tombstone paths go through `store::gotcha_ops`. Direct writes to gotcha records that bypass this module are a bug.

**Write order (partially atomic):**

1. Write canonical `gotcha:<slug>` record. Fails hard: if this step fails, nothing else is attempted.
2. Update `file:*` record's `gotcha_keys` list (best-effort; failure sets a dirty marker).
3. Write `HasGotcha` graph edge (best-effort; failure sets a dirty marker).

The canonical `gotcha:*` record is the source of truth. `file:*` gotcha_keys and `HasGotcha` graph edges are derived indexes.

**Recovery:**
- `mati repair` rebuilds derived state from canonical records and verifies consistency.
- `mati repair --check` detects drift without writing (CI-ready, exits non-zero on drift).
- `mati repair --fast` drains only the dirty-marker queue: not a full integrity proof.
- `mati status` surfaces dirty-state warnings when drift is detected.

If `gotcha_keys` and the `HasGotcha` graph edges disagree with the canonical `gotcha:*` record's `affected_files`, the gotcha record wins.

---

## §23: Daemon Lifecycle

The daemon writes structured events to `lifecycle.log` throughout its lifetime. `ensure_daemon` (in `src/mcp/daemon_lifecycle.rs`) reads this log to determine readiness rather than using timer-based polling.

Lifecycle phases logged by the daemon: `startup phase=opening_store`, `startup phase=store_opened`, `startup phase=ready`. The serve proxy logs `startup phase=ensure_daemon` before spawning the daemon, then its own `startup phase=ready` once the proxy is accepting MCP traffic. `serve_failed` is logged on any fatal error in either process.

The daemon registers a `panic_hook` that writes a `panic` event before unwinding (handled fatal errors instead write `serve_failed`, which `ensure_daemon` maps to `Failed`), so `ensure_daemon` can distinguish a daemon that died from a wedged one.

Unix socket path: `~/.mati/<slug>/mati.sock`. Peer credentials (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS, via tokio's `peer_cred()`) are checked; the daemon only accepts connections from the same UID. This same-UID check is the primary access control mechanism for the socket.

---

## §24: Known Limitations

**C9: bash `cat` bypass (~2-5% miss rate).**
`pre-bash.sh` catches `cat <file>` but not all variants. Variable expansion (`cat "$FILE"`), process substitution, piped input, and unusual quoting are not caught. This is a known and accepted limitation. The compliance monitor tracks and reports it. Do not attempt 100% coverage; the cost of false positives outweighs the marginal gain.

**petgraph is in-memory only.**
Edges are loaded from SurrealKV at daemon startup via a full `graph:edge:*` key scan. Any mutation must write back to SurrealKV immediately. Edges not written to SurrealKV are lost on restart.

**tree-sitter grammar crates must be ABI-compatible with the parser runtime.**
Each grammar must expose an ABI compatible with `tree-sitter = "0.23"` — not necessarily the same crate version. Most grammars pin to `"0.23"` (e.g. `tree-sitter-rust = "0.23"`), but some compatible grammars carry a different crate version (e.g. `tree-sitter-elixir = "0.3"`). An ABI-incompatible grammar causes silent parse failures, not errors or panics.

**`mati repair --fast` is not a full integrity guarantee.**
It only drains the dirty-marker queue: gotcha keys that were explicitly flagged during a partial-write failure. It cannot detect drift from manual store edits, bugs in other write paths, or unflagged failures. Use `mati repair` (full scan) for authoritative verification.

**`confirmed: false` records are Layer 0 stubs.**
They exist as graph nodes and gap signals but are never injected into hooks or `mem_bootstrap` critical paths. A `confirmed: false` record with `confidence >= 0.6` will not trigger enforcement; `confirmed` is checked first.

**The hook fast-path checks daemon reachability before enforcing.**
It calls `ensure_daemon` (which pings the daemon internally) rather than invoking `mati ping` directly. If the daemon is unreachable, hooks pass through unconditionally (P9). mati sets an internal deadline of 2,500ms (`HOOK_DEADLINE_MS`), giving itself a 500ms buffer before Claude Code's 3,000ms SIGKILL fires. Do not add blocking I/O to the hook fast-path that could exceed this budget.

**`with_versioning(true, 0)` on `knowledge.db` means indefinite retention.**
The `0` argument is not "disabled". It means retain all versions forever. This is intentional for knowledge records. Sessions use the 90-day retention value. Do not change the knowledge.db versioning config without understanding the storage implications.
