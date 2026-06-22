# ARCHITECTURE.md: mati

Code comments and other docs use the `§N` shorthand for cross-references, for example `§10.1`. Those numbers point to the section headings in this document.

---

## §1: Overview

mati is an enforcement layer for what a team knows about its own codebase. Not just a passive memory store that an agent might consult if it happens to ask.

When Claude Code reads a file, mati can require the relevant institutional knowledge to be surfaced first. On Codex, the same idea applies to `apply_patch` edits through the pre-edit hook. In those enforced paths, if the agent has not consulted the attached knowledge yet, mati can stop the operation until it does.

That distinction is the point. Most “memory for AI” tools are opt-in. They store context, and the model may or may not retrieve it. mati works differently. The decision happens at the hook layer, deterministically, outside the model’s discretion. If a file has a confirmed, high-confidence gotcha attached and the agent has not consulted it, the hook denies the read, or the Codex patch edit, until the consultation happens.

So the captured knowledge cannot be quietly skipped.

What mati enforces is the stuff developers usually carry around in their heads: per-file gotchas, architectural decisions, weird project state, and the implementation details that never make it into comments. It captures those records, lets developers confirm them, then makes them queryable, measurable, and, where it matters, mandatory.

It also leaves a local audit trail. Deny decisions, allow-after-receipt decisions, and consultation receipts are written to a hash-chained event log, so there is a record that the knowledge was actually put in front of the agent.

The larger purpose is institutional memory that survives turnover. The kind of knowledge that otherwise lives in Slack, in a half-remembered incident, or nowhere useful at all. Enforcement is what keeps that memory from being ignored the moment it becomes inconvenient.

There is a side benefit: a high-confidence record can sometimes replace a full file read and reduce token usage. Useful. But not the reason mati exists.

---

## §2: Design Principles

**P1: Hook enforcement comes first. Prompt injection is secondary.**

The pre-read hook’s DENY/ALLOW/advisory decision is the canonical enforcement path. Whatever Claude receives through the MCP tool result is extra context, not the authority.

**P2: Inject nothing by default. Context is pulled only when asked for.**

mati does not push records into Claude’s context at session start. `mem_bootstrap` is an explicit call. Hook injection happens because a file was accessed, not because a session began.

There is one deliberate exception: the passive “Suggested Actions” nudge appended to MCP tool results in `mcp/tools.rs`. It surfaces possible next steps, but it does not inject record content.

**P3: Four MCP tools, no more.**

The exposed tools are `mem_get`, `mem_query`, `mem_bootstrap`, and `mem_set`.

Every tool definition costs tokens on every Claude call. If a fifth tool feels necessary, redesign the feature as a parameter on an existing tool first. This is a hard code-review constraint.

**P4: Memory must reflect developer intent.**

Unconfirmed gotcha records never influence hook enforcement. They exist in the graph and can show up in `mem_bootstrap` as review candidates, but they cannot trigger Deny, and they cannot trigger the gotcha-based context injection path in §10.1 step 4.

The Advisory path in §10.1 step 5 is separate. It uses the file record’s own confidence and quality scores. Those are not tied to any gotcha’s confirmation state.

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

## §3: Repository Layout

```text
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
│       ├── decide.rs        # pure enforcement decision, no I/O
│       ├── pre_read.rs      # pre-read hook adapter
│       ├── pre_bash.rs      # pre-bash hook adapter
│       └── compliance.rs    # compliance event recording
```

---

## §4: Runtime Architecture

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

### §4.1: `mati daemon stop` semantics

| Flag                    | Effect                                                                                         |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| default                 | Sends SIGTERM, then escalates to SIGKILL on timeout. Serve proxies auto-respawn transparently. |
| `--force`               | Sends SIGKILL directly, with no SIGTERM grace. Serve proxies still auto-respawn.               |
| `--include-mcp`         | Also kills all `mati serve` processes. MCP sessions die.                                       |
| `--force --include-mcp` | Sends SIGKILL to the daemon, then SIGKILL to all serves.                                       |

### §4.2: State-aware daemon readiness

`ensure_daemon`, in `src/mcp/daemon_lifecycle.rs`, checks daemon readiness by polling `lifecycle.log` for startup events. It does not rely on timer-based polling.

The public function returns a `bool`. Internally, it calls `wait_for_ready`, which returns the more detailed `ReadinessOutcome` listed below. `ensure_daemon` then collapses that to `true` for `Ready`, and `false` for everything else.

| `ReadinessOutcome` | Condition                                              |
| ------------------ | ------------------------------------------------------ |
| `Ready`            | `startup phase=ready` event received and ping succeeds |
| `Failed`           | `serve_failed` or `panic` event received               |
| `Wedged`           | No new event for 15 seconds                            |
| `HardCap`          | Absolute 60-second budget elapsed                      |

### §4.3: Durability split

Write durability is assigned by key namespace. Do not mix the paths. `durability.rs` treats this table as canonical.

| Durability           | Namespaces                                                                                                    |
| -------------------- | ------------------------------------------------------------------------------------------------------------- |
| Immediate (fsync)    | `gotcha:*` `decision:*` `file:*` `stage:*` `dev_note:*` `dep:*`                                               |
| Eventual (OS buffer) | `session:*` `analytics:*` `hook_event:*` `compliance:*` `graph:edge:*` `health:*` `parse:*` `audit:session:*` |

Unknown prefixes default to Immediate. See §21 for the rationale.

---

## §5: Data Model

All types live in `src/store/record.rs`. Do not redefine them somewhere else because they look “simple enough.” That drift gets expensive.

### §5.1: Record

`Record` is the universal store entry. Every category uses this struct.

| Field                | Type                | Notes                                                                              |
| -------------------- | ------------------- | ---------------------------------------------------------------------------------- |
| `key`                | `String`            | Namespaced primary key and graph node key                                          |
| `value`              | `String`            | Human-readable content: rule, purpose, body. Indexed by tantivy.                   |
| `category`           | `Category`          | Gotcha, File, Decision, Stage, Dependency, DevNote, Session, Analytics             |
| `priority`           | `Priority`          | Low < Normal < High < Critical. Do not reorder variants because `Ord` is derived.  |
| `tags`               | `Vec<String>`       | Free-form. Used for search and filtering.                                          |
| `created_at`         | `u64`               | Unix seconds                                                                       |
| `updated_at`         | `u64`               | Unix seconds                                                                       |
| `ref_url`            | `Option<String>`    | PR, issue, doc, or incident link. Boosts confidence 1.5x when set.                 |
| `staleness`          | `StalenessScore`    | See §17                                                                            |
| `lifecycle`          | `RecordLifecycle`   | Active, Tombstoned, Superseded                                                     |
| `version`            | `RecordVersion`     | Lamport clock + device ID. See §20.                                                |
| `quality`            | `QualityScore`      | See §13.2                                                                          |
| `access_count`       | `u32`               | Total reads through `mem_get` or hooks                                             |
| `last_accessed`      | `u64`               | Unix seconds                                                                       |
| `source`             | `RecordSource`      | StaticAnalysis, ClaudeEnrich, SessionHook, DeveloperManual, Import                 |
| `confidence`         | `ConfidenceScore`   | See §13.1                                                                          |
| `gap_analysis_score` | `f32`               | `change_frequency * (1 - coverage_score)`                                          |
| `payload`            | `Option<JsonValue>` | Typed per-category data, such as FileRecord or GotchaRecord, stored as MessagePack |

### §5.2: FileRecord

Stored under `file:<path>`. The `FileRecord` is attached to the base `Record` through `payload`.

| Field                  | Notes                                                                                     |
| ---------------------- | ----------------------------------------------------------------------------------------- |
| `path`                 | Repo-relative file path                                                                   |
| `purpose`              | One-sentence summary. Empty at Layer 0, filled by Layer 1 enrichment.                     |
| `entry_points`         | Public functions and types visible from other modules                                     |
| `imports`              | Import/use paths found by tree-sitter                                                     |
| `gotcha_keys`          | Keys of associated `gotcha:*` records. Derived index; see §22.                            |
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

### §5.3: GotchaRecord

Stored under `gotcha:<slug>`. Like `FileRecord`, it is attached to the base `Record` through `payload`.

| Field            | Notes                                                                                   |
| ---------------- | --------------------------------------------------------------------------------------- |
| `rule`           | Actionable statement. For Good quality, it must start with an imperative verb.          |
| `reason`         | Why the rule exists. Must include a causality word such as “because”, “since”, or “as”. |
| `severity`       | Priority enum: Low, Normal, High, Critical                                              |
| `affected_files` | Canonical source of truth for which files this gotcha applies to                        |
| `ref_url`        | Optional link to the incident or PR that produced this rule                             |
| `confirmed`      | `false` means Layer 0 candidate stub, never injected. `true` means developer-validated. |

`confirmed: false` records exist as graph nodes and gap signals. They are not used in hook enforcement. A gotcha can trigger a deny only when `confirmed: true`, `confidence >= 0.6`, and `quality >= 0.4`.

### §5.4: Quality Score formula

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

## §6: Context Packet (`mem_bootstrap`)

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

## §7: Key Namespacing

Store keys follow this convention:

```text
gotcha:<slug>          file:<path>           decision:<slug>
stage:current          dep:<ecosystem>:<name> dev_note:<slug>
session:<timestamp>    analytics:<type>_<date>
graph:edge:<from>:<kind>:<to>
enforcement:event:<seq_no>
```

`file:<path>` uses repo-relative paths, normalized lexically. The store key itself does not resolve symlinks; on case-insensitive filesystems, case-folding is applied. Enforcement adds a canonical-key fallback (§24) so a read or edit routed through an in-repo symlink to a gotcha'd file still trips the gate.

---

## §8: Storage Layer

Each project gets two SurrealKV trees under `~/.mati/<slug>/`.

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

## §9: Graph Layer

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

## §10: Hook Pipeline

Hooks are shell scripts installed by `mati hooks` into the project’s `.claude/settings.json`. The command writes files under `.claude/` inside the repository root. Hooks run on `PreToolUse`, before Claude reads a file or runs a bash command, and on `PostToolUse`, after the tool call.

The decision engine in `src/hooks/decide.rs` is pure. No I/O, no daemon calls. The adapter layer in `src/cli/hook_decide.rs` maps semantic decisions to protocol output:

- JSON for Claude Code, which runs the hook as a shell subprocess and reads stdout
- exit codes for environments that support the Codex hook protocol

Hook-based enforcement, meaning the Deny/Advisory path in §10.1, requires the host environment to install and execute the hook scripts. Claude Code does this natively.

Codex hook execution depends on the agent configuration. If hooks are not running, enforcement falls back to MCP-only behavior: `mem_get` still mints consultation receipts, but no file reads are blocked. Other MCP-compatible agents that do not run hooks get tool access only.

### §10.1: Decision Matrix

Decisions are evaluated in this order:

```text
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

6. default
   -> Allow: pass through, no injection
```

`confidence < 0.3` or `quality < 0.4` always allows without injection, no matter what the `confirmed` state says.

### §10.2: Command Classification (pre-bash)

The pre-bash hook classifies shell commands before they run.

- **CatLike**: `cat`, `less`, `head`, `tail`, `bat`. The file path is extracted from the first non-flag argument.
- **GrepLike**: `grep`, `rg`, `sed`, `awk`. The file path is extracted from the last non-flag argument.
- Anything else is not treated as a file-read operation and passes through unconditionally.

Known limitation: `cat` with variable expansion, process substitution, or unusual quoting is not caught. The accepted miss rate is 2-5%. See §24.

### §10.3: Edit Gating (Codex `apply_patch`)

On Codex, the `apply_patch` `PreToolUse` hook (`codex-pre-apply-patch`) gates file edits the same way pre-bash gates reads.

The payload is the raw patch envelope in `tool_input.command`. `decide::extract_apply_patch_files` parses the column-0 markers:

```text
*** Update File:
*** Add File:
*** Delete File:
*** Move to:
```

Those markers become the touched paths. Each path is then run through the same §10.1 decision matrix. If any touched file has an unconsulted confirmed gotcha, the edit is denied with exit 2 and stderr. A `mem_get` consultation receipt clears it, just like reads.

Because the envelope gives mati the exact target path, edit gating is not affected by the shell-wrapper obfuscation that limits pre-bash read detection in §10.2 and §24. There is no command string to misparse.

It fails open on every uncertainty: unparseable patch, unreachable daemon, per-file lookup error, more than `MAX_APPLY_PATCH_FILES = 50` touched files, or an older binary that does not recognize the variant. Blocking all edits by mistake would be worse than missing one gotcha. The wrapper script in `codex_pre_apply_patch.rs` enforces that bias by treating only `exit 2` with a `mati:` message as a real deny.

Coverage depends on platform support. Codex fires `PreToolUse` for `apply_patch` since openai/codex PR #18391, but not for its native file-read tool, so reads are gated only through the shell path. Claude Code edits are covered primarily by the read gate, transitively: Claude Code's own read-before-edit rule forces a prior read, which the read gate gates — and a *naive* blind edit is stopped by Claude Code's "File must be read first" guard *before any PreToolUse hook runs* (confirmed by live test 2026-06-18: a blind Edit yielded Claude Code's built-in guard, not a mati deny; enforcement came from the read gate). The `claude-pre-edit` hook (the `ClaudePreEdit` adapter, PreToolUse on `Edit`/`Write`/`NotebookEdit`) is therefore a BACKSTOP, not the primary blocker: keyed on `consulted_recent` (TTL, like the Codex `apply_patch` edit gate), it denies via `permissionDecision: deny` only an edit whose consultation has gone stale, or one that satisfied read-before-edit via a shell read the best-effort pre-bash path missed (e.g. `cat "$VAR"`; `egrep`/`fgrep` are now detected). Non-deny outcomes defer to the normal permission flow (edits are permission-required, unlike reads, so emitting `allow` would suppress the user's edit prompt). The `consulted_recent` keying is load-bearing: with the read gate's persistent `consulted`, the edit gate would never fire, since the forced read always consults first.

### Sandbox floor (L3, opt-in)

The hook gates above cover the agent's *tool* surface; they cannot reach the shell's *subprocess* surface beyond best-effort command parsing (`cat "$VAR"`, a `python` script, a symlink). For a small crown-jewel tier, `mati sandbox` compiles an **OS-level floor** that closes that gap: confirmed gotchas tagged `crown-jewel` (and `sandbox-deny-read` for secrets) become `sandbox.filesystem.denyWrite`/`denyRead` entries in `.claude/settings.local.json`, enforced by Claude Code's sandbox (Seatbelt on macOS, bubblewrap on Linux/WSL2) across the shell *and every subprocess it spawns*. For a crown-jewel file the shell path is then denied at the OS level, leaving the consultation-gated Read/Edit tools as the only way the agent can touch it (L1 + L3 compose to "reachable only via the gate").

Design invariants (each verified — see `MATI-SOTA-ARCHITECTURE.md` L3): explicit-tag-only, never severity-derived; **absolute canonical paths** (CC's `./` resolution is undocumented, so a relative deny could silently fail to match — a live Seatbelt + Claude Code test confirmed absolute paths enforce and resist symlink bypass); mati owns only the `denyRead`/`denyWrite` entries under the repo root, preserving the user's `~/`/out-of-repo denies via CC's documented array-union + deny-wins across scopes; out-of-repo paths are skipped so a gotcha can never deny `~`/`/etc`; preview-default and reversible (`clear`/`unprotect`); a drift guard refuses to silently remove a protection whose tag was dropped. mati never writes `sandbox.enabled` — enablement is the user's (`/sandbox`) or the Enterprise managed-settings tier's. Commands: `mati sandbox protect <file> [--read]`, `unprotect <file>`, `compile [--apply]`, `clear`.

---

## §11: MCP Server

The MCP server lives in `src/mcp/`. It uses the `rmcp` crate, the Rust MCP SDK, for stdio transport.

Exactly four tools are exposed. This is a hard constraint from P3. Every tool definition costs tokens on every Claude call.

| Tool            | Description                                                                                                        |
| --------------- | ------------------------------------------------------------------------------------------------------------------ |
| `mem_bootstrap` | Returns a `ContextPacket` for the current session. Token-budgeted to 2,000 tokens.                                 |
| `mem_get`       | Looks up a single record by key. Returns the full `Record` JSON. Mints a consultation receipt.                     |
| `mem_query`     | Text search, using BM25 through tantivy, plus optional graph traversal. Supports `mode="text"` and `mode="graph"`. |
| `mem_set`       | Writes a record. Triggers quality recomputation, graph edge updates, and search index update.                      |

`mati serve` runs the rmcp stdio loop and proxies every tool call to `mati daemon` over a Unix domain socket. The daemon handles the call and returns the result.

---

## §12: Static Analysis (Layer 0)

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

## §13: Health System

### §13.1: Confidence Score

Confidence measures how much the system trusts a record’s accuracy.

```text
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

Recomputation is implemented as a pure function, `health::confidence::recompute`, but it is **not wired into the `mem_get` path yet**. Right now, `mem_get` only bumps `access_count`. Automatic recomputation on access is planned.

One small but important note: `file:*` records are written on the Immediate path, not the Eventual path.

Confidence feeds into two different paths in §10.1.

| Path                    | Condition                                                                                | Behavior                                           |
| ----------------------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------- |
| Deny (§10.1 step 4)     | attached gotcha: `confirmed = true`, `confidence >= 0.6`, `quality >= 0.4`               | Block file read; require `mem_get` consultation    |
| Advisory (§10.1 step 5) | file record: `confidence >= 0.3`, `quality >= 0.4`, with no gotcha confirmation required | Allow read + attach context as `additionalContext` |
| No injection            | file record: `confidence < 0.3` or `quality < 0.4`                                       | Allow read unconditionally                         |

### §13.2: Quality Score

Quality tiers use half-open intervals.

| Tier       | Range      | Injection behavior                                          |
| ---------- | ---------- | ----------------------------------------------------------- |
| Suppressed | [0.0, 0.2) | Never injected                                              |
| Poor       | [0.2, 0.4) | Injected with `[mati] LOW QUALITY - verify` warning         |
| Acceptable | [0.4, 0.7) | Injected normally                                           |
| Good       | [0.7, 0.9) | Prioritized in `mem_bootstrap`                              |
| Excellent  | [0.9, 1.0] | Prioritized for template reuse, planned under `mati garden` |

See §5.4 for the formula.

### §13.3: Onboarding Score

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

## §14: Enrichment (Layer 1)

`mati enrich [path]` runs a four-stage per-file pipeline using Claude.

**Stage 1 (Setup):** Query existing confirmed gotchas for the directory and use them as positive examples. Call `mem_get("file:<path>")` to mint a consultation receipt and retrieve the `enrichment_depth_hint`: fast, standard, or deep. For the deep tier, also retrieve recently tombstoned gotchas as negative examples.

**Stage 2 (Enumeration):** Read the file. Extract gotcha candidates and rank them by signal tier:

- HIGH: WARNING/FIXME/HACK/SAFETY comments, `panic!` and `assert!` messages
- MEDIUM: defensive guards, non-obvious literals
- LOW: raw API usage

**Stage 3 (Critique loop):** Run up to three bounded rounds.

1. Specificity filter: discard candidates that are not specific, enforceable, non-obvious, and causal.
2. Cross-reference verification: call `mati verify-evidence`, a deterministic CLI, to confirm that each candidate’s file line and quote are real.
3. Stability check: repeat round 2 if round 2 discarded items. This allows cascading discard, with a maximum of 3 iterations.

**Stage 4 (Write):** For each verified candidate, tighten the rule, verify causality language, assign severity through a hybrid keyword and semantic classifier, then call `mem_set`.

Severity classification works like this:

- Keyword pass first. “panic”, “data loss”, or “corruption” becomes critical. “race” or “silent failure” becomes high. “performance” or “stale state” becomes normal.
- Semantic pass second, using LLM judgment against the same rubric.
- If both passes agree, use that severity. If they disagree, use the higher severity and tag the record `severity-disputed`.

After batch enrichment, run `mati review` to confirm candidates and activate enforcement. Single-file enrichment confirms each gotcha immediately through `mati gotcha confirm <key>`.

---

## §15: Session Model

Sessions use three layers of state in `sessions.db`, with Eventual durability.

**During the session:**

Each `mem_get` call writes `session:consulted:<key>`. This is the consultation receipt proving Claude read the record for that file. The TTL is 15 minutes, set by `CONSULTED_RECENT_TTL_SECS = 900`.

The hook decision engine checks for that key before choosing between Deny and AlreadyConsulted. See §10.1.

**On session flush:**

`session:current` is written with the full list of consulted keys from `session:consulted:*` markers. This interim record is used by harvest if the session ends without an explicit flush.

**On session end (`session_harvest`):**

The harvester reads `session:current`, then writes a final `session:<timestamp>` record summarizing files touched, gotchas encountered, and compliance rate. It also cleans up all `session:consulted:*` markers and runs staleness re-scoring on touched files.

The most recent session summary is meant to appear in the `ContextPacket` returned by `mem_bootstrap` as `recent_session`. Right now that field is always `None` because the assembler is not wired yet. See §6.

---

## §16: Search Layer

tantivy provides BM25 full-text search over the `value` field of all knowledge records. That field is the human-readable content: rule, purpose, body, and similar text.

The tantivy index lives next to the SurrealKV store under `~/.mati/<slug>/`.

It is rebuilt from the `knowledge.db` key scan in three cases:

- First startup after `mati init`, through the deferred indexing path
- Startup when the `search_stale` marker is present
- Startup when the `search_sync_pending` marker is present, for crash recovery

`mem_query mode="text"` runs a BM25 query and returns ranked records. `mem_query mode="graph"` traverses the petgraph edges from a starting node.

---

## §17: Staleness

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

| Tier      | Range      | Hook behavior                                                           |
| --------- | ---------- | ----------------------------------------------------------------------- |
| Fresh     | [0.0, 0.2) | Normal injection                                                        |
| Aging     | [0.2, 0.4) | Normal injection                                                        |
| Stale     | [0.4, 0.7) | Injected with staleness warning                                         |
| Liability | [0.7, 0.9) | Hook passes through; injects warning to read the file directly          |
| Tombstone | [0.9, 1.0] | Hook passes through unconditionally; record excluded from all injection |

At Tombstone, the record is fully excluded. Injecting a wrong record silently is worse than having a cache miss.

Sync merge rule, planned for v0.2: `Tombstone > Liability > Stale > Aging > Fresh`, meaning higher severity wins. There is no sync or conflict resolution in v0.1.

Staleness propagation happens during `mati init`. Staleness scores are propagated through `Imports` edges. A file whose upstream dependency has high staleness inherits partial staleness through `propagated_staleness` in `FileRecord`.

---

## §18: Enforcement Event Log

Every hook decision is recorded in a hash-chained, monotonically sequenced event log. The log is persisted in `knowledge.db` under keys like this:

```text
enforcement:event:<seq_no>
```

**Chain structure:**

- Each event carries a SHA-256 `event_hash` of its own canonical serialization.
- Each event carries `prev_hash`, which is the `event_hash` of the immediately preceding event. The first event uses an empty string.
- `seq_no` is globally unique, monotonically increasing, and persisted before the event that uses it.
- Gaps in `seq_no` are acceptable after a crash. Recovery produces a `RecordingGap` event. Hash chain breaks indicate tampering or corruption.
- `schema_version = 1` is frozen. Do not change field order or serialization without incrementing the schema version.

There are 8 event types:

| Event                      | Trigger                                                                                                          |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `Deny`                     | Pre-read hook blocked an unconsulted file read                                                                   |
| `AllowAfterReceipt`        | Pre-read hook allowed a read because a valid consultation receipt exists                                         |
| `ReceiptMinted`            | A one-time-use read receipt was created by `mem_get`                                                             |
| `BypassDetected`           | A hook bypass was detected after the fact                                                                        |
| `ControlChanged`           | A gotcha was created, confirmed, updated, or deleted                                                             |
| `EnforcementConfigChanged` | A configuration setting changed. Records old and new value.                                                      |
| `RecordingGap`             | Crash/restart gap detected on recovery. Records cause, duration, enforcement mode during the gap, and certainty. |
| `RetentionPruned`          | Events were pruned under enterprise retention policy                                                             |

Each event also carries:

```text
installation_id
actor_local
agent_type
subject_kind
subject_key
decision_reason_code
decision_basis_hash
```

`installation_id` is the stable UUID generated at `mati init`. `actor_local` includes OS username and uid, and is explicitly labeled unverified. `decision_basis_hash` is the hash of the gotcha/config state in force at decision time.

The enforcement event log is local and owned by the developer. The enterprise tier reads it to generate signed audit artifacts. It does not add events to the log.

---

## §19: CLI

All CLI commands write to stdout using `comfy-table` for structured output. There is no TUI framework.

| Command                            | Description                                                                                                                        |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `mati init`                        | Layer 0 scan and project scaffold                                                                                                  |
| `mati enrich [path]`               | Layer 1 enrichment through Claude                                                                                                  |
| `mati gotcha add`                  | Add a gotcha interactively                                                                                                         |
| `mati gotcha confirm <key>`        | Confirm a candidate and activate enforcement                                                                                       |
| `mati review`                      | Batch confirm or tombstone candidates                                                                                              |
| `mati status`                      | Knowledge health dashboard                                                                                                         |
| `mati stats`                       | Coverage and onboarding score                                                                                                      |
| `mati gaps`                        | Files with no records or low confidence                                                                                            |
| `mati stale`                       | Records that have not been touched since a file changed                                                                            |
| `mati explain <file>`              | File briefing: gotchas, blast radius, co-change partners, cluster membership                                                       |
| `mati clusters`                    | Co-change clusters from git history                                                                                                |
| `mati diff [range]`                | Pre-merge check: surface gotchas for files in a git diff range, such as `main..feature`                                            |
| `mati show <key>` / `mati ls`      | Browse records. `mati history` is an alias for time-ordered listing.                                                               |
| `mati repair`                      | Reconcile derived indexes against canonical records                                                                                |
| `mati repair --check`              | Detect index drift without writing. CI-safe, exits non-zero.                                                                       |
| `mati repair --fast`               | Drain dirty-marker queue only. Not a full integrity proof.                                                                         |
| `mati doctor`                      | Aggregated health check and CI gate command                                                                                        |
| `mati daemon start/stop/status`    | Manage the background daemon                                                                                                       |
| `mati check`                       | Environment self-test                                                                                                              |
| `mati hooks`                       | Install pre-read and pre-bash hooks into `.claude/settings.json`, with `--claude` / `--codex` flags                                |
| `mati reparse <file>`              | Rebuild Layer 0 record for a single file                                                                                           |
| `mati import <file>`               | Import records from a file. The `--pack` compliance-pack loader is planned/enterprise and is not in this repo.                     |
| `mati export`                      | Export knowledge records                                                                                                           |
| `mati enable-semantic` _(planned)_ | Not implemented as a subcommand yet. The semantic/vector search layer is currently a build-time opt-in with `--features semantic`. |
| `mati config`                      | Show or update runtime configuration                                                                                               |
| `mati supervisor`                  | Generate a launchd or systemd unit for the daemon                                                                                  |

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

## §20: Versioning (Lamport Clock)

Each record carries a `RecordVersion`.

```rust
pub struct RecordVersion {
    pub device_id: DeviceId,  // UUID (currently v4 placeholder; v7 planned for mati init M-05)
    pub logical_clock: u64,   // Lamport clock, incremented on every local write
    pub wall_clock: u64,      // Display only, never used for conflict ordering
}
```

Wall clock is display-only. It is never used for conflict ordering. Ordering uses `logical_clock`.

The intended conflict-resolution rule is simple: when two writes conflict, meaning the same key from different devices, the higher `logical_clock` wins. That rule is not implemented in v0.1. There is no sync path and no `MergeEngine`, so conflict resolution does not run yet.

`DeviceId` is intended to be generated once and stored in `~/.mati/config.toml`. It should stamp every record write for attribution and later conflict resolution. The current implementation does **not** persist it yet. Each command mints a fresh `Uuid::new_v4()` inline, which means it is not stable across invocations.

Stable persistence in `~/.mati/config.toml`, plus v7 generation for time-ordered monotonic IDs, is deferred to `mati init` M-05.

---

## §21: Durability

Write durability is split by key namespace. Do not mix the paths.

**Immediate, fsync before commit:**

```text
gotcha:*
decision:*
file:*
stage:*
dev_note:*
dep:*
enforcement:event:*  (default, not in SESSION_NAMESPACES)
```

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

## §22: Gotcha Mutations

All gotcha create, edit, and tombstone paths go through `store::gotcha_ops`. A direct write to a gotcha record that bypasses this module is a bug.

**Write order, partially atomic:**

1. Write the canonical `gotcha:<slug>` record. This fails hard. If this step fails, nothing else is attempted.
2. Update the `file:*` record’s `gotcha_keys` list. Best effort; failure sets a dirty marker.
3. Write the `HasGotcha` graph edge. Best effort; failure sets a dirty marker.

The canonical `gotcha:*` record is the source of truth. `file:*` `gotcha_keys` and `HasGotcha` graph edges are derived indexes.

**Recovery:**

- `mati repair` rebuilds derived state from canonical records and verifies consistency.
- `mati repair --check` detects drift without writing. It is CI-ready and exits non-zero on drift.
- `mati repair --fast` drains only the dirty-marker queue. It is not a full integrity proof.
- `mati status` surfaces dirty-state warnings when drift is detected.

If `gotcha_keys` and `HasGotcha` graph edges disagree with the canonical `gotcha:*` record’s `affected_files`, the gotcha record wins.

---

## §23: Daemon Lifecycle

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

## §24: Known Limitations

**C9: bash `cat` bypass, around 2-5% miss rate.**

`pre-bash.sh` catches `cat <file>`, but not every variant. Variable expansion (`cat "$FILE"`), process substitution, piped input, and unusual quoting are not caught. This is known and accepted. The compliance monitor tracks and reports it. Do not chase 100% coverage here; the false positives are not worth the marginal gain.

**In-repo symlink access resolves to the real target for enforcement (WI-20).**

A gotcha is keyed by the lexical repo-relative path, so an agent could route around the gate by reading or editing a gotcha'd file through a symlink whose key differs. The read/edit decision path adds an escalate-only canonical-key fallback: when the lexical gate does not deny, it resolves the accessed path through symlinks (shared with the L3 sandbox's `canonicalize_lenient`), strips the canonicalized repo root, and evaluates the real target's key too — adopting that result only when it denies. It is fully fail-open (no repo root, a `canonicalize` failure, an out-of-repo target, or an identical key all leave the lexical decision intact) and costs one extra `realpath` plus one daemon round-trip, only on the non-deny path. This closes the in-repo symlink bypass at the hook level (L1). It does not change the lexical store key. Hardlink aliases (which `canonicalize` does not resolve) and out-of-tree targets remain out of scope for the hook tier; the L3 OS floor (`mati sandbox`) is what denies crown-jewel files across the shell and its subprocesses.

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

mati sets an internal deadline of 2,500ms with `HOOK_DEADLINE_MS`. That leaves a 500ms buffer before Claude Code’s 3,000ms SIGKILL. Do not add blocking I/O to the hook fast-path if it could exceed that budget.

**`with_versioning(true, 0)` on `knowledge.db` means indefinite retention.**

The `0` argument is not “disabled.” It means retain all versions forever. This is intentional for knowledge records. Sessions use the 90-day retention value. Do not change the `knowledge.db` versioning config unless you understand the storage implications.
