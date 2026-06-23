# mati

mati makes what your team knows about a codebase enforceable in the paths where AI agents touch it. It is not another memory store the model can choose to recall or ignore. When an agent goes to act on a file that has a confirmed gotcha attached, mati's hook surfaces that gotcha and can block the operation until it has been consulted. The decision is made at the hook level, deterministically, outside the model's discretion.

Coverage today: Claude Code gates file reads and edits (`Edit`/`Write`/`NotebookEdit`), Codex gates `apply_patch` edits, and both catch shell-command reads (`cat`, `grep`, and similar commands) on a best-effort basis.

Single Rust binary. MCP stdio server. Claude Code and Codex integration.

Compliance and audit exports live in the Enterprise tier ([getmati.dev](https://getmati.dev)).

---

## The problem

A lot of what you know about a codebase never makes it into the codebase. Why `with_versioning(true, 0)` means indefinite retention and not "disabled." Why a piece of auth middleware does something non-obvious. Why the test suite has to run under `cargo nextest` instead of vanilla `cargo test`. It lands in Slack threads, in review comments, or in a markdown file nobody opens.

When the person who knew it leaves, it's gone. When Claude opens the same file for the twentieth time, you explain it again from scratch.

And even when it _is_ written down, it gets ignored. A comment, a doc, a CONTRIBUTING note: an AI agent (or a hurried teammate) reads right past it. Knowledge that exists but isn't consulted is the same as knowledge that doesn't exist.

mati captures that knowledge as structured records attached to files, confirmed by developers, and enforced at the hook level where the agent integration supports it. In those paths, the agent does not get to read or edit first and discover the gotcha later. The relevant knowledge is surfaced before the operation proceeds.

---

## Why it matters

The cost of lost or ignored knowledge scales with your team, and now with the number of AI agents touching your code.

- **Agents stop repeating known mistakes.** An agent that doesn't know why `with_versioning(true, 0)` is intentional may "fix" it. mati makes it read the reason first when that gotcha is confirmed, attached to the file, and reached through an enforced hook path.
- **Knowledge survives turnover.** When the person who understood a subsystem leaves, the gotchas they confirmed stay attached to the files. The next developer, and the next agent, still get them.
- **Onboarding gets faster, and you can measure it.** `mati stats` reports coverage and an onboarding score, so knowledge health is a number you can track, not a feeling.
- **Enforcement is auditable.** Deny decisions, allow-after-receipt decisions, and consultation receipts are written to a local, hash-chained log. You can show that a rule was put in front of the agent, not just that it was written down somewhere.

---

## What this looks like

A confirmed gotcha is a small structured record attached to a file:

```text
gotcha:surrealkv-versioning   (file: src/store/db.rs)
rule:     Never pass 0 as the retention arg to with_versioning.
reason:   0 means "retain all versions forever," not "disabled."
severity: high   confirmed: true
```

When an agent tries to read or edit `src/store/db.rs` through Claude Code, or patch-edit it through Codex, without consulting it, the hook blocks the operation and hands back the rule instead of letting the agent guess:

```text
[mati] read of src/store/db.rs blocked
mati: call mem_get("file:src/store/db.rs") first
```

The agent reads the reason, then proceeds. In the enforced path, it does not get to skip it.

---

## Who it's for

- **Solo developers** tired of re-explaining the same context to an agent. Free, local, no account.
- **Teams shipping with AI agents**, where the same codebase mistakes resurface across people, sessions, and agents.
- **Regulated or audit-conscious orgs** that need a tamper-evident record that a rule was enforced, not just documented.

---

## How it works

mati runs as two processes:

```
   Claude Code / Codex
        | stdio (MCP)
  ┌─────▼──────┐        ┌──────────────────────┐
  │ mati serve │  UDS   │ mati daemon          │
  │ (MCP proxy)│◄──────►│ SurrealKV + graph    │
  └────────────┘        │ Tantivy search       │
                        │ idle-shutdown        │
                        └──────────────────────┘
```

`mati serve` is a thin MCP-stdio forwarder. It starts the daemon if one isn't already running, then proxies tool calls over a Unix socket.

`mati daemon` owns the store. It holds the SurrealKV lock, answers queries, and shuts down after 30 minutes idle with no active connections.

### The four MCP tools

mati exposes exactly four tools. That's a hard constraint: every tool definition costs tokens on every call.

| Tool            | What it does                                                    |
| --------------- | --------------------------------------------------------------- |
| `mem_bootstrap` | Returns a token-budgeted context packet for the current session |
| `mem_get`       | Looks up a record by key (`file:<path>`, `gotcha:<slug>`, etc.) |
| `mem_query`     | Text search + graph traversal                                   |
| `mem_set`       | Writes a record                                                 |

### Records and gotchas

Every file gets a `file:<path>` record: a purpose summary, entry points, and the keys of any attached gotchas. Gotchas are the core unit, each one a rule, a reason, a severity, and a `confirmed` flag.

Unconfirmed gotchas are candidates. They sit in the graph but don't change the agent's behavior. Confirming one turns on enforcement for it.

Enforcement keys on gotchas, against a single threshold. If a gotcha is `confirmed = true` with `confidence >= 0.6` and `quality >= 0.4`, its hook can deny the operation outright (a Claude Code read or edit, or a Codex `apply_patch` edit) and hand the agent the gotcha instead. File records have no `confirmed` flag; they drive a separate, lower-confidence advisory path that attaches context without ever blocking.

### Static analysis

`mati init` runs a Layer 0 scan with no LLM calls: tree-sitter parsing across 12 languages, import-graph construction, and co-change clustering from git history.

`mati enrich` runs Layer 1 through Claude Code: Claude reads each file and extracts gotcha candidates via a four-stage pipeline (setup, enumeration, critique loop, write). Run `mati review` afterward to confirm candidates and turn on enforcement.

---

## Quick start

```bash
# Install
cargo install mati

# Initialize a project and install the agent integration. Runs the Layer 0
# scan, then installs the MCP server (.mcp.json) and the enforcement hooks
# (.claude/settings.json). Use --codex for the Codex integration instead.
cd your-project
mati init --claude

# The hooks are what enforce. Without them you get tool access but no
# blocking. To (re)install just the hooks later, without a full re-init:
#   mati hooks --claude     # or: mati hooks --codex

# Enrich a file or directory
mati enrich src/auth/

# Review candidates and activate enforcement
mati review

# Check knowledge health
mati status
mati stats
```

---

## CLI reference

| Command                         | What it does                                                                 |
| ------------------------------- | ---------------------------------------------------------------------------- |
| `mati init`                     | Layer 0 scan and scaffold                                                    |
| `mati enrich [path]`            | Layer 1 enrichment via Claude                                                |
| `mati gotcha add`               | Add a gotcha interactively                                                   |
| `mati gotcha confirm <key>`     | Confirm a candidate and activate it                                          |
| `mati review`                   | Batch confirm or tombstone candidates                                        |
| `mati status`                   | Knowledge health dashboard                                                   |
| `mati stats`                    | Coverage and onboarding score                                                |
| `mati gaps`                     | Files with no records or low confidence                                      |
| `mati stale`                    | Records that haven't been touched since a file changed                       |
| `mati explain <file>`           | File briefing: gotchas, blast radius, co-change partners, cluster membership |
| `mati clusters`                 | Co-change clusters from git history                                          |
| `mati diff [range]`             | Pre-merge check: surface gotchas for files in a git diff range               |
| `mati sandbox protect <file>`   | Compile a crown-jewel file into an OS-level sandbox deny floor (opt-in, macOS/Linux/WSL2) |
| `mati repair`                   | Reconcile derived indexes against canonical records                          |
| `mati repair --check`           | Same, exits non-zero if drift is found (CI-safe)                             |
| `mati doctor`                   | Aggregated health check                                                      |
| `mati daemon start/stop/status` | Manage the background daemon                                                 |
| `mati check`                    | Environment self-test                                                        |

---

## Stack

These are locked. Don't swap them without a strong, documented reason.

| Crate                  | Purpose                                       |
| ---------------------- | --------------------------------------------- |
| `surrealkv`            | Primary KV store. SurrealKV, not redb or sled |
| `petgraph`             | In-memory graph. Edges persisted in SurrealKV |
| `tantivy`              | Full-text BM25 search                         |
| `rmcp`                 | MCP stdio server (Rust MCP SDK)               |
| `tree-sitter`          | Static analysis parser, 12 language grammars  |
| `ignore`               | Repo walking, respects `.gitignore`           |
| `git2`                 | Git history mining                            |
| `rayon`                | Parallel file processing                      |
| `clap` + `comfy-table` | CLI. No TUI framework, no ratatui             |

The semantic layer (vector search via `candle` + `usearch`) is feature-gated behind `--features semantic`. It isn't compiled into the default binary.

---

## Free local tool, paid audit layer for teams

mati is the complete product for a solo developer, and all of it is free. From the first run, the enforcement engine records deny decisions, allow-after-receipt decisions, and consultation receipts (plus control and config changes) to a hash-chained, append-only event log. That log stays local and yours.

**mati Enterprise** reads that log and turns it into signed audit artifacts for teams at regulated companies:

- Signed audit PDF export (cryptographically signed, tamper-evident)
- Enforcement reports tied to license state
- Extended retention controls _(in development)_

Also Enterprise-only, and not in this repo: multi-repo sync and a cross-repo gotcha registry; SSO, SAML, OIDC, RBAC; managed Slack / Teams / PagerDuty integration; compliance packs for HIPAA, SOC 2, and PCI; and a centralized governance dashboard.

Enterprise is a reporting layer on top of the local log. The enforcement path itself is identical in both tiers: local-only, deterministic, zero network calls. mati never phones home.

See [getmati.dev](https://getmati.dev) for the Enterprise tier.

---

## Contributing

See `CONTRIBUTING.md` for how to contribute and what's in scope (mati is open core, so some features live in the commercial tier). `ARCHITECTURE.md` has the data model, hook decision matrix, and process lifecycle.

Tests run under `cargo-nextest`:

```bash
cargo install cargo-nextest --locked
cargo nextest run --lib
```

Vanilla `cargo test` works but is constrained to single-threaded execution. See `CLAUDE.md` for why.

---

## The name

**mati** is a Nahuatl verb meaning "to know" or "to think." UNAM's Gran Diccionario Náhuatl lists it as transitive: _nicmati_ is "I know it," _quimati_ is "he or she knows it" ([source](https://gdn.iib.unam.mx/diccionario/mati/182730)). The tool's job is the same: know what matters about your codebase, and make sure it is actually used instead of explained again and again.

---

## License

mati is released under the [MIT License](LICENSE). The "mati" name and logo are trademarks of the project. See [TRADEMARK.md](TRADEMARK.md).
