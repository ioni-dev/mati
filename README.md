# mati

A knowledge store for codebases. It stores what you've learned about each file, injects the relevant records before Claude reads, and blocks reads it can already answer.

Single Rust binary. MCP stdio server. Claude Code plugin.

For compliance teams that need signed audit trails and SOC 2/HIPAA evidence, see [mati Enterprise](https://mati.dev).

---

## The name

**mati** is a Nahuatl verb. It means "to know" or "to think." UNAM's Gran Diccionario Náhuatl defines it as a transitive verb: *nicmati* means "I know it," *quimati* means "he or she knows it." ([source](https://gdn.iib.unam.mx/diccionario/mati/182730))

The name fits. The tool's job is knowing things about your codebase so you don't have to restate them.

---

## The problem

Knowledge about a codebase lives in people's heads. Why `with_versioning(true, 0)` means indefinite retention, not "disabled." Why that auth middleware does something non-obvious. Why the test suite must run under `cargo nextest` and not vanilla `cargo test`. This stuff gets explained in Slack threads, in code review comments, sometimes in a GOTCHAS.md that nobody reads.

When the developer who knew it leaves, it's gone. When Claude opens a file for the twentieth time, you re-explain it from scratch.

mati is built for that: it stores what you've learned as structured records attached to files, confirmed by developers, and enforced at the hook level.

---

## How it works

mati runs as two processes:

```
   Claude Code
        | stdio (MCP)
  ┌─────▼──────┐        ┌──────────────────────┐
  │ mati serve │  UDS   │ mati daemon          │
  │ (MCP proxy)│◄──────►│ SurrealKV + graph    │
  └────────────┘        │ Tantivy search       │
                        │ idle-shutdown        │
                        └──────────────────────┘
```

`mati serve` is a thin MCP-stdio forwarder. It starts the daemon if one isn't running, then proxies tool calls over a Unix socket.

`mati daemon` owns the store. It holds the SurrealKV lock, answers queries, and shuts itself down after 30 minutes of idle with no active connections.

### The four MCP tools

mati exposes exactly four tools. That's a hard constraint: every tool definition costs tokens on every call.

| Tool | What it does |
|---|---|
| `mem_bootstrap` | Returns a token-budgeted context packet for the current session |
| `mem_get` | Looks up a record by key (`file:<path>`, `gotcha:<slug>`, etc.) |
| `mem_query` | Text search + graph traversal |
| `mem_set` | Writes a record |

### Records and gotchas

Every file gets a `file:<path>` record with a purpose summary, entry points, and a list of attached gotcha keys. Gotchas are the core unit: a rule, a reason, a severity, and a `confirmed` flag.

Unconfirmed gotchas are candidates. They exist in the graph but don't affect Claude's behavior. Once a developer confirms one, mati starts enforcing it.

The enforcement rule is simple: if a record has `confidence >= 0.6`, `confirmed = true`, and `quality >= 0.4`, the pre-read hook injects it before Claude opens the file. High-confidence records can deny the read entirely and inject the record instead. Lower-confidence records attach context without blocking.

### Static analysis

`mati init` runs a Layer 0 scan: tree-sitter parsing across 12 languages, import graph construction, co-change clustering from git history. No LLM calls.

`mati enrich` runs Layer 1: Claude reads each file, extracts gotcha candidates using a four-stage pipeline (setup, enumeration, critique loop, write). Run `mati review` afterward to confirm candidates and activate enforcement.

---

## Quick start

```bash
# Install
cargo install mati

# Initialize a project
cd your-project
mati init

# Add the MCP server to Claude Code
# In .claude/settings.json:
{
  "mcpServers": {
    "mati": {
      "command": "mati",
      "args": ["serve"]
    }
  }
}

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

| Command | What it does |
|---|---|
| `mati init` | Layer 0 scan and scaffold |
| `mati enrich [path]` | Layer 1 enrichment via Claude |
| `mati gotcha add` | Add a gotcha interactively |
| `mati gotcha confirm <key>` | Confirm a candidate and activate it |
| `mati review` | Batch confirm or tombstone candidates |
| `mati status` | Knowledge health dashboard |
| `mati stats` | Coverage and onboarding score |
| `mati gaps` | Files with no records or low confidence |
| `mati stale` | Records that haven't been touched since a file changed |
| `mati explain <file>` | File briefing: gotchas, blast radius, co-change partners, cluster membership |
| `mati clusters` | Co-change clusters from git history |
| `mati diff <key>` | Show record history |
| `mati repair` | Reconcile derived indexes against canonical records |
| `mati repair --check` | Same, exits non-zero if drift is found (CI-safe) |
| `mati doctor` | Aggregated health check |
| `mati daemon start/stop/status` | Manage the background daemon |
| `mati check` | Environment self-test |

---

## Stack

These are locked. Don't swap without adding an entry to `DECISIONS.md`.

| Crate | Purpose |
|---|---|
| `surrealkv` | Primary KV store. SurrealKV, not redb or sled |
| `petgraph` | In-memory graph. Edges persisted in SurrealKV |
| `tantivy` | Full-text BM25 search |
| `rmcp` | MCP stdio server (Rust MCP SDK) |
| `tree-sitter` | Static analysis parser, 12 language grammars |
| `ignore` | Repo walking, respects `.gitignore` |
| `git2` | Git history mining |
| `rayon` | Parallel file processing |
| `clap` + `comfy-table` | CLI. No TUI framework, no ratatui |

The semantic layer (vector search via `candle` + `usearch`) is feature-gated behind `--features semantic`. It's not compiled into the default binary.

---

## Free for developers. Paid for compliance teams.

mati is the complete product for a solo developer. Everything here is free and always will be.

One thing to know: the enforcement engine records every DENY, every ALLOW, and every consultation in a hash-chained, tamper-evident event log — from the day you install it. That log is local, append-only, and yours.

For teams at regulated companies, **mati Enterprise** reads that log and produces signed audit artifacts:

- Signed audit PDF export (cryptographically signed, hash-chained, tamper-evident)
- License-verified enforcement reports
- Extended retention controls
- Direct founder support

The following features are reserved for mati Enterprise and will never be in this repo:

- Multi-repo sync and cross-repo gotcha registry
- SSO, SAML, OIDC, RBAC
- Managed Slack / Teams / PagerDuty integration
- Curated compliance packs (HIPAA, SOC 2, PCI)
- Centralized governance dashboard

The enforcement path is identical across both tiers: zero network calls, local-only, deterministic. Enterprise adds the reporting layer — it never changes the enforcement behavior.

One invariant across both tiers: **the enforcement path makes zero network calls.** DENY and ALLOW decisions are local, always. mati never phones home.

See [mati.dev](https://mati.dev) for the enterprise tier, or [SALES_HANDOFF.md] in the mati-cloud repo for internal sales documentation.

---

## Contributing

Read `ARCHITECTURE.md` first. It has the full data model, hook decision matrix, process lifecycle, and everything else that doesn't fit in a README.

`DECISIONS.md` lists locked choices and why. `GOTCHAS.md` has the traps that bit us during development.

Tests run under `cargo-nextest`:

```bash
cargo install cargo-nextest --locked
cargo nextest run --lib
```

Vanilla `cargo test` works but is constrained to single-threaded execution. See `CLAUDE.md` for why.
