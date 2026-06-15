# mati

A knowledge store for codebases. mati remembers what you've learned about each file, surfaces the relevant records before Claude reads, and can skip the read entirely when the stored context is enough.

Single Rust binary. MCP stdio server. Claude Code plugin.

Compliance and audit exports live in the Enterprise tier ([getmati.dev](https://getmati.dev)).

---

## The name

**mati** is a Nahuatl verb meaning "to know" or "to think." UNAM's Gran Diccionario Náhuatl lists it as transitive: _nicmati_ is "I know it," _quimati_ is "he or she knows it" ([source](https://gdn.iib.unam.mx/diccionario/mati/182730)). That is the tool's job: know things about your codebase so you don't have to keep restating them.

---

## The problem

A lot of what you know about a codebase never makes it into the codebase. Why `with_versioning(true, 0)` means indefinite retention and not "disabled." Why a piece of auth middleware does something non-obvious. Why the test suite has to run under `cargo nextest` instead of vanilla `cargo test`. It lands in Slack threads, in review comments, or in a markdown file nobody opens.

When the person who knew it leaves, it's gone. When Claude opens the same file for the twentieth time, you explain it again from scratch.

mati stores that knowledge as structured records attached to files, confirmed by developers, and enforced at the hook level.

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

Unconfirmed gotchas are candidates. They sit in the graph but don't change Claude's behavior. Confirming one turns on enforcement for it.

Enforcement is a single threshold. If a record has `confidence >= 0.6`, `confirmed = true`, and `quality >= 0.4`, the pre-read hook injects it before Claude opens the file. A high-confidence record can deny the read outright and hand Claude the record instead. Lower-confidence records attach context without blocking.

### Static analysis

`mati init` runs a Layer 0 scan with no LLM calls: tree-sitter parsing across 12 languages, import-graph construction, and co-change clustering from git history.

`mati enrich` runs Layer 1 through Claude Code: Claude reads each file and extracts gotcha candidates via a four-stage pipeline (setup, enumeration, critique loop, write). Run `mati review` afterward to confirm candidates and turn on enforcement.

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

mati is the complete product for a solo developer, and all of it is free. From the first run, the enforcement engine records every DENY, every ALLOW, and every hook decision to a hash-chained, append-only event log. That log stays local and yours.

**mati Enterprise** reads that log and turns it into signed audit artifacts for teams at regulated companies:

- Signed audit PDF export (cryptographically signed, tamper-evident)
- Enforcement reports tied to license state
- Extended retention controls

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

## License

mati is released under the [MIT License](LICENSE). The "mati" name and logo are trademarks of the project — see [TRADEMARK.md](TRADEMARK.md).
