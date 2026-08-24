<p align="center">
  <img src="assets/mati-logo.svg" alt="mati" width="300">
</p>

<p align="center">
  <b>Deterministic guardrails for AI coding agents.</b>
</p>

There is a line in your codebase that looks like a mistake. It isn't. Someone wrote it that way on purpose, learned the hard way why it had to be that way, and never wrote the reason down. Then they left. Or they forgot. Or it was two years ago.

Now an AI agent opens the file. It sees the odd line. It "fixes" it. The old bug is back, and nobody remembers why it was a bug.

That is the ordinary tragedy of a codebase. Most of what a team knows about its own code lives where the code can't reach it: a Slack thread, a review comment, one person's head. Agents make it worse. They read fast, act faster, and start every session knowing none of it.

mati closes the gap. It attaches what your team knows to the files themselves and enforces it the moment an agent acts. Not a document the model may consult. A gate it has to pass. The decision is made at the hook level, deterministically, outside the model's discretion.

Coverage today: Claude Code gates file reads and edits (`Edit`/`Write`/`NotebookEdit`), Codex gates `apply_patch` edits, and both catch shell-command reads (`cat`, `grep`, and similar commands) on a best-effort basis.

Single Rust binary. MCP stdio server. Claude Code and Codex integration.

Compliance and audit exports live in the Enterprise tier ([getmati.dev](https://getmati.dev)).

---

## Documentation is a suggestion

Suppose the knowledge does get written down. It still gets ignored. A comment, a CONTRIBUTING note, a wiki page nobody opens: an agent reads straight past it, and so does a tired teammate on a Friday. Knowledge that exists but isn't consulted is the same as knowledge that doesn't exist.

So the real problem isn't that things go unwritten. It's that writing them down doesn't make anyone read them. A doc asks. mati requires.

A gotcha is a small structured record: a rule, the reason behind it, a severity, attached to a file and confirmed by a developer. Once it's confirmed, an agent can't read or edit that file — in the paths mati enforces — without being handed the reason first. It doesn't act and find out later. The knowledge comes first, by construction.

---

## Why it matters

The cost of forgotten knowledge used to scale with the size of your team. Now it scales with the number of agents you point at your code, and agents multiply faster than people do.

- **Agents stop repeating solved mistakes.** An agent that doesn't know why `with_versioning(true, 0)` is deliberate will try to "fix" it. mati makes it read the reason first, whenever that gotcha is confirmed and reached through an enforced path.
- **Knowledge outlives the people who had it.** When the engineer who understood a subsystem leaves, the gotchas they confirmed stay attached to the files. The next hire, and the next agent, still get them.
- **Onboarding becomes a number.** `mati stats` reports coverage and an onboarding score. Knowledge health is something you track, not something you sense.
- **Enforcement leaves a trail.** Every deny, every allow-after-receipt, every consultation is written to a local, hash-chained log. You can prove a rule was put in front of the agent, not merely that someone wrote it down somewhere.

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

## The loop

Three steps. You don't hand-write the knowledge unless you want to.

1. **Capture.** `mati init` scans the repo with no LLM — tree-sitter across 12 languages, the import graph, and co-change history from git. Then `/mati-enrich` sends Claude through the files to draft gotcha candidates. It runs inside your existing agent session, so there's no extra API key or token bill. Or add one by hand.
2. **Confirm.** Candidates enforce nothing. You run `mati review` and approve the ones that are real. Confirming is the switch: it turns enforcement on for that gotcha and nothing else does.
3. **Enforce.** From then on a hook stands in front of every read and edit the agent makes — the block you just saw. It runs locally, decides deterministically, and makes no network call. Same result on every machine, every session.

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

### What the agent gets

`mati init` sets the agent up in one step. No manual prompting, no rules to paste.

- **The tools.** It writes `.mcp.json` for Claude Code, or `.codex/config.toml` for Codex, registering the MCP server. The agent gets the four tools above.
- **The instructions.** For Claude Code it writes `.claude/CLAUDE.md` — the read-gate (call `mem_get` before touching a file), loaded every session — plus load-on-demand skills in `.claude/skills/` for capturing gotchas and policies, and the `/mati-enrich` command. For Codex the same guidance ships as a lazy `.codex/skills/mati/SKILL.md`. Only the read-gate stays always in context; everything else loads when it's needed, so the per-session cost stays small.
- **The hooks.** It writes the enforcement hooks under `.claude/` or `.codex/`. The instructions teach the agent the workflow; the hooks make sure it can't skip it.

Nothing is clobbered. mati's instructions live in a marked block inside `.claude/CLAUDE.md` — it never edits your project-root `CLAUDE.md`. It reads that root file once, at init, to import what you've already written as knowledge, and leaves it untouched. Hooks are added alongside any you already have.

### The four MCP tools

mati exposes exactly four tools. That's a hard constraint: every tool definition costs tokens on every call.

| Tool            | What it does                                                    |
| --------------- | --------------------------------------------------------------- |
| `mem_bootstrap` | Returns a token-budgeted context packet for the current session |
| `mem_get`       | Looks up a record by key (`file:<path>`, `gotcha:<slug>`, etc.) |
| `mem_query`     | Search and traversal — text (BM25), tags, 1-hop graph, directory gotchas, opt-in semantic |
| `mem_set`       | Writes a record, or confirms/deletes one (`action`)             |

### Records and gotchas

Every file gets a `file:<path>` record: a purpose summary, entry points, and the keys of any attached gotchas. Gotchas are the core unit, each one a rule, a reason, a severity, and a `confirmed` flag.

Unconfirmed gotchas are candidates. They sit in the graph but don't change the agent's behavior. Confirming one turns on enforcement for it.

Enforcement keys on gotchas, against a single threshold. If a gotcha is `confirmed = true` with `confidence >= 0.6` and `quality >= 0.4`, its hook can deny the operation outright (a Claude Code read or edit, or a Codex `apply_patch` edit) and hand the agent the gotcha instead. File records have no `confirmed` flag; they drive a separate, lower-confidence advisory path that attaches context without ever blocking.

### Policies and protected paths

Gotchas guard knowledge about a file. Policies guard *actions*. A policy matches a governable action category — a database client connecting, or an edit to a path — and either steers the agent or blocks it. You author a policy at `off`, stage it to `shadow` to watch what it would catch without acting, then promote it to `enforce` once you trust it. `mati policy` runs that lifecycle, and `mati policy test` dry-runs a predicate before you commit.

Two shortcuts sit on top of the same engine:

- `mati protect <glob>` gates edits and deletes to a path behind a fresh consult. Break-glass for crown-jewel files.
- `mati guard <cmd-glob>` gates a destructive command the same way.

For a harder floor, `mati sandbox` compiles confirmed crown-jewel gotchas into an OS-level deny rule (macOS/Linux/WSL2) that holds even outside the hook path.

### Static analysis

`mati init` runs a Layer 0 scan with no LLM calls: tree-sitter parsing across 12 languages, import-graph construction, and co-change clustering from git history.

Layer 1 enrichment runs through your agent, not as a standalone CLI job. The `/mati-enrich` slash command in Claude Code reads each file and extracts gotcha candidates via a four-stage pipeline (setup, enumeration, evidence verification, write); `mati enrich` on its own just prints how to start it. Run `mati review` afterward to confirm candidates and turn on enforcement.

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

# Enrich. The work runs inside your agent session, not as a standalone CLI
# call. `mati enrich` prints the instructions; the real command is the
# /mati-enrich slash command inside Claude Code:
#   /mati-enrich src/auth/   # a directory   (/mati-enrich alone: top gaps)
mati enrich

# Review candidates and activate enforcement
mati review

# Check knowledge health
mati status
mati stats
```

> **Trust the folder, or hooks won't run.** Claude Code only executes project
> hooks (`.claude/settings.json`) after you accept its "Do you trust the files
> in this folder?" prompt for the repo. Until then, enforcement is silently
> inactive: the MCP server and CLAUDE.md instructions still load, so mati
> *appears* to work, but a read that should be denied passes straight through.
> After `mati init --claude`, open Claude Code in the repo once and accept the
> trust prompt, then verify with a read of a gotcha-gated file — it should be
> blocked until `mem_get` is called.

---

## CLI reference

#### Setup

| Command                                     | What it does                                                     |
| ------------------------------------------- | --------------------------------------------------------------- |
| `mati init`                                 | Layer 0 scan and scaffold (`--claude` / `--codex`, `--no-hooks`) |
| `mati hooks`                                | (Re)install just the enforcement hooks (`--claude` / `--codex`)  |
| `mati daemon start/stop/status`             | Manage the background daemon                                     |
| `mati supervisor install/uninstall/status`  | Install a launchd/systemd unit that keeps the daemon alive       |
| `mati serve`                                | Run the MCP stdio server (the agent integration calls this)      |
| `mati check`                                | Environment self-test                                            |
| `mati completion <shell>`                   | Generate a shell completion script (bash, zsh, fish, …)          |

#### Capture and review

| Command                                       | What it does                                                          |
| --------------------------------------------- | -------------------------------------------------------------------- |
| `mati enrich`                                 | Print how to run Layer 1 enrichment (the work runs via `/mati-enrich`) |
| `mati review`                                 | Batch confirm or tombstone candidates                                |
| `mati suggest`                                | Propose candidates from CODEOWNERS and code markers                  |
| `mati gotcha add/edit/delete/confirm <key>`   | Create, edit, tombstone, or activate a gotcha                        |
| `mati note <text>`                            | Record a quick dev note                                             |

#### Inspect

| Command                                          | What it does                                                        |
| ------------------------------------------------ | ------------------------------------------------------------------ |
| `mati status`                                    | Knowledge health dashboard                                          |
| `mati stats`                                     | Coverage and onboarding score                                       |
| `mati explain <file>`                            | File briefing: gotchas, blast radius, co-change partners, cluster   |
| `mati search <query>`                            | Keyword search across gotchas, decisions, notes, and files          |
| `mati show <key>` / `mati ls` / `mati history <key>` | Inspect a record, list records, or view a record's history      |
| `mati gaps`                                      | Files with no records or low confidence                             |
| `mati stale`                                     | Records older than the file they describe                           |
| `mati clusters`                                  | Co-change clusters from git history                                 |
| `mati diff [range]`                              | Pre-merge check: surface gotchas for files in a git diff range      |
| `mati quality-check`                             | List records by quality tier                                        |
| `mati improve <key>`                             | Reopen a record for revision                                        |
| `mati export` / `mati import`                    | Dump or load records (markdown/JSON, CLAUDE.md, auto-memory)        |

#### Enforce and protect

| Command                    | What it does                                                                                          |
| -------------------------- | ---------------------------------------------------------------------------------------------------- |
| `mati policy <sub>`        | Author and stage action policies (`add`, `edit`, `list`, `show`, `stage`, `enable`, `disable`, `delete`, `test`) |
| `mati protect <glob>`      | Gate edits and deletes to a path behind a fresh consult                                               |
| `mati guard <cmd-glob>`    | Gate a destructive command behind a fresh consult                                                     |
| `mati sandbox <sub>`       | Compile crown-jewel gotchas into an OS-level deny floor (`compile`, `protect`, `unprotect`, `clear`)  |
| `mati verify-chain`        | Recompute and verify the hash-chained enforcement log (`--json`)                                     |

#### Maintain

| Command                     | What it does                                                                       |
| --------------------------- | --------------------------------------------------------------------------------- |
| `mati config get/set/dump`  | Read or set enforcement config (retention, write durability, policy mode)         |
| `mati repair`               | Reconcile derived indexes (`--check` CI-safe, exits non-zero on drift; `--fast` drains the dirty queue) |
| `mati doctor`               | Aggregated health check (`--metrics` for live daemon SLOs)                        |
| `mati eval`                 | Run the enforcement regression corpus                                             |

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

That's verifiable, not just asserted. On every change, CI fails the build if the default binary links any HTTP-client crate (dependency ban) and proves the enforcement path opens no outbound socket (syscall audit under a network namespace); `mati doctor` surfaces the same posture in-tool; and every release ships a [CycloneDX](https://cyclonedx.org) SBOM of the exact dependency closure. Don't take our word for it — check the bill of materials.

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

mati is released under the [Apache License 2.0](LICENSE). The "mati" name and logo are trademarks of the project. See [TRADEMARK.md](TRADEMARK.md).
