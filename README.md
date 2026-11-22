<p align="center">
  <img src="assets/mati-logo.svg" alt="mati" width="300">
</p>

<p align="center">
  <b>Deterministic guardrails for AI coding agents.</b>
</p>

There is a line in your codebase that looks like a mistake. It isn't. Someone wrote it that way on purpose, learned the hard way why it had to be that way, and never wrote the reason down. Then they left. Or they forgot. Or it was two years ago.

Now an AI agent opens the file. It sees the odd line. It "fixes" it. The old bug is back, and nobody remembers why it was a bug.

That is the ordinary tragedy of a codebase. Most of what a team knows about its own code lives where the code can't reach it: a Slack thread, a review comment, one person's head. Agents make it worse. They read fast, act faster, and start every session knowing none of it.

mati closes the gap. It attaches what your team knows to the files themselves and denies the agent's access until that knowledge has been read. The decision is made at the hook level, deterministically, outside the model's discretion, and every decision is recorded. It gates the paths it can see, which is not all of them: [What it doesn't catch](#what-it-doesnt-catch) has the numbers.

Coverage today: Claude Code gates file reads and edits (`Edit`/`Write`/`NotebookEdit`), Codex gates `apply_patch` edits, and both catch shell-command reads (`cat`, `grep`, and similar commands) on a best-effort basis.

Single Rust binary. MCP stdio server. Claude Code and Codex integration.

In Claude Code, install the plugin with `/plugin install mati --marketplace ioni-dev/mati`, then run `/mati:setup` in your project. It needs the `mati` binary; see [Quick start](#quick-start).

Compliance and audit exports live in the Enterprise tier ([getmati.dev](https://getmati.dev)).

---

## Documentation is a suggestion

Suppose the knowledge does get written down. It still gets ignored. A comment, a CONTRIBUTING note, a wiki page nobody opens: an agent reads straight past it, and so does a tired teammate on a Friday. Knowledge that exists but isn't consulted is the same as knowledge that doesn't exist.

So the real problem isn't that things go unwritten. It's that writing them down doesn't make anyone read them. A doc asks. mati denies, and records the answer.

A gotcha is a small structured record: a rule, the reason behind it, a severity, attached to a file and confirmed by a developer. Once it's confirmed, an agent that opens that file through a gated path is denied and handed the reason instead of guessing. Gated paths are the agent's own file tools and shell commands that name the file. An agent that reaches the file another way — by searching its contents, by a glob, by importing the module — is not stopped.

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
3. **Enforce.** From then on a hook stands in front of the reads and edits it can see — the block you just saw. It runs locally, decides deterministically, and makes no network call. Same result on every machine, every session.

---

## What it doesn't catch

**Once mati has denied an access, an agent cannot work around it without consulting.** That is a narrower claim than "it can't get in." Here is the measurement.

The hook reads a command before it runs and looks for a path in it. So it sees the agent's file tools, and it sees `cat src/store/db.rs`. It does not see an access that never spells the name.

We measured that rather than guessing. Ten runs, one governed file, an agent told only to keep the filename out of every command:

- **8 of 10** read and rewrote the file with zero consultation.
- **10 of 10** got the file's contents back.
- **0 of 10** were ever denied. The gate did not fire once.

Seven of them found the same route: `F=$(grep -rl "def normalize_path" .); cat "$F"`. The file is located by what is inside it. No classifier reading a command string can gate that, because the string never names the file. That is the interface, not a bug in it.

That 8 of 10 is the ceiling, not the rate. It needed an instruction to hide the filename. We ran the ordinary case too: the same trap, the repo grown to about a hundred files so the target is not the obvious one, a task that names the function to write and never the file, and no instruction to avoid anything.

- **10 of 10** found the file by searching its contents, the same grep route as above.
- Every run then named the file. Seven were denied on that read and consulted; three ran `mem_get` first and were never denied.
- **0 of 10** reached the file without consulting.

Told to hide the name, an agent takes the route no classifier can see. Left to work normally, it names the file it just found, and the gate is there. The hole is a deliberate evasion, not the common case.

What does hold is narrower, and was measured the same day. Twenty runs, same fixture, an agent told to defeat the guard, with the session lockdown on:

- **0 of 20** reached the file without consulting, against 4 of 10 without the lockdown (p=0.0077).
- Consultation rate **1.00**, against 0.60.
- Task success **20 of 20**. Denying the shell did not break the work.

None of those twenty tried a name-free route, so this arm does not cover the hole above. It covers what happens after the gate fires.

Every result on this page was registered before its run, on Claude Sonnet, one fixture family, ten-turn tasks. The 4-of-10 baseline is a historical control on a saved binary; the sealed and unsealed arms below are concurrent.

### The lockdown

That "once denied" result needs the session lockdown, which is **off by default**:

```bash
mati config set enforcement.lockdown on
```

With it on, a deny puts the session in debt for that file. Every further read and shell command is denied — in the main thread and in any subagent in the same worktree — until the agent calls the `mem_get` that the deny message names. It ships off because it denies unrelated work too: an agent blocked on `keys.py` cannot `ls` an unrelated directory until it consults.

### Sealing a file

The hole above is about the route, and no classifier closes it. `mati seal` closes it a different way — it takes the bytes away.

```bash
mati seal add src/keys.py
```

The file goes to mode `000`. The kernel refuses every reader: the shell, anything it spawns, the agent's `Read` (a hard `EACCES`), and its `Grep`, which skips the file entirely rather than redacting it — no match, no count, no filename in the results. `mem_get` lifts the mode for the session, and it goes back when the receipt lapses. While the receipt is owed, the commands that would restore it — `chmod`, `git checkout`, `git restore`, `git reset --hard`, `git worktree add`, `git clone` — are denied.

Same prompt as the 8-of-10 result above, same fixture, same binary, same model. Ten runs sealed against ten unsealed, interleaved:

- **0 of 10** sealed runs finished the task without consulting, against **6 of 10** unsealed (p=0.011).
- The bug the gotcha warns about landed in **0 of 10** sealed runs, against **4 of 10**.
- **9 of 10** sealed runs were denied at least once, against 3 of 10. mati sees the attempt now.
- The route that beat the hook in 7 of 10 unsealed runs showed up in 1 of 10 sealed ones. `grep -rl` cannot list a file it cannot open.

What it does not do:

- **It does not make the bytes unobtainable.** Two sealed runs read the file out of git history with `git cat-file`. That is out of scope by design — git must read its own objects to work at all, and a secret in git history is a secret-scanner problem.
- **A file can be replaced without ever being read.** `os.remove` needs write permission on the directory, not on the file. One sealed run did exactly that, then wrote a new one. The post-command sweep caught it, recorded it and put the mode back — but the seal on its own does not stop it. Turning on Claude Code's sandbox and adding `mati sandbox protect <file>` does: the deny it compiles blocks `chmod` and `unlink` in the kernel, measured against a control.
- **Your build stops too.** A cached `cargo check` still passes; the next real rebuild fails with `Permission denied`. rust-analyzer exits 0 and silently drops the module, so you get wrong answers rather than an error. `git add` cannot index the file. Seal a file whose bytes must be unavailable to everything, not one you are building against.

Three sealed runs did not finish. All three were the agent declining the red-team instruction — one of them after reading the file from history and stopping at the write — not the floor blocking the work. On the seven runs that attempted it, seven succeeded.

The runs above were on macOS with Claude Code. On Linux, the seal's unit tests pass as a non-root user; no agent runs were made there. WSL2 is untested.

### The rest of the boundary

- **The debt expires after 15 minutes.** An agent that works elsewhere for long enough gets the session back without consulting.
- **A subagent in its own git worktree** is a separate scope and does not inherit the debt.
- **Turning the lockdown off is not itself gated** before the first deny. After one, the disarm command is a shell command and is denied like any other.
- **Git history is out of scope.** Git must read its own objects to function, so `git log -p` and `git show <ref>` reach a governed file's committed bytes. A secret in git history is a secret-scanner problem, not this one.
- **Edits are gated through reads.** Claude Code's own read-before-edit rule forces a read, and the gate covers that read. The lockdown itself was measured on reads, not on edits.
- **Codex has no read hook.** There, enforcement is `apply_patch` edits and shell commands only.
- **Codex trusts hooks per project.** Codex ignores a project's `.codex/` hooks until you trust them — the prompt on your first interactive session in the repo, which persists. A fresh scaffold is untrusted, so a headless or CI Codex run enforces nothing until trusted, or until you pass `--dangerously-bypass-hook-trust`. This is Codex's security model; mati can't pre-seed the trust.
- **On Codex, the `Bypasses` count can over-report.** A shell read that follows an MCP `mem_get` consult may still be tallied as a miss, because the receipt's actor scope and the shell post-hook's differ. It inflates the audit summary; it does not mean an unconsulted read reached the file — the gate still denies deterministically.

What the gate does see, it records: every deny, every consultation, and every allow-after-receipt, in a local hash-chained log.

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
- **The hooks.** It writes the enforcement hooks under `.claude/` or `.codex/`. The instructions teach the agent the workflow; the hooks deny it when the agent skips it, on the paths they cover.

Nothing is clobbered. mati's instructions live in a marked block inside `.claude/CLAUDE.md` — it never edits your project-root `CLAUDE.md`. It reads that root file once, at init, to import what you've already written as knowledge, and leaves it untouched. Hooks are added alongside any you already have.

### The four MCP tools

mati exposes exactly four tools. That's a hard constraint: every tool definition costs tokens on every call.

| Tool            | What it does                                                    |
| --------------- | --------------------------------------------------------------- |
| `mem_bootstrap` | Returns a token-budgeted context packet for the current session |
| `mem_get`       | Looks up a record by key (`file:<path>`, `gotcha:<slug>`, etc.) |
| `mem_query`     | Search and traversal — text (BM25), tags, 1-hop graph, directory gotchas, opt-in semantic |
| `mem_set`       | Writes a record, or confirms/deletes one (`action`)             |

The same operations from your shell:

| Agent calls                    | You run                                   |
| ------------------------------ | ----------------------------------------- |
| `mem_set` write `gotcha:*`     | `mati gotcha add <file>` / `mati gotcha edit <key>` |
| `mem_set` confirm `gotcha:*`   | `mati gotcha confirm <key>`, or `mati review` |
| `mem_set` delete `gotcha:*`    | `mati gotcha delete <key>`                |
| `mem_set` write `dev_note:*`   | `mati note <text>`                        |
| `mem_set` write `policy:*`     | `mati policy add`                         |
| `mem_set` write `decision:*`   | No CLI command; agent only                |
| `mem_get file:<path>`          | `mati explain <path>`. Like `mem_get`, it records a consultation and lifts the deny |
| `mem_get <key>`                | `mati show <key>`. Read-only: it does not record a consultation |
| `mem_query`                    | `mati search <query>`, `mati ls <category>` |
| `mem_bootstrap`                | No CLI command                            |

### Records and gotchas

Every file gets a `file:<path>` record: a purpose summary, entry points, and the keys of any attached gotchas. Gotchas are the core unit, each one a rule, a reason, a severity, and a `confirmed` flag.

Unconfirmed gotchas are candidates. They sit in the graph but don't change the agent's behavior. Confirming one turns on enforcement for it.

Enforcement keys on gotchas, against a single threshold. If a gotcha is `confirmed = true` with `confidence >= 0.6` and `quality >= 0.4`, its hook can deny the operation outright (a Claude Code read or edit, or a Codex `apply_patch` edit) and hand the agent the gotcha instead. File records have no `confirmed` flag; they drive a separate, lower-confidence advisory path that attaches context without ever blocking.

### Policies and protected paths

Gotchas guard knowledge about a file. Policies guard *actions*. A policy matches a governable action category — a database client connecting, or an edit to a path — and either steers the agent or blocks it. You author a policy at `off`, stage it to `shadow` to watch what it would catch without acting, then promote it to `enforce` once you trust it. `mati policy` runs that lifecycle, and `mati policy test` dry-runs a predicate before you commit.

Two shortcuts sit on top of the same engine:

- `mati protect <glob>` gates edits and deletes to a path behind a fresh consult. Break-glass for crown-jewel files.
- `mati guard <cmd-glob>` gates a destructive command the same way.

For a harder floor, `mati sandbox` compiles confirmed crown-jewel gotchas into deny rules for the host's own sandbox, which hold outside the hook path. Verified on macOS with Claude Code's `/sandbox` turned on. On Linux, the rules it writes were run through Claude Code's sandbox runtime (`@anthropic-ai/sandbox-runtime` 0.0.83, bubblewrap 0.12.0): shell reads, reads through a symlink and writes were denied, and `unprotect` lifted them. Claude Code itself was not run on Linux. WSL2 is untested.

Hardest of all is `mati seal add <file>`, which holds the file at mode `000` until the session consults it. It is the only one that closes a read the hook never sees, and the only one that also stops your own build. [Sealing a file](#sealing-a-file) has the numbers and the cost.

### Static analysis

`mati init` runs a Layer 0 scan with no LLM calls: tree-sitter parsing across 12 languages, import-graph construction, and co-change clustering from git history.

Layer 1 enrichment runs through your agent, not as a standalone CLI job. The `/mati-enrich` slash command in Claude Code reads each file and extracts gotcha candidates via a four-stage pipeline (setup, enumeration, evidence verification, write); `mati enrich` on its own just prints how to start it. Run `mati review` afterward to confirm candidates and turn on enforcement.

---

## Quick start

Install a prebuilt binary (macOS and Linux, arm64 and x86_64), or build from source:

```bash
brew install ioni-dev/tap/mati
# or: curl -fsSL https://github.com/ioni-dev/mati/releases/latest/download/install.sh | bash
# or: cargo install mati
```

See it work first. `mati demo` runs deny, consult and allow on a throwaway repo
and deletes it after. It takes a few seconds and touches nothing else:

```bash
mati demo
```

Then set it up on your project:

```bash
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
| `mati sandbox <sub>`       | Compile crown-jewel gotchas into a host-sandbox deny floor (`compile`, `protect`, `unprotect`, `clear`) |
| `mati seal <sub>`          | Hold a file at mode 000 until the session consults it (`add`, `remove`, `list`, `clear`) |
| `mati verify-chain`        | Recompute and verify the hash-chained enforcement log (`--json`)                                     |

#### Maintain

| Command                     | What it does                                                                       |
| --------------------------- | --------------------------------------------------------------------------------- |
| `mati config get/set/dump`  | Read or set enforcement config (retention, write durability, policy mode, session lockdown) |
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

That's verifiable, not just asserted. The repo's own `zero_network` tests fail the build if a source file reaches for an HTTP client, if the daemon transport is anything but a Unix socket, or if the default build's dependency graph links a network crate. `mati doctor` reports the same posture in-tool, and the release workflow publishes a [CycloneDX](https://cyclonedx.org) SBOM of the dependency closure alongside each binary. All of it is static analysis of the build, not a runtime probe. Don't take our word for it — run `cargo nextest run --lib -E 'test(zero_network)'` and check the bill of materials.

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
