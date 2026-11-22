# Changelog

All notable changes to mati are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-21

### Upgrading
- **The store upgrade is one-way.** The first run converts `knowledge.db` and `sessions.db` in place, and 0.1.x cannot read them afterwards. mati copies both to `*.bak-0.21` first.
- Stop the daemon in each project before you upgrade: `mati daemon stop`.
- To roll back, stop the daemon, restore the `*.bak-0.21` copies over the converted files, and reinstall 0.1.6.
- Building from source needs Rust 1.89 or later.

### Added
- `mati demo` runs deny, consult and allow on a throwaway repo under its own `MATI_HOME`.
- The README Quick Start lists the prebuilt binaries, the Homebrew tap and the install script, and starts with `mati demo`.

### Changed
- Upgraded surrealkv from 0.21.0 to 1.4.0, which fixes RUSTSEC-2026-0452. The first open converts an existing store in place. The conversion is one-way, so an older mati cannot read the store afterwards. Before converting, mati copies `knowledge.db` and `sessions.db` to `knowledge.db.bak-0.21` and `sessions.db.bak-0.21`. To roll back, restore those copies and reinstall the older mati. Stop any running mati daemon before upgrading.
- Minimum Rust version is now 1.89, up from 1.82. surrealkv 1.4.0 needs it.
- Post-edit parses its payload in Rust (`mati post-edit`). No hook needs `jq` now, and `init` no longer warns about `jq` or `awk`.
- `--help` describes mati as an enforcement layer, matching the crate description.
- `mati ls` accepts singular categories: `gotcha`, `file`, `decision`.
- MCP `serverInfo` reports `mati` and the crate version instead of `rmcp`.
- `init` without hooks says in Next steps that nothing is enforced.

### Fixed
- A reason starting with "because" rendered as "because Because". `init` repairs values stored that way; tombstoned records are left alone.
- `init --claude` exits 0 when a running daemon holds the store lock, and says the re-scan was skipped.
- `init` refuses a `MATI_HOME` whose socket path exceeds the Unix limit, instead of writing hooks that can only fail open. `doctor` reports it.
- A repo reached through a symlinked directory, such as macOS `/tmp`, lost gotcha context after a valid consult and logged a false compliance miss.
- Post-edit runs edit tracking before doc capture. Run together on Linux, the reparse overwrote the captured purpose.
- Codex session-start logs under `MATI_HOME`.
- `graph_bench`, `layer0_bench` and `store_bench` wrote into the real `~/.mati` under `cargo test --all-targets`. They now use a temp `MATI_HOME`.
- Concurrent first writes to the enforcement log could each store a different installation id, so events were stamped with an id the store no longer held.
- Concurrent writes to one key, such as two hook calls updating the same analytics counter, no longer fail on surrealkv 1.x.

## [0.1.6] - 2026-09-03

### Changed
- Excluded stale distribution descriptors (Homebrew formula, npm/pip packaging, registry manifests) from the published crate, and corrected their version and license — they had drifted to 0.1.0/0.1.1 and a wrong `MIT` claim (the project is Apache-2.0).

### Fixed
- `mati policy add`/`edit` reject an unrecognized `--requires via` receipt source instead of silently coercing it to `Unknown` — which authored a policy no receipt could satisfy (and degraded to a silent steer on Codex). The error names the bad value and the valid sources (`mem_get`, `hook_context`, `command_observed`, `db_introspection`).
- `mati policy add`/`edit` no longer fail with `store: Empty key` when authoring a deny-only policy (`deny_if` / content / `require` with no consult requirement). The empty `requires.key` backing-record lookup is now guarded.

## [0.1.5] - 2026-09-02

Enforcement moves from advisory gating to session lockdown, and the policy
engine gains its content and ordering axes.

### Added
- Tier 1 session lockdown: an unmet read gate denies every following tool call — Bash, reads, and subagents — until the owed record is consulted.
- Tier 2 read floor via `mati seal`: crown-jewel files refused at the OS level, surfaced in `mati doctor` and `mati stats`.
- Policy engine axes: `deny_if` (command and path predicates), `require` (allowlist), and a `file_read` content axis that governs the Read tool.
- `CommandObserved` receipts for workflow ordering, e.g. tests before commit.
- Subagent spawn lineage in the enforcement chain (nested `parent_agent_id`, chain schema v4).
- Path-less allow accounting in `mati stats` — an upper bound on the `cat`-wrapper read-gate miss.
- Cacheable `tools/list` and `server/discover` MCP responses.

### Changed
- Relicensed from MIT to Apache-2.0; contributions request a DCO sign-off.
- Moved the enrich pipeline and capture guidance out of the always-on `.claude/CLAUDE.md` stub into on-demand skills and commands; only the read-gate stays every-session.
- Post-read compliance decided in the mati binary, not the hook shell script.
- README rewritten to document the full feature set and the measured enforcement claim.

### Fixed
- Daemon session fence serves a nil request session (the cold-start window between socket bind and metadata publish) instead of rejecting it — closes spurious client retries, phantom metric errors, and null `mati get` reads.
- CLI retries once on `session_mismatch` after a daemon restart; the proxy surfaces daemon read errors instead of masking them as not-found.
- Worktree-scoped consultation receipts; cross-worktree governed reads by absolute path are denied.
- SessionEnd receipt cleanup scoped to the ending worktree instead of the whole store.
- `suggest` fails closed on a gotcha scan and skips files that already carry a confirmed gotcha.
- Copy-verb seal hole and same-version daemon skew closed.
- Codex: gotcha confirm works in-session — the confirm elicitation no longer sends a root `title` that Codex's schema parser rejects.
- Codex: advisory and liability context now injects via `additionalContext` (parity with Claude); previously only hard denies reached the Codex model.

### Security
- Dropped vendored private keys from the published crate; added a gitleaks allowlist.
- Zero-network and zero-telemetry attestation enforced by in-repo build tests, not CI.

## [0.1.3] - 2026-07-09

### Fixed
- `cargo binstall` installs the prebuilt binary (bin-dir template).
- `mati doctor` drift check routed through native `scan_keys` — removes a false positive.
- Integration and unit tests isolated off the real `~/.mati` via `MATI_HOME`.

## [0.1.2] - 2026-07-02

### Added
- Hook enforcement: per-actor consult-required gating, audit attribution, and edit-gating for Claude.
- `mati search` (keyword) and `mati suggest` (onboarding gotcha candidates from CODEOWNERS and markers).
- OS-level sandbox floor for crown-jewel files.
- Zero-network and zero-telemetry attestation; host-aware `doctor` health checks.
- Signed policy-floor bundle verification; a decision-layer eval corpus with `mati eval --json`.
- Shell completion, `config dump`, short command aliases, and CODEOWNERS ownership candidates on init.

### Fixed
- Read-gate detection bypasses: prefix, absolute path, flag value, quote-aware tokenizing, and in-repo symlink.
- Bash permission-prompt bypass; chain-integrity verification with concurrency-safe writes.
- Security bumps: git2 0.20 to 0.21, rmcp 1.4.0, anyhow 1.0.103.

## [0.1.1] - 2026-06-17

Initial foundation.

### Added
- Storage layer (dual-tree SurrealKV) and data model (`Record`, `FileRecord`, `GotchaRecord`, health scores, durability split).
- Graph layer (petgraph edges and traversal) and a tantivy BM25 index that rebuilds on corruption.
- Layer 0 static analysis: parallel file walker, tree-sitter parser, git history mining, dependency parsing.
- MCP stdio server and the CLI surface.

[Unreleased]: https://github.com/ioni-dev/mati/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ioni-dev/mati/compare/v0.1.6...v0.2.0
[0.1.6]: https://github.com/ioni-dev/mati/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/ioni-dev/mati/compare/v0.1.3...v0.1.5
[0.1.3]: https://github.com/ioni-dev/mati/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/ioni-dev/mati/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ioni-dev/mati/releases/tag/v0.1.1
