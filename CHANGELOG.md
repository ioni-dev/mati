# Changelog

All notable changes to mati are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- `mati policy add`/`edit` reject an unrecognized `--requires via` receipt source instead of silently coercing it to `Unknown` — which authored a policy no receipt could satisfy (and degraded to a silent steer on Codex). The error names the bad value and the valid sources (`mem_get`, `hook_context`, `command_observed`, `db_introspection`).

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

[Unreleased]: https://github.com/ioni-dev/mati/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/ioni-dev/mati/compare/v0.1.3...v0.1.5
[0.1.3]: https://github.com/ioni-dev/mati/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/ioni-dev/mati/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ioni-dev/mati/releases/tag/v0.1.1
