# Contributing to mati

Thanks for taking a look. This guide covers how to contribute, and just as important, what belongs in this repo versus the commercial tier. Reading the scope section first will save you from writing a PR that can't be merged here.

## Project scope

mati is open core, and the split is buyer-based. Everything an individual developer needs is here, free and open. Features whose buyer is an organization (governance, audit evidence, identity, compliance, scale) live in the separate commercial tier, mati Enterprise. Those are out of scope for this repository.

### What this repo is, and will stay

The complete product for a solo developer. That means the local knowledge store, the enforcement engine, static analysis, all CLI commands, and the local enforcement-event log. The enforcement path is local-only and makes zero network calls. That doesn't change.

### What will not be merged here

These are enterprise features. They live in mati-cloud, so please don't open PRs for them:

- License validation or checking of any kind
- Signed audit PDF export (this repo records enforcement events; mati-cloud reads them and produces the report)
- Multi-repo sync, or a cross-repo gotcha registry
- SSO, SAML, OIDC, RBAC, SCIM
- Managed Slack/Teams/PagerDuty integration (the OSS tier may emit webhook-compatible output to stdout; the managed, authenticated routing is enterprise)
- Curated compliance packs (HIPAA, SOC 2, PCI). The OSS tier ships the `--pack` loader and format only.
- Policy-as-code continuous sync, a centralized governance dashboard or web UI, and an air-gapped signed installer
- Any network call in the enforcement path. This is a core invariant, not just a feature boundary.
- Telemetry, analytics, or usage metering sent to any external service. The OSS binary never phones home.

What this repo does include, and what enterprise builds on top of: hash-chained enforcement event recording, the Store API, and all CLI commands. mati-cloud reads from these. It does not reimplement them.

Not sure which side of the line a feature is on? Open an issue and ask before you build it. We would rather talk through scope up front than turn away finished work.

## How to contribute

1. Open an issue before non-trivial work. For anything past a small fix, sketch the change in an issue so we can agree on scope and approach first.
2. Branch from `main` (`feature/`, `fix/`, `docs/`).
3. Make the change, with tests.
4. Run the gates below. They mirror CI.
5. Open a PR with a clear description, linked to its issue.

## Development

```bash
# Build
cargo build

# Tests. The supported runner is cargo-nextest.
cargo install cargo-nextest --locked   # one-time
cargo nt --lib                         # alias for `cargo nextest run`
cargo nextest run --lib --profile ci   # match CI behavior locally

# Doc tests (nextest can't run rustdoc examples)
cargo test --doc
```

Vanilla `cargo test` works too, but it's pinned to single-threaded execution by `.cargo/config.toml`. CLAUDE.md ("Running the tests") explains why: the shared-binary model can otherwise trip the macOS kernel watchdog on Apple Silicon.

### Quality gates (CI mirrors these)

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --doc                       # rustdoc -D warnings
```

## Architecture

ARCHITECTURE.md has the data model, hook decision matrix, storage and durability split, graph layer, and process lifecycle. CLAUDE.md covers the day-to-day constraints and the known gotchas, and it loads automatically if you use Claude Code.

## Licensing of contributions

mati is MIT licensed (see LICENSE). When you submit a contribution, you are agreeing it goes in under those same MIT terms (inbound = outbound).
