# Contributing to mati

Thanks for taking a look. This guide covers how to contribute, and just as important, what belongs in this repo versus the commercial tier.

Please read the scope section first. It may save you from spending time on a PR that we cannot merge here.

## Project scope

mati is open core, and the split is buyer-based.

Everything an individual developer needs lives in this repo, free and open. Features whose buyer is an organization, such as governance, audit evidence, identity, compliance, or large-scale administration, live in the separate commercial tier: mati Enterprise.

Those features are out of scope for this repository.

### What this repo is, and will stay

This repo is the complete product for a solo developer.

That includes the local knowledge store, the enforcement engine, static analysis, the OSS CLI commands, and the local enforcement-event log. The enforcement path is local-only and makes zero network calls. That is a core invariant, not a temporary implementation detail.

### What will not be merged here

These are enterprise features. They belong in mati-cloud, so please do not open PRs for them here:

- License validation or license checking of any kind
- Signed audit PDF export. This repo records enforcement events; mati-cloud reads them and produces the report.
- Multi-repo sync, or a cross-repo gotcha registry
- SSO, SAML, OIDC, RBAC, or SCIM
- Managed Slack, Teams, or PagerDuty integration. The OSS tier may emit webhook-compatible output to stdout; managed authenticated routing is enterprise.
- Curated compliance packs, such as HIPAA, SOC 2, or PCI
- Policy-as-code continuous sync
- A centralized governance dashboard or web UI
- An air-gapped signed installer
- Any network call in the enforcement path. This is not just a feature boundary; it is part of the security model.
- Telemetry, analytics, or usage metering sent to any external service. The OSS binary never phones home.

What this repo does include, and what enterprise builds on top of: hash-chained enforcement event recording, the Store API, and the OSS CLI commands. mati-cloud reads from these pieces. It does not reimplement them.

Not sure which side of the line a feature is on? Open an issue and ask before building it. We would rather talk through scope early than turn away finished work.

## How to contribute

1. Open an issue before non-trivial work. For anything beyond a small fix, sketch the change first so we can agree on scope and approach.
2. Branch from `main`. Use `feature/`, `fix/`, or `docs/`.
3. Make the change, with tests.
4. Run the gates below. They mirror CI.
5. Open a PR with a clear description and link it to the issue.

## Development

```bash
# Build
cargo build

# Tests. The supported runner is cargo-nextest.
cargo install cargo-nextest --locked   # one-time
cargo nt --lib                         # alias for `cargo nextest run`
cargo nextest run --lib --profile ci   # match CI behavior locally

# Doc tests. nextest cannot run rustdoc examples.
cargo test --doc
```

Vanilla `cargo test` works too, but it is pinned to single-threaded execution by `.cargo/config.toml`.

`CLAUDE.md`, in the “Running the tests” section, explains why: the shared-binary model can otherwise trip the macOS kernel watchdog on Apple Silicon.

### Quality gates

CI mirrors these checks:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --doc
```

## Architecture

`ARCHITECTURE.md` covers the data model, hook decision matrix, storage and durability split, graph layer, and process lifecycle.

`CLAUDE.md` covers the day-to-day constraints and known gotchas. If you use Claude Code, it loads automatically.

## Licensing of contributions

mati is MIT licensed. See `LICENSE`.

By submitting a contribution, you agree that it will be licensed under the same MIT terms: inbound equals outbound.
