#!/usr/bin/env bash
# Local mirror of every check the GitHub Actions CI workflow runs.
# Catches fmt drift, clippy violations, broken intra-doc links, and
# feature-gate rot before push instead of after.
#
# Does NOT run the main test suites — those take much longer. Run
# `cargo nextest run --lib` separately for full coverage. The eval corpus is
# the one exception: pure functions, no daemon, no store.
#
# Usage:
#   scripts/check-all.sh           # run every gate, stop on first failure
#   scripts/check-all.sh --keep    # run every gate, report at the end
#   scripts/check-all.sh --smoke   # also run the policy + resource-protection smoke tests
#   scripts/check-all.sh --fast    # skip `cargo bench --no-run` (~11 of ~15 min)
#
# A full run is ~15 min, dominated by the bench compile; `--fast` drops it to
# ~3. `--smoke` is opt-in on top of that because it builds the binary and
# spawns a daemon. It skips itself where Unix domain sockets are unavailable.
#
# Mirrors .github/workflows/ci.yml as of:
#   - check: fmt, clippy --locked, check --locked, no-default-features, doc
#   - benches compile (cargo bench --no-run)
#   - eval-corpus: enforcement eval corpus regression test
#   - supply-chain: zero-network attestation (no HTTP-client crate)

set -uo pipefail

KEEP_GOING=false
RUN_SMOKE=false
RUN_FAST=false
for arg in "$@"; do
    case "$arg" in
        --keep)  KEEP_GOING=true ;;
        --smoke) RUN_SMOKE=true ;;
        --fast)  RUN_FAST=true ;;
    esac
done

# Stricter rustdoc — matches the workflow-level env in CI.
export RUSTDOCFLAGS="${RUSTDOCFLAGS:-} -D warnings"

declare -a FAILED=()

run_check() {
    local name="$1"
    shift
    printf '\n── %s ──────────────────────────────────────\n' "$name"
    if ! "$@"; then
        FAILED+=("$name")
        if [[ "$KEEP_GOING" == "false" ]]; then
            printf '\n✗ %s FAILED. Re-run with `scripts/check-all.sh --keep` to see all failures.\n' "$name" >&2
            exit 1
        fi
    fi
}

# Mirrors the "Zero-network attestation" step in the supply-chain job
# (ci.yml): the default build must link no HTTP-client crate.
zero_network_check() {
    local net
    net=$(cargo tree --no-default-features --edges normal --prefix none --format '{p}' \
          | awk '{print $1}' | sort -u \
          | grep -iE '^(reqwest|hyper|hyper-util|hyper-rustls|hyper-tls|h2|ureq|isahc|surf|attohttpc|curl|curl-sys)$' \
          || true)
    if [ -n "$net" ]; then
        echo "network-capable crate(s) in the DEFAULT (enforcement) build — violates the zero-network invariant (CLAUDE.md):"
        echo "$net"
        return 1
    fi
}

run_check "cargo fmt --check"               cargo fmt --all -- --check
run_check "cargo clippy --locked"           cargo clippy --locked --all-targets -- -D warnings
run_check "cargo check --locked"            cargo check --locked --all-targets
run_check "cargo check --no-default-features" cargo check --locked --no-default-features --all-targets
run_check "cargo doc (-D warnings)"         cargo doc --locked --no-deps --all-features
if [[ "$RUN_FAST" == "true" ]]; then
    printf '\n── cargo bench --no-run ────────────────────\n'
    printf '  skipped: --fast (this is not a full run).\n'
else
    run_check "cargo bench --no-run"        cargo bench --locked --no-run
fi
run_check "eval / regression corpus"        cargo test --locked --test eval_corpus -- --nocapture
run_check "zero-network attestation"        zero_network_check

# Run a smoke script that builds the binary and spawns a daemon. Exit 77 is a
# deliberate skip (no Unix domain socket in this environment).
run_smoke() {
    local name="$1" script="$2"
    printf '\n── %s ─────────────────────\n' "$name"
    "$script"
    local rc=$?
    if [[ $rc -eq 77 ]]; then
        printf '  skipped: this environment cannot bind a Unix domain socket.\n'
    elif [[ $rc -ne 0 ]]; then
        FAILED+=("$name")
        if [[ "$KEEP_GOING" == "false" ]]; then
            printf '\n✗ %s FAILED. Re-run with `--keep` to see all failures.\n' "$name" >&2
            exit 1
        fi
    fi
}

if [[ "$RUN_SMOKE" == "true" ]]; then
    run_smoke "policy engine smoke"        scripts/smoke-policy.sh
    run_smoke "resource protection smoke"  scripts/smoke-protect.sh
fi

printf '\n'
if [[ ${#FAILED[@]} -eq 0 ]]; then
    if [[ "$RUN_FAST" == "true" ]]; then
        printf '✓ All CI gates pass locally (--fast: bench compile skipped).\n'
    else
        printf '✓ All CI gates pass locally.\n'
    fi
    exit 0
else
    printf '✗ %d gate(s) failed:\n' "${#FAILED[@]}" >&2
    for g in "${FAILED[@]}"; do printf '    %s\n' "$g" >&2; done
    exit 1
fi
