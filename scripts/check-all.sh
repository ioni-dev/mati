#!/usr/bin/env bash
# Local mirror of every check the GitHub Actions CI workflow runs.
# Catches fmt drift, clippy violations, broken intra-doc links, and
# feature-gate rot before push instead of after.
#
# Does NOT run the test suites — those take much longer. Run `cargo test`
# separately if you want full coverage.
#
# Usage:
#   scripts/check-all.sh           # run every gate, stop on first failure
#   scripts/check-all.sh --keep    # run every gate, report at the end
#   scripts/check-all.sh --smoke   # also run the policy engine smoke test
#
# `--smoke` is opt-in because it builds the binary, spawns a daemon, and takes
# roughly a minute, which would break this script's fast-by-default contract.
# It skips itself where Unix domain sockets are unavailable.
#
# Mirrors .github/workflows/ci.yml as of:
#   - check: fmt, clippy --locked, check --locked, no-default-features, doc
#   - benches compile (cargo bench --no-run)

set -uo pipefail

KEEP_GOING=false
RUN_SMOKE=false
for arg in "$@"; do
    case "$arg" in
        --keep)  KEEP_GOING=true ;;
        --smoke) RUN_SMOKE=true ;;
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

run_check "cargo fmt --check"               cargo fmt --all -- --check
run_check "cargo clippy --locked"           cargo clippy --locked --all-targets -- -D warnings
run_check "cargo check --locked"            cargo check --locked --all-targets
run_check "cargo check --no-default-features" cargo check --locked --no-default-features --all-targets
run_check "cargo doc (-D warnings)"         cargo doc --locked --no-deps --all-features
run_check "cargo bench --no-run"            cargo bench --locked --no-run

if [[ "$RUN_SMOKE" == "true" ]]; then
    printf '\n── policy engine smoke ─────────────────────\n'
    scripts/smoke-policy.sh
    smoke_rc=$?
    if [[ $smoke_rc -eq 77 ]]; then
        printf '  skipped: this environment cannot bind a Unix domain socket.\n'
    elif [[ $smoke_rc -ne 0 ]]; then
        FAILED+=("policy engine smoke")
        if [[ "$KEEP_GOING" == "false" ]]; then
            printf '\n✗ policy engine smoke FAILED. Re-run with `--keep` to see all failures.\n' >&2
            exit 1
        fi
    fi
fi

printf '\n'
if [[ ${#FAILED[@]} -eq 0 ]]; then
    printf '✓ All CI gates pass locally.\n'
    exit 0
else
    printf '✗ %d gate(s) failed:\n' "${#FAILED[@]}" >&2
    for g in "${FAILED[@]}"; do printf '    %s\n' "$g" >&2; done
    exit 1
fi
