#!/usr/bin/env bash
# Install a pre-commit hook that runs fmt + clippy on the staged Rust files.
# Prevents the fmt-drift / clippy-rot class of issue from making it onto a
# PR and breaking CI. Opt-in: developers must run this script once.
#
# Usage:
#   scripts/install-git-hooks.sh
#
# Bypass once (e.g. work-in-progress commits):
#   git commit --no-verify
#
# Uninstall:
#   rm .git/hooks/pre-commit

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK_PATH="$REPO_ROOT/.git/hooks/pre-commit"

if [[ -f "$HOOK_PATH" ]]; then
    printf 'A pre-commit hook already exists at %s\n' "$HOOK_PATH"
    printf 'Overwrite? [y/N] '
    read -r reply
    [[ "$reply" =~ ^[Yy]$ ]] || { printf 'Aborted.\n'; exit 1; }
fi

cat > "$HOOK_PATH" <<'HOOK'
#!/usr/bin/env bash
# mati pre-commit hook — fmt + clippy on staged Rust files.
# Skip with `git commit --no-verify`.

set -uo pipefail

# Collect staged .rs files (added, copied, modified).
mapfile -t STAGED_RS < <(git diff --cached --name-only --diff-filter=ACM | grep -E '\.rs$' || true)

[[ ${#STAGED_RS[@]} -eq 0 ]] && exit 0

# 1. fmt: rejects unformatted code.
if ! cargo fmt --all -- --check >/dev/null 2>&1; then
    echo "✗ fmt drift detected. Run:" >&2
    echo "    cargo fmt --all" >&2
    echo "  then re-stage and commit." >&2
    exit 1
fi

# 2. clippy: catches new prod-code unwrap, lints, etc.
#    Use the same invocation CI uses so signals match.
if ! cargo clippy --locked --all-targets -- -D warnings >/dev/null 2>&1; then
    echo "✗ clippy warnings detected. Run:" >&2
    echo "    cargo clippy --locked --all-targets -- -D warnings" >&2
    echo "  to see them, fix, re-stage and commit." >&2
    exit 1
fi

exit 0
HOOK

chmod +x "$HOOK_PATH"
printf '✓ pre-commit hook installed at %s\n' "$HOOK_PATH"
printf '  Bypass once with: git commit --no-verify\n'
