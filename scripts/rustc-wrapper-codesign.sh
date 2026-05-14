#!/usr/bin/env bash
#
# rustc-wrapper-codesign.sh — RUSTC_WRAPPER that re-signs every freshly-built
# proc-macro dylib with `codesign -s -` so AMFI stops emitting "has no CMS
# blob?" warnings on subsequent loads.
#
# Why a wrapper rather than a one-shot: incremental builds re-link
# proc-macro dylibs whenever their sources change, and each fresh dylib
# starts out linker-signed (no CMS slot). A wrapper sees every rustc
# invocation and signs only the proc-macro outputs.
#
# Setup:
#   In ~/.cargo/config.toml:
#     [build]
#     rustc-wrapper = "/abs/path/to/scripts/rustc-wrapper-codesign.sh"
#
#   Or per-shell:
#     export RUSTC_WRAPPER="$PWD/scripts/rustc-wrapper-codesign.sh"
#
# The wrapper passes through unchanged to rustc; only adds work on
# crate-type=proc-macro outputs on macOS.

set -euo pipefail

# Run the real rustc first.
"$@"
RC=$?
[ "$RC" -ne 0 ] && exit "$RC"

# macOS only — bail out on Linux/etc.
[ "$(uname -s)" = "Darwin" ] || exit 0

# Walk arguments to discover crate-type, --out-dir, and --crate-name.
crate_type_proc_macro=0
out_dir=""
crate_name=""
prev=""
for arg in "$@"; do
    case "$prev" in
        --crate-type) [ "$arg" = "proc-macro" ] && crate_type_proc_macro=1 ;;
        --out-dir)    out_dir="$arg" ;;
        --crate-name) crate_name="$arg" ;;
    esac
    # Also handle the `--crate-type=proc-macro` joined form.
    case "$arg" in
        --crate-type=proc-macro) crate_type_proc_macro=1 ;;
        --out-dir=*)             out_dir="${arg#--out-dir=}" ;;
        --crate-name=*)          crate_name="${arg#--crate-name=}" ;;
    esac
    prev="$arg"
done

if [ "$crate_type_proc_macro" = 1 ] && [ -n "$out_dir" ] && [ -n "$crate_name" ]; then
    # rustc emits target/.../deps/lib<crate_name>-<hash>.dylib
    # Underscores replace hyphens in crate names → match the file naming rustc uses.
    fs_name="${crate_name//-/_}"
    shopt -s nullglob
    for d in "$out_dir"/lib"${fs_name}"-*.dylib; do
        codesign -s - --force "$d" >/dev/null 2>&1 || true
    done
fi

exit 0
