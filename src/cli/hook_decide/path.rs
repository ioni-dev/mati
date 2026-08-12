use super::*;

// ── Path extraction ─────────────────────────────────────────────────────────

/// Reject `extract_file_path` results that cannot be a concrete file path:
/// shell redirection fragments (`2>/dev/null`, `>>`, `2>&1`), unexpanded
/// variables/globs, the bare current-directory token, or a multi-line blob
/// (the classifier grabbed an entire quoted command, not one argument).
/// These pollute the `analytics:miss_*` aggregate that feeds `mati status`'s
/// hit rate. Shell syntax cannot be a concrete `file:` record, and `.` is a
/// directory entry, not a file record. Only rejects; never widens what counts
/// as a real path.
pub(super) fn looks_like_file_path(s: &str) -> bool {
    if s.is_empty() || s.contains('\n') || s.contains('\r') || s == "." {
        return false;
    }
    let trimmed = s.trim_start_matches(|c: char| c.is_ascii_digit());
    if trimmed.starts_with('>') || trimmed.starts_with('<') || trimmed.starts_with('|') {
        return false;
    }

    !contains_shell_variable(s) && !contains_unexpanded_glob(s)
}

fn contains_shell_variable(s: &str) -> bool {
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '$'
            && chars.next().is_some_and(|next| {
                next == '{'
                    || next.is_ascii_alphanumeric()
                    || matches!(next, '_' | '?' | '#' | '@' | '*' | '!')
            })
        {
            return true;
        }
    }
    false
}

/// `*` and `?` only. A `[...]` bracket class is NOT treated as a glob: routing
/// conventions put real files at `app/[slug]/page.tsx` and `pages/[id].tsx`, so
/// rejecting brackets would skip the read gate on every dynamic route in a
/// Next.js repo. `*` and `?` are legal in a POSIX filename but do not appear in
/// practice, and no shipped framework generates them.
fn contains_unexpanded_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?')
}

pub(crate) fn extract_path(input: &serde_json::Value, variant: HookVariant) -> Option<String> {
    match variant {
        HookVariant::ClaudeConfigChange => None,
        HookVariant::ClaudePreRead | HookVariant::ClaudePreEdit => {
            // Structured path from Claude Code. Read/Edit/Write use `file_path`;
            // NotebookEdit uses `notebook_path`. We check both (plus a legacy
            // `path` fallback) so the edit gate covers every edit-class tool in
            // the matcher regardless of which field the tool populates — rather
            // than assuming one field for a tool whose schema we haven't pinned.
            input
                .pointer("/tool_input/file_path")
                .or_else(|| input.pointer("/tool_input/notebook_path"))
                .or_else(|| input.pointer("/tool_input/path"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        }
        HookVariant::ClaudePreBash | HookVariant::CodexPreBash | HookVariant::CodexPostBash => {
            // Raw command string — classify then extract.
            let cmd = input
                .pointer("/tool_input/command")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())?;
            let class = decide::classify_command(cmd)?;
            decide::extract_file_path(cmd, class).filter(|p| looks_like_file_path(p))
        }
        // apply_patch is multi-file and handled by `run_apply_patch` before the
        // single-path pipeline; never reaches here.
        HookVariant::CodexPreApplyPatch => None,
        // post-memget is handled by `run_post_memget` before extract_path is called;
        // it uses tool_input.key directly, not a file path.
        HookVariant::ClaudePostMemGet => None,
        HookVariant::ClaudePostBash => None,
        HookVariant::ClaudeInstructionsLoaded => None,
        // Handled by `run_file_changed` before the single-path pipeline; its
        // `file_path` is absolute and needs repo-relative resolution.
        HookVariant::ClaudeFileChanged => None,
    }
}

// ── Repo root ───────────────────────────────────────────────────────────────

/// Discover the git repo root via git2. Returns `None` for bare repos or
/// when not inside a git repository. No subprocess spawned.
pub(crate) fn discover_repo_root(cwd: &Path) -> Option<PathBuf> {
    discover_repo_root_for(&mati_core::store::RepoIdent::discover(cwd))
}

/// [`discover_repo_root`] for a caller that already discovered a
/// [`mati_core::store::RepoIdent`] this invocation — avoids a second
/// `git2::Repository::discover` call for the same repo (see
/// `entry::run_inner`).
///
/// `to_str` (NOT `to_string_lossy`): a non-UTF-8 root would be silently
/// rewritten with U+FFFD — a valid-looking but WRONG path, producing a wrong
/// slug and wrong store keys (a permanent, silent gate miss). Returning
/// `None` instead falls back to cwd-based resolution, which is at least
/// honest about not knowing the root. `RepoIdent` already strips the
/// trailing separator git2's `workdir()` sometimes adds, so `derive_slug()`
/// hashes the same string `std::env::current_dir()` would produce.
pub(crate) fn discover_repo_root_for(ident: &mati_core::store::RepoIdent) -> Option<PathBuf> {
    let root = ident.workdir.as_ref()?.to_str()?;
    Some(PathBuf::from(root))
}

/// WI-20: compute the CANONICAL repo-relative key for the symlink-bypass
/// fallback, or `None` if the canonical resolution can't be trusted.
///
/// Returns `Some(canonical_rel)` ONLY when, after resolving symlinks on the
/// accessed path, both hold:
///
///   - the canonical target lands UNDER the canonical repo root, AND
///   - the canonical key DIFFERS from the lexical key (`lexical_rel`).
///
/// Otherwise returns `None`, leaving the lexical-only decision intact. This is
/// the additive half of the gate: it never weakens the lexical lookup — the
/// caller only consults it when the lexical gate did not already deny.
///
/// Defensive by construction: a missing repo root, a `canonicalize` failure, a
/// target resolving outside the repo, or a no-op (same key) all yield `None`.
/// Reuses [`super::sandbox::canonicalize_lenient`] so symlink resolution matches
/// the L3 sandbox floor exactly (canonicalize; on a non-existent leaf,
/// canonicalize the parent and re-append the leaf).
pub(crate) fn canonical_rel_path(
    raw_path: &str,
    cwd: &Path,
    repo_root: Option<&Path>,
    lexical_rel: &str,
) -> Option<String> {
    // No repo root → we can't strip a prefix to form a repo-relative key.
    let repo_root = repo_root?;

    // Resolve the repo root itself through symlinks so the `starts_with`
    // containment check below is sound (e.g. macOS `/var` → `/private/var`).
    let canon_root = super::sandbox::canonicalize_lenient(repo_root)?;

    // Build the ABSOLUTE accessed path. A relative shell arg (`cat foo.rs`)
    // resolves against the hook process cwd (the repo root under Claude/Codex).
    let raw = Path::new(raw_path);
    let abs_access = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        cwd.join(raw)
    };

    // Resolve symlinks on the accessed path (this is the whole point: a symlink
    // to a gotcha'd file canonicalizes to the real target).
    let canon_access = super::sandbox::canonicalize_lenient(&abs_access)?;

    // Containment: the canonical target must be inside the repo. Out-of-repo
    // targets can't match a store key and must never deny — fall back to lexical.
    let stripped = canon_access.strip_prefix(&canon_root).ok()?;
    let stripped_str = stripped.to_str()?;

    // Normalize to the same lexical key shape used at registration / lookup.
    let canon_rel = decide::normalize_path(stripped_str, None);

    // Zero-cost no-op: if the canonical key equals the lexical one (no symlink
    // involved), skip the redundant second daemon round-trip.
    if canon_rel == lexical_rel {
        return None;
    }
    Some(canon_rel)
}

/// Resolve `accessed_path` to an absolute path against `cwd`, the way the
/// hook process resolves a bare relative shell argument. Same rule
/// `canonical_rel_path` uses for `abs_access`, without the symlink
/// resolution — an existence check doesn't need it.
pub(super) fn resolve_access_path(accessed_path: &str, cwd: &Path) -> PathBuf {
    let raw = Path::new(accessed_path);
    if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        cwd.join(raw)
    }
}

/// Populate [`EnforcementInput::file_exists`] — but ONLY when `eval_data`'s
/// file record actually carries the `FileDeleted` staleness signal. The
/// common, non-deleted-file path must pay nothing for this: `None` short-
/// circuits before any stat runs.
///
/// `Path::try_exists()` distinguishes "confirmed absent" (`Ok(false)`) from
/// "can't tell" (`Err`, e.g. a permission-denied parent directory) — the
/// latter stays `None` so an ambiguous stat fails open into today's
/// behavior (the signal alone decides) rather than inventing a new one.
pub(crate) fn file_exists_for_deleted_signal(
    eval_data: &serde_json::Value,
    accessed_path: &str,
    cwd: &Path,
) -> Option<bool> {
    let file_record = eval_data.get("file_record")?;
    if !decide::has_file_deleted_signal(file_record) {
        return None;
    }
    resolve_access_path(accessed_path, cwd).try_exists().ok()
}
