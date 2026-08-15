use super::*;

// ── affected_files normalization ─────────────────────────────────────────────

/// Normalize one `affected_files` entry to the repo-relative form the read
/// gate keys on.
///
/// `GotchaRecord.affected_files` is joined to `file:<rel_path>` records by
/// exact string equality. The read gate normalizes its side
/// ([`crate::hooks::decide::normalize_path`], called from `cli::hook_decide`);
/// the write paths used to store whatever the user or agent typed. A gotcha
/// added as `./src/foo.rs` or as an absolute path therefore never matched
/// `file:src/foo.rs` and was silently inert — no denial, no warning.
///
/// This is deliberately the *same* function the gate calls. Agreeing with the
/// read side is the whole point; a second, "smarter" normalizer here would
/// reintroduce the mismatch from the other direction.
///
/// Globs survive unchanged (`src/payments/**`, minted by the CODEOWNERS
/// candidates in `analysis::onboarding`): `normalize_path` only ever drops
/// empty, `.` and `..` components, and `*` is an ordinary component.
pub fn normalize_affected_file(path: &str, repo_root: Option<&str>) -> String {
    // Match the producers of `file:*` keys — `analysis::walker::make_rel_path`
    // and `analysis::git::normalize_git_path` both rewrite `\` to `/`
    // unconditionally, so a backslash can never appear in a `file:*` key and an
    // entry carrying one could not match regardless of platform.
    crate::hooks::decide::normalize_path(&path.replace('\\', "/"), repo_root)
}

/// Normalize a whole `affected_files` list against an explicit repo root.
///
/// Purely lexical — no filesystem access. Empty entries are dropped and
/// duplicates collapsed (two spellings of one path, `./src/a.rs` and
/// `src/a.rs`, normalize to the same string). First-seen order is preserved.
pub fn normalize_affected_files_with_root(
    files: &[String],
    repo_root: Option<&str>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(files.len());
    for raw in files {
        if raw.is_empty() {
            continue;
        }
        let normalized = normalize_affected_file(raw, repo_root);
        if normalized.is_empty() || out.contains(&normalized) {
            continue;
        }
        out.push(normalized);
    }
    out
}

/// [`normalize_affected_files_with_root`] against `repo_root`, with the root
/// and any absolute entry resolved through symlinks first.
///
/// Both only happen when at least one entry is absolute, so the common
/// all-relative case does no filesystem work at all.
///
/// `repo_root` must be the root the store's slug was keyed on
/// ([`crate::store::slug_root`]), never the process cwd. The caller that hands
/// the result to [`confirm_content_stamp`] joins that same root back onto it,
/// and a path keyed to one root joined to another hashes nothing — a confirmed,
/// enforcing gotcha that is permanently drift-blind, with no error.
///
/// Symlink resolution is what makes the prefix strip inside `normalize_path`
/// actually match. The gate never needs it — the agent hands it a path already
/// resolved against its own cwd — but a human running
/// `mati gotcha add /tmp/repo/src/a.rs` on macOS supplies `/tmp/...` while the
/// git workdir is `/private/tmp/...`, and the entry would otherwise become the
/// nonsense relative key `tmp/repo/src/a.rs`. Resolving an already-canonical
/// path is a no-op, so this only ever removes a mismatch.
///
/// A non-UTF-8 root leaves absolute entries to `normalize_path`'s
/// repo-root-less branch, which is exactly what the gate falls back to as well.
pub fn normalize_affected_files(files: &[String], repo_root: &Path) -> Vec<String> {
    if !files.iter().any(|f| looks_absolute(f)) {
        return normalize_affected_files_with_root(files, None);
    }

    let root = repo_root
        .to_str()
        .map(|r| resolve_lenient(r).unwrap_or_else(|| r.to_string()));
    let resolved: Vec<String> = files
        .iter()
        .map(|f| match looks_absolute(f) {
            true => resolve_lenient(f).unwrap_or_else(|| f.clone()),
            false => f.clone(),
        })
        .collect();
    normalize_affected_files_with_root(&resolved, root.as_deref())
}

/// Whether an entry needs a repo root to normalize. Checked before paying for
/// git discovery or symlink resolution.
fn looks_absolute(path: &str) -> bool {
    path.starts_with('/') || std::path::Path::new(path).is_absolute()
}

/// Resolve `path` through symlinks, tolerating a leaf that does not exist yet.
///
/// Mirrors `cli::sandbox::canonicalize_lenient` (which the read gate's
/// symlink-bypass fallback uses): canonicalize; on failure, canonicalize the
/// nearest existing ancestor and re-append the tail. `None` when nothing on the
/// path resolves or the result is not UTF-8, in which case the caller falls
/// back to the entry as typed.
pub(super) fn resolve_lenient(path: &str) -> Option<String> {
    let path = std::path::Path::new(path);
    if let Ok(c) = std::fs::canonicalize(path) {
        return c.to_str().map(str::to_string);
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = path;
    loop {
        let parent = cur.parent()?;
        tail.push(cur.file_name()?.to_os_string());
        if let Ok(cp) = std::fs::canonicalize(parent) {
            let mut out = cp;
            for comp in tail.iter().rev() {
                out.push(comp);
            }
            return out.to_str().map(str::to_string);
        }
        cur = parent;
    }
}

/// Return a copy of `record` with the `affected_files` field of its gotcha
/// payload replaced by `files`, or `None` when the payload already carries
/// exactly those paths.
///
/// Patches the JSON object in place rather than re-serializing a
/// [`crate::store::GotchaRecord`]: the MCP `mem_set` path merges caller-supplied
/// payloads, so a gotcha payload may legitimately carry fields beyond the
/// struct and re-serializing would drop them. Returning `None` keeps the
/// already-normalized path clone-free.
///
/// Crate-visible because the daemon's `confirm_commit_once` re-keys a legacy
/// record the same way and cannot reach this module's private items.
pub(crate) fn with_normalized_affected_files(record: &Record, files: &[String]) -> Option<Record> {
    let current = record.payload.as_ref()?.get("affected_files")?.as_array()?;
    let unchanged = current.len() == files.len()
        && current
            .iter()
            .zip(files)
            .all(|(v, f)| v.as_str() == Some(f.as_str()));
    if unchanged {
        return None;
    }

    let mut out = record.clone();
    let obj = out.payload.as_mut()?.as_object_mut()?;
    obj.insert(
        "affected_files".into(),
        serde_json::Value::Array(
            files
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    Some(out)
}

/// A tombstoned copy of `record`, version bumped. Callers own the write and
/// the derived-index cleanup that has to follow it.
pub(crate) fn tombstoned_copy(record: &Record, reason: TombstoneReason, at: u64) -> Record {
    let mut out = record.clone();
    out.lifecycle = RecordLifecycle::Tombstoned { reason, at };
    out.updated_at = at;
    out.version.logical_clock += 1;
    out.version.wall_clock = at;
    out
}
