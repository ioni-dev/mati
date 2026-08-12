//! Slug derivation from a repo root.

use super::*;

/// Derive a project slug from the repo root.
///
/// Algorithm (matches ARCHITECTURE.md section 22):
/// 1. Try to read the first `fetch` remote URL from `.git/config`.
/// 2. Fall back to SHA-256 of the canonicalized repo root path.
///
/// Returns the first 8 hex characters of the SHA-256 digest.
pub fn derive_slug(repo_root: &Path) -> String {
    let git_root = slug_root(repo_root);

    let input =
        read_remote_url(&git_root).unwrap_or_else(|| git_root.to_string_lossy().into_owned());

    let digest = Sha256::digest(input.as_bytes());
    hex::encode(&digest[..4]) // 4 bytes = 8 hex chars
}

/// The repo root [`derive_slug`] keys on, for callers that must resolve
/// repo-relative record paths against the same root the store was named for.
///
/// Note this is not `git2`'s answer: the walk below tests for a `.git/config`
/// *file*, so a submodule or linked worktree — where `.git` is itself a file —
/// resolves to the parent repo instead. A caller that needs both answers must
/// compare them rather than assume they agree.
pub fn slug_root(repo_root: &Path) -> PathBuf {
    // Canonicalize first so `/tmp/...` and `/private/tmp/...` (macOS symlink),
    // trailing-slash variants, and `./foo` vs `foo` all resolve to the same
    // path before hashing. Without this every CLI invocation that resolves
    // paths differently (`current_dir()` vs `canonicalize(arg)`) used to
    // produce a different slug, scattering records across sibling
    // `~/.mati/<slug>/` directories.
    let canon = std::fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());

    // Walk up to find the nearest `.git/config` so an invocation from a
    // subdirectory of the repo produces the same slug as one from the root.
    // Pre-fix, `mati show` from `src/store/` and `mati serve` from the repo
    // root produced different slugs whenever the subdir lacked a `.git/`.
    walk_up_for_git_root(&canon).unwrap_or(canon)
}

/// Walk `start` and its ancestors looking for a directory that contains a
/// `.git/config` file. Returns the first such directory, or `None` if the
/// walk reaches the filesystem root without finding one.
fn walk_up_for_git_root(start: &Path) -> Option<PathBuf> {
    let mut cur = start;
    loop {
        if cur.join(".git").join("config").is_file() {
            return Some(cur.to_path_buf());
        }
        cur = cur.parent()?;
    }
}

/// Attempt to extract the first `url =` line from `.git/config`.
fn read_remote_url(repo_root: &Path) -> Option<String> {
    let config = std::fs::read_to_string(repo_root.join(".git").join("config")).ok()?;
    config
        .lines()
        .find(|l| l.trim_start().starts_with("url ="))
        .map(|l| {
            l.split_once('=')
                .map(|(_, v)| v.trim().to_owned())
                .unwrap_or_default()
        })
}
