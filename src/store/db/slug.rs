//! Slug derivation from a repo root.

use super::*;

/// Git's own answer to "what repo is this", discovered once per invocation.
///
/// `commondir` is git's *shared* git-dir: for a linked worktree this is the
/// main checkout's `.git/`, so every worktree of one clone reads the same
/// `remote` and hashes to the same slug — worktrees share history, so they
/// share a store. For a submodule it is the submodule's own private dir
/// under `.git/modules/`, carrying the submodule's own remote and therefore
/// its own, different slug — a submodule is a different repo with a
/// disjoint path namespace, so its `file:*` keys must never land in the
/// parent's store.
///
/// `workdir` is `None` for a bare repository (no working tree to resolve
/// record paths against) or when no repo is discoverable at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepoIdent {
    pub workdir: Option<PathBuf>,
    pub commondir: Option<PathBuf>,
    pub remote: Option<String>,
}

impl RepoIdent {
    /// Discover the identity of the repo containing (or rooted at) `path`.
    /// One `git2::Repository::discover` call.
    ///
    /// A caller that needs more than one derived value ([`Self::slug`],
    /// [`Self::slug_root`], a worktree tag, ...) for the same invocation
    /// should discover once and reuse the result rather than calling this
    /// again — see `cli::hook_decide::entry::run_inner`.
    pub fn discover(path: &Path) -> Self {
        git2::Repository::discover(path)
            .map(|repo| Self::from_repo(&repo))
            .unwrap_or_default()
    }

    /// [`Self::discover`], plus the live `git2::Repository` handle for a
    /// caller that also needs actual git operations (blob/commit lookups),
    /// not just identity facts — e.g. [`crate::health::staleness::StalenessAnalyzer`].
    /// Still exactly one `discover` call.
    pub fn discover_with_repo(path: &Path) -> (Self, Option<git2::Repository>) {
        match git2::Repository::discover(path) {
            Ok(repo) => {
                let ident = Self::from_repo(&repo);
                (ident, Some(repo))
            }
            Err(_) => (Self::default(), None),
        }
    }

    fn from_repo(repo: &git2::Repository) -> Self {
        // libgit2 sometimes returns workdir()/commondir() with a trailing
        // separator. Trim it explicitly — do not rely on `Path` methods to
        // swallow it, they don't, and a stray separator hashes differently
        // from the same path without one.
        let workdir = repo.workdir().map(trim_trailing_sep);
        let commondir = trim_trailing_sep(repo.commondir());
        // `commondir` is already the git-dir itself — for a plain repo
        // (`.git/`) and for a submodule's private dir
        // (`.git/modules/<name>/`) alike — so `config` sits directly under
        // it in both cases.
        let remote = read_remote_url(&commondir.join("config"));
        Self {
            workdir,
            commondir: Some(commondir),
            remote,
        }
    }

    /// The slug this identity hashes to: the first 8 hex characters of
    /// SHA-256(remote URL); falling back to SHA-256(workdir) when the repo
    /// has no remote; falling back further to SHA-256(canonicalized
    /// `fallback_path`) when git found no working tree to key on at all —
    /// no repo, or a bare one.
    ///
    /// The no-remote fallback hashes `workdir` itself, never a git-internal
    /// path like `commondir`: a `.git` that is itself a symlink must not
    /// leak its target's location into the project's identity, and hashing
    /// the same field [`Self::slug_root`] returns makes the two agree by
    /// construction rather than by two independent computations that merely
    /// happen to match.
    pub fn slug(&self, fallback_path: &Path) -> String {
        let input = self
            .remote
            .clone()
            .or_else(|| self.workdir.as_ref().map(|p| path_to_string(p)))
            .unwrap_or_else(|| path_to_string(&canonicalize_or_self(fallback_path)));
        let digest = Sha256::digest(input.as_bytes());
        hex::encode(&digest[..4])
    }

    /// The root record paths resolve against: [`Self::workdir`], or the
    /// canonicalized `fallback_path` when there is none (no repo, or a bare
    /// one — a bare repo has no working tree to offer).
    ///
    /// A bare repo's `fallback_path` is its own location, never an
    /// ancestor's: `discover` recognizes a bare repository in its own right
    /// and does not walk past it looking for an enclosing one, so a bare
    /// clone nested under an unrelated working repo can never inherit that
    /// repo's root (or its store).
    pub fn slug_root(&self, fallback_path: &Path) -> PathBuf {
        self.workdir
            .clone()
            .unwrap_or_else(|| canonicalize_or_self(fallback_path))
    }
}

fn trim_trailing_sep(p: &Path) -> PathBuf {
    match p.to_str() {
        Some(s) => PathBuf::from(s.trim_end_matches('/')),
        None => p.to_path_buf(),
    }
}

fn path_to_string(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn canonicalize_or_self(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Derive a project slug from the repo root.
///
/// Discovers the repo via `git2` and hashes [`RepoIdent::slug`] — the first
/// `url =` line of the config the repo's *common* git-dir names (shared
/// across linked worktrees, private per submodule), falling back to the
/// working tree path, and finally to the canonicalized input when git finds
/// no working tree at all.
///
/// Returns the first 8 hex characters of the SHA-256 digest.
pub fn derive_slug(repo_root: &Path) -> String {
    RepoIdent::discover(repo_root).slug(repo_root)
}

/// The repo root [`derive_slug`] keys on, for callers that must resolve
/// repo-relative record paths against the same root the store was named for.
///
/// Always `git2`'s own `workdir()` for a repo with a working tree — the same
/// value [`derive_slug`] falls back to when the repo has no remote — so the
/// two can never name different repos. A submodule and its parent, or a
/// bare repo and any working clone, are never conflated: see
/// [`RepoIdent::slug`] and [`RepoIdent::slug_root`].
pub fn slug_root(repo_root: &Path) -> PathBuf {
    RepoIdent::discover(repo_root).slug_root(repo_root)
}

/// Attempt to extract the first `url =` line from a git config file.
fn read_remote_url(config_path: &Path) -> Option<String> {
    let config = std::fs::read_to_string(config_path).ok()?;
    config
        .lines()
        .find(|l| l.trim_start().starts_with("url ="))
        .map(|l| {
            l.split_once('=')
                .map(|(_, v)| v.trim().to_owned())
                .unwrap_or_default()
        })
}
