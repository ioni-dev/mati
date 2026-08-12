//! SurrealKV storage layer (M-03).
//!
//! Two trees per project:
//! - `knowledge.db` — all user-visible records, indefinite versioning
//! - `sessions.db`  — session analytics and hook events, 90-day retention
//!
//! Path: `~/.mati/<slug>/knowledge.db` and `sessions.db`
//! Slug: first 8 hex chars of SHA-256(git remote URL), falls back to
//!       SHA-256(canonicalized repo root path).
//!
//! Write durability follows the split defined in [`crate::store::Durability`]:
//! - `Immediate` → fsync before commit (knowledge records)
//! - `Eventual`  → OS write buffer (session / analytics records)

mod crud;
mod history;
mod slug;
mod tree;

#[cfg(test)]
mod tests;

pub use history::HistoryEntry;
pub use slug::{derive_slug, slug_root};

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use rmp_serde as rmps;
use sha2::{Digest, Sha256};
use surrealkv::{
    Durability as SkvDurability, HistoryOptions, LSMIterator, Mode, Options, Transaction, Tree,
    TreeBuilder, VLogChecksumLevel,
};

use serde::{Deserialize, Serialize};

use super::record::Record;
use super::{Durability, Encoding};
use crate::search::Search;

#[cfg(test)]
use crud::prefix_end;
use tree::{lock_error_hint, open_knowledge_tree, open_sessions_tree};

/// Marker file written by `mati init` when tantivy indexing is deferred.
/// Detected by [`Store::open_and_rebuild`] (MCP server startup) to trigger
/// a full rebuild before serving search queries.
const SEARCH_STALE_MARKER: &str = "search_stale";
/// Written before every tantivy commit on knowledge keys; removed on success.
/// Presence on startup means a crash interrupted the KV→tantivy sync window.
const SEARCH_SYNC_PENDING: &str = "search_sync_pending";

/// Key namespaces stored in the `knowledge` tree that contain [`Record`] structs.
///
/// Used by [`Store::rebuild_search_index`] to scan everything that was indexed
/// during normal `put`/`put_batch` calls. Must stay in sync with
/// [`Durability::for_key`]'s Immediate set.
const KNOWLEDGE_NAMESPACES: &[&str] = &[
    "gotcha:",
    "decision:",
    "file:",
    "stage:",
    "dev_note:",
    "dep:",
];

/// Key namespaces stored in the `sessions` tree that contain [`Record`] structs.
///
/// `graph:edge:*` is intentionally excluded — those values are raw 8-byte
/// timestamps, not `Record` structs, and must not be fed to the search index.
const SESSION_NAMESPACES: &[&str] = &["session:", "analytics:", "hook_event:", "compliance:"];

/// A write operation for a knowledge-tree transaction.
///
/// Supports both Record writes (indexed by tantivy) and raw byte writes
/// (e.g., audit entries) in the same atomic commit.
pub enum KnowledgeWriteOp<'a> {
    /// Write a Record (serialized via MessagePack, indexed by tantivy).
    PutRecord { key: &'a str, record: &'a Record },
    /// Write raw bytes (not a Record, not indexed by tantivy).
    PutRaw { key: &'a str, value: &'a [u8] },
}

/// Persistent knowledge store for a single mati project.
///
/// Wraps two SurrealKV trees:
/// - `knowledge` — user-visible records (gotchas, files, decisions, …)
/// - `sessions`  — analytics, hook events, compliance logs
///
/// All public methods are `async`; callers must be in a `tokio` context.
pub struct Store {
    knowledge: Tree,
    sessions: Tree,
    /// Tantivy full-text index — lazily initialized on first use.
    ///
    /// Hook commands (`get`, `log-hit`, `log-miss`, `reparse`) never touch the
    /// search index, so we skip the ~30-50ms tantivy init on `Store::open`.
    /// The index is created on the first call to a method that needs it
    /// (`put`, `put_batch`, `search`, `rebuild_search_index`).
    search: OnceCell<Search>,
    /// Absolute path to `~/.mati/<slug>/`
    pub root: PathBuf,
    /// Set by [`Store::open`] when the search index was corrupt or schema-
    /// incompatible on startup. Callers should use [`Store::open_and_rebuild`]
    /// rather than inspecting this field directly.
    index_needs_rebuild: bool,
}

/// Root directory for all mati on-disk state — every project store, the daemon
/// socket, logs, and the device id live under it.
///
/// `~/.mati` by default. Overridable with the `MATI_HOME` environment variable,
/// which relocates the entire footprint in one lever — used by CI, sandboxes,
/// and users with a non-standard layout, and by the test harness to keep test
/// state out of the developer's real home.
///
/// Every site that builds a `~/.mati/...` path MUST go through this (or
/// [`mati_home_opt`]) so the override is honored uniformly; a stray
/// `dirs::home_dir().join(".mati")` silently escapes it.
pub fn mati_home() -> Result<PathBuf> {
    mati_home_opt().context("cannot determine home directory (set MATI_HOME to override)")
}

/// Non-failing [`mati_home`] for the call sites that already tolerate a missing
/// home (logging, best-effort cleanup) with their own fallback.
pub fn mati_home_opt() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("MATI_HOME").filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    // Library unit tests already have their dedicated `cfg(test)` redirect
    // below. Integration tests link this library without `cfg(test)`, so the
    // opt-in check is intentionally compiled into that path instead.
    #[cfg(not(test))]
    if std::env::var_os("MATI_REQUIRE_EXPLICIT_HOME")
        .and_then(|value| value.into_string().ok())
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes"))
    {
        return None;
    }
    // In this crate's own unit tests, never write into the developer's real
    // `~/.mati`: redirect the whole footprint to a per-process temp dir. This
    // is compiled only into the lib's `--test` build, so production and the
    // `mati` binary are unaffected. The bin crate's tests set `MATI_HOME`
    // explicitly (its `cfg(test)` is separate from the lib's); integration
    // tests that spawn `mati` isolate via `HOME`/`MATI_HOME` on the child.
    #[cfg(test)]
    {
        Some(test_home())
    }
    #[cfg(not(test))]
    {
        dirs::home_dir().map(|h| h.join(".mati"))
    }
}

/// Per-process temp `MATI_HOME` for unit tests. Computed once and exported to
/// the environment so any child `mati` process a test spawns inherits the same
/// root instead of computing a divergent one.
#[cfg(test)]
fn test_home() -> PathBuf {
    use std::sync::OnceLock;
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("mati-unit-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::env::set_var("MATI_HOME", &dir);
        dir
    })
    .clone()
}

impl Store {
    /// Open (or create) both trees for the project rooted at `repo_root`.
    ///
    /// Creates `<mati_home>/<slug>/` (i.e. `~/.mati/<slug>/`, or under
    /// `$MATI_HOME`) if it does not exist.
    ///
    /// If the search index is corrupt or schema-incompatible, it is wiped and
    /// replaced with a fresh empty index. [`Store::index_needs_rebuild`] will
    /// return `true` in that case — call [`Store::rebuild_search_index`] before
    /// issuing any search queries, or use [`Store::open_and_rebuild`] which
    /// handles this automatically.
    pub async fn open(repo_root: &Path) -> Result<Self> {
        let slug = derive_slug(repo_root);
        let root = mati_home()?.join(&slug);
        std::fs::create_dir_all(&root)
            .with_context(|| format!("cannot create mati dir at {}", root.display()))?;

        let knowledge = open_knowledge_tree(root.join("knowledge.db"))
            .map_err(|e| lock_error_hint(e, &root.join("knowledge.db")))?;
        let sessions = open_sessions_tree(root.join("sessions.db"))
            .map_err(|e| lock_error_hint(e, &root.join("sessions.db")))?;

        // Tantivy is NOT initialized here — it is lazily created on first use
        // via `ensure_search()`. This saves ~30-50ms for hook commands that
        // only need KV reads/writes (get, log-hit, log-miss, reparse).

        let store = Self {
            knowledge,
            sessions,
            search: OnceCell::new(),
            root,
            index_needs_rebuild: false,
        };

        // Run forward schema migrations atomically. Single-process flock
        // (SurrealKV's exclusive lock) means no concurrent migrator can
        // collide here. If the store is already at the current version
        // this is a single `Store::get` and returns in microseconds.
        // Migrations refuse to open the store on detected downgrade,
        // which propagates the error up to the caller via `?`.
        super::migrations::migrate(&store).await?;

        Ok(store)
    }

    /// Open the store and rebuild the search index from SurrealKV if needed.
    ///
    /// This is the recommended entry point for the CLI and MCP server. It
    /// combines [`Store::open`] with an automatic [`Store::rebuild_search_index`]
    /// call when the index was corrupt or missing (C4). Search queries are safe
    /// to issue immediately on the returned store.
    ///
    /// Unlike [`Store::open`], this eagerly initializes tantivy so corruption
    /// can be detected and recovered from before any queries are issued.
    pub async fn open_and_rebuild(repo_root: &Path) -> Result<Self> {
        let mut store = Self::open(repo_root).await?;

        let search_path = store.root.join("search_index");
        let stale_marker = store.root.join(SEARCH_STALE_MARKER);
        let has_sync_pending = store.root.join(SEARCH_SYNC_PENDING).exists();

        // Stale marker is written by `mati init` when tantivy indexing was
        // deferred. SEARCH_SYNC_PENDING means a crash or sync failure interrupted
        // the KV → tantivy window. In both cases we must wipe the index before
        // rebuild so removed keys and old versions cannot survive restart.
        let has_stale_marker = stale_marker.exists();
        if (has_stale_marker || has_sync_pending) && search_path.exists() {
            std::fs::remove_dir_all(&search_path).with_context(|| {
                format!(
                    "failed to remove stale search index at {}",
                    search_path.display()
                )
            })?;
        }

        // Eagerly initialize tantivy — detect and recover from corruption.
        match Search::open(&search_path) {
            Ok(s) => {
                let _ = store.search.set(s);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path  = %search_path.display(),
                    "search index corrupt or schema-incompatible — wiping and scheduling rebuild"
                );
                if search_path.exists() {
                    std::fs::remove_dir_all(&search_path).with_context(|| {
                        format!(
                            "failed to remove corrupt search index at {}",
                            search_path.display()
                        )
                    })?;
                }
                let s = Search::open(&search_path)
                    .context("failed to open fresh search index after clearing corrupt data")?;
                let _ = store.search.set(s);
                store.index_needs_rebuild = true;
            }
        }

        if has_stale_marker {
            store.index_needs_rebuild = true;
        }

        // Detect crash-window desync: KV write committed but the tantivy
        // commit was interrupted before the fence could be cleared.
        if has_sync_pending {
            tracing::warn!("tantivy crash-window desync detected — scheduling rebuild");
            store.index_needs_rebuild = true;
        }

        if store.index_needs_rebuild() {
            store.rebuild_search_index().await?;
            // Clear the crash-fence if present — a full rebuild is a complete
            // re-sync from KV, so the index is authoritative again.
            let _ = std::fs::remove_file(store.root.join(SEARCH_SYNC_PENDING));
            // Remove stale marker only after a successful rebuild so a
            // crashed rebuild retries on the next open_and_rebuild call.
            if has_stale_marker {
                let _ = std::fs::remove_file(&stale_marker);
            }
        }
        Ok(store)
    }

    /// True when the search index was corrupt or missing on open.
    ///
    /// This flag reflects the state detected at open time and is not reset
    /// after [`Store::rebuild_search_index`] completes. Use it only to decide
    /// whether to call `rebuild_search_index` — not as a post-rebuild status.
    /// [`Store::open_and_rebuild`] handles this automatically.
    #[must_use]
    pub fn index_needs_rebuild(&self) -> bool {
        self.index_needs_rebuild
    }

    /// Lazily initialize (or return) the tantivy search index.
    ///
    /// First call opens the index at `<root>/search_index/`, creating the
    /// directory and schema if absent. Subsequent calls return the cached
    /// reference in O(1). If the index is corrupt, the corrupt directory is
    /// wiped and a fresh index is created.
    fn ensure_search(&self) -> Result<&Search> {
        self.search.get_or_try_init(|| {
            let search_path = self.root.join("search_index");
            match Search::open(&search_path) {
                Ok(s) => Ok(s),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path  = %search_path.display(),
                        "search index corrupt on lazy init — wiping and creating fresh"
                    );
                    if search_path.exists() {
                        std::fs::remove_dir_all(&search_path).with_context(|| {
                            format!(
                                "failed to remove corrupt search index at {}",
                                search_path.display()
                            )
                        })?;
                    }
                    Search::open(&search_path)
                        .context("failed to open fresh search index after clearing corrupt data")
                }
            }
        })
    }

    /// Rebuild the tantivy search index from scratch by scanning all
    /// [`Record`]-containing namespaces in SurrealKV (C4).
    ///
    /// Must be called on a store whose search index is empty — i.e. immediately
    /// after [`Store::open`] detected a corrupt/missing index, before any writes.
    /// Calling on a non-empty index will produce duplicate entries; use the
    /// deduplication in [`Search::query_keys`] to tolerate this if it occurs.
    ///
    /// Returns the total number of records committed to the index.
    pub async fn rebuild_search_index(&self) -> Result<usize> {
        let search = self.ensure_search()?;

        // Scan and index one namespace at a time — avoids loading all records
        // into memory simultaneously. Peak RSS is bounded by the largest single
        // namespace (typically `file:`) rather than the entire corpus.
        let mut committed = 0usize;

        for ns in KNOWLEDGE_NAMESPACES.iter().chain(SESSION_NAMESPACES) {
            let records = self.scan_prefix(ns).await?;
            if records.is_empty() {
                continue;
            }
            let refs: Vec<&Record> = records.iter().collect();
            committed += search.add_records(&refs)?;
        }

        tracing::info!(committed, "search index rebuilt from SurrealKV");

        Ok(committed)
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    /// Flush and close both trees, releasing the LOCK files.
    ///
    /// Must be called before dropping `Store` if another process (or test) will
    /// reopen the same database directory. SurrealKV holds an exclusive lock
    /// for the lifetime of a `Tree`; reopening without closing first fails with
    /// "already locked by another process".
    pub async fn close(self) -> Result<()> {
        tokio::try_join!(self.knowledge.close(), self.sessions.close())?;
        // Only close search if it was initialized during this session.
        if let Some(search) = self.search.into_inner() {
            search.close()?;
        }
        Ok(())
    }

    /// Best-effort durability flush for shutdown paths.
    ///
    /// Calls SurrealKV's `flush_wal(sync=true)` on both trees so every
    /// previously-committed transaction reaches disk. Non-consuming and
    /// `&self` — works through a shared `Arc<RwLock<Graph>>` read lock on
    /// the daemon shutdown path where ownership cannot be reclaimed.
    ///
    /// Necessary because SurrealKV's `Tree::Drop` only fire-and-forget-spawns
    /// `core.close()` onto the current tokio runtime; if the runtime is
    /// shutting down (signal handler, main return) that spawned task may not
    /// run before the process exits, losing buffered "Eventual" writes.
    ///
    /// Errors are logged via `tracing::warn!` and not propagated — shutdown
    /// paths must be infallible. Search index pending writes are committed
    /// per `Search::add_record`/`add_records` call, so no separate flush
    /// is needed here.
    pub async fn flush_for_shutdown(&self) {
        if let Err(e) = self.knowledge.flush_wal(true) {
            tracing::warn!("flush_for_shutdown: knowledge tree flush failed: {e}");
        }
        if let Err(e) = self.sessions.flush_wal(true) {
            tracing::warn!("flush_for_shutdown: sessions tree flush failed: {e}");
        }
    }

    // -------------------------------------------------------------------------
    // Health / ping
    // -------------------------------------------------------------------------

    /// Ping the store. Writes a sentinel key and reads it back; returns
    /// round-trip latency in microseconds.
    ///
    /// Used by `mati ping` and by hook fast-path availability checks.
    pub async fn ping(&self) -> Result<u64> {
        let start = now_micros();

        let sentinel_key = "analytics:ping_probe";
        let ts = start.to_string();
        let mut txn = self.sessions.begin_with_mode(Mode::WriteOnly)?;
        txn.set_durability(SkvDurability::Eventual);
        txn.set(sentinel_key.as_bytes(), ts.as_bytes())?;
        txn.commit().await?;

        let txn = self.sessions.begin_with_mode(Mode::ReadOnly)?;
        let result = txn.get(sentinel_key.as_bytes())?;
        anyhow::ensure!(
            result.is_some(),
            "ping sentinel write was not visible on read-back"
        );

        Ok(now_micros() - start)
    }

    // -------------------------------------------------------------------------
    // Write-seq cache invalidation
    // -------------------------------------------------------------------------

    /// Path to the monotonic counter file: `~/.mati/<slug>/health_write_seq`.
    fn write_seq_path(&self) -> PathBuf {
        self.root.join("health_write_seq")
    }

    /// Read the current knowledge write-sequence counter.
    ///
    /// Returns `0` if the file does not exist or cannot be parsed — callers
    /// treat `0` as "no valid cached snapshot" and recompute.
    pub fn read_write_seq(&self) -> u64 {
        std::fs::read_to_string(self.write_seq_path())
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Increment the write-seq counter. Called after every knowledge-key write.
    ///
    /// Best-effort: file write errors are silently discarded — a failed bump
    /// causes the next stats call to recompute, which is correct behaviour.
    fn bump_write_seq(&self) {
        let next = self.read_write_seq().wrapping_add(1);
        let _ = std::fs::write(self.write_seq_path(), next.to_string());
    }

    // -------------------------------------------------------------------------
    // Internals
    // -------------------------------------------------------------------------

    /// Choose the correct tree based on the key's durability class.
    fn tree_for(&self, key: &str) -> &Tree {
        match Durability::for_key(key) {
            Durability::Eventual => &self.sessions,
            Durability::Immediate => &self.knowledge,
        }
    }

    /// Direct access to the sessions tree for audit reads in tests.
    ///
    /// Production code should use the key-routing methods (`get`, `put_raw`,
    /// `scan_keys`) rather than accessing trees directly.
    pub fn sessions_tree(&self) -> &Tree {
        &self.sessions
    }
}

/// Current time in microseconds since UNIX epoch.
fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}
