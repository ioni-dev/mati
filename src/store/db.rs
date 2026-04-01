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

use super::record::Record;
use super::Durability;
use crate::search::Search;

// 90 days expressed as nanoseconds — retention period for sessions.db
const SESSIONS_RETENTION_NS: u64 = 90 * 24 * 60 * 60 * 1_000_000_000u64;

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

/// Returns `true` for keys whose writes should invalidate cached stats snapshots.
///
/// These are the namespaces that affect the knowledge coverage aggregates
/// displayed by `mati stats` and `mati gaps`. Must stay in sync with
/// [`KNOWLEDGE_NAMESPACES`].
fn is_knowledge_key(key: &str) -> bool {
    key.starts_with("file:")
        || key.starts_with("gotcha:")
        || key.starts_with("decision:")
        || key.starts_with("dep:")
        || key.starts_with("dev_note:")
        || key.starts_with("stage:")
}

/// Key namespaces stored in the `sessions` tree that contain [`Record`] structs.
///
/// `graph:edge:*` is intentionally excluded — those values are raw 8-byte
/// timestamps, not `Record` structs, and must not be fed to the search index.
const SESSION_NAMESPACES: &[&str] = &["session:", "analytics:", "hook_event:", "compliance:"];

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

impl Store {
    /// Open (or create) both trees for the project rooted at `repo_root`.
    ///
    /// Creates `~/.mati/<slug>/` if it does not exist.
    ///
    /// If the search index is corrupt or schema-incompatible, it is wiped and
    /// replaced with a fresh empty index. [`Store::index_needs_rebuild`] will
    /// return `true` in that case — call [`Store::rebuild_search_index`] before
    /// issuing any search queries, or use [`Store::open_and_rebuild`] which
    /// handles this automatically.
    pub async fn open(repo_root: &Path) -> Result<Self> {
        let slug = derive_slug(repo_root);
        let home = dirs::home_dir().context("cannot determine home directory")?;
        let root = home.join(".mati").join(&slug);
        std::fs::create_dir_all(&root)
            .with_context(|| format!("cannot create mati dir at {}", root.display()))?;

        let knowledge = open_knowledge_tree(root.join("knowledge.db"))
            .map_err(|e| lock_error_hint(e, &root.join("knowledge.db")))?;
        let sessions = open_sessions_tree(root.join("sessions.db"))
            .map_err(|e| lock_error_hint(e, &root.join("sessions.db")))?;

        // Tantivy is NOT initialized here — it is lazily created on first use
        // via `ensure_search()`. This saves ~30-50ms for hook commands that
        // only need KV reads/writes (get, log-hit, log-miss, reparse).

        Ok(Self {
            knowledge,
            sessions,
            search: OnceCell::new(),
            root,
            index_needs_rebuild: false,
        })
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
    // Core CRUD
    // -------------------------------------------------------------------------

    /// Read a record by key. Returns `None` if not found.
    pub async fn get(&self, key: &str) -> Result<Option<Record>> {
        let txn = self.tree_for(key).begin_with_mode(Mode::ReadOnly)?;
        read_record(&txn, key)
    }

    /// Write a record with the appropriate durability level.
    ///
    /// Durability is derived from the key prefix via [`Durability::for_key`].
    pub async fn put(&self, key: &str, record: &Record) -> Result<()> {
        let durability = Durability::for_key(key);
        let tree = self.tree_for(key);
        let mut txn = tree.begin_with_mode(Mode::WriteOnly)?;
        txn.set_durability(skv_durability(durability));

        let bytes = rmps::to_vec_named(record)
            .with_context(|| format!("failed to serialize record for key '{key}'"))?;
        txn.set(key.as_bytes(), bytes)?;
        txn.commit().await?;

        // Crash-fence: written after KV commit, removed after tantivy commit.
        // If the process dies between these two points, open_and_rebuild sees
        // the marker on the next start and triggers a full index rebuild.
        if is_knowledge_key(key) {
            let _ = std::fs::write(self.root.join(SEARCH_SYNC_PENDING), b"");
        }

        // Update search index — KV write is primary, search is secondary.
        // We replace by key rather than append, so tantivy stays aligned with
        // the latest KV state without waiting for a full rebuild.
        //
        // Wrapped in catch_unwind: a tantivy panic (e.g., corrupted segment)
        // must never crash the server. The KV write already committed above —
        // the search index will be rebuilt on next startup via the
        // SEARCH_SYNC_PENDING crash-fence marker.
        let mut search_synced = false;
        match self.ensure_search() {
            Ok(search) => {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    search.add_record(record)
                })) {
                    Ok(Ok(())) => {
                        search_synced = true;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("search index update failed for '{key}': {e}");
                    }
                    Err(_panic) => {
                        tracing::error!(
                            "search index panicked during put for '{key}' — \
                             index will be rebuilt on next startup"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!("search index unavailable during put: {e}");
            }
        }
        if is_knowledge_key(key) {
            self.bump_write_seq();
            if search_synced {
                let _ = std::fs::remove_file(self.root.join(SEARCH_SYNC_PENDING));
            }
        }
        Ok(())
    }

    /// Write multiple records to KV only, skipping the tantivy search index.
    ///
    /// Use this during bulk init passes where search indexing would block the
    /// critical path. Follow with [`Self::index_records`] to update tantivy
    /// from the same in-memory records without a KV round-trip.
    ///
    /// Same durability semantics as [`Self::put_batch`]: at most 2 fsyncs.
    pub async fn put_batch_kv_only(&self, records: &[(&str, &Record)]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let mut immediate: Vec<(&str, &Record)> = Vec::new();
        let mut eventual: Vec<(&str, &Record)> = Vec::new();
        for &(key, record) in records {
            match Durability::for_key(key) {
                Durability::Immediate => immediate.push((key, record)),
                Durability::Eventual => eventual.push((key, record)),
            }
        }
        if !immediate.is_empty() {
            let mut txn = self.knowledge.begin_with_mode(Mode::WriteOnly)?;
            txn.set_durability(SkvDurability::Immediate);
            for (key, record) in &immediate {
                let bytes = rmps::to_vec_named(record)
                    .with_context(|| format!("failed to serialize record for key '{key}'"))?;
                txn.set(key.as_bytes(), bytes)?;
            }
            txn.commit().await?;
        }
        if !eventual.is_empty() {
            let mut txn = self.sessions.begin_with_mode(Mode::WriteOnly)?;
            txn.set_durability(SkvDurability::Eventual);
            for (key, record) in &eventual {
                let bytes = rmps::to_vec_named(record)
                    .with_context(|| format!("failed to serialize record for key '{key}'"))?;
                txn.set(key.as_bytes(), bytes)?;
            }
            txn.commit().await?;
        }
        if records.iter().any(|(k, _)| is_knowledge_key(k)) {
            self.bump_write_seq();
        }
        Ok(())
    }

    /// Mark the search index as stale so the next [`Self::open_and_rebuild`]
    /// call wipes and rebuilds it from KV.
    ///
    /// Written by `mati init` after a cold init pass to defer the tantivy
    /// indexing cost (~400ms on 27k records) to the first MCP server startup.
    /// Best-effort: a write failure is silently discarded — the worst outcome
    /// is that the search index contains stale data until the next full rebuild.
    pub fn mark_search_stale(&self) {
        let _ = std::fs::write(self.root.join(SEARCH_STALE_MARKER), b"");
    }

    /// Write multiple records in a single transaction per durability class.
    ///
    /// Records are grouped by their key prefix: all `Immediate` keys share one
    /// transaction on `knowledge` (1 fsync), all `Eventual` keys share one on
    /// `sessions` (1 fsync). The whole batch costs at most 2 fsyncs regardless
    /// of how many records it contains — critical for Layer 0 bulk inserts.
    ///
    /// Empty slice is a no-op. Mixed-durability batches are handled correctly.
    pub async fn put_batch(&self, records: &[(&str, &Record)]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        // Partition by durability class so each tree gets exactly one commit.
        let mut immediate: Vec<(&str, &Record)> = Vec::new();
        let mut eventual: Vec<(&str, &Record)> = Vec::new();
        for &(key, record) in records {
            match Durability::for_key(key) {
                Durability::Immediate => immediate.push((key, record)),
                Durability::Eventual => eventual.push((key, record)),
            }
        }

        if !immediate.is_empty() {
            let mut txn = self.knowledge.begin_with_mode(Mode::WriteOnly)?;
            txn.set_durability(SkvDurability::Immediate);
            for (key, record) in &immediate {
                let bytes = rmps::to_vec_named(record)
                    .with_context(|| format!("failed to serialize record for key '{key}'"))?;
                txn.set(key.as_bytes(), bytes)?;
            }
            txn.commit().await?;
        }

        if !eventual.is_empty() {
            let mut txn = self.sessions.begin_with_mode(Mode::WriteOnly)?;
            txn.set_durability(SkvDurability::Eventual);
            for (key, record) in &eventual {
                let bytes = rmps::to_vec_named(record)
                    .with_context(|| format!("failed to serialize record for key '{key}'"))?;
                txn.set(key.as_bytes(), bytes)?;
            }
            txn.commit().await?;
        }

        let has_knowledge = records.iter().any(|(k, _)| is_knowledge_key(k));

        // Crash-fence — same pattern as put().
        if has_knowledge {
            let _ = std::fs::write(self.root.join(SEARCH_SYNC_PENDING), b"");
        }

        // Update search index — KV write is primary, search is secondary.
        // If tantivy fails to initialize, the KV writes still succeeded.
        // Wrapped in catch_unwind for the same reason as put().
        let mut search_synced = false;
        match self.ensure_search() {
            Ok(search) => {
                let search_records: Vec<&Record> = records.iter().map(|(_, r)| *r).collect();
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    search.add_records(&search_records)
                })) {
                    Ok(Ok(_)) => {
                        search_synced = true;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("search index update failed in put_batch: {e}");
                    }
                    Err(_panic) => {
                        tracing::error!(
                            "search index panicked during put_batch — \
                             index will be rebuilt on next startup"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!("search index unavailable during put_batch: {e}");
            }
        }
        if has_knowledge {
            self.bump_write_seq();
            if search_synced {
                let _ = std::fs::remove_file(self.root.join(SEARCH_SYNC_PENDING));
            }
        }
        Ok(())
    }

    /// Delete a record by key. No-op if the key does not exist.
    pub async fn delete(&self, key: &str) -> Result<()> {
        let tree = self.tree_for(key);
        let mut txn = tree.begin_with_mode(Mode::WriteOnly)?;
        txn.set_durability(skv_durability(Durability::for_key(key)));
        txn.delete(key.as_bytes())?;
        txn.commit().await?;

        if is_knowledge_key(key) {
            let _ = std::fs::write(self.root.join(SEARCH_SYNC_PENDING), b"");
        }

        let mut search_synced = false;
        match self.ensure_search() {
            Ok(search) => {
                search.delete_key(key)?;
                search_synced = true;
            }
            Err(e) => {
                tracing::warn!("search index unavailable during delete: {e}");
            }
        }

        if is_knowledge_key(key) {
            self.bump_write_seq();
            if search_synced {
                let _ = std::fs::remove_file(self.root.join(SEARCH_SYNC_PENDING));
            }
        }
        Ok(())
    }

    /// Return all records whose key starts with `prefix`.
    ///
    /// Prefix must use one of the known key namespaces so the correct tree is
    /// selected. Unknown prefixes are scanned from `knowledge`.
    ///
    /// Return order is not guaranteed. Callers that need a stable order must sort.
    pub async fn scan_prefix(&self, prefix: &str) -> Result<Vec<Record>> {
        let tree = self.tree_for(prefix);
        let txn = tree.begin_with_mode(Mode::ReadOnly)?;

        // Range: [prefix, prefix\xff) covers all keys with this prefix
        let end = prefix_end(prefix);
        let iter = txn.range(prefix.as_bytes(), end.as_bytes())?;

        let mut records = Vec::new();
        let mut cursor = iter;
        while cursor.next()? {
            let bytes = cursor.value()?;
            match rmps::from_slice::<Record>(&bytes) {
                Ok(record) => records.push(record),
                Err(e) => {
                    tracing::warn!("skipping malformed record during scan: {e}");
                }
            }
        }
        Ok(records)
    }

    /// Scan records whose key starts with `prefix`, invoking `callback` for each.
    ///
    /// Same tree routing and prefix semantics as [`scan_prefix`], but records
    /// are deserialized and passed to `callback` one at a time rather than
    /// collected into a `Vec`. Callers can begin processing (e.g. printing to
    /// stdout) before the full scan completes, giving time-to-first-row
    /// latency proportional to a single deserialization rather than the full
    /// scan.
    ///
    /// Return order is lexicographic (underlying KV order). Callers that need
    /// a different order must collect and sort after the fact.
    pub async fn scan_prefix_each<F>(&self, prefix: &str, mut callback: F) -> Result<()>
    where
        F: FnMut(Record),
    {
        let tree = self.tree_for(prefix);
        let txn = tree.begin_with_mode(Mode::ReadOnly)?;
        let end = prefix_end(prefix);
        let mut cursor = txn.range(prefix.as_bytes(), end.as_bytes())?;
        while cursor.next()? {
            let bytes = cursor.value()?;
            match rmps::from_slice::<Record>(&bytes) {
                Ok(record) => callback(record),
                Err(e) => {
                    tracing::warn!("skipping malformed record during scan: {e}");
                }
            }
        }
        Ok(())
    }

    /// Full-text BM25 search over all indexed records.
    ///
    /// Calls tantivy for the top `limit` matching keys, then fetches each full
    /// record from SurrealKV. Keys that tantivy returns but are not found in
    /// the store (e.g. deleted since last commit) are silently skipped.
    ///
    /// Returns results ordered by descending BM25 relevance score. Returns an
    /// empty `Vec` when `text` is blank or `limit` is 0.
    pub async fn search(&self, text: &str, limit: usize) -> Result<Vec<Record>> {
        let search = self.ensure_search()?;
        let keys = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            search.query_keys(text, limit)
        })) {
            Ok(result) => result?,
            Err(_panic) => {
                tracing::error!("search index panicked during query — returning empty results");
                return Ok(vec![]);
            }
        };
        let mut records = Vec::with_capacity(keys.len());
        for key in &keys {
            if let Some(record) = self.get(key).await? {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Write raw bytes under `key` with automatically routed durability.
    ///
    /// Same durability routing as [`Self::put`] — callers do not need to know
    /// which tree a key belongs to. Use this for structural metadata (graph
    /// edges, etc.) where the value is not a [`Record`] and does not need to
    /// be deserialised on reads.
    pub async fn put_raw(&self, key: &str, value: &[u8]) -> Result<()> {
        let durability = Durability::for_key(key);
        let tree = self.tree_for(key);
        let mut txn = tree.begin_with_mode(Mode::WriteOnly)?;
        txn.set_durability(skv_durability(durability));
        txn.set(key.as_bytes(), value.to_vec())?;
        txn.commit().await?;
        Ok(())
    }

    /// Write multiple raw-byte values in a single transaction per durability class.
    ///
    /// Same batch semantics as [`Self::put_batch`] (at most 2 fsyncs for the
    /// whole batch). Use for bulk structural writes like graph edge inserts.
    pub async fn put_batch_raw(&self, records: &[(&str, &[u8])]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let mut immediate: Vec<(&str, &[u8])> = Vec::new();
        let mut eventual: Vec<(&str, &[u8])> = Vec::new();
        for &(key, value) in records {
            match Durability::for_key(key) {
                Durability::Immediate => immediate.push((key, value)),
                Durability::Eventual => eventual.push((key, value)),
            }
        }

        if !immediate.is_empty() {
            let mut txn = self.knowledge.begin_with_mode(Mode::WriteOnly)?;
            txn.set_durability(SkvDurability::Immediate);
            for (key, value) in &immediate {
                txn.set(key.as_bytes(), value.to_vec())?;
            }
            txn.commit().await?;
        }

        if !eventual.is_empty() {
            let mut txn = self.sessions.begin_with_mode(Mode::WriteOnly)?;
            txn.set_durability(SkvDurability::Eventual);
            for (key, value) in &eventual {
                txn.set(key.as_bytes(), value.to_vec())?;
            }
            txn.commit().await?;
        }

        Ok(())
    }

    /// Return all keys whose prefix matches, without deserialising values.
    ///
    /// Cheaper than [`Self::scan_prefix`] when only the key is needed (e.g.
    /// graph edge loading, existence checks). Uses the SurrealKV iterator
    /// `key().user_key()` path so value bytes are never read from disk.
    pub async fn scan_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let tree = self.tree_for(prefix);
        let txn = tree.begin_with_mode(Mode::ReadOnly)?;
        let end = prefix_end(prefix);
        let mut cursor = txn.range(prefix.as_bytes(), end.as_bytes())?;

        let mut keys = Vec::new();
        while cursor.next()? {
            let user_key = cursor.key().user_key();
            match std::str::from_utf8(user_key) {
                Ok(s) => keys.push(s.to_string()),
                Err(e) => tracing::warn!("skipping non-UTF8 key in scan_keys: {e}"),
            }
        }
        Ok(keys)
    }

    // -------------------------------------------------------------------------
    // History (M-14)
    // -------------------------------------------------------------------------

    /// Return version history for a single key, newest first.
    ///
    /// Includes tombstones (deletions). Uses the tight upper bound `key + \0`
    /// so adjacent keys never spill into the result set.
    ///
    /// `limit` caps the number of entries returned; `0` means unlimited.
    pub fn history(&self, key: &str, limit: usize) -> Result<Vec<HistoryEntry>> {
        anyhow::ensure!(!key.is_empty(), "history key must not be empty");
        let tree = self.tree_for(key);
        let txn = tree.begin_with_mode(Mode::ReadOnly)?;

        let mut opts = HistoryOptions::new().with_tombstones(true);
        if limit > 0 {
            opts = opts.with_limit(limit);
        }

        history_impl(&txn, key, &opts)
    }

    /// Return version history for a single key since `since_ts` (seconds),
    /// newest first.
    ///
    /// Timestamps are converted to nanoseconds for the SurrealKV range filter.
    pub fn history_since(
        &self,
        key: &str,
        since_ts: u64,
        limit: usize,
    ) -> Result<Vec<HistoryEntry>> {
        anyhow::ensure!(!key.is_empty(), "history key must not be empty");
        let tree = self.tree_for(key);
        let txn = tree.begin_with_mode(Mode::ReadOnly)?;

        let since_ns = since_ts.saturating_mul(1_000_000_000);
        let mut opts = HistoryOptions::new()
            .with_tombstones(true)
            .with_ts_range(since_ns, u64::MAX);
        if limit > 0 {
            opts = opts.with_limit(limit);
        }

        history_impl(&txn, key, &opts)
    }

    /// Return all records updated since `since_ts` (seconds), newest first.
    ///
    /// Scans every knowledge namespace (including `dep:`) and returns records
    /// whose `updated_at >= since_ts`. Results are sorted by `updated_at`
    /// descending with secondary sort by key for deterministic ordering.
    pub async fn records_since(&self, since_ts: u64, limit: usize) -> Result<Vec<Record>> {
        let mut results = Vec::new();
        for ns in KNOWLEDGE_NAMESPACES {
            let records = self.scan_prefix(ns).await?;
            for r in records {
                if r.updated_at >= since_ts {
                    results.push(r);
                }
            }
        }
        // Newest first, secondary sort by key for determinism
        results.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| a.key.cmp(&b.key))
        });
        if limit > 0 && results.len() > limit {
            results.truncate(limit);
        }
        Ok(results)
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
}

// ---------------------------------------------------------------------------
// Tree construction helpers
// ---------------------------------------------------------------------------

/// If a store open fails and the LOCK file exists, another mati process (MCP
/// server or daemon) holds the exclusive SurrealKV lock. Replace the raw OS
/// error with an actionable message.
/// Improve SurrealKV open errors with actionable context.
///
/// SurrealKV's LOCK file always exists after first use — it is never deleted.
/// The OS-level flock is what prevents concurrent access, not the file's
/// existence. So we detect lock contention by checking the *error message*,
/// not by checking if the LOCK file exists.
fn lock_error_hint(err: anyhow::Error, db_path: &std::path::Path) -> anyhow::Error {
    let msg = format!("{err}");
    if msg.contains("already locked") || msg.contains("WouldBlock") {
        // Real lock contention — another process holds the flock.
        // Read the PID from the LOCK file if available.
        let lock_file = db_path.join("LOCK");
        let pid_hint = std::fs::read_to_string(&lock_file)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .map(|pid| format!(" (holder PID: {pid})"))
            .unwrap_or_default();
        anyhow::anyhow!(
            "cannot open {} — another mati process holds the lock{pid_hint}.\n\
             This is usually the MCP server (mati serve) or a background daemon.\n\
             To stop the daemon: `mati daemon stop`\n\
             To check: `lsof {}/LOCK`",
            db_path.display(),
            db_path.display()
        )
    } else {
        err
    }
}

fn open_knowledge_tree(path: PathBuf) -> Result<Tree> {
    // vlog_value_threshold must be 0 when versioning is enabled — SurrealKV
    // requires all values to be in the VLog for time-travel to work.
    let opts = Options::new()
        .with_path(path)
        .with_versioning(true, 0) // indefinite retention
        .with_enable_vlog(true)
        .with_vlog_value_threshold(0)
        .with_vlog_checksum_verification(VLogChecksumLevel::Full);
    TreeBuilder::with_options(opts)
        .build()
        .context("failed to open knowledge.db")
}

fn open_sessions_tree(path: PathBuf) -> Result<Tree> {
    // Same constraint: vlog_value_threshold = 0 required when versioning is on.
    // VLogChecksumLevel is intentionally omitted — session writes are high-frequency
    // and acceptable to lose on crash. Do not add checksum verification here.
    let opts = Options::new()
        .with_path(path)
        .with_versioning(true, SESSIONS_RETENTION_NS)
        .with_enable_vlog(true)
        .with_vlog_value_threshold(0);
    TreeBuilder::with_options(opts)
        .build()
        .context("failed to open sessions.db")
}

// ---------------------------------------------------------------------------
// Slug derivation
// ---------------------------------------------------------------------------

/// Derive a project slug from the repo root.
///
/// Algorithm (matches ARCHITECTURE.md §22):
/// 1. Try to read the first `fetch` remote URL from `.git/config`.
/// 2. Fall back to SHA-256 of the canonicalized repo root path.
///
/// Returns the first 8 hex characters of the SHA-256 digest.
pub fn derive_slug(repo_root: &Path) -> String {
    let input =
        read_remote_url(repo_root).unwrap_or_else(|| repo_root.to_string_lossy().into_owned());

    let digest = Sha256::digest(input.as_bytes());
    hex::encode(&digest[..4]) // 4 bytes = 8 hex chars
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

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

/// Read and deserialize a record from an active transaction.
fn read_record(txn: &Transaction, key: &str) -> Result<Option<Record>> {
    match txn.get(key.as_bytes())? {
        None => Ok(None),
        Some(bytes) => {
            let record = rmps::from_slice::<Record>(&bytes)
                .with_context(|| format!("corrupt record at key '{key}'"))?;
            Ok(Some(record))
        }
    }
}

/// Map mati's `Durability` enum to SurrealKV's `Durability`.
fn skv_durability(d: Durability) -> SkvDurability {
    match d {
        Durability::Immediate => SkvDurability::Immediate,
        Durability::Eventual => SkvDurability::Eventual,
    }
}

/// Return the smallest string that is lexicographically greater than all keys
/// starting with `prefix`. Used to form the exclusive upper bound for range
/// scans.
fn prefix_end(prefix: &str) -> String {
    let mut bytes = prefix.as_bytes().to_vec();
    // Increment the last byte; if it wraps (0xff → 0x00) keep carrying.
    for b in bytes.iter_mut().rev() {
        if *b < 0xff {
            *b += 1;
            return String::from_utf8(bytes).unwrap_or_else(|_| "\u{ffff}".to_owned());
        }
        *b = 0x00;
    }
    // All bytes were 0xff — no upper bound needed; use a sentinel
    "\u{ffff}".to_owned()
}

/// A single versioned entry from the SurrealKV history iterator.
///
/// Timestamps come from SurrealKV's internal clock (nanoseconds since epoch).
/// Both seconds and nanoseconds are exposed for callers that need either
/// precision level.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    /// Timestamp in whole seconds (nanosecond timestamp / 1_000_000_000).
    pub timestamp_secs: u64,
    /// Raw nanosecond timestamp from SurrealKV.
    pub timestamp_ns: u64,
    /// Deserialized record, `None` for tombstones or corrupt values.
    pub record: Option<Record>,
    /// `true` when this version represents a deletion.
    pub is_tombstone: bool,
}

/// Shared synchronous implementation for key history queries.
///
/// Iterates all versions of `key` using `history_with_options` with the tight
/// upper bound `key + \0` (not `prefix_end`) to guarantee no adjacent key
/// spills. Returns entries sorted newest first.
fn history_impl(txn: &Transaction, key: &str, opts: &HistoryOptions) -> Result<Vec<HistoryEntry>> {
    // Upper bound: key + NUL byte — tighter than prefix_end which increments
    // the last byte. This ensures only exact-key versions are returned.
    let mut upper = key.as_bytes().to_vec();
    upper.push(0x00);

    let mut cursor = txn.history_with_options(key.as_bytes(), upper.as_slice(), opts)?;

    let mut entries = Vec::new();
    while cursor.next()? {
        let key_ref = cursor.key();

        // Guard: only process entries whose user_key matches exactly
        if key_ref.user_key() != key.as_bytes() {
            continue;
        }

        let is_tombstone = key_ref.is_tombstone();
        let ts_ns = key_ref.timestamp();
        let ts_secs = ts_ns / 1_000_000_000;

        let record = if is_tombstone {
            None
        } else {
            match cursor.value() {
                Ok(bytes) => rmps::from_slice::<Record>(&bytes).ok(),
                Err(_) => None,
            }
        };

        entries.push(HistoryEntry {
            timestamp_secs: ts_secs,
            timestamp_ns: ts_ns,
            record,
            is_tombstone,
        });
    }

    // Newest first — SurrealKV history iterator order is not guaranteed to be
    // reverse-chronological, so sort explicitly.
    entries.sort_by(|a, b| b.timestamp_ns.cmp(&a.timestamp_ns));
    Ok(entries)
}

/// Current time in microseconds since UNIX epoch.
fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // Helper: open a store backed by a temp directory (no real git repo needed)
    fn temp_store() -> (Store, TempDir) {
        let dir = TempDir::new().unwrap();
        // Override slug derivation by constructing store path manually
        let root = dir.path().join("mati_test");
        std::fs::create_dir_all(&root).unwrap();
        let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
        let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
        let search = OnceCell::new();
        let _ = search.set(Search::open(&root.join("search_index")).unwrap());
        let store = Store {
            knowledge,
            sessions,
            search,
            root: root.clone(),
            index_needs_rebuild: false,
        };
        (store, dir)
    }

    #[tokio::test]
    async fn ping_roundtrip() {
        let (store, _dir) = temp_store();
        let latency = store.ping().await.unwrap();
        assert!(latency < 5_000_000, "ping took >5s: {latency}µs");
    }

    #[tokio::test]
    async fn put_get_roundtrip() {
        use crate::store::record::{
            Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle,
            RecordSource, RecordVersion, StalenessScore,
        };
        use uuid::Uuid;

        let (store, _dir) = temp_store();

        let device_id = Uuid::new_v4();
        let record = Record {
            key: "gotcha:test-key".to_string(),
            value: "test value".to_string(),
            category: Category::Gotcha,
            priority: Priority::High,
            tags: vec!["test".to_string()],
            created_at: 0,
            updated_at: 0,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id,
                logical_clock: 1,
                wall_clock: 0,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: None,
        };

        store.put("gotcha:test-key", &record).await.unwrap();
        let got = store.get("gotcha:test-key").await.unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().key, "gotcha:test-key");
    }

    #[tokio::test]
    async fn put_delete_get_returns_none() {
        use crate::store::record::{
            Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle,
            RecordSource, RecordVersion, StalenessScore,
        };
        use uuid::Uuid;

        let (store, _dir) = temp_store();

        let device_id = Uuid::new_v4();
        let record = Record {
            key: "file:src/main.rs".to_string(),
            value: "entry point".to_string(),
            category: Category::File,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id,
                logical_clock: 1,
                wall_clock: 0,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: None,
        };

        store.put("file:src/main.rs", &record).await.unwrap();
        store.delete("file:src/main.rs").await.unwrap();
        let got = store.get("file:src/main.rs").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn scan_prefix_returns_matching_keys() {
        use crate::store::record::{
            Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle,
            RecordSource, RecordVersion, StalenessScore,
        };
        use uuid::Uuid;

        let (store, _dir) = temp_store();
        let device_id = Uuid::new_v4();

        let make_record = |key: &str| Record {
            key: key.to_string(),
            value: "v".to_string(),
            category: Category::Gotcha,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id,
                logical_clock: 1,
                wall_clock: 0,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: None,
        };

        store
            .put("gotcha:alpha", &make_record("gotcha:alpha"))
            .await
            .unwrap();
        store
            .put("gotcha:beta", &make_record("gotcha:beta"))
            .await
            .unwrap();
        store
            .put("gotcha:gamma", &make_record("gotcha:gamma"))
            .await
            .unwrap();
        store
            .put("file:src/main.rs", &make_record("file:src/main.rs"))
            .await
            .unwrap();

        let results = store.scan_prefix("gotcha:").await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn write_100_records_survive_reopen() {
        use crate::store::record::{
            Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle,
            RecordSource, RecordVersion, StalenessScore,
        };
        use uuid::Uuid;

        let dir = TempDir::new().unwrap();
        let root = dir.path().join("mati_test");
        std::fs::create_dir_all(&root).unwrap();
        let device_id = Uuid::new_v4();

        let make_record = |i: usize| {
            let key = format!("gotcha:item-{i:03}");
            Record {
                key: key.clone(),
                value: format!("value {i}"),
                category: Category::Gotcha,
                priority: Priority::Normal,
                tags: vec![],
                created_at: i as u64,
                updated_at: i as u64,
                ref_url: None,
                staleness: StalenessScore::fresh(),
                lifecycle: RecordLifecycle::Active,
                version: RecordVersion {
                    device_id,
                    logical_clock: i as u64,
                    wall_clock: i as u64,
                },
                quality: QualityScore::layer0_default(),
                access_count: 0,
                last_accessed: 0,
                source: RecordSource::StaticAnalysis,
                confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
                gap_analysis_score: 0.0,
                payload: None,
            }
        };

        // Write 100 records, then explicitly close to release LOCK.
        {
            let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
            let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
            let search = OnceCell::new();
            let _ = search.set(Search::open(&root.join("search_index")).unwrap());
            let store = Store {
                knowledge,
                sessions,
                search,
                root: root.clone(),
                index_needs_rebuild: false,
            };
            for i in 0..100 {
                let r = make_record(i);
                store.put(&r.key, &r).await.unwrap();
            }
            store.close().await.unwrap();
        }

        // Reopen and verify all 100 are present.
        {
            let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
            let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
            let search = OnceCell::new();
            let _ = search.set(Search::open(&root.join("search_index")).unwrap());
            let store = Store {
                knowledge,
                sessions,
                search,
                root: root.clone(),
                index_needs_rebuild: false,
            };
            let results = store.scan_prefix("gotcha:").await.unwrap();
            assert_eq!(
                results.len(),
                100,
                "expected 100 records after reopen, got {}",
                results.len()
            );
            store.close().await.unwrap();
        }
    }

    #[test]
    fn slug_is_8_hex_chars() {
        let slug = derive_slug(Path::new("/some/repo"));
        assert_eq!(slug.len(), 8);
        assert!(slug.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn slug_is_deterministic() {
        let a = derive_slug(Path::new("/some/repo"));
        let b = derive_slug(Path::new("/some/repo"));
        assert_eq!(a, b);
    }

    #[test]
    fn prefix_end_increments_last_byte() {
        // ':' is ASCII 58; incrementing gives ';' (59) → "gotcha;"
        assert_eq!(prefix_end("gotcha:"), "gotcha;");
        // All 0xff bytes — falls back to sentinel
        let all_ff = String::from_utf8(vec![0xff, 0xff]).unwrap_or_default();
        let end = prefix_end(&all_ff);
        assert_eq!(end, "\u{ffff}");
    }

    // ─── Shared helper ────────────────────────────────────────────────────────

    fn make_record(key: &str) -> Record {
        use crate::store::record::{
            Category, ConfidenceScore, Priority, QualityScore, RecordLifecycle, RecordSource,
            RecordVersion, StalenessScore,
        };
        Record {
            key: key.to_string(),
            value: format!("value for {key}"),
            category: Category::Gotcha,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 0,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: None,
        }
    }

    // ─── get / put / delete ────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_never_written_key_returns_none() {
        let (store, _dir) = temp_store();
        assert!(store.get("gotcha:does-not-exist").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn put_twice_second_value_wins() {
        let (store, _dir) = temp_store();
        let mut r = make_record("gotcha:overwrite-me");
        store.put("gotcha:overwrite-me", &r).await.unwrap();
        r.value = "updated value".to_string();
        r.version.logical_clock = 2;
        store.put("gotcha:overwrite-me", &r).await.unwrap();
        let got = store.get("gotcha:overwrite-me").await.unwrap().unwrap();
        assert_eq!(got.value, "updated value", "second write must win");
        assert_eq!(got.version.logical_clock, 2);
    }

    #[tokio::test]
    async fn delete_nonexistent_key_is_noop() {
        let (store, _dir) = temp_store();
        store.delete("gotcha:never-existed").await.unwrap();
        assert!(store.get("gotcha:never-existed").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_does_not_remove_sibling_keys() {
        let (store, _dir) = temp_store();
        store
            .put("gotcha:keep", &make_record("gotcha:keep"))
            .await
            .unwrap();
        store
            .put("gotcha:remove", &make_record("gotcha:remove"))
            .await
            .unwrap();
        store.delete("gotcha:remove").await.unwrap();
        assert!(
            store.get("gotcha:keep").await.unwrap().is_some(),
            "sibling must survive"
        );
        assert!(store.get("gotcha:remove").await.unwrap().is_none());
    }

    // ─── scan_prefix isolation ─────────────────────────────────────────────────

    #[tokio::test]
    async fn scan_prefix_empty_result() {
        let (store, _dir) = temp_store();
        assert!(store.scan_prefix("gotcha:").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn scan_prefix_does_not_spill_across_namespaces() {
        let (store, _dir) = temp_store();
        store
            .put("gotcha:alpha", &make_record("gotcha:alpha"))
            .await
            .unwrap();
        store
            .put("file:src/main.rs", &make_record("file:src/main.rs"))
            .await
            .unwrap();
        store
            .put("decision:arch", &make_record("decision:arch"))
            .await
            .unwrap();

        let gotcha = store.scan_prefix("gotcha:").await.unwrap();
        assert_eq!(gotcha.len(), 1);
        assert_eq!(gotcha[0].key, "gotcha:alpha");

        let file = store.scan_prefix("file:").await.unwrap();
        assert_eq!(file.len(), 1);
        assert_eq!(file[0].key, "file:src/main.rs");

        let decision = store.scan_prefix("decision:").await.unwrap();
        assert_eq!(decision.len(), 1);
        assert_eq!(decision[0].key, "decision:arch");
    }

    #[tokio::test]
    async fn scan_prefix_values_match_stored_values() {
        let (store, _dir) = temp_store();
        for key in ["gotcha:alpha", "gotcha:beta", "gotcha:gamma"] {
            let mut r = make_record(key);
            r.value = format!("sentinel:{key}");
            store.put(key, &r).await.unwrap();
        }
        let mut results = store.scan_prefix("gotcha:").await.unwrap();
        results.sort_by(|a, b| a.key.cmp(&b.key));
        assert_eq!(results.len(), 3);
        for r in &results {
            assert_eq!(
                r.value,
                format!("sentinel:{}", r.key),
                "value mismatch for key '{}'",
                r.key
            );
        }
    }

    #[tokio::test]
    async fn scan_prefix_excludes_adjacent_namespaces() {
        // prefix_end("gotcha:") == "gotcha;" — "decision:" and "file:" fall outside.
        let (store, _dir) = temp_store();
        store
            .put("gotcha:real", &make_record("gotcha:real"))
            .await
            .unwrap();
        store
            .put("decision:before", &make_record("decision:before"))
            .await
            .unwrap();
        store
            .put("file:after", &make_record("file:after"))
            .await
            .unwrap();

        let results = store.scan_prefix("gotcha:").await.unwrap();
        assert_eq!(results.len(), 1, "only gotcha: keys should appear");
        assert_eq!(results[0].key, "gotcha:real");
    }

    // ─── cross-tree isolation ──────────────────────────────────────────────────

    #[tokio::test]
    async fn knowledge_and_session_trees_are_isolated() {
        let (store, _dir) = temp_store();
        store
            .put("gotcha:in-knowledge", &make_record("gotcha:in-knowledge"))
            .await
            .unwrap();
        store
            .put("session:12345", &make_record("session:12345"))
            .await
            .unwrap();

        let gotcha_results = store.scan_prefix("gotcha:").await.unwrap();
        let session_results = store.scan_prefix("session:").await.unwrap();

        assert_eq!(gotcha_results.len(), 1);
        assert_eq!(gotcha_results[0].key, "gotcha:in-knowledge");
        assert_eq!(session_results.len(), 1);
        assert_eq!(session_results[0].key, "session:12345");
        assert!(
            gotcha_results
                .iter()
                .all(|r| !r.key.starts_with("session:")),
            "session records must not appear in gotcha: scan"
        );
        assert!(
            session_results
                .iter()
                .all(|r| !r.key.starts_with("gotcha:")),
            "gotcha records must not appear in session: scan"
        );
    }

    // ─── corrupt record tolerance ──────────────────────────────────────────────

    #[tokio::test]
    async fn scan_prefix_skips_corrupt_records_and_returns_valid_ones() {
        let (store, _dir) = temp_store();
        store
            .put("gotcha:good", &make_record("gotcha:good"))
            .await
            .unwrap();

        // Inject garbage bytes directly — simulates disk corruption or schema mismatch.
        {
            let mut txn = store.knowledge.begin().unwrap();
            txn.set_durability(SkvDurability::Immediate);
            txn.set(b"gotcha:corrupted", b"not valid json {{{").unwrap();
            txn.commit().await.unwrap();
        }

        let results = store.scan_prefix("gotcha:").await.unwrap();
        assert_eq!(results.len(), 1, "corrupt record must be silently skipped");
        assert_eq!(results[0].key, "gotcha:good");
    }

    #[tokio::test]
    async fn scan_prefix_all_corrupt_returns_empty_not_panic() {
        let (store, _dir) = temp_store();
        {
            let mut txn = store.knowledge.begin().unwrap();
            txn.set_durability(SkvDurability::Immediate);
            txn.set(b"gotcha:bad1", b"null").unwrap();
            txn.set(b"gotcha:bad2", b"{\"x\":1}").unwrap(); // valid JSON, wrong shape
            txn.commit().await.unwrap();
        }
        let results = store.scan_prefix("gotcha:").await.unwrap();
        assert_eq!(
            results.len(),
            0,
            "all corrupt — must return empty, not panic"
        );
    }

    // ─── ping ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn ping_multiple_calls_all_succeed() {
        let (store, _dir) = temp_store();
        for i in 0..10 {
            let latency = store
                .ping()
                .await
                .unwrap_or_else(|e| panic!("ping #{i} failed: {e}"));
            assert!(latency < 5_000_000, "ping #{i} took >5 s: {latency} µs");
        }
    }

    // ─── slug derivation ───────────────────────────────────────────────────────

    #[test]
    fn slug_differs_for_different_paths() {
        let a = derive_slug(Path::new("/repo/project-alpha"));
        let b = derive_slug(Path::new("/repo/project-beta"));
        assert_ne!(a, b, "distinct paths must produce distinct slugs");
    }

    #[test]
    fn slug_uses_remote_url_not_local_path() {
        // Verify the slug is actually derived from the URL, not the filesystem path.
        // We know the algorithm: first 8 hex chars of SHA-256(url).
        let url = "https://github.com/example/mati.git";
        let expected_slug = {
            let digest = Sha256::digest(url.as_bytes());
            hex::encode(&digest[..4])
        };

        let dir = tempfile::TempDir::new().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(
            git_dir.join("config"),
            format!("[remote \"origin\"]\n\turl = {url}\n"),
        )
        .unwrap();

        let actual_slug = derive_slug(dir.path());
        assert_eq!(
            actual_slug, expected_slug,
            "slug must equal SHA-256(remote URL)[0..4] hex"
        );

        // Also verify the path-derived slug for the same dir would differ
        // (i.e., the URL was actually preferred over the path).
        let path_slug = {
            let input = dir.path().to_string_lossy().into_owned();
            let digest = Sha256::digest(input.as_bytes());
            hex::encode(&digest[..4])
        };
        assert_ne!(
            actual_slug, path_slug,
            "URL slug must differ from the path slug for the same directory"
        );
    }

    #[test]
    fn slug_is_stable_for_identical_remote_urls() {
        let make_repo = |url: &str| {
            let dir = tempfile::TempDir::new().unwrap();
            let git_dir = dir.path().join(".git");
            std::fs::create_dir_all(&git_dir).unwrap();
            std::fs::write(
                git_dir.join("config"),
                format!("[remote \"origin\"]\n\turl = {url}\n"),
            )
            .unwrap();
            (derive_slug(dir.path()), dir)
        };
        let (slug_a, _dir_a) = make_repo("https://github.com/example/same-repo.git");
        let (slug_b, _dir_b) = make_repo("https://github.com/example/same-repo.git");
        assert_eq!(
            slug_a, slug_b,
            "same remote URL must always produce the same slug"
        );
    }

    #[test]
    fn slug_differs_for_different_remote_urls() {
        let make_repo = |url: &str| {
            let dir = tempfile::TempDir::new().unwrap();
            let git_dir = dir.path().join(".git");
            std::fs::create_dir_all(&git_dir).unwrap();
            std::fs::write(
                git_dir.join("config"),
                format!("[remote \"origin\"]\n\turl = {url}\n"),
            )
            .unwrap();
            (derive_slug(dir.path()), dir)
        };
        let (slug_a, _dir_a) = make_repo("https://github.com/org/repo-alpha.git");
        let (slug_b, _dir_b) = make_repo("https://github.com/org/repo-beta.git");
        assert_ne!(
            slug_a, slug_b,
            "different remote URLs must produce different slugs"
        );
    }

    // ─── prefix_end edge cases ─────────────────────────────────────────────────

    #[test]
    fn prefix_end_empty_prefix_returns_sentinel() {
        // No bytes to increment → sentinel covers the whole keyspace.
        assert_eq!(prefix_end(""), "\u{ffff}");
    }

    #[test]
    fn prefix_end_single_ascii_char() {
        assert_eq!(prefix_end("a"), "b"); // 0x61 → 0x62
        assert_eq!(prefix_end("z"), "{"); // 0x7a → 0x7b
    }

    #[test]
    fn prefix_end_known_namespace_boundaries() {
        // ':' (0x3a) + 1 = ';' (0x3b) for every namespace prefix.
        assert_eq!(prefix_end("gotcha:"), "gotcha;");
        assert_eq!(prefix_end("file:"), "file;");
        assert_eq!(prefix_end("decision:"), "decision;");
        assert_eq!(prefix_end("session:"), "session;");
    }

    // ─── delete + scan interaction ─────────────────────────────────────────────

    #[tokio::test]
    async fn delete_then_scan_excludes_deleted_key() {
        // Phantom-record regression: delete a key, then scan — must not return it.
        let (store, _dir) = temp_store();
        for key in ["gotcha:a", "gotcha:b", "gotcha:c", "gotcha:d"] {
            store.put(key, &make_record(key)).await.unwrap();
        }
        store.delete("gotcha:b").await.unwrap();
        store.delete("gotcha:d").await.unwrap();

        let results = store.scan_prefix("gotcha:").await.unwrap();
        assert_eq!(results.len(), 2, "deleted keys must not appear in scan");
        let keys: Vec<_> = results.iter().map(|r| r.key.as_str()).collect();
        assert!(keys.contains(&"gotcha:a"), "gotcha:a must survive");
        assert!(keys.contains(&"gotcha:c"), "gotcha:c must survive");
        assert!(!keys.contains(&"gotcha:b"), "gotcha:b must be gone");
        assert!(!keys.contains(&"gotcha:d"), "gotcha:d must be gone");
    }

    // ─── overwrite + scan deduplication ──────────────────────────────────────

    #[tokio::test]
    async fn overwrite_does_not_create_duplicate_in_scan() {
        // If SurrealKV MVCC versioning misbehaves, an overwrite could produce
        // two versions both visible under the same key during a range scan.
        let (store, _dir) = temp_store();
        let mut r = make_record("gotcha:dedup-me");
        store.put("gotcha:dedup-me", &r).await.unwrap();
        r.value = "v2".to_string();
        r.version.logical_clock = 2;
        store.put("gotcha:dedup-me", &r).await.unwrap();
        r.value = "v3".to_string();
        r.version.logical_clock = 3;
        store.put("gotcha:dedup-me", &r).await.unwrap();

        let results = store.scan_prefix("gotcha:").await.unwrap();
        assert_eq!(
            results.len(),
            1,
            "3 overwrites of the same key must yield 1 result in scan"
        );
        assert_eq!(results[0].value, "v3", "scan must return the latest value");
        assert_eq!(results[0].version.logical_clock, 3);
    }

    // ─── full field integrity through the store ────────────────────────────────

    #[tokio::test]
    async fn put_get_preserves_all_record_fields() {
        use crate::store::record::{
            Category, ConfidenceScore, Priority, QualityScore, QualitySignal, QualityTier, Record,
            RecordLifecycle, RecordSource, RecordVersion, StalenessScore, StalenessSignal,
            StalenessTier,
        };

        let (store, _dir) = temp_store();
        let device_id = uuid::Uuid::new_v4();

        // Construct a fully-populated record — every non-default field set.
        let written = Record {
            key: "gotcha:full-fields".to_string(),
            value: "Never hold a write txn across an await point.".to_string(),
            category: Category::Gotcha,
            priority: Priority::Critical,
            tags: vec![
                "async".to_string(),
                "tokio".to_string(),
                "surrealkv".to_string(),
            ],
            created_at: 1_710_520_800,
            updated_at: 1_710_520_900,
            ref_url: Some("https://github.com/example/issue/99".to_string()),
            staleness: StalenessScore {
                value: 0.42,
                tier: StalenessTier::Stale,
                signals: vec![
                    StalenessSignal::NotAccessedDays(45),
                    StalenessSignal::LinesChangedPct(0.3),
                ],
                computed_at: 1_710_520_800,
                last_record_sha: "abc123def456".to_string(),
            },
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id,
                logical_clock: 7,
                wall_clock: 1_710_520_900,
            },
            quality: QualityScore {
                value: 0.78,
                tier: QualityTier::Good,
                signals: vec![
                    QualitySignal::HasImperativeVerb,
                    QualitySignal::HasCausality,
                ],
                computed_at: 1_710_520_800,
            },
            access_count: 12,
            last_accessed: 1_710_520_888,
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore {
                value: 0.75,
                confirmation_count: 3,
                contributor_count: 2,
                last_challenged: Some(1_710_500_000),
                challenge_count: 1,
            },
            gap_analysis_score: 0.31,
            payload: None,
        };

        store.put("gotcha:full-fields", &written).await.unwrap();
        let read = store.get("gotcha:full-fields").await.unwrap().unwrap();

        // Verify every field survives the store round-trip.
        assert_eq!(read.key, written.key);
        assert_eq!(read.value, written.value);
        assert_eq!(read.category, written.category);
        assert_eq!(read.priority, written.priority);
        assert_eq!(read.tags, written.tags);
        assert_eq!(read.created_at, written.created_at);
        assert_eq!(read.updated_at, written.updated_at);
        assert_eq!(read.ref_url, written.ref_url);
        assert_eq!(read.staleness.tier, written.staleness.tier);
        assert_eq!(
            read.staleness.last_record_sha,
            written.staleness.last_record_sha
        );
        assert_eq!(read.staleness.signals.len(), 2);
        assert_eq!(read.lifecycle, written.lifecycle);
        assert_eq!(read.version.device_id, written.version.device_id);
        assert_eq!(read.version.logical_clock, written.version.logical_clock);
        assert_eq!(read.version.wall_clock, written.version.wall_clock);
        assert_eq!(read.quality.tier, written.quality.tier);
        assert_eq!(read.quality.signals.len(), 2);
        assert_eq!(read.access_count, written.access_count);
        assert_eq!(read.last_accessed, written.last_accessed);
        assert_eq!(read.source, written.source);
        assert_eq!(
            read.confidence.confirmation_count,
            written.confidence.confirmation_count
        );
        assert_eq!(
            read.confidence.contributor_count,
            written.confidence.contributor_count
        );
        assert_eq!(
            read.confidence.last_challenged,
            written.confidence.last_challenged
        );
        assert_eq!(
            read.confidence.challenge_count,
            written.confidence.challenge_count
        );
        assert!((read.gap_analysis_score - written.gap_analysis_score).abs() < f32::EPSILON);
    }

    // ─── Eventual durability persistence ──────────────────────────────────────

    #[tokio::test]
    async fn eventual_keys_survive_clean_close_and_reopen() {
        // The existing reopen test only exercises Immediate (gotcha:) keys.
        // This verifies that session: (Eventual) data also persists after close().
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("mati_test");
        std::fs::create_dir_all(&root).unwrap();

        {
            let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
            let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
            let search = OnceCell::new();
            let _ = search.set(Search::open(&root.join("search_index")).unwrap());
            let store = Store {
                knowledge,
                sessions,
                search,
                root: root.clone(),
                index_needs_rebuild: false,
            };
            for i in 0..10 {
                let key = format!("session:{i:04}");
                store.put(&key, &make_record(&key)).await.unwrap();
            }
            store.close().await.unwrap(); // must fsync/flush sessions tree on clean close
        }

        {
            let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
            let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
            let search = OnceCell::new();
            let _ = search.set(Search::open(&root.join("search_index")).unwrap());
            let store = Store {
                knowledge,
                sessions,
                search,
                root: root.clone(),
                index_needs_rebuild: false,
            };
            let results = store.scan_prefix("session:").await.unwrap();
            assert_eq!(
                results.len(),
                10,
                "Eventual session records must survive a clean close+reopen"
            );
            store.close().await.unwrap();
        }
    }

    // ─── corruption tolerance: corrupt record in the middle ───────────────────

    #[tokio::test]
    async fn scan_prefix_corrupt_in_middle_does_not_stop_iteration() {
        // Regression: if scan stops early on corruption rather than skipping,
        // valid records after the corrupt one would silently vanish.
        let (store, _dir) = temp_store();

        store
            .put("gotcha:aaa", &make_record("gotcha:aaa"))
            .await
            .unwrap(); // before corrupt
        store
            .put("gotcha:zzz", &make_record("gotcha:zzz"))
            .await
            .unwrap(); // after corrupt

        // Inject corruption lexicographically between the two valid records.
        {
            let mut txn = store.knowledge.begin().unwrap();
            txn.set_durability(SkvDurability::Immediate);
            txn.set(b"gotcha:mmm", b"not json").unwrap();
            txn.commit().await.unwrap();
        }

        let results = store.scan_prefix("gotcha:").await.unwrap();
        assert_eq!(
            results.len(),
            2,
            "corruption in the middle must not truncate the scan"
        );
        let keys: Vec<_> = results.iter().map(|r| r.key.as_str()).collect();
        assert!(
            keys.contains(&"gotcha:aaa"),
            "record before corruption must be returned"
        );
        assert!(
            keys.contains(&"gotcha:zzz"),
            "record after corruption must be returned"
        );
    }

    // ─── tombstoned lifecycle through the store ───────────────────────────────

    #[tokio::test]
    async fn tombstoned_record_survives_store_round_trip() {
        use crate::store::record::{RecordLifecycle, TombstoneReason};
        let (store, _dir) = temp_store();
        let mut r = make_record("file:src/deleted.rs");
        r.lifecycle = RecordLifecycle::Tombstoned {
            reason: TombstoneReason::FileDeleted,
            at: 1_710_520_800,
        };
        store.put("file:src/deleted.rs", &r).await.unwrap();
        let got = store.get("file:src/deleted.rs").await.unwrap().unwrap();
        match got.lifecycle {
            RecordLifecycle::Tombstoned { reason, at } => {
                assert_eq!(reason, TombstoneReason::FileDeleted);
                assert_eq!(at, 1_710_520_800);
            }
            other => panic!("expected Tombstoned, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn superseded_record_survives_store_round_trip() {
        use crate::store::record::RecordLifecycle;
        let (store, _dir) = temp_store();
        let mut r = make_record("gotcha:old-rule");
        r.lifecycle = RecordLifecycle::Superseded {
            by_key: "gotcha:new-rule".to_string(),
        };
        store.put("gotcha:old-rule", &r).await.unwrap();
        let got = store.get("gotcha:old-rule").await.unwrap().unwrap();
        match got.lifecycle {
            RecordLifecycle::Superseded { by_key } => {
                assert_eq!(by_key, "gotcha:new-rule");
            }
            other => panic!("expected Superseded, got {other:?}"),
        }
    }

    // ─── slug: error-recovery path ────────────────────────────────────────────

    #[test]
    fn slug_with_git_config_but_no_url_line_falls_back_to_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        // Valid .git/config, but no `url =` line — read_remote_url returns None.
        std::fs::write(
            git_dir.join("config"),
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n",
        )
        .unwrap();

        let slug = derive_slug(dir.path());
        // Must fall back to path hash — same as if no .git/config existed at all.
        let expected = {
            let input = dir.path().to_string_lossy().into_owned();
            let digest = Sha256::digest(input.as_bytes());
            hex::encode(&digest[..4])
        };
        assert_eq!(slug, expected, "no url= line must fall back to path hash");
    }

    #[test]
    fn slug_with_no_git_dir_falls_back_to_path() {
        let dir = tempfile::TempDir::new().unwrap();
        // Completely fresh dir, no .git at all.
        let slug = derive_slug(dir.path());
        let expected = {
            let input = dir.path().to_string_lossy().into_owned();
            let digest = Sha256::digest(input.as_bytes());
            hex::encode(&digest[..4])
        };
        assert_eq!(slug, expected);
    }

    // ─── prefix_end: invalid UTF-8 after increment ────────────────────────────

    #[test]
    fn prefix_end_0x7f_byte_increments_to_0x80_which_is_invalid_utf8() {
        // 0x7f (DEL) + 1 = 0x80, which is an invalid lone UTF-8 byte.
        // from_utf8 will fail → must return the sentinel "\u{ffff}", not panic.
        let input = String::from_utf8(vec![0x61, 0x7f]).unwrap(); // "a\x7f"
        let result = prefix_end(&input);
        // 0x7f increments to 0x80 — invalid UTF-8 → sentinel fallback
        assert_eq!(
            result, "\u{ffff}",
            "increment of 0x7f produces invalid UTF-8; must fall back to sentinel"
        );
    }

    #[test]
    fn prefix_end_0xfe_byte_increments_to_0xff_still_invalid_utf8() {
        // Similarly, 0xfe → 0xff is also invalid UTF-8.
        let input = unsafe { String::from_utf8_unchecked(vec![0x61, 0xfe]) };
        let result = prefix_end(&input);
        assert_eq!(result, "\u{ffff}");
    }

    // ─── put_batch ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn put_batch_empty_is_noop() {
        let (store, _dir) = temp_store();
        store.put_batch(&[]).await.unwrap();
        assert!(store.scan_prefix("gotcha:").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn put_batch_single_record_readable() {
        let (store, _dir) = temp_store();
        let r = make_record("gotcha:batch-single");
        store
            .put_batch(&[("gotcha:batch-single", &r)])
            .await
            .unwrap();
        let got = store.get("gotcha:batch-single").await.unwrap().unwrap();
        assert_eq!(got.key, "gotcha:batch-single");
        assert_eq!(got.value, r.value);
    }

    #[tokio::test]
    async fn put_batch_all_records_readable() {
        let (store, _dir) = temp_store();
        let records: Vec<Record> = (0..10)
            .map(|i| make_record(&format!("gotcha:b{i}")))
            .collect();
        let pairs: Vec<(&str, &Record)> = records.iter().map(|r| (r.key.as_str(), r)).collect();
        store.put_batch(&pairs).await.unwrap();
        let results = store.scan_prefix("gotcha:b").await.unwrap();
        assert_eq!(results.len(), 10);
    }

    #[tokio::test]
    async fn put_batch_mixed_durability_both_trees_written() {
        let (store, _dir) = temp_store();
        let immediate = make_record("gotcha:imm");
        let eventual = make_record("session:evt");
        store
            .put_batch(&[("gotcha:imm", &immediate), ("session:evt", &eventual)])
            .await
            .unwrap();
        assert!(store.get("gotcha:imm").await.unwrap().is_some());
        assert!(store.get("session:evt").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn put_batch_matches_sequential_put_for_same_records() {
        let (store_a, _dir_a) = temp_store();
        let (store_b, _dir_b) = temp_store();
        let records: Vec<Record> = (0..20)
            .map(|i| make_record(&format!("file:src/mod{i}.rs")))
            .collect();

        // Sequential puts.
        for r in &records {
            store_a.put(&r.key, r).await.unwrap();
        }
        // Batch put.
        let pairs: Vec<(&str, &Record)> = records.iter().map(|r| (r.key.as_str(), r)).collect();
        store_b.put_batch(&pairs).await.unwrap();

        let a = {
            let mut v = store_a.scan_prefix("file:").await.unwrap();
            v.sort_by(|x, y| x.key.cmp(&y.key));
            v
        };
        let b = {
            let mut v = store_b.scan_prefix("file:").await.unwrap();
            v.sort_by(|x, y| x.key.cmp(&y.key));
            v
        };
        assert_eq!(a.len(), b.len());
        for (ra, rb) in a.iter().zip(b.iter()) {
            assert_eq!(ra.key, rb.key);
            assert_eq!(ra.value, rb.value);
        }
    }

    /// 1,200-record batch must be measurably faster than 1,200 sequential puts.
    /// This test guards against the batch accidentally falling back to N fsyncs.
    ///
    /// Ignored by default (~60s). Run with: `cargo test --lib put_batch_1200 -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn put_batch_1200_faster_than_sequential() {
        use std::time::Instant;

        let (store_seq, _dir_seq) = temp_store();
        let (store_bat, _dir_bat) = temp_store();
        let records: Vec<Record> = (0..1200)
            .map(|i| make_record(&format!("file:src/f{i}.rs")))
            .collect();

        // Sequential baseline.
        let seq_start = Instant::now();
        for r in &records {
            store_seq.put(&r.key, r).await.unwrap();
        }
        let seq_ms = seq_start.elapsed().as_millis();

        // Batch.
        let pairs: Vec<(&str, &Record)> = records.iter().map(|r| (r.key.as_str(), r)).collect();
        let bat_start = Instant::now();
        store_bat.put_batch(&pairs).await.unwrap();
        let bat_ms = bat_start.elapsed().as_millis();

        // Batch must be strictly faster (at least 2× in any environment).
        assert!(
            bat_ms < seq_ms,
            "put_batch ({bat_ms}ms) was not faster than sequential puts ({seq_ms}ms)"
        );

        // Verify all records landed correctly.
        let results = store_bat.scan_prefix("file:").await.unwrap();
        assert_eq!(results.len(), 1200);
    }

    // ─── search (M-05-C / M-05-F) ─────────────────────────────────────────────

    #[tokio::test]
    async fn search_returns_matching_records() {
        let (store, _dir) = temp_store();
        let mut r = make_record("gotcha:async-race");
        r.value = "never use inference inside async context".to_string();
        store.put(&r.key, &r).await.unwrap();

        let results = store.search("inference", 10).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "gotcha:async-race");
    }

    #[tokio::test]
    async fn search_empty_and_whitespace_query_returns_empty() {
        let (store, _dir) = temp_store();
        let r = make_record("gotcha:foo");
        store.put(&r.key, &r).await.unwrap();
        for blank in ["", "  ", "\t", "\n"] {
            assert!(
                store.search(blank, 10).await.unwrap().is_empty(),
                "blank query {blank:?} must return empty"
            );
        }
    }

    #[tokio::test]
    async fn search_no_match_returns_empty() {
        let (store, _dir) = temp_store();
        let r = make_record("gotcha:foo");
        store.put(&r.key, &r).await.unwrap();
        assert!(store
            .search("absolutely_no_match_xyzzy99", 10)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn search_malformed_query_returns_partial_not_error() {
        // Malformed queries must not propagate Err — lenient parse returns
        // best-effort results.
        let (store, _dir) = temp_store();
        let mut r = make_record("gotcha:async-race");
        r.value = "tokio runtime inference race condition".to_string();
        store.put(&r.key, &r).await.unwrap();
        // "tokio AND" has a trailing operator — must not error
        let result = store.search("tokio AND", 10).await;
        assert!(result.is_ok(), "malformed query must not return Err");
    }

    #[tokio::test]
    async fn search_limit_caps_results() {
        let (store, _dir) = temp_store();
        for i in 0..10 {
            let mut r = make_record(&format!("gotcha:item-{i:02}"));
            r.value = "tokio runtime executor gotcha performance".to_string();
            store.put(&r.key, &r).await.unwrap();
        }
        assert_eq!(store.search("tokio", 1).await.unwrap().len(), 1);
        assert_eq!(store.search("tokio", 5).await.unwrap().len(), 5);
        assert_eq!(store.search("tokio", 10).await.unwrap().len(), 10);
        // limit > total docs must return all docs, not panic or error
        assert_eq!(store.search("tokio", 999).await.unwrap().len(), 10);
    }

    #[tokio::test]
    async fn search_deleted_record_not_returned() {
        // Delete should evict the tantivy entry too, not just rely on
        // post-filtering missing keys after a search hit.
        let (store, _dir) = temp_store();
        let mut r = make_record("gotcha:deleted");
        r.value = "this_unique_sentinel_deleted_record".to_string();
        store.put(&r.key, &r).await.unwrap();

        // Confirm it is searchable before deletion
        assert_eq!(
            store
                .search("this_unique_sentinel_deleted_record", 10)
                .await
                .unwrap()
                .len(),
            1
        );

        // Delete from SurrealKV (tantivy index still has the entry)
        store.delete("gotcha:deleted").await.unwrap();

        // Must return empty — the index hit is silently skipped
        let results = store
            .search("this_unique_sentinel_deleted_record", 10)
            .await
            .unwrap();
        assert!(
            results.is_empty(),
            "deleted record must not appear in search results"
        );
    }

    #[tokio::test]
    async fn search_delete_does_not_consume_top_k_slot() {
        let (store, _dir) = temp_store();

        let mut deleted = make_record("gotcha:deleted-slot");
        deleted.value = "shared_sentinel_term".to_string();
        store.put(&deleted.key, &deleted).await.unwrap();

        let mut live = make_record("gotcha:live-slot");
        live.value = "shared_sentinel_term".to_string();
        store.put(&live.key, &live).await.unwrap();

        store.delete(&deleted.key).await.unwrap();

        let results = store.search("shared_sentinel_term", 1).await.unwrap();
        assert_eq!(
            results.len(),
            1,
            "live hit should still fill the top-k slot"
        );
        assert_eq!(results[0].key, "gotcha:live-slot");
    }

    #[tokio::test]
    async fn search_returns_full_record_from_surrealkv_not_tantivy_stored_fields() {
        // Tantivy only stores 6 fields. The full Record (tags, confidence,
        // staleness, etc.) must come from SurrealKV via the key lookup.
        let (store, _dir) = temp_store();
        let mut r = make_record("gotcha:full-record-check");
        r.value = "sentinel_fullrecord_uniqueterm_xqz".to_string();
        r.tags = vec!["production".to_string(), "critical-path".to_string()];
        store.put(&r.key, &r).await.unwrap();

        let results = store
            .search("sentinel_fullrecord_uniqueterm_xqz", 10)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].tags,
            vec!["production", "critical-path"],
            "full tags must come from SurrealKV, not tantivy stored fields"
        );
    }

    /// M-05-F: 20 records total, 5 contain a unique sentinel term.
    /// Query must return exactly those 5 with no false positives.
    #[tokio::test]
    async fn search_m05f_20_records_returns_exactly_correct_5() {
        let (store, _dir) = temp_store();

        // 15 records with unrelated, varied content — must not appear in results
        for i in 0..15 {
            let mut r = make_record(&format!("gotcha:noise-{i:02}"));
            r.value = format!("background noise record about rayon and petgraph item {i}");
            store.put(&r.key, &r).await.unwrap();
        }

        // 5 target records containing the unique sentinel term
        let mut target_keys = Vec::new();
        for i in 0..5 {
            let mut r = make_record(&format!("gotcha:target-{i}"));
            r.value = format!("sentinel_m05f_unique record index {i} with extra text");
            store.put(&r.key, &r).await.unwrap();
            target_keys.push(r.key.clone());
        }

        let results = store.search("sentinel_m05f_unique", 20).await.unwrap();
        let result_keys: Vec<&str> = results.iter().map(|r| r.key.as_str()).collect();

        assert_eq!(
            results.len(),
            5,
            "expected exactly 5 results, got {}: {:?}",
            results.len(),
            result_keys
        );

        for k in &target_keys {
            assert!(
                result_keys.contains(&k.as_str()),
                "target key '{k}' missing from results"
            );
        }

        // No noise records leaked in
        for r in &results {
            assert!(
                r.key.starts_with("gotcha:target-"),
                "noise record '{}' must not appear in results",
                r.key
            );
        }
    }

    /// Worst-case Store volume: 5,000 records at realistic mati project scale
    /// (2,000-file codebase × 2-3 record types). All writes use put_batch
    /// (2 fsyncs total: 1 SurrealKV + 1 tantivy) matching how Layer 0 works.
    /// Proves BM25 returns exactly 20 targets from 4,980 noise records and
    /// that limit enforcement and full-record retrieval both hold at this scale.
    #[tokio::test]
    async fn search_5k_records_zero_false_positives_limit_and_full_record_correct() {
        let (store, _dir) = temp_store();

        // 4,980 noise records — single put_batch call (2 fsyncs total)
        let noise: Vec<Record> = (0..4_980_usize)
            .map(|i| {
                let mut r = make_record(&format!("file:src/module_{i:04}.rs"));
                r.value = format!(
                    "module {i} handles initialization routing configuration management dispatch"
                );
                r
            })
            .collect();
        let noise_pairs: Vec<(&str, &Record)> = noise.iter().map(|r| (r.key.as_str(), r)).collect();
        store.put_batch(&noise_pairs).await.unwrap();

        // 20 target records with unique sentinel + a meaningful tag we can
        // verify came from SurrealKV (not tantivy stored fields)
        let targets: Vec<Record> = (0..20_usize)
            .map(|i| {
                let mut r = make_record(&format!("gotcha:target-{i:02}"));
                r.value = format!("zqx_sentinel_5k_proof unique term record {i}");
                r.tags = vec!["verified-from-surrealkv".to_string()];
                r
            })
            .collect();
        let target_pairs: Vec<(&str, &Record)> =
            targets.iter().map(|r| (r.key.as_str(), r)).collect();
        store.put_batch(&target_pairs).await.unwrap();

        // ── correctness at limit=100 ─────────────────────────────────────────

        let results = store.search("zqx_sentinel_5k_proof", 100).await.unwrap();
        assert_eq!(
            results.len(),
            20,
            "expected 20 hits from 5,000 records, got {}",
            results.len()
        );

        let result_keys: Vec<&str> = results.iter().map(|r| r.key.as_str()).collect();
        let target_keys: Vec<&str> = targets.iter().map(|r| r.key.as_str()).collect();

        // All 20 targets present
        for k in &target_keys {
            assert!(result_keys.contains(k), "missing target: {k}");
        }
        // Zero noise leaked through
        for r in &results {
            assert!(
                r.key.starts_with("gotcha:target-"),
                "noise record '{}' must not appear in results",
                r.key
            );
        }

        // Full record came from SurrealKV — tantivy doesn't store tags
        for r in &results {
            assert_eq!(
                r.tags,
                vec!["verified-from-surrealkv"],
                "tags must be fetched from SurrealKV, key: {}",
                r.key
            );
        }

        // ── limit enforcement at scale ────────────────────────────────────────

        let limited = store.search("zqx_sentinel_5k_proof", 5).await.unwrap();
        assert_eq!(limited.len(), 5, "limit=5 must cap results at scale");

        // Over-limit returns exactly the matching set
        let over = store.search("zqx_sentinel_5k_proof", 999).await.unwrap();
        assert_eq!(
            over.len(),
            20,
            "limit > match count must return all 20 matches, not panic"
        );

        // ── ensure noise records are NOT findable by sentinel term ────────────

        // Pick a random noise record key, search by a term from its value
        // that does NOT appear in sentinel records
        let noise_only_results = store.search("zqx_sentinel_5k_proof", 100).await.unwrap();
        for r in &noise_only_results {
            assert!(
                !r.key.starts_with("file:src/module_"),
                "noise module record should not match sentinel query: {}",
                r.key
            );
        }
    }

    // ─── M-05-D: index rebuild ────────────────────────────────────────────────

    // Helper: make_record with a custom value (needed to control searchable content).
    fn make_record_v(key: &str, value: &str) -> Record {
        let mut r = make_record(key);
        r.value = value.to_string();
        r
    }

    // Helper: open a fresh store over an existing data directory (bypasses slug
    // derivation so tests can point at a tempdir directly).
    fn reopen_store(root: &std::path::Path) -> Store {
        let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
        let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
        let search = OnceCell::new();
        let _ = search.set(Search::open(&root.join("search_index")).unwrap());
        Store {
            knowledge,
            sessions,
            search,
            root: root.to_path_buf(),
            index_needs_rebuild: false,
        }
    }

    async fn reopen_store_open_and_rebuild_like(root: &std::path::Path) -> Store {
        let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
        let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
        let mut store = Store {
            knowledge,
            sessions,
            search: OnceCell::new(),
            root: root.to_path_buf(),
            index_needs_rebuild: false,
        };

        let search_path = store.root.join("search_index");
        let stale_marker = store.root.join(SEARCH_STALE_MARKER);
        let has_stale_marker = stale_marker.exists();
        let has_sync_pending = store.root.join(SEARCH_SYNC_PENDING).exists();

        if (has_stale_marker || has_sync_pending) && search_path.exists() {
            std::fs::remove_dir_all(&search_path).unwrap();
        }

        match Search::open(&search_path) {
            Ok(s) => {
                let _ = store.search.set(s);
            }
            Err(_) => {
                if search_path.exists() {
                    std::fs::remove_dir_all(&search_path).unwrap();
                }
                let _ = store.search.set(Search::open(&search_path).unwrap());
                store.index_needs_rebuild = true;
            }
        }

        if has_stale_marker || has_sync_pending {
            store.index_needs_rebuild = true;
        }

        if store.index_needs_rebuild {
            store.rebuild_search_index().await.unwrap();
            let _ = std::fs::remove_file(store.root.join(SEARCH_SYNC_PENDING));
            if has_stale_marker {
                let _ = std::fs::remove_file(&stale_marker);
            }
        }

        store
    }

    /// Write records, close, delete search_index/, reopen with a fresh empty
    /// index, call rebuild_search_index — all records must be searchable again.
    #[tokio::test]
    async fn rebuild_search_index_after_missing_index_restores_search() {
        let (store, _dir) = temp_store();
        let root = store.root.clone();

        // Write 10 records with a unique sentinel term in their values
        let records: Vec<Record> = (0..10)
            .map(|i| {
                make_record_v(
                    &format!("gotcha:rebuild-miss-{i:02}"),
                    "xq_rebuild_missing_sentinel unique term",
                )
            })
            .collect();
        let pairs: Vec<(&str, &Record)> = records.iter().map(|r| (r.key.as_str(), r)).collect();
        store.put_batch(&pairs).await.unwrap();
        store.close().await.unwrap();

        // Simulate missing index (deleted by user, first run after migration, etc.)
        std::fs::remove_dir_all(root.join("search_index")).unwrap();

        // Reopen with fresh empty index, then rebuild
        let store2 = reopen_store(&root);
        assert!(
            !store2.index_needs_rebuild(),
            "reopen_store sets flag=false; we test rebuild directly"
        );

        let committed = store2.rebuild_search_index().await.unwrap();
        assert_eq!(committed, 10, "rebuild must commit all 10 records");

        let results = store2
            .search("xq_rebuild_missing_sentinel", 20)
            .await
            .unwrap();
        assert_eq!(
            results.len(),
            10,
            "all records must be findable after rebuild"
        );
    }

    /// Corrupt meta.json → Store-level open logic must wipe and flag rebuild.
    /// After rebuild_search_index the record is searchable again.
    #[tokio::test]
    async fn rebuild_search_index_after_corrupt_index_restores_search() {
        let (store, _dir) = temp_store();
        let root = store.root.clone();

        let r = make_record_v(
            "gotcha:rebuild-corrupt",
            "xq_rebuild_corrupt_sentinel unique",
        );
        store.put("gotcha:rebuild-corrupt", &r).await.unwrap();
        store.close().await.unwrap();

        // Corrupt the index by overwriting meta.json with garbage
        std::fs::write(
            root.join("search_index").join("meta.json"),
            b"not valid json {{{{",
        )
        .unwrap();

        // Replicate the Store::open_and_rebuild recovery path: Search::open fails → wipe → reopen
        let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
        let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
        let search_path = root.join("search_index");
        let (search_cell, needs_rebuild) = {
            let cell = OnceCell::new();
            match Search::open(&search_path) {
                Ok(s) => {
                    let _ = cell.set(s);
                    (cell, false)
                }
                Err(_) => {
                    std::fs::remove_dir_all(&search_path).unwrap();
                    let _ = cell.set(Search::open(&search_path).unwrap());
                    (cell, true)
                }
            }
        };
        let store2 = Store {
            knowledge,
            sessions,
            search: search_cell,
            root: root.clone(),
            index_needs_rebuild: needs_rebuild,
        };

        assert!(
            store2.index_needs_rebuild(),
            "corrupt meta.json must trigger rebuild flag"
        );

        store2.rebuild_search_index().await.unwrap();

        let results = store2
            .search("xq_rebuild_corrupt_sentinel", 10)
            .await
            .unwrap();
        assert_eq!(
            results.len(),
            1,
            "record must be searchable after rebuild from corrupt state"
        );
        assert_eq!(results[0].key, "gotcha:rebuild-corrupt");
    }

    /// rebuild_search_index returns the exact number of records it committed.
    #[tokio::test]
    async fn rebuild_search_index_returns_committed_count() {
        let (store, _dir) = temp_store();
        let root = store.root.clone();

        let records: Vec<Record> = (0..7)
            .map(|i| make_record(&format!("file:src/mod_{i}.rs")))
            .collect();
        let pairs: Vec<(&str, &Record)> = records.iter().map(|r| (r.key.as_str(), r)).collect();
        store.put_batch(&pairs).await.unwrap();
        store.close().await.unwrap();

        // Fresh empty index — simulates post-corrupt open
        std::fs::remove_dir_all(root.join("search_index")).unwrap();
        let store2 = reopen_store(&root);
        let committed = store2.rebuild_search_index().await.unwrap();
        assert_eq!(
            committed, 7,
            "committed count must equal number of records in SurrealKV"
        );
    }

    #[tokio::test]
    async fn open_and_rebuild_like_wipes_stale_index_when_sync_pending_exists() {
        let (store, _dir) = temp_store();
        let root = store.root.clone();

        let deleted = make_record_v("gotcha:deleted-after-crash", "shared_crash_sentinel");
        let live = make_record_v("gotcha:live-after-crash", "shared_crash_sentinel");

        store.put(&deleted.key, &deleted).await.unwrap();
        store.put(&live.key, &live).await.unwrap();
        store.delete(&deleted.key).await.unwrap();

        // Simulate a stale tantivy entry surviving a crash window.
        store.ensure_search().unwrap().add_record(&deleted).unwrap();
        std::fs::write(root.join(SEARCH_SYNC_PENDING), b"").unwrap();
        store.close().await.unwrap();

        let reopened = reopen_store_open_and_rebuild_like(&root).await;
        let results = reopened.search("shared_crash_sentinel", 1).await.unwrap();
        assert_eq!(
            results.len(),
            1,
            "live record should fill top-k after rebuild"
        );
        assert_eq!(results[0].key, "gotcha:live-after-crash");
        assert!(
            !root.join(SEARCH_SYNC_PENDING).exists(),
            "successful rebuild should clear sync-pending marker"
        );
    }

    #[tokio::test]
    async fn put_leaves_sync_pending_when_search_cannot_initialize() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("mati_test");
        std::fs::create_dir_all(&root).unwrap();
        let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
        let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
        std::fs::write(root.join("search_index"), b"not a directory").unwrap();

        let store = Store {
            knowledge,
            sessions,
            search: OnceCell::new(),
            root: root.clone(),
            index_needs_rebuild: false,
        };

        let record = make_record("gotcha:search-sync-failure");
        store.put(&record.key, &record).await.unwrap();

        assert!(
            root.join(SEARCH_SYNC_PENDING).exists(),
            "failed search sync must leave the crash-fence marker in place"
        );
    }

    /// Calling rebuild_search_index twice must not panic; query deduplication
    /// in query_keys ensures each key appears exactly once in results.
    #[tokio::test]
    async fn rebuild_search_index_twice_is_safe() {
        let (store, _dir) = temp_store();
        let r = make_record_v("gotcha:idempotent", "xq_rebuild_idempotent_sentinel unique");
        store.put("gotcha:idempotent", &r).await.unwrap();

        store.rebuild_search_index().await.unwrap();
        store.rebuild_search_index().await.unwrap();

        let results = store
            .search("xq_rebuild_idempotent_sentinel", 10)
            .await
            .unwrap();
        assert_eq!(
            results.len(),
            1,
            "dedup must collapse duplicate tantivy entries to one result"
        );
    }

    /// Normal open (healthy index) must not set index_needs_rebuild.
    #[tokio::test]
    async fn open_healthy_index_does_not_set_rebuild_flag() {
        let (store, _dir) = temp_store();
        assert!(!store.index_needs_rebuild());
    }

    // ─── history (M-14) ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn history_empty_key_returns_error() {
        let (store, _dir) = temp_store();
        let result = store.history("", 0);
        assert!(result.is_err(), "empty key must be rejected");
    }

    #[tokio::test]
    async fn history_single_version() {
        let (store, _dir) = temp_store();
        store
            .put("gotcha:single", &make_record("gotcha:single"))
            .await
            .unwrap();

        let entries = store.history("gotcha:single", 0).unwrap();
        assert!(!entries.is_empty(), "must return at least one version");
        assert!(!entries[0].is_tombstone);
        assert!(entries[0].record.is_some());
        assert_eq!(entries[0].record.as_ref().unwrap().key, "gotcha:single");
    }

    #[tokio::test]
    async fn history_multiple_versions_newest_first() {
        let (store, _dir) = temp_store();
        let mut r = make_record("gotcha:multi");
        r.value = "v1".to_string();
        store.put("gotcha:multi", &r).await.unwrap();
        r.value = "v2".to_string();
        r.version.logical_clock = 2;
        store.put("gotcha:multi", &r).await.unwrap();
        r.value = "v3".to_string();
        r.version.logical_clock = 3;
        store.put("gotcha:multi", &r).await.unwrap();

        let entries = store.history("gotcha:multi", 0).unwrap();
        assert!(
            entries.len() >= 3,
            "expected >=3 versions, got {}",
            entries.len()
        );

        // Newest first: timestamps must be non-increasing
        for pair in entries.windows(2) {
            assert!(
                pair[0].timestamp_ns >= pair[1].timestamp_ns,
                "history must be newest-first: {} >= {}",
                pair[0].timestamp_ns,
                pair[1].timestamp_ns,
            );
        }

        // Newest entry should have the latest value
        let newest = entries[0].record.as_ref().unwrap();
        assert_eq!(newest.value, "v3");
    }

    #[tokio::test]
    async fn history_includes_tombstones() {
        let (store, _dir) = temp_store();
        store
            .put("gotcha:tomb", &make_record("gotcha:tomb"))
            .await
            .unwrap();

        // Use soft_delete (not hard delete) so SurrealKV retains the tombstone
        // marker in the version history. Store::delete is a hard delete that
        // erases all versions completely — the history API surfaces soft-delete
        // tombstones from lifecycle transitions.
        {
            let mut txn = store.knowledge.begin_with_mode(Mode::WriteOnly).unwrap();
            txn.set_durability(SkvDurability::Immediate);
            txn.soft_delete(b"gotcha:tomb").unwrap();
            txn.commit().await.unwrap();
        }

        let entries = store.history("gotcha:tomb", 0).unwrap();
        assert!(
            entries.len() >= 2,
            "must have create + soft-delete, got {}",
            entries.len()
        );
        // At least one tombstone must exist
        assert!(
            entries.iter().any(|e| e.is_tombstone),
            "tombstone must be present in history",
        );
    }

    #[tokio::test]
    async fn history_no_key_spill() {
        let (store, _dir) = temp_store();
        store
            .put("gotcha:alpha", &make_record("gotcha:alpha"))
            .await
            .unwrap();
        store
            .put(
                "gotcha:alpha-extended",
                &make_record("gotcha:alpha-extended"),
            )
            .await
            .unwrap();
        store
            .put("gotcha:beta", &make_record("gotcha:beta"))
            .await
            .unwrap();

        let entries = store.history("gotcha:alpha", 0).unwrap();
        for e in &entries {
            if let Some(ref rec) = e.record {
                assert_eq!(
                    rec.key, "gotcha:alpha",
                    "spilled into adjacent key: {}",
                    rec.key
                );
            }
        }
    }

    #[tokio::test]
    async fn history_limit() {
        let (store, _dir) = temp_store();
        let mut r = make_record("gotcha:limited");
        for i in 0..5 {
            r.value = format!("v{i}");
            r.version.logical_clock = i as u64;
            store.put("gotcha:limited", &r).await.unwrap();
        }

        let entries = store.history("gotcha:limited", 2).unwrap();
        assert!(
            entries.len() <= 2,
            "limit=2 but got {} entries",
            entries.len()
        );
    }

    #[tokio::test]
    async fn history_since_filters_old_versions() {
        let (store, _dir) = temp_store();
        let mut r = make_record("gotcha:since");
        r.value = "old".to_string();
        store.put("gotcha:since", &r).await.unwrap();

        // Capture a "since" timestamp between writes — use nanosecond
        // granularity so we can convert to seconds.
        let since_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        r.value = "new".to_string();
        r.version.logical_clock = 2;
        store.put("gotcha:since", &r).await.unwrap();

        let entries = store.history_since("gotcha:since", since_secs, 0).unwrap();
        // Should contain at least the "new" version
        assert!(
            !entries.is_empty(),
            "since filter should include the recent write",
        );
        // Verify all returned timestamps are >= since_secs
        for e in &entries {
            assert!(
                e.timestamp_secs >= since_secs.saturating_sub(1),
                "entry ts {} is before since {}",
                e.timestamp_secs,
                since_secs,
            );
        }
    }

    #[tokio::test]
    async fn records_since_with_dep() {
        let (store, _dir) = temp_store();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let old_ts = now.saturating_sub(3600);

        let mut old_rec = make_record("gotcha:old");
        old_rec.updated_at = old_ts;
        store.put("gotcha:old", &old_rec).await.unwrap();

        let mut new_gotcha = make_record("gotcha:new");
        new_gotcha.updated_at = now;
        store.put("gotcha:new", &new_gotcha).await.unwrap();

        let mut dep_rec = make_record("dep:cargo:serde");
        dep_rec.category = crate::store::record::Category::Dependency;
        dep_rec.updated_at = now;
        store.put("dep:cargo:serde", &dep_rec).await.unwrap();

        let since = now.saturating_sub(60);
        let results = store.records_since(since, 0).await.unwrap();
        let keys: Vec<&str> = results.iter().map(|r| r.key.as_str()).collect();

        assert!(keys.contains(&"gotcha:new"), "new gotcha should appear");
        assert!(
            keys.contains(&"dep:cargo:serde"),
            "dep record should appear"
        );
        assert!(
            !keys.contains(&"gotcha:old"),
            "old gotcha should be excluded"
        );

        // Verify newest-first ordering
        for pair in results.windows(2) {
            assert!(
                pair[0].updated_at >= pair[1].updated_at,
                "results must be newest-first",
            );
        }
    }

    #[tokio::test]
    async fn records_since_respects_limit() {
        let (store, _dir) = temp_store();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for i in 0..10 {
            let mut r = make_record(&format!("gotcha:lim-{i:02}"));
            r.updated_at = now;
            store.put(&r.key, &r).await.unwrap();
        }

        let results = store.records_since(now.saturating_sub(1), 3).await.unwrap();
        assert_eq!(results.len(), 3, "limit=3 should cap at 3");
    }

    #[test]
    fn history_entry_timestamp_conversion() {
        let entry = HistoryEntry {
            timestamp_secs: 1_710_520_800,
            timestamp_ns: 1_710_520_800_000_000_000,
            record: None,
            is_tombstone: false,
        };
        assert_eq!(entry.timestamp_secs, entry.timestamp_ns / 1_000_000_000);
    }

    // ─── lock_error_hint ──────────────────────────────────────────────────

    #[test]
    fn lock_error_hint_rewrites_real_lock_contention_error() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("knowledge.db");
        std::fs::create_dir_all(&db_path).unwrap();

        // Write a fake LOCK file with a PID
        std::fs::write(db_path.join("LOCK"), "12345\n").unwrap();

        let err = anyhow::anyhow!("Database at /foo/LOCK is already locked by another process");
        let result = lock_error_hint(err, &db_path);
        let msg = format!("{result}");
        assert!(
            msg.contains("another mati process holds the lock"),
            "should rewrite lock error, got: {msg}"
        );
        assert!(
            msg.contains("PID: 12345"),
            "should include holder PID, got: {msg}"
        );
    }

    #[test]
    fn lock_error_hint_passes_through_non_lock_errors() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("knowledge.db");
        std::fs::create_dir_all(&db_path).unwrap();

        // LOCK file exists (as it always does after first use)
        std::fs::write(db_path.join("LOCK"), "99999\n").unwrap();

        let err = anyhow::anyhow!("WAL segment corrupt at offset 1234");
        let result = lock_error_hint(err, &db_path);
        let msg = format!("{result}");
        assert!(
            msg.contains("WAL segment corrupt"),
            "non-lock errors must pass through unchanged, got: {msg}"
        );
        assert!(
            !msg.contains("another mati process"),
            "non-lock errors must NOT be rewritten to lock errors, got: {msg}"
        );
    }
}
