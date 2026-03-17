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
use sha2::{Digest, Sha256};
use surrealkv::{
    Durability as SkvDurability, LSMIterator, Mode, Options, Transaction, Tree, TreeBuilder,
    VLogChecksumLevel,
};

use super::record::Record;
use super::Durability;
use crate::search::Search;

// 90 days expressed as nanoseconds — retention period for sessions.db
const SESSIONS_RETENTION_NS: u64 = 90 * 24 * 60 * 60 * 1_000_000_000u64;

/// Persistent knowledge store for a single mati project.
///
/// Wraps two SurrealKV trees:
/// - `knowledge` — user-visible records (gotchas, files, decisions, …)
/// - `sessions`  — analytics, hook events, compliance logs
///
/// All public methods are synchronous wrappers; `commit` inside SurrealKV
/// is `async`, so callers must be in a `tokio` context.
pub struct Store {
    knowledge: Tree,
    sessions: Tree,
    /// Tantivy full-text index — kept open for the session lifetime.
    search: Search,
    /// Absolute path to `~/.mati/<slug>/`
    pub root: PathBuf,
}

impl Store {
    /// Open (or create) both trees for the project rooted at `repo_root`.
    ///
    /// Creates `~/.mati/<slug>/` if it does not exist.
    pub fn open(repo_root: &Path) -> Result<Self> {
        let slug = derive_slug(repo_root);
        let home = dirs::home_dir().context("cannot determine home directory")?;
        let root = home.join(".mati").join(&slug);
        std::fs::create_dir_all(&root)
            .with_context(|| format!("cannot create mati dir at {}", root.display()))?;

        let knowledge = open_knowledge_tree(root.join("knowledge.db"))?;
        let sessions  = open_sessions_tree(root.join("sessions.db"))?;
        let search    = Search::open(&root.join("search_index"))?;

        Ok(Self { knowledge, sessions, search, root })
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

        let bytes = serde_json::to_vec(record)
            .with_context(|| format!("failed to serialize record for key '{key}'"))?;
        txn.set(key.as_bytes(), bytes)?;
        txn.commit().await?;
        self.search.add_record(record)?;
        Ok(())
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
                Durability::Eventual  => eventual.push((key, record)),
            }
        }

        if !immediate.is_empty() {
            let mut txn = self.knowledge.begin_with_mode(Mode::WriteOnly)?;
            txn.set_durability(SkvDurability::Immediate);
            for (key, record) in &immediate {
                let bytes = serde_json::to_vec(record)
                    .with_context(|| format!("failed to serialize record for key '{key}'"))?;
                txn.set(key.as_bytes(), bytes)?;
            }
            txn.commit().await?;
        }

        if !eventual.is_empty() {
            let mut txn = self.sessions.begin_with_mode(Mode::WriteOnly)?;
            txn.set_durability(SkvDurability::Eventual);
            for (key, record) in &eventual {
                let bytes = serde_json::to_vec(record)
                    .with_context(|| format!("failed to serialize record for key '{key}'"))?;
                txn.set(key.as_bytes(), bytes)?;
            }
            txn.commit().await?;
        }

        // Single tantivy commit for the whole batch — one fsync regardless of
        // how many records were written to SurrealKV above.
        self.search.add_records(records)?;
        Ok(())
    }

    /// Delete a record by key. No-op if the key does not exist.
    pub async fn delete(&self, key: &str) -> Result<()> {
        let tree = self.tree_for(key);
        let mut txn = tree.begin_with_mode(Mode::WriteOnly)?;
        txn.set_durability(skv_durability(Durability::for_key(key)));
        txn.delete(key.as_bytes())?;
        txn.commit().await?;
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
            match serde_json::from_slice::<Record>(&bytes) {
                Ok(record) => records.push(record),
                Err(e) => {
                    tracing::warn!("skipping malformed record during scan: {e}");
                }
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
                Durability::Eventual  => eventual.push((key, value)),
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
                Ok(s)  => keys.push(s.to_string()),
                Err(e) => tracing::warn!("skipping non-UTF8 key in scan_keys: {e}"),
            }
        }
        Ok(keys)
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
        self.search.close()?;
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
        anyhow::ensure!(result.is_some(), "ping sentinel write was not visible on read-back");

        Ok(now_micros() - start)
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
    let input = read_remote_url(repo_root)
        .unwrap_or_else(|| repo_root.to_string_lossy().into_owned());

    let digest = Sha256::digest(input.as_bytes());
    hex::encode(&digest[..4]) // 4 bytes = 8 hex chars
}

/// Attempt to extract the first `url =` line from `.git/config`.
fn read_remote_url(repo_root: &Path) -> Option<String> {
    let config = std::fs::read_to_string(repo_root.join(".git").join("config")).ok()?;
    config
        .lines()
        .find(|l| l.trim_start().starts_with("url ="))
        .map(|l| l.splitn(2, '=').nth(1).unwrap_or("").trim().to_owned())
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

/// Read and deserialize a record from an active transaction.
fn read_record(txn: &Transaction, key: &str) -> Result<Option<Record>> {
    match txn.get(key.as_bytes())? {
        None => Ok(None),
        Some(bytes) => {
            let record = serde_json::from_slice::<Record>(&bytes)
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
        let sessions  = open_sessions_tree(root.join("sessions.db")).unwrap();
        let search    = Search::open(&root.join("search_index")).unwrap();
        let store = Store { knowledge, sessions, search, root: root.clone() };
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
        };

        store.put("gotcha:alpha", &make_record("gotcha:alpha")).await.unwrap();
        store.put("gotcha:beta", &make_record("gotcha:beta")).await.unwrap();
        store.put("gotcha:gamma", &make_record("gotcha:gamma")).await.unwrap();
        store.put("file:src/main.rs", &make_record("file:src/main.rs")).await.unwrap();

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
            }
        };

        // Write 100 records, then explicitly close to release LOCK.
        {
            let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
            let sessions  = open_sessions_tree(root.join("sessions.db")).unwrap();
            let search    = Search::open(&root.join("search_index")).unwrap();
            let store = Store { knowledge, sessions, search, root: root.clone() };
            for i in 0..100 {
                let r = make_record(i);
                store.put(&r.key, &r).await.unwrap();
            }
            store.close().await.unwrap();
        }

        // Reopen and verify all 100 are present.
        {
            let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
            let sessions  = open_sessions_tree(root.join("sessions.db")).unwrap();
            let search    = Search::open(&root.join("search_index")).unwrap();
            let store = Store { knowledge, sessions, search, root: root.clone() };
            let results = store.scan_prefix("gotcha:").await.unwrap();
            assert_eq!(results.len(), 100, "expected 100 records after reopen, got {}", results.len());
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
            Category, ConfidenceScore, Priority, QualityScore, RecordLifecycle,
            RecordSource, RecordVersion, StalenessScore,
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
        store.put("gotcha:keep",   &make_record("gotcha:keep")).await.unwrap();
        store.put("gotcha:remove", &make_record("gotcha:remove")).await.unwrap();
        store.delete("gotcha:remove").await.unwrap();
        assert!(store.get("gotcha:keep").await.unwrap().is_some(), "sibling must survive");
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
        store.put("gotcha:alpha",     &make_record("gotcha:alpha")).await.unwrap();
        store.put("file:src/main.rs", &make_record("file:src/main.rs")).await.unwrap();
        store.put("decision:arch",    &make_record("decision:arch")).await.unwrap();

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
            assert_eq!(r.value, format!("sentinel:{}", r.key),
                "value mismatch for key '{}'", r.key);
        }
    }

    #[tokio::test]
    async fn scan_prefix_excludes_adjacent_namespaces() {
        // prefix_end("gotcha:") == "gotcha;" — "decision:" and "file:" fall outside.
        let (store, _dir) = temp_store();
        store.put("gotcha:real",     &make_record("gotcha:real")).await.unwrap();
        store.put("decision:before", &make_record("decision:before")).await.unwrap();
        store.put("file:after",      &make_record("file:after")).await.unwrap();

        let results = store.scan_prefix("gotcha:").await.unwrap();
        assert_eq!(results.len(), 1, "only gotcha: keys should appear");
        assert_eq!(results[0].key, "gotcha:real");
    }

    // ─── cross-tree isolation ──────────────────────────────────────────────────

    #[tokio::test]
    async fn knowledge_and_session_trees_are_isolated() {
        let (store, _dir) = temp_store();
        store.put("gotcha:in-knowledge", &make_record("gotcha:in-knowledge")).await.unwrap();
        store.put("session:12345",       &make_record("session:12345")).await.unwrap();

        let gotcha_results  = store.scan_prefix("gotcha:").await.unwrap();
        let session_results = store.scan_prefix("session:").await.unwrap();

        assert_eq!(gotcha_results.len(), 1);
        assert_eq!(gotcha_results[0].key, "gotcha:in-knowledge");
        assert_eq!(session_results.len(), 1);
        assert_eq!(session_results[0].key, "session:12345");
        assert!(gotcha_results.iter().all(|r| !r.key.starts_with("session:")),
            "session records must not appear in gotcha: scan");
        assert!(session_results.iter().all(|r| !r.key.starts_with("gotcha:")),
            "gotcha records must not appear in session: scan");
    }

    // ─── corrupt record tolerance ──────────────────────────────────────────────

    #[tokio::test]
    async fn scan_prefix_skips_corrupt_records_and_returns_valid_ones() {
        let (store, _dir) = temp_store();
        store.put("gotcha:good", &make_record("gotcha:good")).await.unwrap();

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
        assert_eq!(results.len(), 0, "all corrupt — must return empty, not panic");
    }

    // ─── ping ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn ping_multiple_calls_all_succeed() {
        let (store, _dir) = temp_store();
        for i in 0..10 {
            let latency = store.ping().await
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
        ).unwrap();

        let actual_slug = derive_slug(dir.path());
        assert_eq!(actual_slug, expected_slug,
            "slug must equal SHA-256(remote URL)[0..4] hex");

        // Also verify the path-derived slug for the same dir would differ
        // (i.e., the URL was actually preferred over the path).
        let path_slug = {
            let input = dir.path().to_string_lossy().into_owned();
            let digest = Sha256::digest(input.as_bytes());
            hex::encode(&digest[..4])
        };
        assert_ne!(actual_slug, path_slug,
            "URL slug must differ from the path slug for the same directory");
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
            ).unwrap();
            (derive_slug(dir.path()), dir)
        };
        let (slug_a, _dir_a) = make_repo("https://github.com/example/same-repo.git");
        let (slug_b, _dir_b) = make_repo("https://github.com/example/same-repo.git");
        assert_eq!(slug_a, slug_b, "same remote URL must always produce the same slug");
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
            ).unwrap();
            (derive_slug(dir.path()), dir)
        };
        let (slug_a, _dir_a) = make_repo("https://github.com/org/repo-alpha.git");
        let (slug_b, _dir_b) = make_repo("https://github.com/org/repo-beta.git");
        assert_ne!(slug_a, slug_b, "different remote URLs must produce different slugs");
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
        assert_eq!(prefix_end("gotcha:"),   "gotcha;");
        assert_eq!(prefix_end("file:"),     "file;");
        assert_eq!(prefix_end("decision:"), "decision;");
        assert_eq!(prefix_end("session:"),  "session;");
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
        assert_eq!(results.len(), 1, "3 overwrites of the same key must yield 1 result in scan");
        assert_eq!(results[0].value, "v3", "scan must return the latest value");
        assert_eq!(results[0].version.logical_clock, 3);
    }

    // ─── full field integrity through the store ────────────────────────────────

    #[tokio::test]
    async fn put_get_preserves_all_record_fields() {
        use crate::store::record::{
            Category, ConfidenceScore, Priority, QualityScore, QualitySignal, QualityTier,
            Record, RecordLifecycle, RecordSource, RecordVersion, StalenessScore,
            StalenessSignal, StalenessTier,
        };

        let (store, _dir) = temp_store();
        let device_id = uuid::Uuid::new_v4();

        // Construct a fully-populated record — every non-default field set.
        let written = Record {
            key: "gotcha:full-fields".to_string(),
            value: "Never hold a write txn across an await point.".to_string(),
            category: Category::Gotcha,
            priority: Priority::Critical,
            tags: vec!["async".to_string(), "tokio".to_string(), "surrealkv".to_string()],
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
            version: RecordVersion { device_id, logical_clock: 7, wall_clock: 1_710_520_900 },
            quality: QualityScore {
                value: 0.78,
                tier: QualityTier::Good,
                signals: vec![QualitySignal::HasImperativeVerb, QualitySignal::HasCausality],
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
        assert_eq!(read.staleness.last_record_sha, written.staleness.last_record_sha);
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
        assert_eq!(read.confidence.confirmation_count, written.confidence.confirmation_count);
        assert_eq!(read.confidence.contributor_count, written.confidence.contributor_count);
        assert_eq!(read.confidence.last_challenged, written.confidence.last_challenged);
        assert_eq!(read.confidence.challenge_count, written.confidence.challenge_count);
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
            let sessions  = open_sessions_tree(root.join("sessions.db")).unwrap();
            let search    = Search::open(&root.join("search_index")).unwrap();
            let store = Store { knowledge, sessions, search, root: root.clone() };
            for i in 0..10 {
                let key = format!("session:{i:04}");
                store.put(&key, &make_record(&key)).await.unwrap();
            }
            store.close().await.unwrap(); // must fsync/flush sessions tree on clean close
        }

        {
            let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
            let sessions  = open_sessions_tree(root.join("sessions.db")).unwrap();
            let search    = Search::open(&root.join("search_index")).unwrap();
            let store = Store { knowledge, sessions, search, root: root.clone() };
            let results = store.scan_prefix("session:").await.unwrap();
            assert_eq!(results.len(), 10,
                "Eventual session records must survive a clean close+reopen");
            store.close().await.unwrap();
        }
    }

    // ─── corruption tolerance: corrupt record in the middle ───────────────────

    #[tokio::test]
    async fn scan_prefix_corrupt_in_middle_does_not_stop_iteration() {
        // Regression: if scan stops early on corruption rather than skipping,
        // valid records after the corrupt one would silently vanish.
        let (store, _dir) = temp_store();

        store.put("gotcha:aaa", &make_record("gotcha:aaa")).await.unwrap(); // before corrupt
        store.put("gotcha:zzz", &make_record("gotcha:zzz")).await.unwrap(); // after corrupt

        // Inject corruption lexicographically between the two valid records.
        {
            let mut txn = store.knowledge.begin().unwrap();
            txn.set_durability(SkvDurability::Immediate);
            txn.set(b"gotcha:mmm", b"not json").unwrap();
            txn.commit().await.unwrap();
        }

        let results = store.scan_prefix("gotcha:").await.unwrap();
        assert_eq!(results.len(), 2,
            "corruption in the middle must not truncate the scan");
        let keys: Vec<_> = results.iter().map(|r| r.key.as_str()).collect();
        assert!(keys.contains(&"gotcha:aaa"), "record before corruption must be returned");
        assert!(keys.contains(&"gotcha:zzz"), "record after corruption must be returned");
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
        r.lifecycle = RecordLifecycle::Superseded { by_key: "gotcha:new-rule".to_string() };
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
        ).unwrap();

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
        assert_eq!(result, "\u{ffff}",
            "increment of 0x7f produces invalid UTF-8; must fall back to sentinel");
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
        store.put_batch(&[("gotcha:batch-single", &r)]).await.unwrap();
        let got = store.get("gotcha:batch-single").await.unwrap().unwrap();
        assert_eq!(got.key, "gotcha:batch-single");
        assert_eq!(got.value, r.value);
    }

    #[tokio::test]
    async fn put_batch_all_records_readable() {
        let (store, _dir) = temp_store();
        let records: Vec<Record> = (0..10).map(|i| make_record(&format!("gotcha:b{i}"))).collect();
        let pairs: Vec<(&str, &Record)> = records.iter()
            .map(|r| (r.key.as_str(), r))
            .collect();
        store.put_batch(&pairs).await.unwrap();
        let results = store.scan_prefix("gotcha:b").await.unwrap();
        assert_eq!(results.len(), 10);
    }

    #[tokio::test]
    async fn put_batch_mixed_durability_both_trees_written() {
        let (store, _dir) = temp_store();
        let immediate = make_record("gotcha:imm");
        let eventual  = make_record("session:evt");
        store.put_batch(&[
            ("gotcha:imm",  &immediate),
            ("session:evt", &eventual),
        ]).await.unwrap();
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
    #[tokio::test]
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

}
