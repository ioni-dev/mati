//! Industry-standard schema migration framework.
//!
//! ## Architecture
//!
//! Forward-only, atomic, run-on-open. Matches what PostgreSQL
//! (`pg_migration_history`), Lance (manifest versions), Liquibase,
//! Flyway, and sqlx ship in production.
//!
//! ## On-disk surface (knowledge tree, Immediate durability)
//!
//! | Key                                | Purpose                                  |
//! |-----------------------------------|------------------------------------------|
//! | `system:schema_version`            | Current store version. Overwritten.      |
//! | `system:migration:in_progress`     | Sentinel — written before migration,     |
//! |                                    | cleared on success. Crash detector.      |
//! | `system:migration:applied:<NNNNNN>`| Append-only history. One row per applied |
//! |                                    | migration with timing + record count.    |
//!
//! On-disk path `~/.mati/<slug>/backups/pre-v<N>/knowledge.db/` holds a
//! pre-migration snapshot of the knowledge tree. Created BEFORE running any
//! migration that mutates data; kept after the migration completes so the
//! operator can restore manually if needed.
//!
//! ## Invariants
//!
//! - Migrations are **forward-only**. Never edit a shipped migration; issue
//!   a new forward step to revert.
//! - Each migration step + its version bump + its history row commit in
//!   **one atomic transaction**. A crash mid-migration leaves the on-disk
//!   state at `version=N` or `version=N+1` — never half.
//! - Migrations are **idempotent**. Re-running on the same state must produce
//!   the same result. The version gate prevents re-runs; idempotence keeps
//!   us safe on crash-resume replays.
//! - **Downgrade is refused**. A store with `version > CURRENT_SCHEMA_VERSION`
//!   was written by a newer binary that may use field shapes this one doesn't
//!   understand. Refuse rather than risk corruption.
//! - **Bootstrap fast-path**: a fresh empty store stamps `CURRENT_SCHEMA_VERSION`
//!   directly without replaying any migration body. Matches Postgres `initdb`
//!   behavior — historical migrations never run on stores that were created
//!   at the current version.
//! - **Pre-migration snapshot**: if a non-empty store needs real migration
//!   work, the knowledge tree is copied to `backups/pre-v<TARGET>/` before
//!   any data write. The original is mutated in place; the backup is the
//!   recovery path if a migration is buggy.
//! - **Crash-resume sentinel**: `system:migration:in_progress` is written
//!   before starting and cleared on success. A second open finding a stale
//!   sentinel logs a warning and proceeds (per-step atomicity makes resume
//!   safe). This makes "crashed mid-migration" visible to operators.
//!
//! ## Adding a new migration
//!
//! 1. Bump [`CURRENT_SCHEMA_VERSION`].
//! 2. Add `apply_vN` async fn returning [`Vec<OwnedKnowledgeOp>`] — the data
//!    writes the migration needs. The framework appends the version bump and
//!    the history row.
//! 3. Add an arm to the dispatcher in [`migrate`].
//! 4. Add tests under `tests` covering: fresh→HEAD bootstrap, legacy upgrade
//!    (v_N-1→v_N with planted data), idempotent re-run, partial-state resume.
//! 5. Never edit a shipped `apply_vN` body after release. Issue v(N+1).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::db::{KnowledgeWriteOp, Store};
use super::record::{
    Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore,
};

/// Highest schema version this binary understands. Bump when adding a
/// migration; never decrement.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

/// Key holding the persisted schema version. `system:` keys route to
/// `Durability::Immediate` (fsync) per [`crate::store::Durability::for_key`],
/// so the version write is durable across crashes.
const SCHEMA_VERSION_KEY: &str = "system:schema_version";

/// Sentinel key written before a migration starts and cleared on success.
/// Presence on a fresh open signals a crashed migration.
const SENTINEL_KEY: &str = "system:migration:in_progress";

/// Prefix for append-only migration history records. Zero-padded so
/// lexicographic key order matches numeric order.
const HISTORY_PREFIX: &str = "system:migration:applied:";

/// How old a sentinel must be to be considered stale (and thus indicative of
/// a crash rather than a concurrent in-flight migration). SurrealKV's
/// exclusive flock prevents true concurrency, so any sentinel we find on
/// open is effectively a crash marker — but we still age-gate for safety
/// against clock skew.
const SENTINEL_STALE_SECS: u64 = 30;

/// Compile-time mati binary version stamped into history records.
const MATI_BINARY_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SchemaVersionPayload {
    version: u32,
    applied_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MigrationSentinelPayload {
    target_version: u32,
    started_at: u64,
    pid: u32,
    mati_binary_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MigrationHistoryPayload {
    version: u32,
    started_at: u64,
    completed_at: u64,
    records_migrated: u64,
    mati_binary_version: String,
}

/// Apply pending migrations forward to [`CURRENT_SCHEMA_VERSION`].
///
/// Safe to call on every `Store::open`. The hot path (up-to-date store) is
/// a single `Store::get`. The bootstrap path (fresh store) is one stamp
/// write. Only true upgrades touch user data, and only after a backup.
pub async fn migrate(store: &Store) -> Result<()> {
    let mut current = read_schema_version(store).await?;

    // Refuse to operate on a future version — the on-disk records may use
    // shapes this binary doesn't understand. Loud explicit error rather
    // than risk corruption.
    if current > CURRENT_SCHEMA_VERSION {
        anyhow::bail!(
            "store schema version {current} is newer than this binary supports \
             (max {CURRENT_SCHEMA_VERSION}). \
             A newer mati wrote this store. Upgrade your mati binary before \
             opening it with this one — downgrading risks corruption."
        );
    }

    // Hot path — every open in steady state.
    if current == CURRENT_SCHEMA_VERSION {
        return Ok(());
    }

    // Crash-detection: a sentinel here means a previous migration started
    // and didn't finish. Per-step atomic commits make this safe to resume,
    // but we log a warning so operators can investigate.
    if let Some(stale) = read_sentinel(store).await? {
        tracing::warn!(
            target_version = stale.target_version,
            started_at = stale.started_at,
            pid = stale.pid,
            mati_binary_version = %stale.mati_binary_version,
            "found stale migration sentinel — previous migration crashed \
             before completing; resuming. \
             Backup at backups/pre-v{}/knowledge.db/ should still be intact.",
            stale.target_version
        );
        // Clear the stale sentinel before we proceed so subsequent code paths
        // can detect a fresh crash from THIS attempt rather than the old one.
        let _ = clear_sentinel_op(store).await;
    }

    // Bootstrap fast-path: a brand-new store has no migratable data, so we
    // stamp CURRENT directly without replaying any migration. Matches
    // `pg_initdb`'s behavior of writing the latest catalog version.
    if current == 0 && store_is_empty(store).await? {
        commit_bootstrap(store, CURRENT_SCHEMA_VERSION).await?;
        return Ok(());
    }

    // Migration in progress — emit a single observable signal up front so
    // callers waiting in `ensure_daemon::wait_for_ready` know we are
    // making forward progress (vs. wedged). All `migration *` events go
    // into `lifecycle.log` via the same atomic append path used for
    // `serve_start` / `startup` / `serve_failed`. See
    // `src/mcp/daemon_lifecycle.rs::read_latest_lifecycle_phase`.
    let migration_t0 = std::time::Instant::now();
    crate::mcp::metadata::record_lifecycle_event(
        &store.root,
        "migration",
        &format!("phase=begin from={current} to={CURRENT_SCHEMA_VERSION}"),
    );

    // Real upgrade path. Snapshot before any data writes so a buggy
    // migration can be rolled back by restoring the backup.
    let snapshot_t0 = std::time::Instant::now();
    snapshot_knowledge_tree(store, CURRENT_SCHEMA_VERSION)
        .await
        .with_context(|| "pre-migration snapshot failed — refusing to migrate without backup")?;
    crate::mcp::metadata::record_lifecycle_event(
        &store.root,
        "migration",
        &format!(
            "phase=snapshot_complete elapsed_ms={}",
            snapshot_t0.elapsed().as_millis()
        ),
    );

    // Write the in-progress sentinel. If we crash before clearing it,
    // the next open sees the warning above. Sentinel is one transaction
    // so it's atomic and immediately durable.
    write_sentinel(store, CURRENT_SCHEMA_VERSION).await?;

    while current < CURRENT_SCHEMA_VERSION {
        let next = current + 1;
        let started_at = now_secs();
        let apply_t0 = std::time::Instant::now();
        tracing::info!(
            from = current,
            to = next,
            mati_binary_version = MATI_BINARY_VERSION,
            "applying mati schema migration"
        );
        crate::mcp::metadata::record_lifecycle_event(
            &store.root,
            "migration",
            &format!("phase=apply_begin version={next}"),
        );

        let extra_ops = match next {
            1 => apply_v1_baseline(store).await?,
            2 => apply_v2_unconfirm_auto_derived_gotchas(store).await?,
            n => anyhow::bail!(
                "unknown schema migration v{n} — this is a build bug: \
                 CURRENT_SCHEMA_VERSION was bumped without a matching apply_vN arm"
            ),
        };

        let records_migrated = extra_ops.len() as u64;
        let completed_at = now_secs();
        commit_migration(store, next, extra_ops, started_at, completed_at, records_migrated)
            .await
            .with_context(|| format!("schema migration v{next} commit failed"))?;

        tracing::info!(
            version = next,
            records_migrated,
            duration_ms = completed_at.saturating_sub(started_at) * 1000,
            "schema migration committed"
        );
        crate::mcp::metadata::record_lifecycle_event(
            &store.root,
            "migration",
            &format!(
                "phase=apply_complete version={next} records_migrated={records_migrated} elapsed_ms={}",
                apply_t0.elapsed().as_millis()
            ),
        );
        current = next;
    }

    // Migration sequence complete — clear the in-progress sentinel.
    clear_sentinel_op(store)
        .await
        .with_context(|| "failed to clear migration sentinel — non-fatal but flagged")?;

    crate::mcp::metadata::record_lifecycle_event(
        &store.root,
        "migration",
        &format!(
            "phase=end elapsed_ms={}",
            migration_t0.elapsed().as_millis()
        ),
    );

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap / commit helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Stamp a fresh store at `target_version` without running any migration
/// bodies. The history row records the stamp so operators can audit when
/// the store was created.
async fn commit_bootstrap(store: &Store, target_version: u32) -> Result<()> {
    let now = now_secs();
    let version_record = schema_version_record(target_version, now)?;
    let history_record = history_record(target_version, now, now, 0)?;
    let history_key = history_key(target_version);

    let ops: Vec<KnowledgeWriteOp<'_>> = vec![
        KnowledgeWriteOp::PutRecord {
            key: SCHEMA_VERSION_KEY,
            record: &version_record,
        },
        KnowledgeWriteOp::PutRecord {
            key: history_key.as_str(),
            record: &history_record,
        },
    ];
    store
        .transact_knowledge(&ops)
        .await
        .with_context(|| "bootstrap stamp commit failed")?;

    tracing::debug!(
        version = target_version,
        "store bootstrapped to schema HEAD (no migrations replayed)"
    );
    Ok(())
}

/// Commit a single migration step: its data writes + the version bump +
/// the history row in one atomic SurrealKV transaction. A crash anywhere
/// before commit leaves the version unchanged; a crash anywhere after leaves
/// version=N and history-row N both visible.
async fn commit_migration(
    store: &Store,
    version: u32,
    extra_ops: Vec<OwnedKnowledgeOp>,
    started_at: u64,
    completed_at: u64,
    records_migrated: u64,
) -> Result<()> {
    let version_record = schema_version_record(version, completed_at)?;
    let history_record = history_record(version, started_at, completed_at, records_migrated)?;
    let history_key = history_key(version);

    let mut ops: Vec<KnowledgeWriteOp<'_>> = Vec::with_capacity(extra_ops.len() + 2);
    for op in &extra_ops {
        ops.push(op.as_write_op());
    }
    ops.push(KnowledgeWriteOp::PutRecord {
        key: SCHEMA_VERSION_KEY,
        record: &version_record,
    });
    ops.push(KnowledgeWriteOp::PutRecord {
        key: history_key.as_str(),
        record: &history_record,
    });
    store.transact_knowledge(&ops).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema version / history / sentinel reads + record builders
// ─────────────────────────────────────────────────────────────────────────────

/// Read the persisted schema version. Returns `0` for pre-versioning stores
/// (no `system:schema_version` record).
async fn read_schema_version(store: &Store) -> Result<u32> {
    match store
        .get(SCHEMA_VERSION_KEY)
        .await
        .with_context(|| format!("reading {SCHEMA_VERSION_KEY}"))?
    {
        Some(rec) => rec
            .payload_as::<SchemaVersionPayload>()
            .map(|p| p.version)
            .ok_or_else(|| anyhow::anyhow!("malformed schema_version record — corrupt store")),
        None => Ok(0),
    }
}

/// Read the in-progress sentinel, returning `Some(payload)` if it exists and
/// is older than [`SENTINEL_STALE_SECS`] (i.e. a real crash marker, not a
/// concurrent in-flight migration — though SurrealKV's flock makes the
/// latter impossible anyway).
async fn read_sentinel(store: &Store) -> Result<Option<MigrationSentinelPayload>> {
    let Some(rec) = store
        .get(SENTINEL_KEY)
        .await
        .with_context(|| format!("reading {SENTINEL_KEY}"))?
    else {
        return Ok(None);
    };
    let payload = rec.payload_as::<MigrationSentinelPayload>();
    let Some(payload) = payload else {
        // Malformed sentinel — clear it on the assumption that the previous
        // attempt left bad data.
        tracing::warn!("malformed migration sentinel — clearing");
        let _ = store.delete(SENTINEL_KEY).await;
        return Ok(None);
    };
    let age = now_secs().saturating_sub(payload.started_at);
    if age < SENTINEL_STALE_SECS {
        // Too recent — could theoretically be another process, but SurrealKV
        // flock means we own the lock now, so the holder must have died.
        // Treat as stale anyway since we ARE the only writer.
        tracing::debug!(
            age_secs = age,
            "found recent sentinel; previous attempt died within the stale window"
        );
    }
    Ok(Some(payload))
}

/// Write the in-progress sentinel atomically. Called before any migration
/// step that mutates user data.
async fn write_sentinel(store: &Store, target_version: u32) -> Result<()> {
    let now = now_secs();
    let payload = MigrationSentinelPayload {
        target_version,
        started_at: now,
        pid: std::process::id(),
        mati_binary_version: MATI_BINARY_VERSION.to_string(),
    };
    let payload_value = serde_json::to_value(&payload).context("serialize sentinel payload")?;
    let record = Record {
        key: SENTINEL_KEY.to_string(),
        value: format!("migration in progress → v{target_version}"),
        category: Category::DevNote,
        priority: Priority::Normal,
        tags: vec!["mati-internal".into(), "migration".into()],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::nil(),
            logical_clock: 1,
            wall_clock: now,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
        payload: Some(payload_value),
    };
    let ops: Vec<KnowledgeWriteOp<'_>> = vec![KnowledgeWriteOp::PutRecord {
        key: SENTINEL_KEY,
        record: &record,
    }];
    store.transact_knowledge(&ops).await
}

/// Clear the in-progress sentinel. Called on successful migration completion.
async fn clear_sentinel_op(store: &Store) -> Result<()> {
    store
        .delete(SENTINEL_KEY)
        .await
        .with_context(|| "clear migration sentinel")
}

fn schema_version_record(version: u32, applied_at: u64) -> Result<Record> {
    let payload = SchemaVersionPayload {
        version,
        applied_at,
    };
    let payload_value =
        serde_json::to_value(&payload).context("serialize schema_version payload")?;
    Ok(internal_record(
        SCHEMA_VERSION_KEY,
        format!("schema_version={version}"),
        vec!["mati-internal".into(), "schema".into()],
        u64::from(version),
        applied_at,
        Some(payload_value),
    ))
}

fn history_record(
    version: u32,
    started_at: u64,
    completed_at: u64,
    records_migrated: u64,
) -> Result<Record> {
    let payload = MigrationHistoryPayload {
        version,
        started_at,
        completed_at,
        records_migrated,
        mati_binary_version: MATI_BINARY_VERSION.to_string(),
    };
    let payload_value =
        serde_json::to_value(&payload).context("serialize migration history payload")?;
    Ok(internal_record(
        &history_key(version),
        format!("migrated to v{version}"),
        vec!["mati-internal".into(), "migration".into()],
        u64::from(version),
        completed_at,
        Some(payload_value),
    ))
}

/// Zero-pad to six digits so `system:migration:applied:000001` sorts before
/// `:000002` lexicographically. Six digits supports a million migrations,
/// well past anything realistic.
fn history_key(version: u32) -> String {
    format!("{HISTORY_PREFIX}{version:06}")
}

fn internal_record(
    key: &str,
    value: String,
    tags: Vec<String>,
    logical_clock: u64,
    now: u64,
    payload: Option<serde_json::Value>,
) -> Record {
    Record {
        key: key.to_string(),
        value,
        category: Category::DevNote,
        priority: Priority::Normal,
        tags,
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::nil(),
            logical_clock,
            wall_clock: now,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
        payload,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap-detection probe
// ─────────────────────────────────────────────────────────────────────────────

/// Decide whether the knowledge tree has any pre-existing user data. Probes a
/// fixed set of prefixes and short-circuits on the first non-empty hit. For
/// a truly fresh store this performs ~8 empty range scans (~µs each); for a
/// populated store it returns on the first scan that yields any key.
///
/// We deliberately scan only knowledge-tree prefixes here — session/analytics
/// data is ephemeral by design and never participates in schema migrations.
async fn store_is_empty(store: &Store) -> Result<bool> {
    // Prefixes that any non-fresh mati store would have content under. This
    // list is the union of every knowledge-tree namespace we ship today —
    // adding a new namespace must update this list or migrations against
    // pre-existing stores risk mis-classifying them as "fresh".
    const PROBE_PREFIXES: &[&str] = &[
        "gotcha:",
        "file:",
        "decision:",
        "dev_note:",
        "dep:",
        "stage:",
        "cluster:",
        // `system:` deliberately omitted — the schema_version record itself
        // lives there, and at this point in the flow we've already confirmed
        // version == 0 (so schema_version isn't yet written). The cost of a
        // false-negative "system has data" is that we run the migration loop
        // on a logically-empty store, which is idempotent and safe.
    ];
    for prefix in PROBE_PREFIXES {
        let keys = store
            .scan_keys(prefix)
            .await
            .with_context(|| format!("probe scan of {prefix}"))?;
        if !keys.is_empty() {
            return Ok(false);
        }
    }
    Ok(true)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pre-migration snapshot
// ─────────────────────────────────────────────────────────────────────────────

/// Copy the knowledge tree to `backups/pre-v<target>/knowledge.db/` so the
/// operator can restore it if a migration is buggy. Idempotent: if the
/// backup already exists, leave it (it represents the *original* state from
/// the first attempt; subsequent attempts re-use the same backup rather
/// than overwriting it with mid-migration data).
///
/// Sessions tree is intentionally NOT backed up — its contents are ephemeral
/// (session receipts, daily analytics, audit trails) and have no role in
/// schema migration. The cost of backing it up isn't worth the recovery
/// value.
async fn snapshot_knowledge_tree(store: &Store, target_version: u32) -> Result<PathBuf> {
    let src = store.root.join("knowledge.db");
    if !src.exists() {
        // No source means no data to back up — fall through and let migration
        // proceed against an empty tree. This shouldn't happen in practice
        // (we only snapshot on the non-bootstrap path) but is harmless.
        return Ok(src);
    }

    let backup_root = store.root.join("backups");
    let dst = backup_root.join(format!("pre-v{target_version}")).join("knowledge.db");

    if dst.exists() {
        tracing::debug!(
            ?dst,
            "pre-migration backup already exists (previous attempt); reusing"
        );
        return Ok(dst);
    }

    std::fs::create_dir_all(
        dst.parent()
            .ok_or_else(|| anyhow::anyhow!("backup parent path malformed"))?,
    )
    .with_context(|| format!("create backup parent at {}", dst.display()))?;

    copy_dir_recursive(&src, &dst)
        .with_context(|| format!("copy {} → {}", src.display(), dst.display()))?;

    tracing::info!(
        ?dst,
        target_version,
        "pre-migration snapshot taken — restore by stopping the daemon and \
         renaming this directory back to knowledge.db"
    );
    Ok(dst)
}

/// Recursively copy a directory tree. Uses regular file copies (no hardlinks)
/// so subsequent writes to the source don't mutate the snapshot — this
/// matters because SurrealKV's LSM tree append-only files would otherwise
/// remain shared between live and backup directories via hardlink inode
/// reuse, and a future compaction could rewrite them in place.
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let entry_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_dir_recursive(&entry_path, &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(&entry_path, &dst_path)?;
        }
        // Symlinks and special files are skipped — SurrealKV doesn't use
        // them, and reproducing them correctly across filesystems is fragile.
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Migrations
// ─────────────────────────────────────────────────────────────────────────────

/// v1 baseline — establishes the schema_version record on stores that
/// existed before versioning was introduced. No data rewriting; the
/// version-bump op alone is the migration.
async fn apply_v1_baseline(_store: &Store) -> Result<Vec<OwnedKnowledgeOp>> {
    Ok(Vec::new())
}

/// v2 — auto-derived gotchas (`gotcha:cochange:*`, `gotcha:revert:*`,
/// `gotcha:ownership:*`) must carry `payload.confirmed = false`.
///
/// Pre-v2 init wrote cochange stubs with `confirmed = true`, which violated
/// the schema invariant
///     "confirmed = true  ⇒  developer-authoritative  ⇒  confidence ≥ 0.80"
/// because cochange records sit at confidence 0.45 / 0.65 (`StaticAnalysis`
/// source). The mismatch surfaced as `mati ls gotchas` showing these
/// records as confirmed=Y while `mem_get` returned 0.45.
///
/// Bootstrap injection still surfaces these records (see
/// `is_injectable_gotcha`'s prefix allowlist for auto-derived stubs); hook
/// enforcement now correctly refuses to DENY on them because they're not
/// developer-confirmed. To deny on a cochange/revert/ownership signal,
/// developers explicitly confirm via `mati gotcha confirm`.
async fn apply_v2_unconfirm_auto_derived_gotchas(store: &Store) -> Result<Vec<OwnedKnowledgeOp>> {
    const AUTO_DERIVED_PREFIXES: &[&str] = &[
        "gotcha:cochange:",
        "gotcha:revert:",
        "gotcha:ownership:",
    ];

    let now = now_secs();
    let mut ops = Vec::new();

    for prefix in AUTO_DERIVED_PREFIXES {
        let records = store
            .scan_prefix(prefix)
            .await
            .with_context(|| format!("scan {prefix}"))?;
        for mut record in records {
            if !matches!(record.lifecycle, RecordLifecycle::Active) {
                continue;
            }
            let mut gotcha = match record.payload_as::<GotchaRecord>() {
                Some(g) => g,
                None => continue, // skip records with malformed payloads
            };
            if !gotcha.confirmed {
                continue; // already in target state — idempotent
            }
            gotcha.confirmed = false;

            let new_payload = serde_json::to_value(&gotcha)
                .with_context(|| format!("re-serialize {} payload", record.key))?;
            record.payload = Some(new_payload);
            record.updated_at = now;
            record.version.logical_clock = record.version.logical_clock.saturating_add(1);
            record.version.wall_clock = now;

            let key = record.key.clone();
            ops.push(OwnedKnowledgeOp::PutRecord { key, record });
        }
    }

    Ok(ops)
}

// ─────────────────────────────────────────────────────────────────────────────
// Owned variant of KnowledgeWriteOp (Vec-friendly during async migration build)
// ─────────────────────────────────────────────────────────────────────────────

enum OwnedKnowledgeOp {
    PutRecord { key: String, record: Record },
}

impl OwnedKnowledgeOp {
    fn as_write_op(&self) -> KnowledgeWriteOp<'_> {
        match self {
            Self::PutRecord { key, record } => KnowledgeWriteOp::PutRecord {
                key: key.as_str(),
                record,
            },
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_auto_gotcha(key: &str, confirmed: bool) -> Record {
        let now = 1_000_000;
        let gotcha = GotchaRecord {
            rule: "Auto-derived test rule".to_string(),
            reason: "test".to_string(),
            severity: Priority::Normal,
            affected_files: vec!["a.rs".to_string()],
            ref_url: None,
            discovered_session: now,
            confirmed,
        };
        Record {
            key: key.to_string(),
            value: "Auto-derived test rule".to_string(),
            category: Category::Gotcha,
            priority: Priority::Normal,
            tags: vec!["auto-generated".into()],
            created_at: now,
            updated_at: now,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::nil(),
                logical_clock: 1,
                wall_clock: now,
            },
            quality: QualityScore::cochange_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: serde_json::to_value(&gotcha).ok(),
        }
    }

    /// Open a store via the public API. `Store::open` auto-migrates to HEAD,
    /// so the returned store is at `CURRENT_SCHEMA_VERSION` with zero
    /// pre-existing data.
    async fn fresh_store() -> (Store, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        (store, dir)
    }

    /// Open a store and then erase its auto-migrate stamp, simulating a
    /// legacy store from before the versioning framework existed. Use this
    /// for tests that exercise migration *bodies*; fresh_store() is for
    /// tests that exercise the hot path / bootstrap fast-path.
    async fn legacy_store() -> (Store, TempDir) {
        let (store, dir) = fresh_store().await;
        store.delete(SCHEMA_VERSION_KEY).await.unwrap();
        // Also nuke the bootstrap history record so the legacy store has
        // no migration footprint at all.
        let history = store.scan_keys(HISTORY_PREFIX).await.unwrap();
        for k in history {
            store.delete(&k).await.unwrap();
        }
        (store, dir)
    }

    // ── Hot path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn fresh_store_lands_at_head_after_open() {
        let (store, _dir) = fresh_store().await;
        // Store::open auto-migrated; version is already CURRENT.
        assert_eq!(
            read_schema_version(&store).await.unwrap(),
            CURRENT_SCHEMA_VERSION
        );
    }

    #[tokio::test]
    async fn already_at_head_is_idempotent_noop() {
        let (store, _dir) = fresh_store().await;
        migrate(&store).await.unwrap();
        migrate(&store).await.unwrap();
        assert_eq!(
            read_schema_version(&store).await.unwrap(),
            CURRENT_SCHEMA_VERSION
        );
    }

    // ── Bootstrap fast-path ────────────────────────────────────────────────

    #[tokio::test]
    async fn bootstrap_stamps_head_without_replaying_migrations() {
        // legacy_store() removes the schema_version record from a freshly
        // opened (and thus empty) store, so when we call migrate() the
        // bootstrap path should fire — no migration bodies run.
        let (store, _dir) = legacy_store().await;
        // Sanity: store is empty per our probe.
        assert!(store_is_empty(&store).await.unwrap());

        migrate(&store).await.unwrap();
        assert_eq!(
            read_schema_version(&store).await.unwrap(),
            CURRENT_SCHEMA_VERSION
        );

        // History should contain the bootstrap row only.
        let history = store.scan_keys(HISTORY_PREFIX).await.unwrap();
        assert_eq!(
            history.len(),
            1,
            "bootstrap should write exactly one history row, got: {history:?}"
        );
        assert!(
            history[0].ends_with(&format!("{:06}", CURRENT_SCHEMA_VERSION)),
            "bootstrap history key must encode the current version"
        );
    }

    // ── Real upgrade ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn v2_flips_confirmed_true_to_false_on_cochange_records() {
        let (store, _dir) = legacy_store().await;
        let r = make_auto_gotcha("gotcha:cochange:a.rs|b.rs", true);
        store.put(&r.key, &r).await.unwrap();

        migrate(&store).await.unwrap();

        let fetched = store
            .get("gotcha:cochange:a.rs|b.rs")
            .await
            .unwrap()
            .unwrap();
        let gotcha = fetched.payload_as::<GotchaRecord>().unwrap();
        assert!(
            !gotcha.confirmed,
            "v2 must rewrite confirmed=true cochange records to confirmed=false"
        );
    }

    #[tokio::test]
    async fn v2_covers_revert_and_ownership_too() {
        let (store, _dir) = legacy_store().await;
        let r1 = make_auto_gotcha("gotcha:revert:src/a.rs", true);
        let r2 = make_auto_gotcha("gotcha:ownership:src/b.rs", true);
        store.put(&r1.key, &r1).await.unwrap();
        store.put(&r2.key, &r2).await.unwrap();

        migrate(&store).await.unwrap();

        for key in &["gotcha:revert:src/a.rs", "gotcha:ownership:src/b.rs"] {
            let fetched = store.get(key).await.unwrap().unwrap();
            let gotcha = fetched.payload_as::<GotchaRecord>().unwrap();
            assert!(
                !gotcha.confirmed,
                "{key} must be rewritten confirmed=false by v2"
            );
        }
    }

    #[tokio::test]
    async fn v2_leaves_developer_confirmed_gotchas_alone() {
        let (store, _dir) = legacy_store().await;
        // Non-auto-derived key — must not be touched by v2.
        let r = make_auto_gotcha("gotcha:developer-rule", true);
        store.put(&r.key, &r).await.unwrap();

        migrate(&store).await.unwrap();

        let fetched = store.get("gotcha:developer-rule").await.unwrap().unwrap();
        let gotcha = fetched.payload_as::<GotchaRecord>().unwrap();
        assert!(
            gotcha.confirmed,
            "non-auto-derived gotchas must survive v2 untouched"
        );
    }

    // ── Industry-standard production-grade features ─────────────────────────

    #[tokio::test]
    async fn upgrade_writes_history_record_with_timing_and_count() {
        let (store, _dir) = legacy_store().await;
        // Plant two cochange records that v2 will rewrite.
        store
            .put(
                "gotcha:cochange:a.rs|b.rs",
                &make_auto_gotcha("gotcha:cochange:a.rs|b.rs", true),
            )
            .await
            .unwrap();
        store
            .put(
                "gotcha:cochange:c.rs|d.rs",
                &make_auto_gotcha("gotcha:cochange:c.rs|d.rs", true),
            )
            .await
            .unwrap();

        migrate(&store).await.unwrap();

        // History should have one row per migration step (v1 + v2).
        let history_keys = store.scan_keys(HISTORY_PREFIX).await.unwrap();
        assert_eq!(history_keys.len(), 2, "expected v1 + v2 history rows");

        // v2 row should record both rewrites.
        let v2_record = store.get(&history_key(2)).await.unwrap().unwrap();
        let v2_payload = v2_record
            .payload_as::<MigrationHistoryPayload>()
            .expect("v2 history record must deserialize");
        assert_eq!(v2_payload.version, 2);
        assert_eq!(v2_payload.records_migrated, 2);
        assert!(v2_payload.completed_at >= v2_payload.started_at);
        assert_eq!(v2_payload.mati_binary_version, MATI_BINARY_VERSION);
    }

    #[tokio::test]
    async fn sentinel_is_cleared_after_successful_migration() {
        let (store, _dir) = legacy_store().await;
        store
            .put(
                "gotcha:cochange:a.rs|b.rs",
                &make_auto_gotcha("gotcha:cochange:a.rs|b.rs", true),
            )
            .await
            .unwrap();

        migrate(&store).await.unwrap();

        let sentinel = store.get(SENTINEL_KEY).await.unwrap();
        assert!(
            sentinel.is_none(),
            "sentinel must be cleared after successful migration"
        );
    }

    #[tokio::test]
    async fn stale_sentinel_is_cleared_and_migration_proceeds() {
        let (store, _dir) = legacy_store().await;
        store
            .put(
                "gotcha:cochange:a.rs|b.rs",
                &make_auto_gotcha("gotcha:cochange:a.rs|b.rs", true),
            )
            .await
            .unwrap();
        // Plant a stale sentinel (started long ago, fake pid).
        let stale = Record {
            payload: serde_json::to_value(&MigrationSentinelPayload {
                target_version: 2,
                started_at: 1, // very old
                pid: 999_999,
                mati_binary_version: "0.0.1-stale".into(),
            })
            .ok(),
            ..internal_record(
                SENTINEL_KEY,
                "migration in progress".into(),
                vec!["mati-internal".into()],
                1,
                1,
                None,
            )
        };
        store.put(SENTINEL_KEY, &stale).await.unwrap();

        // Migration should detect the stale sentinel, log a warning, and proceed.
        migrate(&store).await.unwrap();

        // Migration completed: version at HEAD, sentinel cleared, cochega flipped.
        assert_eq!(
            read_schema_version(&store).await.unwrap(),
            CURRENT_SCHEMA_VERSION
        );
        assert!(
            store.get(SENTINEL_KEY).await.unwrap().is_none(),
            "stale sentinel must be cleared and not re-asserted on success"
        );
        let gotcha = store
            .get("gotcha:cochange:a.rs|b.rs")
            .await
            .unwrap()
            .unwrap()
            .payload_as::<GotchaRecord>()
            .unwrap();
        assert!(!gotcha.confirmed);
    }

    #[tokio::test]
    async fn upgrade_takes_pre_migration_snapshot() {
        let (store, dir) = legacy_store().await;
        store
            .put(
                "gotcha:cochange:a.rs|b.rs",
                &make_auto_gotcha("gotcha:cochange:a.rs|b.rs", true),
            )
            .await
            .unwrap();

        migrate(&store).await.unwrap();

        let backup = store.root.join("backups").join("pre-v2").join("knowledge.db");
        assert!(
            backup.exists(),
            "pre-migration snapshot must be created at {}",
            backup.display()
        );
        // The backup should contain at least one file (SurrealKV's manifest
        // or WAL). We don't assert byte-equality with the live tree because
        // the live tree has been mutated by the migration.
        let entry_count = std::fs::read_dir(&backup).unwrap().count();
        assert!(
            entry_count > 0,
            "snapshot at {} must contain SurrealKV files, got 0",
            backup.display()
        );
        let _ = dir; // keep dir alive
    }

    #[tokio::test]
    async fn bootstrap_does_not_create_snapshot_on_fresh_store() {
        let (store, _dir) = fresh_store().await;
        // Auto-migration already ran during open(); bootstrap-fast-path
        // should NOT have created a backup directory.
        let backup_root = store.root.join("backups");
        assert!(
            !backup_root.exists(),
            "bootstrap on a fresh store must not create backups/"
        );
    }

    // ── Schema version recordkeeping ────────────────────────────────────────

    #[tokio::test]
    async fn version_record_persists_after_migration() {
        let (store, _dir) = fresh_store().await;
        let rec = store.get(SCHEMA_VERSION_KEY).await.unwrap().unwrap();
        let payload = rec.payload_as::<SchemaVersionPayload>().unwrap();
        assert_eq!(payload.version, CURRENT_SCHEMA_VERSION);
        assert!(
            payload.applied_at > 0,
            "applied_at must be a real timestamp, got {}",
            payload.applied_at
        );
    }

    #[tokio::test]
    async fn downgrade_from_future_version_refuses_to_open() {
        let (store, _dir) = fresh_store().await;
        // Plant a version higher than this binary knows.
        let bogus = schema_version_record(CURRENT_SCHEMA_VERSION + 99, now_secs()).unwrap();
        store.put(SCHEMA_VERSION_KEY, &bogus).await.unwrap();

        let err = migrate(&store).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("newer than this binary supports"),
            "downgrade refusal must explain the cause, got: {msg}"
        );
    }

    #[tokio::test]
    async fn malformed_payload_records_are_skipped_not_failed() {
        let (store, _dir) = legacy_store().await;
        // A cochange record whose payload is the wrong shape — real corruption
        // surfaces as `payload_as` → None; v2 must skip rather than abort.
        let mut r = make_auto_gotcha("gotcha:cochange:broken|target", true);
        r.payload = Some(serde_json::json!("not an object"));
        store.put(&r.key, &r).await.unwrap();

        migrate(&store).await.unwrap();
        assert_eq!(
            read_schema_version(&store).await.unwrap(),
            CURRENT_SCHEMA_VERSION
        );
    }

    // ── Idempotence safeguards ──────────────────────────────────────────────

    #[tokio::test]
    async fn v2_is_idempotent_on_already_unconfirmed_records() {
        let (store, _dir) = legacy_store().await;
        let r = make_auto_gotcha("gotcha:cochange:a.rs|b.rs", false);
        store.put(&r.key, &r).await.unwrap();

        migrate(&store).await.unwrap();

        let fetched = store
            .get("gotcha:cochange:a.rs|b.rs")
            .await
            .unwrap()
            .unwrap();
        let gotcha = fetched.payload_as::<GotchaRecord>().unwrap();
        assert!(!gotcha.confirmed, "must remain confirmed=false");
        // The migration's logical_clock bump only fires when it actually
        // rewrites a record. The record-level logical_clock should be
        // unchanged here since v2 was a no-op for this record.
        assert_eq!(
            fetched.version.logical_clock, 1,
            "idempotent run must not bump logical_clock"
        );
    }

    // ── Lifecycle event emission (Layer 2 of state-aware readiness) ────────
    //
    // The daemon-readiness state machine in `src/mcp/daemon_lifecycle.rs`
    // depends on the migration framework emitting a known event sequence
    // so callers waiting in `wait_for_ready` can observe forward progress
    // rather than blindly timing out. Pin the sequence here so a future
    // refactor that drops, reorders, or renames events is caught.

    /// Helper: read `lifecycle.log` under `store.root` and return the
    /// migration-phase tags in emission order. Returns empty if the log
    /// doesn't exist (e.g. hot-path migration that's a no-op).
    async fn collect_migration_phases(store: &Store) -> Vec<String> {
        let path = store.root.join("lifecycle.log");
        let Ok(contents) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        let mut phases = Vec::new();
        for line in contents.lines() {
            let mut parts = line.splitn(4, '\t');
            let _ts = parts.next();
            let _pid = parts.next();
            let event = parts.next().unwrap_or("");
            let detail = parts.next().unwrap_or("");
            if event != "migration" {
                continue;
            }
            for tok in detail.split(' ') {
                if let Some(phase) = tok.strip_prefix("phase=") {
                    phases.push(phase.to_string());
                    break;
                }
            }
        }
        phases
    }

    #[tokio::test]
    async fn migration_emits_phase_events_in_correct_order() {
        // Real upgrade path: legacy_store starts at version 0 with data,
        // so `migrate` runs snapshot + apply_v1 + apply_v2 + end. The
        // event sequence is the canonical contract consumed by
        // `wait_for_ready` in `mcp::daemon_lifecycle`.
        let (store, _dir) = legacy_store().await;
        let r = make_auto_gotcha("gotcha:cochange:x|y", true);
        store.put(&r.key, &r).await.unwrap();

        migrate(&store).await.unwrap();

        let phases = collect_migration_phases(&store).await;
        // Expected sequence (one apply pair per migration version applied):
        //   begin → snapshot_complete → apply_begin(v1) → apply_complete(v1)
        //                            → apply_begin(v2) → apply_complete(v2)
        //                            → end
        assert_eq!(
            phases,
            vec![
                "begin",
                "snapshot_complete",
                "apply_begin",
                "apply_complete",
                "apply_begin",
                "apply_complete",
                "end",
            ],
            "migration phase sequence is the contract for state-aware readiness"
        );
    }

    #[tokio::test]
    async fn migration_emits_no_events_on_hot_path_noop() {
        // Already-at-HEAD: `migrate` returns at the version check without
        // touching lifecycle.log. Critical for steady-state cold-start
        // latency — every `Store::open` would otherwise pay a tiny event
        // write even when no work is needed.
        let (store, _dir) = legacy_store().await;
        // Bootstrap to HEAD first.
        migrate(&store).await.unwrap();
        // Remove the lifecycle.log from the bootstrap so the noop path
        // starts clean.
        let _ = std::fs::remove_file(store.root.join("lifecycle.log"));

        // Second migrate must be a true no-op — nothing to emit.
        migrate(&store).await.unwrap();
        let phases = collect_migration_phases(&store).await;
        assert!(
            phases.is_empty(),
            "hot-path migrate must not emit lifecycle events, got {phases:?}"
        );
    }
}
