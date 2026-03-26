//! Internal CLI commands invoked by hook scripts (M-09-G).
//!
//! All commands here are hidden from `--help` and called by bash hook scripts
//! in `.claude/hooks/`. They must be FAST (<50ms) — use `Store::open`, not
//! `open_and_rebuild`.
//!
//! Each `run_*` function is a thin CLI wrapper. When the MCP server (mati serve)
//! is running it holds the SurrealKV exclusive lock, so all store writes are
//! routed through the daemon Unix socket first. The `*_impl` functions in
//! `mati_core::store::session` are used for the direct-store fallback path.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use mati_core::store::{Category, GotchaRecord, Record, Store};
use mati_core::store::session as sess;
use crate::cli::daemon::{daemon_result, mati_root_for, try_auto_start, DaemonResult};

// ── M-09-prereq: mati get --json ────────────────────────────────────────────

/// Output struct for `mati get` — flattens the Record with a top-level `confirmed` field.
#[derive(Serialize, Deserialize)]
struct GetOutput {
    #[serde(flatten)]
    record: Record,
    confirmed: bool,
}

pub async fn run_get(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    match daemon_result(&root, "get", serde_json::json!({ "key": key })).await {
        DaemonResult::Ok(resp) => {
            let json = match resp.get("data") {
                Some(d) if d.is_null() => "null".to_string(),
                Some(d) => d.to_string(),
                None => "null".to_string(),
            };
            println!("{json}");
            return Ok(());
        }
        DaemonResult::NotRunning | DaemonResult::StaleSocket => {
            try_auto_start(&cwd);
        }
        DaemonResult::Unresponsive => {
            tracing::warn!("mati get: daemon unresponsive — degrading gracefully");
            println!("null");
            return Ok(());
        }
    }

    let store = Store::open(&cwd).await?;
    let output = get_json(&store, key).await?;
    println!("{output}");
    store.close().await?;
    Ok(())
}

/// Core logic: fetch a record and return JSON string (or `"null"`).
async fn get_json(store: &Store, key: &str) -> Result<String> {
    match store.get(key).await? {
        None => Ok("null".to_string()),
        Some(record) => {
            let confirmed = extract_confirmed(&record);
            let output = GetOutput { record, confirmed };
            Ok(serde_json::to_string(&output)?)
        }
    }
}

/// Extract `confirmed` from a gotcha record's value (JSON-encoded GotchaRecord).
/// Non-gotcha records always return `false`.
fn extract_confirmed(record: &Record) -> bool {
    if record.category != Category::Gotcha {
        return false;
    }
    record.payload_as::<GotchaRecord>()
        .map(|g| g.confirmed)
        .unwrap_or(false)
}

// ── M-09-G: Internal hook commands ──────────────────────────────────────────


// ── log-miss ─────────────────────────────────────────────────────────────────

pub async fn run_log_miss(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    match daemon_result(&root, "log_miss", serde_json::json!({ "key": key })).await {
        DaemonResult::Ok(_) => return Ok(()),
        DaemonResult::NotRunning | DaemonResult::StaleSocket => {
            try_auto_start(&cwd);
        }
        DaemonResult::Unresponsive => {
            // No fallback: an unresponsive daemon likely holds the SurrealKV lock,
            // so Store::open would block. P9: analytics loss is preferable to hanging.
            // Exception: if the daemon process has since died, the lock is free — fall through.
            let root = mati_root_for(&cwd)?;
            if !crate::cli::daemon::is_pid_dead(&root) {
                tracing::warn!(
                    "mati log-miss: daemon unresponsive (process alive, lock held) — dropping event"
                );
                return Ok(());
            }
            tracing::debug!("mati log-miss: daemon unresponsive + process dead — falling back to direct store");
            // fall through to Store::open below
        }
    }

    let store = Store::open(&cwd).await?;
    log_miss_impl(&store, key).await?;
    store.close().await?;
    Ok(())
}

async fn log_miss_impl(store: &Store, key: &str) -> Result<()> {
    sess::log_miss(store, key).await
}

// ── log-hit ──────────────────────────────────────────────────────────────────

pub async fn run_log_hit(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    match daemon_result(&root, "log_hit", serde_json::json!({ "key": key })).await {
        DaemonResult::Ok(_) => return Ok(()),
        DaemonResult::NotRunning | DaemonResult::StaleSocket => {
            try_auto_start(&cwd);
        }
        DaemonResult::Unresponsive => {
            // No fallback: an unresponsive daemon likely holds the SurrealKV lock,
            // so Store::open would block. P9: analytics loss is preferable to hanging.
            // Exception: if the daemon process has since died, the lock is free — fall through.
            let root = mati_root_for(&cwd)?;
            if !crate::cli::daemon::is_pid_dead(&root) {
                tracing::warn!(
                    "mati log-hit: daemon unresponsive (process alive, lock held) — dropping event"
                );
                return Ok(());
            }
            tracing::debug!("mati log-hit: daemon unresponsive + process dead — falling back to direct store");
            // fall through to Store::open below
        }
    }

    let store = Store::open(&cwd).await?;
    log_hit_impl(&store, key).await?;
    store.close().await?;
    Ok(())
}

async fn log_hit_impl(store: &Store, key: &str) -> Result<()> {
    sess::log_hit(store, key).await
}


// ── edit-hook (combined log-hit + reparse) ───────────────────────────────────

/// Combined log-hit + reparse in a single store open/close cycle.
/// Called by post-edit.sh hook to avoid two separate process spawns.
pub async fn run_edit_hook(path: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    // Normalize to repo-relative. post-edit.sh passes absolute paths;
    // store keys always use relative (e.g. "file:src/main.rs").
    let rel = std::path::Path::new(path)
        .strip_prefix(&cwd)
        .map(|r| r.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string());
    let path = rel.as_str();

    match daemon_result(&root, "edit_hook", serde_json::json!({ "path": path })).await {
        DaemonResult::Ok(_) => return Ok(()),
        DaemonResult::NotRunning | DaemonResult::StaleSocket => {
            try_auto_start(&cwd);
        }
        DaemonResult::Unresponsive => {
            // No fallback: an unresponsive daemon likely holds the SurrealKV lock,
            // so Store::open would block. P9: analytics loss is preferable to hanging.
            // Exception: if the daemon process has since died, the lock is free — fall through.
            let root = mati_root_for(&cwd)?;
            if !crate::cli::daemon::is_pid_dead(&root) {
                tracing::warn!(
                    "mati edit-hook: daemon unresponsive (process alive, lock held) — dropping event"
                );
                return Ok(());
            }
            tracing::debug!("mati edit-hook: daemon unresponsive + process dead — falling back to direct store");
            // fall through to Store::open below
        }
    }

    // Daemon not running — direct store path.
    let store = Store::open(&cwd).await?;
    let file_key = format!("file:{path}");
    if let Err(e) = log_hit_impl(&store, &file_key).await {
        tracing::warn!(path, "edit-hook log-hit failed: {e}");
    }
    if let Err(e) = crate::cli::reparse::reparse_impl(&store, &cwd, path).await {
        tracing::warn!(path, "edit-hook reparse failed: {e}");
    }
    store.close().await?;
    Ok(())
}

// ── doc-capture (2.3) ────────────────────────────────────────────────────────

/// Read first lines of new file content from stdin, detect a canonical doc
/// comment, and update the `file:*` record's purpose + confidence.
///
/// Tries the daemon socket first (content passed as JSON payload). Falls back
/// to direct store open when daemon is not running.
pub async fn run_doc_capture(path: &str) -> Result<()> {
    use std::io::Read as _;
    let mut content = String::new();
    std::io::stdin().read_to_string(&mut content)?;

    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    match daemon_result(
        &root,
        "doc_capture",
        serde_json::json!({ "path": path, "content": content }),
    )
    .await
    {
        DaemonResult::Ok(_) => return Ok(()),
        DaemonResult::NotRunning | DaemonResult::StaleSocket => {
            try_auto_start(&cwd);
        }
        DaemonResult::Unresponsive => {
            tracing::warn!("doc_capture: daemon unresponsive — dropping");
            return Ok(());
        }
    }

    let store = Store::open(&cwd).await?;
    sess::doc_capture(&store, path, &content).await?;
    store.close().await?;
    Ok(())
}

// ── log-compliance-miss ──────────────────────────────────────────────────────

pub async fn run_log_compliance_miss(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    match daemon_result(&root, "log_compliance_miss", serde_json::json!({ "key": key })).await {
        DaemonResult::Ok(_) => return Ok(()),
        DaemonResult::NotRunning | DaemonResult::StaleSocket => {
            try_auto_start(&cwd);
        }
        DaemonResult::Unresponsive => {
            // No fallback: an unresponsive daemon likely holds the SurrealKV lock,
            // so Store::open would block. P9: analytics loss is preferable to hanging.
            // Exception: if the daemon process has since died, the lock is free — fall through.
            let root = mati_root_for(&cwd)?;
            if !crate::cli::daemon::is_pid_dead(&root) {
                tracing::warn!(
                    "mati log-compliance-miss: daemon unresponsive (process alive, lock held) — dropping event"
                );
                return Ok(());
            }
            tracing::debug!("mati log-compliance-miss: daemon unresponsive + process dead — falling back to direct store");
            // fall through to Store::open below
        }
    }

    let store = Store::open(&cwd).await?;
    log_compliance_miss_impl(&store, key).await?;
    store.close().await?;
    Ok(())
}

async fn log_compliance_miss_impl(store: &Store, key: &str) -> Result<()> {
    sess::log_compliance_miss(store, key).await
}

// ── session-check-consulted ──────────────────────────────────────────────────

pub async fn run_session_check_consulted(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    match daemon_result(&root, "session_check_consulted", serde_json::json!({ "key": key })).await {
        DaemonResult::Ok(resp) => {
            let consulted = resp
                .get("data")
                .and_then(|d| d.as_bool())
                .unwrap_or(false);
            println!("{consulted}");
            return Ok(());
        }
        DaemonResult::NotRunning | DaemonResult::StaleSocket => {
            try_auto_start(&cwd);
        }
        DaemonResult::Unresponsive => {
            tracing::warn!("session_check_consulted: daemon unresponsive — returning false");
            println!("false");
            return Ok(());
        }
    }

    let store = Store::open(&cwd).await?;
    let result = check_consulted_impl(&store, key).await?;
    println!("{result}");
    store.close().await?;
    Ok(())
}

async fn check_consulted_impl(store: &Store, key: &str) -> Result<bool> {
    sess::check_consulted(store, key).await
}

// ── session-flush ────────────────────────────────────────────────────────────

pub async fn run_session_flush() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    match daemon_result(&root, "session_flush", serde_json::json!({})).await {
        DaemonResult::Ok(_) => return Ok(()),
        DaemonResult::NotRunning | DaemonResult::StaleSocket => {
            try_auto_start(&cwd);
        }
        DaemonResult::Unresponsive => {
            tracing::warn!("session_flush: daemon unresponsive — dropping");
            return Ok(());
        }
    }

    let store = Store::open(&cwd).await?;
    session_flush_impl(&store).await?;
    store.close().await?;
    Ok(())
}

async fn session_flush_impl(store: &Store) -> Result<()> {
    sess::session_flush(store).await
}

// ── session-harvest ──────────────────────────────────────────────────────────

pub async fn run_session_harvest() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    match daemon_result(&root, "session_harvest", serde_json::json!({})).await {
        DaemonResult::Ok(_) => return Ok(()),
        DaemonResult::NotRunning | DaemonResult::StaleSocket => {
            try_auto_start(&cwd);
        }
        DaemonResult::Unresponsive => {
            tracing::warn!("session_harvest: daemon unresponsive — dropping");
            return Ok(());
        }
    }

    let store = Store::open(&cwd).await?;
    session_harvest_impl(&store, &cwd).await?;
    store.close().await?;
    Ok(())
}

async fn session_harvest_impl(store: &Store, cwd: &std::path::Path) -> Result<()> {
    sess::session_harvest(store, cwd).await
}

// ── Test-only delegates ───────────────────────────────────────────────────────
// Expose mati_core::store::session functions under the names the test suite
// expects via `use super::*`.

#[cfg(test)]
async fn promote_gotcha_candidates(store: &Store) -> Result<u32> {
    sess::promote_gotcha_candidates(store).await
}

#[cfg(test)]
async fn collect_and_store_stale_reviews(
    store: &Store,
    session_value: &str,
    now: u64,
) -> Result<usize> {
    sess::collect_and_store_stale_reviews(store, session_value, now).await
}

#[cfg(test)]
async fn collect_stale_entries(
    store: &Store,
    consulted_keys: &[String],
) -> Result<Vec<mati_core::store::StaleReviewEntry>> {
    sess::collect_stale_entries(store, consulted_keys).await
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // Session helpers needed by tests — imported from mati_core::store::session.
    use mati_core::store::session::{
        analytics_record, format_review_date, session_record, today_key, now_secs,
        upsert_daily_agg, DailyAgg, GOTCHA_PROMOTION_ACCESS_THRESHOLD, MAX_AGG_KEYS,
        MAX_STALE_REVIEW_ENTRIES,
    };
    use mati_core::store::{
        ConfidenceScore, Priority, QualityScore, RecordLifecycle, RecordSource, RecordVersion,
        StaleReviewPayload, StalenessScore,
    };

    // ── Test helpers ─────────────────────────────────────────────────────────

    async fn open_test_store(dir: &TempDir) -> Store {
        Store::open(dir.path()).await.unwrap()
    }

    fn make_file_record(key: &str) -> Record {
        Record {
            key: key.to_string(),
            value: String::new(),
            category: Category::File,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 1_000_000,
            updated_at: 1_000_000,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 1_000_000,
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

    fn make_gotcha_record(key: &str, confirmed: bool) -> Record {
        let gotcha = GotchaRecord {
            rule: "Never do X".into(),
            reason: "because Y".into(),
            severity: Priority::Critical,
            affected_files: vec!["src/main.rs".into()],
            ref_url: None,
            discovered_session: 0,
            confirmed,
        };
        Record {
            key: key.to_string(),
            value: gotcha.rule.clone(),
            payload: serde_json::to_value(&gotcha).ok(),
            category: Category::Gotcha,
            priority: Priority::Critical,
            tags: vec![],
            created_at: 1_000_000,
            updated_at: 1_000_000,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 1_000_000,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
            gap_analysis_score: 0.0,
        }
    }

    fn make_stage_record(value: &str) -> Record {
        Record {
            key: "stage:current".to_string(),
            value: value.to_string(),
            category: Category::Stage,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 1_000_000,
            updated_at: 1_000_000,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 1_000_000,
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

    // ── Pure unit tests ──────────────────────────────────────────────────────

    #[test]
    fn extract_confirmed_true_from_confirmed_gotcha() {
        let record = make_gotcha_record("gotcha:test", true);
        assert!(extract_confirmed(&record));
    }

    #[test]
    fn extract_confirmed_false_from_unconfirmed_gotcha() {
        let record = make_gotcha_record("gotcha:test", false);
        assert!(!extract_confirmed(&record));
    }

    #[test]
    fn extract_confirmed_false_for_non_gotcha_category() {
        let record = make_file_record("file:src/main.rs");
        assert!(!extract_confirmed(&record));
    }

    #[test]
    fn extract_confirmed_false_for_corrupt_gotcha_value() {
        let mut record = make_gotcha_record("gotcha:test", true);
        record.payload = None; // corrupt the payload — extract_confirmed reads payload, not value
        assert!(!extract_confirmed(&record));
    }

    #[test]
    fn today_key_produces_valid_date_format() {
        let key = today_key("analytics:miss_");
        let date_part = key.strip_prefix("analytics:miss_").unwrap();
        assert_eq!(date_part.len(), 10);
        assert_eq!(&date_part[4..5], "-");
        assert_eq!(&date_part[7..8], "-");
    }

    #[test]
    fn daily_agg_serde_roundtrip() {
        let agg = DailyAgg {
            count: 42,
            keys: vec!["file:a.rs".into(), "file:b.rs".into()],
        };
        let json = serde_json::to_string(&agg).unwrap();
        let parsed: DailyAgg = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.count, 42);
        assert_eq!(parsed.keys, vec!["file:a.rs", "file:b.rs"]);
    }

    // ── get_json ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_json_returns_null_for_missing_key() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let result = get_json(&store, "file:nonexistent.rs").await.unwrap();
        assert_eq!(result, "null");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn get_json_returns_record_with_confirmed_true_for_confirmed_gotcha() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let record = make_gotcha_record("gotcha:test-rule", true);
        store.put("gotcha:test-rule", &record).await.unwrap();

        let json = get_json(&store, "gotcha:test-rule").await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["confirmed"], true);
        assert_eq!(parsed["key"], "gotcha:test-rule");
        // Verify flatten works — confidence should be at top level, not nested
        assert!(parsed["confidence"]["value"].is_number());

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn get_json_returns_confirmed_false_for_file_record() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let record = make_file_record("file:src/lib.rs");
        store.put("file:src/lib.rs", &record).await.unwrap();

        let json = get_json(&store, "file:src/lib.rs").await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["confirmed"], false);
        assert_eq!(parsed["category"], "file");

        store.close().await.unwrap();
    }

    // ── upsert_daily_agg ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn upsert_daily_agg_creates_new_record_on_first_call() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        upsert_daily_agg(&store, "analytics:miss_2026-03-18", "file:src/main.rs")
            .await
            .unwrap();

        let record = store.get("analytics:miss_2026-03-18").await.unwrap().unwrap();
        let agg: DailyAgg = record.payload_as::<DailyAgg>().unwrap();
        assert_eq!(agg.count, 1);
        assert_eq!(agg.keys, vec!["file:src/main.rs"]);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn upsert_daily_agg_increments_count_on_repeat() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let agg_key = "analytics:miss_2026-03-18";
        upsert_daily_agg(&store, agg_key, "file:a.rs").await.unwrap();
        upsert_daily_agg(&store, agg_key, "file:b.rs").await.unwrap();
        upsert_daily_agg(&store, agg_key, "file:c.rs").await.unwrap();

        let record = store.get(agg_key).await.unwrap().unwrap();
        let agg: DailyAgg = record.payload_as::<DailyAgg>().unwrap();
        assert_eq!(agg.count, 3);
        assert_eq!(agg.keys.len(), 3);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn upsert_daily_agg_deduplicates_same_key() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let agg_key = "analytics:miss_2026-03-18";
        upsert_daily_agg(&store, agg_key, "file:same.rs").await.unwrap();
        upsert_daily_agg(&store, agg_key, "file:same.rs").await.unwrap();
        upsert_daily_agg(&store, agg_key, "file:same.rs").await.unwrap();

        let record = store.get(agg_key).await.unwrap().unwrap();
        let agg: DailyAgg = record.payload_as::<DailyAgg>().unwrap();
        assert_eq!(agg.count, 3, "count should still increment");
        assert_eq!(agg.keys.len(), 1, "keys should deduplicate");
        assert_eq!(agg.keys[0], "file:same.rs");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn upsert_daily_agg_caps_keys_at_100() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let agg_key = "analytics:miss_2026-03-18";
        for i in 0..120 {
            upsert_daily_agg(&store, agg_key, &format!("file:f{i}.rs"))
                .await
                .unwrap();
        }

        let record = store.get(agg_key).await.unwrap().unwrap();
        let agg: DailyAgg = record.payload_as::<DailyAgg>().unwrap();
        assert_eq!(agg.count, 120, "count tracks every call");
        assert_eq!(agg.keys.len(), 100, "keys capped at MAX_AGG_KEYS");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn upsert_daily_agg_increments_logical_clock() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let agg_key = "analytics:miss_2026-03-18";
        upsert_daily_agg(&store, agg_key, "file:a.rs").await.unwrap();
        upsert_daily_agg(&store, agg_key, "file:b.rs").await.unwrap();

        let record = store.get(agg_key).await.unwrap().unwrap();
        assert_eq!(
            record.version.logical_clock, 2,
            "logical clock should increment on each upsert"
        );

        store.close().await.unwrap();
    }

    // ── log_hit_impl ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn log_hit_creates_consulted_marker() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        log_hit_impl(&store, "file:src/main.rs").await.unwrap();

        let marker = store.get("session:consulted:file:src/main.rs").await.unwrap();
        assert!(marker.is_some(), "consulted marker should exist after log-hit");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn log_hit_bumps_access_count_on_existing_record() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        // Seed a file record
        let record = make_file_record("file:src/db.rs");
        store.put("file:src/db.rs", &record).await.unwrap();
        assert_eq!(record.access_count, 0);

        // Hit it 3 times
        log_hit_impl(&store, "file:src/db.rs").await.unwrap();
        log_hit_impl(&store, "file:src/db.rs").await.unwrap();
        log_hit_impl(&store, "file:src/db.rs").await.unwrap();

        let updated = store.get("file:src/db.rs").await.unwrap().unwrap();
        assert_eq!(updated.access_count, 3);
        assert!(updated.last_accessed > 0, "last_accessed should be set");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn log_hit_does_not_crash_when_target_record_missing() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        // No file:ghost.rs in store — should not error
        log_hit_impl(&store, "file:ghost.rs").await.unwrap();

        // Consulted marker still created
        assert!(
            store
                .get("session:consulted:file:ghost.rs")
                .await
                .unwrap()
                .is_some()
        );

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn log_hit_creates_daily_aggregation() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        log_hit_impl(&store, "file:src/main.rs").await.unwrap();

        let agg_key = today_key("analytics:hit_");
        let record = store.get(&agg_key).await.unwrap().unwrap();
        let agg: DailyAgg = record.payload_as::<DailyAgg>().unwrap();
        assert_eq!(agg.count, 1);
        assert_eq!(agg.keys, vec!["file:src/main.rs"]);

        store.close().await.unwrap();
    }

    // ── check_consulted_impl ─────────────────────────────────────────────────

    #[tokio::test]
    async fn check_consulted_false_before_any_hit() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let result = check_consulted_impl(&store, "file:src/main.rs").await.unwrap();
        assert!(!result);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn check_consulted_true_after_log_hit() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        log_hit_impl(&store, "file:src/main.rs").await.unwrap();

        let result = check_consulted_impl(&store, "file:src/main.rs").await.unwrap();
        assert!(result);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn check_consulted_is_key_specific() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        log_hit_impl(&store, "file:src/a.rs").await.unwrap();

        assert!(check_consulted_impl(&store, "file:src/a.rs").await.unwrap());
        assert!(!check_consulted_impl(&store, "file:src/b.rs").await.unwrap());

        store.close().await.unwrap();
    }

    // ── session_flush_impl ───────────────────────────────────────────────────

    #[tokio::test]
    async fn session_flush_writes_session_current_with_consulted_keys() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        // Create some consulted markers
        log_hit_impl(&store, "file:src/main.rs").await.unwrap();
        log_hit_impl(&store, "file:src/lib.rs").await.unwrap();

        session_flush_impl(&store).await.unwrap();

        let current = store.get("session:current").await.unwrap().unwrap();
        let parsed = current.payload.as_ref().unwrap();

        let keys = parsed["consulted_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
        // Keys should have the session:consulted: prefix stripped
        let key_strs: Vec<&str> = keys.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(key_strs.contains(&"file:src/main.rs"));
        assert!(key_strs.contains(&"file:src/lib.rs"));
        assert!(parsed["flushed_at"].is_number());

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn session_flush_with_no_consulted_keys_writes_empty_list() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        session_flush_impl(&store).await.unwrap();

        let current = store.get("session:current").await.unwrap().unwrap();
        let parsed = current.payload.as_ref().unwrap();
        assert_eq!(parsed["consulted_keys"].as_array().unwrap().len(), 0);

        store.close().await.unwrap();
    }

    // ── session_harvest_impl ─────────────────────────────────────────────────

    #[tokio::test]
    async fn session_harvest_noop_when_no_session_current() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        // Should not error
        session_harvest_impl(&store, dir.path()).await.unwrap();

        // No session:* records created (except if there were consulted markers)
        let sessions = store.scan_prefix("session:").await.unwrap();
        assert!(sessions.is_empty());

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn session_harvest_creates_permanent_record_and_cleans_markers() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        // Simulate a session: hit some files, flush, then harvest
        log_hit_impl(&store, "file:src/a.rs").await.unwrap();
        log_hit_impl(&store, "file:src/b.rs").await.unwrap();
        session_flush_impl(&store).await.unwrap();

        // Verify markers exist before harvest
        let markers_before = store.scan_keys("session:consulted:").await.unwrap();
        assert_eq!(markers_before.len(), 2);

        session_harvest_impl(&store, dir.path()).await.unwrap();

        // Consulted markers should be cleaned up
        let markers_after = store.scan_keys("session:consulted:").await.unwrap();
        assert!(markers_after.is_empty(), "harvest should clean up consulted markers");

        // A permanent session:<timestamp> record should exist
        let all_sessions = store.scan_prefix("session:").await.unwrap();
        let permanent: Vec<_> = all_sessions
            .iter()
            .filter(|r| {
                r.key != "session:current"
                    && !r.key.starts_with("session:consulted:")
            })
            .collect();
        assert_eq!(permanent.len(), 1, "should have exactly one permanent session record");

        // Permanent record should contain the flushed data
        let parsed = permanent[0].payload.as_ref().unwrap();
        let keys = parsed["consulted_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn session_harvest_updates_stage_current() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        // Seed a stage:current record
        let stage = make_stage_record("v0.1 foundation");
        store.put("stage:current", &stage).await.unwrap();

        // Flush + harvest
        session_flush_impl(&store).await.unwrap();
        session_harvest_impl(&store, dir.path()).await.unwrap();

        let updated_stage = store.get("stage:current").await.unwrap().unwrap();
        assert!(
            updated_stage.value.contains("last_session: session:"),
            "stage should contain last_session reference"
        );
        assert!(
            updated_stage.value.contains("v0.1 foundation"),
            "original stage content should be preserved"
        );
        assert_eq!(
            updated_stage.version.logical_clock, 2,
            "logical clock should be incremented"
        );

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn session_harvest_overwrites_last_session_not_appends() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let stage = make_stage_record("v0.1 foundation");
        store.put("stage:current", &stage).await.unwrap();

        // First harvest
        session_flush_impl(&store).await.unwrap();
        session_harvest_impl(&store, dir.path()).await.unwrap();

        // Second harvest — need a new session:current for harvest to proceed
        session_flush_impl(&store).await.unwrap();
        session_harvest_impl(&store, dir.path()).await.unwrap();

        let final_stage = store.get("stage:current").await.unwrap().unwrap();
        let last_session_count = final_stage
            .value
            .lines()
            .filter(|l| l.starts_with("last_session:"))
            .count();
        assert_eq!(
            last_session_count, 1,
            "should have exactly one last_session line, not accumulated"
        );

        store.close().await.unwrap();
    }

    // ── log_miss / log_compliance_miss ────────────────────────────────────────

    #[tokio::test]
    async fn log_miss_creates_analytics_record() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        log_miss_impl(&store, "file:src/missing.rs").await.unwrap();

        let agg_key = today_key("analytics:miss_");
        let record = store.get(&agg_key).await.unwrap().unwrap();
        assert_eq!(record.category, Category::Analytics);
        let agg: DailyAgg = record.payload_as::<DailyAgg>().unwrap();
        assert_eq!(agg.count, 1);
        assert_eq!(agg.keys, vec!["file:src/missing.rs"]);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn log_compliance_miss_uses_compliance_prefix() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        log_compliance_miss_impl(&store, "file:src/unchecked.rs")
            .await
            .unwrap();

        let agg_key = today_key("compliance:miss_");
        let record = store.get(&agg_key).await.unwrap().unwrap();
        let agg: DailyAgg = record.payload_as::<DailyAgg>().unwrap();
        assert_eq!(agg.count, 1);
        assert_eq!(agg.keys, vec!["file:src/unchecked.rs"]);

        store.close().await.unwrap();
    }

    // ── Full lifecycle ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn full_session_lifecycle_hit_flush_harvest_cleanup() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        // Seed file records
        store
            .put("file:src/main.rs", &make_file_record("file:src/main.rs"))
            .await
            .unwrap();
        store
            .put("file:src/lib.rs", &make_file_record("file:src/lib.rs"))
            .await
            .unwrap();

        // Seed stage
        store
            .put("stage:current", &make_stage_record("building"))
            .await
            .unwrap();

        // 1. Simulate hook activity: hits, misses, compliance
        log_hit_impl(&store, "file:src/main.rs").await.unwrap();
        log_hit_impl(&store, "file:src/lib.rs").await.unwrap();
        log_miss_impl(&store, "file:src/unknown.rs").await.unwrap();
        log_compliance_miss_impl(&store, "file:src/sneaky.rs")
            .await
            .unwrap();

        // 2. Verify consulted state
        assert!(check_consulted_impl(&store, "file:src/main.rs").await.unwrap());
        assert!(check_consulted_impl(&store, "file:src/lib.rs").await.unwrap());
        assert!(!check_consulted_impl(&store, "file:src/unknown.rs").await.unwrap());

        // 3. Verify access counts bumped
        let main = store.get("file:src/main.rs").await.unwrap().unwrap();
        assert_eq!(main.access_count, 1);

        // 4. Flush
        session_flush_impl(&store).await.unwrap();
        let current = store.get("session:current").await.unwrap().unwrap();
        let flush_data = current.payload.as_ref().unwrap();
        assert_eq!(flush_data["consulted_keys"].as_array().unwrap().len(), 2);

        // 5. Harvest
        session_harvest_impl(&store, dir.path()).await.unwrap();

        // Consulted markers gone
        assert!(!check_consulted_impl(&store, "file:src/main.rs").await.unwrap());
        assert!(!check_consulted_impl(&store, "file:src/lib.rs").await.unwrap());

        // Stage updated
        let stage = store.get("stage:current").await.unwrap().unwrap();
        assert!(stage.value.contains("last_session:"));
        assert!(stage.value.contains("building"));

        // Analytics survived
        let miss_key = today_key("analytics:miss_");
        let miss = store.get(&miss_key).await.unwrap().unwrap();
        let miss_agg: DailyAgg = miss.payload_as::<DailyAgg>().unwrap();
        assert_eq!(miss_agg.count, 1);

        let compliance_key = today_key("compliance:miss_");
        let comp = store.get(&compliance_key).await.unwrap().unwrap();
        let comp_agg: DailyAgg = comp.payload_as::<DailyAgg>().unwrap();
        assert_eq!(comp_agg.count, 1);

        store.close().await.unwrap();
    }

    // ── promote_gotcha_candidates ────────────────────────────────────────────

    #[tokio::test]
    async fn promote_gotcha_candidates_promotes_when_access_count_sufficient() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        // Unconfirmed gotcha with access_count >= 3
        let mut record = make_gotcha_record("gotcha:candidate", false);
        record.access_count = 5;
        store.put("gotcha:candidate", &record).await.unwrap();

        let promoted = promote_gotcha_candidates(&store).await.unwrap();
        assert_eq!(promoted, 1);

        let updated = store.get("gotcha:candidate").await.unwrap().unwrap();
        let gotcha: GotchaRecord = updated.payload_as::<GotchaRecord>().unwrap();
        assert!(gotcha.confirmed);
        assert_eq!(updated.confidence.confirmation_count, 1);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn promote_gotcha_candidates_skips_already_confirmed() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let mut record = make_gotcha_record("gotcha:already-confirmed", true);
        record.access_count = 10;
        store.put("gotcha:already-confirmed", &record).await.unwrap();

        let promoted = promote_gotcha_candidates(&store).await.unwrap();
        assert_eq!(promoted, 0);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn promote_gotcha_candidates_skips_low_access_count() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let mut record = make_gotcha_record("gotcha:low-access", false);
        record.access_count = 2;
        store.put("gotcha:low-access", &record).await.unwrap();

        let promoted = promote_gotcha_candidates(&store).await.unwrap();
        assert_eq!(promoted, 0);

        // Should still be unconfirmed
        let unchanged = store.get("gotcha:low-access").await.unwrap().unwrap();
        let gotcha: GotchaRecord = unchanged.payload_as::<GotchaRecord>().unwrap();
        assert!(!gotcha.confirmed);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn promote_gotcha_candidates_handles_empty_store() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let promoted = promote_gotcha_candidates(&store).await.unwrap();
        assert_eq!(promoted, 0);

        store.close().await.unwrap();
    }

    // ── M-13-C: stale review collection ─────────────────────────────────────

    fn make_file_record_with_staleness(key: &str, staleness_value: f32) -> Record {
        let mut record = make_file_record(key);
        record.staleness.value = staleness_value;
        record.staleness.tier = StalenessScore::tier_from_value(staleness_value);
        record
    }

    #[tokio::test]
    async fn stale_review_collects_records_in_range() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        // Create records with different staleness values
        let stale_record = make_file_record_with_staleness("file:src/stale.rs", 0.5);
        store.put("file:src/stale.rs", &stale_record).await.unwrap();

        let fresh_record = make_file_record_with_staleness("file:src/fresh.rs", 0.1);
        store.put("file:src/fresh.rs", &fresh_record).await.unwrap();

        let entries = collect_stale_entries(
            &store,
            &["file:src/stale.rs".to_string(), "file:src/fresh.rs".to_string()],
        )
        .await
        .unwrap();

        assert_eq!(entries.len(), 1, "only record in [0.4, 0.7) range should be included");
        assert_eq!(entries[0].key, "file:src/stale.rs");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn stale_review_excludes_liability_and_tombstone() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        // Liability (0.7+)
        let liability = make_file_record_with_staleness("file:src/liability.rs", 0.75);
        store.put("file:src/liability.rs", &liability).await.unwrap();

        // Tombstone (0.9+)
        let tombstone = make_file_record_with_staleness("file:src/tombstone.rs", 0.95);
        store.put("file:src/tombstone.rs", &tombstone).await.unwrap();

        // In range
        let stale = make_file_record_with_staleness("file:src/stale.rs", 0.55);
        store.put("file:src/stale.rs", &stale).await.unwrap();

        let entries = collect_stale_entries(
            &store,
            &[
                "file:src/liability.rs".to_string(),
                "file:src/tombstone.rs".to_string(),
                "file:src/stale.rs".to_string(),
            ],
        )
        .await
        .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "file:src/stale.rs");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn stale_review_sorts_descending() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let low = make_file_record_with_staleness("file:src/low.rs", 0.42);
        store.put("file:src/low.rs", &low).await.unwrap();

        let high = make_file_record_with_staleness("file:src/high.rs", 0.65);
        store.put("file:src/high.rs", &high).await.unwrap();

        let entries = collect_stale_entries(
            &store,
            &["file:src/low.rs".to_string(), "file:src/high.rs".to_string()],
        )
        .await
        .unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "file:src/high.rs", "higher staleness first");
        assert_eq!(entries[1].key, "file:src/low.rs");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn stale_review_merges_same_day() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let now = now_secs();

        // First session: create a stale record and store a review
        let stale1 = make_file_record_with_staleness("file:src/a.rs", 0.5);
        store.put("file:src/a.rs", &stale1).await.unwrap();

        let session_value1 = serde_json::to_string(&serde_json::json!({
            "consulted_keys": ["file:src/a.rs"],
            "flushed_at": now,
        }))
        .unwrap();

        collect_and_store_stale_reviews(&store, &session_value1, now)
            .await
            .unwrap();

        // Second session: add another stale record
        let stale2 = make_file_record_with_staleness("file:src/b.rs", 0.55);
        store.put("file:src/b.rs", &stale2).await.unwrap();

        let session_value2 = serde_json::to_string(&serde_json::json!({
            "consulted_keys": ["file:src/b.rs"],
            "flushed_at": now + 100,
        }))
        .unwrap();

        collect_and_store_stale_reviews(&store, &session_value2, now + 100)
            .await
            .unwrap();

        // Verify merged result
        let date = format_review_date(now);
        let review_key = format!("analytics:stale_review_{date}");
        let record = store.get(&review_key).await.unwrap().unwrap();
        let payload: StaleReviewPayload = record.payload_as::<StaleReviewPayload>().unwrap();

        assert_eq!(payload.entries.len(), 2, "should merge entries from both sessions");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn stale_review_deduplicates_by_key() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let now = now_secs();

        let stale = make_file_record_with_staleness("file:src/dup.rs", 0.5);
        store.put("file:src/dup.rs", &stale).await.unwrap();

        let session_value = serde_json::to_string(&serde_json::json!({
            "consulted_keys": ["file:src/dup.rs"],
            "flushed_at": now,
        }))
        .unwrap();

        // Store twice for same day
        collect_and_store_stale_reviews(&store, &session_value, now)
            .await
            .unwrap();
        collect_and_store_stale_reviews(&store, &session_value, now + 100)
            .await
            .unwrap();

        let date = format_review_date(now);
        let review_key = format!("analytics:stale_review_{date}");
        let record = store.get(&review_key).await.unwrap().unwrap();
        let payload: StaleReviewPayload = record.payload_as::<StaleReviewPayload>().unwrap();

        assert_eq!(payload.entries.len(), 1, "duplicate keys should be deduped");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn stale_review_truncates_to_max() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let now = now_secs();

        // Create more stale records than MAX_STALE_REVIEW_ENTRIES
        let mut keys = Vec::new();
        for i in 0..30 {
            let key = format!("file:src/file{i}.rs");
            let staleness = 0.4 + (i as f32 * 0.005); // all in [0.4, 0.7)
            let record = make_file_record_with_staleness(&key, staleness);
            store.put(&key, &record).await.unwrap();
            keys.push(key);
        }

        let session_value = serde_json::to_string(&serde_json::json!({
            "consulted_keys": keys,
            "flushed_at": now,
        }))
        .unwrap();

        collect_and_store_stale_reviews(&store, &session_value, now)
            .await
            .unwrap();

        let date = format_review_date(now);
        let review_key = format!("analytics:stale_review_{date}");
        let record = store.get(&review_key).await.unwrap().unwrap();
        let payload: StaleReviewPayload = record.payload_as::<StaleReviewPayload>().unwrap();

        assert!(
            payload.entries.len() <= MAX_STALE_REVIEW_ENTRIES,
            "entries should be truncated to MAX_STALE_REVIEW_ENTRIES"
        );

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn session_lifecycle_includes_stale_review() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        // Seed a stale file record. StalenessAnalyzer runs first in harvest
        // and recomputes staleness from scratch. In test env (no git, recent
        // access), recomputed staleness drops to ~0. To test the stale review
        // pipeline, call collect_and_store_stale_reviews directly, bypassing
        // the analyzer — this isolates the collection logic.
        let stale = make_file_record_with_staleness("file:src/stale.rs", 0.55);
        store.put("file:src/stale.rs", &stale).await.unwrap();

        // Build session JSON referencing the stale record as consulted
        let now = now_secs();
        let session_value = serde_json::to_string(&serde_json::json!({
            "consulted_keys": ["file:src/stale.rs"],
            "flushed_at": now,
        }))
        .unwrap();

        let count = collect_and_store_stale_reviews(&store, &session_value, now)
            .await
            .unwrap();
        assert_eq!(count, 1, "one stale record should be flagged");

        // Verify stale review was written
        let review_key = today_key("analytics:stale_review_");
        let review = store.get(&review_key).await.unwrap();

        assert!(review.is_some(), "stale review should be created");
        if let Some(record) = review {
            let payload: StaleReviewPayload = record.payload_as::<StaleReviewPayload>().unwrap();
            assert!(
                payload.entries.iter().any(|e| e.key == "file:src/stale.rs"),
                "stale file should appear in review"
            );
        }

        store.close().await.unwrap();
    }

    #[test]
    fn format_review_date_produces_valid_format() {
        let date = format_review_date(1_700_000_000);
        assert_eq!(date.len(), 10);
        assert_eq!(&date[4..5], "-");
        assert_eq!(&date[7..8], "-");
    }

    #[tokio::test]
    async fn gotcha_promotion_uses_threshold_constant() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        // Test exactly at threshold (GOTCHA_PROMOTION_ACCESS_THRESHOLD = 3)
        let mut record = make_gotcha_record("gotcha:at-threshold", false);
        record.access_count = GOTCHA_PROMOTION_ACCESS_THRESHOLD;
        store.put("gotcha:at-threshold", &record).await.unwrap();

        let promoted = promote_gotcha_candidates(&store).await.unwrap();
        assert_eq!(promoted, 1, "record at threshold should be promoted");

        // Test one below threshold
        let mut below = make_gotcha_record("gotcha:below-threshold", false);
        below.access_count = GOTCHA_PROMOTION_ACCESS_THRESHOLD - 1;
        store.put("gotcha:below-threshold", &below).await.unwrap();

        let promoted = promote_gotcha_candidates(&store).await.unwrap();
        assert_eq!(promoted, 0, "record below threshold should not be promoted");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn stale_review_empty_session_value() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let session_value = serde_json::to_string(&serde_json::json!({
            "consulted_keys": [],
            "flushed_at": 12345,
        }))
        .unwrap();

        let count = collect_and_store_stale_reviews(&store, &session_value, 12345)
            .await
            .unwrap();
        assert_eq!(count, 0, "empty consulted keys should produce no entries");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn stale_review_scopes_to_consulted_keys_only() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        let now = now_secs();

        // Create two stale records but only consult one
        let stale1 = make_file_record_with_staleness("file:src/consulted.rs", 0.5);
        store.put("file:src/consulted.rs", &stale1).await.unwrap();

        let stale2 = make_file_record_with_staleness("file:src/not-consulted.rs", 0.6);
        store.put("file:src/not-consulted.rs", &stale2).await.unwrap();

        let session_value = serde_json::to_string(&serde_json::json!({
            "consulted_keys": ["file:src/consulted.rs"],
            "flushed_at": now,
        }))
        .unwrap();

        collect_and_store_stale_reviews(&store, &session_value, now)
            .await
            .unwrap();

        let date = format_review_date(now);
        let review_key = format!("analytics:stale_review_{date}");
        let record = store.get(&review_key).await.unwrap().unwrap();
        let payload: StaleReviewPayload = record.payload_as::<StaleReviewPayload>().unwrap();

        assert_eq!(payload.entries.len(), 1);
        assert_eq!(payload.entries[0].key, "file:src/consulted.rs");

        store.close().await.unwrap();
    }
}

