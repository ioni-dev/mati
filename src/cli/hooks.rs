//! Internal CLI commands invoked by hook scripts (M-09-G).
//!
//! All commands here are hidden from `--help` and called by bash hook scripts
//! in `.claude/hooks/`. They must be FAST (<50ms) — use `Store::open`, not
//! `open_and_rebuild`.
//!
//! Each `run_*` function is a thin CLI wrapper around an internal `*_impl`
//! that accepts `&Store` for testability.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use mati_core::store::{
    Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore, Store,
};

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
    serde_json::from_str::<GotchaRecord>(&record.value)
        .map(|g| g.confirmed)
        .unwrap_or(false)
}

// ── M-09-G: Internal hook commands ──────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn today_key(prefix: &str) -> String {
    let now = chrono::Utc::now().format("%Y-%m-%d");
    format!("{prefix}{now}")
}

fn new_device_id() -> uuid::Uuid {
    uuid::Uuid::new_v4()
}

fn session_record(key: &str, value: String) -> Record {
    let now = now_secs();
    Record {
        key: key.to_string(),
        value,
        category: Category::Session,
        priority: Priority::Normal,
        tags: vec![],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: new_device_id(),
            logical_clock: 1,
            wall_clock: now,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::SessionHook,
        confidence: ConfidenceScore::for_new_record(&RecordSource::SessionHook),
        gap_analysis_score: 0.0,
    }
}

fn analytics_record(key: &str, value: String) -> Record {
    let mut r = session_record(key, value);
    r.category = Category::Analytics;
    r
}

/// Daily aggregation record value.
#[derive(Serialize, Deserialize, Debug)]
struct DailyAgg {
    count: u64,
    keys: Vec<String>,
}

const MAX_AGG_KEYS: usize = 100;

// ── log-miss ─────────────────────────────────────────────────────────────────

pub async fn run_log_miss(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    log_miss_impl(&store, key).await?;
    store.close().await?;
    Ok(())
}

async fn log_miss_impl(store: &Store, key: &str) -> Result<()> {
    let agg_key = today_key("analytics:miss_");
    upsert_daily_agg(store, &agg_key, key).await
}

// ── log-hit ──────────────────────────────────────────────────────────────────

pub async fn run_log_hit(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    log_hit_impl(&store, key).await?;
    store.close().await?;
    Ok(())
}

async fn log_hit_impl(store: &Store, key: &str) -> Result<()> {
    let now = now_secs();

    // 1. Daily hit aggregation
    let agg_key = today_key("analytics:hit_");
    upsert_daily_agg(store, &agg_key, key).await?;

    // 2. Mark as consulted for session tracking
    let consulted_key = format!("session:consulted:{key}");
    store
        .put(&consulted_key, &session_record(&consulted_key, String::new()))
        .await?;

    // 3. Bump access_count and last_accessed on the target record
    if let Some(mut record) = store.get(key).await? {
        record.access_count += 1;
        record.last_accessed = now;
        store.put(key, &record).await?;
    }

    Ok(())
}

// ── log-compliance-miss ──────────────────────────────────────────────────────

pub async fn run_log_compliance_miss(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    log_compliance_miss_impl(&store, key).await?;
    store.close().await?;
    Ok(())
}

async fn log_compliance_miss_impl(store: &Store, key: &str) -> Result<()> {
    let agg_key = today_key("compliance:miss_");
    upsert_daily_agg(store, &agg_key, key).await
}

// ── session-check-consulted ──────────────────────────────────────────────────

pub async fn run_session_check_consulted(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    let result = check_consulted_impl(&store, key).await?;
    println!("{result}");
    store.close().await?;
    Ok(())
}

async fn check_consulted_impl(store: &Store, key: &str) -> Result<bool> {
    let consulted_key = format!("session:consulted:{key}");
    Ok(store.get(&consulted_key).await?.is_some())
}

// ── session-flush ────────────────────────────────────────────────────────────

pub async fn run_session_flush() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    session_flush_impl(&store).await?;
    store.close().await?;
    Ok(())
}

async fn session_flush_impl(store: &Store) -> Result<()> {
    let now = now_secs();

    // Scan all consulted markers
    let consulted_keys = store.scan_keys("session:consulted:").await?;
    let stripped: Vec<String> = consulted_keys
        .iter()
        .map(|k| k.strip_prefix("session:consulted:").unwrap_or(k).to_string())
        .collect();

    // Write session:current
    let value = serde_json::to_string(&serde_json::json!({
        "consulted_keys": stripped,
        "flushed_at": now,
    }))?;

    store
        .put("session:current", &session_record("session:current", value))
        .await?;
    Ok(())
}

// ── session-harvest ──────────────────────────────────────────────────────────

pub async fn run_session_harvest() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    session_harvest_impl(&store).await?;
    store.close().await?;
    Ok(())
}

async fn session_harvest_impl(store: &Store) -> Result<()> {
    let now = now_secs();

    // Read session:current (written by session-flush)
    let session_value = match store.get("session:current").await? {
        Some(r) => r.value,
        None => return Ok(()),
    };

    // Write permanent session record
    let session_key = format!("session:{now}");
    store
        .put(&session_key, &session_record(&session_key, session_value))
        .await?;

    // Clean up session:consulted:* markers
    let consulted_keys = store.scan_keys("session:consulted:").await?;
    for k in &consulted_keys {
        store.delete(k).await?;
    }

    // Update stage:current with last session timestamp (overwrite, not append)
    if let Some(mut stage) = store.get("stage:current").await? {
        stage.updated_at = now;
        stage.version.logical_clock += 1;
        stage.version.wall_clock = now;
        let base = stage
            .value
            .lines()
            .filter(|l| !l.starts_with("last_session:"))
            .collect::<Vec<_>>()
            .join("\n");
        stage.value = if base.is_empty() {
            format!("last_session: {session_key}")
        } else {
            format!("{base}\nlast_session: {session_key}")
        };
        store.put("stage:current", &stage).await?;
    }

    Ok(())
}

// ── Shared helpers ───────────────────────────────────────────────────────────

/// Upsert a daily aggregation record (miss or hit counter).
async fn upsert_daily_agg(store: &Store, agg_key: &str, target_key: &str) -> Result<()> {
    let now = now_secs();

    match store.get(agg_key).await? {
        Some(mut record) => {
            let mut agg: DailyAgg = serde_json::from_str(&record.value).unwrap_or(DailyAgg {
                count: 0,
                keys: vec![],
            });
            agg.count += 1;
            if agg.keys.len() < MAX_AGG_KEYS && !agg.keys.iter().any(|k| k == target_key) {
                agg.keys.push(target_key.to_string());
            }
            record.value = serde_json::to_string(&agg)?;
            record.updated_at = now;
            record.version.logical_clock += 1;
            record.version.wall_clock = now;
            store.put(agg_key, &record).await?;
        }
        None => {
            let agg = DailyAgg {
                count: 1,
                keys: vec![target_key.to_string()],
            };
            let record = analytics_record(agg_key, serde_json::to_string(&agg)?);
            store.put(agg_key, &record).await?;
        }
    }

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
            value: serde_json::to_string(&gotcha).unwrap(),
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
        record.value = "not valid json at all".into();
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
        let agg: DailyAgg = serde_json::from_str(&record.value).unwrap();
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
        let agg: DailyAgg = serde_json::from_str(&record.value).unwrap();
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
        let agg: DailyAgg = serde_json::from_str(&record.value).unwrap();
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
        let agg: DailyAgg = serde_json::from_str(&record.value).unwrap();
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
        let agg: DailyAgg = serde_json::from_str(&record.value).unwrap();
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
        let parsed: serde_json::Value = serde_json::from_str(&current.value).unwrap();

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
        let parsed: serde_json::Value = serde_json::from_str(&current.value).unwrap();
        assert_eq!(parsed["consulted_keys"].as_array().unwrap().len(), 0);

        store.close().await.unwrap();
    }

    // ── session_harvest_impl ─────────────────────────────────────────────────

    #[tokio::test]
    async fn session_harvest_noop_when_no_session_current() {
        let dir = TempDir::new().unwrap();
        let store = open_test_store(&dir).await;

        // Should not error
        session_harvest_impl(&store).await.unwrap();

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

        session_harvest_impl(&store).await.unwrap();

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
        let parsed: serde_json::Value =
            serde_json::from_str(&permanent[0].value).unwrap();
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
        session_harvest_impl(&store).await.unwrap();

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
        session_harvest_impl(&store).await.unwrap();

        // Second harvest — need a new session:current for harvest to proceed
        session_flush_impl(&store).await.unwrap();
        session_harvest_impl(&store).await.unwrap();

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
        let agg: DailyAgg = serde_json::from_str(&record.value).unwrap();
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
        let agg: DailyAgg = serde_json::from_str(&record.value).unwrap();
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
        let flush_data: serde_json::Value = serde_json::from_str(&current.value).unwrap();
        assert_eq!(flush_data["consulted_keys"].as_array().unwrap().len(), 2);

        // 5. Harvest
        session_harvest_impl(&store).await.unwrap();

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
        let miss_agg: DailyAgg = serde_json::from_str(&miss.value).unwrap();
        assert_eq!(miss_agg.count, 1);

        let compliance_key = today_key("compliance:miss_");
        let comp = store.get(&compliance_key).await.unwrap().unwrap();
        let comp_agg: DailyAgg = serde_json::from_str(&comp.value).unwrap();
        assert_eq!(comp_agg.count, 1);

        store.close().await.unwrap();
    }
}
