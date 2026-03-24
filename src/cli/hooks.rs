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

use mati_core::health::staleness::StalenessAnalyzer;
use mati_core::store::{
    Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, Record, RecordLifecycle,
    RecordSource, RecordVersion, StaleReviewEntry, StaleReviewPayload, StalenessScore, Store,
};
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
        payload: None,
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

/// Minimum staleness value for a record to be included in the daily stale review.
const STALE_REVIEW_MIN: f32 = 0.4;

/// Maximum staleness value for stale review inclusion (Liability and above are excluded).
const STALE_REVIEW_MAX: f32 = 0.7;

/// Maximum number of entries in a single daily stale review record.
const MAX_STALE_REVIEW_ENTRIES: usize = 20;

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
    let agg_key = today_key("analytics:miss_");
    upsert_daily_agg(store, &agg_key, key).await
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

// ── edit-hook (combined log-hit + reparse) ───────────────────────────────────

/// Combined log-hit + reparse in a single store open/close cycle.
/// Called by post-edit.sh hook to avoid two separate process spawns.
pub async fn run_edit_hook(path: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

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
/// Called by `post_edit.sh` in the background — must be fast and non-blocking.
/// Gracefully no-ops when no record exists yet or content has no doc comment.
pub async fn run_doc_capture(path: &str) -> Result<()> {
    use std::io::Read as _;
    let mut content = String::new();
    std::io::stdin().read_to_string(&mut content)?;

    let purpose = extract_doc_comment(path, &content);
    if purpose.is_empty() {
        return Ok(());
    }

    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    let file_key = format!("file:{path}");

    let mut record = match store.get(&file_key).await? {
        Some(r) => r,
        None => {
            store.close().await?;
            return Ok(());
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Only update purpose when the record's current source is static analysis
    // (Layer 0 stub) — don't overwrite developer-manual or higher-quality records.
    if record.source != RecordSource::StaticAnalysis {
        store.close().await?;
        return Ok(());
    }

    if let Some(mut fr) = record.payload_as::<mati_core::store::FileRecord>() {
        fr.purpose = purpose.clone();
        record.payload = serde_json::to_value(&fr).ok();
    } else {
        store.close().await?;
        return Ok(());
    }

    record.value = purpose;
    record.source = RecordSource::SessionHook;
    record.confidence.value = 0.65;
    record.quality = QualityScore::doc_comment_default();
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;

    if let Err(e) = store.put(&file_key, &record).await {
        tracing::warn!(path, "doc-capture put failed: {e}");
    }
    store.close().await?;
    Ok(())
}

/// Detect a canonical module-level doc comment from the first few lines of content.
/// Returns the cleaned comment text, or an empty string if none found.
fn extract_doc_comment(path: &str, content: &str) -> String {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    match ext {
        "rs" => extract_rust_module_doc(content),
        "py" => extract_python_docstring(content),
        "go" => extract_go_package_doc_comment(content),
        "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" => extract_jsdoc(content),
        _ => String::new(),
    }
}

/// Collect consecutive `//!` lines at the top of a Rust file.
fn extract_rust_module_doc(content: &str) -> String {
    let lines: Vec<&str> = content
        .lines()
        .take_while(|l| l.trim_start().starts_with("//!"))
        .map(|l| l.trim_start().trim_start_matches("//!").trim())
        .collect();
    lines.join(" ").trim().to_string()
}

/// Extract the first line of a Python module docstring (`"""` or `'''`).
fn extract_python_docstring(content: &str) -> String {
    let trimmed = content.trim_start();
    for delim in &[r#"""""#, "'''"] {
        if trimmed.starts_with(delim) {
            let rest = &trimmed[delim.len()..];
            if let Some(end) = rest.find(delim) {
                return rest[..end]
                    .trim()
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
            }
        }
    }
    String::new()
}

/// Collect the `//` comment block that appears immediately before `package X`.
fn extract_go_package_doc_comment(content: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with("//") {
            lines.push(t.trim_start_matches("//").trim().to_string());
        } else if t.starts_with("package ") {
            break;
        } else if !t.is_empty() {
            lines.clear(); // non-comment, non-empty line resets the block
        }
    }
    lines.join(" ").trim().to_string()
}

/// Extract a JSDoc `/** ... */` block at the top of a JS/TS file.
fn extract_jsdoc(content: &str) -> String {
    let trimmed = content.trim_start();
    if trimmed.starts_with("/**") {
        let rest = &trimmed[3..];
        if let Some(end) = rest.find("*/") {
            let text: Vec<&str> = rest[..end]
                .lines()
                .map(|l| l.trim().trim_start_matches('*').trim())
                .filter(|l| !l.is_empty())
                .collect();
            return text.join(" ").trim().to_string();
        }
    }
    String::new()
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
    let agg_key = today_key("compliance:miss_");
    upsert_daily_agg(store, &agg_key, key).await
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
    let session_data = serde_json::json!({
        "consulted_keys": stripped,
        "flushed_at": now,
    });
    let mut rec = session_record("session:current", String::new());
    rec.payload = Some(session_data);

    store.put("session:current", &rec).await?;
    Ok(())
}

// ── session-harvest ──────────────────────────────────────────────────────────

pub async fn run_session_harvest() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    session_harvest_impl(&store, &cwd).await?;
    store.close().await?;
    Ok(())
}

async fn session_harvest_impl(store: &Store, cwd: &std::path::Path) -> Result<()> {
    let now = now_secs();

    // M-12-D: promote gotcha candidates before archiving
    match promote_gotcha_candidates(store).await {
        Ok(n) if n > 0 => tracing::info!(promoted = n, "gotcha candidates auto-promoted"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "gotcha promotion failed"),
    }

    // M-13-A: run full staleness analysis
    match StalenessAnalyzer::new(cwd).analyze_all(store).await {
        Ok(report) if report.updated > 0 => {
            tracing::info!(
                scanned = report.scanned,
                updated = report.updated,
                tombstoned = report.tombstoned,
                liability = report.liability,
                "staleness analysis complete"
            );
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "staleness analysis failed"),
    }

    // Read session:current (written by session-flush)
    let session_rec = match store.get("session:current").await? {
        Some(r) => r,
        None => return Ok(()),
    };

    // Reconstruct the session value string for callers that still use &str
    let session_value = match session_rec.payload.as_ref() {
        Some(p) => serde_json::to_string(p).unwrap_or_default(),
        None => session_rec.value.clone(),
    };

    // M-13-C: collect and store stale reviews for consulted keys
    match collect_and_store_stale_reviews(store, &session_value, now).await {
        Ok(n) if n > 0 => tracing::info!(entries = n, "stale review entries collected"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "stale review collection failed"),
    }

    // Write permanent session record — propagate payload so consumers can read structured data
    let session_key = format!("session:{now}");
    let mut perm = session_record(&session_key, session_value);
    perm.payload = session_rec.payload;
    store.put(&session_key, &perm).await?;

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

// ── M-12-D: Gotcha auto-promotion ───────────────────────────────────────

/// Minimum access count before an unconfirmed gotcha is auto-promoted.
const GOTCHA_PROMOTION_ACCESS_THRESHOLD: u32 = 3;

/// Promote gotcha candidates with sufficient access to confirmed status.
///
/// Scans `gotcha:*` records. For each with `confirmed == false` AND
/// `access_count >= 3`: sets `confirmed = true`, bumps `confirmation_count`.
/// Returns the number of promoted records.
async fn promote_gotcha_candidates(store: &Store) -> Result<u32> {
    let gotchas = store.scan_prefix("gotcha:").await?;
    let now = now_secs();
    let mut promoted = 0u32;

    for mut record in gotchas {
        if record.access_count < GOTCHA_PROMOTION_ACCESS_THRESHOLD {
            continue;
        }

        let mut gotcha: GotchaRecord = match record.payload_as::<GotchaRecord>() {
            Some(g) => g,
            None => continue,
        };

        if gotcha.confirmed {
            continue;
        }

        gotcha.confirmed = true;
        record.payload = serde_json::to_value(&gotcha).ok();
        // NOTE: confirmation_count includes auto-promotions. Downstream consumers
        // should not assume this counter reflects only human confirmations.
        record.confidence.confirmation_count += 1;
        record.updated_at = now;
        record.version.logical_clock += 1;
        record.version.wall_clock = now;

        store.put(&record.key, &record).await?;
        promoted += 1;
    }

    Ok(promoted)
}

// ── M-13-C: Stale review collection ─────────────────────────────────────

/// Format a date key for stale review analytics records.
fn format_review_date(now_secs: u64) -> String {
    let dt = chrono::DateTime::from_timestamp(now_secs as i64, 0)
        .unwrap_or_else(|| chrono::Utc::now());
    dt.format("%Y-%m-%d").to_string()
}

/// Collect stale entries from consulted keys and store/merge into a daily review record.
///
/// Merges with any existing daily review (not overwrites). Deduplicates by key,
/// sorts descending by staleness, and truncates to MAX_STALE_REVIEW_ENTRIES.
/// Returns the number of new entries added.
async fn collect_and_store_stale_reviews(
    store: &Store,
    session_value: &str,
    now: u64,
) -> Result<usize> {
    // Parse consulted keys from session value
    let session: serde_json::Value = serde_json::from_str(session_value)?;
    let consulted_keys = match session["consulted_keys"].as_array() {
        Some(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>(),
        None => return Ok(0),
    };

    if consulted_keys.is_empty() {
        return Ok(0);
    }

    // Collect entries from consulted keys that are in the stale range
    let new_entries = collect_stale_entries(store, &consulted_keys).await?;
    if new_entries.is_empty() {
        return Ok(0);
    }

    let date = format_review_date(now);
    let review_key = format!("analytics:stale_review_{date}");
    let new_count = new_entries.len();

    // Merge with existing daily review if present
    let mut payload = match store.get(&review_key).await? {
        Some(existing) => {
            existing.payload_as::<StaleReviewPayload>()
                .unwrap_or(StaleReviewPayload {
                    session_timestamp: now,
                    entries: vec![],
                })
        }
        None => StaleReviewPayload {
            session_timestamp: now,
            entries: vec![],
        },
    };

    // Merge: add new entries, dedup by key (newest wins)
    let mut seen_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut merged = Vec::new();

    // Add new entries first (they take priority)
    for entry in new_entries {
        if seen_keys.insert(entry.key.clone()) {
            merged.push(entry);
        }
    }

    // Then existing entries (skip duplicates)
    for entry in payload.entries {
        if seen_keys.insert(entry.key.clone()) {
            merged.push(entry);
        }
    }

    // Sort descending by staleness
    merged.sort_by(|a, b| {
        b.staleness_value
            .partial_cmp(&a.staleness_value)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Truncate
    merged.truncate(MAX_STALE_REVIEW_ENTRIES);

    payload.session_timestamp = now;
    payload.entries = merged;

    let mut record = analytics_record(&review_key, String::new());
    record.payload = serde_json::to_value(&payload).ok();
    store.put(&review_key, &record).await?;

    Ok(new_count)
}

/// Scan consulted keys, filter those in [STALE_REVIEW_MIN, STALE_REVIEW_MAX),
/// excluding Liability/Tombstone tiers. Sort descending, truncate.
async fn collect_stale_entries(
    store: &Store,
    consulted_keys: &[String],
) -> Result<Vec<StaleReviewEntry>> {
    let mut entries = Vec::new();

    for key in consulted_keys {
        let record = match store.get(key).await? {
            Some(r) => r,
            None => continue,
        };

        // Exclude non-Active lifecycle
        if !matches!(record.lifecycle, RecordLifecycle::Active) {
            continue;
        }

        // Exclude Liability and Tombstone tiers
        if matches!(
            record.staleness.tier,
            mati_core::store::StalenessTier::Liability | mati_core::store::StalenessTier::Tombstone
        ) {
            continue;
        }

        // Filter to [STALE_REVIEW_MIN, STALE_REVIEW_MAX) range
        if record.staleness.value < STALE_REVIEW_MIN || record.staleness.value >= STALE_REVIEW_MAX {
            continue;
        }

        let top_signals: Vec<String> = record
            .staleness
            .signals
            .iter()
            .take(3)
            .map(|s| s.to_string())
            .collect();

        entries.push(StaleReviewEntry {
            key: key.clone(),
            staleness_value: record.staleness.value,
            tier: record.staleness.tier.clone(),
            last_updated: record.updated_at,
            signals: top_signals,
        });
    }

    // Sort descending by staleness
    entries.sort_by(|a, b| {
        b.staleness_value
            .partial_cmp(&a.staleness_value)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    entries.truncate(MAX_STALE_REVIEW_ENTRIES);

    Ok(entries)
}

// ── Shared helpers ───────────────────────────────────────────────────────────

/// Upsert a daily aggregation record (miss or hit counter).
async fn upsert_daily_agg(store: &Store, agg_key: &str, target_key: &str) -> Result<()> {
    let now = now_secs();

    match store.get(agg_key).await? {
        Some(mut record) => {
            let mut agg: DailyAgg = record.payload_as::<DailyAgg>().unwrap_or(DailyAgg {
                count: 0,
                keys: vec![],
            });
            agg.count += 1;
            if agg.keys.len() < MAX_AGG_KEYS && !agg.keys.iter().any(|k| k == target_key) {
                agg.keys.push(target_key.to_string());
            }
            record.payload = serde_json::to_value(&agg).ok();
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
            let mut record = analytics_record(agg_key, String::new());
            record.payload = serde_json::to_value(&agg).ok();
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

