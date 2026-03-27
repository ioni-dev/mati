//! Analytics and session lifecycle functions for the hook pipeline.
//!
//! These functions are called from two paths:
//! - `cli/hooks.rs` fallback (when daemon is not running, direct store open)
//! - `mcp/server.rs` daemon socket (when MCP server holds the exclusive lock)
//!
//! Having them here avoids code duplication and ensures both paths are
//! behaviourally identical.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::health::staleness::StalenessAnalyzer;
use super::{
    Category, ConfidenceScore, FileRecord, GotchaRecord, Priority, QualityScore, Record,
    RecordLifecycle, RecordSource, RecordVersion, StaleReviewEntry, StaleReviewPayload,
    StalenessScore, StalenessTier, Store,
};

// ── Internal helpers ──────────────────────────────────────────────────────────

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn today_key(prefix: &str) -> String {
    let now = chrono::Utc::now().format("%Y-%m-%d");
    format!("{prefix}{now}")
}

pub fn session_record(key: &str, value: String) -> Record {
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
            device_id: uuid::Uuid::new_v4(),
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

pub fn analytics_record(key: &str, value: String) -> Record {
    let mut r = session_record(key, value);
    r.category = Category::Analytics;
    r
}

/// Daily aggregation record value.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct DailyAgg {
    pub count: u64,
    pub keys: Vec<String>,
}

pub const MAX_AGG_KEYS: usize = 100;

/// Minimum staleness value for stale review inclusion.
const STALE_REVIEW_MIN: f32 = 0.4;
/// Maximum staleness value for stale review inclusion (Liability and above excluded).
const STALE_REVIEW_MAX: f32 = 0.7;
/// Maximum entries in a single daily stale review record.
pub const MAX_STALE_REVIEW_ENTRIES: usize = 20;
/// Minimum access count before an unconfirmed gotcha is auto-promoted.
pub const GOTCHA_PROMOTION_ACCESS_THRESHOLD: u32 = 3;

pub async fn upsert_daily_agg(store: &Store, agg_key: &str, target_key: &str) -> Result<()> {
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
            let agg = DailyAgg { count: 1, keys: vec![target_key.to_string()] };
            let mut record = analytics_record(agg_key, String::new());
            record.payload = serde_json::to_value(&agg).ok();
            store.put(agg_key, &record).await?;
        }
    }

    Ok(())
}

// ── log_hit ───────────────────────────────────────────────────────────────────

/// Record a cache hit: write consulted marker, bump access_count, update daily agg.
pub async fn log_hit(store: &Store, key: &str) -> Result<()> {
    let now = now_secs();

    // 1. Daily hit aggregation
    let agg_key = today_key("analytics:hit_");
    upsert_daily_agg(store, &agg_key, key).await?;

    // 2. Mark as consulted for session tracking
    let consulted_key = format!("session:consulted:{key}");
    store.put(&consulted_key, &session_record(&consulted_key, String::new())).await?;

    // 3. Bump access_count and last_accessed on the target record
    if let Some(mut record) = store.get(key).await? {
        record.access_count += 1;
        record.last_accessed = now;
        store.put(key, &record).await?;
    }

    Ok(())
}

// ── log_miss ──────────────────────────────────────────────────────────────────

/// Record a cache miss: update daily miss aggregation.
pub async fn log_miss(store: &Store, key: &str) -> Result<()> {
    let agg_key = today_key("analytics:miss_");
    upsert_daily_agg(store, &agg_key, key).await
}

// ── log_compliance_miss ───────────────────────────────────────────────────────

/// Record a compliance miss: file read without prior mati consultation.
pub async fn log_compliance_miss(store: &Store, key: &str) -> Result<()> {
    let agg_key = today_key("compliance:miss_");
    upsert_daily_agg(store, &agg_key, key).await
}

// ── check_consulted ───────────────────────────────────────────────────────────

/// Return true if `session:consulted:{key}` exists (set by `log_hit`).
pub async fn check_consulted(store: &Store, key: &str) -> Result<bool> {
    let consulted_key = format!("session:consulted:{key}");
    Ok(store.get(&consulted_key).await?.is_some())
}

// ── session_flush ─────────────────────────────────────────────────────────────

/// Collect all consulted markers into `session:current` for harvest.
pub async fn session_flush(store: &Store) -> Result<()> {
    let now = now_secs();

    let consulted_keys = store.scan_keys("session:consulted:").await?;
    let stripped: Vec<String> = consulted_keys
        .iter()
        .map(|k| k.strip_prefix("session:consulted:").unwrap_or(k).to_string())
        .collect();

    let session_data = serde_json::json!({
        "consulted_keys": stripped,
        "flushed_at": now,
    });
    let mut rec = session_record("session:current", String::new());
    rec.payload = Some(session_data);
    store.put("session:current", &rec).await?;
    Ok(())
}

// ── session_harvest ───────────────────────────────────────────────────────────

/// Archive session, run staleness analysis, auto-promote gotchas.
///
/// Full version: includes git-based staleness analysis. Used from CLI path.
/// For the daemon socket path (tokio::spawn, !Send constraint), use
/// `session_harvest_no_staleness` instead.
pub async fn session_harvest(store: &Store, cwd: &Path) -> Result<()> {
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

    // Write permanent session record
    let session_key = format!("session:{now}");
    let mut perm = session_record(&session_key, session_value);
    perm.payload = session_rec.payload;
    store.put(&session_key, &perm).await?;

    // Clean up session:consulted:* markers
    let consulted_keys = store.scan_keys("session:consulted:").await?;
    for k in &consulted_keys {
        store.delete(k).await?;
    }

    // Update stage:current with last session timestamp
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

/// Session harvest without git-based staleness analysis.
///
/// Used from the daemon socket (tokio::spawn requires Send, but StalenessAnalyzer
/// contains git2::Repository which is !Send). Staleness analysis is deferred to
/// the next CLI-path harvest (when the MCP server is not holding the lock).
pub async fn session_harvest_no_staleness(store: &Store) -> Result<()> {
    let now = now_secs();

    // M-12-D: promote gotcha candidates
    match promote_gotcha_candidates(store).await {
        Ok(n) if n > 0 => tracing::info!(promoted = n, "gotcha candidates auto-promoted"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "gotcha promotion failed"),
    }

    // Read session:current (written by session-flush)
    let session_rec = match store.get("session:current").await? {
        Some(r) => r,
        None => return Ok(()),
    };

    let session_value = match session_rec.payload.as_ref() {
        Some(p) => serde_json::to_string(p).unwrap_or_default(),
        None => session_rec.value.clone(),
    };

    // M-13-C: collect stale reviews (no git analysis — uses existing staleness values)
    match collect_and_store_stale_reviews(store, &session_value, now).await {
        Ok(n) if n > 0 => tracing::info!(entries = n, "stale review entries collected"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "stale review collection failed"),
    }

    // Write permanent session record
    let session_key = format!("session:{now}");
    let mut perm = session_record(&session_key, session_value);
    perm.payload = session_rec.payload;
    store.put(&session_key, &perm).await?;

    // Clean up consulted markers
    let consulted_keys = store.scan_keys("session:consulted:").await?;
    for k in &consulted_keys {
        store.delete(k).await?;
    }

    // Update stage:current
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

// ── doc_capture ───────────────────────────────────────────────────────────────

/// Extract a canonical doc comment from `content` and update `file:{path}` record.
///
/// No-ops when: no record exists, record source is not StaticAnalysis, or no
/// doc comment found in content.
pub async fn doc_capture(store: &Store, path: &str, content: &str) -> Result<()> {
    let purpose = extract_doc_comment(path, content);
    if purpose.is_empty() {
        return Ok(());
    }

    let file_key = format!("file:{path}");
    let mut record = match store.get(&file_key).await? {
        Some(r) => r,
        None => return Ok(()),
    };

    // Only update when the record's current source is static analysis
    // (Layer 0 stub) — don't overwrite developer-manual or higher-quality records.
    if record.source != RecordSource::StaticAnalysis {
        return Ok(());
    }

    if let Some(mut fr) = record.payload_as::<FileRecord>() {
        fr.purpose = purpose.clone();
        record.payload = serde_json::to_value(&fr).ok();
    } else {
        return Ok(());
    }

    let now = now_secs();
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
    Ok(())
}

// ── Doc comment extraction ────────────────────────────────────────────────────

pub fn extract_doc_comment(path: &str, content: &str) -> String {
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

fn extract_rust_module_doc(content: &str) -> String {
    let lines: Vec<&str> = content
        .lines()
        .take_while(|l| l.trim_start().starts_with("//!"))
        .map(|l| l.trim_start().trim_start_matches("//!").trim())
        .collect();
    lines.join(" ").trim().to_string()
}

fn extract_python_docstring(content: &str) -> String {
    let trimmed = content.trim_start();
    for delim in &[r#"""""#, "'''"] {
        if let Some(rest) = trimmed.strip_prefix(delim) {
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

fn extract_go_package_doc_comment(content: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with("//") {
            lines.push(t.trim_start_matches("//").trim().to_string());
        } else if t.starts_with("package ") {
            break;
        } else if !t.is_empty() {
            lines.clear();
        }
    }
    lines.join(" ").trim().to_string()
}

fn extract_jsdoc(content: &str) -> String {
    let trimmed = content.trim_start();
    if let Some(rest) = trimmed.strip_prefix("/**") {
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

// ── M-12-D: Gotcha auto-promotion ────────────────────────────────────────────

pub async fn promote_gotcha_candidates(store: &Store) -> Result<u32> {
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

// ── M-13-C: Stale review collection ──────────────────────────────────────────

pub fn format_review_date(now_secs: u64) -> String {
    let dt = chrono::DateTime::from_timestamp(now_secs as i64, 0)
        .unwrap_or_else(chrono::Utc::now);
    dt.format("%Y-%m-%d").to_string()
}

pub async fn collect_and_store_stale_reviews(
    store: &Store,
    session_value: &str,
    now: u64,
) -> Result<usize> {
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

    let new_entries = collect_stale_entries(store, &consulted_keys).await?;
    if new_entries.is_empty() {
        return Ok(0);
    }

    let date = format_review_date(now);
    let review_key = format!("analytics:stale_review_{date}");
    let new_count = new_entries.len();

    let mut payload = match store.get(&review_key).await? {
        Some(existing) => existing
            .payload_as::<StaleReviewPayload>()
            .unwrap_or(StaleReviewPayload { session_timestamp: now, entries: vec![] }),
        None => StaleReviewPayload { session_timestamp: now, entries: vec![] },
    };

    // Merge: new entries take priority, dedup by key
    let mut seen_keys = std::collections::HashSet::new();
    let mut merged = Vec::new();
    for entry in new_entries {
        if seen_keys.insert(entry.key.clone()) {
            merged.push(entry);
        }
    }
    for entry in payload.entries {
        if seen_keys.insert(entry.key.clone()) {
            merged.push(entry);
        }
    }

    // Sort descending by staleness, truncate
    merged.sort_by(|a, b| {
        b.staleness_value
            .partial_cmp(&a.staleness_value)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    merged.truncate(MAX_STALE_REVIEW_ENTRIES);

    payload.session_timestamp = now;
    payload.entries = merged;

    let mut record = analytics_record(&review_key, String::new());
    record.payload = serde_json::to_value(&payload).ok();
    store.put(&review_key, &record).await?;

    Ok(new_count)
}

pub async fn collect_stale_entries(
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
            StalenessTier::Liability | StalenessTier::Tombstone
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

    entries.sort_by(|a, b| {
        b.staleness_value
            .partial_cmp(&a.staleness_value)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    entries.truncate(MAX_STALE_REVIEW_ENTRIES);

    Ok(entries)
}
