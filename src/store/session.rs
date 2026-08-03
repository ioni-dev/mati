//! Analytics and session lifecycle functions for the hook pipeline.
//!
//! These functions are called from two paths:
//! - `cli/hooks.rs` fallback (when daemon is not running, direct store open)
//! - `mcp/server.rs` daemon socket (when MCP server holds the exclusive lock)
//!
//! Having them here avoids code duplication and ensures both paths are
//! behaviourally identical.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use super::{
    Category, ConfidenceScore, FileRecord, GotchaRecord, Priority, QualityScore, Record,
    RecordLifecycle, RecordSource, RecordVersion, StaleReviewEntry, StaleReviewPayload,
    StalenessScore, StalenessTier, Store,
};
use crate::health::staleness::StalenessAnalyzer;

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
            device_id: crate::store::stable_device_id(),
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
    /// Per-target counts for surfaces that need activity by policy, while
    /// preserving the original aggregate count and bounded key set.
    #[serde(default)]
    pub key_counts: BTreeMap<String, u64>,
}

pub const MAX_AGG_KEYS: usize = 100;
pub const MAX_SHADOW_OBSERVATIONS: usize = 100;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ShadowObservation {
    pub policy_key: String,
    pub action: crate::hooks::decide::Action,
    pub timestamp: u64,
    pub would: crate::hooks::decide::ShadowOutcome,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
pub struct ShadowObservationAgg {
    pub policies: BTreeMap<String, PolicyShadowAgg>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
pub struct PolicyShadowAgg {
    pub count: u64,
    pub observations: Vec<ShadowObservation>,
}

pub fn shadow_observation_key() -> String {
    today_key("analytics:policy_shadow_")
}

/// Record a bounded daily aggregate for a shadow policy that would have blocked.
/// This deliberately stays in the eventual session/analytics tree: it is a
/// review signal, not an enforcement fact and not part of the hash chain.
pub async fn record_shadow_observation(
    store: &Store,
    policy_key: &str,
    action: &crate::hooks::decide::Action,
    would: crate::hooks::decide::ShadowOutcome,
) -> Result<()> {
    let key = shadow_observation_key();
    let now = now_secs();
    let mut record = store
        .get(&key)
        .await?
        .unwrap_or_else(|| analytics_record(&key, String::new()));
    let mut agg: ShadowObservationAgg = record.payload_as().unwrap_or_default();
    let policy = agg.policies.entry(policy_key.to_string()).or_default();
    policy.count += 1;
    policy.observations.push(ShadowObservation {
        policy_key: policy_key.to_string(),
        action: action.clone(),
        timestamp: now,
        would,
    });
    if policy.observations.len() > MAX_SHADOW_OBSERVATIONS {
        policy.observations.remove(0);
    }
    record.payload = Some(serde_json::to_value(&agg)?);
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;
    store.put(&key, &record).await
}

/// Minimum staleness value for stale review inclusion.
const STALE_REVIEW_MIN: f32 = 0.4;
/// Maximum staleness value for stale review inclusion (Liability and above excluded).
const STALE_REVIEW_MAX: f32 = 0.7;
/// Default TTL for recent consultation receipts (15 minutes).
pub const CONSULTED_RECENT_TTL_SECS: u64 = 900;
/// Maximum entries in a single daily stale review record.
pub const MAX_STALE_REVIEW_ENTRIES: usize = 20;
/// Minimum access count before an unconfirmed gotcha is auto-promoted.
pub const GOTCHA_PROMOTION_ACCESS_THRESHOLD: u32 = 3;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
pub struct ConsultationReceipt {
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Identifies this mint in the enforcement chain: the `ReceiptMinted` event
    /// carries it, and so does the `AllowAfterReceipt` this receipt later
    /// authorizes. `None` on receipts written before the field existed.
    #[serde(default)]
    pub id: Option<String>,
}

/// A consultation receipt staged for write, carrying the id that links it to
/// the enforcement events it authorizes.
pub struct StagedReceipt {
    pub key: String,
    pub bytes: Vec<u8>,
    pub id: String,
}

/// Hash the stable, knowledge-bearing content of a record. Mutable access and
/// timestamp metadata are excluded so minting a receipt does not invalidate
/// itself when `log_hit` updates access tracking.
pub fn record_content_fingerprint(record: &Record) -> Option<String> {
    let content = (
        &record.key,
        &record.value,
        &record.category,
        &record.priority,
        &record.tags,
        &record.ref_url,
        &record.staleness,
        &record.lifecycle,
        &record.quality,
        &record.source,
        &record.confidence,
        &record.gap_analysis_score,
        &record.payload,
    );
    let bytes = rmp_serde::to_vec_named(&content).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Some(format!("{:x}", hasher.finalize()))
}

pub async fn upsert_daily_agg(store: &Store, agg_key: &str, target_key: &str) -> Result<()> {
    let now = now_secs();

    match store.get(agg_key).await? {
        Some(mut record) => {
            let mut agg: DailyAgg = record.payload_as::<DailyAgg>().unwrap_or(DailyAgg {
                count: 0,
                keys: vec![],
                key_counts: BTreeMap::new(),
            });
            agg.count += 1;
            *agg.key_counts.entry(target_key.to_string()).or_default() += 1;
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
                key_counts: BTreeMap::from([(target_key.to_string(), 1)]),
            };
            let mut record = analytics_record(agg_key, String::new());
            record.payload = serde_json::to_value(&agg).ok();
            store.put(agg_key, &record).await?;
        }
    }

    Ok(())
}

/// Compute the daily aggregation upsert WITHOUT persisting.
///
/// Returns `(key, serialized_record_bytes)` for staging into a
/// `transact_sessions_raw` call. The caller commits this alongside
/// other writes (e.g., audit) in one atomic transaction.
pub async fn upsert_daily_agg_staged(
    store: &Store,
    agg_key: &str,
    target_key: &str,
) -> Result<(String, Vec<u8>)> {
    let now = now_secs();

    let record = match store.get(agg_key).await? {
        Some(mut record) => {
            let mut agg: DailyAgg = record.payload_as::<DailyAgg>().unwrap_or(DailyAgg {
                count: 0,
                keys: vec![],
                key_counts: BTreeMap::new(),
            });
            agg.count += 1;
            *agg.key_counts.entry(target_key.to_string()).or_default() += 1;
            if agg.keys.len() < MAX_AGG_KEYS && !agg.keys.iter().any(|k| k == target_key) {
                agg.keys.push(target_key.to_string());
            }
            record.payload = serde_json::to_value(&agg).ok();
            record.updated_at = now;
            record.version.logical_clock += 1;
            record.version.wall_clock = now;
            record
        }
        None => {
            let agg = DailyAgg {
                count: 1,
                keys: vec![target_key.to_string()],
                key_counts: BTreeMap::from([(target_key.to_string(), 1)]),
            };
            let mut record = analytics_record(agg_key, String::new());
            record.payload = serde_json::to_value(&agg).ok();
            record
        }
    };

    let bytes = rmp_serde::to_vec_named(&record)
        .with_context(|| format!("failed to serialize agg record for {agg_key}"))?;
    Ok((agg_key.to_string(), bytes))
}

fn receipt_key(key: &str, actor: Option<&str>) -> String {
    match actor {
        Some(a) => format!("session:consulted:{a}:{key}"),
        None => format!("session:consulted:{key}"),
    }
}

/// Compute the consultation receipt record WITHOUT persisting.
///
/// When `actor` is `Some`, writes an actor-scoped key `session:consulted:<actor>:<key>`
/// alongside the global key path. Pass `None` for all existing callers (global).
pub fn consultation_receipt_staged(key: &str, actor: Option<&str>) -> Result<StagedReceipt> {
    consultation_receipt_staged_with_fingerprint(key, actor, None)
}

pub fn consultation_receipt_staged_with_fingerprint(
    key: &str,
    actor: Option<&str>,
    fingerprint: Option<String>,
) -> Result<StagedReceipt> {
    let consulted_key = receipt_key(key, actor);
    let id = uuid::Uuid::now_v7().to_string();
    let mut record = session_record(&consulted_key, String::new());
    record.payload = Some(serde_json::to_value(ConsultationReceipt {
        fingerprint,
        id: Some(id.clone()),
    })?);
    let bytes = rmp_serde::to_vec_named(&record)
        .with_context(|| format!("failed to serialize consulted receipt for {consulted_key}"))?;
    Ok(StagedReceipt {
        key: consulted_key,
        bytes,
        id,
    })
}

/// Id of the consultation receipt in force for `key` at this actor's scope.
///
/// `None` when no receipt exists or it was minted before receipt ids. Used to
/// stamp `AllowAfterReceipt` with the receipt that authorized it — never to
/// decide anything, so a missing id costs the audit link, not the gate.
pub async fn receipt_id_in_force(store: &Store, key: &str, actor: Option<&str>) -> Option<String> {
    let record = store.get(&receipt_key(key, actor)).await.ok().flatten()?;
    record.payload_as::<ConsultationReceipt>()?.id
}

pub async fn consultation_receipt_staged_for_store(
    store: &Store,
    key: &str,
    actor: Option<&str>,
    capture_fingerprint: bool,
) -> Result<StagedReceipt> {
    let fingerprint = if capture_fingerprint {
        store
            .get(key)
            .await
            .ok()
            .flatten()
            .and_then(|record| record_content_fingerprint(&record))
    } else {
        None
    };
    consultation_receipt_staged_with_fingerprint(key, actor, fingerprint)
}

/// Compute the session:current flush record WITHOUT persisting.
///
/// Returns `(key, serialized_record_bytes)` for staging.
pub async fn session_flush_staged(store: &Store) -> Result<Option<(String, Vec<u8>)>> {
    let now = now_secs();
    let consulted_keys = store.scan_keys("session:consulted:").await?;
    let stripped: Vec<String> = consulted_keys
        .iter()
        .map(|k| {
            k.strip_prefix("session:consulted:")
                .unwrap_or(k)
                .to_string()
        })
        .collect();

    let session_data = serde_json::json!({
        "consulted_keys": stripped,
        "flushed_at": now,
    });
    let mut rec = session_record("session:current", String::new());
    rec.payload = Some(session_data);
    let bytes = rmp_serde::to_vec_named(&rec)?;
    Ok(Some(("session:current".to_string(), bytes)))
}

// ── log_hit ───────────────────────────────────────────────────────────────────

/// Record a cache hit: write consulted marker, bump access_count, update daily agg.
pub async fn log_hit(store: &Store, key: &str) -> Result<()> {
    let now = now_secs();

    // 1. Daily hit aggregation
    let agg_key = today_key("analytics:hit_");
    upsert_daily_agg(store, &agg_key, key).await?;

    // 2. Mark as consulted for session tracking
    let staged = consultation_receipt_staged_for_store(store, key, None, true).await?;
    let receipt: Record = rmp_serde::from_slice(&staged.bytes)
        .context("failed to deserialize staged consultation receipt")?;
    store.put(&staged.key, &receipt).await?;

    // 3. Bump access_count and last_accessed on the target record
    if let Some(mut record) = store.get(key).await? {
        record.access_count += 1;
        record.last_accessed = now;
        store.put(key, &record).await?;
    }

    // 4. Best-effort enforcement event: ReceiptMinted.
    //
    // Mirrors the socket-mode path in `dispatch_v2::ConsultationHit` so the
    // direct-mode CLI path (`mati explain` without a daemon, or any code
    // calling `session::log_hit` against an open Store) produces the same
    // `receipt_minted` row in `mati history --enforcement`. Without this
    // parity, the enforcement audit log has gaps depending on whether the
    // mint happened over socket or direct mode.
    let _ = crate::store::enforcement::record_event(
        store,
        crate::store::enforcement::EnforcementEventType::ReceiptMinted,
        crate::store::enforcement::SubjectKind::File,
        key.to_string(),
        "claude".to_string(),
        Some(staged.id),
        "consultation_requested".to_string(),
        None,
    )
    .await;

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

/// Record a compliance hit: file access allowed because a valid consultation
/// receipt existed. Platform-neutral — incremented for both Claude pre-read
/// `AlreadyConsulted` allow and Codex post-bash confirmed consultation.
pub async fn log_compliance_hit(store: &Store, key: &str) -> Result<()> {
    let agg_key = today_key("compliance:allow_after_receipt_");
    upsert_daily_agg(store, &agg_key, key).await
}

/// Record a Codex shell compliance miss: Bash file inspection without consultation.
pub async fn log_codex_shell_miss(store: &Store, key: &str) -> Result<()> {
    let agg_key = today_key("compliance:codex_shell_miss_");
    upsert_daily_agg(store, &agg_key, key).await
}

/// Record a Codex prompt nudge: prompt indicated code work before clear consultation.
pub async fn log_prompt_nudge(store: &Store, key: &str) -> Result<()> {
    let agg_key = today_key("analytics:codex_prompt_nudge_");
    upsert_daily_agg(store, &agg_key, key).await
}

/// Record a bootstrap event. Used to measure Codex/agent bootstrap adoption.
pub async fn log_bootstrap(store: &Store, key: &str) -> Result<()> {
    let agg_key = today_key("analytics:bootstrap_");
    upsert_daily_agg(store, &agg_key, key).await
}

// ── check_consulted ───────────────────────────────────────────────────────────

/// Return true if the consulted marker exists (set by `log_hit` / capture hook).
///
/// When `actor` is `Some(id)`, reads the actor-scoped key
/// `session:consulted:<id>:<key>` (subagent path); `None` reads the global key
/// `session:consulted:<key>` (main-thread path — unchanged).
pub async fn check_consulted(store: &Store, key: &str, actor: Option<&str>) -> Result<bool> {
    let consulted_key = receipt_key(key, actor);
    Ok(store.get(&consulted_key).await?.is_some())
}

/// Return true if the consulted marker exists and is newer than `ttl_secs`.
///
/// When `actor` is `Some(id)`, reads the actor-scoped key
/// `session:consulted:<id>:<key>` (subagent enforcement path).
/// When `actor` is `None`, reads the global key `session:consulted:<key>`
/// (main-thread path — unchanged behaviour).
pub async fn check_consulted_recent(
    store: &Store,
    key: &str,
    ttl_secs: u64,
    actor: Option<&str>,
) -> Result<bool> {
    let consulted_key = receipt_key(key, actor);
    let Some(record) = store.get(&consulted_key).await? else {
        return Ok(false);
    };
    let age = now_secs().saturating_sub(record.updated_at);
    Ok(age <= ttl_secs)
}

/// Return true only when a recent receipt carries the current record's
/// fingerprint. Store faults propagate as errors so the caller can fail open;
/// swallowing them into `false` would fail closed and deny on a mati outage.
pub async fn check_consulted_recent_fingerprinted(
    store: &Store,
    key: &str,
    ttl_secs: u64,
    actor: Option<&str>,
) -> Result<bool> {
    let consulted_key = receipt_key(key, actor);
    let Some(receipt) = store.get(&consulted_key).await? else {
        return Ok(false);
    };
    if now_secs().saturating_sub(receipt.updated_at) > ttl_secs {
        return Ok(false);
    }
    let Some(stored) = receipt
        .payload_as::<ConsultationReceipt>()
        .and_then(|payload| payload.fingerprint)
    else {
        return Ok(false);
    };
    // A store read fault must remain an Err so hook callers fail open, never Ok(false).
    let current = store
        .get(key)
        .await?
        .and_then(|record| record_content_fingerprint(&record));
    Ok(current.is_some_and(|current| current == stored))
}

// ── session_flush ─────────────────────────────────────────────────────────────

/// Collect all consulted markers into `session:current` for harvest.
pub async fn session_flush(store: &Store) -> Result<()> {
    let now = now_secs();

    let consulted_keys = store.scan_keys("session:consulted:").await?;
    let stripped: Vec<String> = consulted_keys
        .iter()
        .map(|k| {
            k.strip_prefix("session:consulted:")
                .unwrap_or(k)
                .to_string()
        })
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

/// Delete all consult receipts (`session:consulted:*`) from the store.
///
/// Shared by `session_clear_consults` (PostCompact) and the end-of-session
/// `session_harvest` cleanup. Propagates store errors; the daemon-startup
/// stale-marker sweep keeps its own fail-soft loop.
async fn delete_all_receipts(store: &Store) -> Result<()> {
    let consulted_keys = store.scan_keys("session:consulted:").await?;
    for k in &consulted_keys {
        store.delete(k).await?;
    }
    Ok(())
}

/// Clear all consult receipts for the session.
///
/// Used by the PostCompact hook: compaction wipes the agent's memory of consulted
/// gotchas, but receipts are time-based and survive, so PreToolUse would not
/// re-block. Clearing them forces a fresh mem_get on next access.
pub async fn session_clear_consults(store: &Store) -> Result<()> {
    delete_all_receipts(store).await
}

// ── session_harvest ───────────────────────────────────────────────────────────

/// Archive session, run staleness analysis, auto-promote gotchas.
///
/// `repo_root` is the project root; the git root is discovered upward from it.
/// Called from both daemon socket handlers — `mcp::server::socket_dispatch` and
/// `mcp::dispatch_v2::dispatch_session_side` — on SessionEnd.
///
/// Every step is fail-open: staleness runs on the SessionEnd path, and a git
/// fault must not cost the session its archive, its promotions, or its receipt
/// cleanup.
pub async fn session_harvest(store: &Store, repo_root: &Path) -> Result<()> {
    let now = now_secs();

    // M-12-D: promote gotcha candidates before archiving
    match promote_gotcha_candidates(store).await {
        Ok(n) if n > 0 => tracing::info!(promoted = n, "gotcha candidates auto-promoted"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "gotcha promotion failed"),
    }

    // M-13-A: run full staleness analysis. Bounded by ANALYZE_TIME_BUDGET_MS.
    match StalenessAnalyzer::new(repo_root).analyze_all(store).await {
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
    delete_all_receipts(store).await?;

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

    // Update only records nobody has manually curated: a Layer 0 stub, or a
    // prior doc-capture pass. Never overwrite DeveloperManual, ClaudeEnrich,
    // or Import — those reflect a human or an enrichment pass, not this
    // heuristic scan. Excluding SessionHook here would make this function's
    // own prior write permanently block every later re-capture of the file.
    if !matches!(
        record.source,
        RecordSource::StaticAnalysis | RecordSource::SessionHook
    ) {
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
    let dt = chrono::DateTime::from_timestamp(now_secs as i64, 0).unwrap_or_else(chrono::Utc::now);
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
        Some(existing) => {
            existing
                .payload_as::<StaleReviewPayload>()
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

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    async fn temp_store() -> (TempDir, Store) {
        let dir = TempDir::new().expect("tempdir");
        let store = Store::open(dir.path()).await.expect("open store");
        (dir, store)
    }

    // ── session_harvest ──────────────────────────────────────────────────────

    /// A git worktree with one committed file. Returns the dir and the HEAD SHA.
    fn temp_repo_with_commit(rel_path: &str) -> (TempDir, String) {
        let dir = TempDir::new().expect("tempdir");
        let repo = git2::Repository::init(dir.path()).expect("git init");

        let full = dir.path().join(rel_path);
        std::fs::create_dir_all(full.parent().expect("parent")).expect("mkdir");
        std::fs::write(&full, "fn main() {}").expect("write");

        let mut index = repo.index().expect("index");
        index.add_path(Path::new(rel_path)).expect("add");
        index.write().expect("index write");
        let tree = repo
            .find_tree(index.write_tree().expect("write tree"))
            .expect("tree");
        let sig = git2::Signature::now("mati test", "test@example.invalid").expect("sig");
        let oid = repo
            .commit(Some("HEAD"), &sig, &sig, "seed", &tree, &[])
            .expect("commit");

        (dir, oid.to_string())
    }

    fn file_record_at(key: &str, updated_at: u64) -> Record {
        Record {
            key: key.to_string(),
            value: "seed".to_string(),
            category: Category::File,
            priority: Priority::Normal,
            tags: vec![],
            created_at: updated_at,
            updated_at,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            quality: QualityScore::layer0_default(),
            source: RecordSource::StaticAnalysis,
            payload: None,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: updated_at,
            },
            lifecycle: RecordLifecycle::Active,
            access_count: 0,
            last_accessed: 0,
            gap_analysis_score: 0.0,
        }
    }

    /// The wired path actually runs git staleness. `last_record_sha` is written
    /// only by `StalenessAnalyzer::git_factor`, so finding HEAD there after a
    /// harvest proves `analyze_all` ran — this was inert since the daemon split.
    #[tokio::test]
    async fn session_harvest_runs_git_staleness_analysis() {
        let (repo_dir, head_sha) = temp_repo_with_commit("src/seed.rs");
        let (_dir, store) = temp_store().await;

        let record = file_record_at("file:src/seed.rs", now_secs() - (60 * 86_400));
        assert!(record.staleness.last_record_sha.is_empty());
        store.put(&record.key, &record).await.expect("put");

        session_harvest(&store, repo_dir.path())
            .await
            .expect("harvest");

        let after = store
            .get("file:src/seed.rs")
            .await
            .expect("get")
            .expect("record survives harvest");
        assert_eq!(after.staleness.last_record_sha, head_sha);
        assert_ne!(after.staleness.tier, StalenessTier::Tombstone);

        store.close().await.expect("close");
    }

    /// Staleness runs on the SessionEnd path. When git is unusable the harvest
    /// must still archive the session, clear receipts, and stamp `stage:current`.
    #[tokio::test]
    async fn harvest_survives_a_staleness_failure() {
        let (_dir, store) = temp_store().await;

        let record = file_record_at("file:src/seed.rs", now_secs() - (60 * 86_400));
        store.put(&record.key, &record).await.expect("put");
        let mut stage = file_record_at("stage:current", now_secs());
        stage.category = Category::Stage;
        store.put("stage:current", &stage).await.expect("put stage");
        session_flush(&store).await.expect("flush");

        // No git repo anywhere above a tempdir — the analyzer can do nothing.
        let nowhere = TempDir::new().expect("tempdir");
        session_harvest(&store, nowhere.path())
            .await
            .expect("harvest must not fail when staleness cannot run");

        let sessions = store.scan_keys("session:").await.expect("scan");
        assert!(
            sessions.iter().any(|k| k != "session:current"),
            "session was archived: {sessions:?}"
        );
        let stage = store
            .get("stage:current")
            .await
            .expect("get")
            .expect("stage record");
        assert!(stage.value.contains("last_session:"));

        // And nothing was tombstoned off an unproven root.
        let after = store
            .get("file:src/seed.rs")
            .await
            .expect("get")
            .expect("record");
        assert_ne!(after.staleness.tier, StalenessTier::Tombstone);

        store.close().await.expect("close");
    }

    /// The staleness sweep parks a resume cursor when its budget runs out. That
    /// state is on the Eventual path and reachable by the SessionEnd hook, so a
    /// junk value must cost a fair sweep and nothing else — not the archive,
    /// not the receipts, not the harvest's return value.
    #[tokio::test]
    async fn harvest_survives_a_junk_staleness_cursor() {
        let (repo_dir, head_sha) = temp_repo_with_commit("src/seed.rs");
        let (_dir, store) = temp_store().await;

        let record = file_record_at("file:src/seed.rs", now_secs() - (60 * 86_400));
        store.put(&record.key, &record).await.expect("put");
        session_flush(&store).await.expect("flush");

        // Literals on purpose: the cursor key and its payload field are private
        // to `health::staleness`, which owns the only writes to them.
        let mut junk = file_record_at("health:staleness_cursor", now_secs());
        junk.payload = Some(serde_json::json!({ "after": "retired_namespace:whatever" }));
        store
            .put("health:staleness_cursor", &junk)
            .await
            .expect("put cursor");

        session_harvest(&store, repo_dir.path())
            .await
            .expect("harvest must survive a cursor it cannot place");

        let after = store
            .get("file:src/seed.rs")
            .await
            .expect("get")
            .expect("record");
        assert_eq!(
            after.staleness.last_record_sha, head_sha,
            "the sweep restarted instead of skipping past the junk cursor"
        );
        let sessions = store.scan_keys("session:").await.expect("scan");
        assert!(sessions.iter().any(|k| k != "session:current"));

        store.close().await.expect("close");
    }

    #[tokio::test]
    async fn log_bootstrap_creates_daily_aggregate() {
        let (_dir, store) = temp_store().await;

        log_bootstrap(&store, "__bootstrap__")
            .await
            .expect("log bootstrap");

        let key = today_key("analytics:bootstrap_");
        let record = store
            .get(&key)
            .await
            .expect("get bootstrap aggregate")
            .expect("bootstrap record exists");
        let agg = record.payload_as::<DailyAgg>().expect("daily agg payload");
        assert_eq!(agg.count, 1);
        assert_eq!(agg.keys, vec!["__bootstrap__".to_string()]);
    }

    #[tokio::test]
    async fn shadow_observation_caps_are_isolated_and_keep_recent_entries() {
        let (_dir, store) = temp_store().await;
        let action = crate::hooks::decide::Action {
            tool: "db_client".into(),
            target_path: None,
            host: Some("db.example".into()),
            argv: vec![],
            files: vec![],
        };
        for index in 0..=MAX_SHADOW_OBSERVATIONS {
            let mut action = action.clone();
            action.argv = vec![index.to_string()];
            record_shadow_observation(
                &store,
                "policy:noisy",
                &action,
                crate::hooks::decide::ShadowOutcome::Block,
            )
            .await
            .unwrap();
        }
        record_shadow_observation(
            &store,
            "policy:quiet",
            &action,
            crate::hooks::decide::ShadowOutcome::Steer,
        )
        .await
        .unwrap();

        let record = store.get(&shadow_observation_key()).await.unwrap().unwrap();
        let agg = record.payload_as::<ShadowObservationAgg>().unwrap();
        let noisy = &agg.policies["policy:noisy"];
        assert_eq!(noisy.count, (MAX_SHADOW_OBSERVATIONS + 1) as u64);
        assert_eq!(noisy.observations.len(), MAX_SHADOW_OBSERVATIONS);
        assert_eq!(noisy.observations[0].action.argv, vec!["1"]);
        assert_eq!(agg.policies["policy:quiet"].count, 1);
        assert_eq!(agg.policies["policy:quiet"].observations.len(), 1);
    }

    #[tokio::test]
    async fn check_consulted_recent_uses_receipt_ttl() {
        let (_dir, store) = temp_store().await;
        let key = "file:src/main.rs";

        assert!(!check_consulted_recent(&store, key, 900, None)
            .await
            .expect("no receipt yet"));

        log_hit(&store, key).await.expect("log consultation hit");

        assert!(check_consulted_recent(&store, key, 900, None)
            .await
            .expect("fresh receipt should be valid"));
    }

    #[tokio::test]
    async fn fingerprinted_receipt_invalidates_after_content_drift() {
        let (_dir, store) = temp_store().await;
        let key = "schema:orders";
        store
            .put(key, &session_record(key, "orders v1".into()))
            .await
            .unwrap();
        log_hit(&store, key).await.unwrap();

        let receipt = store.get(&receipt_key(key, None)).await.unwrap().unwrap();
        assert!(receipt
            .payload_as::<ConsultationReceipt>()
            .and_then(|payload| payload.fingerprint)
            .is_some());
        assert!(check_consulted_recent_fingerprinted(&store, key, 900, None)
            .await
            .unwrap());

        let mut changed = store.get(key).await.unwrap().unwrap();
        changed.value = "orders v2".into();
        store.put(key, &changed).await.unwrap();
        assert!(
            !check_consulted_recent_fingerprinted(&store, key, 900, None)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn fingerprinted_check_rejects_missing_receipt() {
        let (_dir, store) = temp_store().await;

        assert!(
            !check_consulted_recent_fingerprinted(&store, "schema:orders", 900, None)
                .await
                .expect("missing receipt is a legitimate non-satisfaction")
        );
    }

    #[tokio::test]
    async fn fingerprinted_check_rejects_legacy_or_introspection_receipts() {
        let (_dir, store) = temp_store().await;
        let key = "schema:orders";
        store
            .put(key, &session_record(key, "orders v1".into()))
            .await
            .unwrap();
        let staged = consultation_receipt_staged(key, None).unwrap();
        let (receipt_key_value, receipt_bytes) = (staged.key, staged.bytes);
        store
            .transact_sessions_raw(&[(&receipt_key_value, &receipt_bytes)])
            .await
            .unwrap();
        assert!(
            !check_consulted_recent_fingerprinted(&store, key, 900, None)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn fingerprinted_check_still_enforces_ttl() {
        let (_dir, store) = temp_store().await;
        let key = "schema:orders";
        store
            .put(key, &session_record(key, "orders v1".into()))
            .await
            .unwrap();
        log_hit(&store, key).await.unwrap();
        let receipt_key_value = receipt_key(key, None);
        let mut receipt = store.get(&receipt_key_value).await.unwrap().unwrap();
        receipt.updated_at = 0;
        store.put(&receipt_key_value, &receipt).await.unwrap();
        assert!(
            !check_consulted_recent_fingerprinted(&store, key, 900, None)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn fingerprinted_check_rejects_deleted_required_record() {
        let (_dir, store) = temp_store().await;
        let key = "schema:orders";
        store
            .put(key, &session_record(key, "orders v1".into()))
            .await
            .unwrap();
        log_hit(&store, key).await.unwrap();
        store.delete(key).await.unwrap();

        assert!(
            !check_consulted_recent_fingerprinted(&store, key, 900, None)
                .await
                .expect("deleted record is a legitimate non-satisfaction")
        );
    }

    #[tokio::test]
    async fn consult_receipt_is_actor_scoped_when_actor_present() {
        let (_dir, store) = temp_store().await;

        // Actor-scoped receipt: actor Some("agentA").
        let staged_k = consultation_receipt_staged("file:x", Some("agentA")).unwrap();
        let (k, v) = (staged_k.key, staged_k.bytes);
        store.transact_sessions_raw(&[(&k, &v)]).await.unwrap();

        let keys = store.scan_keys("session:consulted:").await.unwrap();
        assert!(
            keys.iter().any(|k| k == "session:consulted:agentA:file:x"),
            "actor-scoped key must be present, got: {keys:?}"
        );
        assert!(
            !keys.iter().any(|k| k == "session:consulted:file:x"),
            "global key must NOT be written by actor-scoped call, got: {keys:?}"
        );

        // Global receipt: actor None.
        let staged_k2 = consultation_receipt_staged("file:x", None).unwrap();
        let (k2, v2) = (staged_k2.key, staged_k2.bytes);
        store.transact_sessions_raw(&[(&k2, &v2)]).await.unwrap();

        let keys2 = store.scan_keys("session:consulted:").await.unwrap();
        assert!(
            keys2.iter().any(|k| k == "session:consulted:file:x"),
            "global key must be present with actor=None, got: {keys2:?}"
        );
    }

    #[tokio::test]
    async fn gate_requires_actor_scoped_receipt_for_subagent() {
        let (_dir, store) = temp_store().await;

        // Write an actor-scoped receipt for agentA / file:x.
        let staged_k = consultation_receipt_staged("file:x", Some("agentA")).unwrap();
        let (k, v) = (staged_k.key, staged_k.bytes);
        store.transact_sessions_raw(&[(&k, &v)]).await.unwrap();

        // agentA's own receipt is found.
        assert!(
            check_consulted_recent(&store, "file:x", 900, Some("agentA"))
                .await
                .expect("agentA receipt lookup"),
            "agentA should see its own actor-scoped receipt"
        );

        // A DIFFERENT subagent (agentB) does NOT see agentA's receipt.
        assert!(
            !check_consulted_recent(&store, "file:x", 900, Some("agentB"))
                .await
                .expect("agentB receipt lookup"),
            "agentB must NOT ride agentA's receipt"
        );

        // Write a GLOBAL receipt for file:y (main-thread path).
        let staged_k2 = consultation_receipt_staged("file:y", None).unwrap();
        let (k2, v2) = (staged_k2.key, staged_k2.bytes);
        store.transact_sessions_raw(&[(&k2, &v2)]).await.unwrap();

        // Main thread (actor=None) sees the global receipt unchanged.
        assert!(
            check_consulted_recent(&store, "file:y", 900, None)
                .await
                .expect("global receipt lookup"),
            "main thread must still see the global receipt"
        );

        // A subagent does NOT ride the global (main-thread) receipt.
        assert!(
            !check_consulted_recent(&store, "file:y", 900, Some("agentA"))
                .await
                .expect("agentA vs global receipt lookup"),
            "subagent must NOT ride the global main-thread receipt"
        );
    }

    #[tokio::test]
    async fn session_clear_consults_deletes_all_receipts() {
        let (_dir, store) = temp_store().await;
        let key1 = "file:src/main.rs";
        let key2 = "file:src/lib.rs";

        log_hit(&store, key1).await.expect("log first hit");
        log_hit(&store, key2).await.expect("log second hit");

        // Verify receipts exist before clearing.
        let before = store
            .scan_keys("session:consulted:")
            .await
            .expect("scan before");
        assert_eq!(before.len(), 2, "expected two receipts before clear");

        session_clear_consults(&store)
            .await
            .expect("clear_consults should succeed");

        let after = store
            .scan_keys("session:consulted:")
            .await
            .expect("scan after");
        assert!(after.is_empty(), "all receipts should be gone after clear");
    }

    // ── doc_capture ───────────────────────────────────────────────────────────

    /// Regression: before the fix, the update gate checked
    /// `record.source != RecordSource::StaticAnalysis`, so the very first
    /// capture's `SessionHook` stamp made every later capture on the same
    /// file a permanent no-op — 19 records in the live store were locked
    /// this way. A second capture with different content must still refresh
    /// the purpose while the record stays `SessionHook`-sourced.
    #[tokio::test]
    async fn doc_capture_refreshes_a_prior_session_hook_capture() {
        let (_dir, store) = temp_store().await;

        let mut record = file_record_at("file:src/lib.rs", 100);
        let fr = FileRecord::layer0_stub(
            "src/lib.rs",
            vec![],
            vec![],
            vec![],
            0,
            0,
            0,
            None,
            false,
            0,
            1,
        );
        record.payload = serde_json::to_value(&fr).ok();
        store.put("file:src/lib.rs", &record).await.expect("seed");

        doc_capture(
            &store,
            "src/lib.rs",
            "//! First purpose.
fn main() {}",
        )
        .await
        .expect("first capture");
        let after_first = store
            .get("file:src/lib.rs")
            .await
            .expect("get")
            .expect("record exists");
        assert_eq!(after_first.source, RecordSource::SessionHook);
        let fr1: FileRecord = after_first.payload_as().expect("payload");
        assert_eq!(fr1.purpose, "First purpose.");

        doc_capture(
            &store,
            "src/lib.rs",
            "//! Updated purpose.
fn main() {}",
        )
        .await
        .expect("second capture");
        let after_second = store
            .get("file:src/lib.rs")
            .await
            .expect("get")
            .expect("record exists");
        assert_eq!(after_second.source, RecordSource::SessionHook);
        let fr2: FileRecord = after_second.payload_as().expect("payload");
        assert_eq!(
            fr2.purpose, "Updated purpose.",
            "doc-capture must refresh a SessionHook-sourced record, not ratchet shut"
        );
    }

    /// The gate must still protect developer- and enrichment-authored records
    /// from being clobbered by the heuristic doc-comment scan.
    #[tokio::test]
    async fn doc_capture_never_overwrites_developer_manual() {
        let (_dir, store) = temp_store().await;

        let mut record = file_record_at("file:src/manual.rs", 100);
        record.source = RecordSource::DeveloperManual;
        let fr = FileRecord::layer0_stub(
            "src/manual.rs",
            vec![],
            vec![],
            vec![],
            0,
            0,
            0,
            None,
            false,
            0,
            1,
        );
        record.payload = serde_json::to_value(&fr).ok();
        store
            .put("file:src/manual.rs", &record)
            .await
            .expect("seed");

        doc_capture(
            &store,
            "src/manual.rs",
            "//! Should not apply.
fn main() {}",
        )
        .await
        .expect("capture");
        let after = store
            .get("file:src/manual.rs")
            .await
            .expect("get")
            .expect("record exists");
        assert_eq!(after.source, RecordSource::DeveloperManual);
        let fr_after: FileRecord = after.payload_as().expect("payload");
        assert_eq!(
            fr_after.purpose, "",
            "developer-curated purpose must not be overwritten by doc-capture"
        );
    }
}
