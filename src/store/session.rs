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
    Category, ConfidenceScore, FileRecord, GotchaRecord, Priority, QualityScore, ReceiptSource,
    Record, RecordLifecycle, RecordSource, RecordVersion, RepoIdent, StaleReviewEntry,
    StaleReviewPayload, StalenessScore, StalenessTier, Store,
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

/// Key holding the most recent finished subagent's summary. A single,
/// overwritten key: O(1) for `recent_session` to read, self-bounding (never
/// grows), and cleared at session harvest so it stays scoped to one session.
pub const SUBAGENT_SUMMARY_KEY: &str = "session:summary:latest";

/// Max stored characters of a subagent summary. Bounds what `recent_session`
/// can inject into the bootstrap packet.
const SUBAGENT_SUMMARY_MAX: usize = 800;

fn truncate_summary(s: &str) -> String {
    if s.chars().count() <= SUBAGENT_SUMMARY_MAX {
        return s.to_string();
    }
    let mut out: String = s.chars().take(SUBAGENT_SUMMARY_MAX).collect();
    out.push('…');
    out
}

/// Record a finished subagent's summary, overwriting [`SUBAGENT_SUMMARY_KEY`].
/// Empty summaries are a no-op. Best-effort — the SubagentStop hook fails open.
pub async fn write_subagent_summary(
    store: &Store,
    summary: &str,
    agent_id: Option<&str>,
    agent_type: Option<&str>,
    session_id: Option<&str>,
    transcript_path: Option<&str>,
) -> Result<()> {
    let trimmed = summary.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let mut record = session_record(SUBAGENT_SUMMARY_KEY, truncate_summary(trimmed));
    record.payload = Some(serde_json::json!({
        "agent_id": agent_id,
        "agent_type": agent_type,
        "session_id": session_id,
        "transcript_path": transcript_path,
    }));
    store.put(SUBAGENT_SUMMARY_KEY, &record).await
}

/// Build the eventual record for one Claude Code `InstructionsLoaded` event.
pub fn instructions_loaded_record(
    key: &str,
    payload: &crate::hooks::decide::InstructionsLoadedPayload,
) -> Result<Record> {
    let mut record = session_record(key, payload.file_path.clone());
    record.payload = Some(serde_json::to_value(payload)?);
    Ok(record)
}

/// Persist one Claude Code `InstructionsLoaded` payload.
///
/// The `hook_event:` key namespace routes through `Store::put` to the
/// Eventual/session tree. Recording is best-effort at the hook adapter.
pub async fn record_instructions_loaded(
    store: &Store,
    payload: &crate::hooks::decide::InstructionsLoadedPayload,
) -> Result<String> {
    let key = format!("hook_event:instructions_loaded:{}", uuid::Uuid::now_v7());
    let record = instructions_loaded_record(&key, payload)?;
    store.put(&key, &record).await?;
    Ok(key)
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
    /// How the consultation happened. Policy `requires.via` names the sources a
    /// policy accepts, and satisfaction compares this value with that list.
    ///
    /// `None` on receipts written before the field existed, and on mints whose
    /// source is not attributable: `mati log-hit` and the `StoreProxy` path.
    /// Those are left unset rather than guessed — an invented provenance is
    /// worse than an absent one.
    #[serde(default)]
    pub source: Option<ReceiptSource>,
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

// ── Worktree-scoped receipts ─────────────────────────────────────────────────

/// Identify the git worktree at `cwd` for receipt scoping.
///
/// Git worktrees share history (and, by extension, mati's slug and store)
/// but not working-tree content: the same file path can hold different bytes
/// in two worktrees of the same repo. A consultation receipt minted while
/// operating in one worktree must not satisfy a gate checked from another.
/// `git2::Repository::discover` resolves each worktree's own `workdir()`
/// correctly for both sibling and nested worktree layouts — unlike a lexical
/// `.git`-file check, which mistakes a nested worktree's `.git` pointer file
/// for "no boundary here" and walks up into the main checkout's real `.git`
/// directory. `None` when no git repo is discoverable; the caller then falls
/// back to whatever scope `agent_id` alone provides.
pub fn worktree_scope_tag(cwd: &Path) -> Option<String> {
    worktree_scope_tag_for(&RepoIdent::discover(cwd))
}

/// [`worktree_scope_tag`] for a caller that already discovered a
/// [`RepoIdent`] this invocation — avoids a second `git2::Repository::discover`
/// call for the same repo (see `cli::hook_decide::entry::run_inner`).
pub fn worktree_scope_tag_for(ident: &RepoIdent) -> Option<String> {
    let workdir = ident.workdir.as_ref()?;
    let canon = std::fs::canonicalize(workdir).unwrap_or_else(|_| workdir.clone());
    let digest = Sha256::digest(canon.to_string_lossy().as_bytes());
    Some(hex::encode(&digest[..4]))
}

/// Combine the worktree tag with an optional subagent id into the single
/// opaque scope string receipts key on. `None` only when neither is known,
/// preserving the pre-existing unscoped global receipt outside any git repo.
pub fn combined_actor_scope(worktree: Option<&str>, agent_id: Option<&str>) -> Option<String> {
    match (worktree, agent_id) {
        (Some(w), Some(a)) => Some(format!("{w}:{a}")),
        (Some(w), None) => Some(w.to_string()),
        (None, Some(a)) => Some(a.to_string()),
        (None, None) => None,
    }
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
    consultation_receipt_staged_with_fingerprint(key, actor, None, None)
}

pub fn consultation_receipt_staged_with_fingerprint(
    key: &str,
    actor: Option<&str>,
    fingerprint: Option<String>,
    source: Option<ReceiptSource>,
) -> Result<StagedReceipt> {
    let consulted_key = receipt_key(key, actor);
    let id = uuid::Uuid::now_v7().to_string();
    let mut record = session_record(&consulted_key, String::new());
    record.payload = Some(serde_json::to_value(ConsultationReceipt {
        fingerprint,
        id: Some(id.clone()),
        source,
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
    source: Option<ReceiptSource>,
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
    consultation_receipt_staged_with_fingerprint(key, actor, fingerprint, source)
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
///
/// `actor` scopes the receipt (worktree, or worktree+agent). It MUST match the
/// scope the file gate checks — an unscoped receipt never satisfies a
/// worktree-scoped gate. Callers derive it from their cwd via
/// [`worktree_scope_tag`]; see `cli::proxy::StoreProxy::log_hit`.
pub async fn log_hit(store: &Store, key: &str, actor: Option<&str>) -> Result<()> {
    let now = now_secs();

    // 1. Daily hit aggregation
    let agg_key = today_key("analytics:hit_");
    upsert_daily_agg(store, &agg_key, key).await?;

    // 2. Mark as consulted for session tracking. No source: this is the direct
    // store path behind `StoreProxy::log_hit`, reached from CLI commands whose
    // consultation is neither a `mem_get` nor an introspection.
    let staged = consultation_receipt_staged_for_store(store, key, actor, true, None).await?;
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

/// Return true only when a recent receipt records one of the policy's accepted
/// consultation sources. A missing source is deliberately not accepted: it is
/// legacy or unattributed evidence, not evidence for a named channel.
pub async fn check_consulted_recent_with_sources(
    store: &Store,
    key: &str,
    ttl_secs: u64,
    actor: Option<&str>,
    accepted_sources: &[ReceiptSource],
) -> Result<bool> {
    let consulted_key = receipt_key(key, actor);
    let Some(record) = store.get(&consulted_key).await? else {
        return Ok(false);
    };
    if now_secs().saturating_sub(record.updated_at) > ttl_secs {
        return Ok(false);
    }
    let payload = record
        .payload
        .ok_or_else(|| anyhow::anyhow!("consultation receipt {consulted_key} has no payload"))?;
    let receipt: ConsultationReceipt = serde_json::from_value(payload)
        .with_context(|| format!("invalid consultation receipt payload at {consulted_key}"))?;
    Ok(receipt
        .source
        .is_some_and(|source| accepted_sources.contains(&source)))
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

/// Return true only when a recent, fingerprint-valid receipt records one of
/// the policy's accepted consultation sources.
pub async fn check_consulted_recent_fingerprinted_with_sources(
    store: &Store,
    key: &str,
    ttl_secs: u64,
    actor: Option<&str>,
    accepted_sources: &[ReceiptSource],
) -> Result<bool> {
    let consulted_key = receipt_key(key, actor);
    let Some(receipt_record) = store.get(&consulted_key).await? else {
        return Ok(false);
    };
    if now_secs().saturating_sub(receipt_record.updated_at) > ttl_secs {
        return Ok(false);
    }
    let payload = receipt_record
        .payload
        .ok_or_else(|| anyhow::anyhow!("consultation receipt {consulted_key} has no payload"))?;
    let receipt: ConsultationReceipt = serde_json::from_value(payload)
        .with_context(|| format!("invalid consultation receipt payload at {consulted_key}"))?;
    if !receipt
        .source
        .is_some_and(|source| accepted_sources.contains(&source))
    {
        return Ok(false);
    }
    let Some(stored) = receipt.fingerprint else {
        return Ok(false);
    };
    // A store read fault must remain an Err so hook callers fail open, never
    // Ok(false).
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

// ── Tier 1 session lockdown ───────────────────────────────────────────────────

/// Prefix for the markers naming a file an actor was denied and has not
/// consulted since.
pub const OWED_PREFIX: &str = "session:owed:";

/// How long an unconsulted deny keeps locking the session down. The same
/// window as the shell gate's receipt TTL, so a debt lasts exactly as long as
/// the receipt that would have settled it.
pub const OWED_RECEIPT_TTL_SECS: u64 = CONSULTED_RECENT_TTL_SECS;

/// `session:owed:<actor>|<key>`. `|` separates scope from key so that a scan
/// stops at the scope boundary: an actor scope is a worktree tag optionally
/// `:`-joined to an agent id, and without the terminator a scan for one scope
/// would cross-match a key that merely starts the same way.
fn owed_key(key: &str, actor: Option<&str>) -> String {
    format!("{}{key}", owed_scan_prefix(actor))
}

fn owed_scan_prefix(actor: Option<&str>) -> String {
    format!("{OWED_PREFIX}{}|", actor.unwrap_or("-"))
}

/// The prefix covering every debt in one worktree: the main thread's markers
/// (`session:owed:<wt>|…`) and its subagents' (`session:owed:<wt>:<agent>|…`)
/// alike. Stopping before the `|` is what widens the scan, and the worktree tag
/// is a fixed-width hex digest, so a prefix match on it is tag equality — no
/// other worktree can be caught by it.
///
/// Outside a git repo there is no tag, and a bare `session:owed:` prefix would
/// scan every scope in the store, so that case falls back to the actor scope.
fn owed_debt_scan_prefix(worktree: Option<&str>, actor: Option<&str>) -> String {
    match worktree {
        Some(worktree) => format!("{OWED_PREFIX}{worktree}"),
        None => owed_scan_prefix(actor),
    }
}

/// Record that `actor` was denied `key` and owes its consultation receipt.
///
/// Expired markers for the same actor are dropped in the same pass, which is
/// what bounds the scan [`outstanding_owed`] runs on every Bash command.
/// Already-settled ones are not: settlement is per actor, so a marker this
/// actor has consulted may be the only thing still holding another actor's
/// lockdown.
pub async fn record_owed_receipt(store: &Store, key: &str, actor: Option<&str>) -> Result<()> {
    let prefix = owed_scan_prefix(actor);
    let now = now_secs();
    for record in store.scan_prefix(&prefix).await? {
        if now.saturating_sub(record.updated_at) > OWED_RECEIPT_TTL_SECS {
            store.delete(&record.key).await?;
        }
    }
    let marker_key = owed_key(key, actor);
    // Create-once per window, not per session: the debt runs from the first
    // deny, so an agent that keeps retrying cannot refresh its way into an
    // endless lockdown. The sweep above already dropped this key's marker if
    // the window had passed, so a deny after it re-arms rather than finding a
    // marker `outstanding_owed` will skip as stale and never lock down again.
    if store.get(&marker_key).await?.is_some() {
        return Ok(());
    }
    let record = session_record(&marker_key, String::new());
    store.put(&marker_key, &record).await
}

/// The most recently denied key in `worktree` that `actor` has not consulted.
///
/// The two scopes differ on purpose. The debt is worktree-wide: it records that
/// this worktree was denied, and spawning a fresh context window does not
/// un-happen that, so a parent's deny binds its subagents and a subagent's
/// binds its parent. Settlement stays per actor, because a receipt proves the
/// record entered *that* context window and a subagent's `mem_get` puts nothing
/// in its parent's.
///
/// Settlement is re-derived here on every call, never recorded: a marker holds
/// no memory of having been paid, so clearing receipts re-owes every marker.
///
/// `None` when nothing is owed: no marker, all expired, or every one settled by
/// a receipt this actor holds. This is the decidable question the lockdown asks
/// instead of "does this command touch file X" — a computed filename is
/// invisible to a classifier and irrelevant here.
pub async fn outstanding_owed(
    store: &Store,
    worktree: Option<&str>,
    actor: Option<&str>,
) -> Result<Option<String>> {
    let prefix = owed_debt_scan_prefix(worktree, actor);
    let now = now_secs();
    let mut markers = store.scan_prefix(&prefix).await?;
    markers.sort_by_key(|record| std::cmp::Reverse(record.updated_at));
    for record in markers {
        if now.saturating_sub(record.updated_at) > OWED_RECEIPT_TTL_SECS {
            continue;
        }
        // Split on the FIRST `|`, not the caller's prefix: the scan spans
        // several actor scopes and each has its own prefix length. The scope
        // is the leading field, so this is exact as long as no agent id
        // contains a `|` — a record key may, since a path can.
        let Some((_, owed)) = record.key.split_once('|') else {
            continue;
        };
        if !check_consulted(store, owed, actor).await? {
            return Ok(Some(owed.to_string()));
        }
    }
    Ok(None)
}

/// Delete all consult receipts (`session:consulted:*`) from the store.
///
/// Used by `session_clear_consults` (PostCompact), which resets the whole
/// store's consultation state. `session_harvest` scopes its cleanup to the
/// ending worktree instead (see [`delete_scope_receipts`]). Propagates store
/// errors; the daemon-startup stale-marker sweep keeps its own fail-soft loop.
async fn delete_all_receipts(store: &Store) -> Result<()> {
    let consulted_keys = store.scan_keys("session:consulted:").await?;
    for k in &consulted_keys {
        store.delete(k).await?;
    }
    // Lockdown markers go with them: clearing receipts re-arms every gate, so
    // markers left behind would lock the next window down before it touched
    // anything.
    for k in &store.scan_keys(OWED_PREFIX).await? {
        store.delete(k).await?;
    }
    Ok(())
}

/// Delete only the ending worktree's consult receipts and lockdown markers.
///
/// Harvest runs on the daemon, which serves every sibling worktree of a
/// shared-slug clone (a checkout with a remote). A store-wide wipe would clear
/// a sibling worktree's outstanding debt and lift its lockdown for free, so
/// both deletes are scoped to the ending worktree: `session:consulted:<wt>…`
/// and `session:owed:<wt>…`, the same worktree tag `record_owed_receipt` and
/// the receipt writer key on. Clearing receipts re-arms this worktree's gates,
/// so its markers go with them; the sibling's stay untouched. Outside a git
/// repo (`worktree` None) there is no sibling and the wipe stays store-wide.
async fn delete_scope_receipts(store: &Store, worktree: Option<&str>) -> Result<()> {
    let (consulted_prefix, owed_prefix) = match worktree {
        Some(wt) => (
            format!("session:consulted:{wt}"),
            format!("{OWED_PREFIX}{wt}"),
        ),
        None => ("session:consulted:".to_string(), OWED_PREFIX.to_string()),
    };
    for k in &store.scan_keys(&consulted_prefix).await? {
        store.delete(k).await?;
    }
    for k in &store.scan_keys(&owed_prefix).await? {
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
/// `worktree` is the ending session's worktree tag, computed client-side from
/// the SessionEnd hook's cwd — the daemon's own `repo_root` names whichever
/// worktree started it, not the one ending, so the receipt cleanup cannot be
/// scoped from `repo_root`. Called from both daemon socket handlers —
/// `mcp::server::socket_dispatch` and `mcp::dispatch_v2::session::dispatch_session_side`
/// — on SessionEnd.
///
/// Every step is fail-open: staleness runs on the SessionEnd path, and a git
/// fault must not cost the session its archive, its promotions, or its receipt
/// cleanup.
pub async fn session_harvest(
    store: &Store,
    repo_root: &Path,
    worktree: Option<&str>,
) -> Result<()> {
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

    // Drop the latest subagent summary — scoped to the session that just ended.
    // Above the session:current guard: a session can produce subagent summaries
    // without a main-agent flush, and the summary must not leak to the next one.
    let _ = store.delete(SUBAGENT_SUMMARY_KEY).await;

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

    // Clean up this worktree's consulted markers and lockdown debt only.
    delete_scope_receipts(store, worktree).await?;

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

    #[test]
    fn instructions_loaded_record_preserves_the_captured_payload() {
        let payload = crate::hooks::decide::InstructionsLoadedPayload {
            session_id: "session-123".into(),
            transcript_path: "/tmp/transcript.jsonl".into(),
            cwd: "/repo".into(),
            hook_event_name: "InstructionsLoaded".into(),
            file_path: "/repo/.claude/rules/safety.md".into(),
            memory_type: "Project".into(),
            load_reason: "session_start".into(),
        };
        let record = instructions_loaded_record("hook_event:instructions_loaded:test", &payload)
            .expect("record should serialize");

        assert_eq!(record.key, "hook_event:instructions_loaded:test");
        assert_eq!(record.value, payload.file_path);
        assert_eq!(
            record.payload_as::<crate::hooks::decide::InstructionsLoadedPayload>(),
            Some(payload)
        );
        assert_eq!(
            crate::store::Durability::for_key(&record.key),
            crate::store::Durability::Eventual
        );
    }

    // ── receipt provenance ───────────────────────────────────────────────────

    /// The source reaches the stored payload, not just the argument list.
    ///
    /// Reads back through the same serialization the store uses, so a receipt
    /// that records provenance in memory but drops it on write fails here.
    #[test]
    fn receipt_records_the_source_it_was_minted_with() {
        for source in [
            ReceiptSource::MemGet,
            ReceiptSource::DbIntrospection,
            ReceiptSource::HookContext,
        ] {
            let staged = consultation_receipt_staged_with_fingerprint(
                "decision:x",
                None,
                None,
                Some(source),
            )
            .expect("stage receipt");
            let record: Record = rmp_serde::from_slice(&staged.bytes).expect("deserialize record");
            let receipt = record
                .payload_as::<ConsultationReceipt>()
                .expect("receipt payload");
            assert_eq!(
                receipt.source,
                Some(source),
                "minted with {source:?} but stored {:?}",
                receipt.source
            );
        }
    }

    /// An unset source stays unset. Guards the deliberate choice at the mint
    /// sites that cannot name their provenance — a default would invent one.
    #[test]
    fn receipt_without_a_source_stays_none() {
        let staged = consultation_receipt_staged_with_fingerprint("decision:x", None, None, None)
            .expect("stage receipt");
        let record: Record = rmp_serde::from_slice(&staged.bytes).expect("deserialize record");
        let receipt = record
            .payload_as::<ConsultationReceipt>()
            .expect("receipt payload");
        assert_eq!(receipt.source, None);
    }

    /// Receipts written before the field existed must still load. They are the
    /// majority of any store upgrading into this change.
    #[test]
    fn legacy_receipt_payload_deserializes_with_no_source() {
        let legacy = serde_json::json!({ "fingerprint": null, "id": "01890000-0000-7000-8000-000000000000" });
        let receipt: ConsultationReceipt =
            serde_json::from_value(legacy).expect("legacy receipt must still parse");
        assert_eq!(receipt.source, None);
        assert!(receipt.id.is_some(), "unrelated fields must survive");
    }

    #[tokio::test]
    async fn source_aware_recent_check_requires_an_accepted_source() {
        let (_dir, store) = temp_store().await;
        let key = "decision:source-aware";

        for source in [
            ReceiptSource::MemGet,
            ReceiptSource::DbIntrospection,
            ReceiptSource::HookContext,
            ReceiptSource::CommandObserved,
        ] {
            let staged =
                consultation_receipt_staged_with_fingerprint(key, None, None, Some(source))
                    .expect("stage receipt");
            let record: Record = rmp_serde::from_slice(&staged.bytes).expect("receipt record");
            store
                .put(&staged.key, &record)
                .await
                .expect("write receipt");
            assert!(
                check_consulted_recent_with_sources(&store, key, 900, None, &[source])
                    .await
                    .expect("check receipt"),
                "{source:?} should satisfy a policy accepting it"
            );
            let other = match source {
                ReceiptSource::MemGet => ReceiptSource::DbIntrospection,
                ReceiptSource::DbIntrospection => ReceiptSource::HookContext,
                ReceiptSource::HookContext => ReceiptSource::CommandObserved,
                ReceiptSource::CommandObserved => ReceiptSource::MemGet,
                ReceiptSource::Unknown => ReceiptSource::MemGet,
            };
            assert!(
                !check_consulted_recent_with_sources(&store, key, 900, None, &[other])
                    .await
                    .expect("check receipt"),
                "{source:?} must not satisfy a policy accepting only {other:?}"
            );
        }

        let staged = consultation_receipt_staged_with_fingerprint(key, None, None, None)
            .expect("stage unattributed receipt");
        let record: Record = rmp_serde::from_slice(&staged.bytes).expect("receipt record");
        store
            .put(&staged.key, &record)
            .await
            .expect("write receipt");
        assert!(!check_consulted_recent_with_sources(
            &store,
            key,
            900,
            None,
            &[
                ReceiptSource::MemGet,
                ReceiptSource::DbIntrospection,
                ReceiptSource::HookContext
            ]
        )
        .await
        .expect("check unattributed receipt"));

        let mut legacy = session_record(&format!("session:consulted:{key}"), String::new());
        legacy.payload = Some(serde_json::json!({
            "fingerprint": null,
            "id": "01890000-0000-7000-8000-000000000000"
        }));
        store
            .put(&legacy.key, &legacy)
            .await
            .expect("write legacy receipt");
        assert!(!check_consulted_recent_with_sources(
            &store,
            key,
            900,
            None,
            &[ReceiptSource::MemGet]
        )
        .await
        .expect("check legacy receipt"));
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

        session_harvest(&store, repo_dir.path(), None)
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
        session_harvest(&store, nowhere.path(), None)
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

    #[tokio::test]
    async fn write_subagent_summary_writes_latest_key() {
        let (_dir, store) = temp_store().await;

        write_subagent_summary(
            &store,
            "  Read config.rs; the timeout is in millis.  ",
            Some("agent-abc"),
            Some("general-purpose"),
            Some("sess-1"),
            Some("/t/agent-abc.jsonl"),
        )
        .await
        .expect("write summary");

        let rec = store
            .get(SUBAGENT_SUMMARY_KEY)
            .await
            .expect("get")
            .expect("summary record exists");
        assert_eq!(rec.value, "Read config.rs; the timeout is in millis.");
        let payload = rec.payload.expect("payload");
        assert_eq!(payload["agent_id"], "agent-abc");
        assert_eq!(payload["agent_type"], "general-purpose");
        assert_eq!(payload["session_id"], "sess-1");

        store.close().await.expect("close");
    }

    #[tokio::test]
    async fn write_subagent_summary_empty_is_noop() {
        let (_dir, store) = temp_store().await;

        write_subagent_summary(&store, "   \n  ", None, None, None, None)
            .await
            .expect("empty summary is ok");

        assert!(
            store
                .get(SUBAGENT_SUMMARY_KEY)
                .await
                .expect("get")
                .is_none(),
            "empty summary must not write a record"
        );

        store.close().await.expect("close");
    }

    #[tokio::test]
    async fn write_subagent_summary_truncates_long_input() {
        let (_dir, store) = temp_store().await;

        let long = "x".repeat(SUBAGENT_SUMMARY_MAX + 500);
        write_subagent_summary(&store, &long, None, None, None, None)
            .await
            .expect("write");

        let rec = store
            .get(SUBAGENT_SUMMARY_KEY)
            .await
            .expect("get")
            .expect("record");
        // SUBAGENT_SUMMARY_MAX chars plus the ellipsis marker.
        assert_eq!(rec.value.chars().count(), SUBAGENT_SUMMARY_MAX + 1);
        assert!(rec.value.ends_with('…'));

        store.close().await.expect("close");
    }

    /// Two sibling worktrees share one store (a clone with a remote resolves to
    /// one slug). A session ending in one worktree must settle only its own
    /// lockdown debt: its owed markers and consult receipts clear, the sibling's
    /// survive untouched. A store-wide wipe would lift the sibling's lockdown.
    #[tokio::test]
    async fn harvest_settles_only_the_ending_worktree_debt() {
        let (_dir, store) = temp_store().await;

        let ending = "aaaaaaaa";
        let sibling = "bbbbbbbb";

        // Each worktree owes an unconsulted deny and holds one consult receipt.
        record_owed_receipt(&store, "file:a.rs", Some(ending))
            .await
            .expect("owe ending");
        record_owed_receipt(&store, "file:b.rs", Some(sibling))
            .await
            .expect("owe sibling");
        for (actor, key) in [(ending, "file:a.rs"), (sibling, "file:b.rs")] {
            let rec = session_record(&receipt_key(key, Some(actor)), String::new());
            store.put(&rec.key, &rec).await.expect("put receipt");
        }

        // Harvest returns early without a session:current — mint one.
        session_flush(&store).await.expect("flush");

        let nowhere = TempDir::new().expect("tempdir");
        session_harvest(&store, nowhere.path(), Some(ending))
            .await
            .expect("harvest");

        let owed = store.scan_keys(OWED_PREFIX).await.expect("scan owed");
        assert!(
            owed.iter().all(|k| !k.contains(ending)),
            "ending worktree debt must clear: {owed:?}"
        );
        assert!(
            owed.iter().any(|k| k.contains(sibling)),
            "sibling worktree debt must survive: {owed:?}"
        );

        let consulted = store
            .scan_keys("session:consulted:")
            .await
            .expect("scan consulted");
        assert!(
            consulted.iter().all(|k| !k.contains(ending)),
            "ending worktree receipt must clear: {consulted:?}"
        );
        assert!(
            consulted.iter().any(|k| k.contains(sibling)),
            "sibling worktree receipt must survive: {consulted:?}"
        );

        store.close().await.expect("close");
    }

    #[tokio::test]
    async fn session_harvest_clears_subagent_summary() {
        let (_dir, store) = temp_store().await;

        write_subagent_summary(&store, "did a thing", None, None, None, None)
            .await
            .expect("write");
        assert!(store
            .get(SUBAGENT_SUMMARY_KEY)
            .await
            .expect("get")
            .is_some());

        // Harvest with no git repo — still runs the archive + cleanup path.
        let nowhere = TempDir::new().expect("tempdir");
        session_harvest(&store, nowhere.path(), None)
            .await
            .expect("harvest");

        assert!(
            store
                .get(SUBAGENT_SUMMARY_KEY)
                .await
                .expect("get")
                .is_none(),
            "harvest must clear the subagent summary"
        );

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

        session_harvest(&store, repo_dir.path(), None)
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

        log_hit(&store, key, None)
            .await
            .expect("log consultation hit");

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
        log_hit(&store, key, None).await.unwrap();

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
        log_hit(&store, key, None).await.unwrap();
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
        log_hit(&store, key, None).await.unwrap();
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

        log_hit(&store, key1, None).await.expect("log first hit");
        log_hit(&store, key2, None).await.expect("log second hit");

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

    // ── worktree_scope_tag ───────────────────────────────────────────────────

    fn run_git(dir: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .expect("run git");
        assert!(status.success(), "git {args:?} failed in {dir:?}");
    }

    /// A git repo with one commit, ready for `git worktree add`.
    fn temp_repo_for_worktrees() -> TempDir {
        let dir = TempDir::new().expect("tempdir");
        run_git(dir.path(), &["init", "-q"]);
        run_git(dir.path(), &["config", "user.email", "t@t.com"]);
        run_git(dir.path(), &["config", "user.name", "t"]);
        std::fs::write(dir.path().join("file.txt"), "hello").expect("write");
        run_git(dir.path(), &["add", "-A"]);
        run_git(dir.path(), &["commit", "-q", "-m", "init"]);
        dir
    }

    /// The debt scan matches a worktree tag with no terminator after it, so
    /// the tag must be fixed width or one tree's prefix could catch another's
    /// markers. `hex::encode` of four bytes is always eight characters.
    #[test]
    fn a_worktree_scope_tag_is_always_eight_hex_characters() {
        let main = temp_repo_for_worktrees();
        let tag = worktree_scope_tag(main.path()).expect("main tag");
        assert_eq!(tag.len(), 8, "tag width is what makes the debt scan exact");
        assert!(tag.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The common layout: `git worktree add ../feature`. The worktree's own
    /// `.git` is a pointer *file*, not a directory, and it has no real `.git`
    /// directory anywhere in its own ancestry (its sibling relationship to
    /// the main checkout means walking up never reaches one either).
    #[test]
    fn worktree_scope_tag_differs_for_sibling_worktrees() {
        let main = temp_repo_for_worktrees();
        let sibling_parent = TempDir::new().expect("tempdir");
        let wt_path = sibling_parent.path().join("wt");
        run_git(
            main.path(),
            &[
                "worktree",
                "add",
                wt_path.to_str().unwrap(),
                "-b",
                "wt-branch",
            ],
        );
        let main_tag = worktree_scope_tag(main.path()).expect("main tag");
        let wt_tag = worktree_scope_tag(&wt_path).expect("worktree tag");
        assert_ne!(
            main_tag, wt_tag,
            "a sibling worktree must not share the main checkout's scope"
        );
    }

    /// The exact bug case: a worktree nested INSIDE the main repo's directory
    /// tree (e.g. `.worktrees/<branch>`). A lexical `.git`-file check (as a
    /// naive walk-up would do) walks past the worktree's own `.git` pointer
    /// file and lands on the main repo's real `.git` directory, wrongly
    /// treating the nested worktree as if it were the main checkout.
    /// `git2::Repository::discover` must not make that mistake.
    #[test]
    fn worktree_scope_tag_differs_for_nested_worktree() {
        let main = temp_repo_for_worktrees();
        let nested = main.path().join(".worktrees").join("wt");
        run_git(
            main.path(),
            &[
                "worktree",
                "add",
                nested.to_str().unwrap(),
                "-b",
                "nested-branch",
            ],
        );
        let main_tag = worktree_scope_tag(main.path()).expect("main tag");
        let nested_tag = worktree_scope_tag(&nested).expect("nested tag");
        assert_ne!(
            main_tag, nested_tag,
            "a nested worktree must not share the main checkout's scope"
        );
    }

    #[test]
    fn worktree_scope_tag_is_stable_for_the_same_worktree() {
        let main = temp_repo_for_worktrees();
        let a = worktree_scope_tag(main.path());
        let b = worktree_scope_tag(main.path());
        assert!(a.is_some());
        assert_eq!(a, b);
    }

    #[test]
    fn worktree_scope_tag_is_none_outside_a_git_repo() {
        let dir = TempDir::new().expect("tempdir");
        assert_eq!(worktree_scope_tag(dir.path()), None);
    }

    #[test]
    fn combined_actor_scope_precedence() {
        assert_eq!(combined_actor_scope(None, None), None);
        assert_eq!(
            combined_actor_scope(Some("wtA"), None),
            Some("wtA".to_string())
        );
        assert_eq!(
            combined_actor_scope(None, Some("agent-a")),
            Some("agent-a".to_string())
        );
        assert_eq!(
            combined_actor_scope(Some("wtA"), Some("agent-a")),
            Some("wtA:agent-a".to_string())
        );
    }
}
