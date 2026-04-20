//! Enforcement event recording — the audit backbone.
//!
//! This module provides the canonical event envelope for all enforcement
//! decisions made by mati hooks. Events form a hash-chained, monotonically
//! sequenced, tamper-evident stream that can be exported for audit.
//!
//! # Invariants (FROZEN for schema_version 1)
//!
//! - The canonical hash contract (field order, serialization format, algorithm)
//!   must not change without incrementing [`SCHEMA_VERSION`].
//! - Sequence numbers are globally unique, monotonically increasing, and
//!   persisted before the event that uses them.
//! - The hash chain (`prev_hash`) links each event to its predecessor.
//!   Gaps in seq_no are acceptable (crash recovery) but hash chain breaks
//!   indicate tampering or corruption.

use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::db::Store;

// ─────────────────────────────────────────────
// Constants (FROZEN for v1)
// ─────────────────────────────────────────────

/// Schema version for the enforcement event envelope. Frozen at 1 for v1.
/// Increment only when fields are added or serialization changes.
/// Verifiers must reject events with unknown schema versions.
pub const SCHEMA_VERSION: u8 = 1;

/// Hash algorithm used for event_hash and prev_hash.
/// Frozen for v1. Do not change without incrementing SCHEMA_VERSION.
pub const HASH_ALGORITHM: &str = "sha256";

/// Store key for the global enforcement sequence counter.
const SEQ_KEY: &str = "enforcement:seq";

/// Store key for the installation identifier.
pub const INSTALLATION_ID_KEY: &str = "system:installation_id";

/// Store key prefix for enforcement event records.
pub const EVENT_PREFIX: &str = "enforcement:event:";

// ─────────────────────────────────────────────
// Event Envelope
// ─────────────────────────────────────────────

/// The canonical enforcement event envelope.
///
/// Every enforcement decision (deny, allow-after-receipt, bypass detection,
/// control changes) is recorded as one of these events. They form a
/// hash-chained, sequenced stream for tamper-evident audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementEvent {
    /// Globally unique event identifier. UUIDv7 (time-ordered).
    pub event_id: String,

    /// Schema version. Always SCHEMA_VERSION for v1.
    pub schema_version: u8,

    /// Global durable monotonic sequence number within this store.
    /// Allocated atomically. Never reused. Never gaps except after crash
    /// (which produces a RecordingGap event on recovery).
    pub seq_no: u64,

    /// Unix milliseconds UTC when this event was recorded.
    pub recorded_at_ms: u64,

    /// The type of event. Determines which optional fields are populated.
    pub event_type: EnforcementEventType,

    /// SHA-256 hash of this event's canonical serialization (see hash contract).
    /// Computed AFTER all other fields are set, stored as lowercase hex.
    pub event_hash: String,

    /// SHA-256 hash of the previous event in the stream. Empty string for
    /// the first event in the store. Forms a hash chain for tamper detection.
    pub prev_hash: String,

    /// Stable installation identifier. UUID generated once at first init,
    /// persisted in the store, never changes. NOT derived from hostname.
    pub installation_id: String,

    /// Local OS identity of the actor. Structured, explicitly labeled as
    /// unverified. None if identity cannot be determined.
    pub actor_local: Option<ActorLocal>,

    /// The AI agent type that triggered this event.
    pub agent_type: String,

    /// What kind of subject this event pertains to.
    pub subject_kind: SubjectKind,

    /// Canonical identifier of the subject. For files: the canonical file key
    /// (normalized, symlink-resolved, case-folded where applicable).
    /// For controls: the gotcha or config key.
    pub subject_key: String,

    /// Hash of the canonical file path for file-backed subjects. Allows
    /// cross-referencing even if paths are later renamed.
    pub canonical_subject_hash: Option<String>,

    /// Links events back to the receipt that authorized them.
    pub receipt_id: Option<String>,

    /// Stable enum string for the reason. NOT freeform prose.
    /// Examples: "gotcha_above_threshold", "receipt_valid", "receipt_expired",
    /// "daemon_unreachable", "control_created", "control_deleted"
    pub decision_reason_code: String,

    /// Hash of the gotcha/config state that was used to make this decision.
    /// Proves which rule text and thresholds were in force at decision time.
    pub decision_basis_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorLocal {
    /// OS username (e.g. "ioni")
    pub username: String,
    /// OS user ID where available (Unix uid). None on platforms without uid.
    pub uid: Option<u32>,
    /// Explicitly labeled as local and unverified.
    pub verified: bool, // always false in v1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    File,
    Control,
    Config,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EnforcementEventType {
    Deny,
    AllowAfterReceipt,
    ReceiptMinted,
    BypassDetected,
    ControlChanged {
        change_kind: ControlChangeKind,
    },
    EnforcementConfigChanged {
        setting: String,
        old_value: String,
        new_value: String,
    },
    RecordingGap {
        gap_start_ms: u64,
        gap_end_ms: u64,
        cause: GapCause,
        enforcement_mode_during_gap: EnforcementMode,
        missed_event_count: MissedEventCount,
        certainty: GapCertainty,
    },
    RetentionPruned {
        pruned_count: u64,
        oldest_pruned_seq: u64,
        newest_pruned_seq: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlChangeKind {
    Created,
    Confirmed,
    Updated,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapCause {
    DaemonUnreachable,
    StoreWriteFailure,
    StoreLocked,
    CorruptionRecovery,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Advisory,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissedEventCount {
    Known(u64),
    Zero,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapCertainty {
    Exact,
    Inferred,
}

// ─────────────────────────────────────────────
// Canonical Hash Contract (FROZEN for v1)
// ─────────────────────────────────────────────

/// Canonical serialization form — mirrors EnforcementEvent but excludes
/// `event_hash` (which is the output, not the input).
///
/// Field order is load-bearing: changing it changes the hash. This struct
/// exists solely to enforce a stable serialization order via serde's
/// derive(Serialize) which uses declaration order.
#[derive(Serialize)]
struct CanonicalEvent<'a> {
    event_id: &'a str,
    schema_version: u8,
    seq_no: u64,
    recorded_at_ms: u64,
    event_type: &'a EnforcementEventType,
    prev_hash: &'a str,
    installation_id: &'a str,
    actor_local: &'a Option<ActorLocal>,
    agent_type: &'a str,
    subject_kind: SubjectKind,
    subject_key: &'a str,
    canonical_subject_hash: Option<&'a str>,
    receipt_id: Option<&'a str>,
    decision_reason_code: &'a str,
    decision_basis_hash: Option<&'a str>,
}

impl EnforcementEvent {
    /// Compute the canonical hash of this event.
    ///
    /// The hash covers all fields EXCEPT `event_hash` itself.
    /// This function is frozen for schema_version 1 — do not modify
    /// without incrementing SCHEMA_VERSION.
    pub fn compute_hash(&self) -> String {
        let canonical = CanonicalEvent {
            event_id: &self.event_id,
            schema_version: self.schema_version,
            seq_no: self.seq_no,
            recorded_at_ms: self.recorded_at_ms,
            event_type: &self.event_type,
            prev_hash: &self.prev_hash,
            installation_id: &self.installation_id,
            actor_local: &self.actor_local,
            agent_type: &self.agent_type,
            subject_kind: self.subject_kind,
            subject_key: &self.subject_key,
            canonical_subject_hash: self.canonical_subject_hash.as_deref(),
            receipt_id: self.receipt_id.as_deref(),
            decision_reason_code: &self.decision_reason_code,
            decision_basis_hash: self.decision_basis_hash.as_deref(),
        };

        let json =
            serde_json::to_string(&canonical).expect("canonical serialization must not fail");

        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

// ─────────────────────────────────────────────
// Sequence Number Allocator
// ─────────────────────────────────────────────

/// Atomic sequence number allocator backed by the store.
///
/// Key: "enforcement:seq" — stores the current counter as a big-endian u64.
/// The counter is persisted before `next()` returns — if the store write
/// fails, the sequence number is not allocated.
pub struct SeqAllocator {
    current: u64,
}

impl SeqAllocator {
    /// Load the current sequence number from the store, or initialize to 0.
    pub async fn load(store: &Store) -> Self {
        let current = match store.get_raw_bytes(SEQ_KEY).await {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                u64::from_be_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
            }
            _ => 0,
        };
        Self { current }
    }

    /// Allocate the next sequence number and persist it durably.
    ///
    /// Returns the allocated seq_no. If the store write fails, the seq is
    /// NOT allocated and the caller gets an error.
    pub async fn next(&mut self, store: &Store) -> Result<u64> {
        self.current += 1;
        store.put_raw(SEQ_KEY, &self.current.to_be_bytes()).await?;
        Ok(self.current)
    }

    /// Return the current (last allocated) sequence number without incrementing.
    pub fn current(&self) -> u64 {
        self.current
    }
}

// ─────────────────────────────────────────────
// Installation ID
// ─────────────────────────────────────────────

/// Retrieve the installation_id from the store, or generate and persist one.
///
/// The installation_id is a UUIDv4 generated once at first init. It never
/// changes after that. NOT derived from hostname — stable across renames.
pub async fn get_or_create_installation_id(store: &Store) -> Result<String> {
    if let Ok(Some(bytes)) = store.get_raw_bytes(INSTALLATION_ID_KEY).await {
        if let Ok(id) = std::str::from_utf8(&bytes) {
            if !id.is_empty() {
                return Ok(id.to_string());
            }
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    store.put_raw(INSTALLATION_ID_KEY, id.as_bytes()).await?;
    Ok(id)
}

// ─────────────────────────────────────────────
// Actor Identity
// ─────────────────────────────────────────────

/// Get the local OS actor identity. Unverified — v1 trusts the local OS.
pub fn get_local_actor() -> Option<ActorLocal> {
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()?;

    #[cfg(unix)]
    let uid = Some(unsafe { libc::getuid() } as u32);
    #[cfg(not(unix))]
    let uid = None;

    Some(ActorLocal {
        username,
        uid,
        verified: false,
    })
}

// ─────────────────────────────────────────────
// Canonical File Identity
// ─────────────────────────────────────────────

/// Canonicalize a file path for use as a subject_key in enforcement events.
///
/// Rules (frozen for v1):
/// 1. Resolve relative paths against the repo root
/// 2. Normalize path separators to forward slash
/// 3. Remove `.` and `..` components
/// 4. Resolve symlinks where possible (fall back to normalized path if resolution fails)
/// 5. Strip the repo root prefix to produce a repo-relative path
/// 6. On case-insensitive filesystems (macOS default, Windows), lowercase the path
///
/// The output is a stable, canonical string that survives path aliasing.
///
/// # Known limitation (v1)
///
/// Case sensitivity is detected by platform default, not per-volume. Some
/// macOS volumes are case-sensitive and some Linux volumes (ecryptfs) are
/// case-insensitive. For v1, the platform default is acceptable.
pub fn canonicalize_file_key(path: &str, repo_root: &Path) -> String {
    // Step 1: Make absolute
    let abs_path = if Path::new(path).is_relative() {
        repo_root.join(path)
    } else {
        PathBuf::from(path)
    };

    // Step 2+3: Normalize components (remove `.` and `..`)
    let normalized = normalize_components(&abs_path);

    // Step 4: Try symlink resolution, fall back to normalized
    let resolved = std::fs::canonicalize(&normalized).unwrap_or(normalized);

    // Step 5: Strip repo root to get repo-relative path
    let repo_root_canonical =
        std::fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let relative = resolved
        .strip_prefix(&repo_root_canonical)
        .unwrap_or(&resolved);

    // Convert to forward-slash string
    let mut key = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/");

    // Step 6: Case-fold on case-insensitive platforms
    if is_case_insensitive() {
        key = key.to_lowercase();
    }

    key
}

/// Normalize path components without filesystem access.
/// Collapses `.` and `..` lexically.
fn normalize_components(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {} // skip "."
            Component::ParentDir => {
                // Pop last normal component; keep prefix/root
                if matches!(components.last(), Some(Component::Normal(_))) {
                    components.pop();
                } else {
                    components.push(component);
                }
            }
            _ => components.push(component),
        }
    }
    components.iter().collect()
}

/// Platform-default case sensitivity detection.
///
/// v1 simplification: macOS and Windows are case-insensitive,
/// Linux is case-sensitive. Per-volume detection deferred to v2.
fn is_case_insensitive() -> bool {
    cfg!(target_os = "macos") || cfg!(target_os = "windows")
}

/// Compute a SHA-256 hash of the canonical file key for cross-reference stability.
///
/// Allows correlating events even after file renames.
pub fn canonical_subject_hash(canonical_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_key.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ─────────────────────────────────────────────
// UUIDv7 generation
// ─────────────────────────────────────────────

/// Generate a UUIDv7 (time-ordered) string.
///
/// UUIDv7 encodes millisecond-precision Unix time in the high bits,
/// producing lexicographically sortable IDs that cluster temporally.
fn uuid7_string() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Current time as Unix milliseconds.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ─────────────────────────────────────────────
// Event Writer
// ─────────────────────────────────────────────

/// The enforcement event writer. Ties together sequence allocation,
/// hash chaining, and store persistence into a single write path.
///
/// One writer per store lifetime. Not Clone — the seq counter and
/// prev_hash chain are stateful.
pub struct EnforcementEventWriter {
    seq: SeqAllocator,
    installation_id: String,
    prev_hash: String,
}

impl EnforcementEventWriter {
    /// Initialize the writer from store state.
    ///
    /// Loads the current seq counter, installation_id, and the hash of
    /// the last event in the stream (for chain continuity).
    pub async fn new(store: &Store) -> Result<Self> {
        let seq = SeqAllocator::load(store).await;
        let installation_id = get_or_create_installation_id(store).await?;
        let prev_hash = Self::load_last_hash(store).await;

        Ok(Self {
            seq,
            installation_id,
            prev_hash,
        })
    }

    /// Load the hash of the most recent enforcement event.
    ///
    /// Scans for the highest seq_no enforcement event and returns its
    /// event_hash. Returns empty string if no events exist (first event).
    async fn load_last_hash(store: &Store) -> String {
        // The last event key is "enforcement:event:{seq_no}" with zero-padded seq.
        // Scan all event keys and find the highest.
        let keys = match store.scan_keys(EVENT_PREFIX).await {
            Ok(k) => k,
            Err(_) => return String::new(),
        };

        if keys.is_empty() {
            return String::new();
        }

        // Find the key with the highest seq_no
        let last_key = keys
            .iter()
            .max_by_key(|k| {
                k.strip_prefix(EVENT_PREFIX)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
            })
            .cloned();

        if let Some(key) = last_key {
            if let Ok(Some(bytes)) = store.get_raw_bytes(&key).await {
                if let Ok(event) = serde_json::from_slice::<EnforcementEvent>(&bytes) {
                    return event.event_hash;
                }
            }
        }

        String::new()
    }

    /// Write an enforcement event to the store.
    ///
    /// Allocates a seq_no (persisted before event write), computes the
    /// hash chain, and writes the event as JSON under `enforcement:event:{seq_no}`.
    ///
    /// Returns the written event (with computed hashes) or an error.
    #[allow(clippy::too_many_arguments)]
    pub async fn write(
        &mut self,
        store: &Store,
        event_type: EnforcementEventType,
        subject_kind: SubjectKind,
        subject_key: String,
        agent_type: String,
        receipt_id: Option<String>,
        decision_reason_code: String,
        decision_basis_hash: Option<String>,
    ) -> Result<EnforcementEvent> {
        let seq_no = self.seq.next(store).await?;

        let canonical_subject_hash_value = if subject_kind == SubjectKind::File {
            Some(canonical_subject_hash(&subject_key))
        } else {
            None
        };

        let mut event = EnforcementEvent {
            event_id: uuid7_string(),
            schema_version: SCHEMA_VERSION,
            seq_no,
            recorded_at_ms: now_ms(),
            event_type,
            event_hash: String::new(), // computed below
            prev_hash: self.prev_hash.clone(),
            installation_id: self.installation_id.clone(),
            actor_local: get_local_actor(),
            agent_type,
            subject_kind,
            subject_key,
            canonical_subject_hash: canonical_subject_hash_value,
            receipt_id,
            decision_reason_code,
            decision_basis_hash,
        };

        // Compute and set the event hash
        event.event_hash = event.compute_hash();

        // Write to store — zero-padded seq for lexicographic ordering
        let key = format!("{EVENT_PREFIX}{:020}", seq_no);
        let json = serde_json::to_vec(&event)?;
        store.put_raw(&key, &json).await?;

        // Update prev_hash for the next event in this writer's lifetime
        self.prev_hash = event.event_hash.clone();

        Ok(event)
    }

    /// Return the current installation ID.
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// Return the current sequence number (last allocated).
    pub fn current_seq(&self) -> u64 {
        self.seq.current()
    }

    /// Return the hash of the last written event.
    pub fn prev_hash(&self) -> &str {
        &self.prev_hash
    }

    /// Detect gaps in the event stream and emit a RecordingGap event.
    ///
    /// Called on writer initialization when the seq counter is ahead of
    /// the last stored event (indicating a crash between seq allocation
    /// and event write).
    pub async fn detect_and_record_gap(
        &mut self,
        store: &Store,
        gap_start_ms: u64,
        gap_end_ms: u64,
        cause: GapCause,
    ) -> Result<EnforcementEvent> {
        self.write(
            store,
            EnforcementEventType::RecordingGap {
                gap_start_ms,
                gap_end_ms,
                cause,
                enforcement_mode_during_gap: EnforcementMode::Advisory,
                missed_event_count: MissedEventCount::Unknown,
                certainty: GapCertainty::Inferred,
            },
            SubjectKind::System,
            "enforcement:stream".to_string(),
            "system".to_string(),
            None,
            "recording_gap_detected".to_string(),
            None,
        )
        .await
    }
}

// ─────────────────────────────────────────────
// Store scan helpers
// ─────────────────────────────────────────────

/// Read enforcement events within a seq_no range [since, until] inclusive.
///
/// Returns events in seq_no order. Events outside the range or with
/// corrupt JSON are skipped with a warning.
pub async fn scan_enforcement_events(
    store: &Store,
    since_seq: u64,
    until_seq: u64,
) -> Result<Vec<EnforcementEvent>> {
    let keys = store.scan_keys(EVENT_PREFIX).await?;
    let mut events = Vec::new();

    for key in &keys {
        let seq = match key
            .strip_prefix(EVENT_PREFIX)
            .and_then(|s| s.parse::<u64>().ok())
        {
            Some(s) => s,
            None => continue,
        };
        if seq < since_seq || seq > until_seq {
            continue;
        }
        if let Ok(Some(bytes)) = store.get_raw_bytes(key).await {
            match serde_json::from_slice::<EnforcementEvent>(&bytes) {
                Ok(event) => events.push(event),
                Err(e) => {
                    tracing::warn!(key, "skipping corrupt enforcement event: {e}");
                }
            }
        }
    }

    events.sort_by_key(|e| e.seq_no);
    Ok(events)
}

// ─────────────────────────────────────────────
// Enforcement Mode
// ─────────────────────────────────────────────

/// Store key for the enforcement mode setting.
const ENFORCEMENT_MODE_KEY: &str = "enforcement:mode";

/// Default retention period in days.
const DEFAULT_RETENTION_DAYS: u64 = 365;

/// Store key for the retention period setting.
const RETENTION_DAYS_KEY: &str = "enforcement:retention_days";

/// Read the current enforcement mode from the store.
/// Defaults to Advisory if not set or unreadable.
pub async fn get_enforcement_mode(store: &Store) -> EnforcementMode {
    match store.get_raw_bytes(ENFORCEMENT_MODE_KEY).await {
        Ok(Some(bytes)) => match std::str::from_utf8(&bytes) {
            Ok("strict") => EnforcementMode::Strict,
            _ => EnforcementMode::Advisory,
        },
        _ => EnforcementMode::Advisory,
    }
}

/// Persist the enforcement mode to the store. Returns the previous mode.
/// Records an EnforcementConfigChanged event when the mode actually changes.
pub async fn set_enforcement_mode(store: &Store, mode: EnforcementMode) -> Result<EnforcementMode> {
    let old = get_enforcement_mode(store).await;
    let value = match mode {
        EnforcementMode::Advisory => "advisory",
        EnforcementMode::Strict => "strict",
    };
    store
        .put_raw(ENFORCEMENT_MODE_KEY, value.as_bytes())
        .await?;

    // Record config change event if the mode actually changed
    if old != mode {
        let old_str = match old {
            EnforcementMode::Advisory => "advisory",
            EnforcementMode::Strict => "strict",
        };
        // Best-effort — don't fail the config change if event recording fails
        let _ = record_event(
            store,
            EnforcementEventType::EnforcementConfigChanged {
                setting: "enforcement.mode".to_string(),
                old_value: old_str.to_string(),
                new_value: value.to_string(),
            },
            SubjectKind::Config,
            "enforcement:mode".to_string(),
            "developer".to_string(),
            None,
            "config_changed".to_string(),
            None,
        )
        .await;
    }
    Ok(old)
}

/// Read the configured retention period in days.
pub async fn get_retention_days(store: &Store) -> u64 {
    match store.get_raw_bytes(RETENTION_DAYS_KEY).await {
        Ok(Some(bytes)) => std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_RETENTION_DAYS),
        _ => DEFAULT_RETENTION_DAYS,
    }
}

/// Persist the retention period.
pub async fn set_retention_days(store: &Store, days: u64) -> Result<()> {
    store
        .put_raw(RETENTION_DAYS_KEY, days.to_string().as_bytes())
        .await
}

// ─────────────────────────────────────────────
// Decision Basis Hash
// ─────────────────────────────────────────────

/// Compute a hash of the gotcha state used for an enforcement decision.
///
/// Each gotcha contributes its key, rule text, and confidence value to the
/// hash. This proves which exact rule state was in force at decision time.
pub fn compute_decision_basis_hash(gotchas: &[(String, serde_json::Value)]) -> String {
    let mut hasher = Sha256::new();
    for (key, record_json) in gotchas {
        hasher.update(key.as_bytes());
        let rule = record_json
            .pointer("/value")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        hasher.update(rule.as_bytes());
        let conf = record_json
            .pointer("/confidence/value")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        hasher.update(format!("{conf}").as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

// ─────────────────────────────────────────────
// Standalone Event Recording
// ─────────────────────────────────────────────

/// Record a single enforcement event without requiring a long-lived writer.
///
/// Creates a fresh writer on each call (loads seq + prev_hash from store).
/// Correct for hash chain continuity. Slightly slower than using a shared
/// writer (~2 extra reads), but avoids threading a writer through all paths.
///
/// Respects the enforcement mode: in advisory mode, write failures are
/// logged but Ok(None) is returned. In strict mode, write failures propagate.
#[allow(clippy::too_many_arguments)]
pub async fn record_event(
    store: &Store,
    event_type: EnforcementEventType,
    subject_kind: SubjectKind,
    subject_key: String,
    agent_type: String,
    receipt_id: Option<String>,
    decision_reason_code: String,
    decision_basis_hash: Option<String>,
) -> Result<Option<EnforcementEvent>> {
    let mode = get_enforcement_mode(store).await;

    let result = async {
        let mut writer = EnforcementEventWriter::new(store).await?;
        writer
            .write(
                store,
                event_type,
                subject_kind,
                subject_key,
                agent_type,
                receipt_id,
                decision_reason_code,
                decision_basis_hash,
            )
            .await
    }
    .await;

    match result {
        Ok(event) => Ok(Some(event)),
        Err(e) => match mode {
            EnforcementMode::Advisory => {
                tracing::warn!("enforcement event write failed (advisory mode): {e}");
                Ok(None)
            }
            EnforcementMode::Strict => Err(e),
        },
    }
}

// ─────────────────────────────────────────────
// Retention / Pruning
// ─────────────────────────────────────────────

/// Result of a retention enforcement run.
#[derive(Debug)]
pub enum PruneResult {
    NothingToPrune,
    Pruned {
        count: u64,
        oldest_seq: u64,
        newest_seq: u64,
    },
}

/// Prune enforcement events older than the configured retention period
/// and record a RetentionPruned event for the deletion.
///
/// Called during `mati init` and `mati repair --full`.
pub async fn enforce_retention(store: &Store) -> Result<PruneResult> {
    let retention_days = get_retention_days(store).await;
    let cutoff_ms = now_ms().saturating_sub(retention_days * 86_400_000);

    let all_events = scan_enforcement_events(store, 0, u64::MAX).await?;
    let old_events: Vec<&EnforcementEvent> = all_events
        .iter()
        .filter(|e| e.recorded_at_ms < cutoff_ms)
        .collect();

    if old_events.is_empty() {
        return Ok(PruneResult::NothingToPrune);
    }

    let count = old_events.len() as u64;
    let oldest_seq = old_events.first().unwrap().seq_no;
    let newest_seq = old_events.last().unwrap().seq_no;

    // Delete the old events
    for event in &old_events {
        let key = format!("{EVENT_PREFIX}{:020}", event.seq_no);
        store.delete(&key).await?;
    }

    // Record the prune as an event
    record_event(
        store,
        EnforcementEventType::RetentionPruned {
            pruned_count: count,
            oldest_pruned_seq: oldest_seq,
            newest_pruned_seq: newest_seq,
        },
        SubjectKind::System,
        "enforcement:retention".to_string(),
        "system".to_string(),
        None,
        "retention_policy_enforced".to_string(),
        None,
    )
    .await?;

    Ok(PruneResult::Pruned {
        count,
        oldest_seq,
        newest_seq,
    })
}

// ─────────────────────────────────────────────
// Gap Detection on Startup
// ─────────────────────────────────────────────

/// Check for and record gaps on writer startup.
///
/// If the store has events AND the last event's recorded_at_ms is older
/// than `gap_threshold_ms`, emit a RecordingGap event. Conservative:
/// may over-report gaps where the daemon was simply idle, but
/// under-reporting is worse for a compliance tool.
pub async fn detect_startup_gap(store: &Store, gap_threshold_ms: u64) -> Result<()> {
    let events = scan_enforcement_events(store, 0, u64::MAX).await?;
    if events.is_empty() {
        return Ok(());
    }
    let last = events.last().unwrap();
    let current = now_ms();
    let age = current.saturating_sub(last.recorded_at_ms);

    if age > gap_threshold_ms {
        let mut writer = EnforcementEventWriter::new(store).await?;
        writer
            .detect_and_record_gap(store, last.recorded_at_ms, current, GapCause::Unknown)
            .await?;
    }
    Ok(())
}

// ─────────────────────────────────────────────
// Scan helpers for CLI display
// ─────────────────────────────────────────────

/// Scan enforcement events within a time window.
pub async fn scan_events_since(store: &Store, since_ms: u64) -> Result<Vec<EnforcementEvent>> {
    let all = scan_enforcement_events(store, 0, u64::MAX).await?;
    Ok(all
        .into_iter()
        .filter(|e| e.recorded_at_ms >= since_ms)
        .collect())
}

/// Count enforcement events by type within a time window.
pub async fn count_events_by_type(store: &Store, since_ms: u64) -> Result<EnforcementEventCounts> {
    let events = scan_events_since(store, since_ms).await?;
    let mut counts = EnforcementEventCounts {
        total: events.len() as u64,
        ..Default::default()
    };
    for e in &events {
        match &e.event_type {
            EnforcementEventType::Deny => counts.denials += 1,
            EnforcementEventType::AllowAfterReceipt => counts.allowed_after_receipt += 1,
            EnforcementEventType::ReceiptMinted => counts.receipts_minted += 1,
            EnforcementEventType::BypassDetected => counts.bypasses += 1,
            EnforcementEventType::ControlChanged { .. } => counts.controls_changed += 1,
            EnforcementEventType::EnforcementConfigChanged { .. } => counts.config_changes += 1,
            EnforcementEventType::RecordingGap { .. } => counts.gaps += 1,
            EnforcementEventType::RetentionPruned { .. } => counts.retention_prunes += 1,
        }
    }
    Ok(counts)
}

/// Aggregated event counts for CLI display.
#[derive(Debug, Default)]
pub struct EnforcementEventCounts {
    pub total: u64,
    pub denials: u64,
    pub allowed_after_receipt: u64,
    pub receipts_minted: u64,
    pub bypasses: u64,
    pub controls_changed: u64,
    pub config_changes: u64,
    pub gaps: u64,
    pub retention_prunes: u64,
}

/// Format an event type as a short display string.
pub fn event_type_label(event_type: &EnforcementEventType) -> &'static str {
    match event_type {
        EnforcementEventType::Deny => "deny",
        EnforcementEventType::AllowAfterReceipt => "allow_receipt",
        EnforcementEventType::ReceiptMinted => "receipt_minted",
        EnforcementEventType::BypassDetected => "bypass",
        EnforcementEventType::ControlChanged { .. } => "control_changed",
        EnforcementEventType::EnforcementConfigChanged { .. } => "config_changed",
        EnforcementEventType::RecordingGap { .. } => "gap",
        EnforcementEventType::RetentionPruned { .. } => "retention_pruned",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct a deterministic event for hash testing.
    fn frozen_test_event() -> EnforcementEvent {
        EnforcementEvent {
            event_id: "01900000-0000-7000-8000-000000000001".to_string(),
            schema_version: 1,
            seq_no: 1,
            recorded_at_ms: 1700000000000,
            event_type: EnforcementEventType::Deny,
            event_hash: String::new(),
            prev_hash: String::new(),
            installation_id: "test-install-id".to_string(),
            actor_local: Some(ActorLocal {
                username: "testuser".to_string(),
                uid: Some(1000),
                verified: false,
            }),
            agent_type: "claude".to_string(),
            subject_kind: SubjectKind::File,
            subject_key: "file:src/billing/charges.rs".to_string(),
            canonical_subject_hash: Some("abc123".to_string()),
            receipt_id: None,
            decision_reason_code: "gotcha_above_threshold".to_string(),
            decision_basis_hash: Some("def456".to_string()),
        }
    }

    #[test]
    fn canonical_hash_is_deterministic_and_frozen() {
        let event = frozen_test_event();
        let hash = event.compute_hash();

        // This hash is frozen. If this test fails, either the canonical
        // serialization changed (which breaks all existing hash chains)
        // or the hash algorithm changed. Neither is acceptable without
        // incrementing SCHEMA_VERSION.
        assert_eq!(
            hash,
            "e8a42cb3c1c4dde12f807f46678c5d4393466a831007540a85ff84a003203e37"
        );

        // Verify determinism — same input always produces same hash.
        assert_eq!(hash, event.compute_hash());
        assert_eq!(hash, event.compute_hash());
    }

    #[test]
    fn hash_changes_when_field_changes() {
        let mut event = frozen_test_event();
        let hash1 = event.compute_hash();

        event.seq_no = 2;
        let hash2 = event.compute_hash();

        assert_ne!(hash1, hash2, "changing seq_no must change the hash");
    }

    #[test]
    fn hash_excludes_event_hash_field() {
        let mut event = frozen_test_event();
        let hash1 = event.compute_hash();

        // Setting event_hash should not affect compute_hash output
        event.event_hash = "something_completely_different".to_string();
        let hash2 = event.compute_hash();

        assert_eq!(
            hash1, hash2,
            "event_hash field must be excluded from canonical form"
        );
    }

    #[test]
    fn canonical_path_aliasing_produces_same_key() {
        let repo_root = PathBuf::from("/tmp/test-repo");

        // These should all produce the same canonical key (lexical normalization)
        let paths = [
            "src/billing/charges.rs",
            "./src/billing/charges.rs",
            "src/billing/../billing/charges.rs",
            "src/./billing/charges.rs",
        ];

        // Use normalize_components only (no fs access in test)
        let canonical_keys: Vec<String> = paths
            .iter()
            .map(|p| {
                let abs = repo_root.join(p);
                let normalized = normalize_components(&abs);
                let relative = normalized
                    .strip_prefix(&repo_root)
                    .unwrap_or(&normalized)
                    .to_string_lossy()
                    .replace('\\', "/");
                if is_case_insensitive() {
                    relative.to_lowercase()
                } else {
                    relative
                }
            })
            .collect();

        for key in &canonical_keys {
            assert_eq!(
                key, &canonical_keys[0],
                "Path aliasing produced different keys"
            );
        }

        assert_eq!(canonical_keys[0], "src/billing/charges.rs");
    }

    #[test]
    fn canonical_subject_hash_is_deterministic() {
        let hash1 = canonical_subject_hash("src/billing/charges.rs");
        let hash2 = canonical_subject_hash("src/billing/charges.rs");
        assert_eq!(hash1, hash2);

        let hash3 = canonical_subject_hash("src/billing/other.rs");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn schema_version_is_one() {
        assert_eq!(SCHEMA_VERSION, 1);
        assert_eq!(HASH_ALGORITHM, "sha256");
    }
}
