use super::*;

// ─────────────────────────────────────────────
// Constants (FROZEN for v1)
// ─────────────────────────────────────────────

/// Schema version for the enforcement event envelope. v2 adds `agent_session`,
/// appended to the canonical form and hashed only for v2+ events; v1 events keep
/// their original 14-field canonical layout and hashes (see `compute_hash`).
/// Increment only when fields are added or serialization changes.
/// Verifiers must reject events with unknown schema versions.
pub const SCHEMA_VERSION: u8 = 2;

/// Hash algorithm used for event_hash and prev_hash.
/// Frozen for v1. Do not change without incrementing SCHEMA_VERSION.
pub const HASH_ALGORITHM: &str = "sha256";

/// Store key for the global enforcement sequence counter.
pub(crate) const SEQ_KEY: &str = "enforcement:seq";

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

    /// Links events back to the receipt that authorized them: the
    /// `ConsultationReceipt::id` minted by `mem_get` / the consult hook.
    /// `ReceiptMinted` carries the id it just minted; `AllowAfterReceipt`
    /// carries the id of the receipt that satisfied the gate. `None` on denies
    /// (no receipt existed) and on receipts minted before ids existed.
    pub receipt_id: Option<String>,

    /// Stable enum string for the reason. NOT freeform prose.
    /// Examples: "gotcha_above_threshold", "receipt_valid", "receipt_expired",
    /// "daemon_unreachable", "control_created", "control_deleted"
    pub decision_reason_code: String,

    /// Hash of the gotcha/config state that was used to make this decision.
    /// Proves which rule text and thresholds were in force at decision time.
    pub decision_basis_hash: Option<String>,

    /// The AI agent SESSION that triggered this event (Claude Code `session_id`).
    /// Enables per-actor audit attribution — proving the same session that
    /// consulted a file also acted on it. `None` for events with no session
    /// (Codex, config changes, gaps). Added in schema_version 2; hashed only for
    /// v2+ events (see `compute_hash`).
    pub agent_session: Option<String>,
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
    /// The daemon exited gracefully. Written after in-flight handlers drain and
    /// before the store closes, so it is the last event of its run. Its ABSENCE
    /// at the tail is the crash signal (section 18.2) — which is why no other
    /// process may write one on a dead daemon's behalf.
    ///
    /// `reason` is the shutdown reason `run_daemon_start` already names:
    /// `signal_sigterm`, `signal_sigint`, `signal_sighup`, `idle_timeout`,
    /// `serve_loop_exit`.
    CleanShutdown {
        reason: String,
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
    /// The previous run ended without a `CleanShutdown` terminator in a log
    /// that has one elsewhere. Claimable only once the log is known to come
    /// from a writer that emits them; otherwise the cause is [`Self::Unknown`].
    UncleanShutdown,
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

/// schema_version 2 canonical form: the v1 fields followed by `agent_session`,
/// appended at the END so v1 events (serialized via `CanonicalEvent`) keep a
/// byte-identical canonical form and their original hashes.
#[derive(Serialize)]
struct CanonicalEventV2<'a> {
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
    agent_session: Option<&'a str>,
}

impl EnforcementEvent {
    /// Compute the canonical hash of this event.
    ///
    /// The hash covers all fields EXCEPT `event_hash` itself.
    /// This function is frozen for schema_version 1 — do not modify
    /// without incrementing SCHEMA_VERSION.
    pub fn compute_hash(&self) -> String {
        // schema_version 1 hashes the original 14-field canonical form; v2+ hashes
        // the 15-field form with `agent_session` appended. Branching here keeps
        // every pre-existing v1 event's hash byte-identical (no false tamper).
        let json = if self.schema_version >= 2 {
            let canonical = CanonicalEventV2 {
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
                agent_session: self.agent_session.as_deref(),
            };
            serde_json::to_string(&canonical).expect("canonical serialization must not fail")
        } else {
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
            serde_json::to_string(&canonical).expect("canonical serialization must not fail")
        };

        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

// ─────────────────────────────────────────────
// Chain Verification (read-side integrity check)
// ─────────────────────────────────────────────

/// The kind of integrity failure a [`ChainBreak`] records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainBreakKind {
    /// `prev_hash` does not match the predecessor's `event_hash`. Caused by a
    /// deleted/inserted/re-pointed event — or, most commonly on a busy store, a
    /// concurrent write that captured the same `prev_hash` (distinguishable by a
    /// near-zero gap between the break and its predecessor; see [`ChainBreak`]).
    Linkage,
    /// The stored `event_hash` does not match a fresh `compute_hash()` — the
    /// event body was altered after recording.
    Tampered,
    /// This binary cannot verify the event: either its `schema_version` is
    /// newer than it understands, or its stored JSON did not deserialize at all
    /// and the scan reported the seq as skipped. Not evidence of tampering — an
    /// event a newer writer produced reads this way on an older reader.
    UnknownSchema,
}

/// A single integrity failure located in the chain, with enough context to
/// characterize it. For a `Linkage` break, a near-zero delta between
/// `recorded_at_ms` and `prev_recorded_at_ms` indicates a concurrent write
/// rather than tampering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainBreak {
    pub kind: ChainBreakKind,
    /// Seq number of the offending event.
    pub seq_no: u64,
    pub recorded_at_ms: u64,
    pub event_type: String,
    /// Predecessor context — populated for `Linkage` breaks only.
    pub prev_seq_no: Option<u64>,
    pub prev_recorded_at_ms: Option<u64>,
    pub prev_event_type: Option<String>,
}

/// Result of verifying the integrity of an enforcement event chain.
///
/// Verification is a READ-SIDE check over already-recorded events: it never
/// mutates the store and performs no network I/O. It is the inverse of the
/// write-time hash contract — it recomputes each event's hash AND re-checks the
/// `prev_hash` linkage, so it detects both:
///
/// - **content tampering** — an event whose body was altered after recording
///   while its stored `event_hash` was left untouched (a linkage-only check
///   misses this, because the stored hashes still chain together); and
/// - **linkage breaks** — a deleted, inserted, or re-pointed event, where one
///   event's `prev_hash` no longer matches its predecessor's `event_hash`.
///
/// A full from-genesis rewrite (every hash recomputed consistently) is *not*
/// detectable here by design — that is the inherent limit of a local,
/// externally-unanchored chain, and is addressed at the custody layer, not here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainVerification {
    /// Events whose hash was recomputed and compared (excludes unknown-schema).
    pub checked: usize,
    /// Events whose stored `event_hash` does not match a fresh `compute_hash()`
    /// — i.e. the content was altered after recording.
    pub tampered_events: usize,
    /// Adjacent events where `prev_hash` does not match the predecessor's
    /// `event_hash`. The earliest surviving event is never counted, so a
    /// legitimately retention-pruned prefix is not a break.
    pub linkage_breaks: usize,
    /// Events this binary cannot verify: a `schema_version` newer than it
    /// understands, or a seq_no the scan reported as unread (anywhere in the
    /// range, not only where it sits between two present events).
    /// Reported, not verified — and never counted as tampering.
    pub unknown_schema: usize,
    /// Every located break, in seq order. Empty when the chain is intact.
    pub breaks: Vec<ChainBreak>,
}

impl ChainVerification {
    /// True only when the chain is fully intact and fully verifiable: no content
    /// tampering, no linkage breaks, and no events this binary cannot verify.
    pub fn is_valid(&self) -> bool {
        self.tampered_events == 0 && self.linkage_breaks == 0 && self.unknown_schema == 0
    }
}

/// Verify the integrity of a set of enforcement events.
///
/// `events` may be in any order — they are sorted by `seq_no` for the linkage
/// check. The linkage check compares only *consecutive present* events, so a
/// pruned prefix (the earliest surviving event's dangling `prev_hash`) is not
/// reported as a break.
///
/// Pure: no store access, no network, no mutation. A single shared primitive so
/// every consumer verifies against one source of truth for the frozen hash
/// contract.
pub fn verify_chain(events: &[EnforcementEvent]) -> ChainVerification {
    verify_chain_with_skips(events, &[])
}

/// [`verify_chain`], told which seq numbers the scan could not read.
///
/// A skipped event is missing from `events`, so its successor's `prev_hash`
/// matches nothing present. That is byte-for-byte the signature of a deleted
/// event, and only the scan knows the difference: it saw the key and failed to
/// read it. Gaps explained by `skipped_seqs` are reported as `UnknownSchema`,
/// not `Linkage`, so version skew does not read as tampering in a signed audit.
///
/// Every seq in `skipped_seqs` surfaces as a break, whether or not it sits
/// between two present events — one before the first present event, after the
/// last, or with nothing present at all still counts toward `unknown_schema`,
/// so a chain this binary could not fully read is never reported valid.
pub fn verify_chain_with_skips(
    events: &[EnforcementEvent],
    skipped_seqs: &[u64],
) -> ChainVerification {
    let mut sorted: Vec<&EnforcementEvent> = events.iter().collect();
    sorted.sort_by_key(|e| e.seq_no);

    let mut result = ChainVerification::default();

    // A skip strictly between the lowest and highest present seq_no is
    // "explained" below when its bracketing pair's linkage is checked. One
    // before the first present event, after the last, or with no present
    // event at all has no pair to attach to — it must still surface, anchored
    // on its own seq_no since there is no successor to blame it on. The event
    // itself was never read, so `recorded_at_ms`/`event_type` are placeholders.
    let first_present = sorted.first().map(|e| e.seq_no);
    let last_present = sorted.last().map(|e| e.seq_no);
    for &seq in skipped_seqs {
        let bracketed =
            matches!((first_present, last_present), (Some(f), Some(l)) if f <= seq && seq <= l);
        if !bracketed {
            result.unknown_schema += 1;
            result.breaks.push(ChainBreak {
                kind: ChainBreakKind::UnknownSchema,
                seq_no: seq,
                recorded_at_ms: 0,
                event_type: "unreadable".to_string(),
                prev_seq_no: None,
                prev_recorded_at_ms: None,
                prev_event_type: None,
            });
        }
    }

    let mut prev: Option<&EnforcementEvent> = None;

    for e in sorted {
        // Linkage uses the stored hashes, so it is schema-independent.
        if let Some(p) = prev {
            if e.prev_hash != p.event_hash {
                let explained_by_skip = skipped_seqs.iter().any(|s| *s > p.seq_no && *s < e.seq_no);
                let kind = if explained_by_skip {
                    result.unknown_schema += 1;
                    ChainBreakKind::UnknownSchema
                } else {
                    result.linkage_breaks += 1;
                    ChainBreakKind::Linkage
                };
                result.breaks.push(ChainBreak {
                    kind,
                    seq_no: e.seq_no,
                    recorded_at_ms: e.recorded_at_ms,
                    event_type: event_type_label(&e.event_type).to_string(),
                    prev_seq_no: Some(p.seq_no),
                    prev_recorded_at_ms: Some(p.recorded_at_ms),
                    prev_event_type: Some(event_type_label(&p.event_type).to_string()),
                });
            }
        }

        // Content integrity: only events whose schema this binary can
        // canonicalize are recomputed; newer schemas are reported as unknown.
        if e.schema_version > SCHEMA_VERSION {
            result.unknown_schema += 1;
            result.breaks.push(ChainBreak {
                kind: ChainBreakKind::UnknownSchema,
                seq_no: e.seq_no,
                recorded_at_ms: e.recorded_at_ms,
                event_type: event_type_label(&e.event_type).to_string(),
                prev_seq_no: None,
                prev_recorded_at_ms: None,
                prev_event_type: None,
            });
        } else {
            result.checked += 1;
            if e.event_hash != e.compute_hash() {
                result.tampered_events += 1;
                result.breaks.push(ChainBreak {
                    kind: ChainBreakKind::Tampered,
                    seq_no: e.seq_no,
                    recorded_at_ms: e.recorded_at_ms,
                    event_type: event_type_label(&e.event_type).to_string(),
                    prev_seq_no: None,
                    prev_recorded_at_ms: None,
                    prev_event_type: None,
                });
            }
        }

        prev = Some(e);
    }

    // Breaks are pushed in two passes (unbracketed skips, then the linkage
    // scan), so the combined vec needs a final sort to keep the "in seq
    // order" contract in `ChainVerification::breaks`'s doc comment.
    result.breaks.sort_by_key(|b| b.seq_no);
    result
}
