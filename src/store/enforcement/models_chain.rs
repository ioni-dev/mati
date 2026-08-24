use super::*;

// ─────────────────────────────────────────────
// Constants (FROZEN for v1)
// ─────────────────────────────────────────────

/// Schema version for the enforcement event envelope. v2 appends `agent_session`
/// (the spawning session); v3 appends `agent_id` (the subagent actor, for
/// one-level agent lineage); v4 appends `parent_agent_id` (the spawner of that
/// subagent, for nested agent→agent lineage). Each version appends its new field
/// at the END of the canonical form and is hashed only for events at that version
/// or newer, so v1 events keep their original 14-field layout and hashes, v2
/// events keep their 15-field layout, and v3 events keep their 16-field layout
/// (see `compute_hash`). Increment only when fields are added or serialization
/// changes. A NEW EVENT TYPE does not bump this: `event_type` is one opaque hashed
/// field, so a new `EnforcementEventType` variant changes no layout (section 24).
/// An older binary cannot deserialize the new tag and reports the event as
/// `UnknownSchema` — bumping instead would make it reject EVERY newer event, so
/// the no-bump path preserves the most downgrade-compatibility. Verifiers must
/// reject events with unknown schema versions.
pub const SCHEMA_VERSION: u8 = 4;

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

    /// The subagent ACTOR that triggered this event (Claude Code Task `agent_id`).
    /// Set only when a subagent's tool call drove the event, carried by the
    /// `post-memget` hook payload. `None` on the main thread and on paths with no
    /// subagent id (direct-mode CLI, plain MCP `mem_get`). Together with
    /// `agent_session` (the spawning session) this records one-level agent
    /// lineage — which subagent acted, under which session — the question an
    /// enterprise audit asks. Added in schema_version 3; hashed only for v3+
    /// events (see `compute_hash`).
    pub agent_id: Option<String>,

    /// The agent that SPAWNED the subagent in `agent_id` (Claude Code Task
    /// `agent_id` of the parent). `None` when the parent is the root session —
    /// i.e. one-level lineage, where `agent_session` already identifies the
    /// spawner. Set only for nested spawns (a subagent spawning another
    /// subagent), carried by the `Agent`-tool `PostToolUse` hook payload
    /// (top-level `agent_id` = spawner, `tool_response.agentId` = the child in
    /// `agent_id` here). Together with `agent_session` and `agent_id` this walks
    /// the full spawn tree, not just the leaf. Added in schema_version 4; hashed
    /// only for v4+ events (see `compute_hash`).
    pub parent_agent_id: Option<String>,
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
    /// A subagent was spawned (Claude Code `SubagentStart`). Records the
    /// subagent's PRESENCE independent of any consult, so the audit can attribute
    /// and score a subagent that spawned and then did nothing. `agent_session` is
    /// the spawning session and `agent_id` the subagent, giving the same one-level
    /// lineage pair as a consult. `subject_key` is the agent_id; `subject_kind` is
    /// `System`. A new event type, not a new field — no SCHEMA_VERSION bump; it
    /// rides the existing v3 canonical form. Recorded best-effort from the
    /// SubagentStart hook.
    SubagentSpawned,
    /// A subagent spawned another subagent — the nested (agent→agent) spawn edge.
    /// Captured at the child's completion from the Claude Code `Agent`-tool
    /// `PostToolUse` payload, whose top-level `agent_id` is the spawner and whose
    /// `tool_response.agentId` is the child. `subject_key` is the child agent_id,
    /// `subject_kind` is `System`; `agent_id` is the child and `parent_agent_id`
    /// the spawner, so the pair walks the tree past the leaf. Emitted ONLY when
    /// the spawner is itself a subagent — a root-session spawn is already recorded
    /// by `SubagentSpawned` and by every child event's `agent_session`, so this
    /// event is purely additive. A new event TYPE, not a new field — it needed no
    /// bump of its own; the `parent_agent_id` it carries is hashed by the v4
    /// canonical form (see `SCHEMA_VERSION`). Recorded best-effort.
    SubagentEdge,
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

/// schema_version 3 canonical form: the v2 fields followed by `agent_id`,
/// appended at the END so v2 events (serialized via `CanonicalEventV2`) keep a
/// byte-identical canonical form and their original hashes.
#[derive(Serialize)]
struct CanonicalEventV3<'a> {
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
    agent_id: Option<&'a str>,
}

/// schema_version 4 canonical form: the v3 fields followed by `parent_agent_id`,
/// appended at the END so v3 events (serialized via `CanonicalEventV3`) keep a
/// byte-identical canonical form and their original hashes.
#[derive(Serialize)]
struct CanonicalEventV4<'a> {
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
    agent_id: Option<&'a str>,
    parent_agent_id: Option<&'a str>,
}

impl EnforcementEvent {
    /// Compute the canonical hash of this event.
    ///
    /// The hash covers all fields EXCEPT `event_hash` itself.
    /// This function is frozen for schema_version 1 — do not modify
    /// without incrementing SCHEMA_VERSION.
    pub fn compute_hash(&self) -> String {
        // schema_version 1 hashes the original 14-field canonical form; v2 the
        // 15-field form with `agent_session` appended; v3 the 16-field form with
        // `agent_id` appended too; v4+ the 17-field form with `parent_agent_id`
        // appended. Each branch keeps every pre-existing event's hash
        // byte-identical at its own version (no false tamper). Newer schemas
        // never reach here — `verify_chain` short-circuits `schema_version >
        // SCHEMA_VERSION` to UnknownSchema, and the writer only stamps
        // SCHEMA_VERSION — so the `>= 4` arm serializes exactly the v4 layout.
        // A new event TYPE (e.g. SubagentSpawned, SubagentEdge) rides the current
        // arm: just another `event_type` value, no field or layout change.
        let json = if self.schema_version >= 4 {
            let canonical = CanonicalEventV4 {
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
                agent_id: self.agent_id.as_deref(),
                parent_agent_id: self.parent_agent_id.as_deref(),
            };
            serde_json::to_string(&canonical).expect("canonical serialization must not fail")
        } else if self.schema_version == 3 {
            let canonical = CanonicalEventV3 {
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
                agent_id: self.agent_id.as_deref(),
            };
            serde_json::to_string(&canonical).expect("canonical serialization must not fail")
        } else if self.schema_version == 2 {
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
    /// understands, or a seq_no the scan reported as unread. Every unread seq
    /// counts once, wherever it sits — a run of N skips in one gap is N, not one.
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
/// Every seq in `skipped_seqs` surfaces as its own break and counts once toward
/// `unknown_schema`, wherever it sits — before the first present event, after
/// the last, none present at all, or several inside one gap between two present
/// events. A linkage mismatch is suppressed only when *every* seq missing from
/// its gap is a skip; if a non-skipped seq is also missing, an event was
/// deleted, and that reports as a `Linkage` break even though a skip shares the
/// gap. So a chain this binary could not fully read is never reported valid, the
/// count reflects how many events it missed, and a deletion hiding behind a skip
/// still surfaces as tampering.
pub fn verify_chain_with_skips(
    events: &[EnforcementEvent],
    skipped_seqs: &[u64],
) -> ChainVerification {
    let mut sorted: Vec<&EnforcementEvent> = events.iter().collect();
    sorted.sort_by_key(|e| e.seq_no);

    let mut result = ChainVerification::default();

    // Every skipped seq is an event this binary could not read; surface each on
    // its own seq_no and count it once. A gap of N unread events is N unknown,
    // not one — counting per bracketing pair would fold a run of skips into a
    // single tally. The bracketing linkage mismatch a skip creates is left to
    // the loop below, which suppresses the duplicate break for any gap a skip
    // already explains. The event itself was never read, so `recorded_at_ms`/
    // `event_type` are placeholders.
    for &seq in skipped_seqs {
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

    let mut prev: Option<&EnforcementEvent> = None;

    for e in sorted {
        // Linkage uses the stored hashes, so it is schema-independent.
        if let Some(p) = prev {
            if e.prev_hash != p.event_hash {
                // seq_no is allocated +1 (SeqAllocator::next), so the events
                // missing from this gap are exactly `gap_start..e.seq_no`. The
                // gap is fully explained only when every one of them is a skip
                // — each was surfaced and counted as an UnknownSchema break on
                // its own seq above, so suppress the duplicate here. If any
                // missing seq is not a skip, an event was deleted: a real
                // linkage break, even when another skip shares the gap.
                let gap_start = p.seq_no + 1;
                let explained_by_skip = gap_start < e.seq_no
                    && (gap_start..e.seq_no).all(|s| skipped_seqs.contains(&s));
                if !explained_by_skip {
                    result.linkage_breaks += 1;
                    result.breaks.push(ChainBreak {
                        kind: ChainBreakKind::Linkage,
                        seq_no: e.seq_no,
                        recorded_at_ms: e.recorded_at_ms,
                        event_type: event_type_label(&e.event_type).to_string(),
                        prev_seq_no: Some(p.seq_no),
                        prev_recorded_at_ms: Some(p.recorded_at_ms),
                        prev_event_type: Some(event_type_label(&p.event_type).to_string()),
                    });
                }
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
