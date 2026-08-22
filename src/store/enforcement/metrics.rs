use super::*;

/// Count *consultations* — not `ReceiptMinted` events.
///
/// # Why the raw count is wrong
///
/// `ReceiptMinted` has three emitters and they are not mutually exclusive:
///
/// - `mcp::handlers::handle_mem_get` — every MCP `mem_get`, never
///   session-attributed.
/// - `Command::ConsultationHit` (`mcp::dispatch_v2`) — the `post-memget.sh`
///   PostToolUse hook, and `mati explain` / `mati diff` over the daemon socket.
///   The only emitter that can carry an `agent_session`.
/// - `store::session::log_hit` — direct-mode CLI, gotcha confirm, legacy socket.
///
/// On a fully-installed Claude Code setup the first two both fire for a single
/// `mem_get`, so the raw count is twice the number of consultations. All three
/// are wanted in the *log* (each is the only record when the others' path is
/// absent) — the correction belongs in the metric, and it has to be at read
/// time because the log is append-only and existing stores already hold the
/// duplicates.
///
/// # Identity
///
/// One consultation is `(subject_key, run of receipts starting at the first
/// event of that run and extending at most [`CONSULTATION_COALESCE_MS`])`.
/// Nothing sharper is available. `receipt_id` does not help: each emitter mints
/// its OWN receipt for the same consultation, so the two reports of one action
/// carry two different ids. `agent_session` is set on only some events from only
/// one emitter, so grouping by it would keep the duplicate rather than remove it.
///
/// The run is anchored to its first event, not chained to the previous one: a
/// steady drip of receipts under the window would otherwise collapse into one
/// unbounded "consultation".
///
/// # Failure modes
///
/// Over-counts when the two reporters of one action are further apart than the
/// window (a cold daemon start slow enough to push the hook past 2s — beyond
/// that Claude Code kills the hook and there is only one event anyway), and
/// when a genuine burst on one subject spans more than the window, which splits
/// it at the anchor boundary.
///
/// Under-counts when two *different* consultations of the same subject land
/// inside the window — a retry, or a subagent and the main thread consulting
/// the same file at once. Splitting those apart needs a per-consultation id on
/// the event, which is a schema change.
pub fn count_consultations(events: &[EnforcementEvent]) -> u64 {
    let mut by_subject: HashMap<&str, Vec<u64>> = HashMap::new();
    for e in events {
        if matches!(e.event_type, EnforcementEventType::ReceiptMinted) {
            by_subject
                .entry(e.subject_key.as_str())
                .or_default()
                .push(e.recorded_at_ms);
        }
    }

    let mut consultations = 0u64;
    for times in by_subject.values_mut() {
        times.sort_unstable();
        let mut anchor: Option<u64> = None;
        for &t in times.iter() {
            let coalesces =
                matches!(anchor, Some(a) if t.saturating_sub(a) <= CONSULTATION_COALESCE_MS);
            if !coalesces {
                anchor = Some(t);
                consultations += 1;
            }
        }
    }
    consultations
}

/// Aggregate a slice of events into typed counts.
///
/// Pure (no store / no I/O) so the aggregation — including the `ControlChanged`
/// lifecycle breakdown — is unit-testable from hand-built events.
pub fn aggregate_event_counts(events: &[EnforcementEvent]) -> EnforcementEventCounts {
    let mut counts = EnforcementEventCounts {
        total: events.len() as u64,
        consultations: count_consultations(events),
        ..Default::default()
    };
    for e in events {
        match &e.event_type {
            EnforcementEventType::Deny => counts.denials += 1,
            EnforcementEventType::AllowAfterReceipt => counts.allowed_after_receipt += 1,
            EnforcementEventType::ReceiptMinted => counts.receipts_minted += 1,
            EnforcementEventType::BypassDetected => counts.bypasses += 1,
            EnforcementEventType::ControlChanged { change_kind } => {
                counts.controls_changed += 1;
                match change_kind {
                    ControlChangeKind::Created => counts.controls_created += 1,
                    ControlChangeKind::Confirmed => counts.controls_confirmed += 1,
                    ControlChangeKind::Updated => counts.controls_updated += 1,
                    ControlChangeKind::Deleted => counts.controls_removed += 1,
                }
            }
            EnforcementEventType::EnforcementConfigChanged { .. } => counts.config_changes += 1,
            EnforcementEventType::RecordingGap { .. } => counts.gaps += 1,
            EnforcementEventType::RetentionPruned { .. } => counts.retention_prunes += 1,
            EnforcementEventType::CleanShutdown { .. } => counts.clean_shutdowns += 1,
            EnforcementEventType::SubagentSpawned => counts.subagent_spawns += 1,
        }
    }
    counts
}

/// Aggregated event counts for CLI display.
#[derive(Debug, Default)]
pub struct EnforcementEventCounts {
    pub total: u64,
    pub denials: u64,
    pub allowed_after_receipt: u64,
    /// Raw `ReceiptMinted` event count — audit-grade, one row per emitter.
    /// Not the number of consultations: see [`count_consultations`].
    pub receipts_minted: u64,
    /// `receipts_minted` de-duplicated to one per consultation. This is the
    /// number to report as "consulted"; the raw count above is inflated by the
    /// multiple emitters that record the same consultation.
    pub consultations: u64,
    pub bypasses: u64,
    /// Total `ControlChanged` events (sum of the four `controls_*` lifecycle
    /// counters below).
    pub controls_changed: u64,
    /// Lifecycle breakdown of `ControlChanged` events (control == confirmed
    /// gotcha). These let `mati stats` report gotcha created/confirmed/updated/
    /// removed velocity from the audit log without new capture.
    pub controls_created: u64,
    pub controls_confirmed: u64,
    pub controls_updated: u64,
    pub controls_removed: u64,
    pub config_changes: u64,
    pub gaps: u64,
    pub retention_prunes: u64,
    /// Graceful daemon exits. One per run that ended cleanly, so the count
    /// falls short of the number of runs by exactly the crashes.
    pub clean_shutdowns: u64,
    /// `SubagentSpawned` events — subagents that spawned, whether or not they
    /// went on to consult. Lets the audit attribute spawned-then-idle subagents.
    pub subagent_spawns: u64,
}

/// Derived enforcement metrics (PMF/friction signals) computed from the
/// raw event stream. All derived from existing events — no new capture.
#[derive(Debug, Default)]
pub struct DerivedEnforcementMetrics {
    /// Distinct `agent_session` ids that produced at least one `Deny`.
    ///
    /// `Deny` is hook-path and carries a session id; `ReceiptMinted` is
    /// MCP-path and does not (schema_version 2). So only *blocks* can be
    /// attributed to sessions, not consultations.
    pub blocked_sessions: u64,
    /// `Deny` events that carry a session id — the numerator for the ratio.
    pub attributed_denials: u64,
    /// `attributed_denials / blocked_sessions`; `None` when no denied session
    /// carries an id (nothing to attribute).
    pub blocks_per_session: Option<f64>,
    /// Median milliseconds from a `Deny` to the next `ReceiptMinted` on the
    /// **same `subject_key`** (paired by subject + temporal order, since
    /// receipts lack a session id), counting only pairs within
    /// `CONSULTED_RECENT_TTL_SECS` — the system's own "recent consult" window.
    /// A later receipt is a separate interaction, not a response to the block.
    /// Measures how long an agent takes to consult after being blocked. `None`
    /// when no Deny→consult pair exists inside the window.
    pub median_time_to_consult_ms: Option<u64>,
    /// Number of Deny→consult pairs that fed the median.
    pub consult_pairs: u64,
}

/// Compute [`DerivedEnforcementMetrics`] from a slice of events.
///
/// Pure (no store / no I/O) so it is unit-testable from hand-built events.
pub fn derive_enforcement_metrics(events: &[EnforcementEvent]) -> DerivedEnforcementMetrics {
    use std::collections::{BTreeSet, HashMap};

    // --- blocks per session: Deny events carry session ids ---
    let mut blocked_sessions: BTreeSet<&str> = BTreeSet::new();
    let mut attributed_denials = 0u64;
    for e in events {
        if matches!(e.event_type, EnforcementEventType::Deny) {
            if let Some(sid) = e.agent_session.as_deref() {
                blocked_sessions.insert(sid);
                attributed_denials += 1;
            }
        }
    }
    let blocks_per_session = if blocked_sessions.is_empty() {
        None
    } else {
        Some(attributed_denials as f64 / blocked_sessions.len() as f64)
    };

    // --- time to consult: Deny -> next ReceiptMinted on the same subject ---
    // Index receipt timestamps per subject, sorted ascending, so each Deny can
    // find the first consultation at or after it.
    //
    // Deliberately NOT de-duplicated the way `count_consultations` is, and it
    // does not need to be: the pairing takes the *minimum* receipt timestamp at
    // or after the deny, and a duplicate report of the same consultation is
    // always at or after the first one, so it can never become the minimum.
    // `consult_pairs` counts denials, not receipts, so it is unaffected too.
    // `duplicate_receipts_do_not_move_the_median` pins both — this is a
    // property of `find`-the-first, and a change to the pairing rule breaks it.
    let mut receipts_by_subject: HashMap<&str, Vec<u64>> = HashMap::new();
    for e in events {
        if matches!(e.event_type, EnforcementEventType::ReceiptMinted) {
            receipts_by_subject
                .entry(e.subject_key.as_str())
                .or_default()
                .push(e.recorded_at_ms);
        }
    }
    for times in receipts_by_subject.values_mut() {
        times.sort_unstable();
    }
    // Only a consult within this window counts as a response to the block;
    // a later receipt is a separate interaction (avoids cross-day/cross-session
    // pairs that would inflate the median).
    let window_ms = crate::store::session::CONSULTED_RECENT_TTL_SECS * 1_000;
    let mut deltas: Vec<u64> = Vec::new();
    for e in events {
        if matches!(e.event_type, EnforcementEventType::Deny) {
            if let Some(times) = receipts_by_subject.get(e.subject_key.as_str()) {
                // First receipt at or after this deny (sorted ascending).
                if let Some(&t) = times.iter().find(|&&t| t >= e.recorded_at_ms) {
                    let delta = t - e.recorded_at_ms;
                    if delta <= window_ms {
                        deltas.push(delta);
                    }
                }
            }
        }
    }
    let consult_pairs = deltas.len() as u64;
    let median_time_to_consult_ms = median_u64(&mut deltas);

    DerivedEnforcementMetrics {
        blocked_sessions: blocked_sessions.len() as u64,
        attributed_denials,
        blocks_per_session,
        median_time_to_consult_ms,
        consult_pairs,
    }
}

/// Median of a slice (mutated: sorted in place). Even counts average the two
/// middle values (integer division). `None` for an empty slice.
pub(crate) fn median_u64(values: &mut [u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let n = values.len();
    let mid = n / 2;
    if n % 2 == 1 {
        Some(values[mid])
    } else {
        Some((values[mid - 1] + values[mid]) / 2)
    }
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
        EnforcementEventType::CleanShutdown { .. } => "clean_shutdown",
        EnforcementEventType::SubagentSpawned => "subagent_spawned",
    }
}
