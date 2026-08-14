use super::*;

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
/// Called by `mati repair`'s full scan, which holds the store exclusively —
/// never from a read path, a hook, or `--check`/`--fast`.
///
/// Deletes an oldest-first **prefix** and nothing else. The walk stops at the
/// first event still inside the window, and also at the first key this binary
/// cannot read or parse, so every deleted key is individually proven expired.
/// [`verify_chain`] ignores the earliest survivor's dangling `prev_hash`, so a
/// pruned prefix verifies clean; a hole anywhere else reads as
/// [`ChainBreakKind::Linkage`] — the tamper signal. Selecting by timestamp
/// alone would punch that hole the first time the wall clock stepped backwards.
///
/// A retention of `0` disables pruning. An unset or unparseable setting reads
/// as the 365-day default (`get_retention_days`), never as zero.
pub async fn enforce_retention(store: &Store) -> Result<PruneResult> {
    let retention_days = get_retention_days(store).await;
    if retention_days == 0 {
        return Ok(PruneResult::NothingToPrune);
    }
    let cutoff_ms = now_ms().saturating_sub(retention_days.saturating_mul(86_400_000));

    // Zero-padded keys sort in seq order, so this walk is the chain order.
    let keys = store.scan_keys(EVENT_PREFIX).await?;
    let mut expired: Vec<(String, u64)> = Vec::new();
    for key in &keys {
        let Some(seq) = key
            .strip_prefix(EVENT_PREFIX)
            .and_then(|s| s.parse::<u64>().ok())
        else {
            break;
        };
        let Ok(Some(bytes)) = store.get_raw_bytes(key).await else {
            break;
        };
        let Ok(event) = serde_json::from_slice::<EnforcementEvent>(&bytes) else {
            break;
        };
        if event.recorded_at_ms >= cutoff_ms {
            break;
        }
        expired.push((key.clone(), seq));
    }

    if expired.is_empty() {
        return Ok(PruneResult::NothingToPrune);
    }
    let oldest_seq = expired.first().expect("checked non-empty above").1;
    let newest_seq = expired.last().expect("checked non-empty above").1;
    let count = expired.len() as u64;

    for (key, _) in &expired {
        store.delete(key).await?;
    }

    // After the deletion, so the prune event links to the newest SURVIVING
    // event rather than to one this run is about to remove.
    let recorded = record_event(
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

    // Advisory mode swallows event-write failures. Here that would leave a
    // deletion no one can see: a pruned prefix is invisible to `verify_chain`
    // by design, so the RetentionPruned event is the only trace it happened.
    if recorded.is_none() {
        anyhow::bail!(
            "pruned {count} enforcement events (seq {oldest_seq}-{newest_seq}) but could not \
             record the RetentionPruned event — the deletion is unattested"
        );
    }

    Ok(PruneResult::Pruned {
        count,
        oldest_seq,
        newest_seq,
    })
}

// ─────────────────────────────────────────────
// Gap Detection on Startup
// ─────────────────────────────────────────────

/// How long the event log may stay quiet before a daemon start reads it as a
/// recording gap.
///
/// Bounded below by the daemon's own rhythm: it idles out after
/// `mcp::server::IDLE_SHUTDOWN_SECS` (30 min), so anything shorter than a
/// working day records a gap on every ordinary restart — an overnight break
/// alone would do it — and a log of those buries the outages worth finding.
pub const STARTUP_GAP_THRESHOLD_MS: u64 = 24 * 60 * 60 * 1000;

/// Record a `RecordingGap` event when the daemon comes up after a window in
/// which nothing was recorded.
///
/// Called by `mati daemon start`, before the graph loads.
///
/// Reads only the newest event. A full scan of an unbounded log sits on the
/// cold-start path that `ensure_daemon` blocks every hook on.
///
/// What it reports is "no enforcement event was written between T1 and T2",
/// which is equally true of a crash, a `mati daemon stop`, a P9 fail-open, and
/// an idle weekend. Nothing in the store tells them apart, so the cause is
/// [`GapCause::Unknown`] and `gap_threshold_ms` is the whole of the judgment
/// about what counts as quiet.
///
/// Returns the event it recorded, or `None` when there is no gap.
pub async fn detect_startup_gap(
    store: &Store,
    gap_threshold_ms: u64,
) -> Result<Option<EnforcementEvent>> {
    // Zero-padded keys sort in seq order, so the tail is the newest event. Skip
    // back past any this binary cannot read rather than treat one as absent.
    let keys = store.scan_keys(EVENT_PREFIX).await?;
    let mut last_ms = None;
    for key in keys.iter().rev() {
        if let Ok(Some(bytes)) = store.get_raw_bytes(key).await {
            if let Ok(event) = serde_json::from_slice::<EnforcementEvent>(&bytes) {
                last_ms = Some(event.recorded_at_ms);
                break;
            }
        }
    }
    let Some(last_ms) = last_ms else {
        return Ok(None);
    };

    let current = now_ms();
    if current.saturating_sub(last_ms) <= gap_threshold_ms {
        return Ok(None);
    }

    // Route through the shared writer so the cached chain head stays in sync
    // with this RecordingGap write.
    let writer = shared_writer(store).await?;
    let event = writer
        .lock()
        .await
        .detect_and_record_gap(store, last_ms, current, GapCause::Unknown)
        .await?;
    Ok(Some(event))
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
    Ok(aggregate_event_counts(&events))
}

/// Window over which several `ReceiptMinted` events on the same subject are
/// read as reports of a **single** consultation. See [`count_consultations`].
///
/// Derived from the hook path's own deadline rather than picked: the second
/// event of a pair is written by the `post-memget.sh` PostToolUse hook, and
/// that hook is bounded by `cli::hook_decide::HOOK_DEADLINE_MS` (2500ms, itself
/// under the 4s scaffold timeout), so it cannot report later than that.
/// Measured spread against a warm daemon is 8–100ms, so 2s is the bound with
/// margin, not the typical case.
pub const CONSULTATION_COALESCE_MS: u64 = 2_000;
