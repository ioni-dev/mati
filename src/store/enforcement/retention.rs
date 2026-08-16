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
/// Reads only the newest event on the healthy path. A full scan of an unbounded
/// log sits on the cold-start path that `ensure_daemon` blocks every hook on.
///
/// Three outcomes, decided by what sits at the tail:
///
/// - A [`EnforcementEventType::CleanShutdown`] terminator — the previous run
///   stopped deliberately and the chain already bounds the quiet window. No gap,
///   whatever its duration.
/// - An ordinary event in a log that has a terminator somewhere — the previous
///   run died. [`GapCause::UncleanShutdown`], recorded at any duration, since a
///   crash is worth reporting whether it lasted three hours or three days.
/// - An ordinary event in a log with no terminator at all — the log predates
///   terminators, so absence proves nothing about how the last run ended. Falls
///   back to [`GapCause::Unknown`] past `gap_threshold_ms`, which is then the
///   whole of the judgment about what counts as quiet.
///
/// The backscan the middle case needs is the full read this function otherwise
/// avoids, so it runs only when the tail is not a terminator: once per store at
/// upgrade, and once per genuine crash.
///
/// Returns the event it recorded, or `None` when there is no gap.
pub async fn detect_startup_gap(
    store: &Store,
    gap_threshold_ms: u64,
) -> Result<Option<EnforcementEvent>> {
    // Zero-padded keys sort in seq order, so the tail is the newest event. Skip
    // back past any this binary cannot read rather than treat one as absent.
    let keys = store.scan_keys(EVENT_PREFIX).await?;
    let mut newest = None;
    for (i, key) in keys.iter().enumerate().rev() {
        if let Ok(Some(bytes)) = store.get_raw_bytes(key).await {
            if let Ok(event) = serde_json::from_slice::<EnforcementEvent>(&bytes) {
                newest = Some((i, event));
                break;
            }
        }
    }
    let Some((newest_idx, newest)) = newest else {
        return Ok(None);
    };

    // A terminator at the tail says recording stopped deliberately. The window
    // is already bounded in the chain by this event and the next one written,
    // so it needs no RecordingGap of its own.
    if matches!(
        newest.event_type,
        EnforcementEventType::CleanShutdown { .. }
    ) {
        return Ok(None);
    }

    // No terminator at the tail is a crash only in a log whose writer emits
    // them. Nothing cheaper than a backscan tells that apart from a store
    // written before terminators existed, and mislabeling every pre-upgrade
    // store as a crash is worse than the read. This runs only off the healthy
    // path: once per store at upgrade, and once per genuine crash.
    let (cause, threshold_ms) = if has_terminator(store, &keys[..newest_idx]).await {
        (GapCause::UncleanShutdown, 0)
    } else {
        (GapCause::Unknown, gap_threshold_ms)
    };

    let current = now_ms();
    if current.saturating_sub(newest.recorded_at_ms) <= threshold_ms {
        return Ok(None);
    }

    // Route through the shared writer so the cached chain head stays in sync
    // with this RecordingGap write.
    let writer = shared_writer(store).await?;
    let event = writer
        .lock()
        .await
        .detect_and_record_gap(store, newest.recorded_at_ms, current, cause)
        .await?;
    Ok(Some(event))
}

/// True if any readable event under `keys` is a `CleanShutdown`.
///
/// Newest-first, but the worst case is the whole slice: after a crash the last
/// terminator sits behind every event the crashed run wrote.
async fn has_terminator(store: &Store, keys: &[String]) -> bool {
    for key in keys.iter().rev() {
        if let Ok(Some(bytes)) = store.get_raw_bytes(key).await {
            if let Ok(event) = serde_json::from_slice::<EnforcementEvent>(&bytes) {
                if matches!(event.event_type, EnforcementEventType::CleanShutdown { .. }) {
                    return true;
                }
            }
        }
    }
    false
}

/// Write the terminator that marks a graceful daemon exit.
///
/// Called by `mati daemon start` after in-flight handlers drain and before the
/// store closes, so it lands as the last event of the run. Ordering is
/// load-bearing: a handler still draining writes enforcement events, and any
/// event after the terminator leaves an ordinary event at the tail, which the
/// next start reads as a crash (section 18.2).
///
/// Best-effort like every other write on the shutdown path. A shutdown that
/// cannot record its terminator degrades to looking like a crash, which is the
/// safe direction — it over-reports an outage, it never hides one.
pub async fn record_clean_shutdown(
    store: &Store,
    reason: &str,
) -> Result<Option<EnforcementEvent>> {
    record_event(
        store,
        EnforcementEventType::CleanShutdown {
            reason: reason.to_string(),
        },
        SubjectKind::System,
        "enforcement:stream".to_string(),
        "system".to_string(),
        None,
        "clean_shutdown".to_string(),
        None,
    )
    .await
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
