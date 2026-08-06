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
/// Nothing in production calls this — the only caller is a test. Until it is
/// wired into `mati init` or `mati repair`, the event log grows without bound.
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
    let oldest_seq = old_events.first().expect("checked non-empty above").seq_no;
    let newest_seq = old_events.last().expect("checked non-empty above").seq_no;

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
    let last = events.last().expect("checked non-empty above");
    let current = now_ms();
    let age = current.saturating_sub(last.recorded_at_ms);

    if age > gap_threshold_ms {
        // Route through the shared writer so the cached chain head stays in sync
        // with this RecordingGap write.
        let writer = shared_writer(store).await?;
        writer
            .lock()
            .await
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
