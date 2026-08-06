use super::*;

pub(crate) const MAX_REPARSE_INCREMENT: f32 = 0.4;

/// Ceiling on the staleness a record can hold from reparse alone.
///
/// Sits below the 0.7 `Liability` floor on purpose. `Liability` and
/// `Tombstone` no longer gate gotcha enforcement (`hooks::decide::evaluate`
/// runs the gotcha loop before it checks the tier), but they still gate
/// injection — `Liability` degrades the cached blurb to a warning,
/// `Tombstone` suppresses it. An increment that accumulates per edit would
/// let a few edits in one session mark a file's blurb untrustworthy, when
/// the file was only being actively worked on, not abandoned.
///
/// That harm is smaller now than when this constant was written: a degraded
/// blurb precedes a file read that was about to happen anyway, not a
/// disabled deny. It is still real — Liability also drops any blast-radius
/// warning from the same pass, per `hooks::decide::evaluate` — and the
/// margin under 0.7 is about maximizing signal while staying clear of the
/// floor, not about which harm sits past it. The value does not need to
/// change because of the reorder. Git, time, dep and cascade factors still
/// reach those tiers through [`StalenessAnalyzer::compute_staleness`].
pub(crate) const MAX_REPARSE_STALENESS: f32 = 0.69;

/// Staleness increment per entry point change.
pub(super) const ENTRY_POINT_WEIGHT: f32 = 0.15;

/// Staleness increment per import change.
pub(super) const IMPORT_WEIGHT: f32 = 0.10;

/// Staleness increment when TODOs change.
pub(super) const TODOS_WEIGHT: f32 = 0.05;

/// Staleness increment per unsafe block change.
pub(super) const UNSAFE_WEIGHT: f32 = 0.10;

/// Staleness increment per unwrap change.
pub(super) const UNWRAP_WEIGHT: f32 = 0.05;

/// Staleness increment cascaded to linked gotchas.
pub(super) const CASCADE_WEIGHT: f32 = 0.10;

/// Diff between old and new file analysis — drives staleness signals.
#[derive(Debug, Clone)]
pub struct ReparseDiff {
    pub entry_points_added: Vec<String>,
    pub entry_points_removed: Vec<String>,
    pub imports_added: Vec<String>,
    pub imports_removed: Vec<String>,
    pub todos_changed: bool,
    pub unsafe_delta: i32,
    pub unwrap_delta: i32,
}

impl ReparseDiff {
    /// True when no structural changes were detected.
    pub fn is_empty(&self) -> bool {
        self.entry_points_added.is_empty()
            && self.entry_points_removed.is_empty()
            && self.imports_added.is_empty()
            && self.imports_removed.is_empty()
            && !self.todos_changed
            && self.unsafe_delta == 0
            && self.unwrap_delta == 0
    }
}

/// Apply reparse-derived staleness signals to a record's `StalenessScore`.
///
/// Returns the new signals added (empty if diff is empty). The record's
/// staleness value/tier/signals/computed_at are updated in place.
pub fn apply_reparse_staleness(record: &mut Record, diff: &ReparseDiff) -> Vec<StalenessSignal> {
    if diff.is_empty() {
        return vec![];
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut new_signals = Vec::new();
    let mut increment: f32 = 0.0;

    let ep_changes = (diff.entry_points_added.len() + diff.entry_points_removed.len()) as u32;
    if ep_changes > 0 {
        let signal = StalenessSignal::EntryPointsChanged(ep_changes);
        new_signals.push(signal);
        increment += ep_changes as f32 * ENTRY_POINT_WEIGHT;
    }

    let import_changes = (diff.imports_added.len() + diff.imports_removed.len()) as u32;
    if import_changes > 0 {
        let signal = StalenessSignal::ImportsChanged(import_changes);
        new_signals.push(signal);
        increment += import_changes as f32 * IMPORT_WEIGHT;
    }

    if diff.todos_changed {
        new_signals.push(StalenessSignal::TodosChanged);
        increment += TODOS_WEIGHT;
    }

    if diff.unsafe_delta != 0 {
        new_signals.push(StalenessSignal::UnsafeCountChanged(diff.unsafe_delta));
        increment += diff.unsafe_delta.unsigned_abs() as f32 * UNSAFE_WEIGHT;
    }

    if diff.unwrap_delta != 0 {
        new_signals.push(StalenessSignal::UnwrapCountChanged(diff.unwrap_delta));
        increment += diff.unwrap_delta.unsigned_abs() as f32 * UNWRAP_WEIGHT;
    }

    // Cap increment
    increment = increment.min(MAX_REPARSE_INCREMENT);

    // Saturating add: never past the reparse ceiling, never below a value some
    // other factor (or a hard override) already set.
    let new_value = (record.staleness.value + increment)
        .min(MAX_REPARSE_STALENESS)
        .max(record.staleness.value);
    record.staleness.value = new_value;
    record.staleness.tier = StalenessScore::tier_from_value(new_value);
    record.staleness.computed_at = now;
    record.staleness.signals.extend(new_signals.clone());

    // Cap signal history to prevent unbounded growth
    const MAX_SIGNALS: usize = 20;
    if record.staleness.signals.len() > MAX_SIGNALS {
        let drain_count = record.staleness.signals.len() - MAX_SIGNALS;
        record.staleness.signals.drain(..drain_count);
    }

    new_signals
}

/// Cascade staleness to gotcha records linked from this file record.
///
/// For each `gotcha_keys` entry: add `LinkedFileChanged`, bump staleness by 0.10.
pub async fn cascade_staleness_to_gotchas(store: &Store, file_record: &FileRecord) -> Result<u32> {
    if file_record.gotcha_keys.is_empty() {
        return Ok(0);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut cascaded = 0u32;

    for gotcha_key in &file_record.gotcha_keys {
        if let Some(mut gotcha_record) = store.get(gotcha_key).await? {
            let signal = StalenessSignal::LinkedFileChanged {
                path: file_record.path.clone(),
            };

            let new_value = (gotcha_record.staleness.value + CASCADE_WEIGHT)
                .min(MAX_REPARSE_STALENESS)
                .max(gotcha_record.staleness.value);
            gotcha_record.staleness.value = new_value;
            gotcha_record.staleness.tier = StalenessScore::tier_from_value(new_value);
            gotcha_record.staleness.computed_at = now;
            gotcha_record.staleness.signals.push(signal);

            const MAX_SIGNALS: usize = 20;
            if gotcha_record.staleness.signals.len() > MAX_SIGNALS {
                let drain_count = gotcha_record.staleness.signals.len() - MAX_SIGNALS;
                gotcha_record.staleness.signals.drain(..drain_count);
            }

            gotcha_record.updated_at = now;
            gotcha_record.version.logical_clock += 1;
            gotcha_record.version.wall_clock = now;

            store.put(gotcha_key, &gotcha_record).await?;
            cascaded += 1;
        }
    }

    Ok(cascaded)
}
