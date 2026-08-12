//! Incremental staleness from reparse diffs (M-12-C) and full staleness
//! analysis (M-13-A).
//!
//! When `mati reparse` detects structural changes in a file, this module
//! updates the staleness score on the file record and cascades staleness
//! to linked gotcha records.
//!
//! The [`StalenessAnalyzer`] performs a complete 5-factor staleness computation
//! across all knowledge records, using time, git, semantic, dependency, and
//! cascade signals.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::store::record::{
    Category, FileRecord, GotchaRecord, Record, RecordLifecycle, StalenessScore, StalenessSignal,
    StalenessTier,
};
use crate::store::{RepoIdent, Store};

/// Where a budget-truncated scan stopped, so the next one resumes there.
///
/// `health:*` is Eventual durability (`store::durability`): the cursor is
/// derived scheduling state, not knowledge. Losing it to a crash restarts the
/// sweep at the first prefix, which costs one redundant pass and nothing else.
const STALENESS_CURSOR_KEY: &str = "health:staleness_cursor";

async fn write_cursor(store: &Store, key: &str, now: u64) {
    let mut record = Record::layer0_file_stub(
        STALENESS_CURSOR_KEY,
        crate::store::stable_device_id(),
        1,
        now,
    );
    record.category = Category::Analytics;
    record.payload = Some(serde_json::json!({ CURSOR_FIELD: key }));
    if let Err(e) = store.put(STALENESS_CURSOR_KEY, &record).await {
        tracing::warn!("staleness cursor write failed: {e}");
    }
}

mod analyzer;
mod cursor;
mod factors;
mod git;
mod reparse;

#[cfg(test)]
mod tests;

pub use analyzer::{StalenessAnalyzer, StalenessReport, ANALYZE_TIME_BUDGET_MS};
pub use reparse::{apply_reparse_staleness, cascade_staleness_to_gotchas, ReparseDiff};

#[cfg(test)]
pub(super) use analyzer::GIT_CAP_HIT_COMMITS;
pub(super) use analyzer::{SECS_PER_DAY, TIME_STALE_DAYS};
pub(super) use cursor::{clear_cursor, read_cursor, CURSOR_FIELD};
pub(super) use factors::{cascade_factor, dep_factor, semantic_factor, time_factor};
pub(super) use git::{
    blob_sha_at_commit, blob_sha_at_head, commit_touches_file, commits_to_factor, head_commit_sha,
    is_reparse_signal, staleness_changed,
};
#[cfg(test)]
pub(super) use reparse::MAX_REPARSE_INCREMENT;
pub(super) use reparse::MAX_REPARSE_STALENESS;
