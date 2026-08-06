pub(super) use anyhow::Result;
pub(super) use comfy_table::{
    presets::UTF8_FULL_CONDENSED, Cell, Color, ContentArrangement, Table,
};
pub(super) use serde::{Deserialize, Serialize};
pub(super) use std::io::IsTerminal as _;
pub(super) use std::path::PathBuf;

pub(super) use mati_core::store::{
    Category, ConfidenceScore, FileRecord, Priority, QualityScore, QualitySignal, QualityTier,
    Record, RecordLifecycle, RecordSource, RecordVersion, StalenessScore, StalenessTier,
};

pub(super) use super::colors;
pub(super) use super::proxy;
pub(super) use super::proxy::StoreProxy;

mod display;
mod export;
mod history;
mod ls;

#[cfg(test)]
mod tests;

pub use display::{run_show, ExportArgs, HistoryArgs, ImportArgs, LsArgs, ShowArgs};
pub use export::{run_export, run_import};
pub use history::run_history;
pub use ls::run_ls;

#[allow(unused_imports)]
pub(crate) use display::{
    category_color, category_label, format_date, format_ts, hook_tier_label, quality_tier_label,
    score_color, signal_label, source_label, source_short, staleness_color, staleness_tier_label,
    truncate,
};

#[allow(unused_imports)]
use display::{
    days_to_ymd, priority_comfy_color, priority_short, priority_weight, score_comfy_color,
};

#[allow(unused_imports)]
use history::{
    duration_label, format_ts_short, now_secs, parse_since_duration, source_short_label,
};
#[allow(unused_imports)]
use ls::ls_file_row;
