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

pub(crate) use display::{format_date, signal_label, source_short, staleness_color, truncate};

#[cfg(test)]
use display::format_ts;

use display::{
    days_to_ymd, priority_comfy_color, priority_short, priority_weight, score_comfy_color,
};

#[cfg(test)]
use history::{duration_label, format_ts_short, source_short_label};

use history::{now_secs, parse_since_duration};

#[cfg(test)]
use ls::ls_file_row;
