use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Args;
use uuid::Uuid;

use mati_core::analysis::{
    build_edges, build_file_records, hash_and_parse_parallel, import_claude_md, mine_git_history,
    parse_dependencies, Walker,
};
use mati_core::graph::edges::EdgeKind;
use mati_core::graph::Graph;
use mati_core::scaffold::codex::CodexInstallResult;
use mati_core::scaffold::settings::InstallResult;
use mati_core::scaffold::{install_codex, write_claude_md_stub, write_mati_enrich_command};
use mati_core::store::{
    derive_slug, slug_root, Category, ConfidenceScore, FileRecord, GotchaRecord, Priority,
    QualityScore, Record, RecordLifecycle, RecordSource, RecordVersion, StalenessScore,
    StalenessSignal, Store,
};

mod display;
mod generated_gotchas;
mod rename_migration;
mod run;
mod scaffold;

#[cfg(test)]
mod tests;

pub use run::run;
pub use scaffold::{install_scaffold, run_hooks, HooksArgs};

pub(super) use super::{colors, sandbox, stale, stats};
pub(super) use display::is_code_file;
pub(super) use generated_gotchas::{
    build_cochange_gotchas, build_codeowners_candidates, build_ownership_gotchas,
    build_revert_gotchas, stale_dependency_keys, CoChangeGotcha, OwnershipGotcha, RevertGotcha,
};
pub(super) use mati_core::store::gotcha_ops::is_auto_gotcha;
pub(super) use rename_migration::migrate_renamed_gotchas;
#[cfg(test)]
pub(super) use rename_migration::{plan_rename_migrations, TAG_PATH_MIGRATED};

#[derive(Args)]
pub struct InitArgs {
    /// Path to repository root (defaults to current directory)
    #[arg(short, long)]
    pub path: Option<PathBuf>,

    /// Skip agent hook/config installation
    #[arg(long)]
    pub no_hooks: bool,

    /// Install or update Codex integration into .codex/
    /// (auto-detected if .codex/ exists and no flag is given)
    #[arg(long)]
    pub codex: bool,

    /// Install or update Claude integration into .claude/
    /// (auto-detected if .claude/ exists and no flag is given)
    #[arg(long)]
    pub claude: bool,

    /// Also scaffold the experimental Claude mcp_tool hook transport. The
    /// shell hook remains installed as the startup-independent path.
    #[arg(long)]
    pub claude_mcp_tool: bool,
}
