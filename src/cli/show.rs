use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct ShowArgs {
    /// Record key (e.g., "file:src/main.rs", "gotcha:inference-async")
    pub key: String,
}

#[derive(Args)]
pub struct LsArgs {
    /// Category to list: files, gotchas, decisions (omit for all)
    pub category: Option<String>,
}

#[derive(Args)]
pub struct HistoryArgs {
    /// Record key
    pub key: String,

    /// Show records changed in time window (e.g., "2w", "30d")
    #[arg(long)]
    pub since: Option<String>,
}

#[derive(Args)]
pub struct ExportArgs {
    /// Output format: md or json
    #[arg(long, default_value = "md")]
    pub format: String,

    /// Output file (defaults to stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct ImportArgs {
    /// Path to CLAUDE.md or JSON file
    pub file: PathBuf,
}

pub async fn run_show(_args: ShowArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati show not yet implemented (M-05-E)"))
}

pub async fn run_ls(_args: LsArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati ls not yet implemented (M-08-C/D/E)"))
}

pub async fn run_history(_args: HistoryArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati history not yet implemented (M-14-C)"))
}

pub async fn run_export(_args: ExportArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati export not yet implemented (M-08-M)"))
}

pub async fn run_import(_args: ImportArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati import not yet implemented (M-08-N)"))
}
