use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct InitArgs {
    /// Path to repository root (defaults to current directory)
    #[arg(short, long)]
    pub path: Option<PathBuf>,

    /// Skip hook installation into .claude/hooks/
    #[arg(long)]
    pub no_hooks: bool,

    /// Skip writing .claude/settings.json
    #[arg(long)]
    pub no_settings: bool,
}

pub async fn run(_args: InitArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati init not yet implemented (M-06)"))
}
