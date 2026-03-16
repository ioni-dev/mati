use anyhow::Result;
use clap::Args;

#[derive(Args)]
pub struct EnrichArgs {
    /// Only re-enrich Suppressed/Poor quality records
    #[arg(long)]
    pub quality_pass: bool,

    /// Show cost estimate without running enrichment
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn run(_args: EnrichArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati enrich not yet implemented (M-11)"))
}
