use anyhow::Result;
use clap::Args;

#[derive(Args)]
pub struct StatsArgs {}

pub async fn run(_args: StatsArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati stats not yet implemented (M-10-G)"))
}
