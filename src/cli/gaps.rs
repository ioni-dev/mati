use anyhow::Result;
use clap::Args;

#[derive(Args)]
pub struct GapsArgs {
    /// Minimum risk score to include (0.0–1.0)
    #[arg(long, default_value = "0.3")]
    pub min_risk: f32,

    /// Maximum results to show
    #[arg(long, short = 'n', default_value = "20")]
    pub limit: usize,
}

pub async fn run(_args: GapsArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati gaps not yet implemented (M-10-E)"))
}
