use anyhow::Result;
use clap::Args;

#[derive(Args)]
pub struct StatusArgs {}

pub async fn run(_args: StatusArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati status not yet implemented (M-08-B)"))
}
