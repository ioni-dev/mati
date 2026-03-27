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
    println!("mati enrichment runs inside your Claude Code session.");
    println!();
    println!("In Claude Code, type:");
    println!("  /mati-enrich              enrich top hotspot gaps");
    println!("  /mati-enrich src/payments  enrich a directory");
    println!("  /mati-enrich src/main.rs   enrich a single file");
    println!();
    println!("After enrichment: run `mati review` to confirm and activate hooks.");
    Ok(())
}
