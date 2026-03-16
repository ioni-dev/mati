use anyhow::Result;
use clap::{Args, Subcommand};

#[derive(Args)]
pub struct GotchaArgs {
    #[command(subcommand)]
    pub command: GotchaCommand,
}

#[derive(Subcommand)]
pub enum GotchaCommand {
    /// Add a new gotcha for a file
    Add {
        /// File path to add gotcha for (e.g., "src/store/db.rs")
        file: String,
    },
}

pub async fn run(args: GotchaArgs) -> Result<()> {
    match args.command {
        GotchaCommand::Add { file } => {
            tracing::warn!("mati gotcha add {file} not yet implemented (M-08-F)");
        }
    }
    Err(anyhow::anyhow!("mati gotcha not yet implemented (M-08-F)"))
}
