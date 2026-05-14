//! CLI config subcommand for enforcement settings.
//!
//! ```text
//! mati config get enforcement.mode
//! mati config set enforcement.mode strict
//! mati config get enforcement.retention
//! mati config set enforcement.retention 365
//! ```

use anyhow::Result;
use clap::{Args, Subcommand};

use super::proxy::StoreProxy;

#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Get a configuration value
    Get {
        /// Configuration key (e.g., enforcement.mode, enforcement.retention)
        key: String,
    },
    /// Set a configuration value
    Set {
        /// Configuration key (e.g., enforcement.mode, enforcement.retention)
        key: String,
        /// Value to set
        value: String,
    },
}

pub async fn run(args: ConfigArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;

    let result = match args.command {
        ConfigCommand::Get { ref key } => run_get(&proxy, key).await,
        ConfigCommand::Set { ref key, ref value } => run_set(&proxy, key, value).await,
    };

    proxy.close().await?;
    result
}

async fn run_get(proxy: &StoreProxy, key: &str) -> Result<()> {
    let value = proxy.config_get(key).await?;
    println!("{value}");
    Ok(())
}

async fn run_set(proxy: &StoreProxy, key: &str, value: &str) -> Result<()> {
    let old = proxy.config_set(key, value).await?;
    match key {
        "enforcement.mode" => {
            if old == value {
                println!("enforcement.mode is already {value}");
            } else if old.is_empty() {
                println!("enforcement.mode: {value}");
            } else {
                println!("enforcement.mode: {old} → {value}");
            }
        }
        "enforcement.retention" => {
            println!("enforcement.retention: {value} days");
        }
        _ => {}
    }
    Ok(())
}
