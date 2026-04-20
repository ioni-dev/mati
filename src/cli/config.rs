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

use mati_core::store::enforcement::{
    get_enforcement_mode, get_retention_days, set_enforcement_mode, set_retention_days,
    EnforcementMode,
};

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
    let store = proxy.direct_store().ok_or_else(|| {
        anyhow::anyhow!(
            "config commands require direct store access.\n\
             Stop the daemon first: mati daemon stop"
        )
    })?;

    match key {
        "enforcement.mode" => {
            let mode = get_enforcement_mode(store).await;
            let label = match mode {
                EnforcementMode::Advisory => "advisory",
                EnforcementMode::Strict => "strict",
            };
            println!("{label}");
        }
        "enforcement.retention" => {
            let days = get_retention_days(store).await;
            println!("{days}");
        }
        _ => {
            anyhow::bail!(
                "unknown config key: {key}\n\
                 Valid keys: enforcement.mode, enforcement.retention"
            );
        }
    }
    Ok(())
}

async fn run_set(proxy: &StoreProxy, key: &str, value: &str) -> Result<()> {
    let store = proxy.direct_store().ok_or_else(|| {
        anyhow::anyhow!(
            "config commands require direct store access.\n\
             Stop the daemon first: mati daemon stop"
        )
    })?;

    match key {
        "enforcement.mode" => {
            let mode = match value {
                "advisory" => EnforcementMode::Advisory,
                "strict" => EnforcementMode::Strict,
                _ => {
                    anyhow::bail!(
                        "invalid enforcement mode: {value}\n\
                         Valid values: advisory, strict"
                    );
                }
            };
            let old = set_enforcement_mode(store, mode).await?;
            let old_label = match old {
                EnforcementMode::Advisory => "advisory",
                EnforcementMode::Strict => "strict",
            };
            if old == mode {
                println!("enforcement.mode is already {value}");
            } else {
                println!("enforcement.mode: {old_label} → {value}");
            }
        }
        "enforcement.retention" => {
            let days: u64 = value.parse().map_err(|_| {
                anyhow::anyhow!("invalid retention value: {value} (expected integer days)")
            })?;
            if days == 0 {
                anyhow::bail!("retention must be at least 1 day");
            }
            set_retention_days(store, days).await?;
            println!("enforcement.retention: {days} days");
        }
        _ => {
            anyhow::bail!(
                "unknown config key: {key}\n\
                 Valid keys: enforcement.mode, enforcement.retention"
            );
        }
    }
    Ok(())
}
