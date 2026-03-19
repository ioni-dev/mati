use anyhow::Result;
use clap::{Parser, Subcommand};
use mati_core::store::Store;

mod cli;

#[derive(Parser)]
#[command(
    name = "mati",
    version,
    about = "Engineering knowledge that survives turnover",
    long_about = "mati is a persistent, queryable knowledge store for codebases.\n\
                  Exposed as a Claude Code plugin via MCP stdio."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize mati in the current repository (Layer 0 scan + scaffold)
    Init(cli::init::InitArgs),
    /// Batch-enrich file records using Claude API (Layer 1)
    Enrich(cli::enrich::EnrichArgs),
    /// Show project knowledge dashboard
    Status(cli::status::StatusArgs),
    /// Show knowledge health metrics
    Stats(cli::stats::StatsArgs),
    /// Show knowledge gaps ranked by risk
    Gaps(cli::gaps::GapsArgs),
    /// Show a record by key
    Show(cli::show::ShowArgs),
    /// List records by category (files, gotchas, decisions)
    Ls(cli::show::LsArgs),
    /// Show version history of a record
    History(cli::show::HistoryArgs),
    /// Manage gotcha records
    Gotcha(cli::gotcha::GotchaArgs),
    /// List records by quality tier
    QualityCheck,
    /// Re-open a record for improvement
    Improve {
        /// Record key to improve (e.g., "gotcha:inference-async")
        key: String,
    },
    /// Add a quick developer note
    Note {
        /// Note text
        text: String,
    },
    /// Export knowledge base to markdown or JSON
    Export(cli::show::ExportArgs),
    /// Import from CLAUDE.md or JSON
    Import(cli::show::ImportArgs),
    /// List stale records
    Stale,
    /// Check mati daemon reachability and latency
    Ping,
    /// Run as MCP stdio server (for Claude Code plugin)
    Serve,
    // ── Internal hook commands (hidden from --help) ─────────────────────
    #[command(hide = true)]
    LogMiss { key: String },
    #[command(hide = true)]
    LogHit { key: String },
    #[command(hide = true)]
    LogComplianceMiss { key: String },
    #[command(hide = true)]
    SessionCheckConsulted { key: String },
    #[command(hide = true)]
    SessionFlush,
    #[command(hide = true)]
    SessionHarvest,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init(args) => cli::init::run(args).await,
        Commands::Enrich(args) => cli::enrich::run(args).await,
        Commands::Status(args) => cli::status::run(args).await,
        Commands::Stats(args) => cli::stats::run(args).await,
        Commands::Gaps(args) => cli::gaps::run(args).await,
        Commands::Show(args) => cli::show::run_show(args).await,
        Commands::Ls(args) => cli::show::run_ls(args).await,
        Commands::History(args) => cli::show::run_history(args).await,
        Commands::Gotcha(args) => cli::gotcha::run(args).await,
        Commands::QualityCheck => Err(anyhow::anyhow!(
            "quality-check not yet implemented (M-08-J)"
        )),
        Commands::Improve { key } => Err(anyhow::anyhow!(
            "improve {key} not yet implemented (M-08-K)"
        )),
        Commands::Note { text } => {
            Err(anyhow::anyhow!("note not yet implemented (M-08-L): {text}"))
        }
        Commands::Export(args) => cli::show::run_export(args).await,
        Commands::Import(args) => cli::show::run_import(args).await,
        Commands::Stale => Err(anyhow::anyhow!("stale not yet implemented (M-08-O)")),
        Commands::Ping => {
            let cwd = std::env::current_dir()?;
            let store = Store::open(&cwd).await?;
            let latency_us = store.ping().await?;
            println!("mati ok  {latency_us}µs");
            Ok(())
        }
        Commands::Serve => {
            let cwd = std::env::current_dir()?;
            mati_core::mcp::serve(&cwd).await
        }
        Commands::LogMiss { key: _ } => Ok(()),
        Commands::LogHit { key: _ } => Ok(()),
        Commands::LogComplianceMiss { key: _ } => Ok(()),
        Commands::SessionCheckConsulted { key: _ } => Ok(()),
        Commands::SessionFlush => Ok(()),
        Commands::SessionHarvest => Ok(()),
    }
}
