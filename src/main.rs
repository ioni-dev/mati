use std::io::{self, BufRead, IsTerminal, Write as _};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::{Parser, Subcommand};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, ContentArrangement, Table};
use slugify::slugify;

use cli::proxy::StoreProxy;
use mati_core::health::quality;
use mati_core::store::{
    Category, ConfidenceScore, QualityScore, QualityTier, Record, RecordLifecycle, RecordSource,
    RecordVersion, StalenessScore, Store,
};

mod cli;

#[derive(Parser)]
#[command(
    name = "mati",
    version,
    about = "Engineering knowledge that survives turnover",
    long_about = "mati is a persistent, queryable knowledge store for codebases.\n\
                  Exposed to agents via MCP stdio, with Claude and Codex integration paths.\n\n\
                  Core workflow:\n  \
                    mati init              build project memory\n  \
                    mati explain <file>    file briefing before editing\n  \
                    mati diff <range>      pre-merge check against knowledge store\n  \
                    mati status            project memory dashboard"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // ── Core workflow ────────────────────────────────────────────────────
    /// Build project memory — scan files, mine git history, detect patterns
    Init(cli::init::InitArgs),
    /// File briefing — gotchas, decisions, and co-changes before editing
    Explain(cli::explain::ExplainArgs),
    /// Pre-merge check — surface gotchas for files in a diff range
    Diff(cli::diff::DiffArgs),
    /// Project memory dashboard — record counts, health, and next actions
    Status(cli::status::StatusArgs),

    // ── Knowledge management ─────────────────────────────────────────────
    /// Manage gotcha records (add, edit, delete, confirm, list)
    Gotcha(cli::gotcha::GotchaArgs),
    /// Show a record by key
    Show(cli::show::ShowArgs),
    /// List records by category (files, gotchas, decisions)
    Ls(cli::show::LsArgs),
    /// Show version history of a record
    History(cli::show::HistoryArgs),
    /// Show knowledge gaps ranked by risk
    Gaps(cli::gaps::GapsArgs),
    /// List co-change clusters discovered from git history
    Clusters(cli::clusters::ClustersArgs),
    /// Show knowledge health metrics
    Stats(cli::stats::StatsArgs),
    /// Batch-enrich file records using Claude API (Layer 1)
    Enrich(cli::enrich::EnrichArgs),
    /// Add a quick developer note
    Note {
        /// Note text
        text: String,
    },
    /// Export knowledge base to markdown or JSON
    Export(cli::show::ExportArgs),
    /// Import from CLAUDE.md or JSON
    Import(cli::show::ImportArgs),

    // ── Maintenance ──────────────────────────────────────────────────────
    /// [Maintenance] Confirm auto-detected candidates for hook enforcement
    Review(cli::review::ReviewArgs),
    /// [Maintenance] List stale records with action hints
    Stale(cli::stale::StaleArgs),
    /// [Maintenance] Reconcile gotcha indexes from canonical records
    Repair(cli::repair::RepairArgs),
    /// [Maintenance] Verify hook enforcement pipeline
    Check,
    /// [Maintenance] List records by quality tier
    QualityCheck,
    /// [Maintenance] Re-open a record for improvement
    Improve {
        /// Record key to improve (e.g., "gotcha:inference-async")
        key: String,
    },

    // ── Infrastructure ───────────────────────────────────────────────────
    /// Install or update agent hooks without a full re-init (safe while daemon is running)
    Hooks(cli::init::HooksArgs),
    /// Manage the background daemon (reduces hook latency from ~150ms to <1ms)
    Daemon(cli::daemon::DaemonArgs),
    /// Check mati daemon reachability and latency
    Ping {
        /// Only check the daemon socket — exit 1 if no daemon is running
        /// (skip direct store fallback). Used by hook scripts.
        #[arg(long)]
        daemon_only: bool,
    },
    /// Run as MCP stdio server (for Claude/Codex agent integration)
    Serve {
        /// Project root directory. Defaults to current working directory.
        /// Required when the MCP host (e.g. Codex) spawns the server with
        /// a working directory that differs from the project root.
        #[arg(long)]
        path: Option<std::path::PathBuf>,
    },
    // ── Internal hook commands (hidden from --help) ─────────────────────
    /// Enforcement decision engine for hook scripts.
    #[command(hide = true, name = "hook-decide")]
    HookDecide(cli::hook_decide::HookDecideArgs),
    #[command(hide = true)]
    DocCapture {
        /// Repo-relative file path
        path: String,
    },
    #[command(hide = true)]
    Get { key: String },
    #[command(hide = true)]
    LogMiss { key: String },
    #[command(hide = true)]
    LogHit { key: String },
    #[command(hide = true)]
    LogComplianceMiss { key: String },
    #[command(hide = true)]
    LogComplianceHit { key: String },
    #[command(hide = true)]
    LogCodexShellMiss { key: String },
    #[command(hide = true)]
    LogBootstrap { key: String },
    #[command(hide = true)]
    LogPromptNudge { key: String },
    #[command(hide = true)]
    SessionCheckConsulted { key: String },
    #[command(hide = true)]
    SessionCheckConsultedRecent {
        key: String,
        #[arg(long, default_value_t = mati_core::store::session::CONSULTED_RECENT_TTL_SECS)]
        ttl_secs: u64,
    },
    #[command(hide = true)]
    SessionFlush,
    #[command(hide = true)]
    SessionHarvest,
    #[command(hide = true)]
    EditHook {
        /// Repo-relative file path
        path: String,
    },
    #[command(hide = true)]
    Reparse {
        /// Repo-relative file path to re-parse
        path: String,
    },
    /// Fetch gotcha context for files (used by Codex UserPromptSubmit hook).
    /// Returns bootstrap markdown for the given context files via daemon socket.
    #[command(hide = true, name = "prompt-context")]
    PromptContext {
        /// File paths to look up gotchas for
        files: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
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
        Commands::Clusters(args) => cli::clusters::run(args).await,
        Commands::Show(args) => cli::show::run_show(args).await,
        Commands::Ls(args) => cli::show::run_ls(args).await,
        Commands::History(args) => cli::show::run_history(args).await,
        Commands::Gotcha(args) => cli::gotcha::run(args).await,
        Commands::QualityCheck => run_quality_check().await,
        Commands::Improve { key } => run_improve(&key).await,
        Commands::Note { text } => run_note(&text).await,
        Commands::Export(args) => cli::show::run_export(args).await,
        Commands::Import(args) => cli::show::run_import(args).await,
        Commands::Review(args) => cli::review::run(args).await,
        Commands::Explain(args) => cli::explain::run(args).await,
        Commands::Diff(args) => cli::diff::run(args).await,
        Commands::Stale(args) => cli::stale::run(args).await,
        Commands::Repair(args) => cli::repair::run(args).await,
        Commands::Check => cli::check::run().await,
        Commands::Hooks(args) => cli::init::run_hooks(args),
        Commands::Daemon(args) => match args.command {
            cli::daemon::DaemonCommand::Start => cli::daemon::run_daemon_start().await,
            cli::daemon::DaemonCommand::Stop => cli::daemon::run_daemon_stop().await,
            cli::daemon::DaemonCommand::Status => cli::daemon::run_daemon_status().await,
        },
        Commands::Ping { daemon_only } => {
            let cwd = std::env::current_dir()?;
            // Try daemon socket first (avoids store open conflict when mati serve is running).
            let root = cli::daemon::mati_root_for(&cwd)?;
            match cli::daemon::daemon_result(&root, "ping", serde_json::json!({})).await {
                cli::daemon::DaemonResult::Ok(_) => {
                    println!("mati ok");
                    return Ok(());
                }
                cli::daemon::DaemonResult::Unresponsive => {
                    // Daemon alive but not responding — don't try to open store.
                    anyhow::bail!("mati daemon unresponsive");
                }
                cli::daemon::DaemonResult::NotRunning | cli::daemon::DaemonResult::StaleSocket => {
                    if daemon_only {
                        // Hook scripts use --daemon-only to check daemon liveness
                        // without the store fallback. Exit 1 so hooks fail-open
                        // with a visible warning instead of silently succeeding.
                        std::process::exit(1);
                    }
                    // No daemon — fall through to direct store open.
                }
            }
            let store = Store::open(&cwd).await?;
            let latency_us = store.ping().await?;
            println!("mati ok  {latency_us}µs");
            Ok(())
        }
        Commands::Serve { path } => {
            let root = match path {
                Some(p) => std::fs::canonicalize(&p)?,
                None => std::env::current_dir()?,
            };
            mati_core::mcp::serve(&root).await
        }
        Commands::HookDecide(args) => cli::hook_decide::run(args).await,
        Commands::Get { key } => cli::hooks::run_get(&key).await,
        Commands::LogMiss { key } => cli::hooks::run_log_miss(&key).await,
        Commands::LogHit { key } => cli::hooks::run_log_hit(&key).await,
        Commands::LogComplianceMiss { key } => cli::hooks::run_log_compliance_miss(&key).await,
        Commands::LogComplianceHit { key } => cli::hooks::run_log_compliance_hit(&key).await,
        Commands::LogCodexShellMiss { key } => cli::hooks::run_log_codex_shell_miss(&key).await,
        Commands::LogBootstrap { key } => cli::hooks::run_log_bootstrap(&key).await,
        Commands::LogPromptNudge { key } => cli::hooks::run_log_prompt_nudge(&key).await,
        Commands::SessionCheckConsulted { key } => {
            cli::hooks::run_session_check_consulted(&key).await
        }
        Commands::SessionCheckConsultedRecent { key, ttl_secs } => {
            cli::hooks::run_session_check_consulted_recent(&key, ttl_secs).await
        }
        Commands::SessionFlush => cli::hooks::run_session_flush().await,
        Commands::SessionHarvest => cli::hooks::run_session_harvest().await,
        Commands::DocCapture { path } => cli::hooks::run_doc_capture(&path).await,
        Commands::EditHook { path } => cli::hooks::run_edit_hook(&path).await,
        Commands::Reparse { path } => cli::reparse::run(&path).await,
        Commands::PromptContext { files } => cli::hooks::run_prompt_context(&files).await,
    }
}

// ── M-08-L: mati note ────────────────────────────────────────────────────────

async fn run_note(text: &str) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let slug = slugify!(text, max_length = 30);
    let key = format!("dev_note:{slug}-{now}");

    let device_id = uuid::Uuid::new_v4();
    let mut record = Record {
        key: key.clone(),
        value: text.to_string(),
        category: Category::DevNote,
        priority: mati_core::store::Priority::Normal,
        tags: vec![],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id,
            logical_clock: 1,
            wall_clock: now,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::DeveloperManual,
        confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
        gap_analysis_score: 0.0,
        payload: None,
    };

    // Run quality analyzer (display score, but no gate for notes)
    let score = quality::analyze(&record);
    record.quality = score.clone();

    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    proxy.put(&key, &record).await?;

    println!("Created {key}  (quality: {:.2})", score.value);
    Ok(())
}

// ── M-08-J: mati quality-check ──────────────────────────────────────────────

async fn run_quality_check() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;

    let mut all: Vec<Record> = Vec::new();
    for prefix in &["file:", "gotcha:", "decision:", "dev_note:"] {
        all.extend(
            proxy
                .scan_prefix(prefix)
                .await?
                .into_iter()
                .filter(|r| matches!(r.lifecycle, RecordLifecycle::Active)),
        );
    }

    if all.is_empty() {
        println!("No knowledge records found. Run `mati init` first.");
        return Ok(());
    }

    // Re-analyze quality for each record
    for r in &mut all {
        let score = quality::analyze(r);
        r.quality = score;
    }

    // Group by tier
    let tiers = [
        QualityTier::Suppressed,
        QualityTier::Poor,
        QualityTier::Acceptable,
        QualityTier::Good,
        QualityTier::Excellent,
    ];

    for tier in &tiers {
        let tier_records: Vec<&Record> = all.iter().filter(|r| r.quality.tier == *tier).collect();

        if tier_records.is_empty() {
            continue;
        }

        let tier_label = match tier {
            QualityTier::Suppressed => "Suppressed (< 0.2)",
            QualityTier::Poor => "Poor (0.2 – 0.4)",
            QualityTier::Acceptable => "Acceptable (0.4 – 0.7)",
            QualityTier::Good => "Good (0.7 – 0.9)",
            QualityTier::Excellent => "Excellent (>= 0.9)",
        };

        println!("\n{tier_label}  ({} records)", tier_records.len());

        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new("Key"),
                Cell::new("Score"),
                Cell::new("Signals"),
            ]);

        for r in &tier_records {
            let sigs: Vec<&str> = r
                .quality
                .signals
                .iter()
                .map(|s| cli::show::signal_label(s))
                .collect();
            table.add_row(vec![
                Cell::new(&r.key),
                Cell::new(format!("{:.2}", r.quality.value)),
                Cell::new(sigs.join(", ")),
            ]);
        }
        println!("{table}");

        // Show improvement hints for Suppressed/Poor
        if *tier == QualityTier::Suppressed || *tier == QualityTier::Poor {
            if let Some(first) = tier_records.first() {
                let hints = quality::generate_improvement_hints(&first.quality);
                if !hints.is_empty() {
                    println!("  Hints:");
                    for hint in hints {
                        println!("    - {hint}");
                    }
                }
            }
        }
    }

    println!();
    Ok(())
}

// ── M-08-K: mati improve ────────────────────────────────────────────────────

async fn run_improve(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let use_color = io::stderr().is_terminal();

    let mut record = match proxy.get(key).await? {
        Some(r) => r,
        None => anyhow::bail!("no record found for key '{key}'"),
    };

    // Display current state
    let score = quality::analyze(&record);
    println!("Current quality: {:.2} ({:?})", score.value, score.tier);
    println!("Current value:\n  {}\n", record.value);

    let hints = quality::generate_improvement_hints(&score);
    if !hints.is_empty() {
        println!("Improvement hints:");
        for hint in &hints {
            println!("  - {hint}");
        }
        println!();
    }

    // Read new value from stdin
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    eprint_prompt("New value (empty to keep current): ", use_color);
    let new_value = read_line(&mut lines)?;

    if !new_value.is_empty() {
        record.value = new_value;
    }

    // Re-analyze
    let new_score = quality::analyze(&record);

    // Quality gate
    if quality::below_quality_gate(&new_score) {
        quality::print_quality_gate_error(&new_score, use_color);
        anyhow::bail!(
            "record rejected by quality gate (score {:.2})",
            new_score.value
        );
    }

    // Quality caveat
    if new_score.value < 0.4 {
        quality::print_quality_caveat(&new_score, use_color);
    }

    // Update record
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    record.quality = new_score.clone();
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;

    proxy.put(key, &record).await?;

    println!(
        "Updated {key}  (quality: {:.2} -> {:.2})",
        score.value, new_score.value
    );
    Ok(())
}

// ── Shared helpers ───────────────────────────────────────────────────────────

fn eprint_prompt(msg: &str, use_color: bool) {
    if use_color {
        eprint!("{}{}{}", cli::colors::BLUE, msg, cli::colors::RESET);
    } else {
        eprint!("{msg}");
    }
    let _ = io::stderr().flush();
}

fn read_line(lines: &mut io::Lines<io::StdinLock<'_>>) -> Result<String> {
    match lines.next() {
        Some(Ok(line)) => Ok(line.trim().to_string()),
        Some(Err(e)) => Err(e.into()),
        None => Ok(String::new()),
    }
}
