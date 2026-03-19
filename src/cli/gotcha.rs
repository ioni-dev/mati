use std::io::{self, BufRead, IsTerminal, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::{Args, Subcommand};
use slugify::slugify;

use mati_core::graph::{EdgeKind, Graph};
use mati_core::health::quality;
use mati_core::store::{
    Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore, Store,
};

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
        GotchaCommand::Add { file } => run_gotcha_add(&file).await,
    }
}

async fn run_gotcha_add(file: &str) -> Result<()> {
    let use_color = io::stderr().is_terminal();
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    // ── Prompted template ────────────────────────────────────────────────────
    // Prompts go to stderr so piped input works cleanly.

    eprint_prompt("Rule (imperative — what MUST Claude do/avoid): ", use_color);
    let rule = read_line(&mut lines)?;
    if rule.is_empty() {
        anyhow::bail!("rule cannot be empty");
    }

    eprint_prompt("Reason (why — what goes wrong otherwise): ", use_color);
    let reason = read_line(&mut lines)?;

    eprint_prompt("Severity (low/normal/high/critical) [normal]: ", use_color);
    let severity_input = read_line(&mut lines)?;
    let severity = parse_severity(&severity_input);

    eprint_prompt(
        &format!("Affected files (comma-separated) [{file}]: "),
        use_color,
    );
    let files_input = read_line(&mut lines)?;
    let affected_files: Vec<String> = if files_input.is_empty() {
        vec![file.to_string()]
    } else {
        files_input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    eprint_prompt("Reference URL (optional): ", use_color);
    let ref_url_input = read_line(&mut lines)?;
    let ref_url = if ref_url_input.is_empty() {
        None
    } else {
        Some(ref_url_input)
    };

    // ── Construct record ─────────────────────────────────────────────────────

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let slug = slugify!(&rule, max_length = 40);
    let key = format!("gotcha:{slug}");

    let gotcha = GotchaRecord {
        rule: rule.clone(),
        reason: reason.clone(),
        severity: severity.clone(),
        affected_files: affected_files.clone(),
        ref_url: ref_url.clone(),
        discovered_session: now,
        confirmed: true,
    };

    // Build the value from rule + reason for quality analysis
    let value = if reason.is_empty() {
        rule.clone()
    } else {
        format!("{rule} because {reason}")
    };

    let device_id = uuid::Uuid::new_v4();
    let mut record = Record {
        key: key.clone(),
        value: serde_json::to_string(&gotcha)?,
        category: Category::Gotcha,
        priority: severity,
        tags: vec![],
        created_at: now,
        updated_at: now,
        ref_url,
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
    };

    // ── Quality analysis ─────────────────────────────────────────────────────

    // Analyze quality on a clone with the human-readable text, not the JSON
    // serialization. The stored record keeps the GotchaRecord JSON in `value`
    // (expected by ls_gotchas and the MCP layer).
    let score = {
        let mut qa_record = record.clone();
        qa_record.value = value;
        quality::analyze(&qa_record)
    };
    record.quality = score.clone();

    // Quality gate (< 0.2 → reject)
    if quality::below_quality_gate(&score) {
        quality::print_quality_gate_error(&score, use_color);
        anyhow::bail!("record rejected by quality gate (score {:.2})", score.value);
    }

    // Quality caveat (0.2–0.4 → warn)
    if score.value < 0.4 {
        quality::print_quality_caveat(&score, use_color);
    }

    // ── Write to store ───────────────────────────────────────────────────────

    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    store.put(&key, &record).await?;

    // ── Add graph edges ──────────────────────────────────────────────────────

    let mut graph = Graph::load(store).await?;
    for af in &affected_files {
        let file_key = format!("file:{af}");
        graph
            .add_edge(&file_key, EdgeKind::HasGotcha, &key)
            .await?;
    }

    // ── Output ───────────────────────────────────────────────────────────────

    println!("Created {key}  (quality: {:.2}, confidence: {:.2})", score.value, record.confidence.value);
    for af in &affected_files {
        println!("  -> file:{af} HasGotcha {key}");
    }

    graph.close().await?;
    Ok(())
}

fn eprint_prompt(msg: &str, use_color: bool) {
    if use_color {
        eprint!(
            "{}{}{} ",
            crate::cli::colors::BLUE,
            msg,
            crate::cli::colors::RESET
        );
    } else {
        eprint!("{msg} ");
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

fn parse_severity(input: &str) -> Priority {
    match input.to_lowercase().trim() {
        "low" => Priority::Low,
        "high" => Priority::High,
        "critical" | "crit" => Priority::Critical,
        _ => Priority::Normal,
    }
}
