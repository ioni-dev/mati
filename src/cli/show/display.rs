use super::*;
use clap::Args;

#[derive(Args)]
pub struct ShowArgs {
    /// Record key (e.g., "file:src/main.rs", "gotcha:inference-async")
    pub key: String,
}

#[derive(Args)]
pub struct LsArgs {
    /// Category to list: files, gotchas, decisions, notes, tombstoned (omit for all)
    pub category: Option<String>,

    /// Maximum file records to show (hotspots first; 0 = unlimited)
    #[arg(long, short = 'n', default_value = "200")]
    pub limit: usize,

    /// (tombstoned only) Time window — e.g. "30d", "7d", "12h". Defaults to "30d".
    #[arg(long)]
    pub recent: Option<String>,

    /// (tombstoned only) Directory filter — e.g. "src/cli". Required for the
    /// tombstoned category since negative exemplars are keyed by dirname.
    #[arg(long)]
    pub dir: Option<String>,

    /// (tombstoned only) Emit JSON instead of human-readable table.
    /// Designed for programmatic consumption by `/mati-enrich`'s Stage 2
    /// negative-exemplar retrieval.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct HistoryArgs {
    /// Record key (omit to list all recently changed records with --since)
    pub key: Option<String>,

    /// Show records changed in time window (e.g., "2h", "7d", "2w", "3m", "1y")
    #[arg(long)]
    pub since: Option<String>,

    /// Maximum entries to display
    #[arg(long, default_value = "50")]
    pub limit: usize,

    /// Show enforcement events instead of record history
    #[arg(long)]
    pub enforcement: bool,

    /// Filter enforcement events by type (deny, allow_receipt, receipt_minted, bypass, control_changed, config_changed, gap)
    #[arg(long, requires = "enforcement")]
    pub r#type: Option<String>,

    /// Filter enforcement events by subject file path
    #[arg(long, requires = "enforcement")]
    pub file: Option<String>,
}

#[derive(Args)]
pub struct ExportArgs {
    /// Output format: md or json
    #[arg(
        long,
        default_value = "md",
        long_help = "Output format:\n  md    Markdown with sections per category (gotchas, decisions, files, notes)\n  json  JSON array of Record objects. Each element contains: key, value, category,\n        confidence, quality, staleness_tier, lifecycle, payload, and version fields."
    )]
    pub format: String,

    /// Output file (defaults to stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct ImportArgs {
    /// Path to CLAUDE.md or JSON file
    #[arg(required_unless_present = "auto_memory")]
    pub file: Option<PathBuf>,

    /// Import Claude Code's auto-memory directory for this project
    /// (`~/.claude/projects/<slug>/memory/`) as dev notes
    #[arg(long, conflicts_with = "file")]
    pub auto_memory: bool,
}

// ── run_show ──────────────────────────────────────────────────────────────────

pub async fn run_show(args: ShowArgs) -> Result<()> {
    // Detect bare namespace prefix (e.g. "gotcha:", "file:", "decision:") and
    // redirect to `ls` — callers often type `mati show gotcha:` expecting a list.
    if args.key.ends_with(':') {
        let category = match args.key.trim_end_matches(':') {
            "gotcha" | "gotchas" => Some("gotchas".to_string()),
            "file" | "files" => Some("files".to_string()),
            "decision" | "decisions" => Some("decisions".to_string()),
            _ => None,
        };
        return run_ls(LsArgs {
            category,
            limit: 200,
            recent: None,
            dir: None,
            json: false,
        })
        .await;
    }

    let cwd = std::env::current_dir()?;
    let store = StoreProxy::open(&cwd).await?;

    let record = match store.get(&args.key).await? {
        Some(r) => r,
        None => anyhow::bail!(
            "no record found for key '{}'.\n\
             Run `mati ls` to see available records, or check key spelling.",
            args.key
        ),
    };

    let use_color = std::io::stdout().is_terminal();
    print_record(&record, use_color);
    Ok(())
}

fn print_record(record: &Record, use_color: bool) {
    let (red, yellow, _green, blue, _purple, gray, cyan, white, bold, reset) = if use_color {
        (
            colors::RED,
            colors::YELLOW,
            colors::GREEN,
            colors::BLUE,
            colors::PURPLE,
            colors::GRAY,
            colors::CYAN,
            colors::WHITE,
            colors::BOLD,
            colors::RESET,
        )
    } else {
        ("", "", "", "", "", "", "", "", "", "")
    };

    let sc = |v: f32| -> &'static str {
        if use_color {
            score_color(v)
        } else {
            ""
        }
    };
    let stc = |tier: &StalenessTier| -> &'static str {
        if use_color {
            staleness_color(tier)
        } else {
            ""
        }
    };
    let pc = |prio: &Priority| -> &'static str {
        if use_color {
            priority_color(prio)
        } else {
            ""
        }
    };
    let cc = |cat: &Category| -> &'static str {
        if use_color {
            category_color(cat)
        } else {
            ""
        }
    };

    // ── Header ────────────────────────────────────────────────────────────────

    let cat_label = category_label(&record.category);
    let cat_color = cc(&record.category);
    println!(
        "\n{bold}{cat_color}{cat_label}{reset}  {bold}{white}{key}{reset}",
        key = record.key
    );

    match &record.lifecycle {
        RecordLifecycle::Active => {}
        RecordLifecycle::Tombstoned { reason, .. } => {
            println!("  {red}[TOMBSTONED]{reset} {gray}{reason:?}{reset}");
        }
        RecordLifecycle::Superseded { by_key } => {
            println!("  {yellow}[SUPERSEDED]{reset} {gray}by {by_key}{reset}");
        }
    }

    println!();

    // ── Value ─────────────────────────────────────────────────────────────────

    println!("{blue}  value{reset}");
    for line in record.value.lines() {
        println!("    {white}{line}{reset}");
    }
    println!();

    // ── Confidence breakdown ──────────────────────────────────────────────────

    let conf = &record.confidence;
    let conf_val_color = sc(conf.value);
    let hook_label = hook_tier_label(conf.value);

    println!("{blue}  confidence{reset}");
    println!(
        "    value          {conf_val_color}{:.2}{reset}  {gray}({hook_label}){reset}",
        conf.value
    );
    println!(
        "    base (source)  {gray}{:.2}{reset}  {gray}— {source}{reset}",
        ConfidenceScore::base_for_source(&record.source),
        source = source_label(&record.source),
    );
    println!(
        "    confirmations  {white}{}{reset}",
        conf.confirmation_count
    );
    println!(
        "    contributors   {white}{}{reset}",
        conf.contributor_count
    );
    if conf.challenge_count > 0 {
        println!("    challenges     {yellow}{}{reset}", conf.challenge_count);
    }
    if let Some(ts) = conf.last_challenged {
        println!("    last challenged  {gray}{}{reset}", format_ts(ts));
    }
    println!();

    // ── Quality ───────────────────────────────────────────────────────────────

    let qual = &record.quality;
    let qual_val_color = sc(qual.value);
    let tier_label = quality_tier_label(&qual.tier);

    println!("{blue}  quality{reset}");
    println!(
        "    value    {qual_val_color}{:.2}{reset}  {gray}({tier_label}){reset}",
        qual.value
    );
    if !qual.signals.is_empty() {
        let sigs: Vec<&str> = qual.signals.iter().map(signal_label).collect();
        println!("    signals  {gray}{}{reset}", sigs.join(", "));
    }
    println!();

    // ── Staleness ─────────────────────────────────────────────────────────────

    let stale = &record.staleness;
    let stale_color = stc(&stale.tier);
    let stale_tier = staleness_tier_label(&stale.tier);

    println!("{blue}  staleness{reset}");
    println!(
        "    value  {stale_color}{:.2}{reset}  {gray}({stale_tier}){reset}",
        stale.value
    );
    if !stale.last_record_sha.is_empty() {
        println!(
            "    last sha  {gray}{}{reset}",
            &stale.last_record_sha[..stale.last_record_sha.len().min(12)]
        );
    }
    println!();

    // ── Blast radius (file records only) ────────────────────────────────────

    if record.category == Category::File {
        if let Some(fr) = record.payload_as::<FileRecord>() {
            if let Some(ref br) = fr.blast_radius {
                let tier_color = match br.tier {
                    mati_core::analysis::blast_radius::BlastTier::Critical => red,
                    mati_core::analysis::blast_radius::BlastTier::High => yellow,
                    _ => gray,
                };
                println!("{blue}  blast radius{reset}");
                println!("    direct         {white}{}{reset}", br.direct);
                println!("    transitive     {white}{}{reset}", br.transitive);
                println!("    score          {white}{:.1}{reset}", br.score);
                println!("    tier           {tier_color}{}{reset}", br.tier.label());
                println!();
            }
        }
    }

    // ── Payload (Analytics + DevNote — categories without a dedicated renderer
    //     above that still carry meaningful data in their JSON payload). Without
    //     this block, `mati show analytics:extraction:<slug>` shows only metadata
    //     and hides the per-extraction config / outcome / file_path / etc. that
    //     the SOTA pipeline writes. Pretty-printed JSON keeps it human-scannable
    //     without inventing a per-shape renderer for every analytics category.
    if matches!(record.category, Category::Analytics | Category::DevNote) {
        if let Some(ref payload) = record.payload {
            if !payload.is_null() {
                let pretty =
                    serde_json::to_string_pretty(payload).unwrap_or_else(|_| payload.to_string());
                println!("{blue}  payload{reset}");
                for line in pretty.lines() {
                    println!("    {gray}{line}{reset}");
                }
                println!();
            }
        }
    }

    // ── Metadata ──────────────────────────────────────────────────────────────

    let prio_color = pc(&record.priority);
    println!("{blue}  metadata{reset}");
    println!("    priority    {prio_color}{:?}{reset}", record.priority);
    println!(
        "    source      {gray}{}{reset}",
        source_label(&record.source)
    );
    println!(
        "    created     {gray}{}{reset}",
        format_ts(record.created_at)
    );
    println!(
        "    updated     {gray}{}{reset}",
        format_ts(record.updated_at)
    );
    if record.last_accessed > 0 {
        println!(
            "    accessed    {gray}{}{reset}  {gray}(x{}){reset}",
            format_ts(record.last_accessed),
            record.access_count,
        );
    }
    if let Some(url) = &record.ref_url {
        println!("    ref         {cyan}{url}{reset}");
    }
    if !record.tags.is_empty() {
        println!("    tags        {gray}{}{reset}", record.tags.join(", "));
    }
    if record.gap_analysis_score > 0.0 {
        println!(
            "    gap score   {yellow}{:.3}{reset}",
            record.gap_analysis_score
        );
    }
    println!("    device      {gray}{}{reset}", record.version.device_id);
    println!(
        "    clock       {gray}logical={} wall={}{reset}",
        record.version.logical_clock,
        format_ts(record.version.wall_clock),
    );
    println!();
}

// ── Display helpers (pub(crate) for reuse by status, quality-check, etc.) ────

pub(crate) fn hook_tier_label(value: f32) -> &'static str {
    if value >= 0.6 {
        "injects — deny file read (gotcha: also needs confirmed + quality>=0.4)"
    } else if value >= 0.3 {
        "attaches as additionalContext"
    } else {
        "allows read, no injection"
    }
}

pub(crate) fn score_color(v: f32) -> &'static str {
    if v >= 0.6 {
        colors::GREEN
    } else if v >= 0.3 {
        colors::YELLOW
    } else {
        colors::RED
    }
}

pub(crate) fn staleness_color(tier: &StalenessTier) -> &'static str {
    match tier {
        StalenessTier::Fresh | StalenessTier::Aging => colors::GREEN,
        StalenessTier::Stale => colors::YELLOW,
        StalenessTier::Liability | StalenessTier::Tombstone => colors::RED,
    }
}

pub(crate) fn staleness_tier_label(tier: &StalenessTier) -> &'static str {
    match tier {
        StalenessTier::Fresh => "Fresh",
        StalenessTier::Aging => "Aging",
        StalenessTier::Stale => "Stale",
        StalenessTier::Liability => "Liability — blocks injection",
        StalenessTier::Tombstone => "Tombstone — excluded entirely",
    }
}

pub(crate) fn quality_tier_label(tier: &QualityTier) -> &'static str {
    match tier {
        QualityTier::Suppressed => "Suppressed — never injected",
        QualityTier::Poor => "Poor — injected with caveat",
        QualityTier::Acceptable => "Acceptable",
        QualityTier::Good => "Good — prioritised in bootstrap",
        QualityTier::Excellent => "Excellent",
    }
}

pub(crate) fn category_label(cat: &Category) -> &'static str {
    match cat {
        Category::Gotcha => "gotcha",
        Category::File => "file",
        Category::Decision => "decision",
        Category::Stage => "stage",
        Category::Dependency => "dependency",
        Category::DevNote => "dev_note",
        Category::Session => "session",
        Category::Analytics => "analytics",
        Category::Policy => "policy",
    }
}

pub(crate) fn category_color(cat: &Category) -> &'static str {
    match cat {
        Category::Gotcha => colors::RED,
        Category::File => colors::CYAN,
        Category::Decision => colors::PURPLE,
        Category::Stage => colors::BLUE,
        Category::Dependency => colors::YELLOW,
        Category::DevNote => colors::WHITE,
        Category::Session | Category::Analytics => colors::GRAY,
        Category::Policy => colors::PURPLE,
    }
}

pub(crate) fn priority_color(p: &Priority) -> &'static str {
    match p {
        Priority::Critical => colors::RED,
        Priority::High => colors::YELLOW,
        Priority::Normal => colors::WHITE,
        Priority::Low => colors::GRAY,
    }
}

pub(crate) fn source_label(src: &RecordSource) -> &'static str {
    match src {
        RecordSource::StaticAnalysis => "StaticAnalysis (Layer 0)",
        RecordSource::ClaudeEnrich => "ClaudeEnrich (Layer 1)",
        RecordSource::SessionHook => "SessionHook (Layer 2)",
        RecordSource::DeveloperManual => "DeveloperManual",
        RecordSource::Import => "Import",
    }
}

/// Compact source label for inline trust cues in explain/diff output.
pub(crate) fn source_short(src: &RecordSource) -> &'static str {
    match src {
        RecordSource::DeveloperManual => "developer",
        RecordSource::Import => "imported",
        RecordSource::ClaudeEnrich => "enriched",
        RecordSource::SessionHook => "session",
        RecordSource::StaticAnalysis => "auto-detected",
    }
}

pub(crate) fn signal_label(sig: &QualitySignal) -> &'static str {
    match sig {
        QualitySignal::HasImperativeVerb => "imperative verb",
        QualitySignal::HasCausality => "causality",
        QualitySignal::HasSeveritySet => "severity set",
        QualitySignal::HasReference => "reference",
        QualitySignal::RuleLengthAdequate => "rule length ok",
        QualitySignal::ReasonLengthAdequate => "reason length ok",
        QualitySignal::AffectedFilesSpecified => "affected files",
        QualitySignal::HasSpecificIdentifier => "specific identifier",
        QualitySignal::VaguePhrasing => "vague phrasing [penalty]",
        QualitySignal::NoActionableRule => "no actionable rule [penalty]",
        QualitySignal::NoReason => "no reason [penalty]",
        QualitySignal::TooShort => "too short [penalty]",
        QualitySignal::DuplicatesFilePurpose => "duplicates file purpose [penalty]",
    }
}

/// Format a Unix timestamp (seconds) as `YYYY-MM-DD HH:MM:SS UTC`.
/// Returns `"—"` for the sentinel value `0`.
pub(crate) fn format_ts(ts: u64) -> String {
    if ts == 0 {
        return "\u{2014}".to_string();
    }
    let days = ts / 86400;
    let rem = ts % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

/// Format a Unix timestamp as just `YYYY-MM-DD`.
pub(crate) fn format_date(ts: u64) -> String {
    if ts == 0 {
        return "\u{2014}".to_string();
    }
    let days = ts / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}")
}

/// Convert days since Unix epoch to `(year, month, day)`.
pub(super) fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

// ── Table helper functions ───────────────────────────────────────────────────

/// Truncate a string to `max` display characters, appending "..." if truncated.
///
/// UTF-8 safe: uses `char_indices` to find the correct byte boundary so
/// multi-byte characters are never split.
pub(crate) fn truncate(s: &str, max: usize) -> String {
    let first_line = s.lines().next().unwrap_or(s);
    if max < 4 {
        // Too small for "..." — just return what fits
        return first_line.chars().take(max).collect();
    }
    // Check whether the first line fits within `max` characters
    let char_count = first_line.chars().count();
    if char_count <= max {
        return first_line.to_string();
    }
    // Find the byte index where we need to cut (max - 3 characters for "...")
    let target_chars = max - 3;
    let byte_end = first_line
        .char_indices()
        .nth(target_chars)
        .map(|(i, _)| i)
        .unwrap_or(first_line.len());
    format!("{}...", &first_line[..byte_end])
}

pub(super) fn priority_weight(p: &Priority) -> f32 {
    match p {
        Priority::Low => 0.5,
        Priority::Normal => 1.0,
        Priority::High => 1.5,
        Priority::Critical => 2.0,
    }
}

pub(super) fn priority_short(p: &Priority) -> &'static str {
    match p {
        Priority::Low => "Low",
        Priority::Normal => "Norm",
        Priority::High => "High",
        Priority::Critical => "Crit",
    }
}

pub(super) fn score_comfy_color(v: f32) -> Color {
    if v >= 0.6 {
        Color::Green
    } else if v >= 0.3 {
        Color::Yellow
    } else {
        Color::Red
    }
}

pub(super) fn priority_comfy_color(p: &Priority) -> Color {
    match p {
        Priority::Critical => Color::Red,
        Priority::High => Color::Yellow,
        Priority::Normal => Color::White,
        Priority::Low => Color::Grey,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────
