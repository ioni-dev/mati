use anyhow::Result;
use clap::Args;
use std::io::IsTerminal as _;
use std::path::PathBuf;

use mati_core::store::{
    Category, ConfidenceScore, Priority, QualitySignal, QualityTier, Record, RecordLifecycle,
    RecordSource, StalenessTier, Store,
};

use super::colors;

// ── Arg types ─────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct ShowArgs {
    /// Record key (e.g., "file:src/main.rs", "gotcha:inference-async")
    pub key: String,
}

#[derive(Args)]
pub struct LsArgs {
    /// Category to list: files, gotchas, decisions (omit for all)
    pub category: Option<String>,
}

#[derive(Args)]
pub struct HistoryArgs {
    /// Record key
    pub key: String,

    /// Show records changed in time window (e.g., "2w", "30d")
    #[arg(long)]
    pub since: Option<String>,
}

#[derive(Args)]
pub struct ExportArgs {
    /// Output format: md or json
    #[arg(long, default_value = "md")]
    pub format: String,

    /// Output file (defaults to stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct ImportArgs {
    /// Path to CLAUDE.md or JSON file
    pub file: PathBuf,
}

// ── run_show ──────────────────────────────────────────────────────────────────

pub async fn run_show(args: ShowArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;

    let record = match store.get(&args.key).await? {
        Some(r) => r,
        // Fix 1: anyhow::bail! instead of process::exit — allows Store drop to run.
        None => anyhow::bail!("no record found for key '{}'", args.key),
    };

    let use_color = std::io::stdout().is_terminal();
    print_record(&record, use_color);
    Ok(())
}

fn print_record(record: &Record, use_color: bool) {
    // Fix 3: rebind colour names to empty strings when stdout is not a TTY so
    // piped output (mati show key | grep ...) is free of escape sequences.
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

    // Wrap colour helpers so they also respect use_color.
    let sc = |v: f32| -> &'static str {
        if use_color { score_color(v) } else { "" }
    };
    let stc = |tier: &StalenessTier| -> &'static str {
        if use_color { staleness_color(tier) } else { "" }
    };
    let pc = |prio: &Priority| -> &'static str {
        if use_color { priority_color(prio) } else { "" }
    };
    let cc = |cat: &Category| -> &'static str {
        if use_color { category_color(cat) } else { "" }
    };

    // ── Header ────────────────────────────────────────────────────────────────

    let cat_label = category_label(&record.category);
    let cat_color = cc(&record.category);
    println!("\n{bold}{cat_color}{cat_label}{reset}  {bold}{white}{key}{reset}", key = record.key);

    // Fix 2: use imported RecordLifecycle consistently across all arms.
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
    println!("    confirmations  {white}{}{reset}", conf.confirmation_count);
    println!("    contributors   {white}{}{reset}", conf.contributor_count);
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
        // Fix 4: human-readable signal labels instead of Debug formatting.
        let sigs: Vec<&str> = qual.signals.iter().map(signal_label).collect();
        println!("    signals  {gray}{}{reset}", sigs.join(", "));
    }
    println!();

    // ── Staleness ─────────────────────────────────────────────────────────────

    let stale = &record.staleness;
    let stale_color = stc(&stale.tier);
    let stale_tier = staleness_tier_label(&stale.tier);

    println!("{blue}  staleness{reset}");
    println!("    value  {stale_color}{:.2}{reset}  {gray}({stale_tier}){reset}", stale.value);
    if !stale.last_record_sha.is_empty() {
        println!(
            "    last sha  {gray}{}{reset}",
            &stale.last_record_sha[..stale.last_record_sha.len().min(12)]
        );
    }
    println!();

    // ── Metadata ──────────────────────────────────────────────────────────────

    let prio_color = pc(&record.priority);
    println!("{blue}  metadata{reset}");
    println!("    priority    {prio_color}{:?}{reset}", record.priority);
    println!("    source      {gray}{}{reset}", source_label(&record.source));
    println!("    created     {gray}{}{reset}", format_ts(record.created_at));
    println!("    updated     {gray}{}{reset}", format_ts(record.updated_at));
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
        println!("    gap score   {yellow}{:.3}{reset}", record.gap_analysis_score);
    }
    println!("    device      {gray}{}{reset}", record.version.device_id);
    println!(
        "    clock       {gray}logical={} wall={}{reset}",
        record.version.logical_clock,
        format_ts(record.version.wall_clock),
    );
    println!();
}

// ── Display helpers ───────────────────────────────────────────────────────────

/// Hook injection tier label — confidence axis only.
///
/// For `gotcha:*` records, injection additionally requires `confirmed=true`
/// and `quality >= 0.4` (CLAUDE.md Hook Decision Matrix).
fn hook_tier_label(value: f32) -> &'static str {
    if value >= 0.6 {
        "injects — deny file read (gotcha: also needs confirmed + quality>=0.4)"
    } else if value >= 0.3 {
        "attaches as additionalContext"
    } else {
        "allows read, no injection"
    }
}

fn score_color(v: f32) -> &'static str {
    if v >= 0.6 { colors::GREEN } else if v >= 0.3 { colors::YELLOW } else { colors::RED }
}

fn staleness_color(tier: &StalenessTier) -> &'static str {
    match tier {
        StalenessTier::Fresh | StalenessTier::Aging => colors::GREEN,
        StalenessTier::Stale => colors::YELLOW,
        StalenessTier::Liability | StalenessTier::Tombstone => colors::RED,
    }
}

fn staleness_tier_label(tier: &StalenessTier) -> &'static str {
    match tier {
        StalenessTier::Fresh => "Fresh",
        StalenessTier::Aging => "Aging",
        StalenessTier::Stale => "Stale",
        StalenessTier::Liability => "Liability — blocks injection",
        StalenessTier::Tombstone => "Tombstone — excluded entirely",
    }
}

fn quality_tier_label(tier: &QualityTier) -> &'static str {
    match tier {
        QualityTier::Suppressed => "Suppressed — never injected",
        QualityTier::Poor => "Poor — injected with caveat",
        QualityTier::Acceptable => "Acceptable",
        QualityTier::Good => "Good — prioritised in bootstrap",
        QualityTier::Excellent => "Excellent",
    }
}

fn category_label(cat: &Category) -> &'static str {
    match cat {
        Category::Gotcha => "gotcha",
        Category::File => "file",
        Category::Decision => "decision",
        Category::Stage => "stage",
        Category::Dependency => "dependency",
        Category::DevNote => "dev_note",
        Category::Session => "session",
        Category::Analytics => "analytics",
    }
}

fn category_color(cat: &Category) -> &'static str {
    match cat {
        Category::Gotcha => colors::RED,
        Category::File => colors::CYAN,
        Category::Decision => colors::PURPLE,
        Category::Stage => colors::BLUE,
        Category::Dependency => colors::YELLOW,
        Category::DevNote => colors::WHITE,
        Category::Session | Category::Analytics => colors::GRAY,
    }
}

fn priority_color(p: &Priority) -> &'static str {
    match p {
        Priority::Critical => colors::RED,
        Priority::High => colors::YELLOW,
        Priority::Normal => colors::WHITE,
        Priority::Low => colors::GRAY,
    }
}

fn source_label(src: &RecordSource) -> &'static str {
    match src {
        RecordSource::StaticAnalysis => "StaticAnalysis (Layer 0)",
        RecordSource::ClaudeEnrich => "ClaudeEnrich (Layer 1)",
        RecordSource::SessionHook => "SessionHook (Layer 2)",
        RecordSource::DeveloperManual => "DeveloperManual",
        RecordSource::Import => "Import",
    }
}

/// Fix 4: human-readable label for each QualitySignal variant.
/// Penalty signals are suffixed with "[penalty]" to distinguish them from
/// positive signals at a glance.
fn signal_label(sig: &QualitySignal) -> &'static str {
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
fn format_ts(ts: u64) -> String {
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

/// Convert days since Unix epoch to `(year, month, day)`.
///
/// Uses the proleptic Gregorian algorithm from
/// <http://howardhinnant.github.io/date_algorithms.html>.
/// Only valid for dates >= 1970-01-01 (all mati timestamps are `u64`).
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    // z is always >= 719468 for Unix-epoch inputs, so all divisions are
    // positive and Rust's truncating integer division equals floor division.
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

// ── Stubs for future milestones ───────────────────────────────────────────────

pub async fn run_ls(_args: LsArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati ls not yet implemented (M-08-C/D/E)"))
}

pub async fn run_history(_args: HistoryArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati history not yet implemented (M-14-C)"))
}

pub async fn run_export(_args: ExportArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati export not yet implemented (M-08-M)"))
}

pub async fn run_import(_args: ImportArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati import not yet implemented (M-08-N)"))
}

// ── Tests — Fix 6 ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── format_ts ─────────────────────────────────────────────────────────────

    #[test]
    fn format_ts_zero_is_em_dash() {
        assert_eq!(format_ts(0), "\u{2014}");
    }

    #[test]
    fn format_ts_epoch_plus_one_second() {
        assert_eq!(format_ts(1), "1970-01-01 00:00:01 UTC");
    }

    #[test]
    fn format_ts_exactly_one_day() {
        assert_eq!(format_ts(86400), "1970-01-02 00:00:00 UTC");
    }

    #[test]
    fn format_ts_known_date_2024_01_15() {
        // 2024-01-15 00:00:00 UTC = 19737 * 86400
        assert_eq!(format_ts(19737 * 86400), "2024-01-15 00:00:00 UTC");
    }

    #[test]
    fn format_ts_hms_components() {
        // 1970-01-01 01:02:03 UTC = 3600 + 120 + 3 = 3723
        assert_eq!(format_ts(3723), "1970-01-01 01:02:03 UTC");
    }

    // ── days_to_ymd ───────────────────────────────────────────────────────────

    #[test]
    fn days_to_ymd_unix_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_2024_01_15() {
        assert_eq!(days_to_ymd(19737), (2024, 1, 15));
    }

    #[test]
    fn days_to_ymd_leap_day_2024_02_29() {
        // 2024 is a leap year: Jan(31) + 29 days into Feb = day 59 from Jan 1.
        // Jan 1 2024 = day 19723; Feb 29 = 19723 + 59 = 19782.
        assert_eq!(days_to_ymd(19782), (2024, 2, 29));
    }

    #[test]
    fn days_to_ymd_post_feb_non_leap_2023_03_01() {
        // 2023 is not a leap year. Mar 1 = Jan 1 + 31 + 28 = day 59 from Jan 1.
        // Jan 1 2023 = day 19358; Mar 1 = 19358 + 59 = 19417.
        assert_eq!(days_to_ymd(19417), (2023, 3, 1));
    }

    #[test]
    fn days_to_ymd_year_boundary_dec_31() {
        // 2023-12-31 = day before 2024-01-01.
        // Jan 1 2024 = day 19723, so Dec 31 2023 = day 19722.
        assert_eq!(days_to_ymd(19722), (2023, 12, 31));
    }

    #[test]
    fn days_to_ymd_new_year_2024_01_01() {
        assert_eq!(days_to_ymd(19723), (2024, 1, 1));
    }

    #[test]
    fn days_to_ymd_consistent_with_format_ts() {
        // Cross-check: days_to_ymd and format_ts agree on 2024-01-15.
        let ts = 19737_u64 * 86400;
        let (y, mo, d) = days_to_ymd(ts / 86400);
        assert_eq!((y, mo, d), (2024, 1, 15));
        assert!(format_ts(ts).starts_with("2024-01-15"));
    }
}
