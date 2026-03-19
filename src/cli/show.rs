use anyhow::Result;
use clap::Args;
use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, Color, ContentArrangement, Table};
use std::io::IsTerminal as _;
use std::path::PathBuf;

use mati_core::store::{
    Category, ConfidenceScore, FileRecord, Priority, QualitySignal, QualityTier, Record,
    RecordLifecycle, RecordSource, StalenessTier, Store,
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
        None => anyhow::bail!("no record found for key '{}'", args.key),
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
    println!(
        "    device      {gray}{}{reset}",
        record.version.device_id
    );
    println!(
        "    clock       {gray}logical={} wall={}{reset}",
        record.version.logical_clock,
        format_ts(record.version.wall_clock),
    );
    println!();
}

// ── run_ls (M-08-C/D/E) ─────────────────────────────────────────────────────

pub async fn run_ls(args: LsArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    let use_color = std::io::stdout().is_terminal();

    match args.category.as_deref() {
        Some("files") => ls_files(&store, use_color).await?,
        Some("gotchas") => ls_gotchas(&store, use_color).await?,
        Some("decisions") => ls_decisions(&store, use_color).await?,
        Some(other) => anyhow::bail!(
            "unknown category '{other}'. Valid: files, gotchas, decisions"
        ),
        None => {
            ls_files(&store, use_color).await?;
            println!();
            ls_gotchas(&store, use_color).await?;
            println!();
            ls_decisions(&store, use_color).await?;
        }
    }
    Ok(())
}

async fn ls_files(store: &Store, _use_color: bool) -> Result<()> {
    let records = store.scan_prefix("file:").await?;
    if records.is_empty() {
        println!("No file records found.");
        return Ok(());
    }

    // Parse FileRecord from each record's value for display purposes.
    // Sort: hotspots first, then by path.
    let mut rows: Vec<(String, String, usize, f32, f32, bool)> = Vec::new();
    for r in &records {
        let path = r.key.strip_prefix("file:").unwrap_or(&r.key);
        let (purpose, entry_count, is_hotspot) = match serde_json::from_str::<FileRecord>(&r.value)
        {
            Ok(fr) => {
                let purpose = if fr.purpose.is_empty() {
                    "(pending enrichment)".to_string()
                } else {
                    truncate(&fr.purpose, 40)
                };
                (purpose, fr.entry_points.len(), fr.is_hotspot)
            }
            Err(_) => {
                let purpose = if r.value.is_empty() {
                    "(pending enrichment)".to_string()
                } else {
                    truncate(&r.value, 40)
                };
                (purpose, 0, false)
            }
        };
        rows.push((
            path.to_string(),
            purpose,
            entry_count,
            r.confidence.value,
            r.quality.value,
            is_hotspot,
        ));
    }

    // Sort: hotspots first, then alphabetical by path
    rows.sort_by(|a, b| b.5.cmp(&a.5).then_with(|| a.0.cmp(&b.0)));

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Path"),
            Cell::new("Purpose"),
            Cell::new("Entries"),
            Cell::new("Conf"),
            Cell::new("Qual"),
            Cell::new("Hot"),
        ]);

    for (path, purpose, entries, conf, qual, hot) in &rows {
        table.add_row(vec![
            Cell::new(path),
            Cell::new(purpose),
            Cell::new(entries),
            Cell::new(format!("{conf:.2}")).fg(score_comfy_color(*conf)),
            Cell::new(format!("{qual:.2}")).fg(score_comfy_color(*qual)),
            Cell::new(if *hot { "*" } else { "" }),
        ]);
    }

    println!("{table}");
    println!("  {} file records", records.len());
    Ok(())
}

async fn ls_gotchas(store: &Store, _use_color: bool) -> Result<()> {
    let mut records = store.scan_prefix("gotcha:").await?;
    if records.is_empty() {
        println!("No gotcha records found.");
        return Ok(());
    }

    // Sort by confidence * priority_weight descending
    records.sort_by(|a, b| {
        let score_a = a.confidence.value * priority_weight(&a.priority);
        let score_b = b.confidence.value * priority_weight(&b.priority);
        score_b
            .partial_cmp(&score_a)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Key"),
            Cell::new("Rule"),
            Cell::new("Sev"),
            Cell::new("Conf"),
            Cell::new("Qual"),
            Cell::new("Confirmed"),
        ]);

    for r in &records {
        let key_short = r.key.strip_prefix("gotcha:").unwrap_or(&r.key);
        let (rule, confirmed) = match serde_json::from_str::<mati_core::store::GotchaRecord>(&r.value) {
            Ok(gr) => (truncate(&gr.rule, 40), gr.confirmed),
            Err(_) => (truncate(&r.value, 40), false),
        };
        let sev = priority_short(&r.priority);
        table.add_row(vec![
            Cell::new(key_short),
            Cell::new(&rule),
            Cell::new(sev).fg(priority_comfy_color(&r.priority)),
            Cell::new(format!("{:.2}", r.confidence.value)).fg(score_comfy_color(r.confidence.value)),
            Cell::new(format!("{:.2}", r.quality.value)).fg(score_comfy_color(r.quality.value)),
            Cell::new(if confirmed { "Y" } else { "-" }),
        ]);
    }

    println!("{table}");
    println!("  {} gotcha records", records.len());
    Ok(())
}

async fn ls_decisions(store: &Store, _use_color: bool) -> Result<()> {
    let mut records = store.scan_prefix("decision:").await?;
    if records.is_empty() {
        println!("No decision records found.");
        return Ok(());
    }

    // Sort by updated_at descending
    records.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Key"),
            Cell::new("Value"),
            Cell::new("Pri"),
            Cell::new("Conf"),
            Cell::new("Qual"),
            Cell::new("Updated"),
        ]);

    for r in &records {
        let key_short = r.key.strip_prefix("decision:").unwrap_or(&r.key);
        table.add_row(vec![
            Cell::new(key_short),
            Cell::new(truncate(&r.value, 40)),
            Cell::new(priority_short(&r.priority)).fg(priority_comfy_color(&r.priority)),
            Cell::new(format!("{:.2}", r.confidence.value)).fg(score_comfy_color(r.confidence.value)),
            Cell::new(format!("{:.2}", r.quality.value)).fg(score_comfy_color(r.quality.value)),
            Cell::new(format_date(r.updated_at)),
        ]);
    }

    println!("{table}");
    println!("  {} decision records", records.len());
    Ok(())
}

// ── run_export (M-08-M) ─────────────────────────────────────────────────────

pub async fn run_export(args: ExportArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;

    let output = match args.format.as_str() {
        "json" => export_json(&store).await?,
        "md" => export_md(&store).await?,
        other => anyhow::bail!("unknown format '{other}'. Valid: md, json"),
    };

    match args.output {
        Some(path) => std::fs::write(&path, &output)?,
        None => print!("{output}"),
    }
    Ok(())
}

async fn export_json(store: &Store) -> Result<String> {
    let mut all: Vec<Record> = Vec::new();
    for prefix in &["gotcha:", "decision:", "file:", "stage:", "dev_note:", "dep:"] {
        all.extend(store.scan_prefix(prefix).await?);
    }
    Ok(serde_json::to_string_pretty(&all)?)
}

async fn export_md(store: &Store) -> Result<String> {
    let mut out = String::from("# mati knowledge export\n\n");

    let sections: &[(&str, &str)] = &[
        ("gotcha:", "Gotchas"),
        ("decision:", "Decisions"),
        ("file:", "Files"),
        ("dev_note:", "Notes"),
        ("dep:", "Dependencies"),
    ];

    for &(prefix, heading) in sections {
        let records = store.scan_prefix(prefix).await?;
        if records.is_empty() {
            continue;
        }
        out.push_str(&format!("## {heading}\n\n"));
        for r in &records {
            out.push_str(&format!("### {}\n\n", r.key));
            if !r.value.is_empty() {
                out.push_str(&r.value);
                out.push_str("\n\n");
            }
            out.push_str(&format!(
                "- priority: {:?}\n- confidence: {:.2}\n- quality: {:.2}\n- source: {:?}\n\n",
                r.priority, r.confidence.value, r.quality.value, r.source
            ));
        }
    }

    Ok(out)
}

// ── run_import (M-08-N) ─────────────────────────────────────────────────────

pub async fn run_import(args: ImportArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;

    let path = &args.file;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    match ext {
        "json" => {
            let content = std::fs::read_to_string(path)?;
            let records: Vec<Record> = serde_json::from_str(&content)?;
            let pairs: Vec<(&str, &Record)> =
                records.iter().map(|r| (r.key.as_str(), r)).collect();
            store.put_batch(&pairs).await?;
            println!("Imported {} records from JSON.", records.len());
        }
        "md" => {
            let device_id = uuid::Uuid::new_v4();
            let import = mati_core::analysis::import_claude_md(path, device_id, 1)?;
            let pairs: Vec<(&str, &Record)> = import
                .records
                .iter()
                .map(|r| (r.key.as_str(), r))
                .collect();
            store.put_batch(&pairs).await?;
            println!(
                "Imported {} records from CLAUDE.md.",
                import.records.len()
            );
        }
        _ => {
            // Try JSON first, fall back to CLAUDE.md import
            let content = std::fs::read_to_string(path)?;
            if content.trim_start().starts_with('[') || content.trim_start().starts_with('{') {
                let records: Vec<Record> = serde_json::from_str(&content)?;
                let pairs: Vec<(&str, &Record)> =
                    records.iter().map(|r| (r.key.as_str(), r)).collect();
                store.put_batch(&pairs).await?;
                println!("Imported {} records from JSON.", records.len());
            } else {
                let device_id = uuid::Uuid::new_v4();
                let import = mati_core::analysis::import_claude_md(path, device_id, 1)?;
                let pairs: Vec<(&str, &Record)> = import
                    .records
                    .iter()
                    .map(|r| (r.key.as_str(), r))
                    .collect();
                store.put_batch(&pairs).await?;
                println!(
                    "Imported {} records from CLAUDE.md.",
                    import.records.len()
                );
            }
        }
    }
    Ok(())
}

// ── run_history (M-14-C stub) ────────────────────────────────────────────────

pub async fn run_history(_args: HistoryArgs) -> Result<()> {
    Err(anyhow::anyhow!("mati history not yet implemented (M-14-C)"))
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
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
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

fn truncate(s: &str, max: usize) -> String {
    let first_line = s.lines().next().unwrap_or(s);
    if first_line.len() <= max {
        first_line.to_string()
    } else {
        format!("{}...", &first_line[..max - 3])
    }
}

fn priority_weight(p: &Priority) -> f32 {
    match p {
        Priority::Low => 0.5,
        Priority::Normal => 1.0,
        Priority::High => 1.5,
        Priority::Critical => 2.0,
    }
}

fn priority_short(p: &Priority) -> &'static str {
    match p {
        Priority::Low => "Low",
        Priority::Normal => "Norm",
        Priority::High => "High",
        Priority::Critical => "Crit",
    }
}

fn score_comfy_color(v: f32) -> Color {
    if v >= 0.6 {
        Color::Green
    } else if v >= 0.3 {
        Color::Yellow
    } else {
        Color::Red
    }
}

fn priority_comfy_color(p: &Priority) -> Color {
    match p {
        Priority::Critical => Color::Red,
        Priority::High => Color::Yellow,
        Priority::Normal => Color::White,
        Priority::Low => Color::Grey,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

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
        assert_eq!(format_ts(19737 * 86400), "2024-01-15 00:00:00 UTC");
    }

    #[test]
    fn format_ts_hms_components() {
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
        assert_eq!(days_to_ymd(19782), (2024, 2, 29));
    }

    #[test]
    fn days_to_ymd_post_feb_non_leap_2023_03_01() {
        assert_eq!(days_to_ymd(19417), (2023, 3, 1));
    }

    #[test]
    fn days_to_ymd_year_boundary_dec_31() {
        assert_eq!(days_to_ymd(19722), (2023, 12, 31));
    }

    #[test]
    fn days_to_ymd_new_year_2024_01_01() {
        assert_eq!(days_to_ymd(19723), (2024, 1, 1));
    }

    #[test]
    fn days_to_ymd_consistent_with_format_ts() {
        let ts = 19737_u64 * 86400;
        let (y, mo, d) = days_to_ymd(ts / 86400);
        assert_eq!((y, mo, d), (2024, 1, 15));
        assert!(format_ts(ts).starts_with("2024-01-15"));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("hello world this is long", 10), "hello w...");
    }

    #[test]
    fn truncate_multiline() {
        assert_eq!(truncate("first line\nsecond line", 40), "first line");
    }

    #[test]
    fn format_date_zero() {
        assert_eq!(format_date(0), "\u{2014}");
    }

    #[test]
    fn format_date_known() {
        assert_eq!(format_date(19737 * 86400), "2024-01-15");
    }
}
