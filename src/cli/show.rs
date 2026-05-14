use anyhow::Result;
use clap::Args;
use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, Color, ContentArrangement, Table};
use serde::{Deserialize, Serialize};
use std::io::IsTerminal as _;
use std::path::PathBuf;

use mati_core::store::{
    Category, ConfidenceScore, FileRecord, Priority, QualityScore, QualitySignal, QualityTier,
    Record, RecordLifecycle, RecordSource, RecordVersion, StalenessScore, StalenessTier,
};

use super::colors;
use super::proxy::StoreProxy;

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

    /// Maximum file records to show (hotspots first; 0 = unlimited)
    #[arg(long, short = 'n', default_value = "200")]
    pub limit: usize,
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
    pub file: PathBuf,
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

// ── ls cache types ────────────────────────────────────────────────────────────

/// Pre-sorted display row for a single file record.
#[derive(Serialize, Deserialize)]
struct LsFileRow {
    path: String,
    purpose: String,
    entry_count: usize,
    confidence: f32,
    quality: f32,
    is_hotspot: bool,
}

/// Write-seq-invalidated cache for `mati ls files`.
///
/// Cache key: `analytics:ls_files_cache`.
/// Valid when `write_seq == store.read_write_seq()` AND `limit == requested_limit`.
#[derive(Serialize, Deserialize)]
struct LsFilesCache {
    write_seq: u64,
    /// The `--limit` value used when this cache was built.
    limit: usize,
    /// Total file records in the store (shown in the footer even when truncated).
    total: usize,
    rows: Vec<LsFileRow>,
}

/// Build a minimal analytics Record for caching ls output.
fn ls_cache_record(key: &str, value: String) -> Record {
    let now = now_secs();
    Record {
        key: key.to_string(),
        value,
        category: Category::Analytics,
        priority: Priority::Normal,
        tags: vec![],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: now,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::SessionHook,
        confidence: ConfidenceScore::for_new_record(&RecordSource::SessionHook),
        gap_analysis_score: 0.0,
        payload: None,
    }
}

// ── run_ls (M-08-C/D/E) ─────────────────────────────────────────────────────

pub async fn run_ls(args: LsArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = StoreProxy::open(&cwd).await?;
    let use_color = std::io::stdout().is_terminal();
    let limit = args.limit;

    match args.category.as_deref() {
        Some("files") => ls_files(&store, use_color, limit).await?,
        Some("gotchas") => ls_gotchas(&store, use_color).await?,
        Some("decisions") => ls_decisions(&store, use_color).await?,
        Some("notes") | Some("note") | Some("dev_note") | Some("dev_notes") => {
            ls_notes(&store, use_color).await?
        }
        Some(other) => {
            anyhow::bail!("unknown category '{other}'. Valid: files, gotchas, decisions, notes")
        }
        None => {
            ls_files(&store, use_color, limit).await?;
            println!();
            ls_gotchas(&store, use_color).await?;
            println!();
            ls_decisions(&store, use_color).await?;
            println!();
            ls_notes(&store, use_color).await?;
        }
    }
    Ok(())
}

const LS_FILES_CACHE_KEY: &str = "analytics:ls_files_cache";

async fn ls_files(store: &StoreProxy, _use_color: bool, limit: usize) -> Result<()> {
    // ── Cache check ───────────────────────────────────────────────────────
    let current_seq = store.read_write_seq();
    if let Some(cached) = store.get(LS_FILES_CACHE_KEY).await? {
        if let Some(entry) = cached.payload_as::<LsFilesCache>() {
            if entry.write_seq == current_seq && entry.limit == limit {
                render_ls_files_table(&entry.rows, entry.total, limit);
                return Ok(());
            }
        }
    }

    // ── Cold path: streaming scan ──────────────────────────────────────────
    // Print the header immediately so the user sees output before the full
    // scan completes. Rows are printed in store (lexicographic) order as they
    // arrive; the cache written at the end stores them sorted (hotspots first)
    // for the hot path rendered by render_ls_files_table.
    let mut first = true;
    let mut rows: Vec<LsFileRow> = Vec::new();
    let mut printed_count: usize = 0;

    let all_records = store.scan_prefix("file:").await?;
    for r in &all_records {
        if !matches!(r.lifecycle, RecordLifecycle::Active) {
            continue;
        }
        let path = r.key.strip_prefix("file:").unwrap_or(&r.key).to_string();
        let (purpose, entry_count, is_hotspot) = match r.payload_as::<FileRecord>() {
            Some(fr) => {
                let purpose = if fr.purpose.is_empty() {
                    "(pending enrichment)".to_string()
                } else {
                    truncate(&fr.purpose, 40)
                };
                (purpose, fr.entry_points.len(), fr.is_hotspot)
            }
            None => {
                let purpose = if r.value.is_empty() {
                    "(pending enrichment)".to_string()
                } else {
                    truncate(&r.value, 40)
                };
                (purpose, 0, false)
            }
        };
        let row = LsFileRow {
            path,
            purpose,
            entry_count,
            confidence: r.confidence.value,
            quality: r.quality.value,
            is_hotspot,
        };
        if limit == 0 || printed_count < limit {
            if first {
                print_ls_files_stream_header();
                first = false;
            }
            print_ls_files_stream_row(&row);
            printed_count += 1;
        }
        rows.push(row);
    }

    if rows.is_empty() {
        println!("No file records found.");
        return Ok(());
    }

    let total = rows.len();
    if limit > 0 && printed_count < total {
        println!(
            "  showing {} of {} file records (hotspots first on next call) — use -n 0 for all",
            printed_count, total
        );
    } else {
        println!("  {} file records", total);
    }

    // ── Write cache (sorted, best-effort) ────────────────────────────────
    rows.sort_by(|a, b| {
        b.is_hotspot
            .cmp(&a.is_hotspot)
            .then_with(|| a.path.cmp(&b.path))
    });
    let display_rows: Vec<LsFileRow> = if limit == 0 {
        rows
    } else {
        rows.into_iter().take(limit).collect()
    };
    let cache = LsFilesCache {
        write_seq: current_seq,
        limit,
        total,
        rows: display_rows,
    };
    let mut record = ls_cache_record(LS_FILES_CACHE_KEY, String::new());
    record.payload = serde_json::to_value(&cache).ok();
    let _ = store.put(LS_FILES_CACHE_KEY, &record).await;

    Ok(())
}

// Column widths for the streaming (cold-path) fixed-width format.
// PATH is left-truncated to preserve the filename when paths are long.
const COL_PATH: usize = 42;
const COL_PURPOSE: usize = 38;

/// Print the fixed-width header for the streaming cold-path display.
fn print_ls_files_stream_header() {
    println!(
        "{:<COL_PATH$}  {:<COL_PURPOSE$}  {:>3}  {:>4}  {:>4}  {:>3}",
        "PATH", "PURPOSE", "ENT", "CONF", "QUAL", "HOT"
    );
    println!("{}", "─".repeat(COL_PATH + COL_PURPOSE + 22));
}

/// Print a single row in fixed-width format during the streaming cold-path scan.
fn print_ls_files_stream_row(row: &LsFileRow) {
    // Left-truncate paths so the filename is always visible.
    let path = if row.path.chars().count() > COL_PATH {
        let chars: Vec<char> = row.path.chars().collect();
        let start = chars.len() - (COL_PATH - 1);
        format!("…{}", chars[start..].iter().collect::<String>())
    } else {
        row.path.clone()
    };
    let hot = if row.is_hotspot { "*" } else { "" };
    println!(
        "{:<COL_PATH$}  {:<COL_PURPOSE$}  {:>3}  {:>4.2}  {:>4.2}  {:>3}",
        path, row.purpose, row.entry_count, row.confidence, row.quality, hot
    );
}

/// Render the file listing table from pre-sorted, already-limited rows.
fn render_ls_files_table(rows: &[LsFileRow], total: usize, limit: usize) {
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

    for row in rows {
        table.add_row(vec![
            Cell::new(&row.path),
            Cell::new(&row.purpose),
            Cell::new(row.entry_count),
            Cell::new(format!("{:.2}", row.confidence)).fg(score_comfy_color(row.confidence)),
            Cell::new(format!("{:.2}", row.quality)).fg(score_comfy_color(row.quality)),
            Cell::new(if row.is_hotspot { "*" } else { "" }),
        ]);
    }

    println!("{table}");
    if limit > 0 && rows.len() < total {
        println!(
            "  showing {} of {} file records (hotspots first) — use -n 0 for all",
            rows.len(),
            total
        );
    } else {
        println!("  {} file records", total);
    }
}

async fn ls_gotchas(store: &StoreProxy, _use_color: bool) -> Result<()> {
    let mut records = store.scan_prefix("gotcha:").await?;
    records.retain(|r| matches!(r.lifecycle, RecordLifecycle::Active));
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
        let (rule, confirmed) = match r.payload_as::<mati_core::store::GotchaRecord>() {
            Some(gr) => (truncate(&gr.rule, 40), gr.confirmed),
            None => (truncate(&r.value, 40), false),
        };
        let sev = priority_short(&r.priority);
        table.add_row(vec![
            Cell::new(key_short),
            Cell::new(&rule),
            Cell::new(sev).fg(priority_comfy_color(&r.priority)),
            Cell::new(format!("{:.2}", r.confidence.value))
                .fg(score_comfy_color(r.confidence.value)),
            Cell::new(format!("{:.2}", r.quality.value)).fg(score_comfy_color(r.quality.value)),
            Cell::new(if confirmed { "Y" } else { "-" }),
        ]);
    }

    println!("{table}");
    println!("  {} gotcha records", records.len());
    Ok(())
}

async fn ls_decisions(store: &StoreProxy, _use_color: bool) -> Result<()> {
    let mut records = store.scan_prefix("decision:").await?;
    records.retain(|r| matches!(r.lifecycle, RecordLifecycle::Active));
    if records.is_empty() {
        println!("No decision records found.");
        return Ok(());
    }

    // Sort by updated_at descending
    records.sort_by_key(|r| std::cmp::Reverse(r.updated_at));

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
            Cell::new(format!("{:.2}", r.confidence.value))
                .fg(score_comfy_color(r.confidence.value)),
            Cell::new(format!("{:.2}", r.quality.value)).fg(score_comfy_color(r.quality.value)),
            Cell::new(format_date(r.updated_at)),
        ]);
    }

    println!("{table}");
    println!("  {} decision records", records.len());
    Ok(())
}

async fn ls_notes(store: &StoreProxy, _use_color: bool) -> Result<()> {
    let mut records = store.scan_prefix("dev_note:").await?;
    records.retain(|r| matches!(r.lifecycle, RecordLifecycle::Active));
    if records.is_empty() {
        println!("No note records found.");
        return Ok(());
    }

    // Sort by updated_at descending
    records.sort_by_key(|r| std::cmp::Reverse(r.updated_at));

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Key"),
            Cell::new("Text"),
            Cell::new("Qual"),
            Cell::new("Updated"),
        ]);

    for r in &records {
        let key_short = r.key.strip_prefix("dev_note:").unwrap_or(&r.key);
        table.add_row(vec![
            Cell::new(key_short),
            Cell::new(truncate(&r.value, 60)),
            Cell::new(format!("{:.2}", r.quality.value)).fg(score_comfy_color(r.quality.value)),
            Cell::new(format_date(r.updated_at)),
        ]);
    }

    println!("{table}");
    println!("  {} note records", records.len());
    Ok(())
}

// ── run_export (M-08-M) ─────────────────────────────────────────────────────

pub async fn run_export(args: ExportArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = StoreProxy::open(&cwd).await?;

    let output = match args.format.as_str() {
        "json" => export_json(&store).await?,
        "md" | "markdown" => export_md(&store).await?,
        other => anyhow::bail!("unknown format '{other}'. Valid: md, json"),
    };

    match args.output {
        Some(path) => std::fs::write(&path, &output)?,
        None => print!("{output}"),
    }
    Ok(())
}

async fn export_json(store: &StoreProxy) -> Result<String> {
    let mut all: Vec<Record> = Vec::new();
    for prefix in &[
        "gotcha:",
        "decision:",
        "file:",
        "stage:",
        "dev_note:",
        "dep:",
    ] {
        all.extend(store.scan_prefix(prefix).await?);
    }
    Ok(serde_json::to_string_pretty(&all)?)
}

async fn export_md(store: &StoreProxy) -> Result<String> {
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
    let proxy = super::proxy::StoreProxy::open(&cwd).await?;

    let path = &args.file;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext {
        "json" => {
            let content = std::fs::read_to_string(path)?;
            let records: Vec<Record> = serde_json::from_str(&content)?;
            let pairs: Vec<(&str, &Record)> = records.iter().map(|r| (r.key.as_str(), r)).collect();
            proxy.put_batch(&pairs).await?;
            println!("Imported {} records from JSON.", records.len());
        }
        "md" => {
            let device_id = uuid::Uuid::new_v4();
            let import = mati_core::analysis::import_claude_md(path, device_id, 1)?;
            let pairs: Vec<(&str, &Record)> =
                import.records.iter().map(|r| (r.key.as_str(), r)).collect();
            proxy.put_batch(&pairs).await?;
            println!("Imported {} records from CLAUDE.md.", import.records.len());
        }
        _ => {
            // Try JSON first, fall back to CLAUDE.md import
            let content = std::fs::read_to_string(path)?;
            if content.trim_start().starts_with('[') || content.trim_start().starts_with('{') {
                let records: Vec<Record> = serde_json::from_str(&content)?;
                let pairs: Vec<(&str, &Record)> =
                    records.iter().map(|r| (r.key.as_str(), r)).collect();
                proxy.put_batch(&pairs).await?;
                println!("Imported {} records from JSON.", records.len());
            } else {
                let device_id = uuid::Uuid::new_v4();
                let import = mati_core::analysis::import_claude_md(path, device_id, 1)?;
                let pairs: Vec<(&str, &Record)> =
                    import.records.iter().map(|r| (r.key.as_str(), r)).collect();
                proxy.put_batch(&pairs).await?;
                println!("Imported {} records from CLAUDE.md.", import.records.len());
            }
        }
    }
    proxy.close().await?;
    Ok(())
}

// ── run_history (M-14-C stub) ────────────────────────────────────────────────

pub async fn run_history(args: HistoryArgs) -> Result<()> {
    if args.limit == 0 {
        anyhow::bail!("--limit must be at least 1");
    }

    let cwd = std::env::current_dir()?;
    let proxy = super::proxy::StoreProxy::open(&cwd).await?;

    let result = if args.enforcement {
        run_enforcement_history(&proxy, &args).await
    } else {
        run_history_inner(&proxy, &args).await
    };
    proxy.close().await?;
    result
}

async fn run_enforcement_history(
    proxy: &super::proxy::StoreProxy,
    args: &HistoryArgs,
) -> Result<()> {
    let since_ms = match &args.since {
        Some(since_str) => {
            let secs = parse_since_duration(since_str)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            now.saturating_sub(secs * 1000)
        }
        None => 0,
    };

    // Pull all events via the proxy (routes through the daemon socket if it's
    // running, otherwise opens the store directly), then filter by since_ms.
    let all_events = proxy.scan_enforcement_events(0, u64::MAX).await?;
    let events: Vec<_> = all_events
        .into_iter()
        .filter(|e| e.recorded_at_ms >= since_ms)
        .collect();

    // Apply filters
    let filtered: Vec<_> = events
        .into_iter()
        .filter(|e| {
            if let Some(ref type_filter) = args.r#type {
                let label = mati_core::store::enforcement::event_type_label(&e.event_type);
                if !label.contains(type_filter.as_str()) {
                    return false;
                }
            }
            if let Some(ref file_filter) = args.file {
                if !e.subject_key.contains(file_filter.as_str()) {
                    return false;
                }
            }
            true
        })
        .collect();

    // `--limit N` shows the LAST N events (most recent), still rendered in
    // ascending chronological order. This matches `git log -N` and `tail -n N`
    // semantics — the user wants "what just happened?", not "what happened
    // first ever?". With thousands of accumulated enforcement events, a head-
    // limit is unusable: the first 50 events are months old and never reflect
    // recent activity. Bug surfaced in pass 31 — every smoke test pre-pass-31
    // failed Phase 5 history checks because `--limit 10` returned events from
    // weeks ago.
    let total = filtered.len();
    let skip = total.saturating_sub(args.limit);
    let events: Vec<_> = filtered.into_iter().skip(skip).collect();

    if events.is_empty() {
        let window = args
            .since
            .as_deref()
            .map(|s| format!(" in the last {s}"))
            .unwrap_or_default();
        println!("No enforcement events{window}.");
        return Ok(());
    }

    let use_color = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let (red, green, yellow, cyan, reset) = if use_color {
        ("\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[36m", "\x1b[0m")
    } else {
        ("", "", "", "", "")
    };

    println!(
        "{:>6}  {:19}  {:16}  {:30}  {:6}",
        "SEQ", "TIMESTAMP", "TYPE", "SUBJECT", "REASON"
    );
    println!("{}", "-".repeat(90));

    for event in &events {
        let ts = chrono::DateTime::from_timestamp_millis(event.recorded_at_ms as i64)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "?".to_string());

        let type_label = mati_core::store::enforcement::event_type_label(&event.event_type);
        let color = match &event.event_type {
            mati_core::store::enforcement::EnforcementEventType::Deny => red,
            mati_core::store::enforcement::EnforcementEventType::AllowAfterReceipt => green,
            mati_core::store::enforcement::EnforcementEventType::RecordingGap { .. } => yellow,
            _ => cyan,
        };

        println!(
            "{:>6}  {ts}  {color}{type_label:<16}{reset}  {}  {}",
            event.seq_no,
            truncate_str(&event.subject_key, 30),
            &event.decision_reason_code,
        );
    }

    println!("\n{} event(s) shown.", events.len());
    Ok(())
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        format!("{s:<width$}", width = max)
    } else {
        format!("{}...", &s[..max - 3])
    }
}

async fn run_history_inner(proxy: &super::proxy::StoreProxy, args: &HistoryArgs) -> Result<()> {
    let use_color = std::io::stdout().is_terminal();

    match (&args.key, &args.since) {
        // mati history <key> --since 7d
        (Some(key), Some(since_str)) => {
            let secs = parse_since_duration(since_str)?;
            let since_ts = now_secs().saturating_sub(secs);
            let entries = proxy.history_since(key, since_ts, args.limit).await?;
            if entries.is_empty() {
                println!(
                    "No history for '{}' in the last {}.",
                    key,
                    duration_label(secs)
                );
                return Ok(());
            }
            render_timeline(key, &entries, use_color);
        }
        // mati history <key>
        (Some(key), None) => {
            let entries = proxy.history(key, args.limit).await?;
            if entries.is_empty() {
                println!("No history for '{}'.", key);
                return Ok(());
            }
            render_timeline(key, &entries, use_color);
        }
        // mati history --since 7d
        (None, Some(since_str)) => {
            let secs = parse_since_duration(since_str)?;
            let since_ts = now_secs().saturating_sub(secs);
            let records = proxy.records_since(since_ts, args.limit).await?;
            if records.is_empty() {
                println!("No records changed in the last {}.", duration_label(secs));
                return Ok(());
            }
            show_records_since(&records, secs, use_color);
        }
        // mati history (no args at all)
        (None, None) => {
            anyhow::bail!(
                "provide a key (e.g., mati history gotcha:foo) or --since (e.g., mati history --since 7d)"
            );
        }
    }
    Ok(())
}

fn render_timeline(key: &str, entries: &[mati_core::store::db::HistoryEntry], use_color: bool) {
    let (blue, gray, red, yellow, green, white, bold, reset) = if use_color {
        (
            colors::BLUE,
            colors::GRAY,
            colors::RED,
            colors::YELLOW,
            colors::GREEN,
            colors::WHITE,
            colors::BOLD,
            colors::RESET,
        )
    } else {
        ("", "", "", "", "", "", "", "")
    };

    println!(
        "\n{bold}{blue}history{reset}  {bold}{white}{key}{reset}  {gray}({} version{}){reset}\n",
        entries.len(),
        if entries.len() == 1 { "" } else { "s" },
    );

    for (i, entry) in entries.iter().enumerate() {
        let ts_label = format_ts_short(entry.timestamp_secs);

        if entry.is_tombstone {
            println!("  {red}x{reset}  {gray}{ts_label}{reset}  {red}deleted{reset}");
        } else if let Some(ref rec) = entry.record {
            // Detect "created" by comparing created_at == updated_at on the record
            let is_creation = rec.created_at == rec.updated_at;
            let action = if is_creation { "created" } else { "updated" };
            let action_color = if is_creation { green } else { yellow };

            let src = source_short_label(&rec.source);
            let val_preview = truncate(&rec.value, 60);

            println!(
                "  {action_color}*{reset}  {gray}{ts_label}{reset}  {action_color}{action}{reset}  {gray}{src}{reset}"
            );
            if i == 0 || !val_preview.is_empty() {
                println!("     {white}{val_preview}{reset}");
            }
            println!(
                "     {gray}conf={:.2}  qual={:.2}  clock={}{reset}",
                rec.confidence.value, rec.quality.value, rec.version.logical_clock,
            );
        } else {
            // Non-tombstone but record could not be deserialized
            println!(
                "  {yellow}?{reset}  {gray}{ts_label}{reset}  {yellow}unreadable version{reset}"
            );
        }

        if i < entries.len() - 1 {
            println!("  {gray}|{reset}");
        }
    }
    println!();
}

fn show_records_since(records: &[Record], window_secs: u64, _use_color: bool) {
    println!(
        "\nRecords changed in the last {}  ({} total)\n",
        duration_label(window_secs),
        records.len(),
    );

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Key"),
            Cell::new("Updated (UTC)"),
            Cell::new("Source"),
            Cell::new("Conf"),
            Cell::new("Value"),
        ]);

    for r in records {
        table.add_row(vec![
            Cell::new(&r.key),
            Cell::new(format_ts_short(r.updated_at)),
            Cell::new(source_short_label(&r.source)),
            Cell::new(format!("{:.2}", r.confidence.value))
                .fg(score_comfy_color(r.confidence.value)),
            Cell::new(truncate(&r.value, 40)),
        ]);
    }

    println!("{table}");
}

/// Parse a human-friendly duration suffix into seconds.
///
/// Supported suffixes: h (hours), d (days), w (weeks), m (months ~30d), y (years ~365d).
fn parse_since_duration(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("--since value must not be empty");
    }
    let (digits, suffix) = s.split_at(s.len() - 1);
    let n: u64 = digits.parse().map_err(|_| {
        anyhow::anyhow!("invalid --since format '{s}': expected <number><h|d|w|m|y>")
    })?;
    if n == 0 {
        anyhow::bail!("--since value must be positive, got '{s}'");
    }
    let multiplier: u64 = match suffix {
        "h" => 3600,
        "d" => 86400,
        "w" => 7 * 86400,
        "m" => 30 * 86400,
        "y" => 365 * 86400,
        _ => anyhow::bail!("unknown --since suffix '{suffix}': expected h, d, w, m, or y"),
    };
    Ok(n.saturating_mul(multiplier))
}

/// Format a Unix timestamp (seconds) as "YYYY-MM-DD HH:MM".
fn format_ts_short(ts: u64) -> String {
    if ts == 0 {
        return "\u{2014}".to_string();
    }
    let days = ts / 86400;
    let rem = ts % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}")
}

/// Short label for RecordSource (no parenthetical detail).
fn source_short_label(src: &RecordSource) -> &'static str {
    match src {
        RecordSource::StaticAnalysis => "L0",
        RecordSource::ClaudeEnrich => "L1",
        RecordSource::SessionHook => "L2",
        RecordSource::DeveloperManual => "manual",
        RecordSource::Import => "import",
    }
}

/// Human-friendly duration label from seconds.
fn duration_label(secs: u64) -> String {
    if secs >= 365 * 86400 {
        let y = secs / (365 * 86400);
        return format!("{y} year{}", if y == 1 { "" } else { "s" });
    }
    if secs >= 30 * 86400 {
        let m = secs / (30 * 86400);
        return format!("{m} month{}", if m == 1 { "" } else { "s" });
    }
    if secs >= 7 * 86400 {
        let w = secs / (7 * 86400);
        return format!("{w} week{}", if w == 1 { "" } else { "s" });
    }
    if secs >= 86400 {
        let d = secs / 86400;
        return format!("{d} day{}", if d == 1 { "" } else { "s" });
    }
    let h = secs / 3600;
    format!("{h} hour{}", if h == 1 { "" } else { "s" })
}

/// Current wall-clock time in seconds since Unix epoch.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    // ── parse_since_duration ─────────────────────────────────────────────────

    #[test]
    fn parse_since_hours() {
        assert_eq!(parse_since_duration("2h").unwrap(), 7200);
    }

    #[test]
    fn parse_since_days() {
        assert_eq!(parse_since_duration("7d").unwrap(), 604800);
    }

    #[test]
    fn parse_since_weeks() {
        assert_eq!(parse_since_duration("2w").unwrap(), 14 * 86400);
    }

    #[test]
    fn parse_since_months() {
        assert_eq!(parse_since_duration("3m").unwrap(), 90 * 86400);
    }

    #[test]
    fn parse_since_years() {
        assert_eq!(parse_since_duration("1y").unwrap(), 365 * 86400);
    }

    #[test]
    fn parse_since_invalid_suffix() {
        assert!(parse_since_duration("7x").is_err());
    }

    #[test]
    fn parse_since_no_number() {
        assert!(parse_since_duration("d").is_err());
    }

    #[test]
    fn parse_since_zero_value() {
        assert!(parse_since_duration("0d").is_err());
    }

    #[test]
    fn parse_since_empty() {
        assert!(parse_since_duration("").is_err());
    }

    // ── format_ts_short ──────────────────────────────────────────────────────

    #[test]
    fn format_ts_short_zero_is_em_dash() {
        assert_eq!(format_ts_short(0), "\u{2014}");
    }

    #[test]
    fn format_ts_short_known_date() {
        // 2024-01-15 01:02
        let ts = 19737 * 86400 + 3720;
        assert_eq!(format_ts_short(ts), "2024-01-15 01:02");
    }

    // ── source_short_label ───────────────────────────────────────────────────

    #[test]
    fn source_short_label_values() {
        assert_eq!(source_short_label(&RecordSource::StaticAnalysis), "L0");
        assert_eq!(source_short_label(&RecordSource::ClaudeEnrich), "L1");
        assert_eq!(source_short_label(&RecordSource::SessionHook), "L2");
        assert_eq!(source_short_label(&RecordSource::DeveloperManual), "manual");
        assert_eq!(source_short_label(&RecordSource::Import), "import");
    }

    // ── duration_label ───────────────────────────────────────────────────────

    #[test]
    fn duration_label_hours() {
        assert_eq!(duration_label(3600), "1 hour");
        assert_eq!(duration_label(7200), "2 hours");
    }

    #[test]
    fn duration_label_days() {
        assert_eq!(duration_label(86400), "1 day");
        assert_eq!(duration_label(3 * 86400), "3 days");
    }

    #[test]
    fn duration_label_weeks() {
        assert_eq!(duration_label(7 * 86400), "1 week");
        assert_eq!(duration_label(14 * 86400), "2 weeks");
    }

    #[test]
    fn duration_label_months() {
        assert_eq!(duration_label(30 * 86400), "1 month");
        assert_eq!(duration_label(60 * 86400), "2 months");
    }

    #[test]
    fn duration_label_years() {
        assert_eq!(duration_label(365 * 86400), "1 year");
        assert_eq!(duration_label(730 * 86400), "2 years");
    }

    // ── truncate multibyte + edge cases ──────────────────────────────────────

    #[test]
    fn truncate_multibyte_chars() {
        // Each emoji is 4 bytes. "abcde" is 9 chars total.
        let s = "ab\u{1F600}cd\u{1F600}ef";
        // max=6 means we need 3 chars + "..."
        let result = truncate(s, 6);
        assert!(result.ends_with("..."));
        assert_eq!(result.chars().count(), 6); // 3 chars + 3 dots
    }

    #[test]
    fn truncate_exact_boundary() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_one_over() {
        assert_eq!(truncate("hello!", 5), "he...");
    }

    #[test]
    fn truncate_max_less_than_four() {
        // max < 4: just take what fits, no "..."
        assert_eq!(truncate("hello", 3), "hel");
    }

    #[test]
    fn truncate_empty_string() {
        assert_eq!(truncate("", 10), "");
    }

    #[test]
    fn truncate_all_multibyte() {
        // 4 emoji = 4 chars, each 4 bytes
        let s = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}";
        let result = truncate(s, 4);
        assert_eq!(result, s); // exactly fits
    }

    #[test]
    fn truncate_all_multibyte_over() {
        let s = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}\u{1F604}";
        let result = truncate(s, 4);
        // 1 char + "..." = 4 chars
        assert_eq!(result, "\u{1F600}...");
    }

    // ── enforcement history --limit tail semantics (pass 31) ─────────────────

    /// Pass 31 regression: `mati history --enforcement --limit N` MUST show
    /// the LAST N events (most recent), not the FIRST N (oldest). Pre-pass-31
    /// the function used `.take(N)` on the ascending-ordered list, returning
    /// events from weeks ago no matter how many were in the store. Smoke
    /// tests failed Phase 5 history checks because `--limit 10` returned seq
    /// 1-10 (months old), and the smoke's freshly-emitted `allow_receipt`
    /// event lived at e.g. seq 1268 — invisible.
    ///
    /// We test the slice math directly: `total.saturating_sub(limit)` is
    /// what makes the tail behavior work. A simple unit on this expression
    /// pins the semantics without spinning up a daemon.
    #[test]
    fn enforcement_limit_returns_tail_not_head() {
        // Simulate 1268 events (matching the real-world repro size).
        let total = 1268usize;
        let limit = 10usize;

        // The new tail-semantics computation:
        let skip = total.saturating_sub(limit);
        let kept_indices: Vec<usize> = (0..total).skip(skip).collect();

        assert_eq!(kept_indices.len(), 10, "exactly `limit` events kept");
        assert_eq!(
            kept_indices.first(),
            Some(&1258),
            "first kept event must be at index `total - limit`, not 0 (head)"
        );
        assert_eq!(
            kept_indices.last(),
            Some(&1267),
            "last kept event must be the most recent (index total-1)"
        );
        assert!(
            !kept_indices.contains(&0),
            "head events must NOT appear when total > limit (this was the pre-pass-31 bug)"
        );
    }

    /// Edge case: when total <= limit, return everything (no skip).
    /// `saturating_sub` is what makes this safe — `total.saturating_sub(limit)`
    /// returns 0 when `limit >= total`, so `.skip(0)` keeps the whole list.
    #[test]
    fn enforcement_limit_smaller_than_total_returns_all() {
        let total = 5usize;
        let limit = 100usize;
        let skip = total.saturating_sub(limit);
        let kept: Vec<usize> = (0..total).skip(skip).collect();
        assert_eq!(
            kept,
            vec![0, 1, 2, 3, 4],
            "all events kept when limit >= total"
        );
    }

    /// Edge case: limit=0 returns empty (no events). Matches existing semantics.
    #[test]
    fn enforcement_limit_zero_returns_empty() {
        let total = 50usize;
        let limit = 0usize;
        let skip = total.saturating_sub(limit);
        // skip == 50, so .skip(50).collect() on 0..50 returns empty.
        let kept: Vec<usize> = (0..total).skip(skip).collect();
        assert!(kept.is_empty(), "limit=0 returns empty");
    }
}
