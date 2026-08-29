use super::*;

// ── ls cache types ────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub(super) struct LsFileRow {
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
    /// Active file records excluded because `StalenessTier::Tombstone` — the
    /// file no longer exists on disk (see `health::staleness`'s `FileDeleted`
    /// hard override). Hidden from the table rather than shown as a dead row
    /// mixed in with live ones; `mati stale` is where a tombstoned record's
    /// existence and reason are surfaced in full.
    excluded_deleted: usize,
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
            device_id: mati_core::store::stable_device_id(),
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
    // `--json` is implemented for `tombstoned` only. Accepting it silently on
    // the other categories left callers parsing the human table — which is how
    // a `Last author:` bullet from the Stability block ends up counted as a
    // gotcha. Fail loudly and name the command that does work.
    if !matches!(
        args.category.as_deref(),
        Some("tombstoned") | Some("tombstones")
    ) && args.json
    {
        anyhow::bail!(
            "--json is only supported for the `tombstoned` category.\n\
             For machine-readable records use `mati export --format json`."
        );
    }

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
        Some("tombstoned") | Some("tombstones") => {
            ls_tombstoned(
                &store,
                args.dir.as_deref(),
                args.recent.as_deref(),
                limit,
                args.json,
            )
            .await?
        }
        Some(other) => {
            anyhow::bail!(
                "unknown category '{other}'. \
                 Valid: files, gotchas, decisions, notes, tombstoned"
            )
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

/// Build a display row for a `file:*` record, or `None` if it should be
/// excluded from `mati ls files`.
///
/// Excludes `StalenessTier::Tombstone` — the `FileDeleted` hard override
/// (`health::staleness::compute_staleness`) — because the path no longer
/// exists on disk and enforcement already treats the record as inert; a
/// dead row mixed into a live listing trains the reader to skim past all of
/// them. Excluded, not hidden outright: `mati stale` is the existing place
/// an inert staleness tier is surfaced with a reason and an impact label,
/// and `ls_files` reports how many rows it left out for the caller to look
/// there.
pub(super) fn ls_file_row(r: &Record) -> Option<LsFileRow> {
    if r.staleness.tier == StalenessTier::Tombstone {
        return None;
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
    Some(LsFileRow {
        path,
        purpose,
        entry_count,
        confidence: r.confidence.value,
        quality: r.quality.value,
        is_hotspot,
    })
}

async fn ls_files(store: &StoreProxy, use_color: bool, limit: usize) -> Result<()> {
    // ── Cache check ───────────────────────────────────────────────────────
    let current_seq = store.read_write_seq();
    if let Some(cached) = store.get(LS_FILES_CACHE_KEY).await? {
        if let Some(entry) = cached.payload_as::<LsFilesCache>() {
            if entry.write_seq == current_seq && entry.limit == limit {
                render_ls_files_table(&entry.rows, entry.total, limit);
                print_excluded_deleted_note(entry.excluded_deleted, use_color);
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
    let mut excluded_deleted: usize = 0;

    let all_records = store.scan_prefix("file:").await?;
    for r in &all_records {
        if !matches!(r.lifecycle, RecordLifecycle::Active) {
            continue;
        }
        let Some(row) = ls_file_row(r) else {
            excluded_deleted += 1;
            continue;
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
        if excluded_deleted == 0 {
            println!("No file records found.");
        } else {
            println!("No file records found.");
            print_excluded_deleted_note(excluded_deleted, use_color);
        }
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
    print_excluded_deleted_note(excluded_deleted, use_color);

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
        excluded_deleted,
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

/// Tell the reader why the file count doesn't match what's on disk, rather
/// than letting `excluded_deleted` rows disappear without a trace.
fn print_excluded_deleted_note(excluded_deleted: usize, use_color: bool) {
    if excluded_deleted == 0 {
        return;
    }
    let plural = if excluded_deleted == 1 { "" } else { "s" };
    if use_color {
        println!(
            "  {}{} file record{} excluded — file deleted on disk. See `mati stale`.{}",
            colors::RED,
            excluded_deleted,
            plural,
            colors::RESET
        );
    } else {
        println!(
            "  {excluded_deleted} file record{plural} excluded — file deleted on disk. \
             See `mati stale`."
        );
    }
}

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
        let gotcha = r.payload_as::<mati_core::store::GotchaRecord>();
        let (rule, confirmed) = match &gotcha {
            Some(gr) => (truncate(&gr.rule, 40), gr.confirmed),
            None => (truncate(&r.value, 40), false),
        };
        // Severity from the gotcha payload, not the Record.priority — the
        // payload field is what the user set when creating the gotcha
        // (e.g. mem_set payload.severity = "high"); Record.priority is the
        // record-level priority (often Normal regardless of severity).
        // Falls back to Record.priority when the payload is missing.
        let severity = gotcha
            .as_ref()
            .map(|gr| gr.severity.clone())
            .unwrap_or_else(|| r.priority.clone());
        let sev = priority_short(&severity);
        table.add_row(vec![
            Cell::new(key_short),
            Cell::new(&rule),
            Cell::new(sev).fg(priority_comfy_color(&severity)),
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

// ── ls_tombstoned (D2-β) ────────────────────────────────────────────────────
//
// Reads `analytics:negative_exemplar:<dirname>:*` records (written by
// `gotcha_ops::apply_gotcha_tombstone` since D3-foundation) and emits
// the most-recent ones for a directory. Designed for two consumers:
//
// 1. Humans: a quick view of what gotchas were recently rejected in
//    a directory ("why did we tombstone these?"). Pretty table by default.
// 2. The `/mati-enrich` Stage 2 prompt (D2-γ): JSON output via `--json`
//    so the agent can include the negative exemplars in the Deep-tier
//    extraction prompt.
//
// Routes through `StoreProxy::scan_prefix` so it works whether the
// daemon is up (via socket) or down (direct store).

async fn ls_tombstoned(
    store: &StoreProxy,
    dir: Option<&str>,
    recent: Option<&str>,
    limit: usize,
    json: bool,
) -> Result<()> {
    use mati_core::store::negative_exemplar::{NegativeExemplar, NEG_EXEMPLAR_PREFIX};

    let dirname = dir.ok_or_else(|| {
        anyhow::anyhow!(
            "--dir is required for `mati ls tombstoned` \
             (negative exemplars are keyed by dirname; pass e.g. --dir src/cli)"
        )
    })?;

    // Default window: 30d. Matches the spec's D2-β recommendation —
    // long enough to capture recent tuning context, short enough to
    // stay relevant.
    let recent_str = recent.unwrap_or("30d");
    let window_secs = parse_since_duration(recent_str)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let since_secs = now.saturating_sub(window_secs);

    let scan_prefix = format!("{NEG_EXEMPLAR_PREFIX}{dirname}:");
    let records = store.scan_prefix(&scan_prefix).await.unwrap_or_default();

    let mut exemplars: Vec<NegativeExemplar> = records
        .into_iter()
        .filter_map(|r| r.payload.and_then(|p| serde_json::from_value(p).ok()))
        .filter(|e: &NegativeExemplar| e.tombstoned_at >= since_secs)
        .collect();
    exemplars.sort_by_key(|e| std::cmp::Reverse(e.tombstoned_at));
    // limit=0 means unlimited; otherwise truncate.
    if limit > 0 {
        exemplars.truncate(limit);
    }

    if json {
        // Stable JSON envelope so the slash-flow can parse deterministically.
        let envelope = serde_json::json!({
            "dirname": dirname,
            "window": recent_str,
            "since_secs": since_secs,
            "count": exemplars.len(),
            "exemplars": &exemplars,
        });
        println!("{}", serde_json::to_string(&envelope)?);
        return Ok(());
    }

    if exemplars.is_empty() {
        println!("No tombstoned gotchas in {dirname} within the last {recent_str}.");
        return Ok(());
    }

    let use_color = std::io::stdout().is_terminal();
    let (yellow, gray, reset) = if use_color {
        (
            super::colors::YELLOW,
            super::colors::GRAY,
            super::colors::RESET,
        )
    } else {
        ("", "", "")
    };

    println!(
        "\n{yellow}Tombstoned gotchas in {dirname} (last {recent_str}) — {count} found{reset}\n",
        count = exemplars.len()
    );

    for e in &exemplars {
        println!("  {} {gray}({:?}){reset}", e.gotcha_key, e.severity);
        println!("    rule:   {}", e.rule);
        println!("    reason: {}", e.reason);
        println!();
    }
    Ok(())
}

// ── run_export (M-08-M) ─────────────────────────────────────────────────────
