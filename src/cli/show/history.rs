use super::*;

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

    // Bounded scan via the proxy (daemon socket if one is running, direct store
    // otherwise). `--since` binary-searches to the boundary instead of reading
    // the whole chain; `u64::MAX` leaves the upper bound open, so the window is
    // identical to the scan-then-filter this replaced.
    let events = proxy
        .scan_enforcement_events_since_ms(since_ms, u64::MAX)
        .await?
        .events;

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
        "{:>6}  {:19}  {:16}  {:30}  {:24}  {:12}",
        "SEQ", "TIMESTAMP", "TYPE", "SUBJECT", "REASON", "SESSION"
    );
    println!("{}", "-".repeat(104));

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
            "{:>6}  {ts}  {color}{type_label:<16}{reset}  {:30}  {:24}  {}",
            event.seq_no,
            truncate_str(&event.subject_key, 30),
            event.decision_reason_code,
            event.agent_session.as_deref().unwrap_or("-"),
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
pub(super) fn parse_since_duration(s: &str) -> Result<u64> {
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
pub(super) fn format_ts_short(ts: u64) -> String {
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
pub(super) fn source_short_label(src: &RecordSource) -> &'static str {
    match src {
        RecordSource::StaticAnalysis => "L0",
        RecordSource::ClaudeEnrich => "L1",
        RecordSource::SessionHook => "L2",
        RecordSource::DeveloperManual => "manual",
        RecordSource::Import => "import",
    }
}

/// Human-friendly duration label from seconds.
pub(super) fn duration_label(secs: u64) -> String {
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
pub(super) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
