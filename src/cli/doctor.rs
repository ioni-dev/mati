//! `mati doctor` — diagnostic health aggregator for support and CI.
//!
//! Fans out to: daemon reachability, dirty-marker presence, drift check,
//! and recent lifecycle events. Exits 0 if everything is healthy; non-zero
//! if any check is in a fail state. Intended as the "paste this output"
//! command for support requests and as a CI gate for repository health.
//!
//! Drift checks require direct store access. When the daemon holds the
//! exclusive lock, those checks report "skipped" rather than failing —
//! the daemon's own boot-time auto-drain (see `mcp::server::serve`) is
//! already running the same logic on its side.

use std::io::{self, IsTerminal};
use std::path::Path;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use mati_core::store::repair::{check_gotcha_indexes, is_dirty, read_dirty_marker};
use mati_core::store::Store;

use super::daemon::{daemon_result, mati_root_for, DaemonResult};

/// Doctor command arguments.
#[derive(Args)]
pub struct DoctorArgs {
    /// Output a structured JSON report on stdout (CI-friendly).
    #[arg(long)]
    pub json: bool,

    /// Show live daemon metrics (per-command counters and p50/p95/p99
    /// latencies) instead of the health-check report. Requires the daemon
    /// to be running — exits non-zero with a clear message otherwise.
    /// SLO-relevant view (ADR-010).
    #[arg(long)]
    pub internal: bool,
}

/// Run all doctor checks, render the report, exit 1 if any FAIL.
pub async fn run(args: DoctorArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    // `--internal` is a separate view — live daemon metrics, not the health
    // checklist. We intentionally don't run any of the health checks here:
    // those produce side effects (peer credentials, store locks) and would
    // muddy the metric numbers we're about to print.
    if args.internal {
        return run_internal(&root, args.json).await;
    }

    let report = collect(&cwd, &root).await;

    if args.json {
        // JSON goes to stdout — keep stderr quiet so consumers can pipe.
        let json = serde_json::to_string_pretty(&report)?;
        println!("{json}");
    } else {
        let use_color = io::stderr().is_terminal();
        render_human(&report, use_color);
    }

    if report.summary.fail > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Fetch the metrics snapshot from the live daemon and render it.
///
/// Returns Ok(()) on render success, even if the daemon is unreachable —
/// in that case a one-line "daemon not running" message is printed and the
/// process exits 1 (so CI wrappers don't silently succeed).
async fn run_internal(root: &Path, json: bool) -> Result<()> {
    let resp = daemon_result(root, "metrics", serde_json::json!({})).await;
    let data = match resp {
        DaemonResult::Ok(envelope) => envelope
            .get("data")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        DaemonResult::NotRunning | DaemonResult::StaleSocket => {
            eprintln!("daemon is not running — start it with `mati daemon start`");
            std::process::exit(1);
        }
        DaemonResult::Unresponsive => {
            eprintln!("daemon socket exists but is unresponsive");
            eprintln!("  hint: mati daemon stop && mati daemon start");
            std::process::exit(1);
        }
    };

    if json {
        // JSON envelope passes through unchanged so callers see the same shape
        // the daemon emits.
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    render_internal_human(&data);
    Ok(())
}

/// Render a metrics snapshot as a human-readable table on stdout.
///
/// Resilient to schema drift: if the daemon returns a shape this binary
/// doesn't understand, fall back to pretty-printing the raw JSON so the
/// user still sees something useful.
fn render_internal_human(data: &serde_json::Value) {
    use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, ContentArrangement, Table};

    if data.is_null() {
        println!("(daemon has no metrics yet — none recorded since startup)");
        return;
    }

    let uptime = data
        .get("uptime_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let total = data
        .get("total_calls")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let errors = data
        .get("total_errors")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let err_pct = if total == 0 {
        0.0
    } else {
        (errors as f64 / total as f64) * 100.0
    };

    println!("daemon metrics");
    println!("  uptime         {}", format_duration(uptime));
    println!("  total calls    {total} (errors: {errors}, {err_pct:.2}%)");
    println!();

    let Some(commands) = data.get("commands").and_then(|v| v.as_array()) else {
        // Shape didn't match — dump raw so the user can still inspect.
        println!("(unknown metrics shape; raw payload:)");
        if let Ok(pretty) = serde_json::to_string_pretty(data) {
            println!("{pretty}");
        }
        return;
    };

    if commands.is_empty() {
        println!("(no commands recorded since startup)");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("command"),
            Cell::new("count"),
            Cell::new("err%"),
            Cell::new("mean"),
            Cell::new("p50"),
            Cell::new("p95"),
            Cell::new("p99"),
            Cell::new("max"),
        ]);

    for cmd in commands {
        let name = cmd.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let count = cmd.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let errs = cmd.get("error_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let cmd_err_pct = if count == 0 {
            0.0
        } else {
            (errs as f64 / count as f64) * 100.0
        };
        let mean = cmd.get("mean_us").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let p50 = cmd.get("p50_us").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let p95 = cmd.get("p95_us").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let p99 = cmd.get("p99_us").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let max = cmd.get("max_us").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        table.add_row(vec![
            Cell::new(name),
            Cell::new(count),
            Cell::new(format!("{cmd_err_pct:.1}%")),
            Cell::new(format_us(mean)),
            Cell::new(format_us(p50)),
            Cell::new(format_us(p95)),
            Cell::new(format_us(p99)),
            Cell::new(format_us(max)),
        ]);
    }

    println!("{table}");
}

/// Render a microsecond duration in the most readable unit.
fn format_us(us: u32) -> String {
    if us < 1_000 {
        format!("{us}µs")
    } else if us < 1_000_000 {
        format!("{:.1}ms", f64::from(us) / 1_000.0)
    } else {
        format!("{:.2}s", f64::from(us) / 1_000_000.0)
    }
}

/// Render a duration in seconds as a compact human-readable string.
fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

// ── Report types ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct Report {
    version: u32,
    root: String,
    checks: Vec<CheckResult>,
    lifecycle: Vec<LifecycleEntry>,
    summary: Summary,
    /// D3: per-tier accuracy of `/mati-enrich` extractions, computed from
    /// `analytics:extraction:*` records. `None` when the store wasn't
    /// reachable (e.g. uninitialized repo); empty stats when the store is
    /// reachable but no enrichment-tagged gotchas exist yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    extraction: Option<mati_core::store::extraction::ExtractionStats>,
}

#[derive(Serialize)]
struct CheckResult {
    section: &'static str,
    name: &'static str,
    status: Status,
    detail: String,
    /// One-line remediation hint when status is warn/fail.
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<&'static str>,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Status {
    Pass,
    Warn,
    Fail,
    Info,
}

#[derive(Serialize)]
struct LifecycleEntry {
    ts: u64,
    pid: u32,
    event: String,
    detail: String,
}

#[derive(Serialize, Default)]
struct Summary {
    pass: u32,
    warn: u32,
    fail: u32,
    info: u32,
}

// ── Collection ──────────────────────────────────────────────────────────────

async fn collect(cwd: &Path, root: &Path) -> Report {
    let mut checks: Vec<CheckResult> = Vec::new();

    // Daemon ping.
    let daemon_state = daemon_result(root, "ping", serde_json::json!({})).await;
    match &daemon_state {
        DaemonResult::Ok(_) => checks.push(CheckResult {
            section: "daemon",
            name: "ping",
            status: Status::Pass,
            detail: "ok".into(),
            fix: None,
        }),
        DaemonResult::Unresponsive => checks.push(CheckResult {
            section: "daemon",
            name: "ping",
            status: Status::Fail,
            detail: "socket exists but daemon is not responding".into(),
            fix: Some("mati daemon stop && mati daemon start"),
        }),
        DaemonResult::StaleSocket => checks.push(CheckResult {
            section: "daemon",
            name: "ping",
            status: Status::Warn,
            detail: "stale socket detected and cleaned up".into(),
            fix: None,
        }),
        DaemonResult::NotRunning => checks.push(CheckResult {
            section: "daemon",
            name: "ping",
            status: Status::Info,
            detail: "not running (OK if no agent session is active)".into(),
            fix: None,
        }),
    }

    // Integrity: dirty_marker + drift.
    //
    // Schema-stability invariant: this block always pushes exactly two
    // `integrity` checks — `dirty_marker` followed by `drift` — in that
    // order, regardless of whether the daemon holds the lock, the store
    // is uninitialized, or `Store::open` failed. Consumers parsing
    // `mati doctor --json` rely on `version: 1` meaning the same set of
    // check names appears in the same order across all scenarios, so
    // `.checks[]` indices and a name-keyed lookup both stay stable.
    //
    // Skip Store::open whenever the daemon (or some still-living former
    // daemon) is holding the lock. Treating only `Ok` as "daemon owns
    // store" would attempt Store::open in the `Unresponsive` case — which
    // is *guaranteed* to fail with "already locked" and emit a redundant
    // `store_open FAIL` next to the `ping FAIL`. Both states mean
    // "another process holds the lock; integrity not verifiable from
    // here", which is one signal, not two.
    let daemon_holds_lock = matches!(
        daemon_state,
        DaemonResult::Ok(_) | DaemonResult::Unresponsive
    );
    if daemon_holds_lock {
        let lock_detail = match daemon_state {
            DaemonResult::Ok(_) => "skipped — daemon holds the store lock",
            DaemonResult::Unresponsive => {
                "skipped — daemon is unresponsive; integrity unverifiable until it is restarted"
            }
            _ => "skipped",
        };
        let drift_detail = match daemon_state {
            DaemonResult::Ok(_) => {
                "skipped — daemon holds the store lock; auto-drain runs on its side"
            }
            DaemonResult::Unresponsive => {
                "skipped — daemon is unresponsive; integrity unverifiable until it is restarted"
            }
            _ => "skipped",
        };
        checks.push(CheckResult {
            section: "integrity",
            name: "dirty_marker",
            status: Status::Info,
            detail: lock_detail.into(),
            fix: None,
        });
        checks.push(CheckResult {
            section: "integrity",
            name: "drift",
            status: Status::Info,
            detail: drift_detail.into(),
            fix: None,
        });
    } else if !root.join("knowledge.db").exists() {
        // Doctor must be side-effect-free. `Store::open` is "create-or-open"
        // — it would scaffold `~/.mati/<slug>/` and initialize SurrealKV
        // files in a directory that has no mati state yet. Diagnostic tools
        // should report state, not create it. So bail out here when the
        // store hasn't been initialized.
        //
        // Fold the "run `mati init`" hint into the skip detail (instead of
        // emitting an extra `integrity/store` check that other scenarios
        // omit) to keep the JSON shape stable across scenarios.
        let no_store_detail =
            "skipped — no store initialized for this directory (run `mati init` to set up)";
        checks.push(CheckResult {
            section: "integrity",
            name: "dirty_marker",
            status: Status::Info,
            detail: no_store_detail.into(),
            fix: Some("mati init"),
        });
        checks.push(CheckResult {
            section: "integrity",
            name: "drift",
            status: Status::Info,
            detail: no_store_detail.into(),
            fix: Some("mati init"),
        });
    } else {
        match Store::open(cwd).await {
            Ok(store) => {
                if is_dirty(&store).await {
                    let detail = match read_dirty_marker(&store).await {
                        Some(m) => format!("{} key(s) flagged: {}", m.affected_keys.len(), m.cause),
                        None => "flagged but cause not readable".to_string(),
                    };
                    checks.push(CheckResult {
                        section: "integrity",
                        name: "dirty_marker",
                        status: Status::Warn,
                        detail,
                        fix: Some("mati repair --fast"),
                    });
                } else {
                    checks.push(CheckResult {
                        section: "integrity",
                        name: "dirty_marker",
                        status: Status::Pass,
                        detail: "not set".into(),
                        fix: None,
                    });
                }

                match check_gotcha_indexes(&store).await {
                    Ok(report) => {
                        if report.has_drift() {
                            let detail = format!(
                                "missing_file={}, stale_file={}, missing_edge={}, stale_edge={}",
                                report.missing_file_links.len(),
                                report.stale_file_links.len(),
                                report.missing_edges.len(),
                                report.stale_edges.len(),
                            );
                            checks.push(CheckResult {
                                section: "integrity",
                                name: "drift",
                                status: Status::Fail,
                                detail,
                                fix: Some("mati repair"),
                            });
                        } else {
                            checks.push(CheckResult {
                                section: "integrity",
                                name: "drift",
                                status: Status::Pass,
                                detail: "no drift detected".into(),
                                fix: None,
                            });
                        }
                    }
                    Err(e) => checks.push(CheckResult {
                        section: "integrity",
                        name: "drift",
                        status: Status::Fail,
                        detail: format!("check error: {e}"),
                        fix: None,
                    }),
                }

                let _ = store.close().await;
            }
            Err(e) => {
                // Store-open failure: emit BOTH dirty_marker and drift as
                // Fail with the same root cause, so the `checks[]` shape
                // matches the other scenarios (always exactly two integrity
                // checks: dirty_marker then drift). The detail carries the
                // open error so triagers see the actual cause.
                let detail = format!("store open failed: {e}");
                checks.push(CheckResult {
                    section: "integrity",
                    name: "dirty_marker",
                    status: Status::Fail,
                    detail: detail.clone(),
                    fix: None,
                });
                checks.push(CheckResult {
                    section: "integrity",
                    name: "drift",
                    status: Status::Fail,
                    detail,
                    fix: None,
                });
            }
        }
    }

    // Lifecycle log tail.
    let lifecycle = read_lifecycle_tail(root, 5);

    // D3: extraction-quality stats. Routes through StoreProxy so it works
    // whether the daemon owns the lock (socket-routed scan_prefix) or the
    // store is direct-accessible. Default window: last 30 days — matches
    // `mati ls tombstoned --recent`'s default and the spec.
    let extraction = collect_extraction_stats(cwd).await;

    // Summary.
    let mut summary = Summary::default();
    for c in &checks {
        match c.status {
            Status::Pass => summary.pass += 1,
            Status::Warn => summary.warn += 1,
            Status::Fail => summary.fail += 1,
            Status::Info => summary.info += 1,
        }
    }

    Report {
        version: 1,
        root: root.display().to_string(),
        checks,
        lifecycle,
        summary,
        extraction,
    }
}

/// Read all `analytics:extraction:*` records via StoreProxy and aggregate.
/// Returns `None` when the proxy can't be opened (uninitialized repo); an
/// empty `ExtractionStats` (total=0) is a valid Some(stats) — means "no
/// enrichment-tagged gotchas have been written yet."
///
/// Window: last 30 days, matching `mati ls tombstoned --recent`'s default
/// and ENRICH_QUALITY.md Section 8.
async fn collect_extraction_stats(
    cwd: &Path,
) -> Option<mati_core::store::extraction::ExtractionStats> {
    use mati_core::store::extraction::{
        aggregate_stats, ExtractionRecord, EXTRACTION_PREFIX,
    };

    let proxy = match crate::cli::proxy::StoreProxy::open(cwd).await {
        Ok(p) => p,
        Err(_) => return None,
    };
    let records = proxy.scan_prefix(EXTRACTION_PREFIX).await.unwrap_or_default();
    let _ = proxy.close().await;

    let extractions: Vec<ExtractionRecord> = records
        .into_iter()
        .filter_map(|r| r.payload.and_then(|p| serde_json::from_value(p).ok()))
        .collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let since = now.saturating_sub(30 * 86_400);
    Some(aggregate_stats(&extractions, since, now))
}

fn read_lifecycle_tail(root: &Path, n: usize) -> Vec<LifecycleEntry> {
    let path = root.join("lifecycle.log");
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..]
        .iter()
        .filter_map(|line| {
            let cols: Vec<&str> = line.splitn(4, '\t').collect();
            if cols.len() != 4 {
                return None;
            }
            Some(LifecycleEntry {
                ts: cols[0].parse().unwrap_or(0),
                pid: cols[1].parse().unwrap_or(0),
                event: cols[2].to_string(),
                detail: cols[3].to_string(),
            })
        })
        .collect()
}

// ── Human renderer ──────────────────────────────────────────────────────────

fn render_human(report: &Report, use_color: bool) {
    println!();
    println!("mati doctor — {}", report.root);
    println!();

    let mut current_section: &str = "";
    for c in &report.checks {
        if c.section != current_section {
            if !current_section.is_empty() {
                println!();
            }
            let title = match c.section {
                "daemon" => "Daemon",
                "integrity" => "Integrity",
                other => other,
            };
            println!("{title}");
            current_section = c.section;
        }
        let symbol = symbol_for(c.status, use_color);
        println!("  {:18} {}  {}", c.name, symbol, c.detail);
        if let Some(fix) = c.fix {
            println!("                       fix: {fix}");
        }
    }

    println!();
    println!("Lifecycle (last {} events)", report.lifecycle.len());
    if report.lifecycle.is_empty() {
        println!("  (no lifecycle.log yet — log fills as the daemon runs)");
    } else {
        for e in &report.lifecycle {
            println!(
                "  {:<14}  pid={:<6} {:<18} {}",
                relative_ts(e.ts),
                e.pid,
                e.event,
                e.detail
            );
        }
    }

    if let Some(extraction) = &report.extraction {
        render_extraction_section(extraction);
    }

    println!();
    let s = &report.summary;
    if s.fail > 0 {
        println!(
            "Result: {} fail, {} warn, {} pass — see fixes above",
            s.fail, s.warn, s.pass
        );
    } else if s.warn > 0 {
        println!("Result: clean with {} warn ({} pass)", s.warn, s.pass);
    } else {
        println!("Result: all checks passed ({} pass)", s.pass);
    }
}

/// Render the D3 extraction-quality section. Skipped entirely when no
/// extractions have been recorded (`total == 0`) — keeps the doctor
/// output clean on fresh installs.
fn render_extraction_section(
    s: &mati_core::store::extraction::ExtractionStats,
) {
    if s.total == 0 {
        return;
    }
    println!();
    println!("Extraction quality (last 30d, /mati-enrich pipeline)");
    println!(
        "  total           {:>4}",
        s.total
    );
    println!(
        "  confirmed       {:>4}  ({})",
        s.confirmed,
        rate_label(s.confirmed, s.total)
    );
    println!(
        "  tombstoned      {:>4}  ({})",
        s.tombstoned,
        rate_label(s.tombstoned, s.total)
    );
    println!(
        "  pending         {:>4}",
        s.pending
    );
    if s.expired > 0 {
        println!("  expired (>90d)  {:>4}", s.expired);
    }

    // Per-tier breakdown — only render tiers with non-zero data.
    let tiers = [
        ("fast    ", &s.per_tier.fast),
        ("standard", &s.per_tier.standard),
        ("deep    ", &s.per_tier.deep),
        ("unknown ", &s.per_tier.unknown),
    ];
    let any_tier_used = tiers.iter().any(|(_, t)| t.total > 0);
    if any_tier_used {
        println!();
        println!("  Per-tier:");
        for (label, tier) in &tiers {
            if tier.total == 0 {
                continue;
            }
            let rate = tier.confirmed_rate().map_or_else(
                || "—".to_string(),
                |r| format!("{:>3.0}% confirmed", r * 100.0),
            );
            println!(
                "    {label}  {:>3} extractions, {rate}",
                tier.total
            );
        }
    }

    // SOTA-δ: per-config A/B breakdown. Hidden when only one config has
    // data (the comparison is meaningless until at least two configs
    // have extractions). Useful for proving the SOTA pipeline (`ast+*`)
    // outperforms the legacy LLM-driven scan (`llm+*`).
    let active_configs: Vec<_> = s
        .per_config
        .iter()
        .filter(|(_, t)| t.total > 0)
        .collect();
    if active_configs.len() >= 2 {
        println!();
        println!("  Per-config (A/B):");
        // Render in stable order: BTreeMap iteration is alphabetical
        // which is fine — `ast+*` sorts before `llm+*`.
        for (label, tier) in &active_configs {
            let rate = tier.confirmed_rate().map_or_else(
                || "—".to_string(),
                |r| format!("{:>3.0}% confirmed", r * 100.0),
            );
            println!(
                "    {label:>11}  {:>3} extractions, {rate}",
                tier.total
            );
        }
    }
}

fn rate_label(n: u64, total: u64) -> String {
    if total == 0 {
        "0%".to_string()
    } else {
        format!("{}%", (n * 100) / total)
    }
}

fn symbol_for(status: Status, use_color: bool) -> String {
    let s = match status {
        Status::Pass => "ok",
        Status::Warn => "WARN",
        Status::Fail => "FAIL",
        Status::Info => "—",
    };
    if !use_color {
        return s.to_string();
    }
    match status {
        Status::Pass => format!("\x1b[32m{s}\x1b[0m"),
        Status::Warn => format!("\x1b[33m{s}\x1b[0m"),
        Status::Fail => format!("\x1b[31m{s}\x1b[0m"),
        Status::Info => format!("\x1b[90m{s}\x1b[0m"),
    }
}

fn relative_ts(ts: u64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ago = now.saturating_sub(ts);
    if ago == 0 {
        "just now".into()
    } else if ago < 60 {
        format!("{ago}s ago")
    } else if ago < 3600 {
        format!("{}m ago", ago / 60)
    } else if ago < 86400 {
        format!("{}h ago", ago / 3600)
    } else {
        format!("{}d ago", ago / 86400)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_lifecycle_tail_parses_well_formed_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lifecycle.log"),
            "100\t111\tserve_start\tpid=111 owner=mcp\n\
             200\t111\tserve_shutdown\tclean\n",
        )
        .unwrap();
        let entries = read_lifecycle_tail(dir.path(), 5);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ts, 100);
        assert_eq!(entries[0].event, "serve_start");
        assert_eq!(entries[1].detail, "clean");
    }

    #[test]
    fn read_lifecycle_tail_returns_last_n_only() {
        let dir = tempfile::tempdir().unwrap();
        let body: String = (0..10)
            .map(|i| format!("{i}\t{i}\tevent{i}\tdetail{i}\n"))
            .collect();
        std::fs::write(dir.path().join("lifecycle.log"), body).unwrap();
        let entries = read_lifecycle_tail(dir.path(), 3);
        assert_eq!(entries.len(), 3);
        // Last three: 7, 8, 9
        assert_eq!(entries[0].ts, 7);
        assert_eq!(entries[2].ts, 9);
    }

    #[test]
    fn read_lifecycle_tail_skips_malformed_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lifecycle.log"),
            "100\t111\tserve_start\tok\n\
             not\ta\tvalid\n\
             200\t111\tserve_shutdown\tclean\n",
        )
        .unwrap();
        let entries = read_lifecycle_tail(dir.path(), 5);
        // Malformed line has only 3 tab-separated fields → skipped.
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn read_lifecycle_tail_returns_empty_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let entries = read_lifecycle_tail(dir.path(), 5);
        assert!(entries.is_empty());
    }

    /// End-to-end round trip: events written by the canonical writer
    /// (`mcp::metadata::record_lifecycle_event`) must parse back through the
    /// doctor reader without losing fields. The other reader-side tests use
    /// hand-rolled fixture strings — if the writer's column layout, separator,
    /// or escaping ever drifts, those tests would still pass while doctor's
    /// "Lifecycle (last N events)" panel silently goes blank in the field.
    /// Pass 24 caught this exact pattern in `fail_open.log`; this test guards
    /// the lifecycle.log surface against the same class of regression.
    #[test]
    fn lifecycle_log_round_trip_writer_reader() {
        use mati_core::mcp::metadata::record_lifecycle_event;
        let dir = tempfile::tempdir().unwrap();
        // Three events through the real writer — including a payload with
        // tabs/newlines so we cover the writer's escaping path.
        record_lifecycle_event(dir.path(), "serve_start", "owner=mcp");
        record_lifecycle_event(dir.path(), "panic", "boom\twith\ttabs\nand newline");
        record_lifecycle_event(dir.path(), "serve_shutdown", "reason=signal");

        let entries = read_lifecycle_tail(dir.path(), 5);
        assert_eq!(
            entries.len(),
            3,
            "doctor reader must parse all 3 writer-emitted lines, got {}",
            entries.len()
        );
        assert_eq!(entries[0].event, "serve_start");
        assert_eq!(entries[0].detail, "owner=mcp");
        assert_eq!(entries[1].event, "panic");
        // Writer replaces tabs/newlines with spaces so each event stays one line.
        assert!(
            !entries[1].detail.contains('\t') && !entries[1].detail.contains('\n'),
            "writer must scrub tabs/newlines; reader saw: {:?}",
            entries[1].detail
        );
        assert!(
            entries[1].detail.contains("boom") && entries[1].detail.contains("tabs"),
            "writer must preserve detail content (modulo separator scrubbing); got {:?}",
            entries[1].detail
        );
        assert_eq!(entries[2].event, "serve_shutdown");
        assert_eq!(entries[2].detail, "reason=signal");
        // Timestamps are real Unix seconds — must be non-zero, monotonic.
        assert!(entries[0].ts > 0, "writer must emit a real Unix timestamp");
        assert!(
            entries[0].ts <= entries[2].ts,
            "timestamps must be monotonic"
        );
        // PID must round-trip as the current process id.
        let pid = std::process::id();
        for e in &entries {
            assert_eq!(e.pid, pid, "writer→reader pid round-trip must be stable");
        }
    }

    /// Schema-stability invariant for `mati doctor --json`:
    /// every scenario (no-daemon-no-store, no-daemon-with-store,
    /// daemon-running, daemon-unresponsive, store-open-failed) must emit
    /// exactly one `daemon/ping` check followed by `integrity/dirty_marker`
    /// then `integrity/drift`, in that order. CI consumers parse the report
    /// by name and by index, and a `version: 1` schema must keep both
    /// stable.
    ///
    /// This is a hermetic test: it drives `collect()` against a tempdir
    /// with no daemon and no `knowledge.db`, exercising the no-store
    /// branch. The other branches are exercised by the smoke tests in
    /// audit pass 18; their schema parity is guaranteed by code review of
    /// the single match arm in `collect()` that always pushes
    /// `dirty_marker` before `drift`.
    #[tokio::test]
    async fn doctor_json_shape_is_stable_across_scenarios() {
        let dir = tempfile::tempdir().unwrap();
        // No `knowledge.db` here — exercises the "no store" branch.
        let report = collect(dir.path(), dir.path()).await;
        let names: Vec<(&str, &str)> = report.checks.iter().map(|c| (c.section, c.name)).collect();
        assert_eq!(
            names,
            vec![
                ("daemon", "ping"),
                ("integrity", "dirty_marker"),
                ("integrity", "drift"),
            ],
            "doctor JSON check sequence must be ping → dirty_marker → drift"
        );
        assert_eq!(report.version, 1);
    }
}
