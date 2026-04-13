use std::io::{self, IsTerminal};

use anyhow::Result;
use clap::Args;

use mati_core::store::repair::{
    check_gotcha_indexes, is_dirty, repair_gotcha_indexes, RepairMode, RepairReport,
};
use mati_core::store::Store;

use super::colors;
use super::daemon::{daemon_result, mati_root_for, DaemonResult};
use super::proxy::StoreProxy;

#[derive(Args)]
#[command(
    long_about = "Maintenance: reconcile derived gotcha indexes from canonical records.\n\
                  File links (gotcha_keys) and graph edges are materialized views — if they\n\
                  drift from the canonical gotcha records, this command rebuilds them.\n\n\
                  Drift is detected automatically and surfaced in `mati status`.\n\
                  Use --check in CI to fail the build on index inconsistency."
)]
pub struct RepairArgs {
    /// Check for drift without making changes (exits non-zero if drift exists, CI-ready)
    #[arg(long)]
    pub check: bool,

    /// Drain queued dirty items only — fast but not a full integrity guarantee.
    /// Use the default full scan for authoritative verification.
    #[arg(long)]
    pub fast: bool,

    /// Output machine-readable JSON report
    #[arg(long)]
    pub json: bool,
}

pub async fn run(args: RepairArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let use_color = io::stderr().is_terminal() && !args.json;

    // --check is read-only and works through StoreProxy (daemon or direct).
    if args.check {
        return run_check(&cwd, args.json, use_color).await;
    }

    // Repair (write) requires exclusive direct store access.
    let root = mati_root_for(&cwd)?;
    match daemon_result(&root, "ping", serde_json::json!({})).await {
        DaemonResult::Ok(_) | DaemonResult::Unresponsive => {
            anyhow::bail!(
                "mati repair requires direct store access, which is unavailable while the daemon is running.\n\
                 Run `mati daemon stop` and retry."
            );
        }
        DaemonResult::NotRunning | DaemonResult::StaleSocket => {}
    }

    let store = Store::open(&cwd).await?;

    let mode = if args.fast {
        RepairMode::Fast
    } else {
        RepairMode::Full
    };

    // Show pre-repair state for full mode
    if mode == RepairMode::Full && !args.json {
        let pre = check_gotcha_indexes(&store).await?;
        if !pre.has_drift() {
            let dirty = is_dirty(&store).await;
            if dirty {
                println!("No drift detected, but dirty marker is set. Clearing.");
            } else {
                println!("No drift detected. Indexes are consistent.");
                store.close().await?;
                return Ok(());
            }
        } else {
            print_drift_summary(&pre, use_color);
            println!();
        }
    }

    let report = repair_gotcha_indexes(&store, mode).await?;

    // Phase: recompute blast radius for all file records.
    // Requires graph with Imports edges for traversal.
    if mode == RepairMode::Full {
        let graph = mati_core::graph::Graph::load(store).await?;
        let file_records = graph.store().scan_prefix("file:").await.unwrap_or_default();
        let mut blast_count = 0u32;
        for record in &file_records {
            let mut rec = record.clone();
            if let Some(mut fr) =
                rec.payload_as::<mati_core::store::record::FileRecord>()
            {
                let br = mati_core::analysis::blast_radius::BlastRadius::compute(
                    &rec.key, &graph,
                );
                fr.blast_radius = Some(br);
                rec.payload = serde_json::to_value(&fr).ok();
                let _ = graph.store().put(&rec.key, &rec).await;
                blast_count += 1;
            }
        }
        if !args.json {
            println!("  Blast radius recomputed for {blast_count} files.");
        }
        graph.close().await?;
    } else {
        store.close().await?;
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_repair_report(&report, use_color);
    }

    Ok(())
}

/// Read-only check via StoreProxy — works while daemon/MCP holds the lock.
async fn run_check(cwd: &std::path::Path, json: bool, use_color: bool) -> Result<()> {
    let proxy = StoreProxy::open(cwd).await?;

    let result = async {
        // In direct mode, use the optimized check_gotcha_indexes.
        // In socket mode, replicate the check using proxy scans.
        if let Some(store) = proxy.direct_store() {
            return check_gotcha_indexes(store).await;
        }

        // Socket mode: scan all data through the proxy and diff locally.
        check_via_proxy(&proxy).await
    }
    .await;

    let report = proxy.close_with_result(result).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_check_report(&report, use_color);
    }

    if report.has_drift() {
        std::process::exit(1);
    }
    Ok(())
}

/// Replicate check_gotcha_indexes logic using proxy scans (socket mode).
async fn check_via_proxy(proxy: &StoreProxy) -> Result<RepairReport> {
    use mati_core::graph::edges::{Edge, EdgeKind};
    use mati_core::store::{GotchaRecord, RecordLifecycle};
    use std::collections::{BTreeSet, HashMap};

    // Phase 1: derive desired state from canonical gotcha records
    let gotchas = proxy.scan_prefix("gotcha:").await?;
    let scanned_gotchas = gotchas.len();

    let mut desired_file_links: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut desired_edges: BTreeSet<(String, String)> = BTreeSet::new();

    for record in &gotchas {
        if !matches!(record.lifecycle, RecordLifecycle::Active) {
            continue;
        }
        let Some(gotcha) = record.payload_as::<GotchaRecord>() else {
            continue;
        };
        for file_path in &gotcha.affected_files {
            desired_file_links
                .entry(file_path.clone())
                .or_default()
                .insert(record.key.clone());
            desired_edges.insert((file_path.clone(), record.key.clone()));
        }
    }

    // Phase 2: read actual file links
    let files = proxy.scan_prefix("file:").await?;
    let scanned_files = files.len();
    let mut actual_file_links: HashMap<String, Vec<String>> = HashMap::new();

    for record in &files {
        let path = record
            .key
            .strip_prefix("file:")
            .unwrap_or(&record.key)
            .to_string();
        let keys: Vec<String> = record
            .payload
            .as_ref()
            .and_then(|p| p.get("gotcha_keys"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if !keys.is_empty() {
            actual_file_links.insert(path, keys);
        }
    }

    // Phase 3: read actual edges from graph:edge: records
    let edge_records = proxy.scan_prefix("graph:edge:").await?;
    let mut actual_edges: BTreeSet<(String, String)> = BTreeSet::new();

    for record in &edge_records {
        if let Some(edge) = Edge::from_key(&record.key) {
            if edge.kind == EdgeKind::HasGotcha {
                let file_path = edge
                    .from
                    .strip_prefix("file:")
                    .unwrap_or(&edge.from)
                    .to_string();
                actual_edges.insert((file_path, edge.to));
            }
        }
    }

    // Phase 4: diff
    use mati_core::store::repair::DriftEntry;

    let mut missing_file_links = Vec::new();
    let mut stale_file_links = Vec::new();

    for (file_path, desired_keys) in &desired_file_links {
        let actual_keys: BTreeSet<String> = actual_file_links
            .get(file_path)
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default();
        for key in desired_keys {
            if !actual_keys.contains(key) {
                missing_file_links.push(DriftEntry {
                    file_path: file_path.clone(),
                    gotcha_key: key.clone(),
                });
            }
        }
    }
    for (file_path, actual_keys) in &actual_file_links {
        let desired_keys = desired_file_links
            .get(file_path)
            .cloned()
            .unwrap_or_default();
        for key in actual_keys {
            if !desired_keys.contains(key) {
                stale_file_links.push(DriftEntry {
                    file_path: file_path.clone(),
                    gotcha_key: key.clone(),
                });
            }
        }
    }

    let missing_edges: Vec<DriftEntry> = desired_edges
        .difference(&actual_edges)
        .map(|(f, g)| DriftEntry {
            file_path: f.clone(),
            gotcha_key: g.clone(),
        })
        .collect();
    let stale_edges: Vec<DriftEntry> = actual_edges
        .difference(&desired_edges)
        .map(|(f, g)| DriftEntry {
            file_path: f.clone(),
            gotcha_key: g.clone(),
        })
        .collect();

    Ok(RepairReport {
        scanned_gotchas,
        scanned_files,
        missing_file_links,
        stale_file_links,
        missing_edges,
        stale_edges,
        repaired_count: 0,
        verification_passed: true,
        dirty_marker_cleared: false,
    })
}

fn print_check_report(report: &RepairReport, use_color: bool) {
    let (green, _yellow, blue, gray, white, bold, reset) = if use_color {
        (
            colors::GREEN,
            colors::YELLOW,
            colors::BLUE,
            colors::GRAY,
            colors::WHITE,
            colors::BOLD,
            colors::RESET,
        )
    } else {
        ("", "", "", "", "", "", "")
    };

    println!(
        "\n{bold}{blue}mati repair --check{reset}  {gray}scanned {white}{}{reset} gotchas, {white}{}{reset} files{reset}\n",
        report.scanned_gotchas, report.scanned_files
    );

    if !report.has_drift() {
        println!("  {green}No drift detected.{reset} Indexes are consistent.");
    } else {
        print_drift_summary(report, use_color);
    }
    println!();
}

fn print_drift_summary(report: &RepairReport, use_color: bool) {
    let (yellow, white, reset) = if use_color {
        (colors::YELLOW, colors::WHITE, colors::RESET)
    } else {
        ("", "", "")
    };

    if !report.missing_file_links.is_empty() {
        println!(
            "  {yellow}Missing file links:{reset}  {white}{}{reset}",
            report.missing_file_links.len()
        );
        for entry in report.missing_file_links.iter().take(5) {
            println!("    {entry}", entry = format_drift(entry));
        }
        if report.missing_file_links.len() > 5 {
            println!("    ... and {} more", report.missing_file_links.len() - 5);
        }
    }

    if !report.stale_file_links.is_empty() {
        println!(
            "  {yellow}Stale file links:{reset}    {white}{}{reset}",
            report.stale_file_links.len()
        );
        for entry in report.stale_file_links.iter().take(5) {
            println!("    {entry}", entry = format_drift(entry));
        }
        if report.stale_file_links.len() > 5 {
            println!("    ... and {} more", report.stale_file_links.len() - 5);
        }
    }

    if !report.missing_edges.is_empty() {
        println!(
            "  {yellow}Missing edges:{reset}       {white}{}{reset}",
            report.missing_edges.len()
        );
    }

    if !report.stale_edges.is_empty() {
        println!(
            "  {yellow}Stale edges:{reset}         {white}{}{reset}",
            report.stale_edges.len()
        );
    }

    println!(
        "\n  Total drift: {yellow}{}{reset} items",
        report.total_drift()
    );
}

fn print_repair_report(report: &RepairReport, use_color: bool) {
    let (green, red, white, bold, reset) = if use_color {
        (
            colors::GREEN,
            colors::RED,
            colors::WHITE,
            colors::BOLD,
            colors::RESET,
        )
    } else {
        ("", "", "", "", "")
    };

    if report.repaired_count == 0 {
        println!("{green}Nothing to repair.{reset}");
        return;
    }

    println!(
        "\n{bold}Repaired {white}{}{reset} items.",
        report.repaired_count
    );

    if report.verification_passed {
        println!("  {green}Verification passed.{reset} Indexes are now consistent.");
    } else {
        println!(
            "  {red}Verification failed.{reset} Some drift may remain — run `mati repair` again."
        );
    }

    if report.dirty_marker_cleared {
        println!("  Dirty marker cleared.");
    }
    println!();
}

fn format_drift(entry: &mati_core::store::repair::DriftEntry) -> String {
    format!("{} → {}", entry.file_path, entry.gotcha_key)
}
