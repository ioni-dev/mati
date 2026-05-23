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
        let mut file_records = graph.store().scan_prefix("file:").await.unwrap_or_default();
        let mut blast_count = 0u32;
        let all_keys: Vec<String> = file_records.iter().map(|r| r.key.clone()).collect();
        let blast_map =
            mati_core::analysis::blast_radius::BlastRadius::compute_all(&graph, &all_keys);

        // In-memory mutation.
        for record in file_records.iter_mut() {
            if let Some(mut fr) = record.payload_as::<mati_core::store::record::FileRecord>() {
                if let Some(br) = blast_map.get(&record.key) {
                    fr.blast_radius = Some(br.clone());
                    record.payload = serde_json::to_value(&fr).ok();
                    blast_count += 1;
                }
            }
        }

        // Bulk write.
        let pairs: Vec<(&str, &mati_core::store::record::Record)> =
            file_records.iter().map(|r| (r.key.as_str(), r)).collect();
        let _ = graph.store().put_batch_kv_only(&pairs).await;
        if !args.json {
            println!("  Blast radius recomputed for {blast_count} files.");
        }

        // Phase: recompute cluster index from the persisted source-of-truth
        // pairs record (`analytics:co_change_pairs`). Init writes this record
        // alongside `cluster:index` (see `src/cli/init.rs` Phase 10b-ii).
        //
        // History (DECISIONS.md ADR-021): a previous implementation here
        // reconstructed pairs from CoChanges graph edges with a synthetic
        // `count = MIN_COCHANGE_COUNT`. That bypassed `ClusterIndex::compute`'s
        // count filter (`src/analysis/clusters.rs:55-59`) and collapsed all
        // graph edges into a giant connected component — repair printed e.g.
        // "2 clusters" when init had produced 11. The fix: read the real
        // (a, b, count) tuples from `analytics:co_change_pairs` so the count
        // filter applies correctly.
        {
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let pairs_record = graph.store().get("analytics:co_change_pairs").await;
            let pairs: Option<Vec<(String, String, u32)>> = pairs_record
                .ok()
                .flatten()
                .and_then(|r| r.payload)
                .and_then(|p| p.get("pairs").cloned())
                .and_then(|v| serde_json::from_value(v).ok());

            match pairs {
                Some(pairs) => {
                    let total_files = file_records.len();
                    let cluster_index =
                        mati_core::analysis::clusters::ClusterIndex::compute(
                            &pairs,
                            total_files,
                        );
                    let cluster_record = mati_core::store::record::Record {
                        key: "cluster:index".to_string(),
                        value: format!(
                            "{} clusters, {} clustered files",
                            cluster_index.total, cluster_index.clustered_files
                        ),
                        payload: serde_json::to_value(&cluster_index).ok(),
                        category: mati_core::store::record::Category::Analytics,
                        priority: mati_core::store::record::Priority::Normal,
                        tags: vec![],
                        created_at: now_ts,
                        updated_at: now_ts,
                        ref_url: None,
                        staleness: mati_core::store::record::StalenessScore::fresh(),
                        lifecycle: mati_core::store::record::RecordLifecycle::Active,
                        version: mati_core::store::record::RecordVersion {
                            device_id: uuid::Uuid::new_v4(),
                            logical_clock: 1,
                            wall_clock: now_ts,
                        },
                        quality: mati_core::store::record::QualityScore::layer0_default(),
                        access_count: 0,
                        last_accessed: 0,
                        source: mati_core::store::record::RecordSource::StaticAnalysis,
                        confidence: mati_core::store::record::ConfidenceScore::for_new_record(
                            &mati_core::store::record::RecordSource::StaticAnalysis,
                        ),
                        gap_analysis_score: 0.0,
                    };
                    let _ = graph.store().put("cluster:index", &cluster_record).await;
                    if !args.json {
                        println!("  Clusters recomputed: {} found.", cluster_index.total);
                    }
                }
                None => {
                    if !args.json {
                        println!(
                            "  Clusters: skipped — analytics:co_change_pairs not present \
                             (run `mati init` to populate it). Existing cluster:index left intact."
                        );
                    }
                }
            }
        }

        // Phase: recompute propagated staleness.
        {
            let all_recs = graph.store().scan_prefix("file:").await.unwrap_or_default();
            let propagation =
                mati_core::analysis::propagation::compute_propagation(&all_recs, &graph);
            let mut prop_count = 0u32;
            for (key, prop) in &propagation {
                if let Ok(Some(mut record)) = graph.store().get(key).await {
                    if let Some(mut fr) =
                        record.payload_as::<mati_core::store::record::FileRecord>()
                    {
                        fr.propagated_staleness = Some(prop.clone());
                        record.payload = serde_json::to_value(&fr).ok();
                        let _ = graph.store().put(key, &record).await;
                        prop_count += 1;
                    }
                }
            }
            if !args.json && prop_count > 0 {
                println!("  Staleness propagation recomputed for {prop_count} files.");
            }
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

/// Read-only drift check. Requires direct store access because graph edges
/// are not guaranteed to be fully persisted while the daemon holds the store —
/// in-memory edges can produce false-positive drift reports through the proxy.
async fn run_check(cwd: &std::path::Path, json: bool, use_color: bool) -> Result<()> {
    let proxy = StoreProxy::open(cwd).await?;

    let result = async {
        match proxy.direct_store() {
            Some(store) => check_gotcha_indexes(store).await,
            None => anyhow::bail!(
                "mati repair --check requires direct store access, which is unavailable while the daemon is running.\n\
                 Run `mati daemon stop` and retry."
            ),
        }
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
