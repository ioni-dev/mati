use std::io::{self, IsTerminal};

use anyhow::Result;
use clap::Args;

use mati_core::store::repair::{
    check_gotcha_indexes, find_orphaned_files, is_dirty, purge_orphaned_files,
    repair_gotcha_indexes, OrphanKind, OrphanScan, PurgeOutcome, RepairMode, RepairReport,
};
use mati_core::store::{RepoIdent, Store};

use super::colors;
use super::daemon::{daemon_result, mati_root_for_ident, DaemonResult};
use super::proxy::StoreProxy;

#[derive(Args)]
#[command(
    long_about = "Maintenance: reconcile derived gotcha indexes from canonical records.\n\
                  File links (gotcha_keys) and graph edges are materialized views — if they\n\
                  drift from the canonical gotcha records, this command rebuilds them.\n\n\
                  Drift is detected automatically and surfaced in `mati status`.\n\
                  Use --check in CI to fail the build on index inconsistency.\n\n\
                  The full scan also deletes enforcement events older than\n\
                  `enforcement.retention` (default 365 days) and records a\n\
                  RetentionPruned event. --check and --fast never delete anything.\n\n\
                  The full scan also counts file records whose path is no longer in\n\
                  the repo. It only removes them with --purge-orphans."
)]
pub struct RepairArgs {
    /// Check for drift without making changes (exits non-zero if drift exists, CI-ready)
    #[arg(long)]
    pub check: bool,

    /// Drain queued dirty items only — fast but not a full integrity guarantee.
    /// Use the default full scan for authoritative verification.
    #[arg(long)]
    pub fast: bool,

    /// Tombstone file records whose path is no longer in the repo, and unlink
    /// them from their gotchas. Refuses when they are most of the store.
    #[arg(long, conflicts_with_all = ["check", "fast"])]
    pub purge_orphans: bool,

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

    // One discover call grounds the mati root and the root record paths
    // resolve against in the same git identity.
    let ident = RepoIdent::discover(&cwd);
    let repo_root = ident.slug_root(&cwd);

    // Repair (write) requires exclusive direct store access.
    let root = mati_root_for_ident(&ident, &cwd)?;
    match daemon_result(&root, "ping", serde_json::json!({})).await {
        DaemonResult::Ok(_) | DaemonResult::Unresponsive | DaemonResult::PermissionDenied => {
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

    // Full scan only, and ahead of the "nothing to repair" early return below:
    // the event log expires on its own clock, not on index drift. --check
    // returned above and --fast is Fast mode, so neither reaches this.
    if mode == RepairMode::Full {
        prune_expired_events(&store, args.json).await?;
    }

    // Ahead of the reconcile: a purge tombstones file records, and the desired
    // state has to be derived after that to come out consistent.
    let orphans = if mode == RepairMode::Full {
        let scan = find_orphaned_files(&store, &repo_root).await?;
        if args.purge_orphans {
            purge_orphans(&store, &scan, &ident, args.json).await?;
        } else if !args.json {
            print_orphan_summary(&scan, use_color);
        }
        scan.orphans
    } else {
        vec![]
    };

    // Show pre-repair state for full mode
    if mode == RepairMode::Full && !args.json {
        let pre = check_gotcha_indexes(&store, &repo_root).await?;
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

    let mut report = repair_gotcha_indexes(&store, &repo_root, mode).await?;
    report.orphaned_files = orphans;

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
        // alongside `cluster:index` (see `src/cli/init/run.rs:983-1025` Phase 10b-ii).
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
                        mati_core::analysis::clusters::ClusterIndex::compute(&pairs, total_files);
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
                            device_id: mati_core::store::stable_device_id(),
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

/// Delete enforcement events past the configured retention window.
///
/// The only destructive step in `mati repair` that touches canonical data, so
/// it always says what it removed. `enforce_retention` deletes an oldest-first
/// prefix, which `mati verify-chain` still reads as intact; the
/// `RetentionPruned` event it appends is the record that the deletion happened.
async fn prune_expired_events(store: &Store, json: bool) -> Result<()> {
    use mati_core::store::enforcement::{enforce_retention, PruneResult};

    match enforce_retention(store).await? {
        PruneResult::NothingToPrune => {}
        PruneResult::Pruned {
            count,
            oldest_seq,
            newest_seq,
        } => {
            if !json {
                println!(
                    "  Enforcement events pruned: {count} (seq {oldest_seq}-{newest_seq}) \
                     past the retention window."
                );
            }
        }
    }
    Ok(())
}

/// Tombstone file records whose path is no longer in the repo.
///
/// Refuses without a git working tree. A root that names the wrong tree fails
/// every path, and this repo has already lost a store to two components
/// disagreeing about which root that is — so the purge asserts a deletion only
/// from git's own `workdir`, the same grounding the staleness analyzer requires
/// before it tombstones anything.
async fn purge_orphans(
    store: &Store,
    scan: &OrphanScan,
    ident: &RepoIdent,
    json: bool,
) -> Result<()> {
    if ident.workdir.is_none() {
        anyhow::bail!(
            "--purge-orphans needs a git working tree to resolve record paths against.\n\
             git found none here, so a missing file cannot be told from a wrong root."
        );
    }

    match purge_orphaned_files(store, scan).await? {
        PurgeOutcome::Purged {
            tombstoned,
            unlinked,
        } => {
            if !json {
                println!(
                    "  Orphaned file records tombstoned: {tombstoned} \
                     ({unlinked} gotcha links unlinked)."
                );
            }
        }
        PurgeOutcome::Refused {
            orphans,
            active_files,
        } => {
            anyhow::bail!(
                "refusing to purge: {orphans} of {active_files} file records look orphaned.\n\
                 That is the signature of a wrong repo root, not of a stale store. \
                 Check that `mati status` names the repo you expect before retrying."
            );
        }
    }
    Ok(())
}

/// Read-only drift check. Runs through `StoreProxy`, which routes reads to
/// the daemon socket when one holds the lock and falls back to a direct
/// `Store` otherwise -- `StoreProxy` implements `RepairReader` for exactly
/// this (see `src/cli/proxy.rs`). Edge writes go back to SurrealKV
/// immediately (never held only in the daemon's in-memory graph), so the
/// socket-routed scan sees the same on-disk state a direct open would.
async fn run_check(cwd: &std::path::Path, json: bool, use_color: bool) -> Result<()> {
    let proxy = StoreProxy::open(cwd).await?;

    let result = async {
        let mut report = check_gotcha_indexes(&proxy, proxy.repo_root()).await?;
        let scan = find_orphaned_files(&proxy, proxy.repo_root()).await?;
        report.orphaned_files = scan.orphans;
        Ok((report, scan.active_files))
    }
    .await;

    let (report, active_files) = proxy.close_with_result(result).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_check_report(&report, active_files, use_color);
    }

    if report.has_drift() {
        std::process::exit(1);
    }
    Ok(())
}

fn print_check_report(report: &RepairReport, active_files: usize, use_color: bool) {
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
    let scan = OrphanScan {
        orphans: report.orphaned_files.clone(),
        active_files,
    };
    print_orphan_summary(&scan, use_color);
    println!();
}

/// Orphans are reported, never repaired: `--check` is read-only and a plain
/// `mati repair` is non-destructive. Only `--purge-orphans` acts on them.
///
/// `active_files` is the denominator [`purge_orphaned_files`] refuses on. At
/// that share the store's keys no longer describe this tree, so the summary
/// points at a re-init instead of a purge. It cannot say why — a subtree init,
/// a foreign checkout and a wholesale rename all look identical from the
/// orphan set alone — but re-indexing is the remedy for all three.
fn print_orphan_summary(scan: &OrphanScan, use_color: bool) {
    let orphans = &scan.orphans;
    if orphans.is_empty() {
        return;
    }
    let (yellow, white, gray, reset) = if use_color {
        (colors::YELLOW, colors::WHITE, colors::GRAY, colors::RESET)
    } else {
        ("", "", "", "")
    };

    let count = |kind| orphans.iter().filter(|o| o.kind == kind).count();
    let outside = count(OrphanKind::OutsideRepo);
    let deleted = count(OrphanKind::DeletedInRepo);
    let scaffold = count(OrphanKind::Scaffold);

    println!(
        "\n  {yellow}Orphaned file records:{reset} {white}{}{reset}  \
         {gray}({outside} outside the repo, {deleted} deleted in it, \
         {scaffold} written by mati init){reset}",
        orphans.len()
    );
    for entry in orphans.iter().take(5) {
        println!("    {}", entry.key);
    }
    if orphans.len() > 5 {
        println!("    ... and {} more", orphans.len() - 5);
    }

    if scan.looks_like_wrong_root() {
        println!(
            "  {yellow}Nearly every file record is orphaned.{reset} {gray}Either these keys \
             were written against a different root — most often `mati init --path <subdir>` \
             — or the tree moved wholesale. Re-run `mati init` from the repo root. \
             `--purge-orphans` refuses at this share, and would delete the records rather \
             than re-key them.{reset}"
        );
    } else {
        println!("  {gray}Remove them with `mati repair --purge-orphans`.{reset}");
    }
}

fn print_drift_summary(report: &RepairReport, use_color: bool) {
    let (yellow, white, reset) = if use_color {
        (colors::YELLOW, colors::WHITE, colors::RESET)
    } else {
        ("", "", "")
    };

    if !report.unnormalized_paths.is_empty() {
        println!(
            "  {yellow}Unnormalized paths:{reset}  {white}{}{reset}",
            report.unnormalized_paths.len()
        );
        for entry in report.unnormalized_paths.iter().take(5) {
            println!("    {entry}", entry = format_drift(entry));
        }
        if report.unnormalized_paths.len() > 5 {
            println!("    ... and {} more", report.unnormalized_paths.len() - 5);
        }
    }

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
