use std::io::{self, IsTerminal};

use anyhow::Result;
use clap::Args;

use mati_core::store::repair::{
    check_gotcha_indexes, is_dirty, repair_gotcha_indexes, RepairMode, RepairReport,
};
use mati_core::store::Store;

use super::colors;
use super::daemon::{daemon_result, mati_root_for, DaemonResult};

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
    let root = mati_root_for(&cwd)?;
    let use_color = io::stderr().is_terminal() && !args.json;

    // Refuse if daemon owns the store
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

    let report = if args.check {
        let report = check_gotcha_indexes(&store).await?;
        store.close().await?;

        if args.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            print_check_report(&report, use_color);
        }

        if report.has_drift() {
            std::process::exit(1);
        }
        return Ok(());
    } else {
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

        repair_gotcha_indexes(&store, mode).await?
    };

    store.close().await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_repair_report(&report, use_color);
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
