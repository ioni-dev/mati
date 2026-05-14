//! `mati diff <range>` — PR Review Safety Net (P2)
//!
//! Cross-references a git diff against the knowledge store and surfaces
//! relevant confirmed gotchas at the highest-risk moment: before merge.
//!
//! Usage:
//!   mati diff main
//!   mati diff main..feature-auth
//!   mati diff HEAD~3

use std::io::IsTerminal as _;
use std::process::Command;

use anyhow::Result;
use clap::Args;

use mati_core::store::{
    FileRecord, GotchaRecord, Priority, Record, RecordLifecycle, StalenessTier,
};

use super::proxy::StoreProxy;

use super::colors;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Severity {
    Critical,
    High,
    Normal,
    Unknown,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Normal => "NORMAL",
            Self::Unknown => "UNKNOWN",
        }
    }

    fn marker(self) -> &'static str {
        match self {
            Self::Critical | Self::High => "●",
            Self::Normal => "○",
            Self::Unknown => "?",
        }
    }
}

fn worst_staleness(gotchas: &[Record]) -> Option<StalenessTier> {
    gotchas
        .iter()
        .map(|g| g.staleness.tier.clone())
        .filter(|t| {
            matches!(
                t,
                StalenessTier::Stale | StalenessTier::Liability | StalenessTier::Tombstone
            )
        })
        .max_by_key(|t| match t {
            StalenessTier::Tombstone => 3,
            StalenessTier::Liability => 2,
            StalenessTier::Stale => 1,
            _ => 0,
        })
}

fn stale_label(tier: &StalenessTier) -> &'static str {
    match tier {
        StalenessTier::Stale => "Stale",
        StalenessTier::Liability => "Liability",
        StalenessTier::Tombstone => "Tombstone",
        _ => "",
    }
}

#[derive(Args)]
#[command(
    long_about = "Pre-merge check — cross-reference a git diff against the knowledge store.\n\
                  Surfaces confirmed gotchas for changed files before merge.\n\n\
                  When RANGE is omitted, diffs the working tree + index against HEAD.\n\n\
                  Examples:\n  \
                    mati diff\n  \
                    mati diff main\n  \
                    mati diff main..feature-auth\n  \
                    mati diff HEAD~3"
)]
pub struct DiffArgs {
    /// Git ref or range to diff (e.g. "main", "main..feature-auth", "HEAD~3").
    /// Omit to diff the working tree against HEAD.
    pub range: Option<String>,
}

pub async fn run(args: DiffArgs) -> Result<()> {
    let use_color = std::io::stdout().is_terminal();
    let cwd = std::env::current_dir()?;

    let range = args.range.as_deref().unwrap_or("HEAD");

    // ── Get changed files from git ────────────────────────────────────────────
    let output = Command::new("git")
        .args(["diff", "--name-only", range])
        .current_dir(&cwd)
        .output()?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git diff failed: {err}");
    }

    let changed: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();

    if changed.is_empty() {
        println!("No files changed in '{range}'");
        return Ok(());
    }

    let store = StoreProxy::open(&cwd).await?;

    println!();
    if use_color {
        println!(
            "  {BLUE}PRE-MERGE CHECK — {n} file{s} changed{RESET}",
            BLUE = colors::BLUE,
            RESET = colors::RESET,
            n = changed.len(),
            s = if changed.len() == 1 { "" } else { "s" },
        );
    } else {
        println!(
            "  PRE-MERGE CHECK — {} file{} changed",
            changed.len(),
            if changed.len() == 1 { "" } else { "s" },
        );
    }
    println!();

    // Pre-compute per-file rows so we can right-align status to the longest path.
    struct Row {
        path: String,
        severity: Severity,
        gotcha_count: usize,
        stale: Option<StalenessTier>,
    }
    let mut rows: Vec<Row> = Vec::with_capacity(changed.len());

    for path in &changed {
        let file_key = format!("file:{path}");

        let Some(file_rec) = store.get(&file_key).await? else {
            rows.push(Row {
                path: path.clone(),
                severity: Severity::Unknown,
                gotcha_count: 0,
                stale: None,
            });
            continue;
        };
        let _ = store.log_hit(&file_key).await;

        // Confirmed gotchas via the file's gotcha_keys, plus a fallback scan
        // for gotchas that list this file in affected_files but aren't yet linked.
        let gotcha_keys = file_rec
            .payload_as::<FileRecord>()
            .map(|f| f.gotcha_keys.clone())
            .unwrap_or_default();

        let mut confirmed_gotchas: Vec<Record> = Vec::new();
        for key in &gotcha_keys {
            let Some(gr) = store.get(key).await? else {
                continue;
            };
            if !matches!(gr.lifecycle, RecordLifecycle::Active) {
                continue;
            }
            if gr
                .payload_as::<GotchaRecord>()
                .map(|g| g.confirmed)
                .unwrap_or(false)
            {
                confirmed_gotchas.push(gr);
            }
        }

        let severity = if confirmed_gotchas
            .iter()
            .any(|g| matches!(g.priority, Priority::Critical))
        {
            Severity::Critical
        } else if confirmed_gotchas
            .iter()
            .any(|g| matches!(g.priority, Priority::High))
        {
            Severity::High
        } else if confirmed_gotchas.is_empty() {
            Severity::Normal
        } else {
            // Confirmed gotchas exist but none are critical/high — still warned.
            Severity::High
        };

        let stale = if confirmed_gotchas.is_empty() {
            match file_rec.staleness.tier {
                StalenessTier::Stale | StalenessTier::Liability | StalenessTier::Tombstone => {
                    Some(file_rec.staleness.tier.clone())
                }
                _ => None,
            }
        } else {
            worst_staleness(&confirmed_gotchas)
        };

        rows.push(Row {
            path: path.clone(),
            severity,
            gotcha_count: confirmed_gotchas.len(),
            stale,
        });
    }

    // Column width: pad path to longest + 4 spaces so status text aligns.
    let path_w = rows.iter().map(|r| r.path.len()).max().unwrap_or(0) + 4;

    let mut warned = 0usize;
    let mut documented = 0usize;
    let mut unknown = 0usize;

    for row in &rows {
        let (marker_color, sev_color) = match row.severity {
            Severity::Critical => (colors::RED, colors::RED),
            Severity::High => (colors::YELLOW, colors::YELLOW),
            Severity::Normal => (colors::GREEN, colors::GRAY),
            Severity::Unknown => (colors::GRAY, colors::GRAY),
        };

        let status = match row.severity {
            Severity::Critical | Severity::High => {
                let n = row.gotcha_count;
                let base = format!("{n} gotcha{s}", s = if n == 1 { "" } else { "s" });
                match &row.stale {
                    Some(tier) => format!("{base} (stale — {})", stale_label(tier)),
                    None => base,
                }
            }
            Severity::Normal => match &row.stale {
                Some(tier) => format!("documented, no gotchas (stale — {})", stale_label(tier)),
                None => "documented, no gotchas".to_string(),
            },
            Severity::Unknown => "no file record".to_string(),
        };

        match row.severity {
            Severity::Critical | Severity::High => warned += 1,
            Severity::Normal => documented += 1,
            Severity::Unknown => unknown += 1,
        }

        if use_color {
            println!(
                "  {mc}{marker}{rst} {sc}{sev:<8}{rst}  {cyan}{path:<pw$}{rst}{status}",
                mc = marker_color,
                sc = sev_color,
                rst = colors::RESET,
                cyan = colors::CYAN,
                marker = row.severity.marker(),
                sev = row.severity.label(),
                path = row.path,
                pw = path_w,
                status = status,
            );
        } else {
            println!(
                "  {marker} {sev:<8}  {path:<pw$}{status}",
                marker = row.severity.marker(),
                sev = row.severity.label(),
                path = row.path,
                pw = path_w,
                status = status,
            );
        }
    }

    println!();
    if use_color {
        println!(
            "  {BLUE}Summary:{RESET} {warned} warned · {documented} documented · {unknown} unknown",
            BLUE = colors::BLUE,
            RESET = colors::RESET,
        );
    } else {
        println!("  Summary: {warned} warned · {documented} documented · {unknown} unknown");
    }
    if unknown > 0 {
        let gray = if use_color { colors::GRAY } else { "" };
        let reset = if use_color { colors::RESET } else { "" };
        println!("  {gray}Run `mati explain <file>` for a full briefing on any file above.{reset}");
    }
    println!();

    store.close().await?;

    Ok(())
}
