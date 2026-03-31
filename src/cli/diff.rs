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

use mati_core::store::{FileRecord, GotchaRecord, RecordLifecycle, StalenessTier};

use super::proxy::StoreProxy;
use super::show::source_short;

use super::colors;

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
            "  {BLUE}Files changed in '{range}'{RESET}",
            BLUE = colors::BLUE,
            RESET = colors::RESET
        );
    } else {
        println!("  Files changed in '{range}'");
    }
    println!();

    let mut warned = 0usize;
    let mut documented = 0usize;
    let mut unknown = 0usize;

    for path in &changed {
        let file_key = format!("file:{path}");

        let Some(file_rec) = store.get(&file_key).await? else {
            println!(
                "  {GRAY}○{RESET}  {CYAN}{path}{RESET}  — no records yet",
                GRAY = if use_color { colors::GRAY } else { "" },
                RESET = if use_color { colors::RESET } else { "" },
                CYAN = if use_color { colors::CYAN } else { "" },
            );
            unknown += 1;
            continue;
        };
        let _ = store.log_hit(&file_key).await;

        // Collect confirmed gotchas via gotcha_keys on the file record.
        let gotcha_keys = file_rec
            .payload_as::<FileRecord>()
            .map(|f| f.gotcha_keys.clone())
            .unwrap_or_default();

        let mut confirmed_gotchas = Vec::new();
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

        if confirmed_gotchas.is_empty() {
            println!(
                "  {GREEN}✓{RESET}  {CYAN}{path}{RESET}  — documented, no gotchas flagged",
                GREEN = if use_color { colors::GREEN } else { "" },
                RESET = if use_color { colors::RESET } else { "" },
                CYAN = if use_color { colors::CYAN } else { "" },
            );
            documented += 1;
        } else {
            println!(
                "  {YELLOW}⚠{RESET}  {CYAN}{path}{RESET}  — {n} confirmed gotcha{s}",
                YELLOW = if use_color { colors::YELLOW } else { "" },
                RESET = if use_color { colors::RESET } else { "" },
                CYAN = if use_color { colors::CYAN } else { "" },
                n = confirmed_gotchas.len(),
                s = if confirmed_gotchas.len() == 1 {
                    ""
                } else {
                    "s"
                },
            );
            for cg in &confirmed_gotchas {
                let rule = cg.value.lines().next().unwrap_or(&cg.value);
                let source = source_short(&cg.source);
                let stale_hint = match cg.staleness.tier {
                    StalenessTier::Stale | StalenessTier::Liability | StalenessTier::Tombstone => {
                        if use_color {
                            format!(
                                " {YELLOW}stale{RESET}",
                                YELLOW = colors::YELLOW,
                                RESET = colors::RESET
                            )
                        } else {
                            " stale".to_string()
                        }
                    }
                    _ => String::new(),
                };
                println!(
                    "     {YELLOW}→{RESET} {rule}  ({source}, {conf:.2}){stale_hint}",
                    YELLOW = if use_color { colors::YELLOW } else { "" },
                    RESET = if use_color { colors::RESET } else { "" },
                    conf = cg.confidence.value,
                );
            }
            warned += 1;
        }
    }

    println!();
    println!(
        "  {} file{} changed — {} with gotchas, {} documented, {} unknown",
        changed.len(),
        if changed.len() == 1 { "" } else { "s" },
        warned,
        documented,
        unknown,
    );
    if unknown > 0 {
        let gray = if use_color { colors::GRAY } else { "" };
        let reset = if use_color { colors::RESET } else { "" };
        println!("  {gray}Run `mati explain <file>` for a full briefing on any file above.{reset}");
    }
    println!();

    store.close().await?;

    Ok(())
}
