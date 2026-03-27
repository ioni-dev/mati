//! `mati explain <file>` — File Health Card (P1)
//!
//! Aggregates everything mati knows about a file into a single structured
//! view: purpose, gotchas, decisions, co-change partners, stability signals,
//! and TODOs. All data comes from the store — zero API calls, <100ms.

use std::io::IsTerminal as _;

use anyhow::Result;
use clap::Args;

use mati_core::store::{FileRecord, GotchaRecord, Priority, Record, RecordLifecycle};

use super::colors;
use super::proxy::StoreProxy;

#[derive(Args)]
pub struct ExplainArgs {
    /// Repo-relative file path (e.g. src/auth/session.rs)
    pub path: String,
}

pub async fn run(args: ExplainArgs) -> Result<()> {
    let use_color = std::io::stdout().is_terminal();
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;

    // Strip leading "./" for consistency with stored keys.
    let path = args.path.trim_start_matches("./").to_string();
    let file_key = format!("file:{path}");

    let file_rec = match proxy.get(&file_key).await? {
        Some(r) => r,
        None => {
            eprintln!("No record for '{path}'. Run `mati init` first.");
            return Ok(());
        }
    };

    let fr = file_rec.payload_as::<FileRecord>();

    // ── Header ────────────────────────────────────────────────────────────────
    let filename = std::path::Path::new(&path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&path);

    let purpose = fr
        .as_ref()
        .map(|f| f.purpose.as_str())
        .filter(|p| !p.is_empty())
        .unwrap_or("(no purpose recorded)");

    let hotspot_tag = fr
        .as_ref()
        .filter(|f| f.is_hotspot)
        .map(|_| "  hotspot")
        .unwrap_or("");

    println!();
    if use_color {
        println!(
            "  {CYAN}{filename}{RESET} — {purpose}",
            CYAN = colors::CYAN,
            RESET = colors::RESET
        );
        println!(
            "  {GRAY}confidence {conf:.2}  quality {quality:?}{hotspot}{RESET}",
            GRAY = colors::GRAY,
            RESET = colors::RESET,
            conf = file_rec.confidence.value,
            quality = file_rec.quality.tier,
            hotspot = hotspot_tag,
        );
    } else {
        println!("  {filename} — {purpose}");
        println!(
            "  confidence {:.2}  quality {:?}{}",
            file_rec.confidence.value, file_rec.quality.tier, hotspot_tag
        );
    }

    // ── Gotchas ───────────────────────────────────────────────────────────────
    let gotcha_keys = fr
        .as_ref()
        .map(|f| f.gotcha_keys.clone())
        .unwrap_or_default();

    let mut gotchas: Vec<Record> = Vec::new();
    for key in &gotcha_keys {
        if let Some(r) = proxy.get(key).await? {
            if matches!(r.lifecycle, RecordLifecycle::Active) {
                gotchas.push(r);
            }
        }
    }

    // Fallback: scan gotcha: prefix for any with this file in affected_files.
    // Catches records not yet linked via gotcha_keys (e.g. warm re-init gap).
    if gotchas.is_empty() {
        let all = proxy.scan_prefix("gotcha:").await?;
        for r in all {
            if !matches!(r.lifecycle, RecordLifecycle::Active) {
                continue;
            }
            if let Some(g) = r.payload_as::<GotchaRecord>() {
                if g.affected_files.iter().any(|af| af == &path) {
                    gotchas.push(r);
                }
            }
        }
    }

    if !gotchas.is_empty() {
        println!();
        let header = format!("Gotchas ({})", gotchas.len());
        print_section_header(&header, colors::YELLOW, use_color);
        for g in &gotchas {
            let confirmed = g
                .payload_as::<GotchaRecord>()
                .map(|gr| gr.confirmed)
                .unwrap_or(false);
            let unconfirmed = if confirmed { "" } else { " (unconfirmed)" };
            let sev = match g.priority {
                Priority::Critical => severity_label("CRITICAL", colors::RED, use_color),
                Priority::High => severity_label("HIGH", colors::YELLOW, use_color),
                _ => String::new(),
            };
            println!("  ● {sev}{}{unconfirmed}", g.value);
        }
    }

    // ── Decisions ─────────────────────────────────────────────────────────────
    let decision_keys = fr
        .as_ref()
        .map(|f| f.decision_keys.clone())
        .unwrap_or_default();

    if !decision_keys.is_empty() {
        println!();
        print_section_header("Decisions linked", colors::PURPLE, use_color);
        for key in &decision_keys {
            if let Some(r) = proxy.get(key).await? {
                println!("  ● {} — {}", r.key, r.value);
            }
        }
    }

    // ── Co-changes ────────────────────────────────────────────────────────────
    let cochange_prefix = format!("gotcha:cochange:{path}|");
    let cochange_gotchas = proxy.scan_prefix(&cochange_prefix).await?;
    if !cochange_gotchas.is_empty() {
        println!();
        print_section_header("Co-changes with", colors::BLUE, use_color);
        for cg in &cochange_gotchas {
            // Key format: gotcha:cochange:{source}|{target}
            if let Some(target) = cg.key.strip_prefix(&cochange_prefix) {
                // Extract the "N/M commits (P%)" part from the rule text for a tight display
                let pct_hint = cg
                    .value
                    .split("commits (")
                    .nth(1)
                    .and_then(|s| s.split(')').next())
                    .map(|p| format!("  ({p})"))
                    .unwrap_or_default();
                println!(
                    "  ● {CYAN}{target}{RESET}{pct_hint}",
                    CYAN = if use_color { colors::CYAN } else { "" },
                    RESET = if use_color { colors::RESET } else { "" },
                );
            }
        }
    }

    // ── Stability ─────────────────────────────────────────────────────────────
    let revert_rec = proxy.get(&format!("gotcha:revert:{path}")).await?;
    let ownership_rec = proxy.get(&format!("gotcha:ownership:{path}")).await?;

    if revert_rec.is_some()
        || ownership_rec.is_some()
        || fr.as_ref().and_then(|f| f.last_author.as_ref()).is_some()
    {
        println!();
        print_section_header("Stability", colors::GRAY, use_color);
        if let Some(rv) = &revert_rec {
            println!("  ● {}", rv.value);
        }
        if let Some(ov) = &ownership_rec {
            println!("  ● {}", ov.value);
        }
        if let Some(fr_inner) = &fr {
            if let Some(author) = &fr_inner.last_author {
                println!(
                    "  ● Last author: {author}  ({freq} commits)",
                    freq = fr_inner.change_frequency
                );
            }
        }
    }

    // ── TODOs ─────────────────────────────────────────────────────────────────
    if let Some(fr_inner) = &fr {
        if !fr_inner.todos.is_empty() {
            println!();
            let header = format!("TODOs ({})", fr_inner.todos.len());
            print_section_header(&header, colors::GRAY, use_color);
            for todo in fr_inner.todos.iter().take(5) {
                println!("  ● line {}: {}", todo.line, todo.text);
            }
            if fr_inner.todos.len() > 5 {
                println!("  … and {} more", fr_inner.todos.len() - 5);
            }
        }
    }

    println!();
    proxy.close().await?;
    Ok(())
}

fn print_section_header(label: &str, color: &str, use_color: bool) {
    if use_color {
        println!("  {color}{label}{}", colors::RESET);
    } else {
        println!("  {label}");
    }
}

fn severity_label(label: &str, color: &str, use_color: bool) -> String {
    if use_color {
        format!("{color}{label}{} ", colors::RESET)
    } else {
        format!("{label} ")
    }
}
