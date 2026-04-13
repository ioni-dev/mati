//! `mati explain <file>` — File Health Card (P1)
//!
//! Aggregates everything mati knows about a file into a single structured
//! view: purpose, gotchas, decisions, co-change partners, stability signals,
//! and TODOs. All data comes from the store — zero API calls, <100ms.

use std::io::IsTerminal as _;

use anyhow::Result;
use clap::Args;

use mati_core::store::{
    FileRecord, GotchaRecord, Priority, Record, RecordLifecycle, StalenessTier,
};

use super::colors;
use super::proxy::StoreProxy;
use super::show::source_short;

#[derive(Args)]
#[command(
    long_about = "File briefing — everything mati knows before you edit a file.\n\
                  Shows gotchas, decisions, co-change partners, stability signals, and TODOs.\n\n\
                  Example: mati explain src/auth/session.rs"
)]
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
    let _ = proxy.log_hit(&file_key).await;

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

    let source = source_short(&file_rec.source);

    println!();
    if use_color {
        println!(
            "  {CYAN}{filename}{RESET} — {purpose}",
            CYAN = colors::CYAN,
            RESET = colors::RESET
        );
        println!(
            "  {GRAY}confidence {conf:.2}  quality {quality:?}  source: {source}{hotspot}{RESET}",
            GRAY = colors::GRAY,
            RESET = colors::RESET,
            conf = file_rec.confidence.value,
            quality = file_rec.quality.tier,
            hotspot = hotspot_tag,
        );
    } else {
        println!("  {filename} — {purpose}");
        println!(
            "  confidence {:.2}  quality {:?}  source: {}{}",
            file_rec.confidence.value, file_rec.quality.tier, source, hotspot_tag
        );
    }

    // Blast radius — show only when populated
    if let Some(ref br) = fr.as_ref().and_then(|f| f.blast_radius.as_ref()) {
        use mati_core::analysis::blast_radius::BlastTier;
        let tier_label = br.tier.label();
        let tier_color = match br.tier {
            BlastTier::Critical => colors::RED,
            BlastTier::High => colors::YELLOW,
            _ => colors::GRAY,
        };
        if use_color {
            println!(
                "  {GRAY}blast radius: {direct} direct, {transitive} transitive ({color}{tier}{RESET}{GRAY}){RESET}",
                GRAY = colors::GRAY,
                RESET = colors::RESET,
                color = tier_color,
                direct = br.direct,
                transitive = br.transitive,
                tier = tier_label,
            );
        } else {
            println!(
                "  blast radius: {} direct, {} transitive ({})",
                br.direct, br.transitive, tier_label,
            );
        }
    }

    // Staleness warning — show only when it matters
    match file_rec.staleness.tier {
        StalenessTier::Stale => {
            if use_color {
                println!(
                    "  {YELLOW}stale{RESET} {GRAY}— file changed since last review. Verify before relying on this briefing.{RESET}",
                    YELLOW = colors::YELLOW,
                    GRAY = colors::GRAY,
                    RESET = colors::RESET,
                );
            } else {
                println!("  stale — file changed since last review. Verify before relying on this briefing.");
            }
        }
        StalenessTier::Liability | StalenessTier::Tombstone => {
            if use_color {
                println!(
                    "  {RED}outdated{RESET} {GRAY}— this briefing is unreliable. Record excluded from hook injection.{RESET}",
                    RED = colors::RED,
                    GRAY = colors::GRAY,
                    RESET = colors::RESET,
                );
            } else {
                println!("  outdated — this briefing is unreliable. Record excluded from hook injection.");
            }
        }
        _ => {}
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
            let sev = match g.priority {
                Priority::Critical => severity_label("CRITICAL", colors::RED, use_color),
                Priority::High => severity_label("HIGH", colors::YELLOW, use_color),
                _ => String::new(),
            };
            let rule = g.value.lines().next().unwrap_or(&g.value);
            let provenance = format_gotcha_provenance(g, confirmed, use_color);
            println!("  ● {sev}{rule}  {provenance}");
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

    // ── Review / capture hints ─────────────────────────────────────────────
    let unconfirmed_count = gotchas
        .iter()
        .filter(|g| {
            g.payload_as::<GotchaRecord>()
                .map(|gr| !gr.confirmed)
                .unwrap_or(false)
        })
        .count();

    let is_hotspot = fr.as_ref().map(|f| f.is_hotspot).unwrap_or(false);
    let gray = if use_color { colors::GRAY } else { "" };
    let yellow = if use_color { colors::YELLOW } else { "" };
    let reset = if use_color { colors::RESET } else { "" };

    if unconfirmed_count > 0 {
        println!();
        println!(
            "  {yellow}{unconfirmed_count} unconfirmed{reset} {gray}— run `mati review {path}` to confirm for hook enforcement{reset}"
        );
    } else if gotchas.is_empty() && is_hotspot {
        println!();
        println!("  {gray}Hotspot with no gotchas. Add one:{reset}");
        println!("  {gray}  mati gotcha add {path} -r \"rule text\"{reset}");
    } else if gotchas.is_empty() {
        println!();
        println!(
            "  {gray}No gotchas for this file. Add one: mati gotcha add {path} -r \"rule text\"{reset}"
        );
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

fn format_gotcha_provenance(record: &Record, confirmed: bool, use_color: bool) -> String {
    let source = source_short(&record.source);
    let conf = record.confidence.value;

    let (gray, yellow, green, reset) = if use_color {
        (colors::GRAY, colors::YELLOW, colors::GREEN, colors::RESET)
    } else {
        ("", "", "", "")
    };

    if confirmed {
        // Confirmed records show source + confidence in green/gray
        let stale_note = match record.staleness.tier {
            StalenessTier::Stale | StalenessTier::Liability | StalenessTier::Tombstone => {
                format!(" {yellow}stale{reset}")
            }
            _ => String::new(),
        };
        format!("{gray}({green}confirmed{reset}{gray}, {source}, {conf:.2}){reset}{stale_note}")
    } else {
        // Unconfirmed records are clearly advisory
        format!("{gray}({yellow}unconfirmed{reset}{gray}, {source}, {conf:.2}){reset}")
    }
}
