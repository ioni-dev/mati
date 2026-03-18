use std::io::IsTerminal;

use anyhow::Result;
use clap::Args;

use mati_core::store::{GotchaRecord, QualityTier, Record, Store};

use super::colors;

#[derive(Args)]
pub struct StatusArgs {}

pub async fn run(_args: StatusArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    let use_color = std::io::stdout().is_terminal();

    let (blue, green, yellow, gray, white, bold, reset) = if use_color {
        (
            colors::BLUE,
            colors::GREEN,
            colors::YELLOW,
            colors::GRAY,
            colors::WHITE,
            colors::BOLD,
            colors::RESET,
        )
    } else {
        ("", "", "", "", "", "", "")
    };

    // ── Scan all namespaces ──────────────────────────────────────────────────

    let files = store.scan_prefix("file:").await?;
    let gotchas = store.scan_prefix("gotcha:").await?;
    let decisions = store.scan_prefix("decision:").await?;
    let notes = store.scan_prefix("dev_note:").await?;
    let deps = store.scan_prefix("dep:").await?;

    // ── Project name from cwd ────────────────────────────────────────────────

    let project = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    println!(
        "\n{bold}{blue}◈ mati status{reset} — project: {bold}{white}{project}{reset}\n"
    );

    // ── Record counts ────────────────────────────────────────────────────────

    println!(
        "  {blue}Records{reset}     {white}{}{reset} files  {white}{}{reset} gotchas  {white}{}{reset} decisions  {white}{}{reset} notes  {white}{}{reset} deps",
        files.len(),
        gotchas.len(),
        decisions.len(),
        notes.len(),
        deps.len(),
    );

    // ── Confirmed count ──────────────────────────────────────────────────────

    let confirmed_count = gotchas
        .iter()
        .filter(|r| {
            serde_json::from_str::<GotchaRecord>(&r.value)
                .map(|gr| gr.confirmed)
                .unwrap_or(false)
        })
        .count();

    let total_gotchas = gotchas.len();
    let pct = if total_gotchas > 0 {
        (confirmed_count as f32 / total_gotchas as f32 * 100.0) as u32
    } else {
        0
    };
    println!(
        "  {blue}Confirmed{reset}    {green}{confirmed_count}{reset} / {total_gotchas} gotchas ({pct}%)"
    );

    // ── Quality distribution ─────────────────────────────────────────────────

    // Collect quality-relevant records (gotchas, decisions, notes)
    let quality_records: Vec<&Record> = gotchas
        .iter()
        .chain(decisions.iter())
        .chain(notes.iter())
        .collect();

    if !quality_records.is_empty() {
        let mut excellent = 0u32;
        let mut good = 0u32;
        let mut acceptable = 0u32;
        let mut poor = 0u32;
        let mut suppressed = 0u32;

        for r in &quality_records {
            match r.quality.tier {
                QualityTier::Excellent => excellent += 1,
                QualityTier::Good => good += 1,
                QualityTier::Acceptable => acceptable += 1,
                QualityTier::Poor => poor += 1,
                QualityTier::Suppressed => suppressed += 1,
            }
        }

        let total = quality_records.len() as f32;
        println!("\n  {blue}Quality Distribution{reset}");
        print_bar("Excellent", excellent, total, green, white, reset);
        print_bar("Good", good, total, green, white, reset);
        print_bar("Acceptable", acceptable, total, yellow, white, reset);
        print_bar("Poor", poor, total, yellow, white, reset);
        print_bar("Suppressed", suppressed, total, gray, white, reset);
    }

    // ── Confidence summary ───────────────────────────────────────────────────

    let all_knowledge: Vec<&Record> = files
        .iter()
        .chain(gotchas.iter())
        .chain(decisions.iter())
        .chain(notes.iter())
        .collect();

    if !all_knowledge.is_empty() {
        let mut conf_values: Vec<f32> = all_knowledge.iter().map(|r| r.confidence.value).collect();
        conf_values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let avg = conf_values.iter().sum::<f32>() / conf_values.len() as f32;
        let n = conf_values.len();
        let median = if n % 2 == 0 {
            (conf_values[n / 2 - 1] + conf_values[n / 2]) / 2.0
        } else {
            conf_values[n / 2]
        };

        println!(
            "\n  {blue}Confidence{reset}   avg {white}{avg:.2}{reset}  median {white}{median:.2}{reset}"
        );
    }

    // ── Hotspots ─────────────────────────────────────────────────────────────

    let hotspot_count = files
        .iter()
        .filter(|r| {
            serde_json::from_str::<mati_core::store::FileRecord>(&r.value)
                .map(|fr| fr.is_hotspot)
                .unwrap_or(false)
        })
        .count();

    let total_files = files.len();
    let hot_pct = if total_files > 0 {
        (hotspot_count as f32 / total_files as f32 * 100.0) as u32
    } else {
        0
    };
    println!(
        "  {blue}Hotspots{reset}     {white}{hotspot_count}{reset} / {total_files} ({hot_pct}%)"
    );

    println!();
    Ok(())
}

fn print_bar(label: &str, count: u32, total: f32, color: &str, white: &str, reset: &str) {
    if count == 0 {
        return;
    }
    let pct = (count as f32 / total * 100.0) as u32;
    let bar_width = (count as f32 / total * 20.0).ceil() as usize;
    let bar: String = "█".repeat(bar_width);
    println!(
        "    {:<12} {white}{:>3}{reset}  {color}{bar}{reset}  {pct}%",
        label, count
    );
}
