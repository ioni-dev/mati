use std::io::IsTerminal;

use anyhow::Result;
use clap::Args;

use mati_core::health::gaps;
use mati_core::store::Store;

use super::colors;

#[derive(Args)]
pub struct GapsArgs {
    /// Minimum risk score to include (0.0-1.0)
    #[arg(long, default_value = "0.3")]
    pub min_risk: f32,

    /// Maximum results to show
    #[arg(long, short = 'n', default_value = "20")]
    pub limit: usize,
}

pub async fn run(args: GapsArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    let use_color = std::io::stdout().is_terminal();

    let (red, yellow, blue, gray, bold, reset) = if use_color {
        (
            colors::RED,
            colors::YELLOW,
            colors::BLUE,
            colors::GRAY,
            colors::BOLD,
            colors::RESET,
        )
    } else {
        ("", "", "", "", "", "")
    };

    let all_gaps = gaps::analyze(&store).await?;

    let filtered: Vec<_> = all_gaps
        .into_iter()
        .filter(|g| g.risk_score >= args.min_risk)
        .take(args.limit)
        .collect();

    if filtered.is_empty() {
        println!("No knowledge gaps found.");
        store.close().await?;
        return Ok(());
    }

    println!(
        "\n{bold}KNOWLEDGE GAPS{reset} -- {bold}{}{reset} found                 sorted by risk score\n",
        filtered.len()
    );

    for gap in &filtered {
        let (tier_label, tier_color) = if gap.risk_score >= 0.7 {
            ("CRITICAL", red)
        } else if gap.risk_score >= 0.4 {
            ("HIGH", yellow)
        } else if gap.risk_score >= 0.2 {
            ("NORMAL", blue)
        } else {
            ("LOW", gray)
        };

        // Strip namespace prefix from the key for display (e.g. "file:src/main.rs" -> "src/main.rs")
        let display_key = gap.key.splitn(2, ':').nth(1).unwrap_or(&gap.key);

        println!(
            "{tier_color}{bold}\u{25cf} {tier_label:<9}{reset} {bold}{display_key}{reset}"
        );
        println!(
            "            {gray}{}{reset}",
            gap.description
        );
        println!(
            "            {gray}\u{2192} Action:{reset} {}\n",
            gap.action_hint
        );
    }

    store.close().await?;
    Ok(())
}
