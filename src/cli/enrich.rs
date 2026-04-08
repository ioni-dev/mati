use std::io::IsTerminal;

use anyhow::Result;
use clap::Args;

use super::colors;

#[derive(Args)]
pub struct EnrichArgs {}

pub async fn run(_args: EnrichArgs) -> Result<()> {
    let use_color = std::io::stdout().is_terminal();
    let (blue, gray, white, bold, reset) = if use_color {
        (
            colors::BLUE,
            colors::GRAY,
            colors::WHITE,
            colors::BOLD,
            colors::RESET,
        )
    } else {
        ("", "", "", "", "")
    };

    println!();
    println!("  {bold}{blue}mati enrich{reset} — LLM-powered knowledge extraction");
    println!();
    println!("  Enrichment runs inside your active Claude Code or Codex session.");
    println!("  It uses the agent that's already running — no separate API key or token cost.");
    println!();
    println!("  {bold}In Claude Code, type:{reset}");
    println!("    {white}/mati-enrich{reset}                {gray}enrich top hotspot gaps (recommended first run){reset}");
    println!(
        "    {white}/mati-enrich src/payments{reset}   {gray}enrich a specific directory{reset}"
    );
    println!("    {white}/mati-enrich src/main.rs{reset}    {gray}enrich a single file{reset}");
    println!();
    println!(
        "  {bold}In Codex,{reset} the mati skill guides enrichment automatically during sessions."
    );
    println!();
    println!("  {bold}After enrichment, run:{reset}");
    println!("    {white}mati review{reset}                 {gray}confirm extracted gotchas for hook enforcement{reset}");
    println!("    {white}mati stats{reset}                  {gray}see updated coverage and onboarding score{reset}");
    println!();

    Ok(())
}
