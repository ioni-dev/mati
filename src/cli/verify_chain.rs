//! `mati verify-chain` — verify the integrity of the local enforcement audit chain.
//!
//! Recomputes every event's hash AND re-checks the `prev_hash` linkage using the
//! shared `mati_core::store::enforcement::verify_chain` primitive — one source of
//! truth for the frozen hash contract. Local, read-only, zero-network. Routes
//! through the daemon when one is running (via `StoreProxy`), so it never needs
//! exclusive store access.
//!
//! Exits non-zero when the chain is not fully intact, so it can gate CI.

use anyhow::Result;
use clap::Args;

use mati_core::store::enforcement::{self, ChainBreakKind};

use super::proxy::StoreProxy;

/// Max breaks listed in `--verbose` human output before truncating.
const MAX_LISTED_BREAKS: usize = 100;

#[derive(Args)]
pub struct VerifyChainArgs {
    /// Emit the verification result as JSON (for CI / scripting).
    #[arg(long)]
    pub json: bool,
    /// List each break (seq pair, event types, and the time delta to the
    /// predecessor — a near-zero delta on a linkage break indicates a concurrent
    /// write rather than tampering).
    #[arg(long)]
    pub verbose: bool,
}

pub async fn run(args: VerifyChainArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;

    let events = proxy.scan_enforcement_events(0, u64::MAX).await?;
    let total = events.len();
    let result = enforcement::verify_chain(&events);

    if args.json {
        let mut out = serde_json::json!({
            "valid": result.is_valid(),
            "total_events": total,
            "checked": result.checked,
            "tampered_events": result.tampered_events,
            "linkage_breaks": result.linkage_breaks,
            "unknown_schema": result.unknown_schema,
        });
        if args.verbose {
            out["breaks"] = serde_json::to_value(&result.breaks)?;
        }
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Enforcement chain verification");
        println!("  Events:          {total}");
        println!("  Verified:        {}", result.checked);
        println!("  Tampered:        {}", result.tampered_events);
        println!("  Linkage breaks:  {}", result.linkage_breaks);
        println!("  Unknown schema:  {}", result.unknown_schema);

        if args.verbose && !result.breaks.is_empty() {
            println!("\nBreaks:");
            for b in result.breaks.iter().take(MAX_LISTED_BREAKS) {
                match b.kind {
                    ChainBreakKind::Linkage => {
                        // delta = this event's time minus its predecessor's.
                        let delta = match b.prev_recorded_at_ms {
                            Some(prev) => b.recorded_at_ms as i64 - prev as i64,
                            None => 0,
                        };
                        let prev_seq = b.prev_seq_no.unwrap_or(0);
                        let prev_type = b.prev_event_type.as_deref().unwrap_or("?");
                        println!(
                            "  [linkage]  seq {} {} <- prev seq {} {}  (Δ={}ms)",
                            b.seq_no, b.event_type, prev_seq, prev_type, delta
                        );
                    }
                    ChainBreakKind::Tampered => {
                        println!(
                            "  [tampered] seq {} {} (recorded_at_ms={})",
                            b.seq_no, b.event_type, b.recorded_at_ms
                        );
                    }
                    ChainBreakKind::UnknownSchema => {
                        println!("  [unknown-schema] seq {} {}", b.seq_no, b.event_type);
                    }
                }
            }
            if result.breaks.len() > MAX_LISTED_BREAKS {
                println!(
                    "  ... and {} more (use --json for the full list)",
                    result.breaks.len() - MAX_LISTED_BREAKS
                );
            }
        }

        println!();
        if result.is_valid() {
            println!("Result: VALID — chain intact, every event hash verified.");
        } else {
            println!("Result: INVALID — see counts above.");
        }
    }

    // Non-zero exit on any break so the command can gate CI (matches the
    // `mati check` / `mati repair --check` convention).
    if !result.is_valid() {
        std::process::exit(1);
    }
    Ok(())
}
