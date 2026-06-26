//! `mati eval` — run the enforcement regression corpus and report recall /
//! false-positive rate per layer.
//!
//! The public, in-binary face of idea 4: a number a security team can
//! reproduce ("how do I know it doesn't miss?") rather than take on faith.
//! Pure — replays the embedded corpus through the real enforcement functions,
//! no store/daemon/network. Exits non-zero if current behavior drifts from the
//! committed baseline, so it also works as a local regression gate.

use anyhow::Result;
use clap::Args;

use mati_core::eval::{self, EvalReport, LayerReport};

#[derive(Args)]
pub struct EvalArgs {
    /// Output the structured JSON report on stdout (CI-friendly).
    #[arg(long)]
    pub json: bool,
}

pub async fn run(args: EvalArgs) -> Result<()> {
    let report = eval::run();
    let gate = report.gate();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_human(&report);
    }

    if let Err(msg) = gate {
        if !args.json {
            eprintln!("\n{msg}");
        }
        std::process::exit(1);
    }
    Ok(())
}

fn render_human(report: &EvalReport) {
    println!();
    println!("mati eval — enforcement regression corpus");
    for layer in [&report.detection, &report.decision] {
        render_layer(layer);
    }
    println!();
    println!(
        "Note: `known gaps` are inputs we currently mishandle, tracked in \
         tests/fixtures/eval/baseline.json — disclosed, not hidden."
    );
}

fn render_layer(l: &LayerReport) {
    println!();
    println!("{} layer", l.layer);
    println!("  cases      {}", l.cases);
    println!(
        "  recall     {:.3}    fp_rate {:.3}    precision {:.3}",
        l.recall, l.fp_rate, l.precision
    );
    println!(
        "  matrix     TP={} FN={} TN={} FP={}",
        l.tp, l.fn_, l.tn, l.fp
    );
    if !l.known_gaps.is_empty() {
        println!(
            "  known gaps ({}): {}",
            l.known_gaps.len(),
            l.known_gaps.join(", ")
        );
    }
}
