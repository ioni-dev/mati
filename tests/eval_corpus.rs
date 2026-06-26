//! Eval / regression corpus — CI gate (idea 4).
//!
//! The corpus, scorer, and per-layer baseline live in `mati_core::eval`
//! (embedded at compile time and also surfaced by `mati eval --json`). This
//! integration test is the regression gate: each layer's failing set must
//! equal its committed baseline. Self-checks proving the scorer can fail live
//! in the `mati_core::eval` unit tests.
//!
//! Pure — no store, daemon, or network.

use mati_core::eval;

#[test]
fn eval_corpus_matches_baseline() {
    let report = eval::run();

    eprintln!(
        "\ndetection: recall={:.3} fp_rate={:.3}  ({} cases, {} known gaps)\n\
         decision:  recall={:.3} fp_rate={:.3}  ({} cases, {} known gaps)\n",
        report.detection.recall,
        report.detection.fp_rate,
        report.detection.cases,
        report.detection.known_gaps.len(),
        report.decision.recall,
        report.decision.fp_rate,
        report.decision.cases,
        report.decision.known_gaps.len(),
    );

    if let Err(e) = report.gate() {
        panic!("eval corpus gate failed:\n{e}");
    }
}
