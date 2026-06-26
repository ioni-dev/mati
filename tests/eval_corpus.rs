//! Eval / regression corpus — DETECTION layer (idea 4, P0).
//!
//! Replays a labeled corpus through the REAL pure detection functions
//! (`classify_command` + `extract_file_path`) and scores a confusion matrix:
//! recall, false-positive rate, precision. The point is to MEASURE — and
//! regression-gate — how often enforcement's first stage (deciding *which file*
//! a bash command reads) is correct, including the inputs it currently gets
//! wrong. That number is the answer to a regulated buyer's "how do I know it
//! doesn't miss?".
//!
//! Ground truth vs current behavior:
//!   - Each case carries the CORRECT answer (`expect_class` + `expect_path`),
//!     independent of what the code does today.
//!   - Cases the engine currently mishandles are tracked explicitly in
//!     `baseline.json::known_gaps`. The gate asserts the set of failing cases
//!     equals that list EXACTLY — so a NEW miss fails CI (regression) and a
//!     newly-FIXED gap also fails (forcing an honest baseline update that
//!     ratchets recall up). The known-gap list IS the public disclosure of
//!     exactly which inputs detection mishandles.
//!
//! Pure functions only — no store, no daemon, no network. The eval harness
//! itself stays inside mati's zero-network invariant.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use mati_core::hooks::decide::{classify_command, extract_file_path, CommandClass};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    cmd: String,
    /// "violation" = a real file-read enforcement must catch; "benign" = not a
    /// file-read, enforcement must take no action.
    label: String,
    /// Ground-truth class: "cat_like" | "grep_like" | "none".
    expect_class: String,
    /// Ground-truth path (None for benign / no-path cases).
    #[serde(default)]
    expect_path: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Baseline {
    #[serde(default)]
    known_gaps: Vec<String>,
}

fn eval_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/eval")
}

fn load_cases() -> Vec<Case> {
    let dir = eval_dir().join("detection");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read corpus dir {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    files.sort();

    let mut cases = Vec::new();
    for f in &files {
        let txt =
            std::fs::read_to_string(f).unwrap_or_else(|e| panic!("read {}: {e}", f.display()));
        let mut batch: Vec<Case> =
            serde_json::from_str(&txt).unwrap_or_else(|e| panic!("parse {}: {e}", f.display()));
        cases.append(&mut batch);
    }
    assert!(
        !cases.is_empty(),
        "no corpus cases loaded from {}",
        dir.display()
    );

    let mut ids = BTreeSet::new();
    for c in &cases {
        assert!(ids.insert(c.id.as_str()), "duplicate case id: {}", c.id);
        assert!(
            c.label == "violation" || c.label == "benign",
            "case {}: bad label {:?}",
            c.id,
            c.label
        );
    }
    cases
}

fn parse_class(s: &str) -> Option<CommandClass> {
    match s {
        "cat_like" => Some(CommandClass::CatLike),
        "grep_like" => Some(CommandClass::GrepLike),
        "none" => None,
        other => panic!("bad expect_class: {other}"),
    }
}

/// True iff CURRENT detection behavior matches the case's ground truth.
fn case_passes(c: &Case) -> bool {
    let got_class = classify_command(&c.cmd);
    let got_path = got_class.and_then(|cl| extract_file_path(&c.cmd, cl));
    got_class == parse_class(&c.expect_class) && got_path == c.expect_path
}

#[test]
fn detection_corpus_matches_baseline() {
    let cases = load_cases();
    let baseline: Baseline = {
        let p = eval_dir().join("baseline.json");
        let txt = std::fs::read_to_string(&p).expect("read baseline.json");
        serde_json::from_str(&txt).expect("parse baseline.json")
    };

    let (mut tp, mut fn_, mut tn, mut fp) = (0u32, 0u32, 0u32, 0u32);
    let mut failing: BTreeSet<String> = BTreeSet::new();
    for c in &cases {
        let pass = case_passes(c);
        match (c.label.as_str(), pass) {
            ("violation", true) => tp += 1,
            ("violation", false) => fn_ += 1,
            ("benign", true) => tn += 1,
            ("benign", false) => fp += 1,
            _ => unreachable!("label validated in load_cases"),
        }
        if !pass {
            failing.insert(c.id.clone());
        }
    }

    let recall = if tp + fn_ == 0 {
        1.0
    } else {
        tp as f64 / (tp + fn_) as f64
    };
    let fp_rate = if fp + tn == 0 {
        0.0
    } else {
        fp as f64 / (fp + tn) as f64
    };
    let precision = if tp + fp == 0 {
        1.0
    } else {
        tp as f64 / (tp + fp) as f64
    };

    eprintln!("\n── detection eval corpus ──────────────────────────────");
    eprintln!("cases={}  TP={tp} FN={fn_} TN={tn} FP={fp}", cases.len());
    eprintln!("recall={recall:.3}  fp_rate={fp_rate:.3}  precision={precision:.3}");
    eprintln!(
        "known gaps (currently-mishandled inputs): {}",
        failing.len()
    );
    eprintln!("───────────────────────────────────────────────────────\n");

    let known: BTreeSet<String> = baseline.known_gaps.iter().cloned().collect();
    let new_regressions: Vec<&String> = failing.difference(&known).collect();
    let newly_fixed: Vec<&String> = known.difference(&failing).collect();

    assert!(
        new_regressions.is_empty(),
        "REGRESSION — detection now mishandles cases not in baseline known_gaps:\n  {}\n\
         Fix the regression, or (if intended) add these ids to \
         tests/fixtures/eval/baseline.json.",
        new_regressions
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n  ")
    );
    assert!(
        newly_fixed.is_empty(),
        "IMPROVEMENT — these baseline known_gaps now PASS:\n  {}\n\
         Remove them from tests/fixtures/eval/baseline.json so the baseline \
         stays honest and recall ratchets up.",
        newly_fixed
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

/// The scorer must be ABLE to fail — a wrong ground truth must score as a miss.
/// Same discipline as the 1.2 grep validation: prove the gate can trip before
/// trusting a green run.
#[test]
fn scorer_detects_a_deliberate_mismatch() {
    let mk = |expect_class: &str, expect_path: Option<&str>| Case {
        id: "self".into(),
        cmd: "cat src/main.rs".into(),
        label: "violation".into(),
        expect_class: expect_class.into(),
        expect_path: expect_path.map(str::to_string),
        note: None,
    };

    assert!(
        case_passes(&mk("cat_like", Some("src/main.rs"))),
        "sanity: a correct case must pass"
    );
    assert!(
        !case_passes(&mk("cat_like", Some("WRONG.rs"))),
        "scorer must flag a wrong expected path"
    );
    assert!(
        !case_passes(&mk("none", None)),
        "scorer must flag a wrong expected class"
    );
}
