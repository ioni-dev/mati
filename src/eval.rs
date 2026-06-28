//! Eval / regression corpus runner (idea 4).
//!
//! Replays a labeled corpus through the REAL pure enforcement functions and
//! scores a confusion matrix per layer:
//!   - **detection** — `classify_command` + `extract_file_path`: which file a
//!     bash command reads (the read gate's first stage);
//!   - **decision** — `evaluate()`: what enforcement does given a file/gotcha
//!     state (Allow / Advisory / Deny / …).
//!
//! Ground truth is independent of current behavior; cases the engine currently
//! mishandles are tracked in `baseline.json`. The gate asserts each layer's
//! failing set equals its baseline exactly — a new miss is a regression, a
//! fixed gap forces a baseline update (ratcheting recall up). That makes the
//! "how do I know it doesn't miss?" number a measured, regression-gated fact.
//!
//! The corpus + baseline are embedded at compile time so `mati eval` runs the
//! identical corpus in a shipped binary. Pure — no store, daemon, or network;
//! the eval path stays inside mati's zero-network invariant.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::hooks::decide::{
    classify_command, evaluate, extract_file_paths, CommandClass, Decision, EnforcementInput,
};

// ── Embedded corpus (relative to this file, src/eval.rs) ─────────────────────
const DETECTION_KNOWN_GOOD: &str = include_str!("../tests/fixtures/eval/detection/known_good.json");
const DETECTION_BENIGN: &str = include_str!("../tests/fixtures/eval/detection/benign.json");
const DETECTION_ADVERSARIAL: &str =
    include_str!("../tests/fixtures/eval/detection/adversarial.json");
const DECISION_CASES: &str = include_str!("../tests/fixtures/eval/decision/cases.json");
const BASELINE: &str = include_str!("../tests/fixtures/eval/baseline.json");

// ── Corpus case types ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DetectionCase {
    id: String,
    cmd: String,
    /// "violation" = a real file-read enforcement must catch; "benign" = not a
    /// file-read.
    label: String,
    /// Ground-truth class: "cat_like" | "grep_like" | "none".
    expect_class: String,
    /// Ground-truth set of files the gate must check (order-independent). One
    /// entry for a single-file read, several for `cat a.rs b.rs`, empty when no
    /// file is read (benign, or `grep PATTERN` with no file).
    #[serde(default)]
    expect_paths: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DecisionCase {
    id: String,
    /// "violation" = must Deny; "benign" = must NOT Deny.
    label: String,
    rel_path: String,
    #[serde(default)]
    file_record: Option<serde_json::Value>,
    #[serde(default)]
    gotcha_records: HashMap<String, serde_json::Value>,
    #[serde(default)]
    already_consulted: bool,
    /// Ground-truth decision variant: "allow" | "advisory" | "deny" |
    /// "already_consulted" | "liability" | "tombstone" | "no_record".
    expect: String,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Baseline {
    #[serde(default)]
    detection: Vec<String>,
    #[serde(default)]
    decision: Vec<String>,
}

// ── Report types ─────────────────────────────────────────────────────────────

/// Per-layer confusion matrix and baseline comparison.
#[derive(Debug, Serialize)]
pub struct LayerReport {
    pub layer: &'static str,
    pub cases: u32,
    pub tp: u32,
    #[serde(rename = "fn")]
    pub fn_: u32,
    pub tn: u32,
    pub fp: u32,
    pub recall: f64,
    pub fp_rate: f64,
    pub precision: f64,
    /// Case ids whose current output != ground truth.
    pub failing: Vec<String>,
    /// Baseline-accepted gaps for this layer.
    pub known_gaps: Vec<String>,
    /// `failing` − `known_gaps`: new misses. Must be empty for a healthy gate.
    pub regressions: Vec<String>,
    /// `known_gaps` − `failing`: fixed cases that should leave the baseline.
    pub newly_fixed: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct EvalReport {
    pub detection: LayerReport,
    pub decision: LayerReport,
}

impl EvalReport {
    /// Ok iff every layer's failing set equals its baseline (no regressions,
    /// no stale baseline entries). The single source of truth for both the CI
    /// gate and `mati eval`'s exit code.
    pub fn gate(&self) -> Result<(), String> {
        let mut errs = Vec::new();
        for l in [&self.detection, &self.decision] {
            if !l.regressions.is_empty() {
                errs.push(format!(
                    "[{}] REGRESSION — output now wrong for cases not in baseline: {}\n  \
                     Fix the regression, or (if intended) add these ids to \
                     tests/fixtures/eval/baseline.json.",
                    l.layer,
                    l.regressions.join(", ")
                ));
            }
            if !l.newly_fixed.is_empty() {
                errs.push(format!(
                    "[{}] IMPROVEMENT — baseline gaps now PASS: {}\n  \
                     Remove them from tests/fixtures/eval/baseline.json so the \
                     baseline stays honest and recall ratchets up.",
                    l.layer,
                    l.newly_fixed.join(", ")
                ));
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("\n"))
        }
    }
}

// ── Scoring ──────────────────────────────────────────────────────────────────

fn parse_class(s: &str) -> Option<CommandClass> {
    match s {
        "cat_like" => Some(CommandClass::CatLike),
        "grep_like" => Some(CommandClass::GrepLike),
        "none" => None,
        other => panic!("corpus: bad expect_class {other:?}"),
    }
}

fn detection_pass(c: &DetectionCase) -> bool {
    let got_class = classify_command(&c.cmd);
    if got_class != parse_class(&c.expect_class) {
        return false;
    }
    // The gate checks the SET of files a command reads, so compare
    // order-independently. `cat a.rs b.rs` must yield {a.rs, b.rs}.
    let mut got_paths = match got_class {
        Some(cl) => extract_file_paths(&c.cmd, cl),
        None => Vec::new(),
    };
    let mut want = c.expect_paths.clone();
    got_paths.sort();
    want.sort();
    got_paths == want
}

/// Stable name for a `Decision` variant (ignores the inner context strings,
/// which carry human-readable detail that is not part of the contract).
fn decision_variant(d: &Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Deny { .. } => "deny",
        Decision::AlreadyConsulted { .. } => "already_consulted",
        Decision::Advisory { .. } => "advisory",
        Decision::Liability { .. } => "liability",
        Decision::Tombstone => "tombstone",
        Decision::NoRecord => "no_record",
        Decision::NotFileRead => "not_file_read",
    }
}

const DECISION_VARIANTS: &[&str] = &[
    "allow",
    "advisory",
    "deny",
    "already_consulted",
    "liability",
    "tombstone",
    "no_record",
    "not_file_read",
];

fn decision_pass(c: &DecisionCase) -> bool {
    let input = EnforcementInput {
        rel_path: c.rel_path.clone(),
        file_record: c.file_record.clone(),
        gotcha_records: c.gotcha_records.clone(),
        already_consulted: c.already_consulted,
    };
    decision_variant(&evaluate(&input).decision) == c.expect
}

/// Build a `LayerReport` from `(id, is_violation, passed)` rows.
fn score(
    layer: &'static str,
    rows: &[(String, bool, bool)],
    known_gaps: Vec<String>,
) -> LayerReport {
    let (mut tp, mut fn_, mut tn, mut fp) = (0u32, 0u32, 0u32, 0u32);
    let mut failing: BTreeSet<String> = BTreeSet::new();
    for (id, is_violation, pass) in rows {
        match (is_violation, pass) {
            (true, true) => tp += 1,
            (true, false) => fn_ += 1,
            (false, true) => tn += 1,
            (false, false) => fp += 1,
        }
        if !pass {
            failing.insert(id.clone());
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
    let known: BTreeSet<String> = known_gaps.iter().cloned().collect();
    let regressions = failing.difference(&known).cloned().collect();
    let newly_fixed = known.difference(&failing).cloned().collect();
    LayerReport {
        layer,
        cases: rows.len() as u32,
        tp,
        fn_,
        tn,
        fp,
        recall,
        fp_rate,
        precision,
        failing: failing.into_iter().collect(),
        known_gaps,
        regressions,
        newly_fixed,
    }
}

fn assert_unique_ids<'a>(layer: &str, ids: impl Iterator<Item = &'a str>) {
    let mut seen = BTreeSet::new();
    for id in ids {
        assert!(seen.insert(id), "{layer} corpus: duplicate case id {id:?}");
    }
}

/// Run the embedded corpus through the real enforcement functions and score it.
///
/// Panics only on a malformed corpus (bad label/expect/class, duplicate id,
/// or label↔expect inconsistency) — these are compile-embedded fixtures, so a
/// panic is a developer error caught immediately by the test or `mati eval`.
pub fn run() -> EvalReport {
    let baseline: Baseline = serde_json::from_str(BASELINE).expect("parse baseline.json");

    // Detection layer.
    let mut detection: Vec<DetectionCase> = Vec::new();
    for raw in [
        DETECTION_KNOWN_GOOD,
        DETECTION_BENIGN,
        DETECTION_ADVERSARIAL,
    ] {
        detection.extend(serde_json::from_str::<Vec<DetectionCase>>(raw).expect("parse detection"));
    }
    assert_unique_ids("detection", detection.iter().map(|c| c.id.as_str()));
    let det_rows: Vec<(String, bool, bool)> = detection
        .iter()
        .map(|c| {
            assert!(
                c.label == "violation" || c.label == "benign",
                "detection {}: bad label {:?}",
                c.id,
                c.label
            );
            (c.id.clone(), c.label == "violation", detection_pass(c))
        })
        .collect();
    let detection = score("detection", &det_rows, baseline.detection);

    // Decision layer.
    let decision: Vec<DecisionCase> =
        serde_json::from_str(DECISION_CASES).expect("parse decision corpus");
    assert_unique_ids("decision", decision.iter().map(|c| c.id.as_str()));
    let dec_rows: Vec<(String, bool, bool)> = decision
        .iter()
        .map(|c| {
            assert!(
                c.label == "violation" || c.label == "benign",
                "decision {}: bad label {:?}",
                c.id,
                c.label
            );
            assert!(
                DECISION_VARIANTS.contains(&c.expect.as_str()),
                "decision {}: bad expect {:?}",
                c.id,
                c.expect
            );
            // The confusion-matrix axis is "must Deny": keep label and expect
            // consistent so the matrix can't silently mislabel.
            assert_eq!(
                c.label == "violation",
                c.expect == "deny",
                "decision {}: label/expect mismatch (violation iff expect==deny)",
                c.id
            );
            (c.id.clone(), c.label == "violation", decision_pass(c))
        })
        .collect();
    let decision = score("decision", &dec_rows, baseline.decision);

    EvalReport {
        detection,
        decision,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_pass_can_fail() {
        // Same discipline as the 1.2 grep validation: prove the scorer trips.
        let mk = |expect_class: &str, expect_paths: &[&str]| DetectionCase {
            id: "x".into(),
            cmd: "cat src/main.rs".into(),
            label: "violation".into(),
            expect_class: expect_class.into(),
            expect_paths: expect_paths.iter().map(|s| s.to_string()).collect(),
            note: None,
        };
        assert!(detection_pass(&mk("cat_like", &["src/main.rs"])));
        assert!(!detection_pass(&mk("cat_like", &["WRONG.rs"])));
        assert!(!detection_pass(&mk("none", &[])));
    }

    #[test]
    fn decision_pass_can_fail() {
        let deny_input = DecisionCase {
            id: "x".into(),
            label: "violation".into(),
            rel_path: "src/a.rs".into(),
            file_record: Some(serde_json::json!({
                "confidence": {"value": 0.9}, "quality": {"value": 0.8},
                "staleness": {"value": 0.1, "tier": "fresh"},
                "payload": {"gotcha_keys": ["g"]}
            })),
            gotcha_records: HashMap::from([(
                "g".to_string(),
                serde_json::json!({
                    "value": "r", "confidence": {"value": 0.9}, "quality": {"value": 0.8},
                    "payload": {"confirmed": true}
                }),
            )]),
            already_consulted: false,
            expect: "deny".into(),
            note: None,
        };
        assert!(decision_pass(&deny_input), "real deny case must pass");

        let mut wrong = deny_input;
        wrong.expect = "allow".into();
        assert!(
            !decision_pass(&wrong),
            "a deny scored against expect=allow must fail"
        );
    }

    #[test]
    fn corpus_is_well_formed_and_gates() {
        // Loads + validates the embedded corpus (panics on malformed data) and
        // confirms the committed baseline matches current behavior.
        let report = run();
        assert!(report.detection.cases > 0);
        assert!(report.decision.cases > 0);
        report
            .gate()
            .expect("embedded corpus must match its baseline");
    }
}
