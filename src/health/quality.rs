//! Record quality analyzer (M-08-G).
//!
//! Pure synchronous quality scoring — no I/O, no async. Formula matches
//! ARCHITECTURE.md §5 exactly.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::store::{Priority, QualityScore, QualitySignal, Record};

// ── Signal detection constants ───────────────────────────────────────────────

const IMPERATIVE_VERBS: &[&str] = &[
    "never", "always", "avoid", "use", "ensure", "do", "call", "wrap", "handle",
    "add", "remove", "set", "pass", "return", "check", "run", "test", "import",
    "export", "create", "delete", "update", "replace", "disable", "enable",
    "require", "prefer", "pin", "lock", "bump", "drop", "close", "open",
    "flush", "retry", "skip", "guard", "validate", "sanitize", "escape",
    "encode", "decode", "serialize", "deserialize", "convert", "cast",
    "assert", "verify", "confirm", "reject", "deny", "allow", "block",
    "keep", "move", "copy", "clone", "initialize", "reset", "clear",
];

const CAUSALITY_MARKERS: &[&str] = &[
    "because", "since", "otherwise", "to avoid", "to prevent", "due to",
    "leads to", "results in", "causes", "reason:",
];

const VAGUE_PHRASES: &[&str] = &[
    "be careful", "watch out", "might", "maybe", "probably", "should work",
    "seems to", "i think", "not sure",
];

// ── Quality formula weights (ARCHITECTURE.md §5) ────────────────────────────

const W_IMPERATIVE: f32 = 0.20;
const W_CAUSALITY: f32 = 0.25;
const W_SEVERITY: f32 = 0.10;
const W_REFERENCE: f32 = 0.15;
const W_LENGTH: f32 = 0.15;
const W_SPECIFICITY: f32 = 0.15;

const PENALTY_VAGUE: f32 = 0.5;
const PENALTY_NO_REASON: f32 = 0.6;
const PENALTY_TOO_SHORT: f32 = 0.4;

// ── Public API ───────────────────────────────────────────────────────────────

/// Compute a `QualityScore` for a record using the formula from
/// ARCHITECTURE.md §5.
pub fn analyze(record: &Record) -> QualityScore {
    let text = &record.value;
    let lower = text.to_lowercase();
    let mut signals = Vec::new();

    // ── Positive signals ─────────────────────────────────────────────────

    let has_imperative = detect_imperative_verb(text);
    if has_imperative {
        signals.push(QualitySignal::HasImperativeVerb);
    }

    let has_causality = detect_causality(&lower);
    if has_causality {
        signals.push(QualitySignal::HasCausality);
    }

    let has_severity = record.priority != Priority::Normal;
    if has_severity {
        signals.push(QualitySignal::HasSeveritySet);
    }

    let has_reference = record.ref_url.is_some();
    if has_reference {
        signals.push(QualitySignal::HasReference);
    }

    let length = length_score(text);
    if length >= 0.5 {
        signals.push(QualitySignal::RuleLengthAdequate);
    }

    let specificity = specificity_score(text);
    if specificity >= 0.5 {
        signals.push(QualitySignal::HasSpecificIdentifier);
    }

    // ── Base score ───────────────────────────────────────────────────────

    let mut value = bool_weight(has_imperative) * W_IMPERATIVE
        + bool_weight(has_causality) * W_CAUSALITY
        + bool_weight(has_severity) * W_SEVERITY
        + bool_weight(has_reference) * W_REFERENCE
        + length * W_LENGTH
        + specificity * W_SPECIFICITY;

    // ── Penalties (multiplicative) ───────────────────────────────────────

    if detect_vague_phrase(&lower) {
        signals.push(QualitySignal::VaguePhrasing);
        value *= PENALTY_VAGUE;
    }

    if text.len() < 30 {
        signals.push(QualitySignal::TooShort);
        value *= PENALTY_TOO_SHORT;
    }

    if !has_causality && !lower.contains("because") && !lower.contains("reason:") {
        signals.push(QualitySignal::NoReason);
        value *= PENALTY_NO_REASON;
    }

    // Clamp to [0, 1]
    value = value.clamp(0.0, 1.0);

    let tier = QualityScore::tier_from_value(value);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    QualityScore {
        value,
        tier,
        signals,
        computed_at: now,
    }
}

/// Return `true` if the quality score is below the gate threshold (0.2).
pub fn below_quality_gate(score: &QualityScore) -> bool {
    score.value < 0.2
}

/// Generate concrete improvement hints based on missing positive signals.
pub fn generate_improvement_hints(score: &QualityScore) -> Vec<String> {
    let mut hints = Vec::new();
    let signals = &score.signals;

    if !signals.contains(&QualitySignal::HasImperativeVerb) {
        hints.push("Start with an imperative verb (Never, Always, Avoid, Use, Ensure, ...)".into());
    }
    if !signals.contains(&QualitySignal::HasCausality) {
        hints.push(
            "Add a reason: use \"because\", \"otherwise\", \"to avoid\", or \"to prevent\"".into(),
        );
    }
    if !signals.contains(&QualitySignal::HasSeveritySet) {
        hints.push("Set severity to high or critical if this gotcha can cause real damage".into());
    }
    if !signals.contains(&QualitySignal::HasReference) {
        hints.push("Add a reference URL (PR, issue, or doc that explains the context)".into());
    }
    if !signals.contains(&QualitySignal::RuleLengthAdequate) {
        hints.push("Expand the rule text — aim for at least 100 characters".into());
    }
    if !signals.contains(&QualitySignal::HasSpecificIdentifier) {
        hints.push(
            "Include specific identifiers: function names (foo()), paths (src/), types (CamelCase)"
                .into(),
        );
    }
    if signals.contains(&QualitySignal::VaguePhrasing) {
        hints
            .push("Remove vague phrases: \"be careful\", \"might\", \"probably\", \"should work\"".into());
    }
    if signals.contains(&QualitySignal::TooShort) {
        hints.push("Record is too short (<30 chars) — add detail".into());
    }

    hints
}

// ANSI color constants (duplicated from cli::colors to avoid lib→bin dependency)
const RED: &str = "\x1b[38;2;248;81;73m";
const YELLOW: &str = "\x1b[38;2;210;153;34m";
const RESET: &str = "\x1b[0m";

/// Print quality gate rejection to stderr (score < 0.2).
pub fn print_quality_gate_error(score: &QualityScore, use_color: bool) {
    let (red, yellow, reset) = if use_color {
        (RED, YELLOW, RESET)
    } else {
        ("", "", "")
    };

    eprintln!(
        "\n{red}Quality gate failed{reset} — score {:.2} is below minimum 0.20",
        score.value
    );
    eprintln!("{yellow}Improve your record:{reset}");
    for hint in generate_improvement_hints(score) {
        eprintln!("  - {hint}");
    }
    eprintln!();
}

/// Print quality caveat warning to stderr (score 0.2–0.4).
pub fn print_quality_caveat(score: &QualityScore, use_color: bool) {
    let (yellow, reset) = if use_color { (YELLOW, RESET) } else { ("", "") };

    eprintln!(
        "\n{yellow}Quality caveat{reset} — score {:.2} (Poor). Record will be injected with a low-quality warning.",
        score.value
    );
    eprintln!("{yellow}To improve:{reset}");
    for hint in generate_improvement_hints(score) {
        eprintln!("  - {hint}");
    }
    eprintln!();
}

// ── Internal helpers ─────────────────────────────────────────────────────────

fn bool_weight(b: bool) -> f32 {
    if b { 1.0 } else { 0.0 }
}

/// Check if the first word of `text` is an imperative verb.
fn detect_imperative_verb(text: &str) -> bool {
    let first_word = text
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    // Strip trailing punctuation from the first word
    let first_word = first_word.trim_end_matches(|c: char| !c.is_alphanumeric());
    IMPERATIVE_VERBS.contains(&first_word.as_ref())
}

/// Check if text contains any causality marker.
fn detect_causality(lower: &str) -> bool {
    CAUSALITY_MARKERS.iter().any(|m| lower.contains(m))
}

/// Check if text contains any vague phrase.
fn detect_vague_phrase(lower: &str) -> bool {
    VAGUE_PHRASES.iter().any(|m| lower.contains(m))
}

/// Linear ramp: 0.0 at <20 chars, 1.0 at >=100 chars.
fn length_score(text: &str) -> f32 {
    let len = text.len() as f32;
    if len < 20.0 {
        0.0
    } else if len >= 100.0 {
        1.0
    } else {
        (len - 20.0) / 80.0
    }
}

/// Specificity: presence of `::`, `()`, file paths (`/`, `.rs`), or CamelCase.
fn specificity_score(text: &str) -> f32 {
    let mut score = 0.0f32;
    let checks = [
        text.contains("::"),
        text.contains("()"),
        text.contains('/') && (text.contains(".rs") || text.contains(".ts") || text.contains(".py") || text.contains(".go") || text.contains(".js") || text.contains(".json") || text.contains(".toml")),
        has_camel_case(text),
    ];
    let hit_count = checks.iter().filter(|&&b| b).count();
    score += hit_count as f32 * 0.25;
    score.min(1.0)
}

/// Check for CamelCase identifiers (at least two uppercase letters in a word).
fn has_camel_case(text: &str) -> bool {
    text.split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|word| {
            let upper_count = word.chars().filter(|c| c.is_uppercase()).count();
            let lower_count = word.chars().filter(|c| c.is_lowercase()).count();
            upper_count >= 2 && lower_count >= 1 && word.len() >= 4
        })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        Category, ConfidenceScore, QualityTier, RecordLifecycle, RecordSource, RecordVersion,
        StalenessScore,
    };
    use uuid::Uuid;

    fn device_id() -> Uuid {
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    fn make_record(value: &str, priority: Priority, ref_url: Option<&str>) -> Record {
        Record {
            key: "gotcha:test".into(),
            value: value.into(),
            category: Category::Gotcha,
            priority,
            tags: vec![],
            created_at: 1_710_520_800,
            updated_at: 1_710_520_800,
            ref_url: ref_url.map(|s| s.into()),
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: device_id(),
                logical_clock: 1,
                wall_clock: 1_710_520_800,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
            gap_analysis_score: 0.0,
        }
    }

    #[test]
    fn high_quality_record_scores_well() {
        let r = make_record(
            "Never call .await inside a rayon::spawn closure because the tokio runtime panics on nested block_on",
            Priority::Critical,
            Some("https://github.com/example/issue/42"),
        );
        let score = analyze(&r);
        assert!(score.value >= 0.7, "expected Good+, got {:.2}", score.value);
        assert!(score.signals.contains(&QualitySignal::HasImperativeVerb));
        assert!(score.signals.contains(&QualitySignal::HasCausality));
        assert!(score.signals.contains(&QualitySignal::HasSeveritySet));
        assert!(score.signals.contains(&QualitySignal::HasReference));
    }

    #[test]
    fn vague_short_record_scores_poorly() {
        let r = make_record("be careful with this", Priority::Normal, None);
        let score = analyze(&r);
        assert!(
            score.value < 0.2,
            "expected Suppressed, got {:.2}",
            score.value
        );
        assert!(score.signals.contains(&QualitySignal::VaguePhrasing));
        assert!(score.signals.contains(&QualitySignal::TooShort));
    }

    #[test]
    fn empty_record_is_suppressed() {
        let r = make_record("", Priority::Normal, None);
        let score = analyze(&r);
        assert!(score.value < 0.2);
        assert_eq!(score.tier, QualityTier::Suppressed);
    }

    #[test]
    fn imperative_without_reason_is_penalized() {
        let r = make_record(
            "Always wrap database calls in a transaction for consistency guarantees",
            Priority::Normal,
            None,
        );
        let score = analyze(&r);
        // Has imperative + length, but no causality → NoReason penalty
        assert!(score.signals.contains(&QualitySignal::NoReason));
        assert!(score.value < 0.7);
    }

    #[test]
    fn quality_gate_rejects_below_02() {
        let score = QualityScore {
            value: 0.15,
            tier: QualityTier::Suppressed,
            signals: vec![],
            computed_at: 0,
        };
        assert!(below_quality_gate(&score));
    }

    #[test]
    fn quality_gate_passes_above_02() {
        let score = QualityScore {
            value: 0.25,
            tier: QualityTier::Poor,
            signals: vec![],
            computed_at: 0,
        };
        assert!(!below_quality_gate(&score));
    }

    #[test]
    fn improvement_hints_cover_missing_signals() {
        let score = QualityScore {
            value: 0.10,
            tier: QualityTier::Suppressed,
            signals: vec![QualitySignal::TooShort, QualitySignal::NoReason],
            computed_at: 0,
        };
        let hints = generate_improvement_hints(&score);
        assert!(hints.len() >= 4); // missing: imperative, causality, severity, reference, length, specificity
        assert!(hints.iter().any(|h| h.contains("imperative")));
    }

    #[test]
    fn length_score_ramp() {
        assert!((length_score("short") - 0.0).abs() < f32::EPSILON);
        assert!((length_score(&"x".repeat(60)) - 0.5).abs() < 0.01);
        assert!((length_score(&"x".repeat(100)) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn specificity_detects_identifiers() {
        assert!(specificity_score("Use Store::open() for initialization") > 0.0);
        assert!(specificity_score("something generic") < 0.01);
    }

    #[test]
    fn camel_case_detection() {
        assert!(has_camel_case("SurrealKV is the store"));
        assert!(has_camel_case("use RecordVersion"));
        assert!(!has_camel_case("all lowercase words"));
        assert!(!has_camel_case("ALL CAPS"));
    }
}
