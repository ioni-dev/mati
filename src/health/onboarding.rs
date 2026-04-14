//! Onboarding score computation (M-10-F).
//!
//! Estimates how many minutes a new developer needs to become productive,
//! based on the knowledge coverage of the codebase.
//!
//! Formula (ARCHITECTURE.md §13.3):
//!
//! ```text
//! base_time = 22 minutes
//!
//! weighted_reduction =
//!     hotspot_coverage  * 0.40
//!   + gotcha_coverage   * 0.25
//!   + decision_coverage * 0.15
//!   + avg_confidence    * 0.20
//!
//! estimated_minutes = base_time * (1 - weighted_reduction)
//! ```
//!
//! Each factor is a fraction in `[0.0, 1.0]`:
//! - `hotspot_coverage`:  fraction of hotspot files with non-empty `purpose`
//! - `gotcha_coverage`:   fraction of hotspot files with at least one gotcha key
//! - `decision_coverage`: fraction of `decision:*` records with non-empty value
//! - `avg_confidence`:    mean confidence across records with `confidence >= 0.6`

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::store::{FileRecord, OnboardingScore, Store};

// ── Constants ────────────────────────────────────────────────────────────────

/// Baseline onboarding time (minutes) for a completely undocumented codebase.
const BASE_TIME: f32 = 22.0;

/// Weight for hotspot file purpose coverage.
const W_HOTSPOT: f32 = 0.40;
/// Weight for gotcha coverage on hotspot files.
const W_GOTCHA: f32 = 0.25;
/// Weight for architectural decision documentation.
const W_DECISION: f32 = 0.15;
/// Weight for average confidence across confirmed records.
const W_CONFIDENCE: f32 = 0.20;

/// Minimum confidence value for a record to count as "confirmed".
const CONFIDENCE_THRESHOLD: f32 = 0.6;

// ── Public API ───────────────────────────────────────────────────────────────

/// Compute the [`OnboardingScore`] from pre-loaded record slices.
///
/// Use this when the caller already has the store data to avoid redundant scans.
pub fn compute_from_records(
    file_records: &[crate::store::Record],
    decisions: &[crate::store::Record],
    gotchas: &[crate::store::Record],
) -> OnboardingScore {
    let file_data: Vec<FileRecord> = file_records
        .iter()
        .filter_map(|r| r.payload_as::<FileRecord>())
        .collect();
    let hotspot_coverage = compute_hotspot_coverage(&file_data);
    let gotcha_coverage = compute_gotcha_coverage(&file_data);
    let decision_coverage = compute_decision_coverage(decisions);
    let all_knowledge: Vec<_> = gotchas.iter().chain(decisions.iter()).collect();
    let avg_confidence = compute_avg_confidence(&all_knowledge);
    let estimated_minutes = compute_estimated_minutes(
        hotspot_coverage,
        gotcha_coverage,
        decision_coverage,
        avg_confidence,
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    OnboardingScore {
        estimated_minutes,
        critical_files_covered: hotspot_coverage,
        gotcha_coverage,
        decision_coverage,
        avg_confidence,
        computed_at: now,
    }
}

/// Compute the [`OnboardingScore`] by scanning the store for file, decision,
/// and gotcha records.
pub async fn compute(store: &Store) -> Result<OnboardingScore> {
    let file_records = store.scan_prefix("file:").await?;
    let decision_records = store.scan_prefix("decision:").await?;
    let gotcha_records = store.scan_prefix("gotcha:").await?;
    Ok(compute_from_records(
        &file_records,
        &decision_records,
        &gotcha_records,
    ))
}

// ── Pure helpers (testable without Store) ────────────────────────────────────

/// Fraction of hotspot files with a non-empty `purpose` field.
/// Returns 0.0 if there are no hotspot files.
fn compute_hotspot_coverage(files: &[FileRecord]) -> f32 {
    let hotspots: Vec<&FileRecord> = files.iter().filter(|f| f.is_hotspot).collect();
    if hotspots.is_empty() {
        return 0.0;
    }
    let covered = hotspots.iter().filter(|f| !f.purpose.is_empty()).count();
    covered as f32 / hotspots.len() as f32
}

/// Fraction of hotspot files with at least one gotcha key.
/// Returns 0.0 if there are no hotspot files.
fn compute_gotcha_coverage(files: &[FileRecord]) -> f32 {
    let hotspots: Vec<&FileRecord> = files.iter().filter(|f| f.is_hotspot).collect();
    if hotspots.is_empty() {
        return 0.0;
    }
    let covered = hotspots
        .iter()
        .filter(|f| !f.gotcha_keys.is_empty())
        .count();
    covered as f32 / hotspots.len() as f32
}

/// Fraction of `decision:*` records with a non-empty value (enriched vs stub).
/// Returns 0.0 if no decisions exist.
fn compute_decision_coverage(decisions: &[crate::store::Record]) -> f32 {
    if decisions.is_empty() {
        return 0.0;
    }
    let enriched = decisions
        .iter()
        .filter(|r| !r.value.trim().is_empty())
        .count();
    enriched as f32 / decisions.len() as f32
}

/// Average `confidence.value` across records where `confidence.value >= 0.6`.
/// Returns 0.0 if no records meet the threshold.
fn compute_avg_confidence(records: &[&crate::store::Record]) -> f32 {
    let qualifying: Vec<f32> = records
        .iter()
        .filter(|r| r.confidence.value >= CONFIDENCE_THRESHOLD)
        .map(|r| r.confidence.value)
        .collect();
    if qualifying.is_empty() {
        return 0.0;
    }
    qualifying.iter().sum::<f32>() / qualifying.len() as f32
}

/// Apply the onboarding formula to produce estimated minutes.
fn compute_estimated_minutes(
    hotspot_coverage: f32,
    gotcha_coverage: f32,
    decision_coverage: f32,
    avg_confidence: f32,
) -> f32 {
    let weighted_reduction = hotspot_coverage * W_HOTSPOT
        + gotcha_coverage * W_GOTCHA
        + decision_coverage * W_DECISION
        + avg_confidence * W_CONFIDENCE;

    // Clamp reduction to [0, 1] to avoid negative minutes.
    let clamped = weighted_reduction.clamp(0.0, 1.0);
    BASE_TIME * (1.0 - clamped)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle, RecordSource,
        RecordVersion, StalenessScore, TodoComment,
    };
    use uuid::Uuid;

    fn device_id() -> Uuid {
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    fn make_file_record(
        path: &str,
        purpose: &str,
        gotcha_keys: Vec<String>,
        is_hotspot: bool,
    ) -> FileRecord {
        FileRecord {
            path: path.into(),
            purpose: purpose.into(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys,
            decision_keys: vec![],
            todos: Vec::<TodoComment>::new(),
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: if is_hotspot { 50 } else { 5 },
            last_author: None,
            is_hotspot,
            token_cost_estimate: 200,
            last_modified_session: 0,
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
        }
    }

    fn make_record(key: &str, value: &str, confidence_value: f32) -> Record {
        Record {
            key: key.into(),
            value: value.into(),
            category: if key.starts_with("gotcha:") {
                Category::Gotcha
            } else if key.starts_with("decision:") {
                Category::Decision
            } else {
                Category::File
            },
            priority: Priority::Normal,
            tags: vec![],
            created_at: 1_710_520_800,
            updated_at: 1_710_520_800,
            ref_url: None,
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
            confidence: ConfidenceScore {
                value: confidence_value,
                confirmation_count: if confidence_value >= 0.6 { 1 } else { 0 },
                contributor_count: 1,
                last_challenged: None,
                challenge_count: 0,
            },
            gap_analysis_score: 0.0,
            payload: None,
        }
    }

    // ── Formula tests ────────────────────────────────────────────────────

    #[test]
    fn no_records_yields_base_time() {
        let minutes = compute_estimated_minutes(0.0, 0.0, 0.0, 0.0);
        assert!(
            (minutes - BASE_TIME).abs() < f32::EPSILON,
            "expected {BASE_TIME}, got {minutes}"
        );
    }

    #[test]
    fn full_coverage_yields_near_zero() {
        let minutes = compute_estimated_minutes(1.0, 1.0, 1.0, 1.0);
        assert!(minutes.abs() < 0.01, "expected ~0.0, got {minutes}");
    }

    #[test]
    fn partial_coverage_proportional_reduction() {
        // 50% hotspot coverage only: reduction = 0.5 * 0.40 = 0.20
        let minutes = compute_estimated_minutes(0.5, 0.0, 0.0, 0.0);
        let expected = BASE_TIME * (1.0 - 0.20);
        assert!(
            (minutes - expected).abs() < 0.01,
            "expected {expected}, got {minutes}"
        );
    }

    // ── Hotspot coverage ─────────────────────────────────────────────────

    #[test]
    fn hotspot_coverage_no_hotspots() {
        let files = vec![make_file_record(
            "src/lib.rs",
            "library root",
            vec![],
            false,
        )];
        assert!((compute_hotspot_coverage(&files) - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn hotspot_coverage_all_documented() {
        let files = vec![
            make_file_record("src/main.rs", "entry point", vec![], true),
            make_file_record("src/db.rs", "database layer", vec![], true),
        ];
        assert!((compute_hotspot_coverage(&files) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn hotspot_coverage_partial() {
        let files = vec![
            make_file_record("src/main.rs", "entry point", vec![], true),
            make_file_record("src/db.rs", "", vec![], true), // empty purpose
        ];
        assert!((compute_hotspot_coverage(&files) - 0.5).abs() < f32::EPSILON);
    }

    // ── Gotcha coverage ──────────────────────────────────────────────────

    #[test]
    fn gotcha_coverage_no_hotspots() {
        let files = vec![make_file_record(
            "src/lib.rs",
            "",
            vec!["gotcha:x".into()],
            false,
        )];
        assert!((compute_gotcha_coverage(&files) - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn gotcha_coverage_all_have_gotchas() {
        let files = vec![
            make_file_record("src/main.rs", "", vec!["gotcha:a".into()], true),
            make_file_record("src/db.rs", "", vec!["gotcha:b".into()], true),
        ];
        assert!((compute_gotcha_coverage(&files) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn gotcha_coverage_partial() {
        let files = vec![
            make_file_record("src/main.rs", "", vec!["gotcha:a".into()], true),
            make_file_record("src/db.rs", "", vec![], true), // no gotchas
        ];
        assert!((compute_gotcha_coverage(&files) - 0.5).abs() < f32::EPSILON);
    }

    // ── Decision coverage ────────────────────────────────────────────────

    #[test]
    fn decision_coverage_no_decisions() {
        let records: Vec<Record> = vec![];
        assert!((compute_decision_coverage(&records) - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn decision_coverage_all_enriched() {
        let records = vec![
            make_record(
                "decision:use-surrealkv",
                "We chose SurrealKV because...",
                0.8,
            ),
            make_record(
                "decision:three-tools",
                "MCP tools capped at 3 to save tokens",
                0.7,
            ),
        ];
        assert!((compute_decision_coverage(&records) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn decision_coverage_half_stubs() {
        let records = vec![
            make_record(
                "decision:use-surrealkv",
                "We chose SurrealKV because...",
                0.8,
            ),
            make_record("decision:three-tools", "", 0.1), // stub
        ];
        assert!((compute_decision_coverage(&records) - 0.5).abs() < f32::EPSILON);
    }

    // ── Average confidence ───────────────────────────────────────────────

    #[test]
    fn avg_confidence_no_qualifying() {
        let records = [
            make_record("gotcha:low", "some text", 0.3),
            make_record("gotcha:also-low", "other text", 0.5),
        ];
        let refs: Vec<&Record> = records.iter().collect();
        assert!((compute_avg_confidence(&refs) - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn avg_confidence_all_qualifying() {
        let records = [
            make_record("gotcha:high", "some text", 0.8),
            make_record("decision:important", "other text", 0.6),
        ];
        let refs: Vec<&Record> = records.iter().collect();
        let expected = (0.8 + 0.6) / 2.0;
        assert!(
            (compute_avg_confidence(&refs) - expected).abs() < 0.001,
            "expected {expected}, got {}",
            compute_avg_confidence(&refs)
        );
    }

    #[test]
    fn avg_confidence_mixed() {
        let records = [
            make_record("gotcha:high", "some text", 0.9),
            make_record("gotcha:low", "other text", 0.3), // below threshold
            make_record("decision:mid", "text", 0.7),
        ];
        let refs: Vec<&Record> = records.iter().collect();
        let expected = (0.9 + 0.7) / 2.0;
        assert!(
            (compute_avg_confidence(&refs) - expected).abs() < 0.001,
            "expected {expected}, got {}",
            compute_avg_confidence(&refs)
        );
    }

    // ── Individual factor weights ────────────────────────────────────────

    #[test]
    fn hotspot_factor_only() {
        // Full hotspot coverage, nothing else.
        let minutes = compute_estimated_minutes(1.0, 0.0, 0.0, 0.0);
        let expected = BASE_TIME * (1.0 - W_HOTSPOT);
        assert!(
            (minutes - expected).abs() < 0.01,
            "expected {expected}, got {minutes}"
        );
    }

    #[test]
    fn gotcha_factor_only() {
        let minutes = compute_estimated_minutes(0.0, 1.0, 0.0, 0.0);
        let expected = BASE_TIME * (1.0 - W_GOTCHA);
        assert!(
            (minutes - expected).abs() < 0.01,
            "expected {expected}, got {minutes}"
        );
    }

    #[test]
    fn decision_factor_only() {
        let minutes = compute_estimated_minutes(0.0, 0.0, 1.0, 0.0);
        let expected = BASE_TIME * (1.0 - W_DECISION);
        assert!(
            (minutes - expected).abs() < 0.01,
            "expected {expected}, got {minutes}"
        );
    }

    #[test]
    fn confidence_factor_only() {
        let minutes = compute_estimated_minutes(0.0, 0.0, 0.0, 1.0);
        let expected = BASE_TIME * (1.0 - W_CONFIDENCE);
        assert!(
            (minutes - expected).abs() < 0.01,
            "expected {expected}, got {minutes}"
        );
    }
}
