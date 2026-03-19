//! Confidence score recomputation (M-10-A).
//!
//! Pure synchronous computation — no I/O, no async. Applies the formula from
//! ARCHITECTURE.md §13.1:
//!
//! ```text
//! confidence = base_score
//!   × log2(confirmation_count + 2)      capped at 2.0
//!   × min(contributor_count, 3) / 3
//!   × recency_weight(last_accessed)      90-day half-life
//!   × ref_boost                          1.5× if ref_url set
//! ```
//!
//! The `+2` inside the log ensures the base case (0 confirmations) yields
//! `log2(2) = 1.0`, so the score is never zeroed out by the log factor alone.
//! The cap at 2.0 prevents runaway inflation from many confirmations.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::store::{ConfidenceScore, Record};

// ── Constants ────────────────────────────────────────────────────────────────

/// Exponential decay half-life in days for the recency weight.
const HALF_LIFE_DAYS: f64 = 90.0;

/// Seconds in one day.
const SECS_PER_DAY: f64 = 86_400.0;

/// Maximum value for the log2 confirmation factor.
const LOG_FACTOR_CAP: f32 = 2.0;

/// Maximum contributor count that contributes to the score.
const MAX_CONTRIBUTORS: f32 = 3.0;

/// Multiplier applied when `ref_url` is present.
const REF_BOOST: f32 = 1.5;

// ── Public API ───────────────────────────────────────────────────────────────

/// Recompute the confidence value for `record` using the formula from
/// ARCHITECTURE.md §13.1.
///
/// Returns a new `ConfidenceScore` with the recomputed `value`. All other
/// fields (`confirmation_count`, `contributor_count`, `last_challenged`,
/// `challenge_count`) are copied unchanged from the existing record.
///
/// The caller is responsible for writing the result back to the record.
pub fn recompute(record: &Record) -> ConfidenceScore {
    let conf = &record.confidence;

    let base = ConfidenceScore::base_for_source(&record.source);

    // log2(confirmation_count + 2), capped at LOG_FACTOR_CAP.
    // +2 ensures 0 confirmations → log2(2) = 1.0 (identity).
    let log_factor = ((conf.confirmation_count as f32 + 2.0).log2()).min(LOG_FACTOR_CAP);

    // min(contributor_count, 3) / 3 — at least 1 contributor assumed.
    let contributor_factor =
        (conf.contributor_count.max(1) as f32).min(MAX_CONTRIBUTORS) / MAX_CONTRIBUTORS;

    // Recency weight: 2^(-days_since_access / 90).
    let recency = recency_weight(record.last_accessed, record.created_at);

    // 1.5× if ref_url is present, 1.0 otherwise.
    let ref_boost = if record.ref_url.is_some() {
        REF_BOOST
    } else {
        1.0
    };

    let value = (base * log_factor * contributor_factor * recency * ref_boost).clamp(0.0, 1.0);

    ConfidenceScore {
        value,
        confirmation_count: conf.confirmation_count,
        contributor_count: conf.contributor_count,
        last_challenged: conf.last_challenged,
        challenge_count: conf.challenge_count,
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Compute the recency weight using exponential decay with a 90-day half-life.
///
/// `2^(-days_since_access / 90)`
///
/// If `last_accessed` is 0 (never accessed), `created_at` is used instead.
fn recency_weight(last_accessed: u64, created_at: u64) -> f32 {
    let reference_time = if last_accessed == 0 {
        created_at
    } else {
        last_accessed
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // If reference_time is in the future (clock skew), treat as fully fresh.
    if reference_time >= now {
        return 1.0;
    }

    let days_elapsed = (now - reference_time) as f64 / SECS_PER_DAY;
    let weight = 2.0_f64.powf(-days_elapsed / HALF_LIFE_DAYS);
    weight as f32
}

/// Testable version of recency_weight that accepts an explicit `now` timestamp.
#[cfg(test)]
fn recency_weight_at(last_accessed: u64, created_at: u64, now: u64) -> f32 {
    let reference_time = if last_accessed == 0 {
        created_at
    } else {
        last_accessed
    };

    if reference_time >= now {
        return 1.0;
    }

    let days_elapsed = (now - reference_time) as f64 / SECS_PER_DAY;
    let weight = 2.0_f64.powf(-days_elapsed / HALF_LIFE_DAYS);
    weight as f32
}

/// Testable version of recompute that accepts an explicit `now` timestamp,
/// bypassing `SystemTime::now()`.
#[cfg(test)]
fn recompute_at(record: &Record, now: u64) -> ConfidenceScore {
    let conf = &record.confidence;

    let base = ConfidenceScore::base_for_source(&record.source);
    let log_factor = ((conf.confirmation_count as f32 + 2.0).log2()).min(LOG_FACTOR_CAP);
    let contributor_factor =
        (conf.contributor_count.max(1) as f32).min(MAX_CONTRIBUTORS) / MAX_CONTRIBUTORS;
    let recency = recency_weight_at(record.last_accessed, record.created_at, now);
    let ref_boost = if record.ref_url.is_some() {
        REF_BOOST
    } else {
        1.0
    };

    let value = (base * log_factor * contributor_factor * recency * ref_boost).clamp(0.0, 1.0);

    ConfidenceScore {
        value,
        confirmation_count: conf.confirmation_count,
        contributor_count: conf.contributor_count,
        last_challenged: conf.last_challenged,
        challenge_count: conf.challenge_count,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        Category, QualityScore, RecordLifecycle, RecordSource, RecordVersion, StalenessScore,
    };
    use crate::store::Priority;
    use uuid::Uuid;

    const NOW: u64 = 1_710_520_800; // 2024-03-15 ~20:00 UTC

    fn device_id() -> Uuid {
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    /// Build a test record with sensible defaults. `last_accessed` is set to
    /// `NOW` so recency decay is zero unless the test overrides it.
    fn make_record(
        source: RecordSource,
        confirmation_count: u32,
        contributor_count: u32,
        ref_url: Option<&str>,
    ) -> Record {
        Record {
            key: "gotcha:test".into(),
            value: "Test record value".into(),
            category: Category::Gotcha,
            priority: Priority::Normal,
            tags: vec![],
            created_at: NOW,
            updated_at: NOW,
            ref_url: ref_url.map(|s| s.into()),
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: device_id(),
                logical_clock: 1,
                wall_clock: NOW,
            },
            quality: QualityScore::layer0_default(),
            access_count: 1,
            last_accessed: NOW,
            source,
            confidence: ConfidenceScore {
                value: 0.0, // will be recomputed
                confirmation_count,
                contributor_count,
                last_challenged: None,
                challenge_count: 0,
            },
            gap_analysis_score: 0.0,
        }
    }

    // ── Base score by source ─────────────────────────────────────────────

    #[test]
    fn developer_manual_zero_confirmations_gives_base() {
        // base=0.80, log2(0+2)=1.0, contributors=1/3, recency=1.0, no ref
        // expected: 0.80 × 1.0 × (1/3) × 1.0 × 1.0 ≈ 0.2667
        let r = make_record(RecordSource::DeveloperManual, 0, 1, None);
        let score = recompute_at(&r, NOW);
        assert!(
            (score.value - 0.2667).abs() < 0.01,
            "expected ~0.27, got {:.4}",
            score.value
        );
    }

    #[test]
    fn developer_manual_full_contributors_gives_base() {
        // base=0.80, log2(2)=1.0, contributors=3/3=1.0, recency=1.0, no ref
        // expected: 0.80
        let r = make_record(RecordSource::DeveloperManual, 0, 3, None);
        let score = recompute_at(&r, NOW);
        assert!(
            (score.value - 0.80).abs() < 0.01,
            "expected ~0.80, got {:.4}",
            score.value
        );
    }

    #[test]
    fn static_analysis_gives_low_score() {
        // base=0.10, log2(2)=1.0, contributors=1/3, recency=1.0, no ref
        // expected: 0.10 × 1.0 × 0.333 × 1.0 ≈ 0.0333
        let r = make_record(RecordSource::StaticAnalysis, 0, 1, None);
        let score = recompute_at(&r, NOW);
        assert!(
            score.value < 0.10,
            "expected low score for StaticAnalysis, got {:.4}",
            score.value
        );
    }

    // ── Confirmation count raises score ──────────────────────────────────

    #[test]
    fn confirmations_raise_score() {
        // Use StaticAnalysis (base=0.10) with 1 contributor to keep scores
        // well below the 1.0 clamp so log factor differences are visible.
        //
        // log2(0+2)=1.0, log2(1+2)≈1.585, log2(2+2)=2.0 (at cap).
        // Beyond 2 confirmations the factor is capped at 2.0.
        let r0 = make_record(RecordSource::StaticAnalysis, 0, 1, None);
        let r1 = make_record(RecordSource::StaticAnalysis, 1, 1, None);
        let r2 = make_record(RecordSource::StaticAnalysis, 2, 1, None);

        let s0 = recompute_at(&r0, NOW);
        let s1 = recompute_at(&r1, NOW);
        let s2 = recompute_at(&r2, NOW);

        assert!(
            s1.value > s0.value,
            "1 confirmation ({:.4}) should beat 0 ({:.4})",
            s1.value,
            s0.value
        );
        assert!(
            s2.value > s1.value,
            "2 confirmations ({:.4}) should beat 1 ({:.4})",
            s2.value,
            s1.value
        );
    }

    #[test]
    fn log_factor_is_capped_at_2() {
        // log2(1000 + 2) ≈ 9.97, but capped at 2.0
        // base=0.80, cap=2.0, contributors=3/3, recency=1.0, no ref
        // expected: 0.80 × 2.0 × 1.0 × 1.0 × 1.0 = 1.60, clamped to 1.0
        let r = make_record(RecordSource::DeveloperManual, 1000, 3, None);
        let score = recompute_at(&r, NOW);
        assert!(
            (score.value - 1.0).abs() < f32::EPSILON,
            "expected clamped 1.0, got {:.4}",
            score.value
        );
    }

    // ── Contributor count ────────────────────────────────────────────────

    #[test]
    fn contributor_count_up_to_3_raises_score() {
        let r1 = make_record(RecordSource::DeveloperManual, 0, 1, None);
        let r2 = make_record(RecordSource::DeveloperManual, 0, 2, None);
        let r3 = make_record(RecordSource::DeveloperManual, 0, 3, None);

        let s1 = recompute_at(&r1, NOW);
        let s2 = recompute_at(&r2, NOW);
        let s3 = recompute_at(&r3, NOW);

        assert!(s2.value > s1.value, "2 contributors should beat 1");
        assert!(s3.value > s2.value, "3 contributors should beat 2");
    }

    #[test]
    fn contributor_count_beyond_3_no_additional_effect() {
        let r3 = make_record(RecordSource::DeveloperManual, 0, 3, None);
        let r5 = make_record(RecordSource::DeveloperManual, 0, 5, None);
        let r10 = make_record(RecordSource::DeveloperManual, 0, 10, None);

        let s3 = recompute_at(&r3, NOW);
        let s5 = recompute_at(&r5, NOW);
        let s10 = recompute_at(&r10, NOW);

        assert!(
            (s3.value - s5.value).abs() < f32::EPSILON,
            "5 contributors ({:.4}) should equal 3 ({:.4})",
            s5.value,
            s3.value
        );
        assert!(
            (s3.value - s10.value).abs() < f32::EPSILON,
            "10 contributors ({:.4}) should equal 3 ({:.4})",
            s10.value,
            s3.value
        );
    }

    // ── Recency decay ────────────────────────────────────────────────────

    #[test]
    fn old_access_significantly_reduces_score() {
        // 180 days old → recency = 2^(-180/90) = 2^(-2) = 0.25
        let days_180 = 180 * 86_400;
        let mut r = make_record(RecordSource::DeveloperManual, 0, 3, None);
        r.last_accessed = NOW - days_180;

        let score = recompute_at(&r, NOW);
        // base=0.80 × 1.0 × 1.0 × 0.25 × 1.0 = 0.20
        assert!(
            (score.value - 0.20).abs() < 0.02,
            "180-day-old record should score ~0.20, got {:.4}",
            score.value
        );
    }

    #[test]
    fn ninety_day_old_access_halves_recency() {
        let days_90 = 90 * 86_400;
        let recency = recency_weight_at(NOW - days_90, NOW - days_90, NOW);
        assert!(
            (recency - 0.5).abs() < 0.01,
            "90-day half-life should give 0.5, got {:.4}",
            recency
        );
    }

    #[test]
    fn recent_access_gives_full_recency() {
        let recency = recency_weight_at(NOW, NOW, NOW);
        assert!(
            (recency - 1.0).abs() < f32::EPSILON,
            "same-time access should give 1.0, got {:.4}",
            recency
        );
    }

    // ── ref_url boost ────────────────────────────────────────────────────

    #[test]
    fn ref_url_boost_increases_score() {
        // Use StaticAnalysis (base=0.10) with 1 contributor to keep both
        // scores well below 1.0 so the 1.5× ratio is not distorted by clamping.
        let r_no_ref = make_record(RecordSource::StaticAnalysis, 0, 1, None);
        let r_with_ref = make_record(
            RecordSource::StaticAnalysis,
            0,
            1,
            Some("https://github.com/example/issue/42"),
        );

        let s_no_ref = recompute_at(&r_no_ref, NOW);
        let s_with_ref = recompute_at(&r_with_ref, NOW);

        // ref_boost = 1.5, so with_ref should be ~1.5× no_ref
        let ratio = s_with_ref.value / s_no_ref.value;
        assert!(
            (ratio - 1.5).abs() < 0.01,
            "ref_url should give ~1.5× boost, got ratio {:.4}",
            ratio
        );
    }

    // ── Clamping ─────────────────────────────────────────────────────────

    #[test]
    fn result_is_clamped_to_0_1() {
        // DeveloperManual(0.80) × log2(1002)≈2.0(capped) × 3/3 × 1.0 × 1.5
        // = 0.80 × 2.0 × 1.0 × 1.0 × 1.5 = 2.40 → clamped to 1.0
        let r = make_record(
            RecordSource::DeveloperManual,
            1000,
            3,
            Some("https://example.com"),
        );
        let score = recompute_at(&r, NOW);
        assert!(
            score.value <= 1.0,
            "score should be clamped to 1.0, got {:.4}",
            score.value
        );
        assert!(
            score.value >= 0.0,
            "score should be >= 0.0, got {:.4}",
            score.value
        );
    }

    // ── Never-accessed record uses created_at ────────────────────────────

    #[test]
    fn never_accessed_uses_created_at() {
        let mut r = make_record(RecordSource::DeveloperManual, 0, 3, None);
        r.last_accessed = 0;
        r.created_at = NOW; // created "now" so recency = 1.0

        let score = recompute_at(&r, NOW);
        // Should behave as if last_accessed == NOW
        assert!(
            (score.value - 0.80).abs() < 0.01,
            "never-accessed record created now should score ~0.80, got {:.4}",
            score.value
        );
    }

    #[test]
    fn never_accessed_old_created_at_decays() {
        let days_180 = 180 * 86_400;
        let mut r = make_record(RecordSource::DeveloperManual, 0, 3, None);
        r.last_accessed = 0;
        r.created_at = NOW - days_180;

        let score = recompute_at(&r, NOW);
        // Falls back to created_at which is 180 days ago → recency ≈ 0.25
        // 0.80 × 1.0 × 1.0 × 0.25 = 0.20
        assert!(
            (score.value - 0.20).abs() < 0.02,
            "never-accessed 180-day-old record should score ~0.20, got {:.4}",
            score.value
        );
    }

    // ── Fields are preserved ─────────────────────────────────────────────

    #[test]
    fn recompute_preserves_confidence_metadata() {
        let mut r = make_record(RecordSource::DeveloperManual, 5, 2, None);
        r.confidence.last_challenged = Some(1_710_000_000);
        r.confidence.challenge_count = 3;

        let score = recompute_at(&r, NOW);
        assert_eq!(score.confirmation_count, 5);
        assert_eq!(score.contributor_count, 2);
        assert_eq!(score.last_challenged, Some(1_710_000_000));
        assert_eq!(score.challenge_count, 3);
    }

    // ── All source types produce expected relative ordering ──────────────

    #[test]
    fn source_ordering_matches_base_scores() {
        let sources = [
            RecordSource::StaticAnalysis,
            RecordSource::SessionHook,
            RecordSource::ClaudeEnrich,
            RecordSource::Import,
            RecordSource::DeveloperManual,
        ];

        let scores: Vec<f32> = sources
            .iter()
            .map(|s| {
                let r = make_record(s.clone(), 0, 3, None);
                recompute_at(&r, NOW).value
            })
            .collect();

        for i in 1..scores.len() {
            assert!(
                scores[i] > scores[i - 1],
                "{:?} ({:.4}) should score higher than {:?} ({:.4})",
                sources[i],
                scores[i],
                sources[i - 1],
                scores[i - 1]
            );
        }
    }
}
