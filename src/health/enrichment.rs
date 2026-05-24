//! Adaptive triage scoring for `/mati-enrich` (D2-α).
//!
//! Maps per-file signals to a depth tier that the `/mati-enrich` slash flow
//! uses to decide how aggressive to be during extraction:
//!
//! - **Fast**     — single-pass, schema-only guidance. ~30% of typical files.
//! - **Standard** — positive exemplars + Pass 3 Rounds 1 and 2. ~50% of files.
//! - **Deep**     — full pipeline with positive AND negative exemplars +
//!                  full critique loop. ~20% of files.
//!
//! Surfaced to the agent via the `enrichment_depth_hint` field on `mem_get`
//! responses for `file:` keys (`src/mcp/handlers.rs::handle_mem_get`).
//!
//! Pure synchronous scoring — no I/O. Mirrors the pattern of
//! `src/health/quality.rs`.
//!
//! Reference: `ENRICH_QUALITY.md` Section 4 (Proposal D, Phase D2-α).

use serde::{Deserialize, Serialize};

use crate::analysis::blast_radius::BlastTier;

/// Triage tier for `/mati-enrich`'s adaptive depth selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrichmentDepth {
    Fast,
    Standard,
    Deep,
}

impl EnrichmentDepth {
    /// Stable string label for the response envelope and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            EnrichmentDepth::Fast => "fast",
            EnrichmentDepth::Standard => "standard",
            EnrichmentDepth::Deep => "deep",
        }
    }
}

/// Threshold constants. Tuned for typical Rust codebases.
///
/// Changing any of these is a behavior change for `/mati-enrich`'s per-file
/// triage — record the rationale in DECISIONS.md before tuning.
mod thresholds {
    pub const LARGE_FILE_LOC: u32 = 400;
    pub const MEDIUM_FILE_LOC: u32 = 100;
    pub const STRONG_CLUSTER_SIZE: u32 = 5;
    pub const STRONG_GOTCHA_COUNT: usize = 3;
    pub const SIGNAL_RICH_COMMENT_RATIO: f32 = 0.15;
}

/// Score a file's enrichment depth based on its persisted signals.
///
/// All inputs are derivable from `FileRecord` + a `cluster:index` lookup;
/// the daemon gathers them and calls this function. No I/O here.
///
/// # Scoring rubric
///
/// | Signal                                | Points       |
/// | ------------------------------------- | ------------ |
/// | `line_count >= 400`                   | +3           |
/// | `line_count >= 100` (and < 400)       | +1           |
/// | `blast_tier` ∈ {Moderate, High, Critical} | +2       |
/// | `cluster_size >= 5`                   | +2           |
/// | `gotcha_count >= 3`                   | +2           |
/// | `comment_density >= 0.15` (when known)| +1           |
///
/// | Score | Tier      |
/// | ----- | --------- |
/// | 0-1   | Fast      |
/// | 2-4   | Standard  |
/// | 5+    | Deep      |
///
/// `comment_density` is `None` on the cheap path (recomputing it requires
/// re-reading source); the function still works without it.
pub fn enrichment_depth(
    line_count: u32,
    blast_tier: BlastTier,
    cluster_size: u32,
    gotcha_count: usize,
    comment_density: Option<f32>,
) -> EnrichmentDepth {
    use thresholds::*;

    let mut score: u32 = 0;

    if line_count >= LARGE_FILE_LOC {
        score += 3;
    } else if line_count >= MEDIUM_FILE_LOC {
        score += 1;
    }

    // BlastTier doesn't derive Ord; match explicitly for the "≥ Moderate" gate.
    if matches!(
        blast_tier,
        BlastTier::Moderate | BlastTier::High | BlastTier::Critical
    ) {
        score += 2;
    }

    if cluster_size >= STRONG_CLUSTER_SIZE {
        score += 2;
    }

    if gotcha_count >= STRONG_GOTCHA_COUNT {
        score += 2;
    }

    if let Some(density) = comment_density {
        if density >= SIGNAL_RICH_COMMENT_RATIO {
            score += 1;
        }
    }

    match score {
        0..=1 => EnrichmentDepth::Fast,
        2..=4 => EnrichmentDepth::Standard,
        _ => EnrichmentDepth::Deep,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiny_isolated_file_is_fast() {
        // 50 LoC, no blast, no cluster, no gotchas, no comment data
        // score = 0 → Fast
        assert_eq!(
            enrichment_depth(50, BlastTier::Isolated, 0, 0, None),
            EnrichmentDepth::Fast
        );
    }

    #[test]
    fn medium_file_alone_is_standard() {
        // 200 LoC (+1), no other signals → score = 1 → Fast (boundary)
        assert_eq!(
            enrichment_depth(200, BlastTier::Isolated, 0, 0, None),
            EnrichmentDepth::Fast
        );
        // 200 LoC (+1) + comments (+1) → score = 2 → Standard
        assert_eq!(
            enrichment_depth(200, BlastTier::Isolated, 0, 0, Some(0.2)),
            EnrichmentDepth::Standard
        );
    }

    #[test]
    fn large_file_alone_is_standard() {
        // 500 LoC (+3) → score = 3 → Standard
        assert_eq!(
            enrichment_depth(500, BlastTier::Isolated, 0, 0, None),
            EnrichmentDepth::Standard
        );
    }

    #[test]
    fn large_file_with_blast_is_deep() {
        // 500 LoC (+3) + High blast (+2) → score = 5 → Deep
        assert_eq!(
            enrichment_depth(500, BlastTier::High, 0, 0, None),
            EnrichmentDepth::Deep
        );
    }

    #[test]
    fn hotspot_with_many_gotchas_is_deep() {
        // 200 LoC (+1) + High blast (+2) + 4 gotchas (+2) → score = 5 → Deep
        assert_eq!(
            enrichment_depth(200, BlastTier::High, 0, 4, None),
            EnrichmentDepth::Deep
        );
    }

    #[test]
    fn large_cluster_member_is_at_least_standard() {
        // 50 LoC + Moderate blast (+2) + cluster size 6 (+2) → 4 → Standard
        assert_eq!(
            enrichment_depth(50, BlastTier::Moderate, 6, 0, None),
            EnrichmentDepth::Standard
        );
    }

    #[test]
    fn boundary_loc_400_qualifies_for_3_points() {
        // exactly 400 LoC → +3 → Standard alone
        assert_eq!(
            enrichment_depth(400, BlastTier::Isolated, 0, 0, None),
            EnrichmentDepth::Standard
        );
    }

    #[test]
    fn comment_density_below_threshold_does_not_score() {
        // 200 LoC (+1) + density 0.14 (below 0.15) → score = 1 → Fast
        assert_eq!(
            enrichment_depth(200, BlastTier::Isolated, 0, 0, Some(0.14)),
            EnrichmentDepth::Fast
        );
    }

    #[test]
    fn blast_below_moderate_does_not_score() {
        // 50 LoC + Low blast → 0 → Fast
        assert_eq!(
            enrichment_depth(50, BlastTier::Low, 0, 0, None),
            EnrichmentDepth::Fast
        );
        // 50 LoC + Isolated → 0 → Fast
        assert_eq!(
            enrichment_depth(50, BlastTier::Isolated, 0, 0, None),
            EnrichmentDepth::Fast
        );
    }

    #[test]
    fn as_str_returns_stable_labels() {
        assert_eq!(EnrichmentDepth::Fast.as_str(), "fast");
        assert_eq!(EnrichmentDepth::Standard.as_str(), "standard");
        assert_eq!(EnrichmentDepth::Deep.as_str(), "deep");
    }

    #[test]
    fn serialization_matches_label() {
        let json = serde_json::to_string(&EnrichmentDepth::Deep).unwrap();
        assert_eq!(json, "\"deep\"");
        let back: EnrichmentDepth = serde_json::from_str("\"standard\"").unwrap();
        assert_eq!(back, EnrichmentDepth::Standard);
    }
}
