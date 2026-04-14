//! Staleness propagation through Imports edges.
//!
//! When a file becomes Stale (≥ 0.4), a bounded, decaying fraction of that
//! staleness cascades to files that import it. Propagated staleness is stored
//! separately from local staleness so the developer can distinguish inherent
//! vs inherited staleness in `mati explain` and `mati stale`.
//!
//! Three critical properties:
//! 1. **Idempotent** — running twice produces the same result.
//! 2. **Bounded** — cascade terminates at depth 2, never loops.
//! 3. **Max, not sum** — importing two stale files gives the higher bump, not the sum.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::graph::edges::EdgeKind;
use crate::graph::graph::Graph;
use crate::store::record::Record;

/// Staleness at or above this value acts as a propagation source.
/// Corresponds to the Stale tier boundary (0.4).
pub const STALE_THRESHOLD: f32 = 0.4;

/// Fraction of source staleness applied to direct importers (depth 1).
pub const PROPAGATION_D1: f32 = 0.15;

/// Fraction of source staleness applied to depth-2 importers.
pub const PROPAGATION_D2: f32 = 0.05;

/// Maximum propagation depth. Depth 3+ is excluded.
pub const MAX_PROPAGATION_DEPTH: usize = 2;

/// Files at or above this staleness are excluded from propagation
/// (too stale to trust — they'd poison importers with false staleness).
pub const TOMBSTONE_THRESHOLD: f32 = 0.8;

/// Staleness inherited from upstream stale sources via Imports edges.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PropagatedStaleness {
    /// Cascaded staleness value (0.0–1.0). Max across sources, not sum.
    pub value: f32,
    /// Number of upstream source files contributing.
    pub source_count: u32,
    /// Most impactful upstream source (highest single contribution).
    pub primary_source: Option<String>,
}

/// Compute propagated staleness for all files from their upstream imports.
///
/// Takes the full set of Records (for staleness values) and the graph
/// (for Imports edge traversal). Returns a map from `file:<path>` keys
/// to their computed PropagatedStaleness.
pub fn compute_propagation(
    file_records: &[Record],
    graph: &Graph,
) -> HashMap<String, PropagatedStaleness> {
    let mut result: HashMap<String, PropagatedStaleness> = HashMap::new();

    for rec in file_records {
        let source_staleness = rec.staleness.value;

        // Skip below threshold
        if source_staleness < STALE_THRESHOLD {
            continue;
        }
        // Skip tombstoned
        if source_staleness >= TOMBSTONE_THRESHOLD {
            continue;
        }

        let source_key = &rec.key;
        let source_path = rec.key.strip_prefix("file:").unwrap_or(&rec.key);

        // Depth 1: direct importers
        let d1_importers = graph.neighbors_incoming(source_key, &EdgeKind::Imports);
        let d1_bump = source_staleness * PROPAGATION_D1;

        for importer in &d1_importers {
            apply_propagation(&mut result, importer, d1_bump, source_path);
        }

        // Depth 2: importers of importers
        let d1_set: HashSet<&String> = d1_importers.iter().collect();
        let d2_bump = source_staleness * PROPAGATION_D2;

        for d1_importer in &d1_importers {
            let d2_importers = graph.neighbors_incoming(d1_importer, &EdgeKind::Imports);
            for d2_importer in &d2_importers {
                if d2_importer == source_key {
                    continue;
                }
                if d1_set.contains(&d2_importer) {
                    continue;
                }
                apply_propagation(&mut result, d2_importer, d2_bump, source_path);
            }
        }
    }

    result
}

fn apply_propagation(
    result: &mut HashMap<String, PropagatedStaleness>,
    target_key: &str,
    bump: f32,
    source_path: &str,
) {
    let entry = result.entry(target_key.to_string()).or_default();
    entry.source_count += 1;
    if bump > entry.value {
        entry.value = bump;
        entry.primary_source = Some(source_path.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::record::*;
    use crate::store::Store;
    use tempfile::TempDir;

    async fn temp_graph() -> (Graph, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let g = Graph::empty(store);
        (g, dir)
    }

    fn file_record(key: &str, staleness_value: f32) -> Record {
        let now = 1_000_000u64;
        let tier = StalenessScore::tier_from_value(staleness_value);
        Record {
            key: key.to_string(),
            value: String::new(),
            category: Category::File,
            priority: Priority::Normal,
            tags: vec![],
            created_at: now,
            updated_at: now,
            ref_url: None,
            staleness: StalenessScore {
                value: staleness_value,
                tier,
                signals: vec![],
                computed_at: now,
                last_record_sha: String::new(),
            },
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: now,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: None,
        }
    }

    #[tokio::test]
    async fn no_stale_sources_produces_no_propagation() {
        let (g, _dir) = temp_graph().await;
        let records = vec![
            file_record("file:src/a.rs", 0.1),
            file_record("file:src/b.rs", 0.2),
        ];
        let result = compute_propagation(&records, &g);
        assert!(result.is_empty());
        g.close().await.unwrap();
    }

    #[tokio::test]
    async fn stale_source_bumps_direct_importers() {
        let (mut g, _dir) = temp_graph().await;
        // A imports B. B is Stale (0.5).
        g.add_edge("file:src/a.rs", EdgeKind::Imports, "file:src/b.rs")
            .await
            .unwrap();
        let records = vec![
            file_record("file:src/a.rs", 0.0),
            file_record("file:src/b.rs", 0.5),
        ];
        let result = compute_propagation(&records, &g);
        let a = result.get("file:src/a.rs").unwrap();
        let expected = 0.5 * PROPAGATION_D1; // 0.075
        assert!(
            (a.value - expected).abs() < f32::EPSILON,
            "expected {expected}, got {}",
            a.value
        );
        assert_eq!(a.source_count, 1);
        assert_eq!(a.primary_source.as_deref(), Some("src/b.rs"));
        g.close().await.unwrap();
    }

    #[tokio::test]
    async fn tombstoned_source_does_not_propagate() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:src/a.rs", EdgeKind::Imports, "file:src/b.rs")
            .await
            .unwrap();
        let records = vec![
            file_record("file:src/a.rs", 0.0),
            file_record("file:src/b.rs", 0.9), // tombstone range
        ];
        let result = compute_propagation(&records, &g);
        assert!(result.is_empty());
        g.close().await.unwrap();
    }

    #[tokio::test]
    async fn below_threshold_source_does_not_propagate() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:src/a.rs", EdgeKind::Imports, "file:src/b.rs")
            .await
            .unwrap();
        let records = vec![
            file_record("file:src/a.rs", 0.0),
            file_record("file:src/b.rs", 0.3), // below 0.4 threshold
        ];
        let result = compute_propagation(&records, &g);
        assert!(result.is_empty());
        g.close().await.unwrap();
    }

    #[tokio::test]
    async fn depth_2_cascade_uses_smaller_weight() {
        let (mut g, _dir) = temp_graph().await;
        // A imports B, B imports C. C is Stale.
        g.add_edge("file:src/a.rs", EdgeKind::Imports, "file:src/b.rs")
            .await
            .unwrap();
        g.add_edge("file:src/b.rs", EdgeKind::Imports, "file:src/c.rs")
            .await
            .unwrap();
        let records = vec![
            file_record("file:src/a.rs", 0.0),
            file_record("file:src/b.rs", 0.0),
            file_record("file:src/c.rs", 0.6),
        ];
        let result = compute_propagation(&records, &g);
        // B gets d1 bump, A gets d2 bump
        let b = result.get("file:src/b.rs").unwrap();
        assert!((b.value - 0.6 * PROPAGATION_D1).abs() < f32::EPSILON);
        let a = result.get("file:src/a.rs").unwrap();
        assert!((a.value - 0.6 * PROPAGATION_D2).abs() < f32::EPSILON);
        g.close().await.unwrap();
    }

    #[tokio::test]
    async fn depth_3_is_excluded() {
        let (mut g, _dir) = temp_graph().await;
        // A→B→C→D, D is Stale.
        g.add_edge("file:src/a.rs", EdgeKind::Imports, "file:src/b.rs")
            .await
            .unwrap();
        g.add_edge("file:src/b.rs", EdgeKind::Imports, "file:src/c.rs")
            .await
            .unwrap();
        g.add_edge("file:src/c.rs", EdgeKind::Imports, "file:src/d.rs")
            .await
            .unwrap();
        let records = vec![
            file_record("file:src/a.rs", 0.0),
            file_record("file:src/b.rs", 0.0),
            file_record("file:src/c.rs", 0.0),
            file_record("file:src/d.rs", 0.5),
        ];
        let result = compute_propagation(&records, &g);
        // C gets d1, B gets d2, A gets nothing (depth 3)
        assert!(result.contains_key("file:src/c.rs"));
        assert!(result.contains_key("file:src/b.rs"));
        assert!(
            !result.contains_key("file:src/a.rs"),
            "depth 3 should be excluded"
        );
        g.close().await.unwrap();
    }

    #[tokio::test]
    async fn cycle_terminates_safely() {
        let (mut g, _dir) = temp_graph().await;
        // A→B→A, B is Stale.
        g.add_edge("file:src/a.rs", EdgeKind::Imports, "file:src/b.rs")
            .await
            .unwrap();
        g.add_edge("file:src/b.rs", EdgeKind::Imports, "file:src/a.rs")
            .await
            .unwrap();
        let records = vec![
            file_record("file:src/a.rs", 0.0),
            file_record("file:src/b.rs", 0.5),
        ];
        let result = compute_propagation(&records, &g);
        let a = result.get("file:src/a.rs").unwrap();
        assert_eq!(a.source_count, 1);
        assert!((a.value - 0.5 * PROPAGATION_D1).abs() < f32::EPSILON);
        g.close().await.unwrap();
    }

    #[tokio::test]
    async fn multiple_sources_take_max_not_sum() {
        let (mut g, _dir) = temp_graph().await;
        // A imports B and C. Both are Stale.
        g.add_edge("file:src/a.rs", EdgeKind::Imports, "file:src/b.rs")
            .await
            .unwrap();
        g.add_edge("file:src/a.rs", EdgeKind::Imports, "file:src/c.rs")
            .await
            .unwrap();
        let records = vec![
            file_record("file:src/a.rs", 0.0),
            file_record("file:src/b.rs", 0.5),
            file_record("file:src/c.rs", 0.6),
        ];
        let result = compute_propagation(&records, &g);
        let a = result.get("file:src/a.rs").unwrap();
        // Should be max(0.5*0.15, 0.6*0.15) = 0.6*0.15 = 0.09
        let expected = 0.6 * PROPAGATION_D1;
        assert!(
            (a.value - expected).abs() < f32::EPSILON,
            "should take max not sum: expected {expected}, got {}",
            a.value
        );
        g.close().await.unwrap();
    }

    #[tokio::test]
    async fn source_count_increments_for_multiple_sources() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:src/a.rs", EdgeKind::Imports, "file:src/b.rs")
            .await
            .unwrap();
        g.add_edge("file:src/a.rs", EdgeKind::Imports, "file:src/c.rs")
            .await
            .unwrap();
        let records = vec![
            file_record("file:src/a.rs", 0.0),
            file_record("file:src/b.rs", 0.5),
            file_record("file:src/c.rs", 0.6),
        ];
        let result = compute_propagation(&records, &g);
        let a = result.get("file:src/a.rs").unwrap();
        assert_eq!(a.source_count, 2);
        g.close().await.unwrap();
    }

    #[tokio::test]
    async fn primary_source_is_highest_contributor() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:src/a.rs", EdgeKind::Imports, "file:src/b.rs")
            .await
            .unwrap();
        g.add_edge("file:src/a.rs", EdgeKind::Imports, "file:src/c.rs")
            .await
            .unwrap();
        let records = vec![
            file_record("file:src/a.rs", 0.0),
            file_record("file:src/b.rs", 0.5), // bump = 0.075
            file_record("file:src/c.rs", 0.6), // bump = 0.09 — higher
        ];
        let result = compute_propagation(&records, &g);
        let a = result.get("file:src/a.rs").unwrap();
        assert_eq!(a.primary_source.as_deref(), Some("src/c.rs"));
        g.close().await.unwrap();
    }
}
