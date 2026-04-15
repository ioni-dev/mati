//! Blast radius computation for files in the knowledge graph.
//!
//! Measures how many other files depend on a given file (directly or
//! transitively) via `Imports` edges. Higher blast radius means changes
//! to the file have wider impact and warrant extra review care.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::graph::edges::EdgeKind;
use crate::graph::graph::Graph;

/// Weight applied to transitive importers when computing the blast score.
/// Direct importers contribute 1.0, transitive importers contribute this much.
pub const TRANSITIVE_WEIGHT: f32 = 0.3;

/// Maximum depth for transitive import traversal.
pub const TRANSITIVE_DEPTH: usize = 3;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlastRadius {
    /// Number of files that directly import this file (1 hop via Imports edges).
    pub direct: u32,

    /// Number of files that transitively import this file within TRANSITIVE_DEPTH,
    /// excluding direct importers. Deduplicated across all paths.
    pub transitive: u32,

    /// Weighted score: direct + (transitive * TRANSITIVE_WEIGHT).
    /// Higher means more dangerous to modify.
    pub score: f32,

    /// Categorical tier for agent-friendly consumption.
    pub tier: BlastTier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlastTier {
    /// No files import this file. Safe to modify in isolation.
    Isolated,
    /// 1-5 direct importers. Modest blast radius.
    Low,
    /// 6-15 direct importers. Noticeable impact on changes.
    Moderate,
    /// 16-40 direct importers. High impact file.
    High,
    /// 40+ direct importers. Critical infrastructure file.
    Critical,
}

impl BlastTier {
    pub fn from_direct_count(direct: u32) -> Self {
        match direct {
            0 => Self::Isolated,
            1..=5 => Self::Low,
            6..=15 => Self::Moderate,
            16..=40 => Self::High,
            _ => Self::Critical,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Isolated => "isolated",
            Self::Low => "low",
            Self::Moderate => "moderate",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl BlastRadius {
    /// Compute blast radius for a single file given the graph.
    ///
    /// Uses `neighbors_incoming` with `EdgeKind::Imports` at depth 1 for direct
    /// count, and `traverse_incoming` at `TRANSITIVE_DEPTH` for the full
    /// transitive set. Transitive count excludes direct importers.
    ///
    /// Prefer [`compute_all`] for batch computation — it's O(V+E) total
    /// vs O(N*(V+E)) when calling this in a loop.
    pub fn compute(file_key: &str, graph: &Graph) -> Self {
        let direct_set: HashSet<String> = graph
            .neighbors_incoming(file_key, &EdgeKind::Imports)
            .into_iter()
            .collect();

        let all_ancestors: HashSet<String> = graph
            .traverse_incoming(file_key, &EdgeKind::Imports, TRANSITIVE_DEPTH)
            .into_iter()
            .collect();

        let direct = direct_set.len() as u32;
        let transitive = all_ancestors.difference(&direct_set).count() as u32;

        let score = direct as f32 + (transitive as f32 * TRANSITIVE_WEIGHT);
        let tier = BlastTier::from_direct_count(direct);

        Self {
            direct,
            transitive,
            score,
            tier,
        }
    }

    /// Compute blast radius for every file in the graph in a single pass.
    ///
    /// Returns a map from `file:<path>` keys to their `BlastRadius`.
    /// Pre-computes the reverse adjacency list once, then runs bounded BFS
    /// per node. This avoids repeated `edges_directed` lookups in petgraph,
    /// reducing constant factors significantly on large graphs.
    pub fn compute_all(graph: &Graph, file_keys: &[String]) -> HashMap<String, BlastRadius> {
        // Pre-compute reverse adjacency list: for each node, who imports it?
        let reverse_adj = graph.reverse_adjacency(&EdgeKind::Imports);
        let mut result = HashMap::with_capacity(file_keys.len());

        for file_key in file_keys {
            let direct_vec = reverse_adj
                .get(file_key.as_str())
                .cloned()
                .unwrap_or_default();
            let direct_set: HashSet<&str> = direct_vec.iter().map(|s| s.as_str()).collect();

            // BFS for transitive ancestors at depth 2..=TRANSITIVE_DEPTH
            let mut all_ancestors: HashSet<&str> = HashSet::new();
            all_ancestors.extend(direct_set.iter());

            let mut frontier: Vec<&str> = direct_vec.iter().map(|s| s.as_str()).collect();
            for _depth in 1..TRANSITIVE_DEPTH {
                let mut next_frontier = Vec::new();
                for node in &frontier {
                    if let Some(parents) = reverse_adj.get(*node) {
                        for p in parents {
                            if all_ancestors.insert(p.as_str()) {
                                next_frontier.push(p.as_str());
                            }
                        }
                    }
                }
                if next_frontier.is_empty() {
                    break;
                }
                frontier = next_frontier;
            }

            let direct = direct_set.len() as u32;
            let transitive = (all_ancestors.len() - direct_set.len()) as u32;
            let score = direct as f32 + (transitive as f32 * TRANSITIVE_WEIGHT);
            let tier = BlastTier::from_direct_count(direct);

            result.insert(
                file_key.clone(),
                BlastRadius {
                    direct,
                    transitive,
                    score,
                    tier,
                },
            );
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::Graph;
    use crate::store::Store;
    use tempfile::TempDir;

    async fn temp_graph() -> (Graph, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let g = Graph::empty(store);
        (g, dir)
    }

    // ── BlastTier::from_direct_count boundary tests ──────────────────────────

    #[test]
    fn tier_isolated_at_zero() {
        assert_eq!(BlastTier::from_direct_count(0), BlastTier::Isolated);
    }

    #[test]
    fn tier_low_at_one() {
        assert_eq!(BlastTier::from_direct_count(1), BlastTier::Low);
    }

    #[test]
    fn tier_low_at_five() {
        assert_eq!(BlastTier::from_direct_count(5), BlastTier::Low);
    }

    #[test]
    fn tier_moderate_at_six() {
        assert_eq!(BlastTier::from_direct_count(6), BlastTier::Moderate);
    }

    #[test]
    fn tier_moderate_at_fifteen() {
        assert_eq!(BlastTier::from_direct_count(15), BlastTier::Moderate);
    }

    #[test]
    fn tier_high_at_sixteen() {
        assert_eq!(BlastTier::from_direct_count(16), BlastTier::High);
    }

    #[test]
    fn tier_high_at_forty() {
        assert_eq!(BlastTier::from_direct_count(40), BlastTier::High);
    }

    #[test]
    fn tier_critical_at_forty_one() {
        assert_eq!(BlastTier::from_direct_count(41), BlastTier::Critical);
    }

    // ── BlastRadius::compute tests ───────────────────────────────────────────

    /// A imports B, C imports B, D imports B → B has direct=3, transitive=0.
    #[tokio::test]
    async fn compute_three_direct_importers() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports, "file:b")
            .await
            .unwrap();
        g.add_edge("file:c", EdgeKind::Imports, "file:b")
            .await
            .unwrap();
        g.add_edge("file:d", EdgeKind::Imports, "file:b")
            .await
            .unwrap();

        let br = BlastRadius::compute("file:b", &g);
        assert_eq!(br.direct, 3);
        assert_eq!(br.transitive, 0);
        assert_eq!(br.tier, BlastTier::Low);
        assert!((br.score - 3.0).abs() < f32::EPSILON);

        g.close().await.unwrap();
    }

    /// Chain A→B→C→D: C has direct=1 (B), transitive=1 (A).
    #[tokio::test]
    async fn compute_chain_one_direct_one_transitive() {
        let (mut g, _dir) = temp_graph().await;
        // A imports B, B imports C, C imports D
        g.add_edge("file:a", EdgeKind::Imports, "file:b")
            .await
            .unwrap();
        g.add_edge("file:b", EdgeKind::Imports, "file:c")
            .await
            .unwrap();
        g.add_edge("file:c", EdgeKind::Imports, "file:d")
            .await
            .unwrap();

        // Who imports C? B directly, A transitively.
        let br = BlastRadius::compute("file:c", &g);
        assert_eq!(br.direct, 1); // B
        assert_eq!(br.transitive, 1); // A
        assert_eq!(br.tier, BlastTier::Low);
        let expected_score = 1.0 + (1.0 * TRANSITIVE_WEIGHT);
        assert!((br.score - expected_score).abs() < f32::EPSILON);

        g.close().await.unwrap();
    }

    /// File with no incoming imports → isolated.
    #[tokio::test]
    async fn compute_no_importers_is_isolated() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports, "file:b")
            .await
            .unwrap();

        // file:a has no incoming imports
        let br = BlastRadius::compute("file:a", &g);
        assert_eq!(br.direct, 0);
        assert_eq!(br.transitive, 0);
        assert_eq!(br.tier, BlastTier::Isolated);
        assert!((br.score - 0.0).abs() < f32::EPSILON);

        g.close().await.unwrap();
    }

    /// Cycle A→B→A must terminate without double-counting.
    #[tokio::test]
    async fn compute_cycle_terminates() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports, "file:b")
            .await
            .unwrap();
        g.add_edge("file:b", EdgeKind::Imports, "file:a")
            .await
            .unwrap();

        let br_a = BlastRadius::compute("file:a", &g);
        assert_eq!(br_a.direct, 1); // B imports A
                                    // B is direct; no transitive beyond that in a 2-node cycle
        assert_eq!(br_a.tier, BlastTier::Low);

        let br_b = BlastRadius::compute("file:b", &g);
        assert_eq!(br_b.direct, 1); // A imports B

        g.close().await.unwrap();
    }

    /// File 5 hops away must NOT appear in transitive count (depth cap = 3).
    #[tokio::test]
    async fn compute_depth_cap_excludes_distant_file() {
        let (mut g, _dir) = temp_graph().await;
        // Chain: e → d → c → b → a (reading as "e imports d", etc.)
        g.add_edge("file:e", EdgeKind::Imports, "file:d")
            .await
            .unwrap();
        g.add_edge("file:d", EdgeKind::Imports, "file:c")
            .await
            .unwrap();
        g.add_edge("file:c", EdgeKind::Imports, "file:b")
            .await
            .unwrap();
        g.add_edge("file:b", EdgeKind::Imports, "file:a")
            .await
            .unwrap();

        // Who imports file:a?
        // Direct (depth 1): b
        // Transitive (depth 2-3): c, d
        // Beyond depth 3: e — should NOT be counted
        let br = BlastRadius::compute("file:a", &g);
        assert_eq!(br.direct, 1); // b
                                  // traverse_incoming at depth 3 returns b, c, d (3 nodes)
                                  // minus direct (b) = 2 transitive
        assert_eq!(br.transitive, 2); // c, d — but NOT e
        assert_eq!(br.tier, BlastTier::Low);

        g.close().await.unwrap();
    }

    /// Diamond: a→c, b→c, a→d, d→c — c reachable from a via two paths, counted once.
    #[tokio::test]
    async fn compute_deduplication_across_paths() {
        let (mut g, _dir) = temp_graph().await;
        // a imports c (direct)
        g.add_edge("file:a", EdgeKind::Imports, "file:c")
            .await
            .unwrap();
        // b imports c (direct)
        g.add_edge("file:b", EdgeKind::Imports, "file:c")
            .await
            .unwrap();
        // d imports c (direct)
        g.add_edge("file:d", EdgeKind::Imports, "file:c")
            .await
            .unwrap();
        // a also imports d (so a reaches c via two paths)
        g.add_edge("file:a", EdgeKind::Imports, "file:d")
            .await
            .unwrap();

        let br = BlastRadius::compute("file:c", &g);
        // Direct importers of c: a, b, d
        assert_eq!(br.direct, 3);
        // a is already counted as direct — no extra transitive
        assert_eq!(br.transitive, 0);
        assert_eq!(br.tier, BlastTier::Low);

        g.close().await.unwrap();
    }

    /// Unknown file key returns isolated (score 0).
    #[tokio::test]
    async fn compute_unknown_file_is_isolated() {
        let (g, _dir) = temp_graph().await;

        let br = BlastRadius::compute("file:nonexistent", &g);
        assert_eq!(br.direct, 0);
        assert_eq!(br.transitive, 0);
        assert_eq!(br.tier, BlastTier::Isolated);
        assert!((br.score - 0.0).abs() < f32::EPSILON);

        g.close().await.unwrap();
    }

    /// Serde roundtrip preserves all fields.
    #[test]
    fn serde_roundtrip() {
        let br = BlastRadius {
            direct: 7,
            transitive: 3,
            score: 7.9,
            tier: BlastTier::Moderate,
        };
        let json = serde_json::to_string(&br).unwrap();
        let back: BlastRadius = serde_json::from_str(&json).unwrap();
        assert_eq!(br, back);
    }

    /// All tier labels are lowercase and match serde rename.
    #[test]
    fn tier_labels_match_serde() {
        let tiers = [
            BlastTier::Isolated,
            BlastTier::Low,
            BlastTier::Moderate,
            BlastTier::High,
            BlastTier::Critical,
        ];
        for tier in tiers {
            let json = serde_json::to_string(&tier).unwrap();
            let label = tier.label();
            assert_eq!(json, format!("\"{label}\""));
        }
    }

    // ── compute_all tests ────────────────────────────────────────────────────

    /// compute_all matches per-file compute on the same graph.
    #[tokio::test]
    async fn compute_all_matches_per_file_compute() {
        let (mut g, _dir) = temp_graph().await;
        // a→b, b→c, c→d
        g.add_edge("file:a", EdgeKind::Imports, "file:b")
            .await
            .unwrap();
        g.add_edge("file:b", EdgeKind::Imports, "file:c")
            .await
            .unwrap();
        g.add_edge("file:c", EdgeKind::Imports, "file:d")
            .await
            .unwrap();

        let keys: Vec<String> = ["file:a", "file:b", "file:c", "file:d"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let batch = BlastRadius::compute_all(&g, &keys);
        for key in &keys {
            let single = BlastRadius::compute(key, &g);
            let from_batch = batch.get(key).expect("key missing from compute_all");
            assert_eq!(
                single.direct, from_batch.direct,
                "direct mismatch for {key}"
            );
            assert_eq!(
                single.transitive, from_batch.transitive,
                "transitive mismatch for {key}"
            );
        }

        g.close().await.unwrap();
    }

    /// compute_all handles cycles without infinite recursion.
    #[tokio::test]
    async fn compute_all_handles_cycle_safely() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports, "file:b")
            .await
            .unwrap();
        g.add_edge("file:b", EdgeKind::Imports, "file:a")
            .await
            .unwrap();

        let keys = vec!["file:a".to_string(), "file:b".to_string()];
        let batch = BlastRadius::compute_all(&g, &keys);

        let br_a = batch.get("file:a").unwrap();
        let br_b = batch.get("file:b").unwrap();
        assert_eq!(br_a.direct, 1);
        assert_eq!(br_b.direct, 1);

        // Verify matches single-file compute
        let single_a = BlastRadius::compute("file:a", &g);
        let single_b = BlastRadius::compute("file:b", &g);
        assert_eq!(br_a.direct, single_a.direct);
        assert_eq!(br_b.direct, single_b.direct);

        g.close().await.unwrap();
    }

    /// compute_all on empty graph returns empty map.
    #[tokio::test]
    async fn compute_all_on_empty_graph_returns_empty_map() {
        let (g, _dir) = temp_graph().await;
        let batch = BlastRadius::compute_all(&g, &[]);
        assert!(batch.is_empty());
        g.close().await.unwrap();
    }

    /// Deserialization of BlastRadius with default (missing field in parent).
    #[test]
    fn deserialize_optional_blast_radius() {
        let val: Option<BlastRadius> = serde_json::from_str("null").unwrap();
        assert!(val.is_none());

        let val: BlastRadius =
            serde_json::from_str(r#"{"direct":0,"transitive":0,"score":0.0,"tier":"isolated"}"#)
                .unwrap();
        assert_eq!(val.tier, BlastTier::Isolated);
    }
}
