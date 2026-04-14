//! Co-change cluster detection from git history.
//!
//! Discovers logical modules by running connected-components over co-change
//! pairs. Files that frequently change together form clusters, regardless of
//! directory structure. Uses union-find over filtered pairs — simpler and more
//! transparent than petgraph's SCC algorithms for undirected, weighted edges.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Minimum raw co-change count for a pair to count toward cluster formation.
/// Below this, pairs are treated as noise even if they passed the 0.70
/// correlation threshold in `mine_git_history`.
pub const MIN_COCHANGE_COUNT: u32 = 5;

/// A co-change cluster discovered from git history.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cluster {
    /// Stable identifier derived from the centroid file name.
    pub id: String,
    /// Human-readable label from shared directory prefix or centroid stem.
    pub label: String,
    /// File paths (not keys) belonging to this cluster. Sorted.
    pub members: Vec<String>,
    /// Graph density: edges_in_cluster / max_possible_edges. Range 0.0–1.0.
    pub cohesion: f32,
    /// File with highest intra-cluster degree.
    pub centroid: String,
    /// Number of members.
    pub size: u32,
}

/// Full cluster index for a repository. Cached under key `cluster:index`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterIndex {
    /// Clusters of size >= 2, sorted by size descending.
    pub clusters: Vec<Cluster>,
    /// Total cluster count.
    pub total: u32,
    /// Files belonging to at least one cluster.
    pub clustered_files: u32,
    /// Files with no co-change neighbors meeting the threshold.
    pub isolated_files: u32,
}

impl ClusterIndex {
    /// Compute cluster index from co-change pairs (with raw counts).
    ///
    /// `co_change_pairs` are `(path_a, path_b, count)` with `a < b`, already
    /// filtered by the 0.70 correlation threshold. This function applies the
    /// additional `MIN_COCHANGE_COUNT` filter for cluster formation.
    ///
    /// `total_files` is the total file count for computing `isolated_files`.
    pub fn compute(co_change_pairs: &[(String, String, u32)], total_files: usize) -> Self {
        // Filter pairs by minimum count.
        let strong_pairs: Vec<&(String, String, u32)> = co_change_pairs
            .iter()
            .filter(|(_, _, count)| *count >= MIN_COCHANGE_COUNT)
            .collect();

        if strong_pairs.is_empty() {
            return ClusterIndex {
                clusters: vec![],
                total: 0,
                clustered_files: 0,
                isolated_files: total_files as u32,
            };
        }

        // Collect all nodes that participate in strong pairs.
        let mut all_nodes: HashSet<&str> = HashSet::new();
        for (a, b, _) in &strong_pairs {
            all_nodes.insert(a.as_str());
            all_nodes.insert(b.as_str());
        }

        // Assign indices to nodes for union-find.
        let node_list: Vec<&str> = all_nodes.into_iter().collect();
        let node_to_idx: HashMap<&str, usize> =
            node_list.iter().enumerate().map(|(i, &n)| (n, i)).collect();

        // Union-find.
        let mut parent: Vec<usize> = (0..node_list.len()).collect();
        let mut rank: Vec<usize> = vec![0; node_list.len()];

        fn find(parent: &mut [usize], x: usize) -> usize {
            if parent[x] != x {
                parent[x] = find(parent, parent[x]);
            }
            parent[x]
        }

        fn union(parent: &mut [usize], rank: &mut [usize], a: usize, b: usize) {
            let ra = find(parent, a);
            let rb = find(parent, b);
            if ra == rb {
                return;
            }
            if rank[ra] < rank[rb] {
                parent[ra] = rb;
            } else if rank[ra] > rank[rb] {
                parent[rb] = ra;
            } else {
                parent[rb] = ra;
                rank[ra] += 1;
            }
        }

        for (a, b, _) in &strong_pairs {
            let ia = node_to_idx[a.as_str()];
            let ib = node_to_idx[b.as_str()];
            union(&mut parent, &mut rank, ia, ib);
        }

        // Group nodes by component root.
        let mut components: HashMap<usize, Vec<&str>> = HashMap::new();
        for (i, &node) in node_list.iter().enumerate() {
            let root = find(&mut parent, i);
            components.entry(root).or_default().push(node);
        }

        // Build edge set for cohesion and degree computation.
        let edge_set: HashSet<(&str, &str)> = strong_pairs
            .iter()
            .map(|(a, b, _)| (a.as_str(), b.as_str()))
            .collect();

        // Build clusters from components with size >= 2.
        let mut clusters: Vec<Cluster> = components
            .into_values()
            .filter(|members| members.len() >= 2)
            .map(|mut members| {
                members.sort();
                let member_set: HashSet<&str> = members.iter().copied().collect();
                let n = members.len();

                // Count intra-cluster edges.
                let mut intra_edges = 0u32;
                let mut degree: HashMap<&str, u32> = HashMap::new();
                for &(a, b) in &edge_set {
                    if member_set.contains(a) && member_set.contains(b) {
                        intra_edges += 1;
                        *degree.entry(a).or_default() += 1;
                        *degree.entry(b).or_default() += 1;
                    }
                }

                // Cohesion = edges / max_possible_edges (undirected).
                let max_edges = (n * (n - 1) / 2) as f32;
                let cohesion = if max_edges > 0.0 {
                    intra_edges as f32 / max_edges
                } else {
                    0.0
                };

                // Centroid = member with highest degree.
                let centroid = members
                    .iter()
                    .max_by_key(|&&m| degree.get(m).copied().unwrap_or(0))
                    .copied()
                    .unwrap_or(members[0]);

                let label = compute_label(&members, centroid);
                let id = stem(centroid);
                let centroid_owned = centroid.to_string();

                Cluster {
                    id,
                    label,
                    members: members.into_iter().map(String::from).collect(),
                    cohesion,
                    centroid: centroid_owned,
                    size: n as u32,
                }
            })
            .collect();

        // Sort by size descending, then by label for stability.
        clusters.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.label.cmp(&b.label)));

        // Disambiguate duplicate labels. If two or more clusters share a
        // directory-based label, suffix each except the first (largest) with
        // its centroid's filename stem. The largest keeps the clean label.
        {
            let mut label_counts: HashMap<String, u32> = HashMap::new();
            for cluster in &clusters {
                *label_counts.entry(cluster.label.clone()).or_insert(0) += 1;
            }

            let mut seen: HashMap<String, u32> = HashMap::new();
            for cluster in clusters.iter_mut() {
                let total = *label_counts.get(&cluster.label).unwrap_or(&0);
                if total > 1 {
                    let count = seen.entry(cluster.label.clone()).or_insert(0);
                    if *count > 0 {
                        cluster.label = format!("{} ({})", cluster.label, stem(&cluster.centroid));
                    }
                    *count += 1;
                }
            }
        }

        let clustered_files: u32 = clusters.iter().map(|c| c.size).sum();
        let total = clusters.len() as u32;
        let isolated_files = total_files.saturating_sub(clustered_files as usize) as u32;

        ClusterIndex {
            clusters,
            total,
            clustered_files,
            isolated_files,
        }
    }

    /// Return the cluster containing the given file path, if any.
    pub fn cluster_for(&self, file_path: &str) -> Option<&Cluster> {
        self.clusters
            .iter()
            .find(|c| c.members.iter().any(|m| m == file_path))
    }
}

/// Compute a human-readable label for a cluster.
///
/// Priority:
/// 1. Shared directory prefix of >= 2 segments → last segment
/// 2. Single shared root segment → centroid stem
/// 3. No shared prefix → centroid stem
fn compute_label(members: &[&str], centroid: &str) -> String {
    if members.len() < 2 {
        return stem(centroid);
    }

    // Split each member into path segments.
    let segments: Vec<Vec<&str>> = members
        .iter()
        .map(|m| m.split('/').collect::<Vec<_>>())
        .collect();

    // Find common prefix length.
    let min_len = segments.iter().map(|s| s.len()).min().unwrap_or(0);
    let mut prefix_len = 0;
    for i in 0..min_len {
        if segments.iter().all(|s| s[i] == segments[0][i]) {
            prefix_len = i + 1;
        } else {
            break;
        }
    }

    // Need at least 2 common segments for a meaningful prefix label.
    if prefix_len >= 2 {
        segments[0][prefix_len - 1].to_string()
    } else {
        stem(centroid)
    }
}

/// Extract filename stem (without extension) from a path.
fn stem(path: &str) -> String {
    std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(data: &[(&str, &str, u32)]) -> Vec<(String, String, u32)> {
        data.iter()
            .map(|(a, b, c)| (a.to_string(), b.to_string(), *c))
            .collect()
    }

    #[test]
    fn empty_pairs_produce_empty_index() {
        let idx = ClusterIndex::compute(&[], 10);
        assert_eq!(idx.total, 0);
        assert!(idx.clusters.is_empty());
        assert_eq!(idx.isolated_files, 10);
        assert_eq!(idx.clustered_files, 0);
    }

    #[test]
    fn pairs_below_threshold_produce_no_clusters() {
        let p = pairs(&[("src/a.rs", "src/b.rs", 3)]); // count=3 < MIN_COCHANGE_COUNT=5
        let idx = ClusterIndex::compute(&p, 5);
        assert_eq!(idx.total, 0);
        assert!(idx.clusters.is_empty());
    }

    #[test]
    fn triangle_forms_one_cluster_with_full_cohesion() {
        let p = pairs(&[
            ("src/a.rs", "src/b.rs", 10),
            ("src/b.rs", "src/c.rs", 8),
            ("src/a.rs", "src/c.rs", 7),
        ]);
        let idx = ClusterIndex::compute(&p, 5);
        assert_eq!(idx.total, 1);
        assert_eq!(idx.clusters[0].size, 3);
        assert!(
            (idx.clusters[0].cohesion - 1.0).abs() < f32::EPSILON,
            "triangle should have cohesion 1.0, got {}",
            idx.clusters[0].cohesion
        );
    }

    #[test]
    fn two_disjoint_pairs_form_two_clusters() {
        let p = pairs(&[("src/a.rs", "src/b.rs", 10), ("src/c.rs", "src/d.rs", 8)]);
        let idx = ClusterIndex::compute(&p, 10);
        assert_eq!(idx.total, 2);
        assert_eq!(idx.clusters[0].size, 2);
        assert_eq!(idx.clusters[1].size, 2);
        assert_eq!(idx.clustered_files, 4);
        assert_eq!(idx.isolated_files, 6);
    }

    #[test]
    fn chain_of_four_forms_one_cluster_with_partial_cohesion() {
        // A-B, B-C, C-D → 1 component of 4 nodes, 3 edges, max=6
        let p = pairs(&[
            ("src/a.rs", "src/b.rs", 10),
            ("src/b.rs", "src/c.rs", 8),
            ("src/c.rs", "src/d.rs", 7),
        ]);
        let idx = ClusterIndex::compute(&p, 4);
        assert_eq!(idx.total, 1);
        assert_eq!(idx.clusters[0].size, 4);
        let expected_cohesion = 3.0 / 6.0; // 3 edges out of max 6
        assert!(
            (idx.clusters[0].cohesion - expected_cohesion).abs() < f32::EPSILON,
            "chain of 4 should have cohesion 0.5, got {}",
            idx.clusters[0].cohesion
        );
    }

    #[test]
    fn edge_below_min_count_excluded() {
        let p = pairs(&[
            ("src/a.rs", "src/b.rs", 10), // above threshold
            ("src/b.rs", "src/c.rs", 3),  // below MIN_COCHANGE_COUNT
        ]);
        let idx = ClusterIndex::compute(&p, 5);
        // Only A-B qualifies → 1 cluster of size 2, C is isolated
        assert_eq!(idx.total, 1);
        assert_eq!(idx.clusters[0].size, 2);
        assert!(idx.clusters[0].members.contains(&"src/a.rs".to_string()));
        assert!(idx.clusters[0].members.contains(&"src/b.rs".to_string()));
    }

    #[test]
    fn shared_directory_prefix_produces_label() {
        let p = pairs(&[
            ("src/auth/session.rs", "src/auth/tokens.rs", 10),
            ("src/auth/tokens.rs", "src/auth/middleware.rs", 8),
        ]);
        let idx = ClusterIndex::compute(&p, 5);
        assert_eq!(idx.clusters[0].label, "auth");
    }

    #[test]
    fn no_shared_prefix_uses_centroid_stem() {
        let p = pairs(&[
            ("src/store/record.rs", "src/mcp/tools.rs", 10),
            ("src/mcp/tools.rs", "src/cli/init.rs", 8),
        ]);
        let idx = ClusterIndex::compute(&p, 5);
        // No 2-segment common prefix → label is centroid stem
        // tools.rs has degree 2 (connected to both), so it's the centroid
        assert_eq!(idx.clusters[0].label, "tools");
    }

    #[test]
    fn singleton_not_in_any_cluster() {
        let p = pairs(&[("src/a.rs", "src/b.rs", 10)]);
        let idx = ClusterIndex::compute(&p, 5);
        assert!(idx.cluster_for("src/c.rs").is_none());
        assert_eq!(idx.isolated_files, 3); // 5 total - 2 clustered = 3
    }

    #[test]
    fn centroid_is_highest_degree_member() {
        // a connects to b, c, d → degree 3. Others have degree 1.
        let p = pairs(&[
            ("src/a.rs", "src/b.rs", 10),
            ("src/a.rs", "src/c.rs", 8),
            ("src/a.rs", "src/d.rs", 7),
        ]);
        let idx = ClusterIndex::compute(&p, 4);
        assert_eq!(idx.clusters[0].centroid, "src/a.rs");
    }

    #[test]
    fn cohesion_triangle_is_one() {
        let p = pairs(&[
            ("src/x.rs", "src/y.rs", 10),
            ("src/y.rs", "src/z.rs", 10),
            ("src/x.rs", "src/z.rs", 10),
        ]);
        let idx = ClusterIndex::compute(&p, 3);
        // 3 edges, max = 3*(3-1)/2 = 3 → cohesion = 1.0
        assert!((idx.clusters[0].cohesion - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn cohesion_chain_of_four_is_half() {
        let p = pairs(&[
            ("src/a.rs", "src/b.rs", 10),
            ("src/b.rs", "src/c.rs", 10),
            ("src/c.rs", "src/d.rs", 10),
        ]);
        let idx = ClusterIndex::compute(&p, 4);
        // 3 edges, max = 4*3/2 = 6 → cohesion = 0.5
        assert!((idx.clusters[0].cohesion - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn cluster_for_returns_correct_cluster() {
        let p = pairs(&[("src/a.rs", "src/b.rs", 10), ("src/c.rs", "src/d.rs", 8)]);
        let idx = ClusterIndex::compute(&p, 4);
        let c = idx.cluster_for("src/a.rs").unwrap();
        assert!(c.members.contains(&"src/a.rs".to_string()));
        assert!(c.members.contains(&"src/b.rs".to_string()));

        let c2 = idx.cluster_for("src/d.rs").unwrap();
        assert!(c2.members.contains(&"src/c.rs".to_string()));
    }

    #[test]
    fn clusters_sorted_by_size_descending() {
        let p = pairs(&[
            // Cluster 1: 3 files
            ("src/a.rs", "src/b.rs", 10),
            ("src/b.rs", "src/c.rs", 8),
            // Cluster 2: 2 files
            ("src/x.rs", "src/y.rs", 7),
        ]);
        let idx = ClusterIndex::compute(&p, 10);
        assert_eq!(idx.clusters[0].size, 3);
        assert_eq!(idx.clusters[1].size, 2);
    }

    #[test]
    fn serde_roundtrip() {
        let p = pairs(&[("src/a.rs", "src/b.rs", 10)]);
        let idx = ClusterIndex::compute(&p, 5);
        let json = serde_json::to_string(&idx).unwrap();
        let back: ClusterIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(idx.clusters.len(), back.clusters.len());
        assert_eq!(idx.total, back.total);
    }

    // ── Label disambiguation tests ──────────────────────────────────────────

    #[test]
    fn label_disambiguation_two_clusters_same_prefix() {
        // Two disconnected clusters in src/cli/ — both get label "cli".
        // The larger one keeps "cli", the smaller becomes "cli (centroid_stem)".
        let p = pairs(&[
            // Cluster 1: 3 files in cli/
            ("src/cli/init.rs", "src/cli/explain.rs", 10),
            ("src/cli/explain.rs", "src/cli/review.rs", 8),
            // Cluster 2: 2 files in cli/ (disconnected from cluster 1)
            ("src/cli/stats.rs", "src/cli/status.rs", 12),
        ]);
        let idx = ClusterIndex::compute(&p, 10);
        assert_eq!(idx.total, 2);
        // First (larger) keeps clean label
        assert_eq!(idx.clusters[0].label, "cli");
        assert_eq!(idx.clusters[0].size, 3);
        // Second gets disambiguated
        assert!(
            idx.clusters[1].label.starts_with("cli ("),
            "second cluster should be disambiguated, got: {}",
            idx.clusters[1].label
        );
    }

    #[test]
    fn label_disambiguation_three_clusters_same_prefix() {
        let p = pairs(&[
            // Cluster 1: 3 files
            ("src/cli/init.rs", "src/cli/explain.rs", 10),
            ("src/cli/explain.rs", "src/cli/review.rs", 8),
            // Cluster 2: 2 files
            ("src/cli/stats.rs", "src/cli/status.rs", 12),
            // Cluster 3: 2 files
            ("src/cli/gaps.rs", "src/cli/stale.rs", 7),
        ]);
        let idx = ClusterIndex::compute(&p, 10);
        assert_eq!(idx.total, 3);
        assert_eq!(idx.clusters[0].label, "cli");
        // Both second and third are disambiguated
        assert!(idx.clusters[1].label.starts_with("cli ("));
        assert!(idx.clusters[2].label.starts_with("cli ("));
        // And they're distinct from each other
        assert_ne!(idx.clusters[1].label, idx.clusters[2].label);
    }

    #[test]
    fn label_no_collision_stays_clean() {
        let p = pairs(&[
            ("src/cli/init.rs", "src/cli/explain.rs", 10),
            ("src/analysis/parser.rs", "src/analysis/walker.rs", 8),
        ]);
        let idx = ClusterIndex::compute(&p, 10);
        assert_eq!(idx.total, 2);
        // No collisions — both keep clean labels
        let labels: Vec<&str> = idx.clusters.iter().map(|c| c.label.as_str()).collect();
        assert!(labels.contains(&"cli"));
        assert!(labels.contains(&"analysis"));
    }

    #[test]
    fn label_disambiguation_preserves_cluster_id() {
        let p = pairs(&[
            ("src/cli/init.rs", "src/cli/explain.rs", 10),
            ("src/cli/stats.rs", "src/cli/status.rs", 12),
        ]);
        let idx = ClusterIndex::compute(&p, 10);
        // IDs are derived from centroids, not labels — must remain stable
        for c in &idx.clusters {
            assert!(
                !c.id.contains(' ') && !c.id.contains('('),
                "cluster id should not be disambiguated: {}",
                c.id
            );
        }
    }

    #[test]
    fn label_disambiguation_handles_weird_centroid_names() {
        // Files without extension or with unusual names
        let p = pairs(&[
            ("src/cli/Makefile", "src/cli/Dockerfile", 10),
            ("src/cli/init.rs", "src/cli/explain.rs", 8),
        ]);
        let idx = ClusterIndex::compute(&p, 10);
        // Should not panic, and both clusters have labels
        for c in &idx.clusters {
            assert!(!c.label.is_empty(), "label must not be empty");
        }
    }
}
