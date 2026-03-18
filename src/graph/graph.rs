use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use crate::store::Store;
use super::edges::{Edge, EdgeKind};

const EDGE_PREFIX: &str = "graph:edge:";

/// In-memory directed knowledge graph backed by SurrealKV.
///
/// Loaded at session start by scanning all `graph:edge:*` keys.
/// Every mutation writes through to SurrealKV immediately — no edges are lost
/// on restart. Traversal is fully in-memory (<1 ms).
pub struct Graph {
    /// petgraph directed graph. Node weights are namespaced record keys.
    inner: DiGraph<String, EdgeKind>,
    /// Maps a record key → its NodeIndex for O(1) lookup.
    node_index: HashMap<String, NodeIndex>,
    /// Tracks existing (from, kind, to) triples for O(1) duplicate detection.
    /// Avoids an O(E) scan on every `insert_edge_in_memory` call.
    edge_set: HashSet<(NodeIndex, NodeIndex, EdgeKind)>,
    /// Handle to the store for write-through persistence. Private — callers
    /// must go through Graph methods to keep in-memory and persisted state in sync.
    store: Store,
}

impl Graph {
    /// Load the full graph from SurrealKV by scanning `graph:edge:*`.
    pub async fn load(store: Store) -> Result<Self> {
        let keys = store.scan_keys(EDGE_PREFIX).await?;
        // Pre-size all collections to avoid incremental resizes during bulk insert.
        // Each edge connects 2 nodes; upper bound is 2 × edge count unique nodes.
        let n_edges = keys.len();
        let n_nodes = n_edges * 2;
        let mut g = Graph {
            inner: DiGraph::with_capacity(n_nodes, n_edges),
            node_index: HashMap::with_capacity(n_nodes),
            edge_set: HashSet::with_capacity(n_edges),
            store,
        };
        for key in keys {
            if let Some(edge) = Edge::from_key(&key) {
                g.insert_edge_in_memory(&edge);
            }
        }
        Ok(g)
    }

    /// Add an edge and persist it to SurrealKV. Idempotent — skips the store
    /// write entirely if the edge already exists in the in-memory set.
    pub async fn add_edge(&mut self, from: &str, kind: EdgeKind, to: &str) -> Result<()> {
        let edge = Edge::new(from, kind, to);
        // Check before persisting: if both nodes exist and the edge is already
        // in the set, skip the store write. Avoids bumping updated_at on every
        // duplicate call and prevents unnecessary fsync on hot paths.
        if let (Some(&fi), Some(&ti)) = (
            self.node_index.get(&edge.from),
            self.node_index.get(&edge.to),
        ) {
            if self.edge_set.contains(&(fi, ti, edge.kind.clone())) {
                return Ok(());
            }
        }
        persist_edge(&self.store, &edge).await?;
        self.insert_edge_in_memory(&edge);
        Ok(())
    }

    /// Add many edges in a single SurrealKV transaction (1 fsync for the whole
    /// batch). Use this for Layer 0 bulk inserts — never call `add_edge` in a
    /// loop for large graphs.
    ///
    /// Edges already present in `edge_set` are skipped (idempotent).
    /// The batch is applied atomically to the store: either all new edges land
    /// or none do (on write failure).
    pub async fn add_edges_batch(&mut self, edges: &[(String, EdgeKind, String)]) -> Result<()> {
        // Filter to only edges that don't already exist.
        let new_edges: Vec<Edge> = edges
            .iter()
            .filter(|(from, kind, to)| {
                match (self.node_index.get(from), self.node_index.get(to)) {
                    (Some(&fi), Some(&ti)) => !self.edge_set.contains(&(fi, ti, kind.clone())),
                    _ => true, // at least one node is new → edge definitely doesn't exist
                }
            })
            .map(|(from, kind, to)| Edge::new(from.as_str(), kind.clone(), to.as_str()))
            .collect();

        if new_edges.is_empty() {
            return Ok(());
        }

        // Pre-size in-memory collections to absorb the whole batch without resize.
        let n = new_edges.len();
        self.inner.reserve_nodes(n * 2);
        self.inner.reserve_edges(n);
        self.node_index.reserve(n * 2);
        self.edge_set.reserve(n);

        // Pre-compute timestamp once for the whole batch (not per-edge).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_le_bytes();

        let keys: Vec<String> = new_edges.iter().map(|e| e.to_key()).collect();
        let pairs: Vec<(&str, &[u8])> =
            keys.iter().map(|k| (k.as_str(), now.as_ref())).collect();
        self.store.put_batch_raw(&pairs).await?;

        // Update in-memory state only after the write succeeds.
        for edge in &new_edges {
            self.insert_edge_in_memory(edge);
        }
        Ok(())
    }

    /// Remove an edge from the in-memory graph and delete it from SurrealKV.
    pub async fn remove_edge(&mut self, from: &str, kind: &EdgeKind, to: &str) -> Result<()> {
        let edge = Edge::new(from, kind.clone(), to);
        self.store.delete(&edge.to_key()).await?;
        let from_idx = match self.node_index.get(from) { Some(&i) => i, None => return Ok(()) };
        let to_idx   = match self.node_index.get(to)   { Some(&i) => i, None => return Ok(()) };
        self.edge_set.remove(&(from_idx, to_idx, kind.clone()));
        let to_remove: Vec<_> = self.inner
            .edges_connecting(from_idx, to_idx)
            .filter(|e| e.weight() == kind)
            .map(|e| e.id())
            .collect();
        for eid in to_remove {
            self.inner.remove_edge(eid);
        }
        Ok(())
    }

    /// BFS traversal from `seed` following `edge_kind` edges up to `depth` hops.
    /// Returns node keys reachable (seed itself excluded).
    pub fn traverse(&self, seed: &str, edge_kind: &EdgeKind, depth: usize) -> Vec<String> {
        if depth == 0 { return vec![]; }
        let Some(&start) = self.node_index.get(seed) else { return vec![]; };
        let mut visited = HashSet::new();
        let mut queue   = std::collections::VecDeque::new();
        queue.push_back((start, 0usize));
        visited.insert(start);
        let mut results = vec![];
        while let Some((node, d)) = queue.pop_front() {
            if d >= depth { continue; }
            for e in self.inner.edges(node) {
                if e.weight() != edge_kind { continue; }
                let target = e.target();
                if visited.insert(target) {
                    results.push(self.inner[target].clone());
                    queue.push_back((target, d + 1));
                }
            }
        }
        results
    }

    /// Immediate neighbors via `kind` edges (depth = 1).
    pub fn neighbors(&self, node: &str, kind: &EdgeKind) -> Vec<String> {
        self.traverse(node, kind, 1)
    }

    /// BFS traversal following incoming `edge_kind` edges up to `depth` hops.
    /// Returns node keys that have a path *to* `seed` (i.e. sources, not targets).
    /// Used for queries like "which files import this file?" (reverse Imports).
    pub fn traverse_incoming(&self, seed: &str, edge_kind: &EdgeKind, depth: usize) -> Vec<String> {
        if depth == 0 { return vec![]; }
        let Some(&start) = self.node_index.get(seed) else { return vec![]; };
        let mut visited = HashSet::new();
        let mut queue   = std::collections::VecDeque::new();
        queue.push_back((start, 0usize));
        visited.insert(start);
        let mut results = vec![];
        while let Some((node, d)) = queue.pop_front() {
            if d >= depth { continue; }
            for e in self.inner.edges_directed(node, Direction::Incoming) {
                if e.weight() != edge_kind { continue; }
                let source = e.source();
                if visited.insert(source) {
                    results.push(self.inner[source].clone());
                    queue.push_back((source, d + 1));
                }
            }
        }
        results
    }

    /// Immediate incoming neighbors via `kind` edges (depth = 1).
    pub fn neighbors_incoming(&self, node: &str, kind: &EdgeKind) -> Vec<String> {
        self.traverse_incoming(node, kind, 1)
    }

    /// Borrow the underlying store — used by CLI commands that need both
    /// graph traversal and record reads in the same operation.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Flush pending writes and close the underlying store.
    pub async fn close(self) -> Result<()> {
        self.store.close().await
    }

    /// Number of nodes in the graph.
    pub fn node_count(&self) -> usize { self.inner.node_count() }

    /// Number of edges in the graph.
    pub fn edge_count(&self) -> usize { self.inner.edge_count() }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn get_or_insert_node(&mut self, key: &str) -> NodeIndex {
        if let Some(&idx) = self.node_index.get(key) { return idx; }
        let idx = self.inner.add_node(key.to_owned());
        self.node_index.insert(key.to_owned(), idx);
        idx
    }

    fn insert_edge_in_memory(&mut self, edge: &Edge) {
        let from_idx = self.get_or_insert_node(&edge.from);
        let to_idx   = self.get_or_insert_node(&edge.to);
        // O(1) duplicate check via the edge set.
        if self.edge_set.insert((from_idx, to_idx, edge.kind.clone())) {
            self.inner.add_edge(from_idx, to_idx, edge.kind.clone());
        }
    }
}

/// Persist a single edge as an 8-byte creation timestamp.
///
/// The key encodes the full edge (`graph:edge:<from>:<kind>:<to>`), so the
/// stored value only needs to be a non-empty sentinel. An 8-byte LE timestamp
/// is stored for debuggability; `Graph::load` never reads it.
async fn persist_edge(store: &Store, edge: &Edge) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_le_bytes();
    store.put_raw(&edge.to_key(), &now).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Record;
    use tempfile::TempDir;

    async fn temp_graph() -> (Graph, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        (graph, dir)
    }

    fn make_edge_stub_record(key: &str) -> Record {
        use crate::store::record::*;
        let now = 0u64;
        Record {
            key: key.to_owned(),
            value: String::new(),
            category: Category::Stage,
            priority: Priority::Normal,
            tags: vec![],
            created_at: now,
            updated_at: now,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion { device_id: uuid::Uuid::nil(), logical_clock: 0, wall_clock: now },
            quality: QualityScore { value: 1.0, tier: QualityTier::Good, signals: vec![], computed_at: now },
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore { value: 1.0, confirmation_count: 0, contributor_count: 0, last_challenged: None, challenge_count: 0 },
            gap_analysis_score: 0.0,
        }
    }

    #[tokio::test]
    async fn load_empty_store_gives_empty_graph() {
        let (g, _dir) = temp_graph().await;
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[tokio::test]
    async fn add_edge_increases_counts() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:src/main.rs", EdgeKind::HasGotcha, "gotcha:write-txn")
            .await.unwrap();
        assert_eq!(g.node_count(), 2);
        assert_eq!(g.edge_count(), 1);
    }

    #[tokio::test]
    async fn add_edge_is_idempotent() {
        let (mut g, _dir) = temp_graph().await;
        for _ in 0..3 {
            g.add_edge("file:src/a.rs", EdgeKind::Imports, "file:src/b.rs")
                .await.unwrap();
        }
        assert_eq!(g.edge_count(), 1);
    }

    /// Duplicate add_edge must not write to the store a second time.
    /// Verified by scanning the store prefix and checking exactly 1 record exists.
    #[tokio::test]
    async fn add_edge_duplicate_does_not_write_store() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let mut g = Graph::load(store).await.unwrap();
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        let keys = g.store.scan_keys("graph:edge:").await.unwrap();
        assert_eq!(keys.len(), 1, "store must contain exactly 1 edge record");
    }

    #[tokio::test]
    async fn edges_survive_reload() {
        let dir = TempDir::new().unwrap();
        {
            let store = Store::open(dir.path()).await.unwrap();
            let mut g = Graph::load(store).await.unwrap();
            g.add_edge("file:src/a.rs", EdgeKind::CoChanges, "file:src/b.rs")
                .await.unwrap();
            g.close().await.unwrap();
        }
        let store2 = Store::open(dir.path()).await.unwrap();
        let g2 = Graph::load(store2).await.unwrap();
        assert_eq!(g2.edge_count(), 1);
        let neighbors = g2.neighbors("file:src/a.rs", &EdgeKind::CoChanges);
        assert_eq!(neighbors, vec!["file:src/b.rs"]);
    }

    #[tokio::test]
    async fn traverse_two_hops() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        g.add_edge("file:b", EdgeKind::Imports, "file:c").await.unwrap();
        g.add_edge("file:c", EdgeKind::Imports, "file:d").await.unwrap();
        let two_hop = g.traverse("file:a", &EdgeKind::Imports, 2);
        assert!(two_hop.contains(&"file:b".to_string()));
        assert!(two_hop.contains(&"file:c".to_string()));
        assert!(!two_hop.contains(&"file:d".to_string()), "depth=2 must not reach d");
    }

    #[tokio::test]
    async fn traverse_unknown_node_returns_empty() {
        let (g, _dir) = temp_graph().await;
        assert!(g.traverse("file:nonexistent", &EdgeKind::Imports, 5).is_empty());
    }

    #[tokio::test]
    async fn neighbors_returns_direct_targets_only() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::HasGotcha, "gotcha:x").await.unwrap();
        g.add_edge("file:a", EdgeKind::HasGotcha, "gotcha:y").await.unwrap();
        g.add_edge("file:a", EdgeKind::Imports,   "file:b").await.unwrap();
        let gotchas = g.neighbors("file:a", &EdgeKind::HasGotcha);
        assert_eq!(gotchas.len(), 2);
        assert!(gotchas.contains(&"gotcha:x".to_string()));
        assert!(gotchas.contains(&"gotcha:y".to_string()));
        let imports = g.neighbors("file:a", &EdgeKind::Imports);
        assert_eq!(imports, vec!["file:b"]);
    }

    #[tokio::test]
    async fn traverse_does_not_cross_edge_kinds() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports,   "file:b").await.unwrap();
        g.add_edge("file:b", EdgeKind::HasGotcha, "gotcha:x").await.unwrap();
        let result = g.traverse("file:a", &EdgeKind::Imports, 5);
        assert!(result.contains(&"file:b".to_string()));
        assert!(!result.contains(&"gotcha:x".to_string()));
    }

    #[tokio::test]
    async fn remove_edge_works() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        assert_eq!(g.edge_count(), 1);
        g.remove_edge("file:a", &EdgeKind::Imports, "file:b").await.unwrap();
        assert_eq!(g.edge_count(), 0);
        assert!(g.neighbors("file:a", &EdgeKind::Imports).is_empty());
    }

    /// remove_edge must work on edges that were loaded from the store (not just
    /// added in the current session). After reload the edge_set is rebuilt from
    /// scan_prefix — this test confirms remove operates on that rebuilt state.
    #[tokio::test]
    async fn remove_edge_after_reload() {
        let dir = TempDir::new().unwrap();
        {
            let store = Store::open(dir.path()).await.unwrap();
            let mut g = Graph::load(store).await.unwrap();
            g.add_edge("file:a", EdgeKind::HasGotcha, "gotcha:x").await.unwrap();
            g.add_edge("file:a", EdgeKind::HasGotcha, "gotcha:y").await.unwrap();
            g.close().await.unwrap();
        }
        // Reload and remove one of the edges.
        let store2 = Store::open(dir.path()).await.unwrap();
        let mut g2 = Graph::load(store2).await.unwrap();
        assert_eq!(g2.edge_count(), 2);
        g2.remove_edge("file:a", &EdgeKind::HasGotcha, "gotcha:x").await.unwrap();
        assert_eq!(g2.edge_count(), 1);
        assert!(g2.neighbors("file:a", &EdgeKind::HasGotcha).iter().all(|n| n != "gotcha:x"));
        assert!(g2.neighbors("file:a", &EdgeKind::HasGotcha).contains(&"gotcha:y".to_string()));

        // Reload again — the removed edge must not come back.
        g2.close().await.unwrap();
        let store3 = Store::open(dir.path()).await.unwrap();
        let g3 = Graph::load(store3).await.unwrap();
        assert_eq!(g3.edge_count(), 1);
        assert!(g3.neighbors("file:a", &EdgeKind::HasGotcha).contains(&"gotcha:y".to_string()));
    }

    #[tokio::test]
    async fn remove_nonexistent_edge_is_noop() {
        let (mut g, _dir) = temp_graph().await;
        g.remove_edge("file:a", &EdgeKind::Imports, "file:b").await.unwrap();
        assert_eq!(g.edge_count(), 0);
    }

    #[tokio::test]
    async fn ten_node_chain_correct_traversal() {
        let (mut g, _dir) = temp_graph().await;
        for i in 0..9usize {
            g.add_edge(&format!("file:n{i}"), EdgeKind::Imports, &format!("file:n{}", i + 1))
                .await.unwrap();
        }
        assert_eq!(g.node_count(), 10);
        assert_eq!(g.edge_count(), 9);
        let two_hop = g.traverse("file:n0", &EdgeKind::Imports, 2);
        assert_eq!(two_hop.len(), 2);
        assert!(two_hop.contains(&"file:n1".to_string()));
        assert!(two_hop.contains(&"file:n2".to_string()));
        let full = g.traverse("file:n0", &EdgeKind::Imports, 10);
        assert_eq!(full.len(), 9);
    }

    /// Cycle a → b → a must not cause infinite BFS.
    #[tokio::test]
    async fn traverse_cycle_terminates() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        g.add_edge("file:b", EdgeKind::Imports, "file:a").await.unwrap();
        let result = g.traverse("file:a", &EdgeKind::Imports, 10);
        // Only one unique non-seed node reachable.
        assert_eq!(result.len(), 1);
        assert!(result.contains(&"file:b".to_string()));
    }

    /// Diamond: a→b, a→c, b→d, c→d — d should appear exactly once.
    #[tokio::test]
    async fn traverse_diamond_no_duplicates() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        g.add_edge("file:a", EdgeKind::Imports, "file:c").await.unwrap();
        g.add_edge("file:b", EdgeKind::Imports, "file:d").await.unwrap();
        g.add_edge("file:c", EdgeKind::Imports, "file:d").await.unwrap();
        let result = g.traverse("file:a", &EdgeKind::Imports, 3);
        assert_eq!(result.len(), 3, "b, c, d — no duplicates");
        assert!(result.contains(&"file:b".to_string()));
        assert!(result.contains(&"file:c".to_string()));
        assert!(result.contains(&"file:d".to_string()));
    }

    /// depth=0 always returns empty, even when the seed has outgoing edges.
    #[tokio::test]
    async fn traverse_depth_zero_returns_empty() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        assert!(g.traverse("file:a", &EdgeKind::Imports, 0).is_empty());
    }

    /// Multiple edge kinds between the same pair are stored independently.
    /// Removing one must not affect the other.
    #[tokio::test]
    async fn multiple_kinds_between_same_pair_are_independent() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports,   "file:b").await.unwrap();
        g.add_edge("file:a", EdgeKind::CoChanges, "file:b").await.unwrap();
        assert_eq!(g.edge_count(), 2);

        g.remove_edge("file:a", &EdgeKind::Imports, "file:b").await.unwrap();
        assert_eq!(g.edge_count(), 1);
        assert!(g.neighbors("file:a", &EdgeKind::Imports).is_empty());
        assert_eq!(g.neighbors("file:a", &EdgeKind::CoChanges), vec!["file:b"]);
    }

    /// remove then add the same edge — edge_set must let the re-add through.
    #[tokio::test]
    async fn remove_then_readd_edge_works() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        g.remove_edge("file:a", &EdgeKind::Imports, "file:b").await.unwrap();
        assert_eq!(g.edge_count(), 0);
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        assert_eq!(g.edge_count(), 1);
        assert_eq!(g.neighbors("file:a", &EdgeKind::Imports), vec!["file:b"]);
    }

    /// Removing edges does not shrink node_count — petgraph keeps orphan nodes.
    #[tokio::test]
    async fn node_count_stable_after_edge_removal() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        assert_eq!(g.node_count(), 2);
        g.remove_edge("file:a", &EdgeKind::Imports, "file:b").await.unwrap();
        assert_eq!(g.node_count(), 2, "nodes are never removed from the graph");
    }

    /// Two disconnected components must not bleed into each other's traversal.
    /// Graph is directed — traversal from the target of an edge must not
    /// reach the source unless a reverse edge is also present.
    #[tokio::test]
    async fn traverse_incoming_finds_sources() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        g.add_edge("file:c", EdgeKind::Imports, "file:b").await.unwrap();
        // Two files import b — traverse_incoming from b should find both.
        let sources = g.traverse_incoming("file:b", &EdgeKind::Imports, 1);
        assert_eq!(sources.len(), 2);
        assert!(sources.contains(&"file:a".to_string()));
        assert!(sources.contains(&"file:c".to_string()));
    }

    #[tokio::test]
    async fn traverse_incoming_does_not_return_outgoing() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        // traverse outgoing from a gives b; traverse_incoming from a gives nothing.
        assert!(g.traverse_incoming("file:a", &EdgeKind::Imports, 5).is_empty());
    }

    #[tokio::test]
    async fn traverse_incoming_multi_hop() {
        let (mut g, _dir) = temp_graph().await;
        // Chain: c → b → a  (c imports b, b imports a)
        g.add_edge("file:b", EdgeKind::Imports, "file:a").await.unwrap();
        g.add_edge("file:c", EdgeKind::Imports, "file:b").await.unwrap();
        // 1 hop from a: only b
        let one = g.traverse_incoming("file:a", &EdgeKind::Imports, 1);
        assert_eq!(one, vec!["file:b"]);
        // 2 hops from a: b and c
        let two = g.traverse_incoming("file:a", &EdgeKind::Imports, 2);
        assert!(two.contains(&"file:b".to_string()));
        assert!(two.contains(&"file:c".to_string()));
    }

    #[tokio::test]
    async fn neighbors_incoming_returns_direct_sources_only() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:x", EdgeKind::HasGotcha, "gotcha:y").await.unwrap();
        g.add_edge("file:z", EdgeKind::HasGotcha, "gotcha:y").await.unwrap();
        let sources = g.neighbors_incoming("gotcha:y", &EdgeKind::HasGotcha);
        assert_eq!(sources.len(), 2);
        assert!(sources.contains(&"file:x".to_string()));
        assert!(sources.contains(&"file:z".to_string()));
    }

    #[tokio::test]
    async fn traverse_is_directed() {
        let (mut g, _dir) = temp_graph().await;
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        // Forward: a can reach b.
        assert!(!g.traverse("file:a", &EdgeKind::Imports, 1).is_empty());
        // Reverse: b cannot reach a — no back edge exists.
        assert!(g.traverse("file:b", &EdgeKind::Imports, 5).is_empty());
    }

    /// Adding the same edge in two separate sessions must not duplicate it in
    /// the store. The second session loads it from SurrealKV, detects it in
    /// edge_set, and skips the write.
    #[tokio::test]
    async fn add_edge_idempotent_across_sessions() {
        let dir = TempDir::new().unwrap();
        for _ in 0..2 {
            let store = Store::open(dir.path()).await.unwrap();
            let mut g = Graph::load(store).await.unwrap();
            g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
            g.close().await.unwrap();
        }
        let store = Store::open(dir.path()).await.unwrap();
        let g = Graph::load(store).await.unwrap();
        assert_eq!(g.edge_count(), 1);
        // Store should also contain exactly one edge record.
        let keys = g.store.scan_keys("graph:edge:").await.unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[tokio::test]
    async fn disconnected_components_do_not_bleed() {
        let (mut g, _dir) = temp_graph().await;
        // Component 1: a → b → c
        g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();
        g.add_edge("file:b", EdgeKind::Imports, "file:c").await.unwrap();
        // Component 2: x → y
        g.add_edge("file:x", EdgeKind::Imports, "file:y").await.unwrap();

        let from_a = g.traverse("file:a", &EdgeKind::Imports, 10);
        assert!(!from_a.contains(&"file:x".to_string()));
        assert!(!from_a.contains(&"file:y".to_string()));

        let from_x = g.traverse("file:x", &EdgeKind::Imports, 10);
        assert!(!from_x.contains(&"file:a".to_string()));
        assert!(!from_x.contains(&"file:b".to_string()));
    }

    /// graph:edge:* keys that don't parse as valid edges (corrupt or manually
    /// inserted records) must be silently skipped during load — not panic or error.
    #[tokio::test]
    async fn load_skips_unparseable_edge_keys() {
        let dir = TempDir::new().unwrap();
        {
            let store = Store::open(dir.path()).await.unwrap();
            let mut g = Graph::load(store).await.unwrap();

            // Add one legitimate edge.
            g.add_edge("file:a", EdgeKind::Imports, "file:b").await.unwrap();

            // Manually insert a record whose key has the graph:edge: prefix
            // but is not a valid edge key (no parseable from/kind/to triple).
            let corrupt_key = "graph:edge:this_is_not_parseable";
            let record = make_edge_stub_record(corrupt_key);
            g.store.put(corrupt_key, &record).await.unwrap();

            g.close().await.unwrap();
        }
        // Reload — must not panic, must skip the corrupt key.
        let store2 = Store::open(dir.path()).await.unwrap();
        let g2 = Graph::load(store2).await.unwrap();
        assert_eq!(g2.edge_count(), 1, "only the valid edge should be loaded");
        assert_eq!(g2.neighbors("file:a", &EdgeKind::Imports), vec!["file:b"]);
    }

    /// Load 100 pre-persisted edges from SurrealKV — validates the bulk load path.
    #[tokio::test]
    async fn load_100_edges_from_store() {
        let dir = TempDir::new().unwrap();
        let n = 100usize;
        {
            let store = Store::open(dir.path()).await.unwrap();
            let mut g = Graph::load(store).await.unwrap();
            for i in 0..n {
                g.add_edge(
                    &format!("file:src/mod{i}.rs"),
                    EdgeKind::Imports,
                    &format!("file:src/dep{i}.rs"),
                )
                .await.unwrap();
            }
            g.close().await.unwrap();
        }
        let store2 = Store::open(dir.path()).await.unwrap();
        let g2 = Graph::load(store2).await.unwrap();
        assert_eq!(g2.edge_count(), n);
        assert_eq!(g2.node_count(), n * 2);
        assert_eq!(
            g2.neighbors("file:src/mod0.rs", &EdgeKind::Imports),
            vec!["file:src/dep0.rs"]
        );
        assert_eq!(
            g2.neighbors(&format!("file:src/mod{}.rs", n - 1), &EdgeKind::Imports),
            vec![format!("file:src/dep{}.rs", n - 1)]
        );
    }

    #[tokio::test]
    async fn add_edges_batch_correctness() {
        let (mut g, _dir) = temp_graph().await;
        let batch = vec![
            ("file:a".to_string(), EdgeKind::Imports,   "file:b".to_string()),
            ("file:a".to_string(), EdgeKind::HasGotcha, "gotcha:x".to_string()),
            ("file:b".to_string(), EdgeKind::CoChanges, "file:c".to_string()),
        ];
        g.add_edges_batch(&batch).await.unwrap();
        assert_eq!(g.edge_count(), 3);
        assert_eq!(g.neighbors("file:a", &EdgeKind::Imports),   vec!["file:b"]);
        assert_eq!(g.neighbors("file:a", &EdgeKind::HasGotcha), vec!["gotcha:x"]);
        assert_eq!(g.neighbors("file:b", &EdgeKind::CoChanges), vec!["file:c"]);
    }

    #[tokio::test]
    async fn add_edges_batch_is_idempotent() {
        let (mut g, _dir) = temp_graph().await;
        let batch = vec![
            ("file:a".to_string(), EdgeKind::Imports, "file:b".to_string()),
        ];
        g.add_edges_batch(&batch).await.unwrap();
        g.add_edges_batch(&batch).await.unwrap();
        g.add_edges_batch(&batch).await.unwrap();
        assert_eq!(g.edge_count(), 1);
        let keys = g.store.scan_keys("graph:edge:").await.unwrap();
        assert_eq!(keys.len(), 1, "store must have exactly 1 record after duplicate batches");
    }

    #[tokio::test]
    async fn add_edges_batch_survives_reload() {
        let dir = TempDir::new().unwrap();
        {
            let store = Store::open(dir.path()).await.unwrap();
            let mut g = Graph::load(store).await.unwrap();
            let batch: Vec<(String, EdgeKind, String)> = (0..50)
                .map(|i| (format!("file:a{i}"), EdgeKind::Imports, format!("file:b{i}")))
                .collect();
            g.add_edges_batch(&batch).await.unwrap();
            g.close().await.unwrap();
        }
        let store2 = Store::open(dir.path()).await.unwrap();
        let g2 = Graph::load(store2).await.unwrap();
        assert_eq!(g2.edge_count(), 50);
    }

    #[tokio::test]
    async fn add_edges_batch_faster_than_sequential() {
        use std::time::Instant;
        let edges: Vec<(String, EdgeKind, String)> = (0..500)
            .map(|i| (format!("file:m{i}"), EdgeKind::Imports, format!("file:d{i}")))
            .collect();

        // Sequential baseline.
        let dir_seq = TempDir::new().unwrap();
        let store_seq = Store::open(dir_seq.path()).await.unwrap();
        let mut g_seq = Graph::load(store_seq).await.unwrap();
        let seq_start = Instant::now();
        for (from, kind, to) in &edges {
            g_seq.add_edge(from, kind.clone(), to).await.unwrap();
        }
        let seq_ms = seq_start.elapsed().as_millis();

        // Batch.
        let dir_bat = TempDir::new().unwrap();
        let store_bat = Store::open(dir_bat.path()).await.unwrap();
        let mut g_bat = Graph::load(store_bat).await.unwrap();
        let bat_start = Instant::now();
        g_bat.add_edges_batch(&edges).await.unwrap();
        let bat_ms = bat_start.elapsed().as_millis();

        assert!(
            bat_ms < seq_ms,
            "add_edges_batch ({bat_ms}ms) was not faster than sequential add_edge ({seq_ms}ms)"
        );
        assert_eq!(g_bat.edge_count(), 500);
    }

    /// Stress test: 1,200 edges across all 10 EdgeKind variants — matching the
    /// upper bound of what Layer 0 static analysis produces on a real repo.
    /// Verifies correctness of edge_count, traversal, reverse traversal,
    /// duplicate rejection, and full persist + reload cycle.
    #[tokio::test]
    async fn stress_1200_edges_layer0_scale() {
        use std::time::Instant;

        let dir = TempDir::new().unwrap();
        let n_files = 120usize; // 120 files × 10 kinds = 1,200 edges
        let all_kinds = [
            EdgeKind::HasGotcha,
            EdgeKind::Imports,
            EdgeKind::AffectedBy,
            EdgeKind::HasNote,
            EdgeKind::DiscoveredIn,
            EdgeKind::CausedBy,
            EdgeKind::Supersedes,
            EdgeKind::Touched,
            EdgeKind::DependencyAffects,
            EdgeKind::CoChanges,
        ];

        // ── Session 1: build the graph via add_edges_batch ──────────────────
        let build_start = Instant::now();
        {
            let store = Store::open(dir.path()).await.unwrap();
            let mut g = Graph::load(store).await.unwrap();
            let batch: Vec<(String, EdgeKind, String)> = (0..n_files)
                .flat_map(|i| {
                    all_kinds.iter().map(move |kind| (
                        format!("file:src/module{i}.rs"),
                        kind.clone(),
                        format!("file:src/target{i}.rs"),
                    ))
                })
                .collect();
            g.add_edges_batch(&batch).await.unwrap();
            assert_eq!(g.edge_count(), 1_200);
            assert_eq!(g.node_count(), n_files * 2);
            g.close().await.unwrap();
        }
        let build_ms = build_start.elapsed().as_millis();

        // ── Session 2: reload and verify ─────────────────────────────────────
        let load_start = Instant::now();
        let store2 = Store::open(dir.path()).await.unwrap();
        let g2 = Graph::load(store2).await.unwrap();
        let load_ms = load_start.elapsed().as_millis();

        assert_eq!(g2.edge_count(), 1_200, "all edges must survive reload");
        assert_eq!(g2.node_count(), n_files * 2);

        // Spot-check every kind on a mid-range file.
        let mid = n_files / 2;
        for kind in &all_kinds {
            let fwd = g2.neighbors(&format!("file:src/module{mid}.rs"), kind);
            assert_eq!(fwd.len(), 1, "forward: {kind:?}");
            assert_eq!(fwd[0], format!("file:src/target{mid}.rs"));

            let rev = g2.neighbors_incoming(&format!("file:src/target{mid}.rs"), kind);
            assert_eq!(rev.len(), 1, "reverse: {kind:?}");
            assert_eq!(rev[0], format!("file:src/module{mid}.rs"));
        }
        g2.close().await.unwrap();

        // ── Duplicate rejection at scale ─────────────────────────────────────
        // Re-adding all 1,200 edges must be a no-op — edge_count stays at 1,200.
        let store3 = Store::open(dir.path()).await.unwrap();
        let mut g3 = Graph::load(store3).await.unwrap();
        for i in 0..n_files {
            for kind in &all_kinds {
                g3.add_edge(
                    &format!("file:src/module{i}.rs"),
                    kind.clone(),
                    &format!("file:src/target{i}.rs"),
                )
                .await.unwrap();
            }
        }
        assert_eq!(g3.edge_count(), 1_200, "duplicate adds must not grow the graph");
        let store_keys = g3.store.scan_keys("graph:edge:").await.unwrap();
        assert_eq!(store_keys.len(), 1_200, "store must not contain duplicate records");

        // ── Traversal correctness on a hub node ──────────────────────────────
        // Connect all 120 source files to a single hub via CoChanges.
        for i in 0..n_files {
            g3.add_edge(
                &format!("file:src/module{i}.rs"),
                EdgeKind::CoChanges,
                "file:src/hub.rs",
            )
            .await.unwrap();
        }
        let hub_sources = g3.neighbors_incoming("file:src/hub.rs", &EdgeKind::CoChanges);
        assert_eq!(hub_sources.len(), n_files, "hub must have {n_files} incoming CoChanges");

        // ── Timing assertions ─────────────────────────────────────────────────
        // Build uses add_edges_batch → 1 fsync. Load is sequential reads.
        // Both should be well under 1s in debug, <50ms in release.
        // Bounds are intentionally generous for slow CI machines.
        println!("stress_1200  build={build_ms}ms  load={load_ms}ms");
        assert!(
            load_ms < 500,
            "graph load took {load_ms}ms — expected <500ms for 1,200 edges"
        );
        assert!(
            build_ms < 5_000,
            "graph build took {build_ms}ms — expected <5s for 1,200 edges (1 fsync via batch)"
        );
    }

    /// Stress test: 15,000 edges — realistic medium-large production repo.
    /// 1,500 files × 10 EdgeKind variants; exercises batch write, key-only
    /// scan on reload, and duplicate rejection at production scale.
    #[tokio::test]
    async fn stress_15000_edges_production_scale() {
        use std::time::Instant;

        let dir = TempDir::new().unwrap();
        let n_files = 1_500usize; // 1,500 files × 10 kinds = 15,000 edges
        let all_kinds = [
            EdgeKind::HasGotcha,
            EdgeKind::Imports,
            EdgeKind::AffectedBy,
            EdgeKind::HasNote,
            EdgeKind::DiscoveredIn,
            EdgeKind::CausedBy,
            EdgeKind::Supersedes,
            EdgeKind::Touched,
            EdgeKind::DependencyAffects,
            EdgeKind::CoChanges,
        ];

        // ── Session 1: build the graph via add_edges_batch ──────────────────
        let build_start = Instant::now();
        {
            let store = Store::open(dir.path()).await.unwrap();
            let mut g = Graph::load(store).await.unwrap();
            let batch: Vec<(String, EdgeKind, String)> = (0..n_files)
                .flat_map(|i| {
                    all_kinds.iter().map(move |kind| (
                        format!("file:src/module{i}.rs"),
                        kind.clone(),
                        format!("file:src/target{i}.rs"),
                    ))
                })
                .collect();
            g.add_edges_batch(&batch).await.unwrap();
            assert_eq!(g.edge_count(), 15_000);
            assert_eq!(g.node_count(), n_files * 2);
            g.close().await.unwrap();
        }
        let build_ms = build_start.elapsed().as_millis();

        // ── Session 2: reload and verify ─────────────────────────────────────
        let load_start = Instant::now();
        let store2 = Store::open(dir.path()).await.unwrap();
        let g2 = Graph::load(store2).await.unwrap();
        let load_ms = load_start.elapsed().as_millis();

        assert_eq!(g2.edge_count(), 15_000, "all edges must survive reload");
        assert_eq!(g2.node_count(), n_files * 2);

        // Spot-check every kind on a mid-range file.
        let mid = n_files / 2;
        for kind in &all_kinds {
            let fwd = g2.neighbors(&format!("file:src/module{mid}.rs"), kind);
            assert_eq!(fwd.len(), 1, "forward: {kind:?}");
            assert_eq!(fwd[0], format!("file:src/target{mid}.rs"));

            let rev = g2.neighbors_incoming(&format!("file:src/target{mid}.rs"), kind);
            assert_eq!(rev.len(), 1, "reverse: {kind:?}");
            assert_eq!(rev[0], format!("file:src/module{mid}.rs"));
        }
        g2.close().await.unwrap();

        // ── Duplicate rejection at scale ─────────────────────────────────────
        // Re-adding the same batch must be a no-op.
        let store3 = Store::open(dir.path()).await.unwrap();
        let mut g3 = Graph::load(store3).await.unwrap();
        let dup_batch: Vec<(String, EdgeKind, String)> = (0..n_files)
            .flat_map(|i| {
                all_kinds.iter().map(move |kind| (
                    format!("file:src/module{i}.rs"),
                    kind.clone(),
                    format!("file:src/target{i}.rs"),
                ))
            })
            .collect();
        g3.add_edges_batch(&dup_batch).await.unwrap();
        assert_eq!(g3.edge_count(), 15_000, "duplicate adds must not grow the graph");
        let store_keys = g3.store.scan_keys("graph:edge:").await.unwrap();
        assert_eq!(store_keys.len(), 15_000, "store must not contain duplicate records");

        // ── Traversal correctness on a hub node ──────────────────────────────
        // Connect all 1,500 source files to a single hub via CoChanges.
        let hub_batch: Vec<(String, EdgeKind, String)> = (0..n_files)
            .map(|i| (
                format!("file:src/module{i}.rs"),
                EdgeKind::CoChanges,
                "file:src/hub.rs".to_string(),
            ))
            .collect();
        g3.add_edges_batch(&hub_batch).await.unwrap();
        let hub_sources = g3.neighbors_incoming("file:src/hub.rs", &EdgeKind::CoChanges);
        assert_eq!(hub_sources.len(), n_files, "hub must have {n_files} incoming CoChanges");

        // ── Timing assertions ─────────────────────────────────────────────────
        println!("stress_15000  build={build_ms}ms  load={load_ms}ms");
        assert!(
            load_ms < 2_000,
            "graph load took {load_ms}ms — expected <2s for 15,000 edges"
        );
        assert!(
            build_ms < 10_000,
            "graph build took {build_ms}ms — expected <10s for 15,000 edges (1 fsync via batch)"
        );
    }

    /// Stress test: 100,000 edges — monorepo scale ceiling.
    /// 10,000 files × 10 EdgeKind variants; this is the upper bound for any
    /// real-world repo mati will encounter. Validates that batch write, key-only
    /// scan, and in-memory petgraph all hold up without degradation.
    #[tokio::test]
    async fn stress_100000_edges_monorepo_scale() {
        use std::time::Instant;

        let dir = TempDir::new().unwrap();
        let n_files = 10_000usize; // 10,000 files × 10 kinds = 100,000 edges
        let all_kinds = [
            EdgeKind::HasGotcha,
            EdgeKind::Imports,
            EdgeKind::AffectedBy,
            EdgeKind::HasNote,
            EdgeKind::DiscoveredIn,
            EdgeKind::CausedBy,
            EdgeKind::Supersedes,
            EdgeKind::Touched,
            EdgeKind::DependencyAffects,
            EdgeKind::CoChanges,
        ];

        // ── Session 1: build the graph via add_edges_batch ──────────────────
        let build_start = Instant::now();
        {
            let store = Store::open(dir.path()).await.unwrap();
            let mut g = Graph::load(store).await.unwrap();
            let batch: Vec<(String, EdgeKind, String)> = (0..n_files)
                .flat_map(|i| {
                    all_kinds.iter().map(move |kind| (
                        format!("file:src/module{i}.rs"),
                        kind.clone(),
                        format!("file:src/target{i}.rs"),
                    ))
                })
                .collect();
            g.add_edges_batch(&batch).await.unwrap();
            assert_eq!(g.edge_count(), 100_000);
            assert_eq!(g.node_count(), n_files * 2);
            g.close().await.unwrap();
        }
        let build_ms = build_start.elapsed().as_millis();

        // ── Session 2: reload and verify ─────────────────────────────────────
        let load_start = Instant::now();
        let store2 = Store::open(dir.path()).await.unwrap();
        let g2 = Graph::load(store2).await.unwrap();
        let load_ms = load_start.elapsed().as_millis();

        assert_eq!(g2.edge_count(), 100_000, "all edges must survive reload");
        assert_eq!(g2.node_count(), n_files * 2);

        // Spot-check every kind on a mid-range file.
        let mid = n_files / 2;
        for kind in &all_kinds {
            let fwd = g2.neighbors(&format!("file:src/module{mid}.rs"), kind);
            assert_eq!(fwd.len(), 1, "forward: {kind:?}");
            assert_eq!(fwd[0], format!("file:src/target{mid}.rs"));

            let rev = g2.neighbors_incoming(&format!("file:src/target{mid}.rs"), kind);
            assert_eq!(rev.len(), 1, "reverse: {kind:?}");
            assert_eq!(rev[0], format!("file:src/module{mid}.rs"));
        }
        g2.close().await.unwrap();

        // ── Duplicate rejection at scale ─────────────────────────────────────
        let store3 = Store::open(dir.path()).await.unwrap();
        let mut g3 = Graph::load(store3).await.unwrap();
        let dup_batch: Vec<(String, EdgeKind, String)> = (0..n_files)
            .flat_map(|i| {
                all_kinds.iter().map(move |kind| (
                    format!("file:src/module{i}.rs"),
                    kind.clone(),
                    format!("file:src/target{i}.rs"),
                ))
            })
            .collect();
        g3.add_edges_batch(&dup_batch).await.unwrap();
        assert_eq!(g3.edge_count(), 100_000, "duplicate adds must not grow the graph");
        let store_keys = g3.store.scan_keys("graph:edge:").await.unwrap();
        assert_eq!(store_keys.len(), 100_000, "store must not contain duplicate records");

        // ── Hub traversal: 10,000 incoming edges on a single node ─────────────
        let hub_batch: Vec<(String, EdgeKind, String)> = (0..n_files)
            .map(|i| (
                format!("file:src/module{i}.rs"),
                EdgeKind::CoChanges,
                "file:src/hub.rs".to_string(),
            ))
            .collect();
        g3.add_edges_batch(&hub_batch).await.unwrap();
        let hub_sources = g3.neighbors_incoming("file:src/hub.rs", &EdgeKind::CoChanges);
        assert_eq!(hub_sources.len(), n_files, "hub must have {n_files} incoming CoChanges");

        // ── Timing assertions ─────────────────────────────────────────────────
        println!("stress_100000  build={build_ms}ms  load={load_ms}ms");
        assert!(
            load_ms < 5_000,
            "graph load took {load_ms}ms — expected <5s for 100,000 edges"
        );
        assert!(
            build_ms < 30_000,
            "graph build took {build_ms}ms — expected <30s for 100,000 edges (1 fsync via batch)"
        );
    }

    /// Stress test: 700,000 edges — Linux kernel scale.
    /// The Linux kernel has ~70,000 source + header files. At 10 EdgeKind
    /// variants each this represents the absolute ceiling of what mati will
    /// ever index. If this passes, mati handles any real-world repo.
    #[tokio::test]
    async fn stress_700000_edges_linux_kernel_scale() {
        use std::time::Instant;

        let dir = TempDir::new().unwrap();
        let n_files = 70_000usize; // 70,000 files × 10 kinds = 700,000 edges
        let all_kinds = [
            EdgeKind::HasGotcha,
            EdgeKind::Imports,
            EdgeKind::AffectedBy,
            EdgeKind::HasNote,
            EdgeKind::DiscoveredIn,
            EdgeKind::CausedBy,
            EdgeKind::Supersedes,
            EdgeKind::Touched,
            EdgeKind::DependencyAffects,
            EdgeKind::CoChanges,
        ];

        // ── Step 1: batch Vec construction ──────────────────────────────────
        let t0 = Instant::now();
        let batch: Vec<(String, EdgeKind, String)> = (0..n_files)
            .flat_map(|i| {
                all_kinds.iter().map(move |kind| (
                    format!("file:src/module{i}.rs"),
                    kind.clone(),
                    format!("file:src/target{i}.rs"),
                ))
            })
            .collect();
        let batch_construct_ms = t0.elapsed().as_millis();

        // ── Step 2: Store::open + Graph::load (empty) ───────────────────────
        let t1 = Instant::now();
        let store = Store::open(dir.path()).await.unwrap();
        let mut g = Graph::load(store).await.unwrap();
        let open_ms = t1.elapsed().as_millis();

        // ── Step 3: add_edges_batch (SurrealKV writes + in-memory insert) ───
        let t2 = Instant::now();
        g.add_edges_batch(&batch).await.unwrap();
        let add_batch_ms = t2.elapsed().as_millis();

        // ── Step 4: g.close() (flush / drop SurrealKV) ──────────────────────
        let t3 = Instant::now();
        assert_eq!(g.edge_count(), 700_000);
        g.close().await.unwrap();
        let close_ms = t3.elapsed().as_millis();

        // ── Step 5: Store::open (cold reopen) ───────────────────────────────
        let t4 = Instant::now();
        let store2 = Store::open(dir.path()).await.unwrap();
        let reopen_ms = t4.elapsed().as_millis();

        // ── Step 6: Graph::load (scan_keys + petgraph rebuild) ───────────────
        let t5 = Instant::now();
        let g2 = Graph::load(store2).await.unwrap();
        let graph_load_ms = t5.elapsed().as_millis();

        assert_eq!(g2.edge_count(), 700_000, "all edges must survive reload");
        assert_eq!(g2.node_count(), n_files * 2);

        // ── Step 7: traversal (neighbors on hub) ─────────────────────────────
        // Simulates a widely-included header (e.g. linux/types.h).
        // Close g2 first — SurrealKV only allows one writer per db path.
        // Spot-check before closing.
        let mid = n_files / 2;
        for kind in &all_kinds {
            let fwd = g2.neighbors(&format!("file:src/module{mid}.rs"), kind);
            assert_eq!(fwd.len(), 1, "forward: {kind:?}");
            let rev = g2.neighbors_incoming(&format!("file:src/target{mid}.rs"), kind);
            assert_eq!(rev.len(), 1, "reverse: {kind:?}");
        }
        g2.close().await.unwrap();

        let store3 = Store::open(dir.path()).await.unwrap();
        let mut g3 = Graph::load(store3).await.unwrap();
        let hub_batch: Vec<(String, EdgeKind, String)> = (0..n_files)
            .map(|i| (
                format!("file:src/module{i}.rs"),
                EdgeKind::Imports,
                "file:include/linux/types.h".to_string(),
            ))
            .collect();
        g3.add_edges_batch(&hub_batch).await.unwrap();
        let t6 = Instant::now();
        let hub_sources = g3.neighbors_incoming("file:include/linux/types.h", &EdgeKind::Imports);
        let traversal_us = t6.elapsed().as_micros();
        assert_eq!(hub_sources.len(), n_files);


        // ── Breakdown ─────────────────────────────────────────────────────────
        let build_ms = batch_construct_ms + open_ms + add_batch_ms + close_ms;
        let load_ms  = reopen_ms + graph_load_ms;
        println!("\nstress_700000  Linux kernel scale — step breakdown");
        println!("  BUILD  total={build_ms}ms");
        println!("    batch Vec construction : {batch_construct_ms}ms");
        println!("    Store::open (empty)    : {open_ms}ms");
        println!("    add_edges_batch        : {add_batch_ms}ms  ← SurrealKV writes + in-mem insert");
        println!("    g.close / flush        : {close_ms}ms");
        println!("  LOAD   total={load_ms}ms");
        println!("    Store::open (cold)     : {reopen_ms}ms");
        println!("    Graph::load (scan+petgraph): {graph_load_ms}ms  ← scan_keys + DiGraph rebuild");
        println!("  TRAVERSAL");
        println!("    neighbors_incoming (70k edges): {traversal_us}µs  ← pure RAM");

        assert!(build_ms < 60_000, "build took {build_ms}ms");
        assert!(load_ms  < 30_000, "load took {load_ms}ms");
    }
}
