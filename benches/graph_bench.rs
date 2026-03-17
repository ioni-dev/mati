//! Criterion benchmark suite for Graph (petgraph + SurrealKV persistence) — M-04.
//!
//! Stress-tests graph construction, edge insertion, and traversal from 1k
//! to 200k edges (Linux kernel scale: ~80k files × ~1.5 edges/file ≈ 120k edges).
//!
//! Run all (except extreme scale):
//!   cargo bench --bench graph_bench
//!
//! Run extreme scale (200k edges):
//!   MATI_BENCH_EXTREME=1 cargo bench --bench graph_bench extreme_scale

use std::hint::black_box;
use std::path::Path;

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use tempfile::TempDir;

use mati_core::graph::{EdgeKind, Graph};
use mati_core::store::Store;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

async fn open_store(dir: &Path) -> Store {
    Store::open(dir).await.unwrap()
}

/// Generate realistic edges for a project with `n_files` files.
///
/// Distribution per file:
/// - 1 Imports edge (file→file)
/// - 20% chance of HasGotcha edge (file→gotcha)
/// - 10% chance of AffectedBy edge (file→decision)
/// - 5% chance of CoChanges edge (file→file)
fn generate_edges(n_files: usize) -> Vec<(String, EdgeKind, String)> {
    let mut edges = Vec::with_capacity(n_files * 2);

    for i in 0..n_files {
        let file = format!("file:src/module_{i}.rs");

        // Every file imports at least one other
        let target = format!("file:src/module_{}.rs", (i + 1) % n_files);
        edges.push((file.clone(), EdgeKind::Imports, target));

        // 20% have gotchas
        if i % 5 == 0 {
            edges.push((
                file.clone(),
                EdgeKind::HasGotcha,
                format!("gotcha:issue-{i}"),
            ));
        }

        // 10% affected by decisions
        if i % 10 == 0 {
            edges.push((
                file.clone(),
                EdgeKind::AffectedBy,
                format!("decision:arch-{}", i / 10),
            ));
        }

        // 5% co-change pairs
        if i % 20 == 0 && i + 3 < n_files {
            edges.push((
                file.clone(),
                EdgeKind::CoChanges,
                format!("file:src/module_{}.rs", i + 3),
            ));
        }
    }

    edges
}

/// Build a graph pre-loaded with edges persisted to store, return the store dir.
/// Returns the TempDir (must keep alive) and the number of edges.
async fn build_persisted_graph(n_files: usize) -> (TempDir, usize) {
    let dir = TempDir::new().unwrap();
    let store = open_store(dir.path()).await;
    let mut graph = Graph::load(store).await.unwrap();
    let edges = generate_edges(n_files);
    let n_edges = edges.len();
    graph.add_edges_batch(&edges).await.unwrap();
    graph.close().await.unwrap();
    (dir, n_edges)
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 1: graph loading from SurrealKV
// ═══════════════════════════════════════════════════════════════════════════

fn bench_graph_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph_load");
    group.sample_size(20);

    let rt = rt();

    for &(label, n_files) in &[
        ("1k_edges", 800),
        ("5k_edges", 4_000),
        ("10k_edges", 8_000),
        ("50k_edges", 40_000),
    ] {
        let (dir, n_edges) = rt.block_on(build_persisted_graph(n_files));
        group.throughput(Throughput::Elements(n_edges as u64));

        group.bench_with_input(
            BenchmarkId::new("load_from_kv", label),
            &dir,
            |b, dir| {
                b.iter(|| {
                    let store = rt.block_on(open_store(dir.path()));
                    let graph = rt.block_on(Graph::load(store));
                    let g = graph.unwrap();
                    black_box(g.edge_count());
                    rt.block_on(g.close()).unwrap();
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 2: batch edge insertion
// ═══════════════════════════════════════════════════════════════════════════

fn bench_edge_batch_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph_batch_insert");
    group.sample_size(10);

    let rt = rt();

    for &(label, n_files) in &[
        ("1k_edges", 800),
        ("5k_edges", 4_000),
        ("10k_edges", 8_000),
    ] {
        let edges = generate_edges(n_files);
        group.throughput(Throughput::Elements(edges.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("add_edges_batch", label),
            &edges,
            |b, edges| {
                b.iter(|| {
                    let dir = TempDir::new().unwrap();
                    let store = rt.block_on(open_store(dir.path()));
                    let mut graph = rt.block_on(Graph::load(store)).unwrap();
                    rt.block_on(graph.add_edges_batch(edges)).unwrap();
                    black_box(graph.edge_count());
                    rt.block_on(graph.close()).unwrap();
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 3: traversal
// ═══════════════════════════════════════════════════════════════════════════

fn bench_traversal(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph_traversal");
    group.sample_size(100);

    let rt = rt();

    // Build a 10k-edge graph in memory for traversal benchmarks
    let dir = TempDir::new().unwrap();
    let store = rt.block_on(open_store(dir.path()));
    let mut graph = rt.block_on(Graph::load(store)).unwrap();
    let edges = generate_edges(8_000);
    rt.block_on(graph.add_edges_batch(&edges)).unwrap();

    // neighbors (depth=1)
    group.bench_function("neighbors_imports", |b| {
        b.iter(|| {
            let result = graph.neighbors("file:src/module_0.rs", &EdgeKind::Imports);
            black_box(result.len());
        });
    });

    group.bench_function("neighbors_incoming_imports", |b| {
        b.iter(|| {
            let result = graph.neighbors_incoming("file:src/module_100.rs", &EdgeKind::Imports);
            black_box(result.len());
        });
    });

    // traverse depth=3 (multi-hop import chains)
    group.bench_function("traverse_imports_depth3", |b| {
        b.iter(|| {
            let result = graph.traverse("file:src/module_0.rs", &EdgeKind::Imports, 3);
            black_box(result.len());
        });
    });

    // traverse depth=10 (deep chain — tests BFS termination)
    group.bench_function("traverse_imports_depth10", |b| {
        b.iter(|| {
            let result = graph.traverse("file:src/module_0.rs", &EdgeKind::Imports, 10);
            black_box(result.len());
        });
    });

    // traverse full graph (depth=usize::MAX — worst case BFS)
    group.bench_function("traverse_imports_unbounded", |b| {
        b.iter(|| {
            let result = graph.traverse("file:src/module_0.rs", &EdgeKind::Imports, usize::MAX);
            black_box(result.len());
        });
    });

    // traverse HasGotcha (sparser edge type)
    group.bench_function("traverse_has_gotcha_depth3", |b| {
        b.iter(|| {
            let result = graph.traverse("file:src/module_0.rs", &EdgeKind::HasGotcha, 3);
            black_box(result.len());
        });
    });

    // incoming traversal depth=5 ("what depends on this file?")
    group.bench_function("traverse_incoming_imports_depth5", |b| {
        b.iter(|| {
            let result =
                graph.traverse_incoming("file:src/module_100.rs", &EdgeKind::Imports, 5);
            black_box(result.len());
        });
    });

    rt.block_on(graph.close()).unwrap();
    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 4: worst case
// ═══════════════════════════════════════════════════════════════════════════

fn bench_graph_worst_case(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph_worst_case");
    let rt = rt();

    // Star topology: one node connected to N others (worst case for neighbors)
    {
        let dir = TempDir::new().unwrap();
        let store = rt.block_on(open_store(dir.path()));
        let mut graph = rt.block_on(Graph::load(store)).unwrap();

        let hub = "file:src/hub.rs".to_string();
        let edges: Vec<(String, EdgeKind, String)> = (0..5_000)
            .map(|i| {
                (
                    hub.clone(),
                    EdgeKind::Imports,
                    format!("file:src/spoke_{i}.rs"),
                )
            })
            .collect();
        rt.block_on(graph.add_edges_batch(&edges)).unwrap();

        group.bench_function("star_5k_neighbors", |b| {
            b.iter(|| {
                let result = graph.neighbors("file:src/hub.rs", &EdgeKind::Imports);
                black_box(result.len());
            });
        });

        rt.block_on(graph.close()).unwrap();
    }

    // Duplicate edge storm: insert same edges twice (tests idempotency perf)
    {
        let dir = TempDir::new().unwrap();
        let store = rt.block_on(open_store(dir.path()));
        let mut graph = rt.block_on(Graph::load(store)).unwrap();
        let edges = generate_edges(4_000);
        rt.block_on(graph.add_edges_batch(&edges)).unwrap();

        group.bench_function("duplicate_batch_5k", |b| {
            b.iter(|| {
                rt.block_on(graph.add_edges_batch(&edges)).unwrap();
                black_box(graph.edge_count());
            });
        });

        rt.block_on(graph.close()).unwrap();
    }

    // Deep chain: 1000-node linear chain, traverse full depth
    {
        let dir = TempDir::new().unwrap();
        let store = rt.block_on(open_store(dir.path()));
        let mut graph = rt.block_on(Graph::load(store)).unwrap();

        let chain: Vec<(String, EdgeKind, String)> = (0..1_000)
            .map(|i| {
                (
                    format!("file:chain/{i}.rs"),
                    EdgeKind::Imports,
                    format!("file:chain/{}.rs", i + 1),
                )
            })
            .collect();
        rt.block_on(graph.add_edges_batch(&chain)).unwrap();

        group.bench_function("linear_chain_1000_traverse", |b| {
            b.iter(|| {
                let result =
                    graph.traverse("file:chain/0.rs", &EdgeKind::Imports, usize::MAX);
                black_box(result.len());
            });
        });

        rt.block_on(graph.close()).unwrap();
    }

    // Dense graph: every node connected to every other (n=100, ~10k edges)
    {
        let dir = TempDir::new().unwrap();
        let store = rt.block_on(open_store(dir.path()));
        let mut graph = rt.block_on(Graph::load(store)).unwrap();

        let n = 100;
        let mut dense_edges = Vec::with_capacity(n * n);
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    dense_edges.push((
                        format!("file:dense/{i}.rs"),
                        EdgeKind::Imports,
                        format!("file:dense/{j}.rs"),
                    ));
                }
            }
        }
        rt.block_on(graph.add_edges_batch(&dense_edges)).unwrap();

        group.bench_function("dense_100_nodes_traverse", |b| {
            b.iter(|| {
                let result =
                    graph.traverse("file:dense/0.rs", &EdgeKind::Imports, usize::MAX);
                black_box(result.len());
            });
        });

        rt.block_on(graph.close()).unwrap();
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 5: extreme scale (env-gated)
// ═══════════════════════════════════════════════════════════════════════════

fn bench_extreme_scale(c: &mut Criterion) {
    if std::env::var("MATI_BENCH_EXTREME").is_err() {
        eprintln!(
            "Skipping extreme_scale benchmarks. Set MATI_BENCH_EXTREME=1 to enable."
        );
        return;
    }

    let mut group = c.benchmark_group("graph_extreme");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(60));

    let rt = rt();

    // 200k edges (~80k files × 2.5 edges/file) — beyond Linux kernel scale
    let n_files = 160_000;
    eprintln!("Generating edges for {n_files} files...");
    let edges = generate_edges(n_files);
    eprintln!("Generated {} edges", edges.len());

    // Batch insert
    group.throughput(Throughput::Elements(edges.len() as u64));
    group.bench_function("batch_insert_200k", |b| {
        b.iter(|| {
            let dir = TempDir::new().unwrap();
            let store = rt.block_on(open_store(dir.path()));
            let mut graph = rt.block_on(Graph::load(store)).unwrap();
            rt.block_on(graph.add_edges_batch(&edges)).unwrap();
            black_box(graph.edge_count());
            rt.block_on(graph.close()).unwrap();
        });
    });

    // Load from KV
    {
        let (dir, n_edges) = rt.block_on(build_persisted_graph(n_files));
        group.throughput(Throughput::Elements(n_edges as u64));

        group.bench_function("load_200k_from_kv", |b| {
            b.iter(|| {
                let store = rt.block_on(open_store(dir.path()));
                let graph = rt.block_on(Graph::load(store)).unwrap();
                black_box(graph.edge_count());
                rt.block_on(graph.close()).unwrap();
            });
        });
    }

    // Traversal in 200k-edge graph
    {
        let dir = TempDir::new().unwrap();
        let store = rt.block_on(open_store(dir.path()));
        let mut graph = rt.block_on(Graph::load(store)).unwrap();
        rt.block_on(graph.add_edges_batch(&edges)).unwrap();

        group.bench_function("traverse_imports_depth5_in_200k", |b| {
            b.iter(|| {
                let result =
                    graph.traverse("file:src/module_0.rs", &EdgeKind::Imports, 5);
                black_box(result.len());
            });
        });

        group.bench_function("traverse_imports_unbounded_in_200k", |b| {
            b.iter(|| {
                let result =
                    graph.traverse("file:src/module_0.rs", &EdgeKind::Imports, usize::MAX);
                black_box(result.len());
            });
        });

        rt.block_on(graph.close()).unwrap();
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Criterion harness
// ═══════════════════════════════════════════════════════════════════════════

criterion_group!(
    benches,
    bench_graph_load,
    bench_edge_batch_insert,
    bench_traversal,
    bench_graph_worst_case,
    bench_extreme_scale,
);
criterion_main!(benches);
