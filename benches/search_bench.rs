//! Criterion benchmark suite for Search (Tantivy BM25 index) — M-05.
//!
//! Stress-tests index build, query latency, and edge cases from 1k to 500k
//! records. Search is synchronous — no tokio runtime needed.
//!
//! Run all (except extreme scale):
//!   cargo bench --bench search_bench
//!
//! Run extreme scale (500k records):
//!   MATI_BENCH_EXTREME=1 cargo bench --bench search_bench extreme_scale

use std::hint::black_box;
use std::time::{SystemTime, UNIX_EPOCH};

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use tempfile::TempDir;
use uuid::Uuid;

use mati_core::search::Search;
use mati_core::store::record::{
    Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore, StalenessTier,
};

// ── Helpers ─────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Build a Record with varied content for realistic BM25 scoring.
fn make_record(i: usize) -> Record {
    let now = now_secs();

    // Vary category and prefix to create realistic distribution
    let (key, category) = match i % 5 {
        0 => (format!("file:src/module_{i}.rs"), Category::File),
        1 => (format!("gotcha:issue-{i}"), Category::Gotcha),
        2 => (format!("decision:arch-{i}"), Category::Decision),
        3 => (format!("dep:package-{i}"), Category::Dependency),
        _ => (format!("dev_note:note-{i}"), Category::DevNote),
    };

    // Vary content to produce realistic BM25 distributions
    let topics = [
        "authentication middleware handles OAuth token validation and session refresh",
        "database connection pooling manages concurrent transactions with retry logic",
        "API rate limiting enforces per-tenant quotas with sliding window algorithm",
        "file parser extracts structural metadata from source code using tree-sitter",
        "graph traversal discovers transitive dependencies between modules",
        "search index maintains BM25 scores across full-text record corpus",
        "hook enforcement intercepts file reads and injects relevant gotchas",
        "configuration loader reads YAML and validates schema constraints",
        "deployment pipeline stages builds through lint test integration release",
        "error handling propagates context through anyhow Result chain",
    ];
    let topic = topics[i % topics.len()];

    Record {
        key,
        value: format!(
            "{topic}. Component {i} processes data through the pipeline with \
             entry points handle_{i} and transform_{i}. Critical for system \
             reliability and performance under load."
        ),
        category,
        priority: match i % 4 {
            0 => Priority::Low,
            1 => Priority::Normal,
            2 => Priority::High,
            _ => Priority::Critical,
        },
        tags: vec![
            format!("tag_{}", i % 20),
            format!("team_{}", i % 5),
            topics[i % topics.len()].split_whitespace().next().unwrap().to_string(),
        ],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore {
            value: 0.0,
            tier: StalenessTier::Fresh,
            signals: vec![],
            computed_at: now,
            last_record_sha: String::new(),
        },
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: Uuid::nil(),
            logical_clock: i as u64,
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

fn generate_records(n: usize) -> Vec<Record> {
    (0..n).map(make_record).collect()
}

/// Open search index in a temp dir, bulk-index records, return (TempDir, Search).
fn build_index(records: &[Record]) -> (TempDir, Search) {
    let dir = TempDir::new().unwrap();
    let search = Search::open(&dir.path().join("index")).unwrap();
    let refs: Vec<&Record> = records.iter().collect();
    search.add_records(&refs).unwrap();
    (dir, search)
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 1: index build
// ═══════════════════════════════════════════════════════════════════════════

fn bench_index_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("search_build");
    group.sample_size(10);

    for &(label, size) in &[
        ("1k", 1_000),
        ("10k", 10_000),
        ("50k", 50_000),
    ] {
        let records = generate_records(size);
        group.throughput(Throughput::Elements(size as u64));

        group.bench_with_input(
            BenchmarkId::new("add_records", label),
            &records,
            |b, records| {
                b.iter(|| {
                    let dir = TempDir::new().unwrap();
                    let search = Search::open(&dir.path().join("index")).unwrap();
                    let refs: Vec<&Record> = records.iter().collect();
                    let count = search.add_records(&refs).unwrap();
                    black_box(count);
                    search.close().unwrap();
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 2: query latency
// ═══════════════════════════════════════════════════════════════════════════

fn bench_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("search_query");

    let queries = [
        "authentication middleware OAuth",
        "database connection pooling",
        "file parser tree-sitter",
        "graph traversal dependencies",
        "API rate limiting",
        "error handling anyhow",
        "deployment pipeline",
        "hook enforcement gotcha",
    ];

    for &(label, size) in &[
        ("1k", 1_000),
        ("10k", 10_000),
        ("50k", 50_000),
    ] {
        let records = generate_records(size);
        let (_dir, search) = build_index(&records);

        // Standard query (limit=10)
        group.bench_with_input(
            BenchmarkId::new("top10", label),
            &search,
            |b, search| {
                let mut idx = 0usize;
                b.iter(|| {
                    let q = queries[idx % queries.len()];
                    let keys = search.query_keys(q, 10).unwrap();
                    black_box(keys.len());
                    idx += 1;
                });
            },
        );

        // Large limit (100 results)
        group.bench_with_input(
            BenchmarkId::new("top100", label),
            &search,
            |b, search| {
                let mut idx = 0usize;
                b.iter(|| {
                    let q = queries[idx % queries.len()];
                    let keys = search.query_keys(q, 100).unwrap();
                    black_box(keys.len());
                    idx += 1;
                });
            },
        );

        // Single-term query
        group.bench_with_input(
            BenchmarkId::new("single_term", label),
            &search,
            |b, search| {
                b.iter(|| {
                    let keys = search.query_keys("authentication", 10).unwrap();
                    black_box(keys.len());
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 3: worst case
// ═══════════════════════════════════════════════════════════════════════════

fn bench_search_worst_case(c: &mut Criterion) {
    let mut group = c.benchmark_group("search_worst_case");

    let records = generate_records(50_000);
    let (_dir, search) = build_index(&records);

    // No matches — tantivy scans index, returns empty
    group.bench_function("no_matches_50k", |b| {
        b.iter(|| {
            let keys = search
                .query_keys("xyzzyplugh zyxwvuts completely nonexistent gibberish", 10)
                .unwrap();
            black_box(keys.len());
        });
    });

    // Very high limit (1000) — forces tantivy to score and rank many docs
    group.bench_function("top1000_50k", |b| {
        b.iter(|| {
            let keys = search
                .query_keys("authentication middleware", 1_000)
                .unwrap();
            black_box(keys.len());
        });
    });

    // Long query string — many terms to parse and intersect
    group.bench_function("long_query_50k", |b| {
        b.iter(|| {
            let keys = search
                .query_keys(
                    "authentication middleware OAuth token validation session \
                     refresh database connection pooling concurrent transactions \
                     retry logic API rate limiting",
                    10,
                )
                .unwrap();
            black_box(keys.len());
        });
    });

    // Malformed query — tests lenient parsing overhead
    group.bench_function("malformed_query_50k", |b| {
        b.iter(|| {
            let keys = search
                .query_keys("(unclosed AND OR authentication +middleware -", 10)
                .unwrap();
            black_box(keys.len());
        });
    });

    // Single-character query (high fan-out in inverted index)
    group.bench_function("single_char_query_50k", |b| {
        b.iter(|| {
            let keys = search.query_keys("a", 10).unwrap();
            black_box(keys.len());
        });
    });

    // Read-after-write: add record then immediately query
    group.bench_function("read_after_write", |b| {
        let mut i = 900_000usize;
        b.iter(|| {
            let r = make_record(i);
            search.add_record(&r).unwrap();
            let keys = search.query_keys(&r.key, 1).unwrap();
            black_box(keys.len());
            i += 1;
        });
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 4: extreme scale (env-gated)
// ═══════════════════════════════════════════════════════════════════════════

fn bench_extreme_scale(c: &mut Criterion) {
    if std::env::var("MATI_BENCH_EXTREME").is_err() {
        eprintln!(
            "Skipping extreme_scale benchmarks. Set MATI_BENCH_EXTREME=1 to enable."
        );
        return;
    }

    let mut group = c.benchmark_group("search_extreme");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(60));

    // 500k records — well beyond any realistic mati deployment
    eprintln!("Generating 500k records...");
    let records = generate_records(500_000);

    // Index build
    group.throughput(Throughput::Elements(500_000));
    group.bench_function("build_index_500k", |b| {
        b.iter(|| {
            let dir = TempDir::new().unwrap();
            let search = Search::open(&dir.path().join("index")).unwrap();
            let refs: Vec<&Record> = records.iter().collect();
            let count = search.add_records(&refs).unwrap();
            black_box(count);
            search.close().unwrap();
        });
    });

    // Query in 500k
    {
        let (_dir, search) = build_index(&records);

        group.bench_function("query_top10_in_500k", |b| {
            b.iter(|| {
                let keys = search
                    .query_keys("authentication middleware OAuth", 10)
                    .unwrap();
                black_box(keys.len());
            });
        });

        group.bench_function("query_top1000_in_500k", |b| {
            b.iter(|| {
                let keys = search
                    .query_keys("database connection pooling", 1_000)
                    .unwrap();
                black_box(keys.len());
            });
        });

        group.bench_function("query_no_matches_in_500k", |b| {
            b.iter(|| {
                let keys = search
                    .query_keys("xyzzyplugh nonexistent gibberish", 10)
                    .unwrap();
                black_box(keys.len());
            });
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Criterion harness
// ═══════════════════════════════════════════════════════════════════════════

criterion_group!(
    benches,
    bench_index_build,
    bench_query,
    bench_search_worst_case,
    bench_extreme_scale,
);
criterion_main!(benches);
