//! Criterion benchmark suite for Store (SurrealKV + Tantivy) — M-03/M-05.
//!
//! Stress-tests the storage layer at scales from 1k to 500k records,
//! measuring put/get/batch/scan/search/ping latency under realistic
//! and worst-case conditions.
//!
//! Run all (except extreme scale):
//!   cargo bench --bench store_bench
//!
//! Run extreme scale (500k records, ~2GB disk):
//!   MATI_BENCH_EXTREME=1 cargo bench --bench store_bench extreme_scale

use std::hint::black_box;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use tempfile::TempDir;
use uuid::Uuid;

use mati_core::store::record::{
    Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore, StalenessTier,
};
use mati_core::store::Store;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Build a minimal Record for benchmarking. Varies key/value/category per index.
fn make_record(i: usize, category: Category, prefix: &str) -> (String, Record) {
    let key = format!("{prefix}{i}");
    let now = now_secs();
    let record = Record {
        key: key.clone(),
        value: format!(
            "This is record number {i} in category {:?}. It contains some text \
             for BM25 indexing and measures write throughput. The purpose field \
             describes what this component does in the system architecture. \
             Entry points include process_{i}, handle_{i}, and transform_{i}.",
            category
        ),
        category,
        priority: match i % 4 {
            0 => Priority::Low,
            1 => Priority::Normal,
            2 => Priority::High,
            _ => Priority::Critical,
        },
        tags: vec![
            format!("tag_{}", i % 10),
            format!("module_{}", i % 50),
            "bench".to_string(),
        ],
        created_at: now,
        updated_at: now,
        ref_url: if i % 5 == 0 {
            Some(format!("https://github.com/example/pr/{i}"))
        } else {
            None
        },
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
    };
    (key, record)
}

/// Generate records with realistic category distribution.
fn generate_records(n: usize) -> Vec<(String, Record)> {
    (0..n)
        .map(|i| {
            let pct = (i * 100) / n.max(1);
            if pct < 50 {
                make_record(i, Category::File, "file:src/module_")
            } else if pct < 70 {
                make_record(i, Category::Gotcha, "gotcha:issue-")
            } else if pct < 85 {
                make_record(i, Category::Decision, "decision:arch-")
            } else if pct < 90 {
                make_record(i, Category::Dependency, "dep:pkg-")
            } else if pct < 95 {
                make_record(i, Category::DevNote, "dev_note:note-")
            } else {
                make_record(i, Category::Session, "session:sess-")
            }
        })
        .collect()
}

/// Create a tokio runtime for async benchmarks.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Open a store in a temp directory (not the real ~/.mati/).
/// Store::open expects a repo root and derives ~/.mati/<slug>/ from it.
/// For benchmarks we use each temp dir as a unique "repo root".
async fn open_store(dir: &Path) -> Store {
    Store::open(dir).await.unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 1: single operations
// ═══════════════════════════════════════════════════════════════════════════

fn bench_single_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_single");

    let rt = rt();
    let dir = TempDir::new().unwrap();
    let store = rt.block_on(open_store(dir.path()));

    // Seed 1000 records so get/search have data
    let seed = generate_records(1_000);
    let batch: Vec<(&str, &Record)> = seed.iter().map(|(k, r)| (k.as_str(), r)).collect();
    rt.block_on(store.put_batch(&batch)).unwrap();

    // ping
    group.bench_function("ping", |b| {
        b.iter(|| {
            let latency = rt.block_on(store.ping()).unwrap();
            black_box(latency);
        });
    });

    // single put (Immediate durability — fsync)
    group.bench_function("put_single_immediate", |b| {
        let mut i = 100_000usize;
        b.iter(|| {
            let (key, record) = make_record(i, Category::Gotcha, "gotcha:bench-put-");
            rt.block_on(store.put(&key, &record)).unwrap();
            i += 1;
            black_box(());
        });
    });

    // single put (Eventual durability — no fsync)
    group.bench_function("put_single_eventual", |b| {
        let mut i = 200_000usize;
        b.iter(|| {
            let (key, record) = make_record(i, Category::Session, "session:bench-put-");
            rt.block_on(store.put(&key, &record)).unwrap();
            i += 1;
            black_box(());
        });
    });

    // single get (existing key)
    group.bench_function("get_existing", |b| {
        let key = &seed[500].0;
        b.iter(|| {
            let record = rt.block_on(store.get(key)).unwrap();
            black_box(record);
        });
    });

    // single get (missing key)
    group.bench_function("get_missing", |b| {
        b.iter(|| {
            let record = rt.block_on(store.get("file:nonexistent/path.rs")).unwrap();
            black_box(record);
        });
    });

    // search (BM25 query)
    group.bench_function("search_bm25", |b| {
        b.iter(|| {
            let results = rt.block_on(store.search("process architecture module", 10)).unwrap();
            black_box(results.len());
        });
    });

    // scan_prefix (all file: records)
    group.bench_function("scan_prefix_file", |b| {
        b.iter(|| {
            let records = rt.block_on(store.scan_prefix("file:")).unwrap();
            black_box(records.len());
        });
    });

    rt.block_on(store.close()).unwrap();
    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 2: batch writes at scale
// ═══════════════════════════════════════════════════════════════════════════

fn bench_batch_writes(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_batch");
    group.sample_size(10);

    for &(label, size) in &[
        ("1k", 1_000),
        ("10k", 10_000),
    ] {
        let records = generate_records(size);
        group.throughput(Throughput::Elements(size as u64));

        group.bench_with_input(
            BenchmarkId::new("put_batch", label),
            &records,
            |b, records| {
                let rt = rt();
                b.iter(|| {
                    let dir = TempDir::new().unwrap();
                    let store = rt.block_on(open_store(dir.path()));
                    let batch: Vec<(&str, &Record)> =
                        records.iter().map(|(k, r)| (k.as_str(), r)).collect();
                    rt.block_on(store.put_batch(&batch)).unwrap();
                    black_box(());
                    rt.block_on(store.close()).unwrap();
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 3: read performance at scale
// ═══════════════════════════════════════════════════════════════════════════

fn bench_reads_at_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_reads");

    for &(label, size) in &[
        ("1k", 1_000),
        ("10k", 10_000),
        ("50k", 50_000),
    ] {
        let rt = rt();
        let dir = TempDir::new().unwrap();
        let store = rt.block_on(open_store(dir.path()));
        let records = generate_records(size);
        let batch: Vec<(&str, &Record)> =
            records.iter().map(|(k, r)| (k.as_str(), r)).collect();
        rt.block_on(store.put_batch(&batch)).unwrap();

        // Random get (cycle through keys)
        group.bench_with_input(
            BenchmarkId::new("get_random", label),
            &records,
            |b, records| {
                let mut idx = 0usize;
                b.iter(|| {
                    let key = &records[idx % records.len()].0;
                    let r = rt.block_on(store.get(key)).unwrap();
                    black_box(r);
                    idx += 1;
                });
            },
        );

        // Search under load
        let queries = [
            "process architecture",
            "module system",
            "transform handle",
            "component entry points",
            "issue configuration",
        ];
        group.bench_with_input(
            BenchmarkId::new("search_bm25", label),
            &size,
            |b, _| {
                let mut idx = 0usize;
                b.iter(|| {
                    let q = queries[idx % queries.len()];
                    let results = rt.block_on(store.search(q, 10)).unwrap();
                    black_box(results.len());
                    idx += 1;
                });
            },
        );

        // Full prefix scan
        group.bench_with_input(
            BenchmarkId::new("scan_prefix_all_files", label),
            &size,
            |b, _| {
                b.iter(|| {
                    let records = rt.block_on(store.scan_prefix("file:")).unwrap();
                    black_box(records.len());
                });
            },
        );

        rt.block_on(store.close()).unwrap();
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 4: worst case scenarios
// ═══════════════════════════════════════════════════════════════════════════

fn bench_store_worst_case(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_worst_case");

    let rt = rt();

    // Large value: 100KB record value
    {
        let dir = TempDir::new().unwrap();
        let store = rt.block_on(open_store(dir.path()));

        let large_value = "x".repeat(100_000);
        let now = now_secs();
        let record = Record {
            key: "gotcha:large-value".to_string(),
            value: large_value,
            category: Category::Gotcha,
            priority: Priority::Critical,
            tags: vec!["large".to_string()],
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
                logical_clock: 1,
                wall_clock: now,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
            gap_analysis_score: 0.0,
        };
        rt.block_on(store.put("gotcha:large-value", &record)).unwrap();

        group.bench_function("get_100kb_value", |b| {
            b.iter(|| {
                let r = rt.block_on(store.get("gotcha:large-value")).unwrap();
                black_box(r);
            });
        });

        group.bench_function("put_100kb_value", |b| {
            b.iter(|| {
                rt.block_on(store.put("gotcha:large-value", &record)).unwrap();
                black_box(());
            });
        });

        rt.block_on(store.close()).unwrap();
    }

    // Overwrite storm: same key written 1000 times
    {
        let dir = TempDir::new().unwrap();
        let store = rt.block_on(open_store(dir.path()));

        group.bench_function("overwrite_storm_1000", |b| {
            b.iter(|| {
                for i in 0..1_000 {
                    let (_, record) = make_record(i, Category::Gotcha, "gotcha:overwrite-");
                    rt.block_on(store.put("gotcha:overwrite-target", &record)).unwrap();
                }
                black_box(());
            });
        });

        rt.block_on(store.close()).unwrap();
    }

    // Search with no matches (worst case for tantivy — full scan, zero results)
    {
        let dir = TempDir::new().unwrap();
        let store = rt.block_on(open_store(dir.path()));
        let records = generate_records(10_000);
        let batch: Vec<(&str, &Record)> =
            records.iter().map(|(k, r)| (k.as_str(), r)).collect();
        rt.block_on(store.put_batch(&batch)).unwrap();

        group.bench_function("search_no_matches_10k", |b| {
            b.iter(|| {
                let results = rt
                    .block_on(store.search("xyzzyplugh nonexistent gibberish", 10))
                    .unwrap();
                black_box(results.len());
            });
        });

        // Search with very high limit
        group.bench_function("search_limit_1000_in_10k", |b| {
            b.iter(|| {
                let results = rt
                    .block_on(store.search("process module", 1_000))
                    .unwrap();
                black_box(results.len());
            });
        });

        rt.block_on(store.close()).unwrap();
    }

    // Rebuild search index from 10k records
    {
        let dir = TempDir::new().unwrap();
        let store = rt.block_on(open_store(dir.path()));
        let records = generate_records(10_000);
        let batch: Vec<(&str, &Record)> =
            records.iter().map(|(k, r)| (k.as_str(), r)).collect();
        rt.block_on(store.put_batch(&batch)).unwrap();

        group.sample_size(10);
        group.bench_function("rebuild_search_index_10k", |b| {
            b.iter(|| {
                let count = rt.block_on(store.rebuild_search_index()).unwrap();
                black_box(count);
            });
        });

        rt.block_on(store.close()).unwrap();
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

    let mut group = c.benchmark_group("extreme_scale");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(60));

    let rt = rt();

    // 100k records batch write
    {
        eprintln!("Generating 100k records...");
        let records = generate_records(100_000);
        group.throughput(Throughput::Elements(100_000));

        group.bench_function("put_batch_100k", |b| {
            b.iter(|| {
                let dir = TempDir::new().unwrap();
                let store = rt.block_on(open_store(dir.path()));
                let batch: Vec<(&str, &Record)> =
                    records.iter().map(|(k, r)| (k.as_str(), r)).collect();
                rt.block_on(store.put_batch(&batch)).unwrap();
                black_box(());
                rt.block_on(store.close()).unwrap();
            });
        });
    }

    // 500k records: write + search + scan
    {
        eprintln!("Generating 500k records...");
        let records = generate_records(500_000);
        let dir = TempDir::new().unwrap();
        let store = rt.block_on(open_store(dir.path()));
        eprintln!("Writing 500k records to store...");
        // Write in chunks to avoid memory spike
        for chunk in records.chunks(50_000) {
            let batch: Vec<(&str, &Record)> =
                chunk.iter().map(|(k, r)| (k.as_str(), r)).collect();
            rt.block_on(store.put_batch(&batch)).unwrap();
        }
        eprintln!("500k records written.");

        group.bench_function("get_random_in_500k", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let key = &records[idx % records.len()].0;
                let r = rt.block_on(store.get(key)).unwrap();
                black_box(r);
                idx += 1;
            });
        });

        group.bench_function("search_bm25_in_500k", |b| {
            b.iter(|| {
                let results = rt
                    .block_on(store.search("process architecture module", 10))
                    .unwrap();
                black_box(results.len());
            });
        });

        group.bench_function("scan_prefix_file_in_500k", |b| {
            b.iter(|| {
                let records = rt.block_on(store.scan_prefix("file:")).unwrap();
                black_box(records.len());
            });
        });

        group.bench_function("rebuild_search_index_500k", |b| {
            b.iter(|| {
                let count = rt.block_on(store.rebuild_search_index()).unwrap();
                black_box(count);
            });
        });

        rt.block_on(store.close()).unwrap();
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Criterion harness
// ═══════════════════════════════════════════════════════════════════════════

criterion_group!(
    benches,
    bench_single_ops,
    bench_batch_writes,
    bench_reads_at_scale,
    bench_store_worst_case,
    bench_extreme_scale,
);
criterion_main!(benches);
