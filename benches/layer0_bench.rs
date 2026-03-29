//! Criterion benchmark suite for Layer 0 init pipeline — M-06.
//!
//! This suite is intentionally stage-separated so regressions point at one
//! bottleneck instead of hiding inside a single end-to-end number.
//!
//! Run the default set:
//!   cargo bench --bench layer0_bench
//!
//! Run the 80k-file kernel-scale set:
//!   MATI_BENCH_LAYER0_KERNEL=1 cargo bench --bench layer0_bench kernel_scale
//!
//! # Persistence optimization results (2026-03-17)
//!
//! The tantivy decomposition benchmarks (groups 11–13) identified per-commit
//! overhead as the dominant cost in `search_add_records`. Each `commit()` costs
//! ~140ms fixed (segment flush + meta update + merge policy + GC). With
//! COMMIT_CHUNK=1000, 10k records paid 10 × 140ms = 1,400ms in commit overhead.
//!
//! Two changes to `src/search/index.rs`:
//! - **Single commit per batch**: stage all docs, commit once at the end.
//!   Safe because `mati init` is idempotent — a failed init is re-run.
//! - **Writer heap 15MB → 50MB**: enables 3 worker threads for parallel
//!   tokenization. 50MB was the sweet spot — 120MB (8 threads) was slower
//!   at both batch sizes due to thread coordination overhead.
//!
//! Results at 10k records:
//!
//! ```text
//! search_add_records/10k:  1,550ms → 203ms   (7.6× faster)
//! store_put_batch/10k:     1,710ms → 358ms   (4.8× faster)
//! ```
//!
//! The 250-file case regressed from 91ms to 193ms (2.1×) due to the fixed
//! cost of spawning 3 worker threads. Acceptable — 193ms is well under the
//! 200ms Layer 0 budget (P7), and small repos are not the optimization target.
//!
//! Decomposition that led to this (tantivy_* groups at 10k, 15MB baseline):
//!
//! ```text
//! stage-only (no commit):     81ms   — doc construction + tokenization
//! commit-only (1 commit):    118ms   — segment flush + fsync + meta
//! chunk/100  (100 commits): 15.2s    — commit overhead dominates
//! chunk/1000  (10 commits):  1.54s   — previous COMMIT_CHUNK
//! chunk/10000  (1 commit):   221ms   — theoretical minimum at 15MB/1 thread
//! ```
//!
//! KV-only isolation (`put_batch_raw/10k` = 151ms) confirmed SurrealKV is
//! <9% of the combined persist cost. Concurrent KV+tantivy redesign was
//! rejected — max overlap gain of 151ms did not justify the complexity of
//! Arc<Search>, owned batch data, and two-phase failure semantics.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::hint::black_box;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use git2::{IndexAddOption, Repository, Signature};
use tantivy::schema::{NumericOptions, Schema, FAST, STORED, STRING, TEXT};
use tantivy::{Index, IndexWriter, TantivyDocument};
use tempfile::TempDir;
use uuid::Uuid;

use mati_core::analysis::{
    build_file_records, mine_git_history, parse_dependencies, parse_files_parallel, WalkedFile,
    Walker,
};
use mati_core::search::Search;
use mati_core::store::record::{Category, Priority, Record};
use mati_core::store::Store;

// ── Scale configurations ────────────────────────────────────────────────────

const SMALL: usize = 250;
const MEDIUM: usize = 10_000;
const KERNEL: usize = 80_000;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

struct HomeGuard {
    original: Option<std::ffi::OsString>,
}

impl HomeGuard {
    fn set(temp_home: &Path) -> Self {
        let original = std::env::var_os("HOME");
        std::env::set_var("HOME", temp_home);
        Self { original }
    }
}

impl Drop for HomeGuard {
    fn drop(&mut self) {
        match self.original.take() {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }
}

fn make_record_from_file(file: &WalkedFile, logical_clock: u64) -> Record {
    Record::layer0_file_stub(
        format!("file:{}", file.rel_path),
        Uuid::nil(),
        logical_clock,
        now_secs(),
    )
}

fn commit_snapshot(repo: &Repository, message: &str) {
    let sig = Signature::now("mati-bench", "bench@mati.dev").unwrap();
    let mut index = repo.index().unwrap();
    index
        .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
        .unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();

    let mut parent_commits = Vec::new();
    if let Ok(head) = repo.head() {
        if let Some(oid) = head.target() {
            parent_commits.push(repo.find_commit(oid).unwrap());
        }
    }
    let parent_refs: Vec<&git2::Commit<'_>> = parent_commits.iter().collect();

    repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parent_refs)
        .unwrap();
}

fn append_git_comment(path: &Path, commit_idx: usize) {
    let comment = match path.extension().and_then(|s| s.to_str()) {
        Some("py") => "#",
        Some("toml") => "#",
        Some("json") | Some("yaml") | Some("yml") | Some("md") => "#",
        _ => "//",
    };
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    writeln!(file, "{comment} bench commit {commit_idx}").unwrap();
}

fn manifest_contents() -> [(&'static str, &'static str); 3] {
    [
        (
            "Cargo.toml",
            r#"[package]
name = "layer0-bench"
version = "0.1.0"

[dependencies]
serde = "1"
criterion = "0.5"
"#,
        ),
        (
            "package.json",
            r#"{
  "name": "layer0-bench",
  "version": "0.1.0",
  "dependencies": {
    "react": "^18.0.0",
    "typescript": "^5.0.0"
  }
}
"#,
        ),
        (
            "go.mod",
            r#"module example.com/layer0-bench

go 1.22

require (
    github.com/google/uuid v1.6.0
)
"#,
        ),
    ]
}

fn rust_source(i: usize) -> String {
    format!(
        r#"use std::collections::HashMap;
use anyhow::Result;

pub struct Item{i} {{
    pub id: u64,
}}

// TODO: trim benchmark helper {i}
pub fn run_{i}(input: &str) -> Result<String> {{
    if input.is_empty() {{
        return Ok(String::new());
    }}
    let parsed = input.parse::<u64>().unwrap();
    unsafe {{
        let _ = *input.as_ptr();
    }}
    Ok(format!("{{}}:{{parsed}}", input))
}}
"#
    )
}

fn typescript_source(i: usize) -> String {
    format!(
        r#"import {{ helper_{i} }} from "./helper_{i}";

export interface Config{i} {{
  name: string;
  timeout: number;
}}

// TODO: tighten transform {i}
export function transform_{i}(items: string[]): string[] {{
  if (items.length === 0) {{
    return [];
  }}
  return items.map(item => item.toUpperCase());
}}
"#
    )
}

fn python_source(i: usize) -> String {
    format!(
        r#"# TODO: tidy benchmark helper {i}
def compute_{i}(value: int) -> int:
    if value < 0:
        return 0
    return value * 2
"#
    )
}

fn other_source(i: usize) -> String {
    format!("# generated doc {i}\n\nThis file exists to keep the file mix realistic.\n")
}

struct Layer0Fixture {
    _dir: TempDir,
    root: PathBuf,
    files: Vec<WalkedFile>,
    walked_paths: HashSet<String>,
    analyses: Vec<mati_core::analysis::StaticFileAnalysis>,
    git: mati_core::analysis::GitSignals,
    records: Vec<Record>,
}

impl Layer0Fixture {
    fn prepare(file_count: usize, commit_count: usize) -> Self {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();

        for d in [
            "src/core",
            "src/api",
            "src/cli",
            "lib/services",
            "lib/models",
            "tests/unit",
            "docs",
        ] {
            fs::create_dir_all(root.join(d)).unwrap();
        }

        let mut source_paths = Vec::new();
        for i in 0..file_count {
            let bucket = match i % 7 {
                0 => "src/core",
                1 => "src/api",
                2 => "src/cli",
                3 => "lib/services",
                4 => "lib/models",
                5 => "tests/unit",
                _ => "docs",
            };

            let (rel_path, content) = match i % 20 {
                0..=7 => {
                    let rel = format!("{bucket}/module_{i}.rs");
                    source_paths.push(rel.clone());
                    (rel, rust_source(i))
                }
                8..=13 => {
                    let rel = format!("{bucket}/service_{i}.ts");
                    source_paths.push(rel.clone());
                    (rel, typescript_source(i))
                }
                14..=17 => {
                    let rel = format!("{bucket}/handler_{i}.py");
                    source_paths.push(rel.clone());
                    (rel, python_source(i))
                }
                _ => {
                    let rel = format!("{bucket}/note_{i}.md");
                    (rel, other_source(i))
                }
            };

            let abs = root.join(&rel_path);
            if let Some(parent) = abs.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(abs, content).unwrap();
        }

        for (name, content) in manifest_contents() {
            fs::write(root.join(name), content).unwrap();
        }

        let repo = Repository::init(&root).unwrap();
        commit_snapshot(&repo, "initial snapshot");

        if !source_paths.is_empty() {
            let hot_span = source_paths.len().clamp(1, 128);
            for commit_idx in 0..commit_count {
                for offset in 0..8 {
                    let idx = (commit_idx * 8 + offset) % hot_span;
                    let rel = &source_paths[idx];
                    append_git_comment(&root.join(rel), commit_idx);
                }
                commit_snapshot(&repo, &format!("bench commit {commit_idx}"));
            }
        }

        let walker = Walker::new(&root);
        let files = walker.walk().unwrap();
        let walked_paths = files
            .iter()
            .map(|f| f.rel_path.clone())
            .collect::<HashSet<_>>();
        let analyses = parse_files_parallel(&files);
        let git = mine_git_history(&root, &walked_paths).unwrap();
        let _deps = parse_dependencies(&root, &files).unwrap();
        let _file_records = build_file_records(&files, &analyses, Some(&git), now_secs());
        let records = files
            .iter()
            .enumerate()
            .map(|(idx, file)| make_record_from_file(file, idx as u64))
            .collect::<Vec<_>>();

        Self {
            _dir: dir,
            root,
            files,
            walked_paths,
            analyses,
            git,
            records,
        }
    }
}

fn commit_count_for(file_count: usize) -> usize {
    (file_count / 100).clamp(24, 200)
}

fn layer0_sizes() -> Vec<(&'static str, usize)> {
    let mut sizes = vec![("250", SMALL), ("10k", MEDIUM)];
    if std::env::var("MATI_BENCH_LAYER0_KERNEL").is_ok() {
        sizes.push(("80k", KERNEL));
    }
    sizes
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 1: walk
// ═══════════════════════════════════════════════════════════════════════════

fn bench_walk(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer0_walk");
    group.sample_size(20);

    for (label, size) in layer0_sizes() {
        let fixture = Layer0Fixture::prepare(size, commit_count_for(size));
        group.throughput(Throughput::Elements(fixture.files.len() as u64));

        group.bench_with_input(BenchmarkId::new("walker", label), &fixture, |b, fixture| {
            b.iter(|| {
                let files = Walker::new(&fixture.root).walk().unwrap();
                black_box(files.len());
            });
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 2: parse
// ═══════════════════════════════════════════════════════════════════════════

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer0_parse");
    group.sample_size(20);

    for (label, size) in layer0_sizes() {
        let fixture = Layer0Fixture::prepare(size, commit_count_for(size));
        group.throughput(Throughput::Elements(fixture.files.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("parse_parallel", label),
            &fixture,
            |b, fixture| {
                b.iter(|| {
                    let analyses = parse_files_parallel(&fixture.files);
                    black_box(analyses.len());
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 3: git mining
// ═══════════════════════════════════════════════════════════════════════════

fn bench_git(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer0_git");
    group.sample_size(10);

    for (label, size) in layer0_sizes() {
        let fixture = Layer0Fixture::prepare(size, commit_count_for(size));
        group.throughput(Throughput::Elements(fixture.walked_paths.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("mine_git_history", label),
            &fixture,
            |b, fixture| {
                b.iter(|| {
                    let signals = mine_git_history(&fixture.root, &fixture.walked_paths).unwrap();
                    black_box(signals.change_frequency.len());
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 4: dependency parsing
// ═══════════════════════════════════════════════════════════════════════════

fn bench_deps(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer0_deps");
    group.sample_size(20);

    for (label, size) in layer0_sizes() {
        let fixture = Layer0Fixture::prepare(size, commit_count_for(size));
        group.throughput(Throughput::Elements(fixture.files.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("parse_dependencies", label),
            &fixture,
            |b, fixture| {
                b.iter(|| {
                    let deps = parse_dependencies(&fixture.root, &fixture.files).unwrap();
                    black_box(deps.deps.len());
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 5: file record materialization
// ═══════════════════════════════════════════════════════════════════════════

fn bench_materialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer0_materialize");
    group.sample_size(20);

    for (label, size) in layer0_sizes() {
        let fixture = Layer0Fixture::prepare(size, commit_count_for(size));
        group.throughput(Throughput::Elements(fixture.files.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("build_file_records", label),
            &fixture,
            |b, fixture| {
                b.iter(|| {
                    let records = build_file_records(
                        &fixture.files,
                        &fixture.analyses,
                        Some(&fixture.git),
                        now_secs(),
                    );
                    black_box(records.len());
                    black_box(records[0].token_cost_estimate);
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 6: layer-0 persistence
// ═══════════════════════════════════════════════════════════════════════════

fn bench_persist(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer0_persist");
    group.sample_size(10);

    let rt = rt();

    for (label, size) in layer0_sizes() {
        let fixture = Layer0Fixture::prepare(size, commit_count_for(size));
        group.throughput(Throughput::Elements(fixture.records.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("store_put_batch", label),
            &fixture,
            |b, fixture| {
                b.iter_batched(
                    || TempDir::new().unwrap(),
                    |dir| {
                        rt.block_on(async {
                            let home = TempDir::new().unwrap();
                            let _home_guard = HomeGuard::set(home.path());
                            let store = Store::open(dir.path()).await.unwrap();
                            let batch: Vec<(&str, &Record)> = fixture
                                .records
                                .iter()
                                .map(|record| (record.key.as_str(), record))
                                .collect();
                            store.put_batch(&batch).await.unwrap();
                            store.close().await.unwrap();
                        });
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 7: search-index writes during layer-0 persistence
// ═══════════════════════════════════════════════════════════════════════════

fn bench_search_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer0_search_write");
    group.sample_size(10);

    for (label, size) in layer0_sizes() {
        let fixture = Layer0Fixture::prepare(size, commit_count_for(size));
        group.throughput(Throughput::Elements(fixture.records.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("search_add_records", label),
            &fixture,
            |b, fixture| {
                b.iter_batched(
                    || TempDir::new().unwrap(),
                    |dir| {
                        let search = Search::open(&dir.path().join("search_index")).unwrap();
                        let refs: Vec<&Record> = fixture.records.iter().collect();
                        let committed = search.add_records(&refs).unwrap();
                        black_box(committed);
                        search.close().unwrap();
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 8: store close
// ═══════════════════════════════════════════════════════════════════════════

fn bench_store_close(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer0_store_close");
    group.sample_size(10);

    let rt = rt();

    for (label, size) in layer0_sizes() {
        let fixture = Layer0Fixture::prepare(size, commit_count_for(size));
        group.throughput(Throughput::Elements(fixture.records.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("store_close", label),
            &fixture,
            |b, _fixture| {
                b.iter_batched(
                    || {
                        let dir = TempDir::new().unwrap();
                        let home = TempDir::new().unwrap();
                        let home_guard = HomeGuard::set(home.path());
                        let store = rt.block_on(Store::open(dir.path())).unwrap();
                        (store, home, home_guard)
                    },
                    |(store, _home, _home_guard)| {
                        rt.block_on(store.close()).unwrap();
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 9: full analysis bundle
// ═══════════════════════════════════════════════════════════════════════════

fn bench_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer0_full");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    for (label, size) in layer0_sizes() {
        let fixture = Layer0Fixture::prepare(size, commit_count_for(size));
        group.throughput(Throughput::Elements(fixture.files.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("walk_parse_git_deps_materialize", label),
            &fixture,
            |b, fixture| {
                b.iter(|| {
                    let files = Walker::new(&fixture.root).walk().unwrap();
                    let analyses = parse_files_parallel(&files);
                    let git = mine_git_history(&fixture.root, &fixture.walked_paths).unwrap();
                    let deps = parse_dependencies(&fixture.root, &files).unwrap();
                    let records = build_file_records(&files, &analyses, Some(&git), now_secs());

                    black_box(files.len());
                    black_box(analyses.len());
                    black_box(git.change_frequency.len());
                    black_box(deps.deps.len());
                    black_box(records.len());
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 10: KV-only persistence (no tantivy indexing)
// ═══════════════════════════════════════════════════════════════════════════

fn bench_persist_kv_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer0_persist_kv_only");
    group.sample_size(10);

    let rt = rt();

    for (label, size) in layer0_sizes() {
        let fixture = Layer0Fixture::prepare(size, commit_count_for(size));
        group.throughput(Throughput::Elements(fixture.records.len() as u64));

        // Pre-serialize records once — this is the same work put_batch does
        // before handing bytes to the transaction.
        let serialized: Vec<(String, Vec<u8>)> = fixture
            .records
            .iter()
            .map(|r| (r.key.clone(), serde_json::to_vec(r).unwrap()))
            .collect();

        group.bench_with_input(
            BenchmarkId::new("store_put_batch_raw", label),
            &serialized,
            |b, serialized| {
                b.iter_batched(
                    || TempDir::new().unwrap(),
                    |dir| {
                        rt.block_on(async {
                            let home = TempDir::new().unwrap();
                            let _home_guard = HomeGuard::set(home.path());
                            let store = Store::open(dir.path()).await.unwrap();
                            let batch: Vec<(&str, &[u8])> = serialized
                                .iter()
                                .map(|(k, v)| (k.as_str(), v.as_slice()))
                                .collect();
                            store.put_batch_raw(&batch).await.unwrap();
                            store.close().await.unwrap();
                        });
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Tantivy decomposition helpers — bypass Search wrapper for precise measurement
// ═══════════════════════════════════════════════════════════════════════════

/// Tantivy field handles for benchmark doc construction.
/// Mirrors `search::index::Fields` exactly — same schema, same field order.
#[derive(Clone, Copy)]
struct BenchFields {
    key: tantivy::schema::Field,
    value: tantivy::schema::Field,
    category: tantivy::schema::Field,
    tags: tantivy::schema::Field,
    priority: tantivy::schema::Field,
    updated_at: tantivy::schema::Field,
}

/// Build the same schema as `search::index::schema()`.
fn bench_schema() -> (Schema, BenchFields) {
    let mut b = Schema::builder();
    let key = b.add_text_field("key", TEXT | STORED);
    let value = b.add_text_field("value", TEXT | STORED);
    let category = b.add_text_field("category", STRING | STORED | FAST);
    let tags = b.add_text_field("tags", TEXT | STORED);
    let priority = b.add_u64_field(
        "priority",
        NumericOptions::default().set_stored().set_fast(),
    );
    let updated_at = b.add_u64_field(
        "updated_at",
        NumericOptions::default().set_stored().set_fast(),
    );
    (
        b.build(),
        BenchFields {
            key,
            value,
            category,
            tags,
            priority,
            updated_at,
        },
    )
}

/// Same conversion as `search::index::record_to_doc`.
fn bench_record_to_doc(record: &Record, f: &BenchFields) -> TantivyDocument {
    let mut doc = TantivyDocument::default();
    doc.add_text(f.key, &record.key);
    doc.add_text(f.value, &record.value);
    doc.add_text(
        f.category,
        match &record.category {
            Category::Gotcha => "gotcha",
            Category::File => "file",
            Category::Decision => "decision",
            Category::Stage => "stage",
            Category::Dependency => "dependency",
            Category::DevNote => "dev_note",
            Category::Session => "session",
            Category::Analytics => "analytics",
        },
    );
    doc.add_text(f.tags, record.tags.join(" "));
    doc.add_u64(
        f.priority,
        match &record.priority {
            Priority::Low => 0,
            Priority::Normal => 1,
            Priority::High => 2,
            Priority::Critical => 3,
        },
    );
    doc.add_u64(f.updated_at, record.updated_at);
    doc
}

/// Create a tantivy index + writer in a temp dir, matching Search::open config.
fn bench_open_writer(dir: &Path) -> (Index, IndexWriter, BenchFields) {
    std::fs::create_dir_all(dir).unwrap();
    let (schema, fields) = bench_schema();
    let index = Index::create_in_dir(dir, schema).unwrap();
    let writer = index.writer(15_000_000).unwrap();
    (index, writer, fields)
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 11: tantivy stage-only (add_document × N, no commit)
// ═══════════════════════════════════════════════════════════════════════════

fn bench_search_stage_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("tantivy_stage_only");
    group.sample_size(10);

    for (label, size) in layer0_sizes() {
        let fixture = Layer0Fixture::prepare(size, commit_count_for(size));
        group.throughput(Throughput::Elements(fixture.records.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("add_document_no_commit", label),
            &fixture,
            |b, fixture| {
                b.iter_batched(
                    || {
                        let dir = TempDir::new().unwrap();
                        let (_, writer, fields) = bench_open_writer(&dir.path().join("idx"));
                        (writer, fields, dir)
                    },
                    |(mut writer, fields, _dir)| {
                        for record in &fixture.records {
                            writer
                                .add_document(bench_record_to_doc(record, &fields))
                                .unwrap();
                        }
                        // No commit — measure only doc construction + staging.
                        // Rollback to release the segment cleanly.
                        writer.rollback().unwrap();
                        black_box(fixture.records.len());
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 12: tantivy commit-only (stage in setup, measure commit)
// ═══════════════════════════════════════════════════════════════════════════

fn bench_search_commit_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("tantivy_commit_only");
    group.sample_size(10);

    // Fixed 1000-doc batch matching COMMIT_CHUNK, and also 10k to see
    // how commit cost scales with staged doc count.
    let commit_sizes: Vec<(&str, usize)> = vec![("1k", 1_000), ("10k", 10_000)];

    for (label, size) in &commit_sizes {
        let fixture = Layer0Fixture::prepare(*size, commit_count_for(*size));
        group.throughput(Throughput::Elements(fixture.records.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("commit_after_stage", label),
            &fixture,
            |b, fixture| {
                b.iter_batched(
                    || {
                        // Setup: create index, stage all docs (not timed).
                        let dir = TempDir::new().unwrap();
                        let (_, writer, fields) = bench_open_writer(&dir.path().join("idx"));
                        for record in &fixture.records {
                            writer
                                .add_document(bench_record_to_doc(record, &fields))
                                .unwrap();
                        }
                        (writer, dir)
                    },
                    |(mut writer, _dir)| {
                        // Measured: only the commit.
                        writer.commit().unwrap();
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 13: COMMIT_CHUNK sweep — vary docs-per-commit at 10k total
// ═══════════════════════════════════════════════════════════════════════════

fn bench_search_chunk_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("tantivy_chunk_sweep");
    group.sample_size(10);

    let fixture = Layer0Fixture::prepare(MEDIUM, commit_count_for(MEDIUM));
    let total = fixture.records.len();
    group.throughput(Throughput::Elements(total as u64));

    for chunk_size in [100, 500, 1_000, 5_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("chunk", chunk_size),
            &fixture,
            |b, fixture| {
                b.iter_batched(
                    || {
                        let dir = TempDir::new().unwrap();
                        let (_, writer, fields) = bench_open_writer(&dir.path().join("idx"));
                        (writer, fields, dir)
                    },
                    |(mut writer, fields, _dir)| {
                        let mut committed = 0usize;
                        for chunk in fixture.records.chunks(chunk_size) {
                            for record in chunk {
                                writer
                                    .add_document(bench_record_to_doc(record, &fields))
                                    .unwrap();
                            }
                            writer.commit().unwrap();
                            committed += chunk.len();
                        }
                        black_box(committed);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_walk,
    bench_parse,
    bench_git,
    bench_deps,
    bench_materialize,
    bench_persist,
    bench_search_write,
    bench_store_close,
    bench_full,
    bench_persist_kv_only,
    bench_search_stage_only,
    bench_search_commit_only,
    bench_search_chunk_sweep,
);
criterion_main!(benches);
