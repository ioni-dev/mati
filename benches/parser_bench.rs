//! Criterion benchmark suite for Walker + Parser (M-06-L / M-06-M).
//!
//! Targets:
//! - M-06-L: walk + parse <200ms on 250-file Rust project
//! - M-06-M: walk + parse <5s at Linux kernel scale (80k files)
//!
//! Run all (except kernel scale):
//!   cargo bench --bench parser_bench
//!
//! Run kernel scale (~320MB temp data):
//!   MATI_BENCH_KERNEL=1 cargo bench --bench parser_bench kernel_scale
//!
//! View HTML reports:
//!   open target/criterion/report/index.html

use std::hint::black_box;
use std::path::Path;

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use tempfile::TempDir;

use mati_core::analysis::{parse_file, parse_files_parallel, Walker, WalkedFile};

// ── Scale configurations ────────────────────────────────────────────────────

const SMALL: usize = 50;
const MEDIUM: usize = 250; // M-06-L target
const LARGE: usize = 1_000;
const XL: usize = 5_000;
const KERNEL: usize = 80_000; // M-06-M target

// ═══════════════════════════════════════════════════════════════════════════
// Synthetic data generation
// ═══════════════════════════════════════════════════════════════════════════

mod synth {
    use std::fmt::Write;
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    /// A generated test repository on disk.
    pub struct TestRepo {
        pub _dir: TempDir,
        pub root: PathBuf,
        pub file_count: usize,
        pub total_bytes: u64,
    }

    /// Directory buckets for realistic nesting.
    const DIRS: &[&str] = &[
        "src/core",
        "src/api",
        "src/api/handlers",
        "src/cli",
        "src/utils",
        "lib/models",
        "lib/services",
        "lib/middleware",
        "tests/integration",
        "tests/unit",
        "config",
        "scripts",
    ];

    impl TestRepo {
        /// Generate a test repository with `n` files.
        ///
        /// Language distribution: 40% Rust, 25% TypeScript, 20% Python, 15% other.
        /// For kernel scale, uses smaller files (~4KB avg) for realistic distribution.
        pub fn generate(n: usize) -> Self {
            let kernel_mode = n >= 50_000;
            let dir = TempDir::new().expect("failed to create temp dir");
            let root = dir.path().to_path_buf();
            let mut total_bytes: u64 = 0;

            // Create directory structure
            for d in DIRS {
                fs::create_dir_all(root.join(d)).unwrap();
            }

            for i in 0..n {
                let bucket = DIRS[i % DIRS.len()];
                let pct = (i * 100) / n.max(1);

                let (name, content) = if pct < 40 {
                    // 40% Rust
                    let name = format!("{bucket}/mod_{i}.rs");
                    let content = if kernel_mode {
                        generate_rust_small(i)
                    } else {
                        generate_rust(i)
                    };
                    (name, content)
                } else if pct < 65 {
                    // 25% TypeScript
                    let name = format!("{bucket}/service_{i}.ts");
                    let content = if kernel_mode {
                        generate_typescript_small(i)
                    } else {
                        generate_typescript(i)
                    };
                    (name, content)
                } else if pct < 85 {
                    // 20% Python
                    let name = format!("{bucket}/handler_{i}.py");
                    let content = if kernel_mode {
                        generate_python_small(i)
                    } else {
                        generate_python(i)
                    };
                    (name, content)
                } else {
                    // 15% other (md/json/yaml/toml)
                    let name = match i % 4 {
                        0 => format!("{bucket}/README_{i}.md"),
                        1 => format!("{bucket}/config_{i}.json"),
                        2 => format!("{bucket}/config_{i}.yaml"),
                        _ => format!("{bucket}/config_{i}.toml"),
                    };
                    let content = generate_other(i);
                    (name, content)
                };

                let path = root.join(&name);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).unwrap();
                }
                total_bytes += content.len() as u64;
                fs::write(path, content).unwrap();
            }

            TestRepo {
                _dir: dir,
                root,
                file_count: n,
                total_bytes,
            }
        }
    }

    // ── Rust templates ──────────────────────────────────────────────────────

    /// ~12KB Rust file with all capture categories.
    pub fn generate_rust(i: usize) -> String {
        let mut s = String::with_capacity(12_000);

        // Imports (4-8)
        let import_count = 4 + (i % 5);
        for j in 0..import_count {
            writeln!(s, "use std::collections::HashMap{j};").unwrap();
        }
        writeln!(s, "use anyhow::Result;").unwrap();
        writeln!(s).unwrap();

        // Pub structs (2-4)
        let struct_count = 2 + (i % 3);
        for j in 0..struct_count {
            writeln!(s, "pub struct Widget{i}_{j} {{").unwrap();
            writeln!(s, "    pub name: String,").unwrap();
            writeln!(s, "    pub value: u64,").unwrap();
            writeln!(s, "    inner: Vec<u8>,").unwrap();
            writeln!(s, "}}").unwrap();
            writeln!(s).unwrap();
        }

        // Pub enum
        writeln!(s, "pub enum Status{i} {{").unwrap();
        writeln!(s, "    Active,").unwrap();
        writeln!(s, "    Inactive,").unwrap();
        writeln!(s, "    Pending(String),").unwrap();
        writeln!(s, "}}").unwrap();
        writeln!(s).unwrap();

        // Functions (5-15) with branches, unsafe, unwrap, TODOs
        let fn_count = 5 + (i % 11);
        for j in 0..fn_count {
            if j % 5 == 0 {
                writeln!(s, "// TODO: refactor function process_{i}_{j}").unwrap();
            }
            writeln!(s, "pub fn process_{i}_{j}(input: &str) -> Result<String> {{").unwrap();

            // if/match branches
            writeln!(s, "    if input.is_empty() {{").unwrap();
            writeln!(s, "        return Ok(String::new());").unwrap();
            writeln!(s, "    }}").unwrap();

            if j % 3 == 0 {
                writeln!(s, "    match input.len() {{").unwrap();
                writeln!(s, "        0..=10 => {{ let _ = 1; }}").unwrap();
                writeln!(s, "        _ => {{ let _ = 2; }}").unwrap();
                writeln!(s, "    }}").unwrap();
            }

            // unsafe blocks (0-3 across file)
            if j < 3 && (i + j) % 4 == 0 {
                writeln!(s, "    unsafe {{").unwrap();
                writeln!(s, "        let ptr = input.as_ptr();").unwrap();
                writeln!(s, "        let _ = *ptr;").unwrap();
                writeln!(s, "    }}").unwrap();
            }

            // .unwrap() calls (2-5 across file)
            if j % 3 == 0 {
                writeln!(s, "    let parsed = input.parse::<u64>().unwrap();").unwrap();
                writeln!(s, "    let _ = parsed;").unwrap();
            }

            // panic!()
            if j == fn_count - 1 && i % 3 == 0 {
                writeln!(s, "    if input == \"fatal\" {{").unwrap();
                writeln!(s, "        panic!(\"unrecoverable for {i}\");").unwrap();
                writeln!(s, "    }}").unwrap();
            }

            writeln!(s, "    Ok(format!(\"processed: {{input}}\"))").unwrap();
            writeln!(s, "}}").unwrap();
            writeln!(s).unwrap();
        }

        s
    }

    /// ~4KB Rust file for kernel-scale benchmarks.
    fn generate_rust_small(i: usize) -> String {
        let mut s = String::with_capacity(4_000);
        writeln!(s, "use std::collections::HashMap;").unwrap();
        writeln!(s, "use anyhow::Result;").unwrap();
        writeln!(s).unwrap();
        writeln!(s, "pub struct Item{i} {{ pub id: u64 }}").unwrap();
        writeln!(s).unwrap();
        for j in 0..3 {
            writeln!(s, "pub fn handle_{i}_{j}(x: &str) -> Result<()> {{").unwrap();
            writeln!(s, "    if x.is_empty() {{ return Ok(()); }}").unwrap();
            writeln!(s, "    let _ = x.parse::<u64>().unwrap();").unwrap();
            writeln!(s, "    Ok(())").unwrap();
            writeln!(s, "}}").unwrap();
            writeln!(s).unwrap();
        }
        s
    }

    // ── TypeScript templates ────────────────────────────────────────────────

    /// ~10KB TypeScript file.
    pub fn generate_typescript(i: usize) -> String {
        let mut s = String::with_capacity(10_000);

        // Imports (3-6)
        let import_count = 3 + (i % 4);
        for j in 0..import_count {
            writeln!(s, "import {{ Service{j} }} from './service_{j}';").unwrap();
        }
        writeln!(s).unwrap();

        // Exported interface
        writeln!(s, "export interface Config{i} {{").unwrap();
        writeln!(s, "  name: string;").unwrap();
        writeln!(s, "  timeout: number;").unwrap();
        writeln!(s, "  retries?: number;").unwrap();
        writeln!(s, "}}").unwrap();
        writeln!(s).unwrap();

        // Exported class
        writeln!(s, "export class Handler{i} {{").unwrap();
        writeln!(s, "  private config: Config{i};").unwrap();
        writeln!(s).unwrap();
        writeln!(s, "  constructor(config: Config{i}) {{").unwrap();
        writeln!(s, "    this.config = config;").unwrap();
        writeln!(s, "  }}").unwrap();
        writeln!(s).unwrap();
        for j in 0..3 {
            writeln!(s, "  async handle{j}(input: string): Promise<string> {{").unwrap();
            writeln!(s, "    if (!input) {{ throw new Error('empty'); }}").unwrap();
            writeln!(s, "    return input.toUpperCase();").unwrap();
            writeln!(s, "  }}").unwrap();
            writeln!(s).unwrap();
        }
        writeln!(s, "}}").unwrap();
        writeln!(s).unwrap();

        // Exported functions (3-8)
        let fn_count = 3 + (i % 6);
        for j in 0..fn_count {
            if j % 4 == 0 {
                writeln!(s, "// TODO: optimize transform_{i}_{j}").unwrap();
            }
            writeln!(s, "export function transform_{i}_{j}(data: string[]): string[] {{")
                .unwrap();
            writeln!(s, "  if (data.length === 0) {{ return []; }}").unwrap();
            if j % 2 == 0 {
                writeln!(s, "  switch (data[0]) {{").unwrap();
                writeln!(s, "    case 'a': return data.map(x => x.toUpperCase());").unwrap();
                writeln!(s, "    default: return data;").unwrap();
                writeln!(s, "  }}").unwrap();
            } else {
                writeln!(s, "  const result = data.length > 0 ? data : [];").unwrap();
                writeln!(s, "  return result;").unwrap();
            }
            writeln!(s, "}}").unwrap();
            writeln!(s).unwrap();
        }

        // @ts-ignore
        if i % 3 == 0 {
            writeln!(s, "// @ts-ignore").unwrap();
            writeln!(s, "const legacy{i} = null;").unwrap();
        }

        s
    }

    /// ~4KB TypeScript file for kernel scale.
    fn generate_typescript_small(i: usize) -> String {
        let mut s = String::with_capacity(4_000);
        writeln!(s, "import {{ Base }} from './base';").unwrap();
        writeln!(s).unwrap();
        writeln!(s, "export interface Item{i} {{ id: number; }}").unwrap();
        writeln!(s).unwrap();
        for j in 0..3 {
            writeln!(s, "export function handle_{i}_{j}(x: string): string {{").unwrap();
            writeln!(s, "  if (!x) {{ return ''; }}").unwrap();
            writeln!(s, "  return x;").unwrap();
            writeln!(s, "}}").unwrap();
            writeln!(s).unwrap();
        }
        s
    }

    // ── Python templates ────────────────────────────────────────────────────

    /// ~8KB Python file.
    pub fn generate_python(i: usize) -> String {
        let mut s = String::with_capacity(8_000);

        // Imports (3-6)
        let import_count = 3 + (i % 4);
        for j in 0..import_count {
            if j % 2 == 0 {
                writeln!(s, "import os{j}").unwrap();
            } else {
                writeln!(s, "from typing import Optional, List{j}").unwrap();
            }
        }
        writeln!(s).unwrap();

        // Top-level class
        writeln!(s, "class Manager{i}:").unwrap();
        writeln!(s, "    def __init__(self, name: str) -> None:").unwrap();
        writeln!(s, "        self.name = name").unwrap();
        writeln!(s).unwrap();
        writeln!(s, "    def process(self, data: str) -> str:").unwrap();
        writeln!(s, "        if not data:").unwrap();
        writeln!(s, "            return ''").unwrap();
        writeln!(s, "        return data.upper()").unwrap();
        writeln!(s).unwrap();
        writeln!(s, "    def _internal(self) -> None:").unwrap();
        writeln!(s, "        pass").unwrap();
        writeln!(s).unwrap();

        // Top-level functions (3-10)
        let fn_count = 3 + (i % 8);
        for j in 0..fn_count {
            if j % 4 == 0 {
                writeln!(s, "# TODO: refactor compute_{i}_{j}").unwrap();
            }
            writeln!(s, "def compute_{i}_{j}(x: int) -> int:").unwrap();
            writeln!(s, "    if x < 0:").unwrap();
            writeln!(s, "        return 0").unwrap();
            if j % 3 == 0 {
                writeln!(s, "    for k in range(x):").unwrap();
                writeln!(s, "        x += k").unwrap();
            }
            if j % 5 == 0 {
                writeln!(s, "    try:").unwrap();
                writeln!(s, "        result = int(str(x))").unwrap();
                writeln!(s, "    except ValueError:").unwrap();
                writeln!(s, "        result = 0").unwrap();
                writeln!(s, "    return result").unwrap();
            } else {
                writeln!(s, "    return x * 2").unwrap();
            }
            writeln!(s).unwrap();
        }

        // Decorated function
        writeln!(s, "@staticmethod").unwrap();
        writeln!(s, "def helper_{i}() -> None:").unwrap();
        writeln!(s, "    pass").unwrap();
        writeln!(s).unwrap();

        // Private function
        writeln!(s, "def _private_{i}(data):").unwrap();
        writeln!(s, "    # type: ignore[attr-defined]").unwrap();
        writeln!(s, "    return data").unwrap();

        s
    }

    /// ~4KB Python file for kernel scale.
    fn generate_python_small(i: usize) -> String {
        let mut s = String::with_capacity(4_000);
        writeln!(s, "import os").unwrap();
        writeln!(s, "from typing import Optional").unwrap();
        writeln!(s).unwrap();
        writeln!(s, "class Item{i}:").unwrap();
        writeln!(s, "    def __init__(self): pass").unwrap();
        writeln!(s).unwrap();
        for j in 0..3 {
            writeln!(s, "def handle_{i}_{j}(x: int) -> int:").unwrap();
            writeln!(s, "    if x < 0: return 0").unwrap();
            writeln!(s, "    return x").unwrap();
            writeln!(s).unwrap();
        }
        s
    }

    // ── Other templates ─────────────────────────────────────────────────────

    /// ~2KB non-parseable file.
    fn generate_other(i: usize) -> String {
        match i % 4 {
            0 => format!(
                "# Module {i}\n\nThis module handles processing for component {i}.\n\n\
                 ## Usage\n\n```\nimport {{ module{i} }}\n```\n\n\
                 ## Notes\n\n- Performance critical path\n- See ARCHITECTURE.md\n"
            ),
            1 => format!(
                "{{\n  \"name\": \"config-{i}\",\n  \"version\": \"1.0.{i}\",\n  \
                 \"settings\": {{\n    \"timeout\": {timeout},\n    \"retries\": 3,\n    \
                 \"debug\": false\n  }}\n}}\n",
                timeout = 1000 + i
            ),
            2 => format!(
                "name: config-{i}\nversion: '1.0.{version}'\nsettings:\n  \
                 timeout: {timeout}\n  retries: 3\n  debug: false\n",
                version = i,
                timeout = 1000 + i
            ),
            _ => format!(
                "[package]\nname = \"module-{i}\"\nversion = \"0.1.{i}\"\n\n\
                 [dependencies]\nserde = \"1.0\"\n"
            ),
        }
    }

    // ── Worst-case generators ───────────────────────────────────────────────

    /// 50 levels of nested if/match.
    pub fn generate_deeply_nested_rust(depth: usize) -> String {
        let mut s = String::with_capacity(depth * 100);
        writeln!(s, "pub fn deeply_nested(x: u32) -> u32 {{").unwrap();
        for d in 0..depth {
            let indent = "    ".repeat(d + 1);
            writeln!(s, "{indent}if x > {d} {{").unwrap();
        }
        let inner_indent = "    ".repeat(depth + 1);
        writeln!(s, "{inner_indent}return x;").unwrap();
        for d in (0..depth).rev() {
            let indent = "    ".repeat(d + 1);
            writeln!(s, "{indent}}}").unwrap();
        }
        writeln!(s, "    0").unwrap();
        writeln!(s, "}}").unwrap();
        s
    }

    /// ~1MB file at the walker's size limit.
    pub fn generate_max_size_rust() -> String {
        let target = 1_000_000;
        let mut s = String::with_capacity(target + 1000);
        writeln!(s, "use std::collections::HashMap;").unwrap();
        writeln!(s).unwrap();
        let mut i = 0;
        while s.len() < target {
            writeln!(s, "pub fn func_{i}(x: u32) -> u32 {{").unwrap();
            writeln!(s, "    if x > {i} {{ return x; }}").unwrap();
            writeln!(s, "    let val = x.to_string().parse::<u32>().unwrap();").unwrap();
            writeln!(s, "    val + {i}").unwrap();
            writeln!(s, "}}").unwrap();
            writeln!(s).unwrap();
            i += 1;
        }
        s
    }

    /// 200 use statements.
    pub fn generate_heavy_imports_rust() -> String {
        let mut s = String::with_capacity(10_000);
        for i in 0..200 {
            writeln!(s, "use crate::module_{i}::Type{i};").unwrap();
        }
        writeln!(s).unwrap();
        writeln!(s, "pub fn with_imports() {{ }}").unwrap();
        s
    }

    /// unsafe + .unwrap() on every function.
    pub fn generate_high_risk_rust() -> String {
        let mut s = String::with_capacity(15_000);
        writeln!(s, "use std::ptr;").unwrap();
        writeln!(s).unwrap();
        for i in 0..30 {
            writeln!(s, "pub fn risky_{i}(data: &[u8]) -> u8 {{").unwrap();
            writeln!(s, "    let val = data.first().unwrap();").unwrap();
            writeln!(s, "    unsafe {{").unwrap();
            writeln!(s, "        let p = data.as_ptr();").unwrap();
            writeln!(s, "        *p.add({i})").unwrap();
            writeln!(s, "    }}").unwrap();
            writeln!(s, "}}").unwrap();
            writeln!(s).unwrap();
        }
        s
    }

    /// N functions, each with a TODO/FIXME.
    pub fn generate_todo_heavy_rust(count: usize) -> String {
        let mut s = String::with_capacity(count * 120);
        for i in 0..count {
            if i % 2 == 0 {
                writeln!(s, "// TODO: fix function todo_fn_{i}").unwrap();
            } else {
                writeln!(s, "// FIXME: broken function todo_fn_{i}").unwrap();
            }
            writeln!(s, "pub fn todo_fn_{i}() {{ }}").unwrap();
            writeln!(s).unwrap();
        }
        s
    }

    /// Generate a directory tree with `depth` levels of nesting.
    pub fn generate_deep_directory(root: &Path, depth: usize, files_per_level: usize) {
        let mut current = root.to_path_buf();
        for d in 0..depth {
            current = current.join(format!("level_{d}"));
            std::fs::create_dir_all(&current).unwrap();
            for f in 0..files_per_level {
                let content = format!("pub fn func_{d}_{f}() {{}}\n");
                std::fs::write(current.join(format!("mod_{f}.rs")), content).unwrap();
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Create a WalkedFile for a single generated file on disk.
fn make_walked_file(dir: &Path, rel: &str, content: &str) -> WalkedFile {
    use mati_core::analysis::walker::detect_language;

    let abs = dir.join(rel);
    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&abs, content).unwrap();
    WalkedFile {
        abs_path: abs,
        rel_path: rel.to_owned(),
        language: detect_language(Path::new(rel)),
        size_bytes: content.len() as u64,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 1: walker
// ═══════════════════════════════════════════════════════════════════════════

fn bench_walker(c: &mut Criterion) {
    let mut group = c.benchmark_group("walker");

    for &(label, size) in &[
        ("50_files", SMALL),
        ("250_files", MEDIUM),
        ("1k_files", LARGE),
        ("5k_files", XL),
    ] {
        let repo = synth::TestRepo::generate(size);
        group.throughput(Throughput::Elements(repo.file_count as u64));

        group.bench_with_input(
            BenchmarkId::new("walk_batch", label),
            &repo,
            |b, repo| {
                b.iter(|| {
                    let files = Walker::new(&repo.root).walk().unwrap();
                    black_box(files.len());
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("walk_channel", label),
            &repo,
            |b, repo| {
                b.iter(|| {
                    let rx = Walker::new(&repo.root).walk_channel().unwrap();
                    let count: usize = rx.into_iter().map(|f| { black_box(&f); 1 }).sum();
                    black_box(count);
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 2: parser_single
// ═══════════════════════════════════════════════════════════════════════════

fn bench_parser_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_single");
    group.sample_size(100);

    let dir = TempDir::new().unwrap();

    // Standard files per language
    let rust_src = synth::generate_rust(0);
    let rust_file = make_walked_file(dir.path(), "src/mod_0.rs", &rust_src);
    group.throughput(Throughput::Bytes(rust_src.len() as u64));
    group.bench_function("rust_12kb", |b| {
        b.iter(|| black_box(parse_file(&rust_file).unwrap()));
    });

    let ts_src = synth::generate_typescript(0);
    let ts_file = make_walked_file(dir.path(), "src/service_0.ts", &ts_src);
    group.throughput(Throughput::Bytes(ts_src.len() as u64));
    group.bench_function("typescript_10kb", |b| {
        b.iter(|| black_box(parse_file(&ts_file).unwrap()));
    });

    let py_src = synth::generate_python(0);
    let py_file = make_walked_file(dir.path(), "src/handler_0.py", &py_src);
    group.throughput(Throughput::Bytes(py_src.len() as u64));
    group.bench_function("python_8kb", |b| {
        b.iter(|| black_box(parse_file(&py_file).unwrap()));
    });

    // Large Rust file (~80KB)
    let large_src = synth::generate_rust(0).repeat(7);
    let large_file = make_walked_file(dir.path(), "src/large.rs", &large_src);
    group.throughput(Throughput::Bytes(large_src.len() as u64));
    group.bench_function("rust_80kb", |b| {
        b.iter(|| black_box(parse_file(&large_file).unwrap()));
    });

    // Deeply nested (50 levels)
    let nested_src = synth::generate_deeply_nested_rust(50);
    let nested_file = make_walked_file(dir.path(), "src/nested.rs", &nested_src);
    group.throughput(Throughput::Bytes(nested_src.len() as u64));
    group.bench_function("rust_nested_50", |b| {
        b.iter(|| black_box(parse_file(&nested_file).unwrap()));
    });

    // 1MB max-size file
    let max_src = synth::generate_max_size_rust();
    let max_file = make_walked_file(dir.path(), "src/max.rs", &max_src);
    group.throughput(Throughput::Bytes(max_src.len() as u64));
    group.bench_function("rust_1mb", |b| {
        b.iter(|| black_box(parse_file(&max_file).unwrap()));
    });

    // 200 imports
    let imports_src = synth::generate_heavy_imports_rust();
    let imports_file = make_walked_file(dir.path(), "src/imports.rs", &imports_src);
    group.throughput(Throughput::Bytes(imports_src.len() as u64));
    group.bench_function("rust_200_imports", |b| {
        b.iter(|| black_box(parse_file(&imports_file).unwrap()));
    });

    // High risk density
    let risk_src = synth::generate_high_risk_rust();
    let risk_file = make_walked_file(dir.path(), "src/risky.rs", &risk_src);
    group.throughput(Throughput::Bytes(risk_src.len() as u64));
    group.bench_function("rust_high_risk", |b| {
        b.iter(|| black_box(parse_file(&risk_file).unwrap()));
    });

    // 100 TODOs
    let todo_src = synth::generate_todo_heavy_rust(100);
    let todo_file = make_walked_file(dir.path(), "src/todos.rs", &todo_src);
    group.throughput(Throughput::Bytes(todo_src.len() as u64));
    group.bench_function("rust_100_todos", |b| {
        b.iter(|| black_box(parse_file(&todo_file).unwrap()));
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 3: parser_parallel
// ═══════════════════════════════════════════════════════════════════════════

fn bench_parser_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_parallel");
    group.sample_size(20);

    for &(label, size) in &[
        ("50_files", SMALL),
        ("250_files", MEDIUM),
        ("1k_files", LARGE),
        ("5k_files", XL),
    ] {
        let repo = synth::TestRepo::generate(size);
        // Pre-walk to isolate parser timing
        let files = Walker::new(&repo.root).walk().unwrap();
        group.throughput(Throughput::Elements(files.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("parse_parallel", label),
            &files,
            |b, files| {
                b.iter(|| {
                    let results = parse_files_parallel(files);
                    black_box(results.len());
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 4: end_to_end (the M-06-L metric)
// ═══════════════════════════════════════════════════════════════════════════

fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end");
    group.sample_size(20);

    for &(label, size) in &[
        ("50_files", SMALL),
        ("250_files", MEDIUM),
        ("1k_files", LARGE),
        ("5k_files", XL),
    ] {
        let repo = synth::TestRepo::generate(size);
        group.throughput(Throughput::Elements(repo.file_count as u64));

        group.bench_with_input(
            BenchmarkId::new("walk_and_parse", label),
            &repo,
            |b, repo| {
                b.iter(|| {
                    let files = Walker::new(&repo.root).walk().unwrap();
                    let results = parse_files_parallel(&files);
                    black_box(results.len());
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 5: worst_case
// ═══════════════════════════════════════════════════════════════════════════

fn bench_worst_case(c: &mut Criterion) {
    let mut group = c.benchmark_group("worst_case");

    // Deep directory nesting (25 levels) walk
    {
        let dir = TempDir::new().unwrap();
        synth::generate_deep_directory(dir.path(), 25, 4);
        group.bench_function("deep_dir_25_levels_walk", |b| {
            b.iter(|| {
                let files = Walker::new(dir.path()).walk().unwrap();
                black_box(files.len());
            });
        });
    }

    // 1MB file parse
    {
        let dir = TempDir::new().unwrap();
        let src = synth::generate_max_size_rust();
        let file = make_walked_file(dir.path(), "max.rs", &src);
        group.bench_function("1mb_file_parse", |b| {
            b.iter(|| black_box(parse_file(&file).unwrap()));
        });
    }

    // 200 imports file parse
    {
        let dir = TempDir::new().unwrap();
        let src = synth::generate_heavy_imports_rust();
        let file = make_walked_file(dir.path(), "imports.rs", &src);
        group.bench_function("200_imports_parse", |b| {
            b.iter(|| black_box(parse_file(&file).unwrap()));
        });
    }

    // Equal language mix (25% each) walk+parse at 250 files
    {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        let per_lang = 63; // ~250 total (63*4 = 252)
        for i in 0..per_lang {
            std::fs::write(
                root.join(format!("src/mod_{i}.rs")),
                synth::generate_rust(i),
            )
            .unwrap();
            std::fs::write(
                root.join(format!("src/svc_{i}.ts")),
                synth::generate_typescript(i),
            )
            .unwrap();
            std::fs::write(
                root.join(format!("src/hand_{i}.py")),
                synth::generate_python(i),
            )
            .unwrap();
            std::fs::write(
                root.join(format!("src/app_{i}.js")),
                synth::generate_typescript(i), // reuse TS template for JS
            )
            .unwrap();
        }
        group.bench_function("equal_mix_250_walk_and_parse", |b| {
            b.iter(|| {
                let files = Walker::new(root).walk().unwrap();
                let results = parse_files_parallel(&files);
                black_box(results.len());
            });
        });
    }

    // High risk signal density parse
    {
        let dir = TempDir::new().unwrap();
        let src = synth::generate_high_risk_rust();
        let file = make_walked_file(dir.path(), "risky.rs", &src);
        group.bench_function("high_risk_density_parse", |b| {
            b.iter(|| black_box(parse_file(&file).unwrap()));
        });
    }

    // 100 TODOs file parse
    {
        let dir = TempDir::new().unwrap();
        let src = synth::generate_todo_heavy_rust(100);
        let file = make_walked_file(dir.path(), "todos.rs", &src);
        group.bench_function("100_todos_parse", |b| {
            b.iter(|| black_box(parse_file(&file).unwrap()));
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark group 6: kernel_scale (env-gated)
// ═══════════════════════════════════════════════════════════════════════════

fn bench_kernel_scale(c: &mut Criterion) {
    if std::env::var("MATI_BENCH_KERNEL").is_err() {
        eprintln!(
            "Skipping kernel_scale benchmarks. Set MATI_BENCH_KERNEL=1 to enable."
        );
        return;
    }

    let mut group = c.benchmark_group("kernel_scale");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(60));

    eprintln!("Generating 80k file test repo (~320MB)...");
    let repo = synth::TestRepo::generate(KERNEL);
    eprintln!(
        "Generated {} files, {:.0}MB",
        repo.file_count,
        repo.total_bytes as f64 / 1_048_576.0
    );

    group.throughput(Throughput::Elements(repo.file_count as u64));

    // Walk only
    group.bench_function("walk_80k", |b| {
        b.iter(|| {
            let files = Walker::new(&repo.root).walk().unwrap();
            black_box(files.len());
        });
    });

    // Parse only (pre-walked)
    let files = Walker::new(&repo.root).walk().unwrap();
    group.throughput(Throughput::Bytes(repo.total_bytes));
    group.bench_function("parse_80k", |b| {
        b.iter(|| {
            let results = parse_files_parallel(&files);
            black_box(results.len());
        });
    });

    // Walk + parse combined (the M-06-M metric)
    group.throughput(Throughput::Elements(repo.file_count as u64));
    group.bench_function("walk_and_parse_80k", |b| {
        b.iter(|| {
            let files = Walker::new(&repo.root).walk().unwrap();
            let results = parse_files_parallel(&files);
            black_box(results.len());
        });
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Criterion harness
// ═══════════════════════════════════════════════════════════════════════════

criterion_group!(
    benches,
    bench_walker,
    bench_parser_single,
    bench_parser_parallel,
    bench_end_to_end,
    bench_worst_case,
    bench_kernel_scale,
);
criterion_main!(benches);
