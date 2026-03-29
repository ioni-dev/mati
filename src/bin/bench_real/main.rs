//! Real-repo performance and accuracy benchmark for mati.
//!
//! Two-pass design:
//!   Pass 1 (cold) — wipe store, fresh `mati init`, run every command.
//!   Pass 2 (warm) — same commands against existing store (cache warm, OS page cache warm).
//!
//! Measures: wall-clock latency (mean/min/max/stddev), cache speedup, parse
//! accuracy, knowledge health, data integrity, and store size.
//!
//! Usage:
//!   cargo build --release
//!   cargo run --bin bench_real --release -- --repos ripgrep,deno --samples 5
//!   cargo run --bin bench_real --release -- --repos ripgrep --output BENCHMARKS.md

mod parser;
mod report;
mod repos;
mod runner;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use clap::Parser as ClapParser;
use parser::*;
use repos::{
    clean_store, compute_slug, ensure_cloned, find_spec, git_file_count, git_lang_counts, store_dir,
};
use runner::{mati_bin, run_edit_hook, run_once, run_parallel_gets, run_timed, TimedResult};

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(ClapParser, Debug)]
#[command(
    name = "bench_real",
    about = "Real-repo mati performance + accuracy benchmark",
    long_about = "Clones repos, runs mati init (cold) then all commands twice \
                  (cold + warm), measures speed + accuracy, outputs markdown."
)]
struct Args {
    /// Repos to test: ripgrep,deno,nextjs,tokio,mati (comma-separated).
    /// Use "mati" to test against this project itself.
    #[arg(long, default_value = "ripgrep,deno,nextjs")]
    repos: String,

    /// Timing samples per command (more = more accurate, slower).
    #[arg(long, default_value_t = 5)]
    samples: usize,

    /// Directory for cloned repos (created if absent).
    #[arg(long, default_value = "/tmp/mati-bench-repos")]
    repo_cache: PathBuf,

    /// Write markdown output to this file (default: stdout).
    #[arg(long)]
    output: Option<PathBuf>,

    /// Skip the cold pass (only measure warm).
    #[arg(long)]
    warm_only: bool,

    /// Skip the warm pass (only measure cold).
    #[arg(long)]
    cold_only: bool,

    /// Max number of file keys to use for parallel-get tests.
    #[arg(long, default_value_t = 25)]
    parallel_keys: usize,
}

// ── Data model ────────────────────────────────────────────────────────────────

pub struct RepoReport {
    pub repo_name: String,
    pub cold: PassResults,
    pub warm: PassResults,
    pub accuracy: AccuracyReport,
    pub lang_counts: Vec<(String, usize)>,
}

pub struct PassResults {
    pub init: InitMetrics,
    pub commands: HashMap<String, TimedResult>,
    pub samples: usize,
}

impl PassResults {
    fn empty(samples: usize) -> Self {
        PassResults {
            init: InitMetrics::default(),
            commands: HashMap::new(),
            samples,
        }
    }
}

pub struct AccuracyReport {
    // Coverage
    pub file_count_mati: usize,
    pub file_count_git: usize,
    pub total_records: usize,
    pub confidence_avg: f64,

    // Correctness
    pub get_hit_rate_pct: u32,
    pub stats_cold_warm_consistent: bool,
    pub edit_hook_success: bool,
    pub edit_hook_staleness_changed: bool,
    pub export_success: bool,
    pub init_success: bool,
    pub harvest_success: bool,

    // Health
    pub gaps: GapsMetrics,
    pub stale: StaleMetrics,
    pub ping_us: Option<u64>,

    // Store
    pub store_size_mb: Option<f64>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let args = Args::parse();

    // Locate mati binary.
    let bin = mati_bin();
    eprintln!("mati binary: {}", bin.display());
    if !bin.exists() {
        eprintln!("ERROR: mati binary not found. Run `cargo build --release` first.");
        std::process::exit(1);
    }

    // Create repo cache dir.
    std::fs::create_dir_all(&args.repo_cache).expect("failed to create --repo-cache dir");

    let repo_names: Vec<&str> = args.repos.split(',').map(str::trim).collect();
    let mut reports: Vec<RepoReport> = Vec::new();

    for name in &repo_names {
        eprintln!("\n══ {} ══════════════════════════════════", name);

        let repo_path = resolve_repo_path(name, &args.repo_cache);
        let slug = compute_slug(&repo_path);
        eprintln!("  path: {}", repo_path.display());
        eprintln!("  slug: {}", slug);

        // ── Cold pass ─────────────────────────────────────────────────────
        let cold = if !args.warm_only {
            eprintln!("\n  [cold pass]");
            eprintln!("  wiping store...");
            clean_store(&slug);
            run_pass(&bin, &repo_path, args.samples, args.parallel_keys, true)
        } else {
            PassResults::empty(args.samples)
        };

        // ── Warm pass ─────────────────────────────────────────────────────
        let warm = if !args.cold_only {
            eprintln!("\n  [warm pass]");
            run_pass(&bin, &repo_path, args.samples, args.parallel_keys, false)
        } else {
            PassResults::empty(args.samples)
        };

        // ── Accuracy ──────────────────────────────────────────────────────
        eprintln!("\n  [accuracy checks]");
        let accuracy = compute_accuracy(&bin, &repo_path, &cold, &warm, &slug);

        let lang_counts = git_lang_counts(&repo_path);

        // Use the directory basename as display name for absolute paths.
        let display_name = if name.starts_with('/') || name.starts_with('.') {
            repo_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(name)
                .to_string()
        } else {
            name.to_string()
        };

        reports.push(RepoReport {
            repo_name: display_name,
            cold,
            warm,
            accuracy,
            lang_counts,
        });
    }

    // ── Report ────────────────────────────────────────────────────────────
    let date = chrono::Local::now().format("%Y-%m-%d").to_string();
    let markdown = report::generate(&reports, &date);

    if let Some(out_path) = &args.output {
        std::fs::write(out_path, &markdown).expect("failed to write output file");
        eprintln!("\nReport written to {}", out_path.display());
    } else {
        println!("{}", markdown);
    }
}

// ── Repo resolution ───────────────────────────────────────────────────────────

fn resolve_repo_path(name: &str, cache_dir: &Path) -> PathBuf {
    // Absolute path — use directly.
    if name.starts_with('/') || name.starts_with('.') {
        let p = PathBuf::from(name);
        assert!(p.exists(), "repo path does not exist: {}", name);
        return p;
    }

    if name == "mati" {
        // Use this project's root (one level above target/).
        let exe = std::env::current_exe().unwrap_or_default();
        let mut dir = exe
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.to_path_buf());
        while let Some(d) = dir {
            if d.join("Cargo.toml").exists() {
                let content = std::fs::read_to_string(d.join("Cargo.toml")).unwrap_or_default();
                if content.contains("name = \"mati\"") {
                    return d;
                }
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }
        return std::env::current_dir().unwrap();
    }

    let spec = find_spec(name).unwrap_or_else(|| {
        panic!(
            "unknown repo '{}'. Known: ripgrep, deno, nextjs, tokio, mati, or an absolute path",
            name
        )
    });
    ensure_cloned(spec, cache_dir)
}

// ── Pass execution ────────────────────────────────────────────────────────────

fn run_pass(
    bin: &Path,
    repo_path: &Path,
    samples: usize,
    parallel_keys: usize,
    is_cold: bool,
) -> PassResults {
    let mut commands: HashMap<String, TimedResult> = HashMap::new();

    // ── Init (cold only) ──────────────────────────────────────────────────
    let init = if is_cold {
        eprintln!("    mati init...");
        let r = run_once(
            bin,
            &[
                "init",
                "--path",
                repo_path.to_str().unwrap(),
                "--no-hooks",
            ],
            repo_path,
        );
        if !r.success {
            eprintln!(
                "    WARN init failed (exit {}): {}",
                r.exit_code,
                r.stderr.trim()
            );
        } else {
            eprintln!("    init ok ({}ms)", r.mean_ms as u64);
        }
        parse_init(&r.stdout)
    } else {
        InitMetrics::default()
    };

    // ── Discover test keys ────────────────────────────────────────────────
    let ls_out = run_once(bin, &["ls", "files"], repo_path);
    let file_keys = extract_file_keys(&ls_out.stdout);
    let get_key = file_keys
        .first()
        .cloned()
        .unwrap_or_else(|| "file:src/lib.rs".into());

    eprintln!("    {} file keys discovered", file_keys.len());

    // ── mati status ───────────────────────────────────────────────────────
    step("status", &mut commands, || {
        run_timed(bin, &["status"], repo_path, samples)
    });

    // ── mati stats: first run = cache miss, then N more = cache hit ───────
    step("stats_first", &mut commands, || {
        run_timed(bin, &["stats"], repo_path, 1)
    });
    step("stats_avg", &mut commands, || {
        run_timed(bin, &["stats"], repo_path, samples)
    });

    // ── mati gaps ─────────────────────────────────────────────────────────
    step("gaps_first", &mut commands, || {
        run_timed(bin, &["gaps"], repo_path, 1)
    });
    step("gaps_avg", &mut commands, || {
        run_timed(bin, &["gaps"], repo_path, samples)
    });

    // ── mati ls ───────────────────────────────────────────────────────────
    step("ls_files", &mut commands, || {
        run_timed(bin, &["ls", "files"], repo_path, samples)
    });
    step("ls_gotchas", &mut commands, || {
        run_timed(bin, &["ls", "gotchas"], repo_path, samples)
    });
    step("ls_decisions", &mut commands, || {
        run_timed(bin, &["ls", "decisions"], repo_path, samples)
    });

    // ── mati stale ────────────────────────────────────────────────────────
    step("stale", &mut commands, || {
        run_timed(bin, &["stale"], repo_path, samples)
    });

    // ── mati quality-check ────────────────────────────────────────────────
    step("quality_check", &mut commands, || {
        run_timed(bin, &["quality-check"], repo_path, samples)
    });

    // ── mati get ×1 ──────────────────────────────────────────────────────
    step("get_1", &mut commands, || {
        run_timed(bin, &["get", &get_key], repo_path, samples)
    });

    // ── mati show ─────────────────────────────────────────────────────────
    step("show", &mut commands, || {
        run_timed(bin, &["show", &get_key], repo_path, samples)
    });

    // ── mati get ×10 parallel ─────────────────────────────────────────────
    {
        let keys10: Vec<String> = file_keys.iter().take(10).cloned().collect();
        step("get_10", &mut commands, || {
            run_parallel_gets(bin, &keys10, repo_path)
        });
    }

    // ── mati get ×25 parallel ─────────────────────────────────────────────
    {
        let keys25: Vec<String> = file_keys.iter().take(parallel_keys).cloned().collect();
        step("get_25", &mut commands, || {
            run_parallel_gets(bin, &keys25, repo_path)
        });
    }

    // ── mati export --format json ─────────────────────────────────────────
    step("export_json", &mut commands, || {
        run_timed(bin, &["export", "--format", "json"], repo_path, samples)
    });

    // ── mati history ──────────────────────────────────────────────────────
    step("history", &mut commands, || {
        run_timed(bin, &["history", &get_key], repo_path, samples)
    });

    // ── mati ping ─────────────────────────────────────────────────────────
    step("ping", &mut commands, || {
        run_timed(bin, &["ping"], repo_path, samples)
    });

    // ── mati edit-hook ────────────────────────────────────────────────────
    {
        let rel = get_key.strip_prefix("file:").unwrap_or("src/lib.rs");
        let abs = repo_path.join(rel);
        step("edit_hook", &mut commands, || {
            run_edit_hook(bin, &abs, repo_path, samples)
        });
    }

    // ── mati session-harvest ──────────────────────────────────────────────
    step("session_harvest", &mut commands, || {
        run_timed(bin, &["session-harvest"], repo_path, samples)
    });

    // ── mati log-miss / log-hit ───────────────────────────────────────────
    step("log_miss", &mut commands, || {
        run_timed(bin, &["log-miss", &get_key], repo_path, samples)
    });
    step("log_hit", &mut commands, || {
        run_timed(bin, &["log-hit", &get_key], repo_path, samples)
    });

    PassResults {
        init,
        commands,
        samples,
    }
}

/// Run a single step, print progress, insert result.
fn step(key: &str, commands: &mut HashMap<String, TimedResult>, f: impl FnOnce() -> TimedResult) {
    eprint!("    {}...", key);
    let r = f();
    let status = if r.success { "" } else { " [FAIL]" };
    eprintln!(" {:.0}ms{}", r.mean_ms, status);
    commands.insert(key.into(), r);
}

// ── Accuracy computation ──────────────────────────────────────────────────────

fn compute_accuracy(
    bin: &Path,
    repo_path: &Path,
    cold: &PassResults,
    warm: &PassResults,
    slug: &str,
) -> AccuracyReport {
    // File counts.
    let file_count_git = git_file_count(repo_path);
    let status_out = run_once(bin, &["status"], repo_path);
    let status = parse_status(&status_out.stdout);
    let file_count_mati = status.file_count;
    let total_records = status.file_count
        + status.gotcha_count
        + status.decision_count
        + status.note_count
        + status.dep_count;

    eprintln!("    files: mati={} git={}", file_count_mati, file_count_git);

    // Stats consistency: cold first-run vs warm first-run numbers should match.
    let cold_stats = cold
        .commands
        .get("stats_first")
        .map(|r| parse_stats(&r.stdout));
    let warm_stats = warm
        .commands
        .get("stats_first")
        .map(|r| parse_stats(&r.stdout));
    let stats_consistent = match (&cold_stats, &warm_stats) {
        (Some(c), Some(w)) => {
            (c.files_with_purpose as i64 - w.files_with_purpose as i64).abs() <= 1
                && (c.gap_count as i64 - w.gap_count as i64).abs() <= 1
        }
        _ => true, // one pass skipped — can't compare
    };

    // Get hit rate: test up to 25 known file keys.
    let ls_out = run_once(bin, &["ls", "files"], repo_path);
    let keys = extract_file_keys(&ls_out.stdout);
    let test_n = keys.len().min(25);
    let test_keys = keys.iter().take(test_n).cloned().collect::<Vec<_>>();
    let hits: usize = test_keys
        .iter()
        .filter(|k| run_once(bin, &["get", k], repo_path).success)
        .count();
    let get_hit_rate_pct = if test_n > 0 {
        (hits * 100 / test_n) as u32
    } else {
        0
    };
    eprintln!(
        "    get hit rate: {}/{}  ({}%)",
        hits, test_n, get_hit_rate_pct
    );

    // Gaps.
    let gaps_out = run_once(bin, &["gaps"], repo_path);
    let gaps = parse_gaps(&gaps_out.stdout);

    // Staleness.
    let stale_out = run_once(bin, &["stale"], repo_path);
    let stale = parse_stale(&stale_out.stdout);

    // Ping latency (parse µs from output).
    let ping_out = run_once(bin, &["ping"], repo_path);
    let ping_us = parse_ping_us(&ping_out.stdout);

    // Edit-hook accuracy: did the hook succeed? Did staleness change?
    let (edit_hook_success, edit_hook_staleness_changed) =
        check_edit_hook_accuracy(bin, repo_path, &keys);

    // Export.
    let export_out = run_once(bin, &["export", "--format", "json"], repo_path);
    let export_success = export_out.success && export_out.stdout.contains('{');

    // Init & harvest success.
    let init_success = cold.init.completed || cold.commands.is_empty();
    let harvest_success = cold
        .commands
        .get("session_harvest")
        .map(|r| r.success)
        .unwrap_or(false);

    // Store size.
    let store_size_mb = dir_size_mb(&store_dir(slug));

    AccuracyReport {
        file_count_mati,
        file_count_git,
        total_records,
        confidence_avg: status.confidence_avg,
        get_hit_rate_pct,
        stats_cold_warm_consistent: stats_consistent,
        edit_hook_success,
        edit_hook_staleness_changed,
        export_success,
        init_success,
        harvest_success,
        gaps,
        stale,
        ping_us,
        store_size_mb,
    }
}

// ── Edit-hook accuracy ────────────────────────────────────────────────────────

fn check_edit_hook_accuracy(bin: &Path, repo_path: &Path, file_keys: &[String]) -> (bool, bool) {
    let key = match file_keys.first() {
        Some(k) => k,
        None => return (false, false),
    };
    let rel = key.strip_prefix("file:").unwrap_or("");
    let abs = repo_path.join(rel);

    if !abs.exists() || !abs.is_file() {
        return (false, false);
    }

    // Snapshot confidence/staleness before.
    let before_out = run_once(bin, &["show", key], repo_path);

    // Mutate + hook.
    let hook_result = run_edit_hook(bin, &abs, repo_path, 1);
    if !hook_result.success {
        return (false, false);
    }

    // Snapshot after.
    let after_out = run_once(bin, &["show", key], repo_path);

    // A staleness change shows up in the show output (different staleness line).
    let changed = after_out.stdout != before_out.stdout;
    (true, changed)
}

// ── Filesystem helpers ────────────────────────────────────────────────────────

fn dir_size_mb(path: &Path) -> Option<f64> {
    if !path.exists() {
        return None;
    }
    let bytes = du_bytes(path)?;
    Some(bytes as f64 / 1_048_576.0)
}

fn du_bytes(path: &Path) -> Option<u64> {
    // Use `du -sk` for portability; result is in 512-byte blocks on macOS.
    let out = std::process::Command::new("du")
        .args(["-sk", path.to_str()?])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let kb: u64 = s.split_whitespace().next()?.parse().ok()?;
    Some(kb * 1024)
}
