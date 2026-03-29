use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

// ── Result type ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TimedResult {
    /// Mean wall-clock time across all samples (ms).
    pub mean_ms: f64,
    /// Fastest sample (ms).
    pub min_ms: f64,
    /// Slowest sample (ms).
    pub max_ms: f64,
    /// Population standard deviation (ms).
    pub stddev_ms: f64,
    /// How many samples were taken.
    pub samples: usize,
    /// stdout of the last run (ANSI stripped by caller if needed).
    pub stdout: String,
    /// stderr of the last run.
    pub stderr: String,
    /// Whether the last run exited with status 0.
    pub success: bool,
    /// Exit code of the last run.
    pub exit_code: i32,
}

impl TimedResult {
    pub fn failed() -> Self {
        TimedResult {
            mean_ms: 0.0,
            min_ms: 0.0,
            max_ms: 0.0,
            stddev_ms: 0.0,
            samples: 0,
            stdout: String::new(),
            stderr: "not run".into(),
            success: false,
            exit_code: -1,
        }
    }
}

// ── Binary location ───────────────────────────────────────────────────────────

/// Locate the mati binary: sibling of this executable, then PATH.
pub fn mati_bin() -> PathBuf {
    // When run as target/release/bench_real, mati lives alongside us.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("mati");
            if candidate.exists() {
                return candidate;
            }
        }
    }
    // Debug build fallback.
    let debug = PathBuf::from("target/debug/mati");
    if debug.exists() {
        return debug;
    }
    // Last resort: rely on PATH.
    PathBuf::from("mati")
}

// ── Core timing primitive ─────────────────────────────────────────────────────

/// Run `bin args` from `cwd` exactly `n` times, return aggregated stats.
/// Passes `NO_COLOR=1` so ANSI codes don't pollute captured stdout.
pub fn run_timed(bin: &Path, args: &[&str], cwd: &Path, n: usize) -> TimedResult {
    assert!(n > 0, "run_timed: n must be > 0");

    let mut times: Vec<f64> = Vec::with_capacity(n);
    let mut last_stdout = String::new();
    let mut last_stderr = String::new();
    let mut last_code = 0i32;

    for _ in 0..n {
        let t0 = Instant::now();
        let out = Command::new(bin)
            .args(args)
            .current_dir(cwd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("NO_COLOR", "1")
            .output()
            .unwrap_or_else(|e| panic!("failed to run {:?}: {}", bin, e));
        let elapsed_ms = t0.elapsed().as_secs_f64() * 1_000.0;

        times.push(elapsed_ms);
        last_stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        last_stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        last_code = out.status.code().unwrap_or(-1);
    }

    aggregate(times, last_stdout, last_stderr, last_code)
}

/// Convenience: single run (no averaging noise, just raw wall-clock).
pub fn run_once(bin: &Path, args: &[&str], cwd: &Path) -> TimedResult {
    run_timed(bin, args, cwd, 1)
}

// ── Sequential multi-get ──────────────────────────────────────────────────────

/// Run N `mati get` calls sequentially and measure total wall-clock.
///
/// NOTE: SurrealKV holds a process-level LOCK file, so concurrent CLI
/// invocations against the same store always fail with "already locked".
/// Parallel gets require the MCP daemon (single long-lived process).
/// This test measures sequential throughput instead, which reflects hook
/// behaviour in practice (hooks fire one at a time).
pub fn run_parallel_gets(bin: &Path, keys: &[String], cwd: &Path) -> TimedResult {
    if keys.is_empty() {
        return TimedResult::failed();
    }

    let t0 = Instant::now();
    let mut all_ok = true;

    for key in keys {
        let out = Command::new(bin)
            .args(["get", key])
            .current_dir(cwd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("NO_COLOR", "1")
            .output()
            .unwrap_or_else(|e| panic!("get failed: {}", e));
        if !out.status.success() {
            all_ok = false;
        }
    }

    let total_ms = t0.elapsed().as_secs_f64() * 1_000.0;

    TimedResult {
        mean_ms: total_ms / keys.len() as f64, // per-get average
        min_ms: total_ms / keys.len() as f64,
        max_ms: total_ms / keys.len() as f64,
        stddev_ms: 0.0,
        samples: keys.len(),
        stdout: String::new(),
        stderr: String::new(),
        success: all_ok,
        exit_code: if all_ok { 0 } else { 1 },
    }
}

// ── Edit-hook helper ──────────────────────────────────────────────────────────

/// Append a bench comment to `file_path`, run `mati edit-hook`, restore file.
/// Returns the TimedResult for the edit-hook command.
pub fn run_edit_hook(bin: &Path, file_path: &Path, cwd: &Path, n: usize) -> TimedResult {
    if !file_path.exists() || !file_path.is_file() {
        return TimedResult::failed();
    }

    let original = match std::fs::read_to_string(file_path) {
        Ok(s) => s,
        Err(_) => return TimedResult::failed(),
    };

    let comment = match file_path.extension().and_then(|e| e.to_str()) {
        Some("py") | Some("toml") | Some("yaml") | Some("yml") => "#",
        _ => "//",
    };

    let mut times: Vec<f64> = Vec::with_capacity(n);
    let mut last_stdout = String::new();
    let mut last_stderr = String::new();
    let mut last_code = 0i32;

    for i in 0..n {
        // Mutate.
        let modified = format!(
            "{}\n{} bench_real edit {}\n",
            original.trim_end(),
            comment,
            i
        );
        let _ = std::fs::write(file_path, &modified);

        let t0 = Instant::now();
        let out = Command::new(bin)
            .args(["edit-hook", file_path.to_str().unwrap_or("")])
            .current_dir(cwd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("NO_COLOR", "1")
            .output()
            .unwrap_or_else(|e| panic!("failed to run edit-hook: {}", e));
        times.push(t0.elapsed().as_secs_f64() * 1_000.0);

        last_stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        last_stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        last_code = out.status.code().unwrap_or(-1);
    }

    // Always restore.
    let _ = std::fs::write(file_path, &original);

    aggregate(times, last_stdout, last_stderr, last_code)
}

// ── Internal ──────────────────────────────────────────────────────────────────

fn aggregate(times: Vec<f64>, stdout: String, stderr: String, exit_code: i32) -> TimedResult {
    let n = times.len() as f64;
    let mean = times.iter().sum::<f64>() / n;
    let min = times.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = times.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let variance = times.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / n;

    TimedResult {
        mean_ms: mean,
        min_ms: min,
        max_ms: max,
        stddev_ms: variance.sqrt(),
        samples: times.len(),
        stdout,
        stderr,
        success: exit_code == 0,
        exit_code,
    }
}
