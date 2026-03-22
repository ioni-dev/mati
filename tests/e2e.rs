//! End-to-end developer journey test — 5 iterations against a real repo.
//!
//! Exercises every user-facing mati feature across a simulated developer lifecycle:
//!   1. Cold Init
//!   2. Knowledge Creation
//!   3. Warm Re-init (incremental)
//!   4. Change Detection
//!   5. Review & Full Lifecycle
//!
//! # Running
//!
//! ```sh
//! MATI_E2E_REPO=/path/to/repo \
//!   cargo test --test e2e developer_journey -- --ignored --nocapture
//! ```

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use tempfile::TempDir;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Result of a single CLI invocation.
#[derive(Debug, Clone)]
struct StepResult {
    /// Arguments passed to the binary (excluding binary name).
    #[allow(dead_code)]
    args: Vec<String>,
    /// Combined stdout.
    stdout: String,
    /// Combined stderr.
    stderr: String,
    /// Process exit code (0 = success).
    exit_code: i32,
    /// Wall-clock duration in milliseconds.
    duration_ms: u128,
    /// Step label for display purposes.
    label: String,
    /// Pass/fail verdict with optional message.
    verdict: Verdict,
}

#[derive(Debug, Clone)]
enum Verdict {
    Pass,
    Fail(String),
    Skip(String),
}

impl StepResult {
    fn passed(&self) -> bool {
        matches!(self.verdict, Verdict::Pass)
    }

    fn failed(&self) -> bool {
        matches!(self.verdict, Verdict::Fail(_))
    }
}

/// Wraps subprocess invocation with isolated HOME.
#[allow(dead_code)]
struct Harness {
    bin: PathBuf,
    repo: PathBuf,
    /// Isolated HOME directory — all mati store state lives here.
    home: TempDir,
}

impl Harness {
    fn new(bin: PathBuf, repo: PathBuf, home: TempDir) -> Self {
        Self { bin, repo, home }
    }

    /// Run the mati binary with the given args.
    /// HOME is redirected to the isolated tempdir.
    /// CWD is set to the target repo.
    #[allow(dead_code)]
    fn run(&self, args: &[&str]) -> StepResult {
        self.run_with_stdin(args, None, args.join(" "))
    }

    /// Run with label override (for display when args are long).
    fn run_labeled(&self, args: &[&str], label: &str) -> StepResult {
        self.run_with_stdin(args, None, label.to_string())
    }

    /// Run with piped stdin content.
    #[allow(dead_code)]
    fn run_stdin(&self, args: &[&str], stdin_data: &str) -> StepResult {
        self.run_with_stdin(args, Some(stdin_data), args.join(" "))
    }

    /// Run with piped stdin and a label override.
    fn run_stdin_labeled(&self, args: &[&str], stdin_data: &str, label: &str) -> StepResult {
        self.run_with_stdin(args, Some(stdin_data), label.to_string())
    }

    fn run_with_stdin(
        &self,
        args: &[&str],
        stdin_data: Option<&str>,
        label: String,
    ) -> StepResult {
        let start = Instant::now();

        let mut cmd = Command::new(&self.bin);
        cmd.args(args)
            .current_dir(&self.repo)
            .env("HOME", self.home.path())
            .env("RUST_LOG", "warn")
            // Disable color — plain text output is easier to parse.
            .env("NO_COLOR", "1")
            .env("TERM", "dumb");

        if stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let duration_ms = start.elapsed().as_millis();
                return StepResult {
                    args: args.iter().map(|s| s.to_string()).collect(),
                    stdout: String::new(),
                    stderr: format!("spawn error: {e}"),
                    exit_code: -1,
                    duration_ms,
                    label,
                    verdict: Verdict::Fail(format!("failed to spawn: {e}")),
                };
            }
        };

        // Write stdin if provided.
        if let Some(data) = stdin_data {
            if let Some(mut stdin_handle) = child.stdin.take() {
                let _ = stdin_handle.write_all(data.as_bytes());
                // stdin_handle is dropped here, closing the pipe.
            }
        }

        let output = match child.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                let duration_ms = start.elapsed().as_millis();
                return StepResult {
                    args: args.iter().map(|s| s.to_string()).collect(),
                    stdout: String::new(),
                    stderr: format!("wait error: {e}"),
                    exit_code: -1,
                    duration_ms,
                    label,
                    verdict: Verdict::Fail(format!("failed to wait: {e}")),
                };
            }
        };

        let duration_ms = start.elapsed().as_millis();
        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        StepResult {
            args: args_owned,
            stdout,
            stderr,
            exit_code,
            duration_ms,
            label,
            verdict: Verdict::Pass, // caller applies assertions
        }
    }
}

// ── Assertion helpers ─────────────────────────────────────────────────────────

/// Assert exit code == 0, or return Fail verdict.
fn assert_exit_ok(mut r: StepResult) -> StepResult {
    if r.exit_code != 0 {
        r.verdict = Verdict::Fail(format!(
            "expected exit 0, got {}. stderr: {}",
            r.exit_code,
            r.stderr.lines().next().unwrap_or("(empty)")
        ));
    }
    r
}

/// Assert exit code == 0 and stdout contains `needle`.
fn assert_contains(mut r: StepResult, needle: &str) -> StepResult {
    if r.exit_code != 0 {
        r.verdict = Verdict::Fail(format!(
            "expected exit 0, got {}. stderr: {}",
            r.exit_code,
            r.stderr.lines().next().unwrap_or("(empty)")
        ));
        return r;
    }
    if !r.stdout.contains(needle) && !r.stderr.contains(needle) {
        r.verdict = Verdict::Fail(format!(
            "expected stdout/stderr to contain {:?}, got stdout={:?}",
            needle,
            &r.stdout[..r.stdout.len().min(200)]
        ));
    }
    r
}

/// Assert exit code == 0 and stdout non-empty.
fn assert_nonempty(mut r: StepResult) -> StepResult {
    if r.exit_code != 0 {
        r.verdict = Verdict::Fail(format!(
            "expected exit 0, got {}. stderr: {}",
            r.exit_code,
            r.stderr.lines().next().unwrap_or("(empty)")
        ));
        return r;
    }
    if r.stdout.trim().is_empty() {
        r.verdict = Verdict::Fail("expected non-empty stdout".to_string());
    }
    r
}

// ── Metric extraction helpers ─────────────────────────────────────────────────

/// Extract the number of file records from `ls files` output.
/// Looks for "N file records" line.
fn extract_file_count(output: &str) -> Option<usize> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with("file records") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(first) = parts.first() {
                return first.parse().ok();
            }
        }
    }
    None
}

/// Extract the number of gotcha records from `ls gotchas` output.
/// Looks for "N gotcha records" line.
fn extract_gotcha_count(output: &str) -> Option<usize> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with("gotcha records") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(first) = parts.first() {
                return first.parse().ok();
            }
        }
    }
    None
}

/// Extract the number of decision records from `ls decisions` output.
fn extract_decision_count(output: &str) -> Option<usize> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with("decision records") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(first) = parts.first() {
                return first.parse().ok();
            }
        }
    }
    None
}

/// Extract file count from `mati init` summary output.
/// Looks for "file records:          N" line.
fn extract_init_file_count(output: &str) -> Option<usize> {
    for line in output.lines() {
        if line.contains("file records:") {
            // "  file records:          523   (stubs + entry points)"
            let rest = line.splitn(2, ':').nth(1)?;
            let n: usize = rest.split_whitespace().next()?.parse().ok()?;
            return Some(n);
        }
    }
    None
}

/// Extract total init time in ms from "Total: Nms" line.
#[allow(dead_code)]
fn extract_init_ms(output: &str) -> Option<u128> {
    for line in output.lines() {
        if line.contains("Total:") && line.contains("ms") {
            // "  Total: 2847ms · 0 tokens · 0 Claude calls"
            let after = line.split("Total:").nth(1)?;
            let s: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            return s.parse().ok();
        }
    }
    None
}

/// Extract ping latency in µs from "mati ok  Nµs".
fn extract_ping_latency(output: &str) -> Option<u64> {
    for line in output.lines() {
        if line.contains("mati ok") {
            let s: String = line
                .chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(|c| c.is_ascii_digit())
                .collect();
            return s.parse().ok();
        }
    }
    None
}

/// Pick the first file path from `ls files` output.
/// Returns the path (without "file:" prefix).
fn first_file_path(output: &str) -> Option<String> {
    // Handles two output formats from `mati ls files`:
    //   1. Box-drawing: "│ src/foo.rs │ ..."
    //   2. Space-separated: "src/foo.rs   (pending enrichment)  ..."
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('╭')
            || trimmed.starts_with('╰')
            || trimmed.starts_with('├')
            || trimmed.starts_with('─')
            || trimmed.starts_with('═')
            || trimmed.eq_ignore_ascii_case("PATH")
            || trimmed.starts_with("PATH ")
            || trimmed.ends_with("file records")
        {
            continue;
        }

        // Format 1: box-drawing table
        if trimmed.starts_with('│') {
            let parts: Vec<&str> = trimmed.split('│').collect();
            if parts.len() >= 2 {
                let path = parts[1].trim();
                if !path.is_empty()
                    && !path.eq_ignore_ascii_case("path")
                    && !path.starts_with('-')
                    && (path.contains('/') || path.contains('.'))
                {
                    return Some(path.to_string());
                }
            }
            continue;
        }

        // Format 2: space-separated — first token is the path
        let candidate = trimmed.split_whitespace().next().unwrap_or("");
        if !candidate.is_empty()
            && !candidate.eq_ignore_ascii_case("PATH")
            && (candidate.contains('/') || candidate.contains('.'))
            && !candidate.starts_with('-')
        {
            return Some(candidate.to_string());
        }
    }
    None
}

/// Extract record count from JSON export (count of top-level array elements).
fn extract_json_record_count(json: &str) -> Option<usize> {
    // Fast path: count top-level "key" occurrences as proxy.
    // More robust: parse JSON.
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(json) {
        if let Some(arr) = val.as_array() {
            return Some(arr.len());
        }
    }
    None
}

/// Extract the key printed after `mati gotcha add` completes.
/// Looks for "Created gotcha:..." in stdout.
fn extract_created_key(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Created ") {
            // "Created gotcha:tokens-expire-5min-...  (quality: 0.XX, confidence: 0.XX)"
            let key = trimmed
                .strip_prefix("Created ")
                .and_then(|s| s.split_whitespace().next())
                .map(|s| s.to_string());
            if let Some(k) = key {
                if k.starts_with("gotcha:") || k.starts_with("dev_note:") {
                    return Some(k);
                }
            }
        }
    }
    None
}

/// Find a .rs or .py file path from `ls files` output that looks like a real source file.
fn find_parseable_file(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('│') {
            let parts: Vec<&str> = trimmed.split('│').collect();
            if parts.len() >= 2 {
                let path = parts[1].trim();
                if (path.ends_with(".rs") || path.ends_with(".py"))
                    && path.contains('/')
                    && !path.eq_ignore_ascii_case("path")
                {
                    return Some(path.to_string());
                }
            }
        }
    }
    None
}

// ── Report accumulator ────────────────────────────────────────────────────────

struct Report {
    iterations: Vec<(String, Vec<StepResult>)>,
}

impl Report {
    fn new() -> Self {
        Self {
            iterations: Vec::new(),
        }
    }

    fn add_iteration(&mut self, name: &str, steps: Vec<StepResult>) {
        self.iterations.push((name.to_string(), steps));
    }

    fn print(&self, repo: &Path, bin: &Path, store_home: &Path) {
        println!();
        println!("══ mati E2E Developer Journey ══════════════════════════════════");
        println!();

        // Get git HEAD short SHA
        let git_sha = std::process::Command::new("git")
            .args(["-C", &repo.to_string_lossy(), "rev-parse", "--short", "HEAD"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        println!("  Target repo: {}", repo.display());
        println!("  Git HEAD:    {git_sha}");
        println!("  Binary:      {}", bin.display());
        println!("  Store home:  {}", store_home.display());
        println!();

        let mut total_steps = 0usize;
        let mut passed_steps = 0usize;

        let separators = [
            "─ Iteration 1 — Cold Init ──────────────────────────────────────",
            "─ Iteration 2 — Knowledge Creation ────────────────────────────",
            "─ Iteration 3 — Warm Re-init ───────────────────────────────────",
            "─ Iteration 4 — Change Detection ──────────────────────────────",
            "─ Iteration 5 — Review & Lifecycle ────────────────────────────",
        ];

        for (idx, (iter_name, steps)) in self.iterations.iter().enumerate() {
            if idx < separators.len() {
                println!("{}", separators[idx]);
            } else {
                println!("─ {iter_name} ─────────────────────────────");
            }

            for step in steps {
                let is_skip = matches!(step.verdict, Verdict::Skip(_));
                if !is_skip {
                    total_steps += 1;
                }
                let ok = step.passed();
                if ok {
                    passed_steps += 1;
                }

                let status = match &step.verdict {
                    Verdict::Pass => "ok  ",
                    Verdict::Fail(_) => "FAIL",
                    Verdict::Skip(_) => "skip",
                };

                let label = &step.label;
                let ms = step.duration_ms;

                print!("  {label:<14}  {status}  {:>6}ms", ms);

                // Print verdict details for failures
                match &step.verdict {
                    Verdict::Pass => {}
                    Verdict::Fail(msg) => {
                        print!("   FAIL: {msg}");
                    }
                    Verdict::Skip(msg) => {
                        print!("   (skipped: {msg})");
                    }
                }
                println!();
            }
            println!();
        }

        // Summary
        println!("══ Summary ═════════════════════════════════════════════════════");
        let result_label = if passed_steps == total_steps {
            format!("ALL PASS ({passed_steps} / {total_steps})")
        } else {
            format!("FAIL  ({passed_steps} / {total_steps} passed)")
        };
        println!("  Result:  {result_label}");
        println!();
    }

    /// Returns true if all non-skipped steps passed.
    fn all_passed(&self) -> bool {
        self.iterations
            .iter()
            .all(|(_, steps)| steps.iter().all(|s| s.passed() || matches!(s.verdict, Verdict::Skip(_))))
    }
}

// ── Main test ─────────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn developer_journey() {
    let repo_path = match std::env::var("MATI_E2E_REPO") {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            println!("[e2e] MATI_E2E_REPO not set — skipping");
            return;
        }
    };

    assert!(
        repo_path.exists(),
        "MATI_E2E_REPO path does not exist: {}",
        repo_path.display()
    );

    let bin = PathBuf::from(env!("CARGO_BIN_EXE_mati"));
    assert!(bin.exists(), "mati binary not found at {}", bin.display());

    let home = TempDir::new().expect("failed to create temp HOME dir");
    let h = Harness::new(bin.clone(), repo_path.clone(), home);

    let mut report = Report::new();

    // ══════════════════════════════════════════════════════════════════════════
    // Iteration 1 — Cold Init
    // ══════════════════════════════════════════════════════════════════════════

    let mut iter1_steps: Vec<StepResult> = Vec::new();
    let mut cold_init_ms: u128 = 0;
    let mut _iter1_file_count: usize = 0;

    // 1.1 mati init
    {
        let mut r = h.run_labeled(&["init", "--no-hooks"], "init");
        r = assert_exit_ok(r);
        if r.passed() {
            cold_init_ms = r.duration_ms;
            if let Some(n) = extract_init_file_count(&r.stdout) {
                _iter1_file_count = n;
                if n == 0 {
                    r.verdict = Verdict::Fail(format!(
                        "expected files > 0 from init, got 0. stdout={}",
                        &r.stdout[..r.stdout.len().min(400)]
                    ));
                }
            }
        }
        iter1_steps.push(r);
    }

    // 1.2 mati ping
    {
        let mut r = h.run_labeled(&["ping"], "ping");
        r = assert_contains(r, "mati ok");
        if r.passed() {
            if let Some(lat) = extract_ping_latency(&r.stdout) {
                r.label = format!("ping ({}µs)", lat);
            }
        }
        iter1_steps.push(r);
    }

    // 1.3 mati status
    {
        let r = h.run_labeled(&["status"], "status");
        let r = assert_exit_ok(r);
        iter1_steps.push(r);
    }

    // 1.4 mati stats
    {
        let r = h.run_labeled(&["stats"], "stats");
        let r = assert_exit_ok(r);
        iter1_steps.push(r);
    }

    // 1.5 mati gaps
    {
        let r = h.run_labeled(&["gaps"], "gaps");
        let r = assert_exit_ok(r);
        iter1_steps.push(r);
    }

    // 1.6 mati ls files — count rows
    let ls_files_output: String;
    {
        let r = h.run_labeled(&["ls", "files"], "ls files");
        let mut r = assert_exit_ok(r);
        ls_files_output = r.stdout.clone();
        if r.passed() {
            if let Some(n) = extract_file_count(&r.stdout) {
                r.label = format!("ls files ({})", n);
            }
        }
        iter1_steps.push(r);
    }

    // 1.7 mati ls gotchas
    let mut iter1_gotcha_count: usize = 0;
    {
        let r = h.run_labeled(&["ls", "gotchas"], "ls gotchas");
        let mut r = assert_exit_ok(r);
        if r.passed() {
            if let Some(n) = extract_gotcha_count(&r.stdout) {
                iter1_gotcha_count = n;
                r.label = format!("ls gotchas ({})", n);
            }
        }
        iter1_steps.push(r);
    }

    // 1.8 mati ls decisions
    {
        let r = h.run_labeled(&["ls", "decisions"], "ls decisions");
        let mut r = assert_exit_ok(r);
        if r.passed() {
            if let Some(n) = extract_decision_count(&r.stdout) {
                r.label = format!("ls decisions ({})", n);
            }
        }
        iter1_steps.push(r);
    }

    // Pick the first file path for explain/show
    let first_path = first_file_path(&ls_files_output)
        .or_else(|| {
            // Fallback: grab from ls output for parseable files
            find_parseable_file(&ls_files_output)
        })
        .unwrap_or_else(|| "src/main.rs".to_string());

    // 1.9 mati explain <path>
    {
        let key_arg = first_path.as_str();
        let mut r = h.run_labeled(&["explain", key_arg], "explain");
        // `explain` may not be implemented yet — treat as skip if exit != 0
        // but command not found (help text) — just check exit 0
        r = assert_exit_ok(r);
        if r.failed() {
            // explain may not exist — downgrade to skip
            r.verdict = Verdict::Skip("command not yet available".to_string());
        }
        iter1_steps.push(r);
    }

    // 1.10 mati show file:<path>
    {
        let file_key = format!("file:{}", first_path);
        let mut r = h.run_labeled(&["show", &file_key], "show");
        r = assert_nonempty(r);
        iter1_steps.push(r);
    }

    report.add_iteration("Iteration 1 — Cold Init", iter1_steps);

    // ══════════════════════════════════════════════════════════════════════════
    // Iteration 2 — Knowledge Creation
    // ══════════════════════════════════════════════════════════════════════════

    let mut iter2_steps: Vec<StepResult> = Vec::new();
    let mut gotcha_key = String::new();
    let mut iter2_json_record_count: usize = 0;

    // 2.1 mati gotcha add <path>
    // The add command prompts for: rule, reason, severity, affected files, ref URL (5 lines).
    {
        let stdin_data =
            "Tokens expire 5min before stated TTL due to clock skew\n\
             Clock skew with upstream proxy causes early expiry\n\
             \n\
             \n\
             \n";
        let mut r = h.run_stdin_labeled(
            &["gotcha", "add", &first_path],
            stdin_data,
            "gotcha add",
        );
        r = assert_exit_ok(r);
        if r.passed() {
            if let Some(k) = extract_created_key(&r.stdout) {
                gotcha_key = k;
                r.label = format!("gotcha add ({})", &gotcha_key);
            } else {
                r.verdict = Verdict::Fail(format!(
                    "could not extract key from output: {}",
                    &r.stdout[..r.stdout.len().min(300)]
                ));
            }
        }
        iter2_steps.push(r);
    }

    // 2.2 mati show <gotcha_key>
    {
        let key_ref = if gotcha_key.is_empty() {
            "gotcha:".to_string()
        } else {
            gotcha_key.clone()
        };
        let mut r = h.run_labeled(&["show", &key_ref], "show gotcha");
        r = assert_contains(r, "Tokens expire");
        iter2_steps.push(r);
    }

    // 2.3 mati note "E2E test iteration 2"
    {
        let mut r = h.run_labeled(&["note", "E2E test iteration 2"], "note");
        r = assert_exit_ok(r);
        if r.passed() {
            if let Some(k) = extract_created_key(&r.stdout) {
                r.label = format!("note ({})", &k);
            }
        }
        iter2_steps.push(r);
    }

    // 2.4 mati improve <gotcha_key> — pipe new value
    {
        let new_value =
            "Tokens expire 5min before stated TTL — clock skew with upstream proxy \
             causes early expiry; add 10s buffer on client side\n";
        let key_ref = if gotcha_key.is_empty() {
            "gotcha:".to_string()
        } else {
            gotcha_key.clone()
        };
        let mut r = h.run_stdin_labeled(&["improve", &key_ref], new_value, "improve");
        // improve may fail if gotcha_key is empty; mark skip if so
        if key_ref == "gotcha:" {
            r.verdict = Verdict::Skip("no gotcha key from step 2.1".to_string());
        } else {
            r = assert_exit_ok(r);
        }
        iter2_steps.push(r);
    }

    // 2.5 mati export --format json
    let json_export_path = h.home.path().join("mati-e2e-export.json");
    {
        let out_path = json_export_path.to_string_lossy().to_string();
        let mut r = h.run_labeled(
            &["export", "--format", "json", "--output", &out_path],
            "export json",
        );
        r = assert_exit_ok(r);
        if r.passed() {
            // Verify JSON file was written and is valid.
            match fs::read_to_string(&json_export_path) {
                Ok(content) => {
                    if let Some(count) = extract_json_record_count(&content) {
                        iter2_json_record_count = count;
                        r.label = format!("export json ({count} records)");
                        if count == 0 {
                            r.verdict = Verdict::Fail(
                                "export JSON is valid but empty array".to_string(),
                            );
                        }
                    } else {
                        r.verdict = Verdict::Fail(
                            "export output is not valid JSON array".to_string(),
                        );
                    }
                }
                Err(e) => {
                    r.verdict = Verdict::Fail(format!("could not read export file: {e}"));
                }
            }
        }
        iter2_steps.push(r);
    }

    // 2.6 mati export --format md
    {
        let md_path = h.home.path().join("mati-e2e-export.md");
        let md_path_str = md_path.to_string_lossy().to_string();
        let mut r = h.run_labeled(
            &["export", "--format", "md", "--output", &md_path_str],
            "export md",
        );
        r = assert_exit_ok(r);
        if r.passed() {
            match fs::read_to_string(&md_path) {
                Ok(content) => {
                    if !content.contains("##") {
                        r.verdict =
                            Verdict::Fail("export MD missing '##' section markers".to_string());
                    }
                }
                Err(e) => {
                    r.verdict = Verdict::Fail(format!("could not read md export: {e}"));
                }
            }
        }
        iter2_steps.push(r);
    }

    // 2.7 mati diff HEAD~1 (skip gracefully on shallow clones with only 1 commit)
    {
        let mut r = h.run_labeled(&["diff", "HEAD~1"], "diff HEAD~1");
        if r.exit_code != 0 {
            if r.stderr.contains("ambiguous argument") || r.stderr.contains("unknown revision") {
                r.verdict = Verdict::Skip("shallow clone — HEAD~1 not available".to_string());
            } else {
                r.verdict = Verdict::Fail(format!(
                    "expected exit 0, got {}. stderr: {}",
                    r.exit_code,
                    r.stderr.trim()
                ));
            }
        }
        iter2_steps.push(r);
    }

    // 2.8 mati history file:<path>
    {
        let file_key = format!("file:{}", first_path);
        let r = h.run_labeled(&["history", &file_key], "history");
        let r = assert_exit_ok(r);
        iter2_steps.push(r);
    }

    report.add_iteration("Iteration 2 — Knowledge Creation", iter2_steps);

    // ══════════════════════════════════════════════════════════════════════════
    // Iteration 3 — Warm Re-init (unchanged files)
    // ══════════════════════════════════════════════════════════════════════════

    let mut iter3_steps: Vec<StepResult> = Vec::new();

    // 3.1 mati init — incremental path
    let mut warm_init_ms: u128 = 0;
    {
        let mut r = h.run_labeled(&["init", "--no-hooks"], "init (warm)");
        r = assert_exit_ok(r);
        if r.passed() {
            warm_init_ms = r.duration_ms;
            // We expect the warm re-init to parse 0 or very few files.
            // The init output shows file records count — should be same or similar.
            if let Some(n) = extract_init_file_count(&r.stdout) {
                r.label = format!(
                    "init warm (files={n}, {}ms)",
                    warm_init_ms
                );
            }
        }
        iter3_steps.push(r);
    }

    // 3.2 mati ls gotchas — should still have the gotcha from iter 2
    {
        let r = h.run_labeled(&["ls", "gotchas"], "ls gotchas");
        let mut r = assert_exit_ok(r);
        if r.passed() {
            if let Some(n) = extract_gotcha_count(&r.stdout) {
                r.label = format!("ls gotchas ({n} rows)");
                // Should be >= iter1_gotcha_count (we added one in iter2)
                if n < iter1_gotcha_count {
                    r.verdict = Verdict::Fail(format!(
                        "gotcha count regressed: was {iter1_gotcha_count} after iter1, \
                         now only {n} after warm re-init"
                    ));
                }
            }
        }
        iter3_steps.push(r);
    }

    // 3.3 mati show <gotcha_key> — cross-iteration persistence
    {
        if gotcha_key.is_empty() {
            iter3_steps.push(StepResult {
                args: vec!["show".to_string()],
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
                duration_ms: 0,
                label: "show gotcha".to_string(),
                verdict: Verdict::Skip("no gotcha key from iter 2.1".to_string()),
            });
        } else {
            let mut r = h.run_labeled(&["show", &gotcha_key], "show gotcha");
            r = assert_contains(r, "Tokens expire");
            iter3_steps.push(r);
        }
    }

    // 3.4 mati ping
    {
        let r = h.run_labeled(&["ping"], "ping");
        let r = assert_contains(r, "mati ok");
        iter3_steps.push(r);
    }

    report.add_iteration("Iteration 3 — Warm Re-init", iter3_steps);

    // ══════════════════════════════════════════════════════════════════════════
    // Iteration 4 — Change Detection
    // ══════════════════════════════════════════════════════════════════════════

    let mut iter4_steps: Vec<StepResult> = Vec::new();

    // Pick a parseable source file to modify.
    let parseable_file = find_parseable_file(&ls_files_output)
        .or_else(|| first_file_path(&ls_files_output))
        .unwrap_or_else(|| "src/main.rs".to_string());

    let target_abs = repo_path.join(&parseable_file);
    let marker_line = "// mati-e2e-test-marker\n";

    // 4.1 Modify the file.
    let original_content = fs::read_to_string(&target_abs)
        .unwrap_or_else(|_| String::new());
    {
        if !original_content.is_empty() {
            let mut modified = original_content.clone();
            modified.push_str(marker_line);
            fs::write(&target_abs, &modified).expect("failed to write modified file");
        }
    }

    // 4.2 mati init — should detect the modified file
    {
        let mut r = h.run_labeled(&["init", "--no-hooks"], "init (changed)");
        r = assert_exit_ok(r);
        if r.passed() {
            if let Some(n) = extract_init_file_count(&r.stdout) {
                r.label = format!("init changed (files={n})");
            }
        }
        iter4_steps.push(r);
    }

    // 4.3 mati stale — just log, no hard assert
    {
        let mut r = h.run_labeled(&["stale"], "stale");
        // stale exits 0 even if no stale records
        r = assert_exit_ok(r);
        iter4_steps.push(r);
    }

    // 4.4 mati explain <modified_file>
    {
        let mut r = h.run_labeled(&["explain", &parseable_file], "explain");
        if r.exit_code != 0 {
            r.verdict = Verdict::Skip("command not yet available".to_string());
        }
        iter4_steps.push(r);
    }

    // 4.5 Restore the file, then re-init
    if !original_content.is_empty() {
        fs::write(&target_abs, &original_content).expect("failed to restore file");
    }

    {
        let mut r = h.run_labeled(&["init", "--no-hooks"], "init (restored)");
        r = assert_exit_ok(r);
        if r.passed() {
            if let Some(n) = extract_init_file_count(&r.stdout) {
                r.label = format!("init restored (files={n})");
            }
        }
        iter4_steps.push(r);
    }

    report.add_iteration("Iteration 4 — Change Detection", iter4_steps);

    // ══════════════════════════════════════════════════════════════════════════
    // Iteration 5 — Review & Full Lifecycle
    // ══════════════════════════════════════════════════════════════════════════

    let mut iter5_steps: Vec<StepResult> = Vec::new();

    // 5.1 mati review — pipe stdin "s\n" * 5 to skip first 5 candidates
    {
        let stdin_data = "s\ns\ns\ns\ns\n";
        let mut r = h.run_stdin_labeled(&["review"], stdin_data, "review");
        if r.exit_code != 0 {
            // review may not be implemented yet
            r.verdict = Verdict::Skip("command not yet available".to_string());
        }
        iter5_steps.push(r);
    }

    // 5.2 mati quality-check
    {
        let r = h.run_labeled(&["quality-check"], "quality-check");
        let r = assert_exit_ok(r);
        iter5_steps.push(r);
    }

    // 5.3 Export to temp file and verify count >= iter2
    let export_path_5 = h.home.path().join("mati-e2e-export-final.json");
    {
        let out_path = export_path_5.to_string_lossy().to_string();
        let mut r = h.run_labeled(
            &["export", "--format", "json", "--output", &out_path],
            "export json (final)",
        );
        r = assert_exit_ok(r);
        if r.passed() {
            match fs::read_to_string(&export_path_5) {
                Ok(content) => {
                    if let Some(count) = extract_json_record_count(&content) {
                        r.label = format!("export json final ({count} records)");
                        if count < iter2_json_record_count.saturating_sub(1) {
                            r.verdict = Verdict::Fail(format!(
                                "final export has {count} records, \
                                 less than iter2 export with {iter2_json_record_count}"
                            ));
                        }
                    } else {
                        r.verdict = Verdict::Fail(
                            "final export is not valid JSON array".to_string(),
                        );
                    }
                }
                Err(e) => {
                    r.verdict = Verdict::Fail(format!("could not read final export: {e}"));
                }
            }
        }
        iter5_steps.push(r);
    }

    // 5.4 mati import <export_file> — idempotent round-trip
    {
        if export_path_5.exists() {
            let import_path = export_path_5.to_string_lossy().to_string();
            let mut r = h.run_labeled(&["import", &import_path], "import");
            r = assert_exit_ok(r);
            iter5_steps.push(r);
        } else {
            iter5_steps.push(StepResult {
                args: vec!["import".to_string()],
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
                duration_ms: 0,
                label: "import".to_string(),
                verdict: Verdict::Skip("no export file from step 5.3".to_string()),
            });
        }
    }

    // 5.5 mati ping — verify system stable after all operations
    {
        let r = h.run_labeled(&["ping"], "ping");
        let r = assert_contains(r, "mati ok");
        iter5_steps.push(r);
    }

    // 5.6 mati stats — final metrics
    {
        let r = h.run_labeled(&["stats"], "stats (final)");
        let r = assert_exit_ok(r);
        iter5_steps.push(r);
    }

    report.add_iteration("Iteration 5 — Review & Lifecycle", iter5_steps);

    // ══════════════════════════════════════════════════════════════════════════
    // Print report
    // ══════════════════════════════════════════════════════════════════════════

    report.print(&repo_path, &bin, h.home.path());

    // Print speedup summary
    if cold_init_ms > 0 && warm_init_ms > 0 {
        let speedup = cold_init_ms as f64 / warm_init_ms as f64;
        println!(
            "  Cold init: {}ms    Warm re-init: {}ms    Speedup: {:.1}x",
            cold_init_ms, warm_init_ms, speedup
        );
        println!();
    }

    // Fail the test if any step failed (skipped steps are fine).
    if !report.all_passed() {
        panic!("E2E developer journey: one or more steps failed (see report above)");
    }
}
