//! Output regression tests — protect user-facing CLI wording and structure.
//!
//! These tests verify the stable parts of mati's command output that define
//! the product experience: workflow framing, trust/provenance vocabulary,
//! section headers, guidance text, and "what next?" hints.
//!
//! Design principles:
//! - Assert on structural elements (section headers, guidance phrases), not exact counts/timing
//! - All commands run in non-TTY mode (piped stdout), so ANSI codes are stripped automatically
//! - Each test uses an isolated HOME + tempdir git repo for full store isolation
//! - Tests are fast: tiny repos, no network, no LLM calls
//!
//! # Running
//!
//! ```sh
//! cargo test --test output_regression
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn mati_bin() -> PathBuf {
    let env_key = "CARGO_BIN_EXE_MATI";
    if let Ok(p) = std::env::var(env_key) {
        return PathBuf::from(p);
    }
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(manifest).join("target").join("debug").join("mati")
}

/// Run mati with the given args, isolating HOME to `home` and CWD to `repo`.
fn run(bin: &Path, repo: &Path, home: &Path, args: &[&str]) -> (String, String, bool) {
    let out = Command::new(bin)
        .args(args)
        .current_dir(repo)
        .env("HOME", home)
        .env("NO_COLOR", "1") // belt-and-suspenders: some CLIs respect this
        .output()
        .expect("failed to run mati");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (stdout, stderr, out.status.success())
}

/// Create a minimal git repo with one Rust file and one commit.
/// Returns (repo_dir, home_dir) — both are TempDirs that must be kept alive.
fn setup_repo() -> (TempDir, TempDir) {
    let repo_dir = TempDir::new().expect("create repo dir");
    let home_dir = TempDir::new().expect("create home dir");
    let repo = repo_dir.path();

    // git init + configure identity
    Command::new("git")
        .args(["init"])
        .current_dir(repo)
        .output()
        .expect("git init");
    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(repo)
        .output()
        .expect("git config email");
    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(repo)
        .output()
        .expect("git config name");

    // Create src/main.rs
    std::fs::create_dir_all(repo.join("src")).expect("mkdir src");
    std::fs::write(
        repo.join("src/main.rs"),
        r#"fn main() {
    println!("hello");
}

fn helper() -> Result<(), Box<dyn std::error::Error>> {
    // TODO: handle error properly
    let x = std::fs::read_to_string("config.toml")?;
    Ok(())
}
"#,
    )
    .expect("write main.rs");

    // Create src/lib.rs (for co-change / multi-file tests)
    std::fs::write(
        repo.join("src/lib.rs"),
        r#"pub fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#,
    )
    .expect("write lib.rs");

    // Create Cargo.toml
    std::fs::write(
        repo.join("Cargo.toml"),
        r#"[package]
name = "test-project"
version = "0.1.0"
edition = "2021"
"#,
    )
    .expect("write Cargo.toml");

    // Initial commit
    Command::new("git")
        .args(["add", "-A"])
        .current_dir(repo)
        .output()
        .expect("git add");
    Command::new("git")
        .args(["commit", "-m", "initial commit"])
        .current_dir(repo)
        .output()
        .expect("git commit");

    (repo_dir, home_dir)
}

/// Run `mati init --no-hooks` and return stdout.
fn init_repo(bin: &Path, repo: &Path, home: &Path) -> String {
    let (stdout, stderr, ok) = run(bin, repo, home, &["init", "--no-hooks"]);
    if !ok {
        panic!("mati init failed:\nstdout: {stdout}\nstderr: {stderr}");
    }
    stdout
}

// Strip ANSI escape codes (safety net if NO_COLOR isn't respected)
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn assert_contains(haystack: &str, needle: &str) {
    let clean = strip_ansi(haystack);
    assert!(
        clean.contains(needle),
        "Expected output to contain: {needle:?}\n\n--- Actual output ---\n{clean}"
    );
}


// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

// ── 1. Top-level help: workflow framing ─────────────────────────────────────

#[test]
fn help_workflow_framing() {
    let bin = mati_bin();
    let (stdout, _stderr, ok) = run(
        &bin,
        Path::new("."),
        Path::new("/tmp"),
        &["--help"],
    );
    assert!(ok, "mati --help should succeed");
    let out = strip_ansi(&stdout);

    // Product identity (long_about shown with --help)
    assert_contains(&out, "persistent, queryable knowledge store");

    // Core workflow commands must appear
    assert_contains(&out, "mati init");
    assert_contains(&out, "mati explain <file>");
    assert_contains(&out, "mati diff <range>");
    assert_contains(&out, "mati status");

    // Workflow role descriptions
    assert_contains(&out, "build project memory");
    assert_contains(&out, "file briefing");
    assert_contains(&out, "pre-merge check");
    assert_contains(&out, "project memory dashboard");
}

#[test]
fn help_subcommands_present() {
    let bin = mati_bin();
    let (stdout, _stderr, ok) = run(
        &bin,
        Path::new("."),
        Path::new("/tmp"),
        &["--help"],
    );
    assert!(ok);
    let out = strip_ansi(&stdout);

    // Core workflow
    for cmd in &["init", "explain", "diff", "status"] {
        assert_contains(&out, cmd);
    }

    // Knowledge management
    for cmd in &["gotcha", "show", "gaps", "stats"] {
        assert_contains(&out, cmd);
    }

    // Maintenance
    for cmd in &["review", "repair", "stale"] {
        assert_contains(&out, cmd);
    }

    // Infrastructure
    for cmd in &["serve", "daemon", "ping"] {
        assert_contains(&out, cmd);
    }
}

// ── 2. Init: summary structure and next steps ──────────────────────────────

#[test]
fn init_next_steps_guidance() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    let stdout = init_repo(&bin, repo_dir.path(), home_dir.path());

    // Project header
    assert_contains(&stdout, "mati");

    // Summary metrics (labels, not values — values vary)
    assert_contains(&stdout, "file records:");
    assert_contains(&stdout, "graph edges:");

    // Zero-token claim
    assert_contains(&stdout, "0 tokens");
    assert_contains(&stdout, "0 Claude calls");

    // Next steps — the most important product guidance
    assert_contains(&stdout, "Next steps");
    assert_contains(&stdout, "mati explain <file>");
    assert_contains(&stdout, "mati review");
    assert_contains(&stdout, "mati status");

    // Next steps descriptions
    assert_contains(&stdout, "file briefing");
    assert_contains(&stdout, "confirm auto-detected candidates");
    assert_contains(&stdout, "project memory dashboard");
}

#[test]
fn init_summary_has_candidate_categories() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    let stdout = init_repo(&bin, repo_dir.path(), home_dir.path());

    // Layer 0 candidate categories
    assert_contains(&stdout, "gotcha candidates:");
    assert_contains(&stdout, "dep records:");
    assert_contains(&stdout, "hotspot files:");
}

// ── 3. Explain: output sections and trust cues ─────────────────────────────

#[test]
fn explain_output_structure() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    init_repo(&bin, repo_dir.path(), home_dir.path());

    let (stdout, _stderr, ok) = run(
        &bin,
        repo_dir.path(),
        home_dir.path(),
        &["explain", "src/main.rs"],
    );
    assert!(ok, "mati explain should succeed");

    // Header: filename + purpose line
    assert_contains(&stdout, "main.rs");

    // Trust cues present in metadata line
    assert_contains(&stdout, "confidence");
    assert_contains(&stdout, "quality");
    assert_contains(&stdout, "source:");

    // Guidance for uncaptured state — file has no gotchas after init
    // Should suggest adding one
    assert_contains(&stdout, "mati gotcha add");
}

#[test]
fn explain_todo_section() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    init_repo(&bin, repo_dir.path(), home_dir.path());

    let (stdout, _stderr, ok) = run(
        &bin,
        repo_dir.path(),
        home_dir.path(),
        &["explain", "src/main.rs"],
    );
    assert!(ok);

    // Our test file has a TODO comment — explain should surface it
    assert_contains(&stdout, "TODOs");
    assert_contains(&stdout, "handle error");
}

#[test]
fn explain_missing_file_suggests_init() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    init_repo(&bin, repo_dir.path(), home_dir.path());

    let (stdout, stderr, _ok) = run(
        &bin,
        repo_dir.path(),
        home_dir.path(),
        &["explain", "nonexistent/file.rs"],
    );
    let combined = format!("{stdout}{stderr}");

    // Should tell the user what to do
    assert_contains(&combined, "mati init");
}

// ── 4. Diff: symbols, summary, and guidance ────────────────────────────────

#[test]
fn diff_output_structure() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    let repo = repo_dir.path();
    init_repo(&bin, repo, home_dir.path());

    // Add a second commit so we have a diff range
    std::fs::write(
        repo.join("src/main.rs"),
        r#"fn main() {
    println!("updated");
}
"#,
    )
    .expect("update main.rs");
    Command::new("git")
        .args(["add", "src/main.rs"])
        .current_dir(repo)
        .output()
        .expect("git add");
    Command::new("git")
        .args(["commit", "-m", "update main"])
        .current_dir(repo)
        .output()
        .expect("git commit");

    let (stdout, _stderr, ok) = run(
        &bin,
        repo,
        home_dir.path(),
        &["diff", "HEAD~1"],
    );
    assert!(ok, "mati diff should succeed");

    // Header shows the range
    assert_contains(&stdout, "Files changed in");
    assert_contains(&stdout, "HEAD~1");

    // Summary line has the right vocabulary
    assert_contains(&stdout, "changed");

    // Status symbols vocabulary (at least one of these per file)
    let has_symbol = stdout.contains("documented")
        || stdout.contains("no records yet")
        || stdout.contains("confirmed gotcha");
    assert!(
        has_symbol,
        "diff output should classify files\n--- stdout ---\n{stdout}"
    );
}

#[test]
fn diff_summary_line_format() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    let repo = repo_dir.path();
    init_repo(&bin, repo, home_dir.path());

    // Second commit
    std::fs::write(repo.join("src/lib.rs"), "pub fn sub(a: i32, b: i32) -> i32 { a - b }\n")
        .expect("update lib.rs");
    Command::new("git")
        .args(["add", "src/lib.rs"])
        .current_dir(repo)
        .output()
        .expect("git add");
    Command::new("git")
        .args(["commit", "-m", "update lib"])
        .current_dir(repo)
        .output()
        .expect("git commit");

    let (stdout, _stderr, ok) = run(
        &bin,
        repo,
        home_dir.path(),
        &["diff", "HEAD~1"],
    );
    assert!(ok);

    // Summary line must include all three counters
    assert_contains(&stdout, "with gotchas");
    assert_contains(&stdout, "documented");
    assert_contains(&stdout, "unknown");
}

// ── 5. Status: dashboard sections and trust vocabulary ─────────────────────

#[test]
fn status_dashboard_sections() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    init_repo(&bin, repo_dir.path(), home_dir.path());

    let (stdout, _stderr, ok) = run(
        &bin,
        repo_dir.path(),
        home_dir.path(),
        &["status"],
    );
    assert!(ok, "mati status should succeed");

    // Dashboard header
    assert_contains(&stdout, "mati status");

    // Core sections
    assert_contains(&stdout, "Records");
    assert_contains(&stdout, "Confirmed");
    assert_contains(&stdout, "Confidence");
    assert_contains(&stdout, "Hotspots");

    // Record type vocabulary
    assert_contains(&stdout, "files");
    assert_contains(&stdout, "gotchas");
}

#[test]
fn status_trust_section_with_unconfirmed() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    init_repo(&bin, repo_dir.path(), home_dir.path());

    let (stdout, _stderr, ok) = run(
        &bin,
        repo_dir.path(),
        home_dir.path(),
        &["status"],
    );
    assert!(ok);

    // After init, there are unconfirmed candidates — trust section should appear
    // with guidance to run review. If no gotcha candidates were generated,
    // the "No gotchas yet" guidance should appear instead.
    let has_trust_guidance = stdout.contains("mati review")
        || stdout.contains("No gotchas yet");
    assert!(
        has_trust_guidance,
        "status should show trust guidance or no-gotchas hint\n--- stdout ---\n{stdout}"
    );
}

// ── 6. Repair: check mode output ───────────────────────────────────────────

#[test]
fn repair_check_clean_state() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    init_repo(&bin, repo_dir.path(), home_dir.path());

    let (stdout, _stderr, ok) = run(
        &bin,
        repo_dir.path(),
        home_dir.path(),
        &["repair", "--check"],
    );
    // After a clean init, there should be no drift → exit 0
    assert!(ok, "repair --check should succeed on clean state");

    // Must report what was scanned
    assert_contains(&stdout, "mati repair --check");
    assert_contains(&stdout, "gotchas");
    assert_contains(&stdout, "files");

    // Clean state message
    assert_contains(&stdout, "No drift detected");
    assert_contains(&stdout, "consistent");
}

#[test]
fn repair_check_json_output() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    init_repo(&bin, repo_dir.path(), home_dir.path());

    let (stdout, _stderr, ok) = run(
        &bin,
        repo_dir.path(),
        home_dir.path(),
        &["repair", "--check", "--json"],
    );
    assert!(ok, "repair --check --json should succeed on clean state");

    // Output should be valid JSON with expected fields
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .expect("repair --check --json should produce valid JSON");
    assert!(v.get("scanned_gotchas").is_some(), "JSON should have scanned_gotchas");
    assert!(v.get("scanned_files").is_some(), "JSON should have scanned_files");
}

// ── 7. Review help: explains the workflow ──────────────────────────────────

#[test]
fn review_help_explains_workflow() {
    let bin = mati_bin();
    let (stdout, _stderr, ok) = run(
        &bin,
        Path::new("."),
        Path::new("/tmp"),
        &["review", "--help"],
    );
    assert!(ok, "mati review --help should succeed");

    // Must explain what candidates are and what confirmation enables
    assert_contains(&stdout, "auto-detected");
    assert_contains(&stdout, "hook enforcement");
    assert_contains(&stdout, "candidates");
}

// ── 8. Repair help: explains trust semantics ───────────────────────────────

#[test]
fn repair_help_explains_semantics() {
    let bin = mati_bin();
    let (stdout, _stderr, ok) = run(
        &bin,
        Path::new("."),
        Path::new("/tmp"),
        &["repair", "--help"],
    );
    assert!(ok, "mati repair --help should succeed");

    // Must reference canonical records
    assert_contains(&stdout, "canonical");

    // --check flag documented with CI mention
    assert_contains(&stdout, "--check");
    assert_contains(&stdout, "CI");

    // --fast flag documented with integrity caveat
    assert_contains(&stdout, "--fast");
    assert_contains(&stdout, "integrity");
}

// ── 9. Explain help: describes the briefing ────────────────────────────────

#[test]
fn explain_help_describes_briefing() {
    let bin = mati_bin();
    let (stdout, _stderr, ok) = run(
        &bin,
        Path::new("."),
        Path::new("/tmp"),
        &["explain", "--help"],
    );
    assert!(ok);

    assert_contains(&stdout, "briefing");
    assert_contains(&stdout, "gotchas");
    assert_contains(&stdout, "decisions");
    assert_contains(&stdout, "co-change");
}

// ── 10. Diff help: describes pre-merge use case ────────────────────────────

#[test]
fn diff_help_describes_premerge() {
    let bin = mati_bin();
    let (stdout, _stderr, ok) = run(
        &bin,
        Path::new("."),
        Path::new("/tmp"),
        &["diff", "--help"],
    );
    assert!(ok);

    assert_contains(&stdout, "Pre-merge");
    assert_contains(&stdout, "gotchas");

    // Range argument with examples
    assert_contains(&stdout, "main");
}
