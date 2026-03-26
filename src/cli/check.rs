//! `mati check` — verify the full hook enforcement pipeline is operational.
//!
//! Runs 7 checks in order, collects results, prints aligned output, then exits
//! with code 1 if any check failed. Warnings do not affect the exit code.
//!
//! Also exposes [`run_silent`] for use by `mati init` to surface warnings at
//! the end of the init flow without re-implementing all checks.

use std::path::{Path, PathBuf};

use anyhow::Result;
use mati_core::scaffold::settings::HOOK_SCRIPTS;

use crate::cli::daemon::{daemon_result, mati_root_for, DaemonResult};

// ── Result types ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct CheckItem {
    /// Short label, padded to 15 chars when printed.
    pub label: &'static str,
    pub status: CheckStatus,
    /// Multi-line hints printed below the status line on Warn/Fail.
    pub hint: Option<String>,
}

#[derive(Debug)]
pub enum CheckStatus {
    Pass(Option<String>),
    Warn(String),
    Fail(String),
}

impl CheckItem {
    fn pass(label: &'static str, detail: Option<String>) -> Self {
        Self { label, status: CheckStatus::Pass(detail), hint: None }
    }

    fn warn(label: &'static str, msg: impl Into<String>, hint: impl Into<Option<String>>) -> Self {
        Self {
            label,
            status: CheckStatus::Warn(msg.into()),
            hint: hint.into(),
        }
    }

    fn fail(label: &'static str, msg: impl Into<String>, hint: impl Into<Option<String>>) -> Self {
        Self {
            label,
            status: CheckStatus::Fail(msg.into()),
            hint: hint.into(),
        }
    }

    pub fn is_fail(&self) -> bool {
        matches!(self.status, CheckStatus::Fail(_))
    }
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Run all checks, print aligned output, exit 1 if any FAIL.
pub async fn run() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let items = run_silent(&cwd).await;
    print_results(&items);
    let failures = items.iter().filter(|i| i.is_fail()).count();
    if failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Run all checks and return results without printing anything.
/// Used by `mati init` to surface warnings at the end of init.
pub async fn run_silent(cwd: &Path) -> Vec<CheckItem> {
    let mut items = Vec::with_capacity(7);

    // ── Check 1: git repo ────────────────────────────────────────────────────
    items.push(check_git_repo(cwd));

    // ── Check 2: store initialized ───────────────────────────────────────────
    let (store_item, mati_root_opt) = check_store(cwd);
    items.push(store_item);

    // ── Check 3: mati on PATH ────────────────────────────────────────────────
    items.push(check_mati_on_path());

    // ── Check 4: awk float math ──────────────────────────────────────────────
    items.push(check_awk_float_math());

    // ── Check 5: hooks installed + executable ────────────────────────────────
    items.push(check_hooks(cwd));

    // ── Check 6: settings.json complete ─────────────────────────────────────
    items.push(check_settings_json(cwd));

    // ── Check 7: daemon reachable ────────────────────────────────────────────
    items.push(check_daemon(mati_root_opt).await);

    items
}

// ── Individual checks ─────────────────────────────────────────────────────────

fn check_git_repo(cwd: &Path) -> CheckItem {
    match git2::Repository::discover(cwd) {
        Ok(_) => CheckItem::pass("git repo", None),
        Err(_) => CheckItem::fail(
            "git repo",
            "not a git repo",
            Some("Layer 0 analysis and slug derivation require git".to_string()),
        ),
    }
}

/// Returns the check item and, if the store path is derivable, the mati root
/// path (needed for check 7). Does NOT call `Store::open()` — just checks file
/// existence to avoid racing with a running daemon.
fn check_store(cwd: &Path) -> (CheckItem, Option<PathBuf>) {
    let root = match mati_root_for(cwd) {
        Ok(r) => r,
        Err(e) => {
            return (
                CheckItem::fail(
                    "store",
                    format!("cannot derive store path: {e}"),
                    None::<String>,
                ),
                None,
            );
        }
    };

    let db_path = root.join("knowledge.db");
    if !db_path.exists() {
        return (
            CheckItem::fail(
                "store",
                "store not initialized",
                Some("run: mati init".to_string()),
            ),
            Some(root),
        );
    }

    let detail = format!("{}", db_path.display());
    (CheckItem::pass("store", Some(detail)), Some(root))
}

fn check_mati_on_path() -> CheckItem {
    let result = std::process::Command::new("mati")
        .arg("--version")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output();

    match result {
        Ok(out) if out.status.success() => {
            let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
            CheckItem::pass("mati in PATH", Some(version))
        }
        Ok(_) => CheckItem::fail(
            "mati in PATH",
            "mati --version returned non-zero",
            Some(
                "hooks call mati get/log-hit/etc. and will silently pass everything through"
                    .to_string(),
            ),
        ),
        Err(_) => CheckItem::fail(
            "mati in PATH",
            "mati not on PATH",
            Some(
                "hooks call mati get/log-hit/etc. and will silently pass everything through"
                    .to_string(),
            ),
        ),
    }
}

fn check_awk_float_math() -> CheckItem {
    // Hooks use awk for float comparison: `awk "BEGIN { exit !(0.7 >= 0.6) }"`
    // Exit code 0 = true, non-zero = false.
    let result = std::process::Command::new("sh")
        .arg("-c")
        .arg(r#"awk "BEGIN { exit !(0.7 >= 0.6) }" && echo ok"#)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output();

    match result {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.trim() == "ok" {
                CheckItem::pass("awk float math", None)
            } else {
                CheckItem::fail(
                    "awk float math",
                    "awk float math failed",
                    Some(
                        "pre-read hook decision matrix will silently allow all reads until fixed"
                            .to_string(),
                    ),
                )
            }
        }
        Err(_) => CheckItem::fail(
            "awk float math",
            "awk not found",
            Some(
                "pre-read hook decision matrix requires awk — install gawk or ensure awk is on PATH"
                    .to_string(),
            ),
        ),
    }
}

fn check_hooks(cwd: &Path) -> CheckItem {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let hooks_dir = cwd.join(".claude").join("hooks");
    let total = HOOK_SCRIPTS.len();
    let mut missing: Vec<String> = Vec::new();
    let mut not_exec: Vec<String> = Vec::new();

    for (name, _) in HOOK_SCRIPTS {
        let path = hooks_dir.join(name);
        if !path.exists() {
            missing.push(name.to_string());
            continue;
        }
        #[cfg(unix)]
        match std::fs::metadata(&path) {
            Ok(meta) => {
                let mode = meta.permissions().mode();
                if mode & 0o111 == 0 {
                    not_exec.push(name.to_string());
                }
            }
            Err(_) => {
                missing.push(name.to_string());
            }
        }
    }

    if missing.is_empty() && not_exec.is_empty() {
        return CheckItem::pass(
            "hooks",
            Some(format!("{total}/{total} installed, executable")),
        );
    }

    let mut problems = Vec::new();
    if !missing.is_empty() {
        problems.push(format!("missing: {}", missing.join(", ")));
    }
    if !not_exec.is_empty() {
        problems.push(format!("not executable: {}", not_exec.join(", ")));
    }

    CheckItem::fail(
        "hooks",
        format!(
            "{}/{total} ok — {}",
            total - missing.len() - not_exec.len(),
            problems.join("; ")
        ),
        Some("run: mati init  to reinstall hooks".to_string()),
    )
}

fn check_settings_json(cwd: &Path) -> CheckItem {
    let path = cwd.join(".claude").join("settings.json");
    if !path.exists() {
        return CheckItem::fail(
            "settings.json",
            "settings.json not found",
            Some("run: mati init".to_string()),
        );
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            return CheckItem::fail(
                "settings.json",
                format!("cannot read settings.json: {e}"),
                None::<String>,
            );
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return CheckItem::fail(
                "settings.json",
                format!("invalid JSON: {e}"),
                Some("run: mati init  to regenerate settings.json".to_string()),
            );
        }
    };

    // Check that each hook script path appears somewhere in the JSON content.
    let mut absent_hooks: Vec<&str> = Vec::new();
    for (name, _) in HOOK_SCRIPTS {
        let hook_path = format!(".claude/hooks/{name}");
        if !content.contains(&hook_path) {
            absent_hooks.push(name);
        }
    }

    // Check mcpServers.mati exists.
    let mcp_ok = json
        .get("mcpServers")
        .and_then(|s| s.get("mati"))
        .is_some();

    if absent_hooks.is_empty() && mcp_ok {
        return CheckItem::pass(
            "settings.json",
            Some(format!("{} hooks + mcpServers registered", HOOK_SCRIPTS.len())),
        );
    }

    let mut problems = Vec::new();
    if !absent_hooks.is_empty() {
        problems.push(format!("hooks absent: {}", absent_hooks.join(", ")));
    }
    if !mcp_ok {
        problems.push("mcpServers.mati missing".to_string());
    }

    CheckItem::fail(
        "settings.json",
        problems.join("; "),
        Some("run: mati init  to regenerate settings.json".to_string()),
    )
}

async fn check_daemon(mati_root_opt: Option<PathBuf>) -> CheckItem {
    let root = match mati_root_opt {
        Some(r) => r,
        None => {
            return CheckItem::warn(
                "daemon",
                "skipped (store not initialized)",
                None::<String>,
            );
        }
    };

    let t0 = std::time::Instant::now();
    let result = daemon_result(&root, "ping", serde_json::json!({})).await;
    let latency = t0.elapsed();

    match result {
        DaemonResult::Ok(_) => {
            let ms = latency.as_secs_f64() * 1000.0;
            CheckItem::pass("daemon", Some(format!("ping {ms:.1}ms")))
        }
        DaemonResult::NotRunning | DaemonResult::StaleSocket => CheckItem::warn(
            "daemon",
            "not running — hook latency ~150ms",
            Some("run: mati daemon start".to_string()),
        ),
        DaemonResult::Unresponsive => CheckItem::fail(
            "daemon",
            "daemon unresponsive — may hold store lock",
            Some("fix: mati daemon stop && mati daemon start".to_string()),
        ),
    }
}

// ── Output ────────────────────────────────────────────────────────────────────

fn print_results(items: &[CheckItem]) {
    println!("\nmati check\n");

    for item in items {
        print_item(item);
    }

    println!();

    let failures = items.iter().filter(|i| i.is_fail()).count();
    let warnings = items
        .iter()
        .filter(|i| matches!(i.status, CheckStatus::Warn(_)))
        .count();

    if failures == 0 && warnings == 0 {
        println!("  All checks passed. Hook enforcement is active.");
    } else if failures == 0 {
        println!(
            "  {} warning(s). Hook enforcement is active but degraded.",
            warnings
        );
    } else {
        println!(
            "  {} blocker(s) found. Hook enforcement is NOT active.",
            failures
        );
    }
    println!();
}

/// Print a single check line, with continuation lines for hints.
fn print_item(item: &CheckItem) {
    // Label column: 15 chars, left-padded with 2 spaces for indent.
    let label = format!("  {:<15}", item.label);

    match &item.status {
        CheckStatus::Pass(extra) => {
            let extra_str = extra.as_deref().unwrap_or("");
            if extra_str.is_empty() {
                println!("{label}  ok");
            } else {
                println!("{label}  ok  ({extra_str})");
            }
        }
        CheckStatus::Warn(msg) => {
            println!("{label}  warn  {msg}");
            if let Some(hint) = &item.hint {
                for line in hint.lines() {
                    println!("{:19}       {line}", "");
                }
            }
        }
        CheckStatus::Fail(msg) => {
            println!("{label}  FAIL  {msg}");
            if let Some(hint) = &item.hint {
                for line in hint.lines() {
                    println!("{:19}       {line}", "");
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── Check 4: awk float math ───────────────────────────────────────────────

    #[test]
    fn check_awk_float_math_passes() {
        // awk is available on all platforms where hooks run.
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(r#"awk "BEGIN { exit !(0.7 >= 0.6) }" && echo ok"#)
            .output();

        match out {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                assert_eq!(
                    stdout.trim(),
                    "ok",
                    "awk should exit 0 for 0.7 >= 0.6; got: {stdout:?}"
                );
            }
            Err(e) => {
                eprintln!("awk not available on this machine, skipping test: {e}");
            }
        }
    }

    #[test]
    fn check_awk_fail_produces_non_ok_output() {
        // Simulate awk failing — exit code 1 means false.
        let result = std::process::Command::new("sh")
            .arg("-c")
            .arg(r#"awk "BEGIN { exit !(0.5 >= 0.6) }" && echo ok || echo fail"#)
            .output();

        if let Ok(out) = result {
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert_eq!(
                stdout.trim(),
                "fail",
                "expected fail output for 0.5 >= 0.6; got: {stdout:?}"
            );
        }
    }

    // ── Check 5: hook executable detection ───────────────────────────────────

    #[test]
    fn check_hook_executable_detection_catches_missing_bit() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let hooks_dir = dir.path().join(".claude").join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();

        // Write all hook scripts and make them all executable first.
        for (name, content) in HOOK_SCRIPTS {
            let path = hooks_dir.join(name);
            std::fs::write(&path, content).unwrap();
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();
        }

        // Strip the executable bit from the first hook.
        if let Some((first_name, _)) = HOOK_SCRIPTS.first() {
            let first_path = hooks_dir.join(first_name);
            let mut perms = std::fs::metadata(&first_path).unwrap().permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&first_path, perms).unwrap();
        }

        let item = check_hooks(dir.path());
        assert!(
            item.is_fail(),
            "expected FAIL when first hook is not executable: {:?}",
            item.status
        );
    }

    #[test]
    fn check_hook_passes_when_all_installed_and_executable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let hooks_dir = dir.path().join(".claude").join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();

        for (name, content) in HOOK_SCRIPTS {
            let path = hooks_dir.join(name);
            std::fs::write(&path, content).unwrap();
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();
        }

        let item = check_hooks(dir.path());
        assert!(
            !item.is_fail(),
            "expected PASS when all hooks are present and executable: {:?}",
            item.status
        );
    }

    // ── Check 6: settings.json parsing ───────────────────────────────────────

    #[test]
    fn check_settings_json_valid_passes() {
        let dir = TempDir::new().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        // Build a settings.json that contains all hook script paths and mati mcp.
        let hook_entries: Vec<String> = HOOK_SCRIPTS
            .iter()
            .map(|(name, _)| format!("\".claude/hooks/{name}\""))
            .collect();
        let hooks_array = hook_entries.join(", ");

        let json = format!(
            r#"{{
  "hooks": {{ "PreToolUse": [{}] }},
  "mcpServers": {{ "mati": {{ "command": "mati", "args": ["serve"] }} }}
}}"#,
            hooks_array
        );

        std::fs::write(claude_dir.join("settings.json"), &json).unwrap();

        let item = check_settings_json(dir.path());
        assert!(
            !item.is_fail(),
            "expected PASS for valid settings.json: {:?}",
            item.status
        );
    }

    #[test]
    fn check_settings_json_missing_hook_fails() {
        let dir = TempDir::new().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        // Only include the first hook entry — the rest are absent.
        let first_hook = HOOK_SCRIPTS.first().map(|(n, _)| *n).unwrap_or("pre-read.sh");

        let json = format!(
            r#"{{
  "hooks": {{ "PreToolUse": [".claude/hooks/{first_hook}"] }},
  "mcpServers": {{ "mati": {{ "command": "mati", "args": ["serve"] }} }}
}}"#
        );

        std::fs::write(claude_dir.join("settings.json"), &json).unwrap();

        let item = check_settings_json(dir.path());
        // Should fail because not all hooks are referenced.
        if HOOK_SCRIPTS.len() > 1 {
            assert!(
                item.is_fail(),
                "expected FAIL when hooks are missing from settings.json: {:?}",
                item.status
            );
        }
    }

    #[test]
    fn check_settings_json_missing_mcp_fails() {
        let dir = TempDir::new().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        // Include all hook paths but no mcpServers entry.
        let hook_entries: Vec<String> = HOOK_SCRIPTS
            .iter()
            .map(|(name, _)| format!("\".claude/hooks/{name}\""))
            .collect();
        let hooks_array = hook_entries.join(", ");

        let json = format!(r#"{{ "hooks": {{ "PreToolUse": [{}] }} }}"#, hooks_array);

        std::fs::write(claude_dir.join("settings.json"), &json).unwrap();

        let item = check_settings_json(dir.path());
        assert!(
            item.is_fail(),
            "expected FAIL when mcpServers.mati is absent: {:?}",
            item.status
        );
    }
}
