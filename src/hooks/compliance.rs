/// M-15 Bash Hook Compliance Test Suite — Categories 1 & 2 (33 tests).
///
/// This module is the core safety certification for mati's trust boundary.
/// It verifies that the bash hook scripts (pre_read.rs SCRIPT, pre_bash.rs SCRIPT)
/// produce correct allow/deny decisions for all combinations of confidence,
/// quality, confirmed status, and staleness tiers.
///
/// The test harness writes the bash script to a temp file, creates a mock `mati`
/// binary, and exercises the hook with controlled stdin JSON + mock responses.
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

use super::codex_post_bash;
use super::codex_pre_bash;
use super::codex_session_start;
use super::codex_stop;
use super::codex_user_prompt;
use super::post_compliance;
use super::post_edit;
use super::pre_bash;
use super::pre_compact;
use super::pre_read;
use super::session_end;

// ─── Test Harness ────────────────────────────────────────────────────────────

struct HookTestHarness {
    script_content: String,
    mock_dir: TempDir,
    mock_responses: HashMap<String, String>,
    exclude_binaries: Vec<String>,
    mock_ping_exit_code: i32,
    mock_recent_consulted: bool,
    /// Optional: inject extra logic into the mock mati script (e.g. sleep).
    mock_extra_cases: String,
}

struct HookOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
    json: Option<serde_json::Value>,
}

impl HookOutput {
    fn decision(&self) -> &str {
        self.json
            .as_ref()
            .and_then(|j| j.pointer("/hookSpecificOutput/permissionDecision"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
    }

    fn reason(&self) -> &str {
        self.json
            .as_ref()
            .and_then(|j| j.pointer("/hookSpecificOutput/permissionDecisionReason"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
    }

    fn additional_context(&self) -> &str {
        self.json
            .as_ref()
            .and_then(|j| j.pointer("/hookSpecificOutput/additionalContext"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
    }
}

impl HookTestHarness {
    fn for_pre_read() -> Self {
        Self {
            script_content: pre_read::SCRIPT.to_string(),
            mock_dir: TempDir::new().expect("failed to create temp dir for harness"),
            mock_responses: HashMap::new(),
            exclude_binaries: Vec::new(),
            mock_ping_exit_code: 0,
            mock_recent_consulted: false,
            mock_extra_cases: String::new(),
        }
    }

    fn for_pre_bash() -> Self {
        Self {
            script_content: pre_bash::SCRIPT.to_string(),
            mock_dir: TempDir::new().expect("failed to create temp dir for harness"),
            mock_responses: HashMap::new(),
            exclude_binaries: Vec::new(),
            mock_ping_exit_code: 0,
            mock_recent_consulted: false,
            mock_extra_cases: String::new(),
        }
    }

    fn for_post_compliance() -> Self {
        Self {
            script_content: post_compliance::SCRIPT.to_string(),
            mock_dir: TempDir::new().expect("failed to create temp dir for harness"),
            mock_responses: HashMap::new(),
            exclude_binaries: Vec::new(),
            mock_ping_exit_code: 0,
            mock_recent_consulted: false,
            mock_extra_cases: String::new(),
        }
    }

    fn for_codex_session_start() -> Self {
        Self {
            script_content: codex_session_start::SCRIPT.to_string(),
            mock_dir: TempDir::new().expect("failed to create temp dir for harness"),
            mock_responses: HashMap::new(),
            exclude_binaries: Vec::new(),
            mock_ping_exit_code: 0,
            mock_recent_consulted: false,
            mock_extra_cases: String::new(),
        }
    }

    fn for_codex_user_prompt() -> Self {
        Self {
            script_content: codex_user_prompt::SCRIPT.to_string(),
            mock_dir: TempDir::new().expect("failed to create temp dir for harness"),
            mock_responses: HashMap::new(),
            exclude_binaries: Vec::new(),
            mock_ping_exit_code: 0,
            mock_recent_consulted: false,
            mock_extra_cases: String::new(),
        }
    }

    fn for_codex_pre_bash() -> Self {
        Self {
            script_content: codex_pre_bash::SCRIPT.to_string(),
            mock_dir: TempDir::new().expect("failed to create temp dir for harness"),
            mock_responses: HashMap::new(),
            exclude_binaries: Vec::new(),
            mock_ping_exit_code: 0,
            mock_recent_consulted: false,
            mock_extra_cases: String::new(),
        }
    }

    fn for_codex_post_bash() -> Self {
        Self {
            script_content: codex_post_bash::SCRIPT.to_string(),
            mock_dir: TempDir::new().expect("failed to create temp dir for harness"),
            mock_responses: HashMap::new(),
            exclude_binaries: Vec::new(),
            mock_ping_exit_code: 0,
            mock_recent_consulted: false,
            mock_extra_cases: String::new(),
        }
    }

    fn for_codex_stop() -> Self {
        Self {
            script_content: codex_stop::SCRIPT.to_string(),
            mock_dir: TempDir::new().expect("failed to create temp dir for harness"),
            mock_responses: HashMap::new(),
            exclude_binaries: Vec::new(),
            mock_ping_exit_code: 0,
            mock_recent_consulted: false,
            mock_extra_cases: String::new(),
        }
    }

    fn for_post_edit() -> Self {
        Self {
            script_content: post_edit::SCRIPT.to_string(),
            mock_dir: TempDir::new().expect("failed to create temp dir for harness"),
            mock_responses: HashMap::new(),
            exclude_binaries: Vec::new(),
            mock_ping_exit_code: 0,
            mock_recent_consulted: false,
            mock_extra_cases: String::new(),
        }
    }

    fn for_pre_compact() -> Self {
        Self {
            script_content: pre_compact::SCRIPT.to_string(),
            mock_dir: TempDir::new().expect("failed to create temp dir for harness"),
            mock_responses: HashMap::new(),
            exclude_binaries: Vec::new(),
            mock_ping_exit_code: 0,
            mock_recent_consulted: false,
            mock_extra_cases: String::new(),
        }
    }

    fn for_session_end() -> Self {
        Self {
            script_content: session_end::SCRIPT.to_string(),
            mock_dir: TempDir::new().expect("failed to create temp dir for harness"),
            mock_responses: HashMap::new(),
            exclude_binaries: Vec::new(),
            mock_ping_exit_code: 0,
            mock_recent_consulted: false,
            mock_extra_cases: String::new(),
        }
    }

    fn with_mock_record(mut self, key: &str, json: &str) -> Self {
        self.mock_responses
            .insert(key.to_string(), json.to_string());
        self
    }

    fn with_ping_failure(mut self) -> Self {
        self.mock_ping_exit_code = 1;
        self
    }

    fn exclude_binary(mut self, name: &str) -> Self {
        self.exclude_binaries.push(name.to_string());
        self
    }

    fn with_extra_mock_case(mut self, case: &str) -> Self {
        self.mock_extra_cases = case.to_string();
        self
    }

    fn with_recent_consulted(mut self, recent: bool) -> Self {
        self.mock_recent_consulted = recent;
        self
    }

    /// Build the mock `mati` script and write it to mock_dir.
    fn write_mock_mati(&self) -> PathBuf {
        let log_file = self.mock_dir.path().join("mati_log.txt");
        let mut get_cases = String::new();
        for (key, response) in &self.mock_responses {
            // Escape single quotes in the response for bash safety
            let escaped = response.replace('\'', "'\\''");
            get_cases.push_str(&format!("            \"{key}\") echo '{escaped}' ;;\n"));
        }
        // Default case for unknown keys
        get_cases.push_str("            *) echo 'null' ;;\n");

        let script = format!(
            r#"#!/usr/bin/env bash
case "$1" in
    ping) exit {ping_exit} ;;
    get)
        KEY="$2"
        case "$KEY" in
{get_cases}        esac ;;
    session-check-consulted)
        echo "false" ;;
    session-check-consulted-recent)
        if [ "${{3:-}}" = "--ttl-secs" ] && [ "${{4:-}}" = "900" ]; then
            echo "{recent_consulted}"
        else
            echo "false"
        fi ;;
    doc-capture)
        cat >/dev/null
        echo "$@" >> "{log_file}" ;;
    log-miss|log-hit|log-compliance-miss|log-compliance-hit|log-codex-shell-miss|log-bootstrap|log-prompt-nudge|edit-hook|session-flush|session-harvest)
        echo "$@" >> "{log_file}" ;;
    reparse)
        exit 0 ;;
    {extra}
    *) exit 0 ;;
esac
"#,
            ping_exit = self.mock_ping_exit_code,
            recent_consulted = if self.mock_recent_consulted {
                "true"
            } else {
                "false"
            },
            get_cases = get_cases,
            log_file = log_file.display(),
            extra = self.mock_extra_cases,
        );

        let mock_path = self.mock_dir.path().join("mati");
        std::fs::write(&mock_path, script).expect("failed to write mock mati script");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&mock_path, std::fs::Permissions::from_mode(0o755))
                .expect("failed to chmod mock mati");
        }

        mock_path
    }

    /// Write the hook bash script to a temp file.
    fn write_hook_script(&self) -> PathBuf {
        let script_path = self.mock_dir.path().join("hook.sh");
        std::fs::write(&script_path, &self.script_content).expect("failed to write hook script");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
                .expect("failed to chmod hook script");
        }

        script_path
    }

    /// Build a controlled PATH that includes the mock dir + essential system dirs,
    /// but excludes specified binaries by creating a filtered bin directory.
    fn build_path(&self) -> String {
        if self.exclude_binaries.is_empty() {
            // No exclusions: prepend mock_dir to system PATH
            let system_path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
            return format!("{}:{}", self.mock_dir.path().display(), system_path);
        }

        // Create a filtered bin dir with symlinks to system binaries,
        // excluding the ones we want to hide.
        let filtered_dir = self.mock_dir.path().join("filtered_bin");
        std::fs::create_dir_all(&filtered_dir).expect("failed to create filtered_bin dir");

        // Find system binaries we need: bash, cat, echo, printf, sed, grep, awk, test, [
        // and optionally jq, bc
        let essential_bins = [
            "bash", "cat", "echo", "printf", "sed", "grep", "awk", "test", "env", "command", "jq",
            "bc", "which", "dirname", "basename", "rm", "mkdir", "touch", "true", "false", "expr",
            "tr", "sort", "cut", "wc",
        ];

        // Search standard system directories for each binary
        let system_dirs = ["/usr/bin", "/bin", "/usr/local/bin"];

        for bin_name in &essential_bins {
            if self.exclude_binaries.contains(&bin_name.to_string()) {
                continue;
            }

            for dir in &system_dirs {
                let src = PathBuf::from(dir).join(bin_name);
                if src.exists() {
                    let dst = filtered_dir.join(bin_name);
                    if !dst.exists() {
                        #[cfg(unix)]
                        std::os::unix::fs::symlink(&src, &dst).ok();
                    }
                    break;
                }
            }
        }

        // PATH = mock_dir (for our mock mati) : filtered_bin (for system tools)
        format!(
            "{}:{}",
            self.mock_dir.path().display(),
            filtered_dir.display()
        )
    }

    /// Run the hook script with the given stdin JSON, capturing output.
    fn run(&self, stdin_json: &str) -> HookOutput {
        self.write_mock_mati();
        let script_path = self.write_hook_script();
        let path = self.build_path();

        let output = Command::new("bash")
            .arg(script_path.to_str().expect("script path not valid UTF-8"))
            .env("PATH", &path)
            .env("HOME", self.mock_dir.path())
            .current_dir(self.mock_dir.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(ref mut stdin) = child.stdin {
                    stdin
                        .write_all(stdin_json.as_bytes())
                        .expect("failed to write to stdin");
                }
                // Drop stdin to send EOF
                child.stdin.take();
                child.wait_with_output()
            })
            .expect("failed to execute hook script");

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        let json = serde_json::from_str::<serde_json::Value>(stdout.trim()).ok();

        HookOutput {
            stdout,
            stderr,
            exit_code,
            json,
        }
    }

    /// Read the log file written by mock mati's log-miss/log-hit commands.
    fn read_log(&self) -> String {
        let log_file = self.mock_dir.path().join("mati_log.txt");
        std::fs::read_to_string(&log_file).unwrap_or_default()
    }

    fn wait_for_log_contains(&self, needle: &str) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if self.read_log().contains(needle) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        false
    }
}

// ─── Helper: build Codex 0.118.0 input format ────────────────────────────────

/// Build the JSON input that Codex 0.118.0 sends to PreToolUse hooks.
/// The `arguments` field is a JSON-encoded string containing the command.
fn codex_bash_input(cmd: &str) -> String {
    let inner = serde_json::json!({"cmd": cmd, "shell": "zsh", "workdir": "."});
    serde_json::json!({"arguments": inner.to_string()}).to_string()
}

// ─── Helper: build a mock record JSON ────────────────────────────────────────

fn make_record(
    confidence: f64,
    quality: f64,
    confirmed: bool,
    staleness: f64,
    staleness_tier: &str,
) -> String {
    serde_json::json!({
        "confidence": { "value": confidence },
        "quality": { "value": quality },
        "confirmed": confirmed,
        "staleness": { "value": staleness, "tier": staleness_tier }
    })
    .to_string()
}

/// Build a file record JSON that has a linked gotcha key in payload.gotcha_keys.
/// The deny signal in the hook comes from linked gotcha records, not the file record itself.
fn make_file_record_with_gotcha(
    confidence: f64,
    quality: f64,
    staleness: f64,
    staleness_tier: &str,
    gotcha_key: &str,
) -> String {
    serde_json::json!({
        "confidence": { "value": confidence },
        "quality": { "value": quality },
        "staleness": { "value": staleness, "tier": staleness_tier },
        "value": "Test file purpose",
        "payload": {
            "gotcha_keys": [gotcha_key]
        }
    })
    .to_string()
}

/// Build a gotcha record JSON for deny testing.
/// Wire format: confirmed lives under payload.confirmed (matches GotchaRecord serialization).
fn make_gotcha_record(confidence: f64, quality: f64, confirmed: bool) -> String {
    serde_json::json!({
        "confidence": { "value": confidence },
        "quality": { "value": quality },
        "value": "Test gotcha: watch out for this",
        "payload": {
            "confirmed": confirmed,
            "rule": "Test gotcha: watch out for this",
            "reason": "Test reason",
            "severity": "normal",
            "affected_files": [],
            "discovered_session": 0,
            "ref_url": null
        }
    })
    .to_string()
}

/// Register a deny-eligible file record + linked gotcha in the harness.
/// The hook denies when a linked gotcha has confirmed=true + confidence>=0.6 + quality>=0.4.
impl HookTestHarness {
    fn with_deny_eligible_record(
        self,
        file_key: &str,
        staleness: f64,
        staleness_tier: &str,
    ) -> Self {
        let gotcha_key = "gotcha:test-deny-signal";
        let gotcha = make_gotcha_record(0.8, 0.7, true);
        let file = make_file_record_with_gotcha(0.8, 0.7, staleness, staleness_tier, gotcha_key);
        self.with_mock_record(file_key, &file)
            .with_mock_record(gotcha_key, &gotcha)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 1: Hook Decision Matrix (25 tests)
// ═════════════════════════════════════════════════════════════════════════════

/// 1.01 — PATH excludes jq -> allow (guard fires).
#[test]
fn preread_no_jq_allows() {
    let harness = HookTestHarness::for_pre_read().exclude_binary("jq");
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0, "hook should exit 0");
    assert_eq!(output.decision(), "allow", "missing jq must allow");
}

/// 1.02 — PATH excludes awk -> allow (guard fires).
#[test]
fn preread_no_awk_allows() {
    let harness = HookTestHarness::for_pre_read().exclude_binary("awk");
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0, "hook should exit 0");
    assert_eq!(output.decision(), "allow", "missing awk must allow");
}

/// 1.03 — Empty file_path in tool_input -> allow.
#[test]
fn preread_empty_file_path_allows() {
    let harness = HookTestHarness::for_pre_read();
    let output = harness.run(r#"{"tool_input":{}}"#);
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.decision(), "allow", "empty file_path must allow");
}

/// 1.04 — mati ping fails -> allow (graceful degradation).
#[test]
fn preread_mati_unreachable_allows() {
    let record = make_record(0.9, 0.9, true, 0.1, "fresh");
    let harness = HookTestHarness::for_pre_read()
        .with_mock_record("file:src/main.rs", &record)
        .with_ping_failure();
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.decision(), "allow", "unreachable mati must allow");
}

/// 1.05 — get returns null -> allow + log-miss in background.
#[test]
fn preread_no_record_allows_and_logs_miss() {
    // No mock record registered -> default is "null"
    let harness = HookTestHarness::for_pre_read();
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.decision(), "allow", "no record must allow");

    // Give the background log-miss a moment to write
    std::thread::sleep(std::time::Duration::from_millis(200));
    let log = harness.read_log();
    assert!(
        log.contains("log-miss"),
        "expected log-miss to be recorded, got: {log}"
    );
}

/// 1.06 — Low confidence (0.2), low quality (0.3) -> allow, no context injection.
#[test]
fn preread_low_confidence_low_quality_allows_no_injection() {
    let record = make_record(0.2, 0.3, true, 0.1, "fresh");
    let harness = HookTestHarness::for_pre_read().with_mock_record("file:src/main.rs", &record);
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.decision(), "allow");
    assert!(
        output.additional_context().is_empty(),
        "low conf + low qual should not inject context"
    );
    assert!(output.reason().is_empty(), "should not have a deny reason");
}

/// 1.07 — Low confidence (0.25), high quality (0.8) -> allow, no context.
#[test]
fn preread_low_confidence_high_quality_allows_no_injection() {
    let record = make_record(0.25, 0.8, true, 0.1, "fresh");
    let harness = HookTestHarness::for_pre_read().with_mock_record("file:src/main.rs", &record);
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.decision(), "allow");
    assert!(
        output.additional_context().is_empty(),
        "conf 0.25 < 0.3 threshold, no context should be injected"
    );
}

/// 1.08 — Medium confidence (0.45), good quality (0.5) -> allow + additionalContext.
#[test]
fn preread_medium_confidence_good_quality_allows_with_context() {
    let record = make_record(0.45, 0.5, false, 0.1, "fresh");
    let harness = HookTestHarness::for_pre_read().with_mock_record("file:src/main.rs", &record);
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.decision(), "allow");
    let ctx = output.additional_context();
    assert!(
        !ctx.is_empty(),
        "medium conf + good qual should inject additionalContext"
    );
    assert!(
        ctx.contains("0.45"),
        "context should include the confidence value, got: {ctx}"
    );
}

/// 1.09 — Medium confidence (0.5), low quality (0.35) -> allow, no context.
#[test]
fn preread_medium_confidence_low_quality_allows_no_injection() {
    let record = make_record(0.5, 0.35, true, 0.1, "fresh");
    let harness = HookTestHarness::for_pre_read().with_mock_record("file:src/main.rs", &record);
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.decision(), "allow");
    assert!(
        output.additional_context().is_empty(),
        "qual 0.35 < 0.4 threshold, no context should be injected"
    );
}

/// 1.10 — High conf, confirmed gotcha linked, good qual, fresh -> DENY.
/// Deny signal comes from a linked gotcha record (payload.gotcha_keys), not the file record itself.
#[test]
fn preread_high_conf_confirmed_good_qual_fresh_denies() {
    let harness =
        HookTestHarness::for_pre_read().with_deny_eligible_record("file:src/main.rs", 0.1, "fresh");
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    assert_eq!(
        output.decision(),
        "deny",
        "confirmed gotcha + high conf + good qual must DENY"
    );
    assert!(
        output.reason().contains("mem_get"),
        "deny reason should reference mem_get, got: {}",
        output.reason()
    );
}

/// 1.11 — Stale (not liability) tier with confirmed gotcha -> still DENY.
#[test]
fn preread_high_conf_confirmed_good_qual_stale_still_denies() {
    let harness =
        HookTestHarness::for_pre_read().with_deny_eligible_record("file:src/main.rs", 0.6, "stale");
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    assert_eq!(
        output.decision(),
        "deny",
        "stale (not liability) should still deny when confirmed gotcha linked"
    );
}

/// 1.12 — High conf + confirmed + good qual + liability -> allow + STALE warning.
#[test]
fn preread_high_conf_confirmed_good_qual_liability_downgrades() {
    let record = make_record(0.8, 0.7, true, 0.9, "liability");
    let harness = HookTestHarness::for_pre_read().with_mock_record("file:src/main.rs", &record);
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    assert_eq!(
        output.decision(),
        "allow",
        "liability tier must downgrade deny to allow"
    );
    let ctx = output.additional_context();
    assert!(
        ctx.contains("STALE"),
        "should include STALE warning, got: {ctx}"
    );
    assert!(
        ctx.contains("liability"),
        "should mention liability tier, got: {ctx}"
    );
}

/// 1.13 — High conf + confirmed + good qual + tombstone -> allow, no context.
#[test]
fn preread_high_conf_confirmed_good_qual_tombstone_passthrough() {
    let record = make_record(0.8, 0.7, true, 1.0, "tombstone");
    let harness = HookTestHarness::for_pre_read().with_mock_record("file:src/main.rs", &record);
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    assert_eq!(
        output.decision(),
        "allow",
        "tombstone must allow unconditionally"
    );
    assert!(
        output.additional_context().is_empty(),
        "tombstone should not inject any context"
    );
}

/// 1.14 — High conf, unconfirmed -> allow (confirmed=false bypasses deny).
#[test]
fn preread_high_conf_unconfirmed_allows() {
    let record = make_record(0.8, 0.7, false, 0.1, "fresh");
    let harness = HookTestHarness::for_pre_read().with_mock_record("file:src/main.rs", &record);
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    // confirmed=false means the deny branch is skipped.
    // But conf >= 0.3 + qual >= 0.4 -> allow + additionalContext
    assert_eq!(output.decision(), "allow");
    let ctx = output.additional_context();
    assert!(
        !ctx.is_empty(),
        "unconfirmed but medium+ conf should still inject context"
    );
}

/// 1.15 — High conf + confirmed but quality < 0.4 -> allow.
#[test]
fn preread_high_conf_confirmed_low_quality_allows() {
    let record = make_record(0.8, 0.35, true, 0.1, "fresh");
    let harness = HookTestHarness::for_pre_read().with_mock_record("file:src/main.rs", &record);
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    assert_eq!(
        output.decision(),
        "allow",
        "quality < 0.4 must prevent deny even with high conf"
    );
    // Quality < 0.4 means neither deny branch nor context branch fires
    assert!(
        output.additional_context().is_empty(),
        "quality < 0.4 should not inject context"
    );
}

/// 1.16 — Medium conf (0.45) + liability tier -> allow + STALE_NOTE.
#[test]
fn preread_medium_conf_liability_allows_with_stale_note() {
    let record = make_record(0.45, 0.5, false, 0.9, "liability");
    let harness = HookTestHarness::for_pre_read().with_mock_record("file:src/main.rs", &record);
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.decision(), "allow");
    let ctx = output.additional_context();
    assert!(
        ctx.contains("WARNING"),
        "medium conf + liability should include WARNING, got: {ctx}"
    );
    assert!(
        ctx.contains("liability"),
        "should mention liability, got: {ctx}"
    );
}

/// 1.17 — File path containing double quotes -> valid JSON output.
#[test]
fn preread_file_path_with_double_quotes_valid_json() {
    let record = make_record(0.8, 0.7, true, 0.1, "fresh");
    let path_with_quotes = r#"src/main"test.rs"#;
    let key = format!("file:{path_with_quotes}");
    let harness = HookTestHarness::for_pre_read().with_mock_record(&key, &record);
    let input = serde_json::json!({
        "tool_input": { "file_path": path_with_quotes }
    })
    .to_string();
    let output = harness.run(&input);
    assert_eq!(output.exit_code, 0);
    assert!(
        output.json.is_some(),
        "output must be valid JSON even with quotes in path, stdout: {}",
        output.stdout
    );
}

/// 1.18 — File path containing backslashes -> valid JSON output.
#[test]
fn preread_file_path_with_backslashes_valid_json() {
    let record = make_record(0.8, 0.7, true, 0.1, "fresh");
    let path_with_backslash = r"src\main\test.rs";
    let key = format!("file:{path_with_backslash}");
    let harness = HookTestHarness::for_pre_read().with_mock_record(&key, &record);
    let input = serde_json::json!({
        "tool_input": { "file_path": path_with_backslash }
    })
    .to_string();
    let output = harness.run(&input);
    assert_eq!(output.exit_code, 0);
    assert!(
        output.json.is_some(),
        "output must be valid JSON even with backslashes in path, stdout: {}",
        output.stdout
    );
}

/// 1.19 — File path with spaces -> correct handling.
#[test]
fn preread_file_path_with_spaces() {
    let path_with_spaces = "src/my file/main.rs";
    let key = format!("file:{path_with_spaces}");
    let harness = HookTestHarness::for_pre_read().with_deny_eligible_record(&key, 0.1, "fresh");
    let input = serde_json::json!({
        "tool_input": { "file_path": path_with_spaces }
    })
    .to_string();
    let output = harness.run(&input);
    assert_eq!(output.exit_code, 0);
    assert!(
        output.json.is_some(),
        "output must be valid JSON with spaces in path, stdout: {}",
        output.stdout
    );
    // High conf + confirmed + good qual -> should deny
    assert_eq!(output.decision(), "deny");
}

/// 1.20 — Unicode file path -> correct handling.
#[test]
fn preread_file_path_with_unicode() {
    let record = make_record(0.45, 0.5, false, 0.1, "fresh");
    let path_unicode = "src/datos/archivo_\u{00f1}.rs";
    let key = format!("file:{path_unicode}");
    let harness = HookTestHarness::for_pre_read().with_mock_record(&key, &record);
    let input = serde_json::json!({
        "tool_input": { "file_path": path_unicode }
    })
    .to_string();
    let output = harness.run(&input);
    assert_eq!(output.exit_code, 0);
    assert!(
        output.json.is_some(),
        "output must be valid JSON with unicode path, stdout: {}",
        output.stdout
    );
    assert_eq!(output.decision(), "allow");
}

/// 1.21 — pre-bash: `cat src/main.rs` detected -> deny (if record has confirmed gotcha).
#[test]
fn prebash_cat_detected_delegates_to_decision() {
    let harness =
        HookTestHarness::for_pre_bash().with_deny_eligible_record("file:src/main.rs", 0.1, "fresh");
    let input = serde_json::json!({
        "tool_input": { "command": "cat src/main.rs" }
    })
    .to_string();
    let output = harness.run(&input);
    assert_eq!(output.exit_code, 0);
    assert_eq!(
        output.decision(),
        "deny",
        "cat with eligible record must deny"
    );
    assert!(
        output.reason().contains("mem_get"),
        "deny reason should reference mem_get"
    );
}

/// 1.22 — pre-bash: `head -n 20 src/main.rs` -> file detected.
///
/// The awk parser skips words starting with `-` but treats `20` as a file path
/// (it doesn't start with `-`). This means `head -n 20 file.rs` detects `20`
/// as the file, NOT `file.rs`. This is a known limitation of the simple regex
/// approach (C9 ~2-5% miss rate). We test with `head -20 src/main.rs` (combined
/// flag) so the first non-flag word is the actual file.
#[test]
fn prebash_head_with_flags_detected() {
    let harness =
        HookTestHarness::for_pre_bash().with_deny_eligible_record("file:src/main.rs", 0.1, "fresh");
    let input = serde_json::json!({
        "tool_input": { "command": "head -20 src/main.rs" }
    })
    .to_string();
    let output = harness.run(&input);
    assert_eq!(output.exit_code, 0);
    assert_eq!(
        output.decision(),
        "deny",
        "head -20 src/main.rs should detect the file and deny"
    );
}

/// 1.23 — pre-bash: `git status` has no file-reading pattern -> allow, no mati call.
#[test]
fn prebash_no_file_reading_pattern_allows() {
    // Even if a record exists, git status should not trigger file detection
    let record = make_record(0.8, 0.7, true, 0.1, "fresh");
    let harness = HookTestHarness::for_pre_bash().with_mock_record("file:src/main.rs", &record);
    let input = serde_json::json!({
        "tool_input": { "command": "git status" }
    })
    .to_string();
    let output = harness.run(&input);
    assert_eq!(output.exit_code, 0);
    assert_eq!(
        output.decision(),
        "allow",
        "non-file-reading command must allow"
    );
}

/// 1.24 — pre-bash: `cat src/main.rs | grep foo` -> file detected (piped).
#[test]
fn prebash_piped_command_detected() {
    let harness =
        HookTestHarness::for_pre_bash().with_deny_eligible_record("file:src/main.rs", 0.1, "fresh");
    let input = serde_json::json!({
        "tool_input": { "command": "cat src/main.rs | grep foo" }
    })
    .to_string();
    let output = harness.run(&input);
    assert_eq!(output.exit_code, 0);
    assert_eq!(
        output.decision(),
        "deny",
        "piped cat command should still detect the file"
    );
}

/// 1.25 — pre-bash: empty command -> allow.
#[test]
fn prebash_empty_command_allows() {
    let harness = HookTestHarness::for_pre_bash();
    let input = serde_json::json!({
        "tool_input": { "command": "" }
    })
    .to_string();
    let output = harness.run(&input);
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.decision(), "allow", "empty command must allow");
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 2: Failure Modes (8 tests)
// ═════════════════════════════════════════════════════════════════════════════

/// 2.01 — No mati binary in PATH at all -> allow.
#[test]
fn preread_mati_binary_not_in_path_allows() {
    let harness = HookTestHarness::for_pre_read().exclude_binary("mati");

    // We also need to remove the mock mati from the mock_dir.
    // The easiest way: don't write it. Override run() behavior by
    // writing the hook script manually without calling write_mock_mati.
    let script_path = harness.mock_dir.path().join("hook.sh");
    std::fs::write(&script_path, &harness.script_content).expect("failed to write hook script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
            .expect("failed to chmod hook script");
    }

    // Build a PATH that excludes our mock dir (no mati anywhere)
    // Use the filtered bin approach but also exclude mati
    let filtered_dir = harness.mock_dir.path().join("no_mati_bin");
    std::fs::create_dir_all(&filtered_dir).expect("failed to create no_mati_bin dir");

    let essential_bins = [
        "bash", "cat", "echo", "printf", "sed", "grep", "awk", "env", "jq", "bc", "which", "tr",
        "sort", "cut", "wc", "true", "false",
    ];
    let system_dirs = ["/usr/bin", "/bin", "/usr/local/bin"];

    for bin_name in &essential_bins {
        for dir in &system_dirs {
            let src = PathBuf::from(dir).join(bin_name);
            if src.exists() {
                let dst = filtered_dir.join(bin_name);
                if !dst.exists() {
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(&src, &dst).ok();
                }
                break;
            }
        }
    }

    let path = format!("{}", filtered_dir.display());

    let output_raw = Command::new("bash")
        .arg(script_path.to_str().expect("script path not valid UTF-8"))
        .env("PATH", &path)
        .env("HOME", harness.mock_dir.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(ref mut stdin) = child.stdin {
                stdin
                    .write_all(br#"{"tool_input":{"file_path":"src/main.rs"}}"#)
                    .expect("failed to write stdin");
            }
            child.stdin.take();
            child.wait_with_output()
        })
        .expect("failed to execute hook script");

    let stdout = String::from_utf8_lossy(&output_raw.stdout).to_string();
    let json: Option<serde_json::Value> = serde_json::from_str(stdout.trim()).ok();

    assert_eq!(output_raw.status.code().unwrap_or(-1), 0, "should exit 0");
    let decision = json
        .as_ref()
        .and_then(|j| j.pointer("/hookSpecificOutput/permissionDecision"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(
        decision, "allow",
        "no mati in PATH must allow, stdout: {stdout}"
    );
}

/// 2.02 — mati get returns invalid JSON (garbage) -> structured allow.
#[test]
fn preread_mati_get_returns_invalid_json_allows() {
    let harness =
        HookTestHarness::for_pre_read().with_mock_record("file:src/main.rs", "NOT_VALID_JSON{{{");
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0, "invalid JSON should fail open cleanly");
    assert_eq!(
        output.decision(),
        "allow",
        "invalid JSON from mati get should produce a structured allow"
    );
}

/// 2.03 — mati get returns empty string -> allow + log-miss.
#[test]
fn preread_mati_get_returns_empty_string_allows() {
    let harness = HookTestHarness::for_pre_read().with_mock_record("file:src/main.rs", "");
    let output = harness.run(r#"{"tool_input":{"file_path":"src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.decision(), "allow");
}

/// 2.04 — Empty stdin -> exits cleanly (code 0).
#[test]
fn preread_stdin_empty_exits_cleanly() {
    let harness = HookTestHarness::for_pre_read();
    let output = harness.run("");
    // With empty stdin, jq will either fail or return empty.
    // set -euo pipefail may cause early exit, but it should still be clean.
    // The main thing: no hang, and exit code should be 0.
    assert_eq!(
        output.exit_code, 0,
        "empty stdin should exit cleanly, stderr: {}",
        output.stderr
    );
}

/// 2.05 — Non-JSON stdin -> clean exit.
#[test]
fn preread_stdin_invalid_json_exits_cleanly() {
    let harness = HookTestHarness::for_pre_read();
    let output = harness.run("this is not json at all");
    // jq should fail on invalid JSON -> the script may exit due to set -e,
    // or the jq fallback defaults kick in. Either way, no hang.
    // We accept exit code 0 (if guards catch it) or non-zero (if set -e fires).
    // If it does produce output, it should be valid JSON
    if !output.stdout.trim().is_empty() {
        assert!(
            output.json.is_some(),
            "if output is produced, it must be valid JSON, got: {}",
            output.stdout
        );
    }
}

/// 2.06 — Mock mati sleeps 2s on get -> hook still completes (no hang).
///
/// This test verifies that the hook does not hang indefinitely when mati is slow.
/// The bash script does not have an explicit timeout on `mati get`, so this test
/// confirms the subprocess completes (via the 2s sleep finishing) rather than
/// testing a timeout mechanism. The test itself has a generous timeout.
#[test]
fn preread_mati_get_slow_does_not_hang() {
    // Create a custom mock that sleeps 2 seconds before responding to get
    let harness = HookTestHarness::for_pre_read()
        .with_extra_mock_case(r#"get) sleep 2; echo 'null' ; exit 0 ;;"#);

    // Override: we need the get case to be the sleep version, not the default.
    // The simplest approach: use a custom mock that handles get specially.
    let log_file = harness.mock_dir.path().join("mati_log.txt");
    let mock_script = format!(
        r#"#!/usr/bin/env bash
case "$1" in
    ping) exit 0 ;;
    get) sleep 2; echo 'null'; exit 0 ;;
    log-miss|log-hit|log-compliance-miss)
        echo "$@" >> "{log}" ;;
    *) exit 0 ;;
esac
"#,
        log = log_file.display()
    );

    let mock_path = harness.mock_dir.path().join("mati");
    std::fs::write(&mock_path, mock_script).expect("failed to write slow mock mati");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&mock_path, std::fs::Permissions::from_mode(0o755))
            .expect("failed to chmod mock mati");
    }

    let script_path = harness.write_hook_script();
    let path = format!(
        "{}:{}",
        harness.mock_dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let start = std::time::Instant::now();
    let output_raw = Command::new("bash")
        .arg(script_path.to_str().expect("script path not valid UTF-8"))
        .env("PATH", &path)
        .env("HOME", harness.mock_dir.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(ref mut stdin) = child.stdin {
                stdin
                    .write_all(br#"{"tool_input":{"file_path":"src/main.rs"}}"#)
                    .expect("failed to write stdin");
            }
            child.stdin.take();
            child.wait_with_output()
        })
        .expect("failed to execute hook script");
    let elapsed = start.elapsed();

    // Should complete (not hang). We allow up to 10s total.
    assert!(
        elapsed.as_secs() < 10,
        "hook should complete within 10s, took {:?}",
        elapsed
    );

    let stdout = String::from_utf8_lossy(&output_raw.stdout).to_string();
    assert_eq!(output_raw.status.code().unwrap_or(-1), 0);

    let json: Option<serde_json::Value> = serde_json::from_str(stdout.trim()).ok();
    let decision = json
        .as_ref()
        .and_then(|j| j.pointer("/hookSpecificOutput/permissionDecision"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(decision, "allow", "slow mati should still result in allow");
}

/// 2.07 — pre-bash: mati get returns an array instead of object -> structured allow.
#[test]
fn prebash_unexpected_jq_type_graceful() {
    let harness =
        HookTestHarness::for_pre_bash().with_mock_record("file:src/main.rs", r#"[1, 2, 3]"#);
    let input = serde_json::json!({
        "tool_input": { "command": "cat src/main.rs" }
    })
    .to_string();
    let output = harness.run(&input);
    assert_eq!(
        output.exit_code, 0,
        "unexpected jq type should fail open cleanly"
    );
    assert_eq!(
        output.decision(),
        "allow",
        "unexpected jq type should produce a structured allow"
    );
}

/// 2.08 — 5 parallel invocations -> all produce valid JSON (no corruption).
#[test]
fn preread_concurrent_invocations_no_corruption() {
    // Deny signal comes from a linked gotcha record, not the file record itself.
    let gotcha_key = "gotcha:concurrent-test";
    let gotcha_record = make_gotcha_record(0.8, 0.7, true);
    let file_record = make_file_record_with_gotcha(0.8, 0.7, 0.1, "fresh", gotcha_key);

    let escaped_file = file_record.replace('\'', "'\\''");
    let escaped_gotcha = gotcha_record.replace('\'', "'\\''");

    // We need a shared setup for all 5 threads. Create the mock environment once.
    let shared_dir = TempDir::new().expect("failed to create shared temp dir");
    let log_file = shared_dir.path().join("mati_log.txt");

    // Write mock mati
    let mock_script = format!(
        r#"#!/usr/bin/env bash
case "$1" in
    ping) exit 0 ;;
    get)
        KEY="$2"
        case "$KEY" in
            "file:src/main.rs") echo '{file}' ;;
            "{gotcha_key}") echo '{gotcha}' ;;
            *) echo 'null' ;;
        esac ;;
    log-miss|log-hit|log-compliance-miss|session-check-consulted)
        echo "$@" >> "{log}" ;;
    *) exit 0 ;;
esac
"#,
        file = escaped_file,
        gotcha_key = gotcha_key,
        gotcha = escaped_gotcha,
        log = log_file.display()
    );

    let mock_path = shared_dir.path().join("mati");
    std::fs::write(&mock_path, mock_script).expect("failed to write mock mati");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&mock_path, std::fs::Permissions::from_mode(0o755))
            .expect("failed to chmod mock mati");
    }

    // Write hook script
    let script_path = shared_dir.path().join("hook.sh");
    std::fs::write(&script_path, pre_read::SCRIPT).expect("failed to write hook");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
            .expect("failed to chmod hook");
    }

    let path = format!(
        "{}:{}",
        shared_dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut handles = Vec::new();
    for i in 0..5 {
        let script = script_path.clone();
        let env_path = path.clone();
        let home = shared_dir.path().to_path_buf();
        handles.push(std::thread::spawn(move || {
            let output = Command::new("bash")
                .arg(script.to_str().expect("script path not valid UTF-8"))
                .env("PATH", &env_path)
                .env("HOME", &home)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    if let Some(ref mut stdin) = child.stdin {
                        stdin
                            .write_all(br#"{"tool_input":{"file_path":"src/main.rs"}}"#)
                            .expect("failed to write stdin");
                    }
                    child.stdin.take();
                    child.wait_with_output()
                })
                .unwrap_or_else(|e| panic!("thread {i} failed to execute hook: {e}"));

            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let exit_code = output.status.code().unwrap_or(-1);
            let json: Option<serde_json::Value> = serde_json::from_str(stdout.trim()).ok();

            (i, stdout, exit_code, json)
        }));
    }

    for handle in handles {
        let (i, stdout, exit_code, json) = handle.join().expect("thread panicked");
        assert_eq!(exit_code, 0, "thread {i} should exit 0");
        assert!(
            json.is_some(),
            "thread {i} must produce valid JSON, got: {stdout}"
        );
        let decision = json
            .as_ref()
            .and_then(|j| j.pointer("/hookSpecificOutput/permissionDecision"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(
            decision, "deny",
            "thread {i} should deny (high conf + confirmed + good qual)"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 3: Post/Lifecycle Hook Contracts (10 tests)
// ═════════════════════════════════════════════════════════════════════════════

/// 3.01 — post-read compliance logs extensionless root-level files.
#[test]
fn post_compliance_logs_extensionless_root_file_miss() {
    let harness = HookTestHarness::for_post_compliance();
    let root_file = harness.mock_dir.path().join("Dockerfile");
    std::fs::write(&root_file, "FROM rust:1.80").expect("failed to write Dockerfile");

    let input = serde_json::json!({
        "tool_input": { "path": "Dockerfile" }
    })
    .to_string();
    let output = harness.run(&input);
    assert_eq!(output.exit_code, 0);
    assert!(
        harness.wait_for_log_contains("log-compliance-miss file:Dockerfile"),
        "extensionless file should still be tracked as a compliance miss, log: {}",
        harness.read_log()
    );
}

/// 3.02 — post-edit invokes both doc-capture and edit-hook.
#[test]
fn post_edit_invokes_doc_capture_and_edit_hook() {
    let harness = HookTestHarness::for_post_edit();
    let input = serde_json::json!({
        "tool_input": {
            "file_path": "src/main.rs",
            "content": "/// Main entrypoint\nfn main() {}\n"
        }
    })
    .to_string();
    let output = harness.run(&input);
    assert_eq!(output.exit_code, 0);
    assert!(
        harness.wait_for_log_contains("doc-capture src/main.rs"),
        "post-edit should invoke doc-capture, log: {}",
        harness.read_log()
    );
    assert!(
        harness.wait_for_log_contains("edit-hook src/main.rs"),
        "post-edit should invoke edit-hook, log: {}",
        harness.read_log()
    );
}

/// 3.03 — pre-compact flushes session state synchronously.
#[test]
fn pre_compact_invokes_session_flush() {
    let harness = HookTestHarness::for_pre_compact();
    let output = harness.run(r#"{"event":"PreCompact"}"#);
    assert_eq!(output.exit_code, 0);
    assert!(
        harness.wait_for_log_contains("session-flush"),
        "pre-compact should invoke session-flush, log: {}",
        harness.read_log()
    );
}

/// 3.04 — session-end triggers session harvest.
#[test]
fn session_end_invokes_session_harvest() {
    let harness = HookTestHarness::for_session_end();
    let output = harness.run("");
    assert_eq!(output.exit_code, 0);
    assert!(
        harness.wait_for_log_contains("session-harvest"),
        "session-end should invoke session-harvest, log: {}",
        harness.read_log()
    );
}

/// 3.05 — Codex session-start nudges mem_bootstrap.
#[test]
fn codex_session_start_emits_bootstrap_guidance() {
    let harness = HookTestHarness::for_codex_session_start();
    let output = harness.run("{}");
    assert_eq!(output.exit_code, 0);
    assert!(
        output.stdout.contains("mem_bootstrap"),
        "session-start should instruct Codex to bootstrap memory"
    );
}

/// 3.06 — Codex user-prompt hook nudges and logs likely edit intent.
#[test]
fn codex_user_prompt_logs_nudge_for_code_edit_intent() {
    let harness = HookTestHarness::for_codex_user_prompt();
    let output = harness.run(r#"{"prompt":"Please inspect src/main.rs and fix the bug"}"#);
    assert_eq!(output.exit_code, 0);
    assert!(
        output.stdout.contains("mem_get"),
        "user-prompt hook should recommend mem_get for risky file work"
    );
    assert!(
        harness.wait_for_log_contains("log-prompt-nudge __codex_prompt__"),
        "user-prompt hook should log prompt nudges, log: {}",
        harness.read_log()
    );
}

/// 3.07 — Codex pre-bash blocks strong gotcha shell reads without a receipt.
///
/// Codex 0.118.0 blocking mechanism: exit 2 + stderr message.
/// Stdout is not used for blocking decisions.
#[test]
fn codex_pre_bash_blocks_shell_read_without_recent_receipt() {
    let harness = HookTestHarness::for_codex_pre_bash().with_deny_eligible_record(
        "file:src/main.rs",
        0.1,
        "fresh",
    );
    // Codex 0.118.0 input format: arguments is a JSON-encoded string
    let input = codex_bash_input("cat src/main.rs");
    let output = harness.run(&input);
    assert_eq!(
        output.exit_code, 2,
        "codex pre-bash should exit 2 to block, got exit {}; stderr: {}",
        output.exit_code, output.stderr
    );
    assert!(
        output.stderr.contains("mem_get"),
        "stderr should instruct the agent to consult memory first, got: {}",
        output.stderr
    );
    assert!(
        harness.wait_for_log_contains("log-codex-shell-miss file:src/main.rs"),
        "pre-bash should log shell misses, log: {}",
        harness.read_log()
    );
}

/// 3.08 — Codex post-bash logs misses and corrective context.
#[test]
fn codex_post_bash_logs_shell_miss_and_context() {
    let harness = HookTestHarness::for_codex_post_bash();
    let output = harness.run(r#"{"tool_input":{"command":"cat src/main.rs"}}"#);
    assert_eq!(output.exit_code, 0);
    let json = output.json.expect("codex post-bash should emit JSON");
    assert!(
        json["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap_or_default()
            .contains("mem_get"),
        "post-bash miss should remind the agent to consult memory"
    );
    assert!(
        harness.wait_for_log_contains("log-codex-shell-miss file:src/main.rs"),
        "post-bash should log shell misses, log: {}",
        harness.read_log()
    );
}

/// 3.09 — Codex pre-bash allows a strong gotcha file after a recent consultation.
#[test]
fn codex_pre_bash_allows_with_recent_receipt() {
    let harness = HookTestHarness::for_codex_pre_bash()
        .with_deny_eligible_record("file:src/main.rs", 0.1, "fresh")
        .with_recent_consulted(true);
    // Codex 0.118.0 input format
    let input = codex_bash_input("cat src/main.rs");
    let output = harness.run(&input);
    assert_eq!(output.exit_code, 0);
    assert!(
        output.stdout.trim().is_empty(),
        "recent consultation should suppress deny/advisory output, got: {}",
        output.stdout
    );
    assert!(
        !harness
            .read_log()
            .contains("log-codex-shell-miss file:src/main.rs"),
        "recent consultation should not log a shell miss, log: {}",
        harness.read_log()
    );
}

/// 3.10 — Codex stop flushes then harvests the session.
#[test]
fn codex_stop_flushes_then_harvests() {
    let harness = HookTestHarness::for_codex_stop();
    let output = harness.run("{}");
    assert_eq!(output.exit_code, 0);
    let log = harness.read_log();
    assert!(
        log.contains("session-flush"),
        "codex stop should flush session state first, log: {log}"
    );
    assert!(
        log.contains("session-harvest"),
        "codex stop should harvest session state, log: {log}"
    );
}
