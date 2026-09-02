/// M-15 Bash Hook Compliance Test Suite — wrapper execution + lifecycle contracts.
///
/// This module tests two things:
///
/// 1. **Wrapper execution** (Category 1) — the thin shell wrappers (`pre_read`,
///    `pre_bash`, `codex_pre_bash`, `codex_post_bash`, `post_compliance`)
///    correctly delegate to `mati hook-decide <variant>` with stdin passthrough
///    and exit-code propagation.
///
/// 2. **Lifecycle contracts** (Category 3) — post-edit,
///    pre-compact, session-end, codex-session-start, codex-user-prompt, and
///    codex-stop hooks invoke the correct daemon commands in the right order.
///
/// Enforcement logic (the allow/deny decision matrix) is tested by:
/// - `hooks::decide::tests` — pure decision functions (51 unit tests)
/// - `cli::hook_decide::tests` — adapter pipeline: eval response → decision →
///   platform events → formatted output (22 tests, including 10 e2e fixtures)
///
/// The test harness writes bash scripts to temp files, creates a mock `mati`
/// binary, and exercises hooks with controlled stdin JSON + mock responses.
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
use super::file_changed;
use super::post_compliance;
use super::post_edit;
use super::pre_bash;
use super::pre_compact;
use super::pre_edit;
use super::pre_read;
use super::session_end;
use super::session_start;

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

// Used by Category 3 lifecycle tests.
#[allow(dead_code)]
struct HookOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
    json: Option<serde_json::Value>,
}

#[allow(dead_code)]
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

// Some constructors (for_pre_read, for_pre_bash, etc.) are used by specific
// Category 1 and Category 3 tests only.
#[allow(dead_code)]
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

    fn for_session_start() -> Self {
        Self {
            script_content: session_start::SCRIPT.to_string(),
            mock_dir: TempDir::new().expect("failed to create temp dir for harness"),
            mock_responses: HashMap::new(),
            exclude_binaries: Vec::new(),
            mock_ping_exit_code: 0,
            mock_recent_consulted: false,
            mock_extra_cases: String::new(),
        }
    }

    fn for_file_changed() -> Self {
        Self {
            script_content: file_changed::SCRIPT.to_string(),
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
    log-miss|log-hit|log-compliance-miss|log-compliance-hit|log-codex-shell-miss|log-bootstrap|log-prompt-nudge|edit-hook|session-flush|session-harvest|post-read-compliance)
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
            "tr", "sort", "cut", "wc", "date",
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
            .env("PATH", path)
            .env("HOME", self.mock_dir.path())
            // Distinct from HOME on purpose: a hook that writes telemetry to
            // $HOME/.mati writes where `mati stats` does not read.
            .env("MATI_HOME", self.mati_home())
            .current_dir(self.mock_dir.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(ref mut stdin) = child.stdin {
                    // BrokenPipe is expected when the script exits before
                    // reading stdin (e.g. the no-op user-prompt hook).
                    let _ = stdin.write_all(stdin_json.as_bytes());
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

    /// The mati root the hook is given, i.e. what `mati_home_opt()` resolves.
    fn mati_home(&self) -> PathBuf {
        self.mock_dir.path().join("mati_home")
    }

    /// Contents of `fail_open.log` under the mati root, `""` if never written.
    fn fail_open_log(&self) -> String {
        std::fs::read_to_string(self.mati_home().join("fail_open.log")).unwrap_or_default()
    }

    /// Read the log file written by mock mati's log-miss/log-hit commands.
    fn read_log(&self) -> String {
        let log_file = self.mock_dir.path().join("mati_log.txt");
        std::fs::read_to_string(&log_file).unwrap_or_default()
    }

    fn wait_for_log_contains(&self, needle: &str) -> bool {
        self.wait_for_log_contains_timeout(needle, std::time::Duration::from_secs(2))
    }

    fn wait_for_log_contains_timeout(&self, needle: &str, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if self.read_log().contains(needle) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        false
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 1: Wrapper Execution Tests
//
// Each thin shell wrapper must:
//   (a) pass stdin through to `mati hook-decide <variant>`,
//   (b) propagate the exit code,
//   (c) relay stdout/stderr.
//
// Enforcement logic is tested by hooks::decide::tests (51 unit tests) and
// cli::hook_decide::tests (22 tests including 10 e2e adapter fixtures).
// ═════════════════════════════════════════════════════════════════════════════

/// Build a mock `mati` that handles `hook-decide <variant>`:
///   - Logs the variant and stdin to a file for assertion.
///   - Outputs a canned JSON response on stdout.
///   - Exits with a configurable code.
struct WrapperHarness {
    mock_dir: TempDir,
}

struct WrapperOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

impl WrapperHarness {
    fn new() -> Self {
        Self {
            mock_dir: TempDir::new().expect("failed to create temp dir"),
        }
    }

    /// Write a mock `mati` binary that records invocation details and replays
    /// a canned response. `exit_code` controls what the mock returns.
    fn write_mock(&self, canned_stdout: &str, canned_stderr: &str, exit_code: i32) {
        let log_path = self.mock_dir.path().join("invocation.log");
        let escaped_stdout = canned_stdout.replace('\'', "'\\''");
        let escaped_stderr = canned_stderr.replace('\'', "'\\''");
        let script = format!(
            r#"#!/usr/bin/env bash
# Log the full argument vector.
echo "ARGS: $*" >> "{log}"
# Log stdin so tests can verify passthrough.
STDIN="$(cat)"
echo "STDIN: $STDIN" >> "{log}"
# Replay canned response.
echo -n '{stdout}' >&1
echo -n '{stderr}' >&2
exit {code}
"#,
            log = log_path.display(),
            stdout = escaped_stdout,
            stderr = escaped_stderr,
            code = exit_code,
        );
        let mock_path = self.mock_dir.path().join("mati");
        std::fs::write(&mock_path, script).expect("write mock");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&mock_path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod mock");
        }
    }

    /// Execute a wrapper script against the mock.
    fn run(&self, script_content: &str, stdin_json: &str) -> WrapperOutput {
        let script_path = self.mock_dir.path().join("hook.sh");
        std::fs::write(&script_path, script_content).expect("write hook script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod hook script");
        }

        // Do NOT include mock_dir in PATH — the wrapper's own HOOKS_DIR
        // setup (`export PATH="$HOOKS_DIR:$PATH"`) must be the only way
        // the sibling `mati` binary is found.
        let path = "/usr/bin:/bin:/usr/local/bin";

        let output = Command::new("bash")
            .arg(script_path.to_str().unwrap())
            .env("PATH", path)
            .env("HOME", self.mock_dir.path())
            .current_dir(self.mock_dir.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(stdin_json.as_bytes()).expect("write stdin");
                }
                child.stdin.take();
                child.wait_with_output()
            })
            .expect("execute hook");

        WrapperOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        }
    }

    /// Read the invocation log written by the mock.
    fn invocation_log(&self) -> String {
        let log_path = self.mock_dir.path().join("invocation.log");
        std::fs::read_to_string(&log_path).unwrap_or_default()
    }
}

// ── 1.01–1.04: Variant handoff — each wrapper passes the correct variant ────

#[test]
fn preread_wrapper_executes_hook_decide_with_correct_variant() {
    let h = WrapperHarness::new();
    let response = r#"{"hookSpecificOutput":{"permissionDecision":"allow"}}"#;
    h.write_mock(response, "", 0);
    let out = h.run(
        pre_read::SCRIPT,
        r#"{"tool_input":{"file_path":"src/main.rs"}}"#,
    );

    assert_eq!(out.exit_code, 0, "wrapper must propagate exit 0");
    assert_eq!(out.stdout.trim(), response, "wrapper must relay stdout");

    let log = h.invocation_log();
    assert!(
        log.contains("ARGS: hook-decide claude-pre-read"),
        "wrapper must pass variant claude-pre-read, log: {log}"
    );
}

#[test]
fn preedit_wrapper_executes_hook_decide_with_correct_variant() {
    let h = WrapperHarness::new();
    // The edit gate denies via a Claude PreToolUse deny JSON on stdout, exit 0.
    let response = r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[mati] before editing this file."}}"#;
    h.write_mock(response, "", 0);
    let out = h.run(
        pre_edit::SCRIPT,
        r#"{"tool_input":{"file_path":"src/main.rs"}}"#,
    );

    assert_eq!(out.exit_code, 0, "wrapper must propagate exit 0");
    assert_eq!(
        out.stdout.trim(),
        response,
        "wrapper must relay the deny JSON"
    );

    let log = h.invocation_log();
    assert!(
        log.contains("ARGS: hook-decide claude-pre-edit"),
        "wrapper must pass variant claude-pre-edit, log: {log}"
    );
    assert!(
        log.contains(r#"STDIN: {"tool_input":{"file_path":"src/main.rs"}}"#),
        "wrapper must pass stdin through, log: {log}"
    );
}

#[test]
fn prebash_wrapper_executes_hook_decide_with_correct_variant() {
    let h = WrapperHarness::new();
    h.write_mock(
        r#"{"hookSpecificOutput":{"permissionDecision":"allow"}}"#,
        "",
        0,
    );
    h.run(
        pre_bash::SCRIPT,
        r#"{"tool_input":{"command":"cat src/main.rs"}}"#,
    );

    let log = h.invocation_log();
    assert!(
        log.contains("ARGS: hook-decide claude-pre-bash"),
        "wrapper must pass variant claude-pre-bash, log: {log}"
    );
}

#[test]
fn codex_prebash_wrapper_executes_hook_decide_with_correct_variant() {
    let h = WrapperHarness::new();
    h.write_mock("", "", 0);
    h.run(
        codex_pre_bash::SCRIPT,
        r#"{"tool_input":{"command":"cat src/main.rs"}}"#,
    );

    let log = h.invocation_log();
    assert!(
        log.contains("ARGS: hook-decide codex-pre-bash"),
        "wrapper must pass variant codex-pre-bash, log: {log}"
    );
}

#[test]
fn post_compliance_wrapper_executes_hook_decide_with_correct_variant() {
    let h = WrapperHarness::new();
    h.write_mock("", "", 0);
    let out = h.run(
        post_compliance::SCRIPT,
        r#"{"tool_input":{"file_path":"src/main.rs"}}"#,
    );

    assert_eq!(out.exit_code, 0, "a PostToolUse hook must always exit 0");
    assert!(
        out.stdout.is_empty(),
        "PostToolUse carries no decision — stdout must stay empty, got: {}",
        out.stdout
    );

    let log = h.invocation_log();
    assert!(
        log.contains("ARGS: hook-decide claude-post-read-compliance"),
        "wrapper must pass variant claude-post-read-compliance, log: {log}"
    );
    assert!(
        log.contains(r#"STDIN: {"tool_input":{"file_path":"src/main.rs"}}"#),
        "wrapper must pass stdin through, log: {log}"
    );
}

#[test]
fn codex_postbash_wrapper_executes_hook_decide_with_correct_variant() {
    let h = WrapperHarness::new();
    h.write_mock("", "", 0);
    h.run(
        codex_post_bash::SCRIPT,
        r#"{"tool_input":{"command":"cat src/main.rs"}}"#,
    );

    let log = h.invocation_log();
    assert!(
        log.contains("ARGS: hook-decide codex-post-bash"),
        "wrapper must pass variant codex-post-bash, log: {log}"
    );
}

// ── 1.05–1.06: Stdin passthrough — tool_input JSON reaches mock mati ────────

#[test]
fn preread_wrapper_passes_stdin_through() {
    let h = WrapperHarness::new();
    h.write_mock(
        r#"{"hookSpecificOutput":{"permissionDecision":"allow"}}"#,
        "",
        0,
    );
    let input = r#"{"tool_input":{"file_path":"src/store/db.rs"}}"#;
    h.run(pre_read::SCRIPT, input);

    let log = h.invocation_log();
    assert!(
        log.contains(input),
        "stdin must reach mock mati intact, log: {log}"
    );
}

#[test]
fn codex_prebash_wrapper_passes_stdin_through() {
    let h = WrapperHarness::new();
    h.write_mock("", "", 0);
    let input = r#"{"tool_input":{"command":"head -20 src/main.rs"}}"#;
    h.run(codex_pre_bash::SCRIPT, input);

    let log = h.invocation_log();
    assert!(
        log.contains(input),
        "stdin must reach mock mati intact, log: {log}"
    );
}

// ── 1.07–1.08: Exit code propagation — non-zero codes survive exec ──────────

#[test]
fn preread_wrapper_propagates_nonzero_exit() {
    let h = WrapperHarness::new();
    h.write_mock("", "blocked", 1);
    let out = h.run(
        pre_read::SCRIPT,
        r#"{"tool_input":{"file_path":"src/main.rs"}}"#,
    );

    assert_eq!(
        out.exit_code, 1,
        "wrapper must propagate exit 1 from hook-decide"
    );
}

#[test]
fn codex_prebash_wrapper_propagates_exit2_deny() {
    let h = WrapperHarness::new();
    h.write_mock("", "Run mem_get first", 2);
    let out = h.run(
        codex_pre_bash::SCRIPT,
        r#"{"tool_input":{"command":"cat src/main.rs"}}"#,
    );

    assert_eq!(out.exit_code, 2, "Codex deny exit 2 must survive exec");
    assert!(
        out.stderr.contains("mem_get"),
        "stderr must relay deny message, got: {}",
        out.stderr
    );
}

// ── 1.09: Stderr relay — wrapper does not swallow stderr ─────────────────────

#[test]
fn preread_wrapper_relays_stderr() {
    let h = WrapperHarness::new();
    h.write_mock(
        r#"{"hookSpecificOutput":{"permissionDecision":"deny"}}"#,
        "[mati] WARNING: test stderr relay",
        0,
    );
    let out = h.run(
        pre_read::SCRIPT,
        r#"{"tool_input":{"file_path":"src/main.rs"}}"#,
    );

    assert!(
        out.stderr.contains("[mati] WARNING: test stderr relay"),
        "wrapper must relay stderr, got: {}",
        out.stderr
    );
}

// ── 1.10: No mati in PATH — set -e should cause a clean failure ─────────────

#[test]
fn preread_wrapper_no_mati_in_path_fails_cleanly() {
    // Don't write any mock — mati is not in PATH.
    let h = WrapperHarness::new();
    let script_path = h.mock_dir.path().join("hook.sh");
    std::fs::write(&script_path, pre_read::SCRIPT).expect("write hook");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
    }

    // PATH with only system dirs — no mock mati.
    let output = Command::new("bash")
        .arg(script_path.to_str().unwrap())
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", h.mock_dir.path())
        .current_dir(h.mock_dir.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(b"{}").expect("write stdin");
            }
            child.stdin.take();
            child.wait_with_output()
        })
        .expect("execute hook");

    // `command -v mati` guard in the wrapper exits 0 (graceful fail-open)
    // when mati is not in PATH — the agent must not be blocked by a missing binary.
    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "missing mati must exit 0 (graceful fail-open)"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 3: Post/Lifecycle Hook Contracts (10 tests)
// ═════════════════════════════════════════════════════════════════════════════

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
    // post-edit fires background processes (`&`) — allow extra time under parallel load.
    let bg_timeout = std::time::Duration::from_secs(5);
    assert!(
        harness.wait_for_log_contains_timeout("doc-capture src/main.rs", bg_timeout),
        "post-edit should invoke doc-capture, log: {}",
        harness.read_log()
    );
    assert!(
        harness.wait_for_log_contains_timeout("edit-hook src/main.rs", bg_timeout),
        "post-edit should invoke edit-hook, log: {}",
        harness.read_log()
    );
}

/// Assert one `fail_open.log` line carries every field `cli::stats`'s scanner
/// and a human reader need: an ISO timestamp it can parse, the FAIL_OPEN
/// marker, and the hook/file/reason triple the Rust writer emits.
fn assert_canonical_fail_open_line(log: &str, reason_fragment: &str) {
    let line = log
        .lines()
        .find(|l| l.contains("FAIL_OPEN"))
        .unwrap_or_else(|| panic!("no FAIL_OPEN line recorded, log: {log:?}"));
    let ts = line.split_whitespace().next().unwrap_or("");
    // `cli::stats::parse_iso_timestamp` needs >= 19 chars of YYYY-MM-DDTHH:MM:SSZ.
    assert!(
        ts.len() >= 19 && ts.as_bytes()[10] == b'T' && ts.ends_with('Z'),
        "timestamp must be the ISO shape cli::stats parses, got {ts:?}"
    );
    for field in ["hook=", "file=", "reason="] {
        assert!(
            line.contains(field),
            "fail-open line is missing {field} — drifted from log_fail_open_named: {line:?}"
        );
    }
    assert!(
        line.contains(reason_fragment),
        "fail-open line must name the cause {reason_fragment:?}: {line:?}"
    );
}

/// 3.02a — no jq means post-edit tracks nothing. The skip must be recorded
/// under $MATI_HOME, the root `mati stats` scans, or an installation with no
/// jq looks identical to a working one.
#[test]
fn post_edit_records_fail_open_when_jq_is_missing() {
    let harness = HookTestHarness::for_post_edit().exclude_binary("jq");
    let input = serde_json::json!({
        "tool_input": { "file_path": "src/main.rs", "content": "/// Doc\nfn main() {}\n" }
    })
    .to_string();
    let output = harness.run(&input);

    assert_eq!(output.exit_code, 0, "a missing dependency must fail open");
    assert_canonical_fail_open_line(&harness.fail_open_log(), "jq not on PATH");
    assert!(
        output.stderr.contains("enforcement bypassed"),
        "the skip must warn on stderr, got: {}",
        output.stderr
    );
    assert!(
        !harness.mock_dir.path().join(".mati/fail_open.log").exists(),
        "the record must follow $MATI_HOME, not $HOME/.mati"
    );
    assert!(
        !harness.read_log().contains("edit-hook"),
        "no jq means no edit tracking — that is the skip being recorded"
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

/// 3.05 — Codex session-start emits compact active sentinel (~5 tokens).
#[test]
fn codex_session_start_emits_active_sentinel() {
    let harness = HookTestHarness::for_codex_session_start();
    let output = harness.run("{}");
    assert_eq!(output.exit_code, 0);
    assert!(
        output.stdout.contains("[mati] active"),
        "session-start should emit compact sentinel, got: {}",
        output.stdout
    );
}

/// 3.05a — SessionStart passes `mati watch-paths` JSON through untouched.
/// Claude Code starts no file watcher without it, so a mangled or wrapped
/// payload silently disables every later FileChanged event.
#[test]
fn session_start_forwards_watch_paths_json() {
    let harness = HookTestHarness::for_session_start().with_extra_mock_case(
        r#"watch-paths) echo '{"hookSpecificOutput":{"hookEventName":"SessionStart","watchPaths":["/repo/src/a.rs"]}}' ;;"#,
    );
    let output = harness.run("{}");
    assert_eq!(output.exit_code, 0);
    let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "stdout must be the hook JSON verbatim: {e}, got: {}",
            output.stdout
        )
    });
    assert_eq!(
        json["hookSpecificOutput"]["watchPaths"][0],
        "/repo/src/a.rs"
    );
}

/// 3.05b — A store with nothing to watch must emit nothing, not an empty
/// object: Claude Code would treat a bare `{}` as a hook response.
#[test]
fn session_start_emits_nothing_when_there_is_nothing_to_watch() {
    let harness = HookTestHarness::for_session_start();
    let output = harness.run("{}");
    assert_eq!(output.exit_code, 0);
    assert!(
        output.stdout.trim().is_empty(),
        "no watch paths must mean no stdout, got: {}",
        output.stdout
    );
}

/// 3.05c — FileChanged is pure recording. Any stdout would be parsed as a
/// hook response for an event that has no decision to make.
#[test]
fn file_changed_emits_no_stdout() {
    let harness = HookTestHarness::for_file_changed();
    let output = harness
        .run(r#"{"hook_event_name":"FileChanged","file_path":"/repo/src/a.rs","event":"change"}"#);
    assert_eq!(output.exit_code, 0);
    assert!(
        output.stdout.trim().is_empty(),
        "FileChanged must inject nothing, got: {}",
        output.stdout
    );
}

// No `exclude_binary("mati")` fail-open case for these two: `build_path`
// always prepends the dir `write_mock_mati` writes into, so the mock is found
// regardless and the test would pass without exercising the branch.

/// 3.06 — Codex user-prompt hook exits cleanly with zero injection.
#[test]
fn codex_user_prompt_exits_clean_no_injection() {
    let harness = HookTestHarness::for_codex_user_prompt();
    let output = harness.run(r#"{"prompt":"Please inspect src/main.rs and fix the bug"}"#);
    assert_eq!(output.exit_code, 0);
    assert!(
        output.stdout.trim().is_empty(),
        "user-prompt hook must inject zero tokens, got: {}",
        output.stdout
    );
}

// 3.07–3.09 — Codex pre-bash and post-bash enforcement is in Rust.
// Wrapper execution is in Category 1 above. Enforcement matrix is covered
// by hooks::decide::tests (51 unit tests) + cli::hook_decide::tests (22 tests).

/// 3.10 — Codex stop flushes then harvests the session.
#[test]
fn codex_stop_flushes_then_harvests() {
    let harness = HookTestHarness::for_codex_stop();
    let output = harness.run("{}");
    assert_eq!(output.exit_code, 0);
    let log = harness.read_log();
    let flush_pos = log
        .find("session-flush")
        .expect("missing session-flush in log");
    let harvest_pos = log
        .find("session-harvest")
        .expect("missing session-harvest in log");
    assert!(
        flush_pos < harvest_pos,
        "flush must precede harvest, log: {log}"
    );
}
