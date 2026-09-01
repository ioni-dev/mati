//! `mati hook-decide claude-post-read-compliance` against a real daemon.
//!
//! The decision is four-way and every branch is a silent one — the hook writes
//! no stdout and always exits 0, so the only observable is the
//! `analytics:miss_<date>` aggregate the daemon keeps. Unit tests reach the
//! path extraction and the fail-open log; nothing below the socket. This walks
//! the four branches in one daemon's lifetime, in an order where each phase's
//! assertion also proves the previous phase recorded nothing:
//!
//!   1. daemon unreachable      → nothing recorded, exit 0, fail-open logged
//!   2. unconsulted, has record → one Miss
//!   3. consulted               → nothing
//!   4. no record at all        → nothing (the read gate already counted it)

use std::path::Path;
use std::process::{Command, Stdio};

use mati_core::store::derive_slug;
use mati_core::store::session::today_key;
use tempfile::TempDir;

mod common;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mati")
}

/// Run a hook variant with `payload` on stdin. Returns the exit code.
fn run_hook(project: &Path, variant: &str, payload: &str, auto_spawn: bool) -> i32 {
    let mut cmd = Command::new(bin());
    cmd.args(["hook-decide", variant])
        .current_dir(project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if !auto_spawn {
        cmd.env("MATI_DISABLE_AUTO_SPAWN", "1");
    }
    let output = cmd
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(payload.as_bytes())?;
            child.wait_with_output()
        })
        .unwrap_or_else(|e| panic!("spawn hook-decide {variant}: {e}"));
    assert!(
        output.stdout.is_empty(),
        "PostToolUse carries no decision — stdout must stay empty, got {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    output.status.code().unwrap_or(-1)
}

/// `mati get <key>` through the daemon, parsed. `None` for a missing record.
fn get(project: &Path, key: &str) -> Option<serde_json::Value> {
    let output = Command::new(bin())
        .args(["get", key])
        .current_dir(project)
        .output()
        .unwrap_or_else(|e| panic!("spawn mati get {key}: {e}"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    match serde_json::from_str::<serde_json::Value>(stdout.trim()) {
        Ok(serde_json::Value::Null) | Err(_) => None,
        Ok(value) => Some(value),
    }
}

/// How many misses the daily aggregate holds, and for which keys.
fn misses(project: &Path, agg_key: &str) -> (u64, Vec<String>) {
    let Some(record) = get(project, agg_key) else {
        return (0, Vec::new());
    };
    let payload = &record["payload"];
    let count = payload["count"].as_u64().unwrap_or(0);
    let keys = payload["keys"]
        .as_array()
        .map(|keys| {
            keys.iter()
                .filter_map(|k| k.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    (count, keys)
}

#[test]
fn a_post_read_compliance_hook_records_only_the_unconsulted_read_of_a_known_file() {
    let project_temp = TempDir::new().expect("project tempdir");
    // Canonical: macOS puts tempdirs under a symlinked `/var`, and the slug
    // must be the one the spawned children derive from their own cwd.
    let project = std::fs::canonicalize(project_temp.path()).expect("canonicalize project");
    common::isolate_mati_home();
    let _daemon_guard = common::DaemonGuard::for_mati_home(&project, common::mati_home());

    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&project)
            .status()
            .expect("git init")
            .success(),
        "git init failed"
    );
    std::fs::write(project.join("a.py"), "x = 1\n").expect("write a.py");

    assert!(
        Command::new(bin())
            .arg("init")
            .current_dir(&project)
            .env("MATI_DISABLE_AUTO_SPAWN", "1")
            .output()
            .expect("spawn mati init")
            .status
            .success(),
        "mati init failed"
    );

    let sock = common::mati_home()
        .join(derive_slug(&project))
        .join("mati.sock");
    let agg_key = today_key("analytics:miss_");
    // Claude Code passes absolute paths; the hook resolves them to the
    // repo-relative store key.
    let a_py = project.join("a.py");
    let read_payload =
        |path: &Path| serde_json::json!({ "tool_input": { "file_path": path } }).to_string();

    // ── 1. Daemon unreachable: nothing recorded, exit 0, fail-open logged. ──
    assert_eq!(
        run_hook(
            &project,
            "claude-post-read-compliance",
            &read_payload(&a_py),
            false,
        ),
        0,
        "an unreachable daemon must never block the agent (P9)"
    );
    assert!(
        !sock.exists(),
        "the unreachable phase must not have started a daemon"
    );
    let fail_open = std::fs::read_to_string(common::mati_home().join("fail_open.log"))
        .expect("fail_open.log must exist after the bypass");
    assert!(
        fail_open.contains("hook=post-read-compliance") && fail_open.contains("daemon not running"),
        "the bypass must be recorded where `mati stats` reads it, got: {fail_open}"
    );

    // ── 2. Unconsulted read of a file that HAS a record: one Miss. ─────────
    assert!(
        get(&project, "file:a.py").is_none(),
        "no daemon yet, so `get` fails open — this only pins the phase-1 state"
    );
    assert_eq!(
        run_hook(
            &project,
            "claude-post-read-compliance",
            &read_payload(&a_py),
            true,
        ),
        0
    );
    assert!(
        get(&project, "file:a.py").is_some(),
        "`mati init` must have left a file record for a.py"
    );
    let (count, keys) = misses(&project, &agg_key);
    assert_eq!(
        count, 1,
        "exactly one Miss — a second would mean the unreachable phase recorded too"
    );
    assert_eq!(keys, vec!["file:a.py".to_string()]);

    // ── 3. Consulted read: nothing. ───────────────────────────────────────
    assert_eq!(
        run_hook(
            &project,
            "claude-post-memget",
            r#"{"tool_input":{"key":"file:a.py"}}"#,
            true,
        ),
        0
    );
    assert_eq!(
        run_hook(
            &project,
            "claude-post-read-compliance",
            &read_payload(&a_py),
            true,
        ),
        0
    );
    assert_eq!(
        misses(&project, &agg_key).0,
        1,
        "a consulted read is not a compliance miss"
    );

    // ── 4. Read of a file with NO record: nothing. ─────────────────────────
    // Written after `mati init`, so Layer 0 never saw it.
    let b_py = project.join("b.py");
    std::fs::write(&b_py, "y = 2\n").expect("write b.py");
    assert!(
        get(&project, "file:b.py").is_none(),
        "b.py must have no record for this phase to test what it claims"
    );
    assert_eq!(
        run_hook(
            &project,
            "claude-post-read-compliance",
            &read_payload(&b_py),
            true,
        ),
        0
    );
    let (count, keys) = misses(&project, &agg_key);
    assert_eq!(
        count, 1,
        "the read gate already counts a no-record read — this hook must not double it"
    );
    assert!(
        !keys.iter().any(|k| k == "file:b.py"),
        "b.py must not appear in the miss aggregate, got {keys:?}"
    );
}
