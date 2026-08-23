//! `mati stats` renders the Enforcement (30d) section — including the subagent
//! spawns line — on the CACHED (snapshot) path, not only the live recompute.
//!
//! Enforcement counts are never stored in the write-seq-keyed snapshot, so a
//! cache hit re-runs the bounded scan. Before the fix the cached render omitted
//! the whole section; this pins the behavior.
//!
//! Flow: record one `SubagentSpawned` event through a live daemon (the only
//! path whose write is visible to a later subprocess), stop the daemon, then
//! run `mati stats` twice with `MATI_DISABLE_AUTO_SPAWN=1`. Direct mode is what
//! lets the first run persist a valid snapshot (the socket proxy rejects
//! `analytics:*` writes) for the second to hit.
//!
//! `#[ignore]` — spawns a daemon subprocess and uses a short `/tmp` home (the
//! Unix-socket path limit rules out the standard long tempdir). Same precedent
//! as `metrics_e2e`. Run with:
//!     cargo nextest run --test stats_cached_enforcement --run-ignored all

use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mati")
}

/// A short home + repo under `/tmp`, cleaned up (and its daemon stopped) on drop.
struct Scratch {
    home: PathBuf,
    repo: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        let pid = std::process::id();
        let home = PathBuf::from(format!("/tmp/mati-it-{tag}-{pid}-h"));
        let repo = PathBuf::from(format!("/tmp/mati-it-{tag}-{pid}-r"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("a.py"), "x = 1\n").unwrap();
        Scratch { home, repo }
    }

    fn mati(&self, args: &[&str], direct: bool) -> std::process::Output {
        let mut cmd = Command::new(bin());
        cmd.args(args)
            .current_dir(&self.repo)
            .env("MATI_HOME", &self.home)
            .env("NO_COLOR", "1");
        if direct {
            cmd.env("MATI_DISABLE_AUTO_SPAWN", "1");
        }
        cmd.output()
            .unwrap_or_else(|e| panic!("spawn mati {args:?}: {e}"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = self.mati(&["daemon", "stop"], false);
        let _ = std::fs::remove_dir_all(&self.home);
        let _ = std::fs::remove_dir_all(&self.repo);
    }
}

fn events_line(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.contains("Events:"))
        .unwrap_or("<no Events line>")
        .to_string()
}

#[test]
#[ignore]
fn cached_stats_renders_enforcement_and_subagent_spawns() {
    let s = Scratch::new("cache");

    assert!(s.mati(&["init"], true).status.success(), "init failed");

    // Warm a daemon (the hook path records only via a reachable daemon), record
    // one presence event, confirm it landed, then bring the daemon down.
    let _ = s.mati(&["stats"], false);
    let rec = Command::new(bin())
        .arg("subagent-record")
        .current_dir(&s.repo)
        .env("MATI_HOME", &s.home)
        .env("NO_COLOR", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(br#"{"agent_id":"agentX","agent_type":"general-purpose"}"#)?;
            child.wait()
        })
        .expect("subagent-record");
    assert!(rec.success(), "subagent-record failed");

    let vc = s.mati(&["verify-chain"], false);
    assert!(
        events_line(&vc).contains("Events:          1"),
        "expected exactly one recorded event, got: {}",
        events_line(&vc)
    );

    let _ = s.mati(&["daemon", "stop"], false);

    // Run 1 (direct) recomputes and persists a valid snapshot; run 2 hits it.
    let _ = s.mati(&["stats"], true);
    let out = s.mati(&["stats"], true);
    let cached = String::from_utf8_lossy(&out.stdout);

    assert!(
        cached.contains("(cached"),
        "second run should hit the snapshot cache, got:\n{cached}"
    );
    assert!(
        cached.contains("Enforcement (30d)"),
        "cached render must include the enforcement section, got:\n{cached}"
    );
    assert!(
        cached.contains("Subagent spawns"),
        "cached render must include the subagent spawns line, got:\n{cached}"
    );
}
