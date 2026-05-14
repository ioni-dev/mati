//! End-to-end crash-recovery test for `mati serve` boot-time auto-drain.
//!
//! Pre-stages a knowledge store with drift and a dirty marker (simulating an
//! unclean shutdown), then spawns `mati serve` as a real subprocess and
//! verifies:
//!
//!   1. The daemon comes up cleanly (`mati.sock` appears).
//!   2. The lifecycle log records an `auto_repair` event — proof that the
//!      boot-time auto-drain code path in `mcp::server::serve` actually ran
//!      against the pre-staged dirty marker.
//!   3. After the auto-drain, the dirty marker on disk reports `dirty:false`
//!      (queried via `mati get` through the daemon socket).
//!
//! The test does NOT mutate `$HOME` in-process — that would race with other
//! tests running in parallel. Instead it uses a unique tempdir as the project
//! root, which derives a unique slug under `~/.mati/<slug>/` for isolation.
//! The slug directory persists on disk after the test (matches existing
//! `Store` test behavior).
//!
//! Marked `#[ignore]` because subprocess tests are slow (~3s) and depend on a
//! filesystem `~/` that is reasonable to write to. Run explicitly with:
//!
//!     cargo test --test crash_recovery -- --ignored

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

use mati_core::graph::edges::{Edge, EdgeKind};
use mati_core::store::record::{
    Category, ConfidenceScore, FileRecord, GotchaRecord, Priority, QualityScore, Record,
    RecordLifecycle, RecordSource, RecordVersion, StalenessScore,
};
use mati_core::store::{derive_slug, repair, Store};

const READY_TIMEOUT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(100);

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore]
async fn crash_recovery_runs_auto_drain_on_serve_boot() {
    let project_temp = TempDir::new().expect("project tempdir");
    // Canonicalize the project path. On macOS `/var/folders/...` resolves to
    // `/private/var/folders/...` via a symlink, and `mati serve` calls
    // `std::env::current_dir()` which returns the resolved form. The test
    // must use the same canonicalized path so the slug derivation matches
    // (otherwise pre-staged data lives under a different `~/.mati/<slug>/`
    // than the daemon opens).
    let project = std::fs::canonicalize(project_temp.path()).expect("canonicalize project path");

    // ── 1. Pre-stage drift + dirty marker via direct Store access. ───────
    // Simulates the on-disk state left behind after an unclean shutdown
    // (panic, SIGKILL): a gotcha targets [B, C], but file A still
    // references it AND has a stale graph edge. The dirty marker records
    // that a partial-write failure was observed.
    {
        let store = Store::open(&project).await.unwrap();
        store
            .put(
                "file:src/a.rs",
                &make_file_record("src/a.rs", &["gotcha:moved"]),
            )
            .await
            .unwrap();
        store
            .put(
                "file:src/b.rs",
                &make_file_record("src/b.rs", &["gotcha:moved"]),
            )
            .await
            .unwrap();
        store
            .put("file:src/c.rs", &make_file_record("src/c.rs", &[]))
            .await
            .unwrap();
        store
            .put(
                "gotcha:moved",
                &make_gotcha_record("gotcha:moved", &["src/b.rs", "src/c.rs"]),
            )
            .await
            .unwrap();
        let stale_edge = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:moved");
        store
            .put_raw(&stale_edge.to_key(), &now_secs().to_le_bytes())
            .await
            .unwrap();
        repair::mark_dirty(&store, "gotcha:moved", "test partial-write").await;
        assert!(
            repair::is_dirty(&store).await,
            "marker must be set before subprocess starts"
        );
        store.close().await.unwrap();
    }

    // ── 2. Spawn `mati serve` as a real subprocess. ───────────────────────
    // Hold stdin open so the MCP stdio transport sees a connected client
    // and the daemon stays alive past the initial pipe-close path.
    let bin = env!("CARGO_BIN_EXE_mati");
    let stderr_path = project.join("serve.stderr");
    let stderr_file = std::fs::File::create(&stderr_path).unwrap();
    let mut child = Command::new(bin)
        .arg("serve")
        .current_dir(&project)
        .env("RUST_LOG", "info,mati=debug,mati_core=debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .expect("failed to spawn `mati serve`");
    let _stdin = child.stdin.take(); // keep handle open
    let _guard = ChildGuard(child);

    // ── 3. Compute the daemon root and wait for daemon-ready. ────────────
    let slug = derive_slug(&project);
    let mati_root = dirs::home_dir().unwrap().join(".mati").join(&slug);
    let lifecycle_log = mati_root.join("lifecycle.log");

    if wait_for_path(&mati_root.join("mati.sock"), READY_TIMEOUT).is_err() {
        let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
        panic!(
            "mati.sock never appeared — daemon failed to bind.\n\
             slug: {slug}\n\
             mati_root: {}\n\
             stderr from mati serve:\n{stderr}",
            mati_root.display()
        );
    }

    // ── 4. Verify the boot-time auto-drain wrote an `auto_repair` event.
    // The event is logged by `serve()` immediately after the Fast drain
    // completes, before binding the socket. So as soon as the socket
    // exists, the event must already be in the log.
    let auto_repair_seen = wait_for_log_event(&lifecycle_log, "auto_repair", READY_TIMEOUT);
    assert!(
        auto_repair_seen,
        "lifecycle.log should record an `auto_repair` event from boot-time drain. \
         contents: {:?}",
        std::fs::read_to_string(&lifecycle_log).ok()
    );

    // The serve_start event must also be present (sanity).
    let log = std::fs::read_to_string(&lifecycle_log).unwrap_or_default();
    assert!(
        log.contains("\tserve_start\t"),
        "lifecycle.log should record serve_start"
    );

    // ── 5. Verify the dirty marker is cleared. ────────────────────────────
    // We can't open Store directly (daemon holds the lock) so query through
    // the daemon socket via `mati get`.
    let output = Command::new(bin)
        .arg("get")
        .arg("analytics:integrity:gotcha_links")
        .current_dir(&project)
        .output()
        .expect("failed to run mati get");
    assert!(
        output.status.success(),
        "mati get exited non-zero: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // After auto-drain succeeds, the marker record persists with dirty=false.
    // (clear_dirty_marker rewrites the record with the cleared payload.)
    assert!(
        stdout.contains("\"dirty\":false"),
        "dirty marker should be cleared after auto-drain. mati get stdout: {stdout}"
    );
}

// ── Polling helpers ─────────────────────────────────────────────────────────

fn wait_for_path(path: &Path, timeout: Duration) -> Result<(), &'static str> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(POLL);
    }
    Err("timeout")
}

fn wait_for_log_event(log_path: &Path, event: &str, timeout: Duration) -> bool {
    let needle = format!("\t{event}\t");
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(contents) = std::fs::read_to_string(log_path) {
            if contents.contains(&needle) {
                return true;
            }
        }
        std::thread::sleep(POLL);
    }
    false
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Record builders (mirror src/store/repair.rs:tests) ──────────────────────

fn make_gotcha_record(key: &str, files: &[&str]) -> Record {
    let gotcha = GotchaRecord {
        rule: "test".into(),
        reason: "test".into(),
        severity: Priority::High,
        affected_files: files.iter().map(|s| s.to_string()).collect(),
        ref_url: None,
        discovered_session: 1_000_000,
        confirmed: true,
    };
    Record {
        key: key.to_string(),
        value: "test".into(),
        payload: serde_json::to_value(&gotcha).ok(),
        category: Category::Gotcha,
        priority: Priority::High,
        tags: vec![],
        created_at: 1_000_000,
        updated_at: 1_000_000,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: 1_000_000,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::DeveloperManual,
        confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
        gap_analysis_score: 0.0,
    }
}

fn make_file_record(path: &str, gotcha_keys: &[&str]) -> Record {
    let file = FileRecord {
        path: path.to_string(),
        purpose: String::new(),
        entry_points: vec![],
        imports: vec![],
        gotcha_keys: gotcha_keys.iter().map(|s| s.to_string()).collect(),
        decision_keys: vec![],
        todos: vec![],
        unsafe_count: 0,
        unwrap_count: 0,
        change_frequency: 0,
        last_author: None,
        is_hotspot: false,
        token_cost_estimate: 0,
        last_modified_session: 0,
        content_hash: None,
        line_count: 0,
        blast_radius: None,
        propagated_staleness: None,
    };
    Record {
        key: format!("file:{path}"),
        value: String::new(),
        payload: serde_json::to_value(&file).ok(),
        category: Category::File,
        priority: Priority::Normal,
        tags: vec![],
        created_at: 1_000_000,
        updated_at: 1_000_000,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: 1_000_000,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
    }
}
