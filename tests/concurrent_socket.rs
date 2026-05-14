//! Concurrent-connection stress test for the daemon socket.
//!
//! Spawns `mati serve` against an isolated tempdir, then fires N parallel
//! `mati ping --daemon-only` subprocesses against it. All must succeed
//! within a timeout, proving the new bounded-concurrency `JoinSet` +
//! `Semaphore` accept loop in `serve_daemon_socket` does not deadlock,
//! lose connections, or serialize requests fatally.
//!
//! Marked `#[ignore]` because it spawns ~16 subprocesses and depends on a
//! writable `~/`. Run explicitly with:
//!
//!     cargo test --test concurrent_socket -- --ignored

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

use mati_core::store::derive_slug;

const READY_TIMEOUT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(100);
const CONCURRENT_CLIENTS: usize = 16;

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn daemon_socket_handles_concurrent_pings() {
    let project_temp = TempDir::new().expect("project tempdir");
    let project = std::fs::canonicalize(project_temp.path()).expect("canonicalize project");
    let bin = env!("CARGO_BIN_EXE_mati");

    // ── 1. Spawn mati serve. ──────────────────────────────────────────────
    let stderr_path = project.join("serve.stderr");
    let stderr_file = std::fs::File::create(&stderr_path).unwrap();
    let mut child = Command::new(bin)
        .arg("serve")
        .current_dir(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .expect("failed to spawn `mati serve`");
    let _stdin = child.stdin.take();
    let _guard = ChildGuard(child);

    let slug = derive_slug(&project);
    let mati_root = dirs::home_dir().unwrap().join(".mati").join(&slug);
    wait_for_path(&mati_root.join("mati.sock"), READY_TIMEOUT).unwrap_or_else(|_| {
        let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
        panic!("daemon never came up; stderr:\n{stderr}");
    });

    // ── 2. Fire N concurrent `mati ping --daemon-only` clients. ───────────
    // Each subprocess opens its own UnixStream, sends a v2 ping request,
    // and exits. Running them in parallel via tokio::spawn pushes the
    // accept loop and JoinSet through their hot path.
    let bin_owned = bin.to_string();
    let project_owned = project.clone();
    let mut handles = Vec::with_capacity(CONCURRENT_CLIENTS);
    let started = Instant::now();
    for _ in 0..CONCURRENT_CLIENTS {
        let bin = bin_owned.clone();
        let project = project_owned.clone();
        handles.push(tokio::spawn(async move {
            let output = tokio::task::spawn_blocking(move || {
                Command::new(&bin)
                    .arg("ping")
                    .arg("--daemon-only")
                    .current_dir(&project)
                    .output()
            })
            .await
            .expect("spawn_blocking join")
            .expect("ping command spawn");
            assert!(
                output.status.success(),
                "ping client failed (exit={:?}): stdout={:?} stderr={:?}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            // Sanity: stdout should contain "ok".
            let s = String::from_utf8_lossy(&output.stdout);
            assert!(
                s.contains("ok"),
                "ping output should contain 'ok'; got: {s}"
            );
        }));
    }

    // ── 3. All clients must complete within the timeout. ──────────────────
    // If the accept loop deadlocks or starves, this hangs; tokio::time::timeout
    // turns that into a deterministic failure.
    let join_all = async {
        for h in handles {
            h.await.expect("client task panicked");
        }
    };
    tokio::time::timeout(Duration::from_secs(30), join_all)
        .await
        .expect("clients did not complete within 30s — accept loop may be deadlocked");

    let elapsed = started.elapsed();
    eprintln!("{CONCURRENT_CLIENTS} concurrent pings completed in {elapsed:?}");
}

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
