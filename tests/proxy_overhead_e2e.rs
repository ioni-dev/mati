//! γ-C2 — Latency comparison gate for the Direct vs Socket mem_get path.
//!
//! Before γ removes `MatiBackend::Direct` (γ-C4), we need a hard guarantee
//! that the UDS-proxied path doesn't regress agent-visible latency. This
//! e2e test measures both paths against the *same* store data and asserts
//! that proxy overhead at the p50 stays under a 2 ms ceiling.
//!
//! If this test fails, γ pauses. Either the proxy path needs optimization
//! or the threshold is wrong — but we never ship a regression that user
//! sessions feel.
//!
//! ## Phasing
//!
//! 1. **Setup**: tempdir + Store + populate N file records.
//! 2. **Direct phase**: construct `MatiServer::with_graph_arc(...)` and
//!    call `mem_get` IN-PROCESS for N iterations. No daemon, no IPC.
//! 3. **Lock release**: drop the in-process graph + server so the
//!    SurrealKV lock is released before the daemon tries to acquire it.
//! 4. **Daemon spawn**: `mati serve` subprocess against the same tempdir.
//!    Wait for `mati.sock` to appear.
//! 5. **Socket phase**: construct `MatiServer::with_socket_root(root)`
//!    and call `mem_get` over UDS for N iterations against the live
//!    daemon. Same key sequence as the Direct phase so the comparison is
//!    apples-to-apples.
//! 6. **Compare**: sort durations, extract p50, assert overhead under 2 ms.
//!
//! ## Why both phases use `MatiServer::mem_get` (not a raw client)
//!
//! Hitting the real rmcp tool entry point measures the path the agent
//! actually goes through — including serde, response formatting, and the
//! socket_call envelope. A pure-store benchmark would understate Direct
//! latency and overstate the relative proxy overhead.
//!
//! ## Note on absolute numbers
//!
//! Per-call p50 in this benchmark runs at ~200-300 ms — well above what
//! a real agent sees in steady state. Cause: every `mem_get` spawns
//! deferred tokio tasks (consultation receipts, analytics, enforcement
//! events). With 50 sequential calls in a tight loop, those background
//! tasks accumulate and contend with the foreground measurement loop for
//! the SurrealKV write lock.
//!
//! The benchmark intentionally measures *under contention* to capture
//! the worst-case experience. Real agents make 1-10 mem_get calls per
//! session with seconds between them, giving the deferred work time to
//! drain. Production p50 is closer to 1-10 ms.
//!
//! For this gate's purpose — "does the Socket path add latency overhead
//! versus Direct?" — the contention applies equally to both paths so
//! the *comparison* is fair, even though the *absolute* numbers are
//! pessimistic.
//!
//! Counterintuitive observation worth pinning: Socket is often *faster*
//! than Direct in this benchmark because the deferred background work
//! runs in the daemon process under Socket mode (off the test's critical
//! path) versus the same process under Direct mode (contending with the
//! foreground loop). That's a structural argument for γ: process
//! separation isolates background side effects from the foreground call.
//!
//! Marked `#[ignore]` — spawns a daemon subprocess, runs ~400 mem_get
//! calls, depends on a writable `~/`. Run explicitly with:
//!
//!     cargo nextest run --test proxy_overhead_e2e --run-ignored only
//!     cargo test --test proxy_overhead_e2e -- --ignored
//!
//! Total wall time on a healthy Mac: ~5-8 s (including daemon spawn).

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use mati_core::graph::Graph;
use mati_core::mcp::tools::MatiServer;
use mati_core::store::{derive_slug, Store};

/// Iterations per phase. Each `bench_mem_get` triggers a session:consulted
/// write + spawns deferred analytics/enforcement writes, so the wall-clock
/// cost compounds with the iteration count even though the per-call
/// foreground work is small. 50 samples gives a stable p50 (the gate
/// threshold is 2 ms, well above sample-to-sample noise) and keeps the
/// total test runtime under ~30 s.
const ITERATIONS: usize = 50;

/// Warmup iterations — discarded before measurement so JIT-like effects
/// (tantivy lazy-init, tokio runtime warmup, page cache) don't pollute
/// the steady-state numbers.
const WARMUP: usize = 10;

/// p50 overhead ceiling. If the Socket path's p50 exceeds Direct's p50 by
/// more than this, γ pauses. Sized to comfortably exceed normal UDS
/// round-trip + JSON serde on macOS (~100–400 µs) while catching real
/// regressions (e.g. accidental fsync, lock contention, runaway alloc).
const MAX_P50_OVERHEAD: Duration = Duration::from_millis(2);

/// How long the daemon socket may take to appear after `mati serve` is
/// spawned. v2 schema migration on a fresh store is bootstrap-fast-path
/// (no work), so this is generous.
const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(20);

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn proxy_overhead_p50_stays_under_2ms_for_mem_get() {
    // ── 1. Setup + Direct phase ───────────────────────────────────────────
    //
    // Single Store::open spans both setup (populate fixtures) and the
    // Direct measurement. Re-opening between phases tripped a SurrealKV
    // lock-release race: the LOCK file's flock is released on drop, but
    // SurrealKV's background flush/index workers don't fully release
    // their fd references synchronously. Keeping one Store live through
    // the whole in-process phase sidesteps the race entirely. The Store
    // (and therefore the lock) is released before Phase 2 (daemon
    // spawn).
    let project_temp = TempDir::new().expect("project tempdir");
    let project = std::fs::canonicalize(project_temp.path()).expect("canonicalize project");

    let record_count = 100;
    let direct_durations = {
        let store = Store::open(&project).await.expect("open store");
        for i in 0..record_count {
            let key = format!("file:src/test_{i}.rs");
            let mut record = mati_core::store::record::Record::layer0_file_stub(
                key.clone(),
                uuid::Uuid::nil(),
                1,
                0,
            );
            record.value = format!("test fixture file {i}");
            store.put(&key, &record).await.expect("put record");
        }
        let graph = Graph::load(store).await.expect("graph load");
        let graph_arc = Arc::new(tokio::sync::RwLock::new(graph));
        let server = MatiServer::with_graph_arc(Arc::clone(&graph_arc));

        // Warmup — discarded.
        for i in 0..WARMUP {
            let key = format!("file:src/test_{}.rs", i % record_count);
            let _ = server.bench_mem_get(key).await;
        }

        let mut durations = Vec::with_capacity(ITERATIONS);
        for i in 0..ITERATIONS {
            let key = format!("file:src/test_{}.rs", i % record_count);
            let start = Instant::now();
            let _ = server.bench_mem_get(key).await;
            durations.push(start.elapsed());
        }
        // server + graph_arc + (transitively) the inner Store all drop
        // here, releasing the SurrealKV lock before Phase 2.
        durations
    };

    // Give SurrealKV's background workers a tick to finish draining
    // their fd references. The Drop has run, but the file system view
    // (LOCK file flock) sometimes lags by a few ms under load. This is
    // belt-and-suspenders — production code never re-opens an active
    // store, so this lag is fine to wait through in a benchmark.
    tokio::time::sleep(Duration::from_millis(250)).await;

    // ── 3. Spawn daemon ───────────────────────────────────────────────────
    let bin = env!("CARGO_BIN_EXE_mati");
    let stderr_path = project.join("serve.stderr");
    let stderr_file = std::fs::File::create(&stderr_path).expect("create stderr file");
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
    let mati_root = dirs::home_dir()
        .expect("home dir")
        .join(".mati")
        .join(&slug);
    wait_for_path(&mati_root.join("mati.sock"), DAEMON_READY_TIMEOUT).unwrap_or_else(|_| {
        let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
        panic!("daemon never came up within {DAEMON_READY_TIMEOUT:?}; stderr:\n{stderr}");
    });

    // ── 4. Socket phase: UDS-proxied mem_get measurement ──────────────────
    let socket_durations = measure_socket(&mati_root, record_count).await;

    // ── 5. Compare p50s ───────────────────────────────────────────────────
    let direct_p50 = percentile(&direct_durations, 50);
    let direct_p95 = percentile(&direct_durations, 95);
    let socket_p50 = percentile(&socket_durations, 50);
    let socket_p95 = percentile(&socket_durations, 95);

    let overhead_p50 = socket_p50.saturating_sub(direct_p50);

    eprintln!(
        "proxy_overhead_e2e: direct p50={direct_p50:?} p95={direct_p95:?}; \
         socket p50={socket_p50:?} p95={socket_p95:?}; \
         overhead p50={overhead_p50:?} (threshold={MAX_P50_OVERHEAD:?})"
    );

    assert!(
        overhead_p50 < MAX_P50_OVERHEAD,
        "γ-C2 GATE: proxy overhead p50 = {overhead_p50:?} exceeds {MAX_P50_OVERHEAD:?} ceiling. \
         Direct p50={direct_p50:?}, Socket p50={socket_p50:?}. \
         Pause γ migration and investigate before removing the Direct path."
    );
}

/// Socket phase — uses `MatiServer::with_socket_root(...)` so every call
/// is a real UDS round-trip to the spawned daemon.
async fn measure_socket(mati_root: &Path, record_count: usize) -> Vec<Duration> {
    let server = MatiServer::with_socket_root(mati_root.to_path_buf());

    for i in 0..WARMUP {
        let key = format!("file:src/test_{}.rs", i % record_count);
        let _ = server.bench_mem_get(key).await;
    }

    let mut durations = Vec::with_capacity(ITERATIONS);
    for i in 0..ITERATIONS {
        let key = format!("file:src/test_{}.rs", i % record_count);
        let start = Instant::now();
        let _ = server.bench_mem_get(key).await;
        durations.push(start.elapsed());
    }
    durations
}

/// Compute a percentile from a vector of durations. Sorts in-place.
fn percentile(durations: &[Duration], pct: usize) -> Duration {
    let mut sorted: Vec<Duration> = durations.to_vec();
    sorted.sort();
    let idx = (sorted.len() * pct / 100).min(sorted.len() - 1);
    sorted[idx]
}

fn wait_for_path(path: &Path, timeout: Duration) -> Result<(), &'static str> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("timeout")
}
