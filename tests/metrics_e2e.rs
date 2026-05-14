//! End-to-end test for the live daemon metrics surface.
//!
//! Spawns `mati serve` against an isolated tempdir, fires N ping requests
//! through the daemon socket, then queries `Command::Metrics` via
//! `mati doctor --internal --json` and verifies:
//!
//!   1. The snapshot's `version` field matches `metrics::SNAPSHOT_VERSION`
//!      (catches schema drift between daemon and client builds).
//!   2. The `ping` command shows `count == N` and `error_count == 0`.
//!   3. Latency stats are ordered (`p50 <= p95 <= p99 <= max`) and non-zero.
//!   4. `total_calls` includes the pings plus the metrics query itself.
//!   5. `uptime_secs` is non-negative.
//!
//! This is the only end-to-end check that proves the entire metrics chain
//! is wired correctly: `metrics::init` at daemon boot → `dispatch_v2`
//! recording → `socket_dispatch` snapshot arm → `v1_to_v2_command` mapping
//! → `daemon_result` round-trip → doctor renderer.
//!
//! Marked `#[ignore]` because it spawns subprocesses and depends on a
//! writable `~/`. Run explicitly with:
//!
//!     cargo test --test metrics_e2e -- --ignored

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

use mati_core::mcp::metrics::SNAPSHOT_VERSION;
use mati_core::store::derive_slug;

const READY_TIMEOUT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(100);
const PING_COUNT: u64 = 5;

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn metrics_snapshot_reflects_dispatch_traffic() {
    let project_temp = TempDir::new().expect("project tempdir");
    let project = std::fs::canonicalize(project_temp.path()).expect("canonicalize project");
    let bin = env!("CARGO_BIN_EXE_mati");

    // ── 1. Spawn mati serve. ──────────────────────────────────────────────
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
    wait_for_path(&mati_root.join("mati.sock"), READY_TIMEOUT).unwrap_or_else(|_| {
        let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
        panic!("daemon never came up; stderr:\n{stderr}");
    });

    // ── 2. Fire N pings sequentially. ─────────────────────────────────────
    // Sequential (not concurrent) so the expected count is deterministic
    // and we don't race the metrics ring's eviction of older samples.
    for i in 0..PING_COUNT {
        let output = Command::new(bin)
            .arg("ping")
            .arg("--daemon-only")
            .current_dir(&project)
            .output()
            .unwrap_or_else(|e| panic!("ping #{i} failed to spawn: {e}"));
        assert!(
            output.status.success(),
            "ping #{i} failed (exit={:?}): stderr={:?}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    // ── 3. Query `mati doctor --internal --json`. ─────────────────────────
    let output = Command::new(bin)
        .arg("doctor")
        .arg("--internal")
        .arg("--json")
        .current_dir(&project)
        .output()
        .expect("doctor --internal --json spawn");
    assert!(
        output.status.success(),
        "doctor --internal exited non-zero ({:?}); stderr={:?}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );

    let raw = String::from_utf8(output.stdout).expect("doctor stdout is utf8");
    let snap: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("doctor --json output not parseable: {e}\nraw:\n{raw}"));

    // ── 4. Schema invariants. ─────────────────────────────────────────────
    let version = snap.get("version").and_then(|v| v.as_u64());
    assert_eq!(
        version,
        Some(u64::from(SNAPSHOT_VERSION)),
        "snapshot version mismatch: client expects {SNAPSHOT_VERSION}, daemon returned {version:?}",
    );

    let uptime = snap.get("uptime_secs").and_then(|v| v.as_u64());
    assert!(
        uptime.is_some(),
        "uptime_secs missing or wrong type: got {uptime:?}",
    );

    let total_calls = snap
        .get("total_calls")
        .and_then(|v| v.as_u64())
        .expect("total_calls field present");
    // PING_COUNT pings + 1 metrics query == total. Pings going through
    // dispatch_v2, the metrics query itself going through dispatch_v2.
    assert!(
        total_calls > PING_COUNT,
        "expected more than {PING_COUNT} total calls (got {total_calls})",
    );

    let total_errors = snap
        .get("total_errors")
        .and_then(|v| v.as_u64())
        .expect("total_errors field present");
    assert_eq!(
        total_errors, 0,
        "did not expect any errors from a clean daemon + valid pings"
    );

    // ── 5. Per-command assertions. ────────────────────────────────────────
    let commands = snap
        .get("commands")
        .and_then(|v| v.as_array())
        .expect("commands array present");
    assert!(!commands.is_empty(), "commands array must not be empty");

    let ping = commands
        .iter()
        .find(|c| c.get("name").and_then(|n| n.as_str()) == Some("ping"))
        .expect("ping command must appear in the snapshot");

    assert_eq!(
        ping.get("count").and_then(|v| v.as_u64()),
        Some(PING_COUNT),
        "ping count must match the number of pings we fired",
    );
    assert_eq!(
        ping.get("error_count").and_then(|v| v.as_u64()),
        Some(0),
        "ping had errors — daemon pinged unsuccessfully?",
    );

    // Latency ordering: p50 ≤ p95 ≤ p99 ≤ max. All non-zero (a sub-µs
    // round-trip is plausible only in micro-benchmarks; over a real
    // tokio socket this should always be at least 1 µs).
    let p50 = ping.get("p50_us").and_then(|v| v.as_u64()).unwrap_or(0);
    let p95 = ping.get("p95_us").and_then(|v| v.as_u64()).unwrap_or(0);
    let p99 = ping.get("p99_us").and_then(|v| v.as_u64()).unwrap_or(0);
    let max = ping.get("max_us").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(
        p50 > 0,
        "ping p50 should be at least 1µs over a real socket (got {p50})",
    );
    assert!(
        p50 <= p95,
        "percentile ordering violated: p50={p50} > p95={p95}",
    );
    assert!(
        p95 <= p99,
        "percentile ordering violated: p95={p95} > p99={p99}",
    );
    assert!(
        p99 <= max,
        "percentile ordering violated: p99={p99} > max={max}",
    );

    eprintln!(
        "metrics_e2e: {PING_COUNT} pings, total_calls={total_calls}, ping p50/p95/p99/max = {p50}/{p95}/{p99}/{max} µs"
    );
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
