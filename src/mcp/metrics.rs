//! Live daemon metrics — per-command call counters and latency percentiles.
//!
//! Wired in once at the `dispatch_v2` boundary (the single entry point for
//! every wire command). Each command records: incremented count, incremented
//! error count if the response is `Response::Err`, and a latency sample in
//! microseconds. Latency samples are kept in a per-command ring of the last
//! `LATENCY_RING_SIZE` observations, from which p50/p95/p99 are computed on
//! read.
//!
//! # Why no new deps
//!
//! `hdrhistogram` would be more accurate at higher cardinality, but the
//! daemon's sustained QPS is low (single-digit req/s under normal hook
//! load), so a 512-entry ring is plenty for stable percentile estimates
//! and keeps the dependency surface unchanged. Total memory budget:
//! ~28 commands × 512 × 4 B ≈ 57 KiB. Negligible.
//!
//! # Why `std::sync::Mutex`
//!
//! The critical section is a single HashMap lookup + VecDeque push +
//! u64 increment. No await points are crossed under lock, so the standard
//! sync `Mutex` is appropriate and avoids pulling in a `tokio::sync::Mutex`
//! that would force `.await` on the recording path.
//!
//! # Global access
//!
//! `OnceLock<Arc<Mutex<Metrics>>>` so callers don't need to plumb a new
//! `Arc` through every dispatch function in `server.rs` / `dispatch_v2.rs`.
//! Initialized at daemon startup via [`init`]; if `record` is called before
//! `init` (e.g. in tests that exercise dispatch without booting the daemon),
//! the recording is silently dropped.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Number of recent latency samples kept per command. Sized so a daemon
/// running ~512 req/s for one second has full-window coverage; anything
/// older is replaced.
pub const LATENCY_RING_SIZE: usize = 512;

/// Process-global metrics handle. Some only after [`init`] has been called.
static METRICS: OnceLock<Arc<Mutex<Metrics>>> = OnceLock::new();

/// Initialize the global metrics handle. Called once at daemon startup.
///
/// Idempotent: a second call is a no-op and returns `false`. Returns `true`
/// the first time it succeeds. Safe to call from a single-threaded context
/// during daemon boot before any dispatch happens.
pub fn init() -> bool {
    METRICS.set(Arc::new(Mutex::new(Metrics::new()))).is_ok()
}

/// Record a single dispatch_v2 invocation.
///
/// `command_kind` should be `Command::kind()` (a static string). `elapsed_us`
/// is the wall-clock duration of the dispatch call. `is_error` is `true`
/// iff the response was [`crate::mcp::protocol::Response::Err`].
///
/// No-op if metrics have not been initialized (e.g. in test code that uses
/// dispatch_v2 directly without starting the daemon).
pub fn record(command_kind: &'static str, elapsed_us: u32, is_error: bool) {
    let Some(handle) = METRICS.get() else {
        return;
    };
    // Lock contention is minimal: only the dispatch_v2 entry point writes.
    // If poisoned, we drop the sample rather than panic — observability
    // should never crash the daemon.
    let Ok(mut m) = handle.lock() else {
        return;
    };
    m.record(command_kind, elapsed_us, is_error);
}

/// Return a serializable snapshot of current metrics. Cheap — produces
/// a sorted copy of each latency ring to compute percentiles.
pub fn snapshot() -> Option<MetricsSnapshot> {
    let handle = METRICS.get()?;
    let m = handle.lock().ok()?;
    Some(m.snapshot())
}

/// Live per-command stats. Reset on daemon restart.
struct CommandStats {
    /// Total successful + failed invocations.
    count: u64,
    /// Subset of `count` that returned `Response::Err`.
    error_count: u64,
    /// Sum of all observed latencies (microseconds). Saturating add.
    latency_sum_us: u64,
    /// Maximum observed latency (microseconds).
    latency_max_us: u32,
    /// Bounded ring of recent latency samples for percentile calculation.
    latencies_us: VecDeque<u32>,
}

impl CommandStats {
    fn new() -> Self {
        Self {
            count: 0,
            error_count: 0,
            latency_sum_us: 0,
            latency_max_us: 0,
            latencies_us: VecDeque::with_capacity(LATENCY_RING_SIZE),
        }
    }

    fn record(&mut self, elapsed_us: u32, is_error: bool) {
        self.count = self.count.saturating_add(1);
        if is_error {
            self.error_count = self.error_count.saturating_add(1);
        }
        self.latency_sum_us = self.latency_sum_us.saturating_add(u64::from(elapsed_us));
        if elapsed_us > self.latency_max_us {
            self.latency_max_us = elapsed_us;
        }
        if self.latencies_us.len() == LATENCY_RING_SIZE {
            self.latencies_us.pop_front();
        }
        self.latencies_us.push_back(elapsed_us);
    }

    /// Compute p50, p95, p99 from the current ring (sorted on demand).
    fn percentiles(&self) -> (u32, u32, u32) {
        if self.latencies_us.is_empty() {
            return (0, 0, 0);
        }
        let mut sorted: Vec<u32> = self.latencies_us.iter().copied().collect();
        sorted.sort_unstable();
        let n = sorted.len();
        // Nearest-rank percentile: ceil(p/100 * n) - 1, bounded.
        let pick = |p: u32| -> u32 {
            let idx = ((u64::from(p) * n as u64).div_ceil(100) as usize).saturating_sub(1);
            sorted[idx.min(n - 1)]
        };
        (pick(50), pick(95), pick(99))
    }
}

/// Live metrics state. Owned by the global `OnceLock` handle.
struct Metrics {
    started_at_secs: u64,
    started_instant: Instant,
    per_command: HashMap<&'static str, CommandStats>,
}

impl Metrics {
    fn new() -> Self {
        Self {
            started_at_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            started_instant: Instant::now(),
            per_command: HashMap::new(),
        }
    }

    fn record(&mut self, command_kind: &'static str, elapsed_us: u32, is_error: bool) {
        self.per_command
            .entry(command_kind)
            .or_insert_with(CommandStats::new)
            .record(elapsed_us, is_error);
    }

    fn snapshot(&self) -> MetricsSnapshot {
        let mut commands: Vec<CommandSnapshot> = self
            .per_command
            .iter()
            .map(|(name, stats)| {
                let (p50, p95, p99) = stats.percentiles();
                let mean_us = stats.latency_sum_us.checked_div(stats.count).unwrap_or(0) as u32;
                CommandSnapshot {
                    name,
                    count: stats.count,
                    error_count: stats.error_count,
                    mean_us,
                    p50_us: p50,
                    p95_us: p95,
                    p99_us: p99,
                    max_us: stats.latency_max_us,
                }
            })
            .collect();
        // Stable order: descending by count, then name.
        commands.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(b.name)));

        let total_calls: u64 = self.per_command.values().map(|s| s.count).sum();
        let total_errors: u64 = self.per_command.values().map(|s| s.error_count).sum();

        MetricsSnapshot {
            version: SNAPSHOT_VERSION,
            uptime_secs: self.started_instant.elapsed().as_secs(),
            started_at_secs: self.started_at_secs,
            total_calls,
            total_errors,
            commands,
        }
    }
}

/// Schema version for the metrics snapshot. Bump when fields change shape so
/// the doctor renderer can pin behavior.
pub const SNAPSHOT_VERSION: u32 = 1;

/// Serializable snapshot returned by [`snapshot`] and over the `metrics`
/// socket command.
#[derive(Debug, Serialize)]
pub struct MetricsSnapshot {
    pub version: u32,
    pub uptime_secs: u64,
    pub started_at_secs: u64,
    pub total_calls: u64,
    pub total_errors: u64,
    pub commands: Vec<CommandSnapshot>,
}

/// Per-command row in a metrics snapshot.
#[derive(Debug, Serialize)]
pub struct CommandSnapshot {
    pub name: &'static str,
    pub count: u64,
    pub error_count: u64,
    pub mean_us: u32,
    pub p50_us: u32,
    pub p95_us: u32,
    pub p99_us: u32,
    pub max_us: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_metrics() -> Metrics {
        Metrics::new()
    }

    #[test]
    fn record_increments_count_and_tracks_latency() {
        let mut m = fresh_metrics();
        m.record("ping", 100, false);
        m.record("ping", 200, false);
        m.record("ping", 300, true);

        let snap = m.snapshot();
        let ping = snap
            .commands
            .iter()
            .find(|c| c.name == "ping")
            .expect("ping row present");
        assert_eq!(ping.count, 3);
        assert_eq!(ping.error_count, 1);
        assert_eq!(ping.max_us, 300);
        assert_eq!(ping.mean_us, 200);
    }

    #[test]
    fn percentiles_with_uniform_distribution() {
        let mut m = fresh_metrics();
        for i in 1..=100u32 {
            m.record("mem_get", i * 10, false);
        }
        let snap = m.snapshot();
        let mem_get = snap
            .commands
            .iter()
            .find(|c| c.name == "mem_get")
            .expect("mem_get row present");
        assert_eq!(mem_get.count, 100);
        // 50th percentile of 1..=100 (×10) is the 50th smallest = 500.
        assert_eq!(mem_get.p50_us, 500);
        // 95th percentile is the 95th smallest = 950.
        assert_eq!(mem_get.p95_us, 950);
        // 99th percentile is the 99th smallest = 990.
        assert_eq!(mem_get.p99_us, 990);
        assert_eq!(mem_get.max_us, 1000);
    }

    #[test]
    fn ring_evicts_oldest_above_capacity() {
        let mut m = fresh_metrics();
        // Push 2× capacity. Older half should be evicted.
        for i in 0..(LATENCY_RING_SIZE * 2) as u32 {
            m.record("mem_query", i + 1, false);
        }
        let snap = m.snapshot();
        let mq = snap
            .commands
            .iter()
            .find(|c| c.name == "mem_query")
            .unwrap();
        assert_eq!(mq.count, (LATENCY_RING_SIZE * 2) as u64);
        // p50 of the retained second half (LATENCY_RING_SIZE+1 .. 2*LATENCY_RING_SIZE).
        let expected_p50 = (LATENCY_RING_SIZE + LATENCY_RING_SIZE / 2) as u32;
        assert_eq!(mq.p50_us, expected_p50);
    }

    #[test]
    fn snapshot_is_ordered_by_count_then_name() {
        let mut m = fresh_metrics();
        for _ in 0..5 {
            m.record("ping", 10, false);
        }
        for _ in 0..10 {
            m.record("mem_get", 20, false);
        }
        for _ in 0..10 {
            m.record("get", 15, false);
        }
        let snap = m.snapshot();
        assert_eq!(snap.commands[0].name, "get"); // tied with mem_get, sorts first by name
        assert_eq!(snap.commands[1].name, "mem_get");
        assert_eq!(snap.commands[2].name, "ping");
    }

    #[test]
    fn empty_metrics_yields_empty_snapshot() {
        let m = fresh_metrics();
        let snap = m.snapshot();
        assert_eq!(snap.total_calls, 0);
        assert_eq!(snap.total_errors, 0);
        assert!(snap.commands.is_empty());
    }
}
