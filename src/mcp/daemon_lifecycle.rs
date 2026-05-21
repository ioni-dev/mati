//! Daemon-readiness lifecycle helpers shared by hook and MCP code paths.
//!
//! `ensure_daemon` probes the daemon over its socket and, if absent or
//! unresponsive, spawns a new `mati daemon start` subprocess and polls for
//! readiness. It is the canonical auto-spawn implementation — both the
//! binary-crate hook adapter (`cli::hook_decide`) and the MCP socket-backed
//! proxy paths (`mcp::server::proxy_daemon_result` / `proxy_daemon_v2`) call
//! through here so the recovery semantics can never drift between the two.
//!
//! Recovery strategy mirrors `cli::hook_decide::ensure_daemon` (pre-pass-33,
//! when this function lived bin-side):
//!   - `Ok` → daemon is healthy, return immediately.
//!   - `NotRunning` / `StaleSocket` → spawn daemon, poll for readiness.
//!   - `Unresponsive` → wait 300ms, re-probe; if still unresponsive,
//!     SIGTERM the stale PID + force-cleanup and spawn fresh. The SIGTERM
//!     is critical: without it the old process holds the exclusive
//!     SurrealKV Store lock and the new spawn deadlocks on `Store::open()`.
//!
//! Phase 2 sentinel: the daemon writes `mati.starting` before acquiring the
//! Store lock. If another hook spawned a daemon within the last 5 seconds,
//! poll for readiness instead of spawning a competitor.
//!
//! Readiness is **state-aware**, not timer-driven. The daemon emits
//! `startup phase=*` and `migration phase=*` events into `lifecycle.log`
//! as it traverses its cold-start sequence. `wait_for_ready` tails that
//! log and:
//!   - returns `Ready` as soon as `startup phase=ready` lands + a ping
//!     succeeds (typical cold start: <300ms)
//!   - returns `Failed` immediately when `serve_failed` is observed
//!   - returns `Wedged` if no new event has landed for `wedge_threshold`
//!     (default 15s) — useful when migration or repair has hung
//!   - returns `HardCap` if the absolute `hard_cap` (default 60s) elapses
//!     even with continuing event activity (pathological cases like a
//!     truly enormous store migration)
//!
//! The state-aware design is necessary because the v2 schema migration
//! framework (and any future long-running startup work) can legitimately
//! delay daemon readiness by seconds. A pure timer-based poll either
//! short-cuts a slow-but-healthy startup (false negative → caller bypasses
//! enforcement) or waits forever on a wedged daemon (false positive →
//! UI hangs). Reading the lifecycle log distinguishes the two cleanly.
//!
//! Test escape hatch: setting `MATI_DISABLE_AUTO_SPAWN=1` skips Phase 3
//! (subprocess spawn) while still running the probe + Phase 2 sentinel
//! polling. This keeps unit tests that depend on `NotRunning` propagation
//! deterministic without requiring per-test mocks. `wait_for_ready` itself
//! is a pure tail-reader and is tested independently of any subprocess.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::server::{proxy_daemon_result_no_spawn, ProxyDaemonResult};

// ─── Readiness state machine ────────────────────────────────────────────────

/// Hard upper bound on `wait_for_ready` — even with continuous event
/// activity, give up after this long. Sized to cover a worst-case schema
/// migration on a large store (snapshot + scan-rewrite of every gotcha)
/// with comfortable headroom.
pub(crate) const READINESS_HARD_CAP: Duration = Duration::from_secs(60);

/// If `lifecycle.log` stops growing for this long (no new events), the
/// daemon is considered wedged. Sized to be safely longer than any
/// individual phase's expected duration — a healthy startup emits at
/// least one new event every few hundred ms during migration.
pub(crate) const READINESS_WEDGE_THRESHOLD: Duration = Duration::from_secs(15);

/// Polling interval for the readiness loop. Sized to keep steady-state
/// cold-start latency near the lower bound (50ms tick × 1–5 ticks for
/// a no-migration cold start = <300ms total) while imposing negligible
/// CPU cost during long waits.
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Outcome of `wait_for_ready`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadinessOutcome {
    /// Daemon emitted `startup phase=ready` and a ping confirmed reachability.
    Ready,
    /// Daemon emitted `serve_failed` — startup aborted. The reason string is
    /// the lifecycle event's `detail` field.
    Failed(String),
    /// `lifecycle.log` stopped emitting new events for at least
    /// `READINESS_WEDGE_THRESHOLD`. The last observed phase is included
    /// so callers (and users) can see *where* the daemon is stuck.
    Wedged { last_phase: String, since: Duration },
    /// Absolute `hard_cap` elapsed before any terminal state. The most
    /// recent phase is included so the failure is diagnosable in the wild.
    HardCap { last_phase: String },
}

/// A single parsed line from `lifecycle.log`.
///
/// Format on disk: `unix_ts<TAB>pid<TAB>event<TAB>detail<NL>`. Detail is
/// freeform but startup/migration events follow `phase=X key=val ...`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LifecycleEvent {
    #[allow(dead_code)] // retained for future diagnostic use
    ts: u64,
    #[allow(dead_code)]
    pid: u32,
    event: String,
    detail: String,
}

impl LifecycleEvent {
    /// Extract `phase=X` from `detail`, if present. Returns the bare value
    /// (no `phase=` prefix). Used to compare progress across events.
    fn phase(&self) -> Option<&str> {
        self.detail
            .split(' ')
            .find_map(|tok| tok.strip_prefix("phase="))
    }
}

/// Parse one line of `lifecycle.log` into an event. Returns `None` on any
/// malformed line — the caller treats unparseable lines as missing data so
/// a corrupted log can never panic the readiness loop.
fn parse_lifecycle_line(line: &str) -> Option<LifecycleEvent> {
    let mut parts = line.splitn(4, '\t');
    let ts: u64 = parts.next()?.parse().ok()?;
    let pid: u32 = parts.next()?.parse().ok()?;
    let event = parts.next()?.to_string();
    let detail = parts.next().unwrap_or("").to_string();
    Some(LifecycleEvent {
        ts,
        pid,
        event,
        detail,
    })
}

/// Incremental tailing of `lifecycle.log`. Each `poll` returns events that
/// have been appended since the previous call. Robust to file rotation,
/// truncation, and absence — all of which surface as "no new events".
struct LifecycleTail {
    path: PathBuf,
    offset: u64,
}

impl LifecycleTail {
    /// Open a tail starting at the *current* end-of-file. Pre-existing
    /// events are ignored — we only care about events emitted during *this*
    /// startup attempt. If the file doesn't exist yet, start at offset 0
    /// so the first daemon write is picked up immediately.
    fn opened_at_end(mati_root: &Path) -> Self {
        let path = mati_root.join("lifecycle.log");
        let offset = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Self { path, offset }
    }

    /// Read newly-appended complete lines. Partial trailing lines (no
    /// `\n` yet) are left for the next poll. Returns an empty vec if no
    /// new complete lines are available (file missing, no growth, etc.).
    fn poll(&mut self) -> Vec<LifecycleEvent> {
        let Ok(mut file) = std::fs::File::open(&self.path) else {
            return Vec::new();
        };
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        if len < self.offset {
            // File was truncated or rotated underneath us. Reset to the
            // new end so we don't reread historical data as if it were new.
            self.offset = len;
            return Vec::new();
        }
        if len == self.offset {
            return Vec::new();
        }
        if file.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }
        let to_read = len - self.offset;
        let mut buf = Vec::with_capacity(to_read as usize);
        if (&mut file).take(to_read).read_to_end(&mut buf).is_err() {
            return Vec::new();
        }
        // Only consume complete lines (those ending with `\n`). A partial
        // trailing line (concurrent appender hasn't finished its write) is
        // left for the next poll. PIPE_BUF + O_APPEND guarantees each
        // emitter's write is atomic, so partial-line interleaving doesn't
        // occur in practice — this is defense-in-depth.
        let s = String::from_utf8_lossy(&buf);
        let mut events = Vec::new();
        let mut consumed = 0usize;
        for line in s.split_inclusive('\n') {
            if !line.ends_with('\n') {
                break;
            }
            consumed += line.len();
            let stripped = line.strip_suffix('\n').unwrap_or(line);
            if let Some(ev) = parse_lifecycle_line(stripped) {
                events.push(ev);
            }
        }
        self.offset += consumed as u64;
        events
    }
}

/// State-aware readiness wait. Tails `lifecycle.log` and applies the
/// state machine documented at module top.
///
/// This is the canonical readiness primitive — `ensure_daemon`'s Phase 2
/// (peer already starting) and Phase 4 (we just spawned) both call here.
/// Independently testable: a unit test can hand-write `lifecycle.log` to
/// simulate any daemon-side state without spawning a real subprocess.
pub(crate) async fn wait_for_ready(
    mati_root: &Path,
    hard_cap: Duration,
    wedge_threshold: Duration,
) -> ReadinessOutcome {
    let started_at = Instant::now();
    let mut last_progress_at = started_at;
    let mut tail = LifecycleTail::opened_at_end(mati_root);
    let mut last_phase = String::from("spawned");

    loop {
        if started_at.elapsed() >= hard_cap {
            return ReadinessOutcome::HardCap { last_phase };
        }

        tokio::time::sleep(READINESS_POLL_INTERVAL).await;

        let new_events = tail.poll();
        if !new_events.is_empty() {
            last_progress_at = Instant::now();
            for ev in &new_events {
                if ev.event == "serve_failed" {
                    return ReadinessOutcome::Failed(ev.detail.clone());
                }
                if let Some(p) = ev.phase() {
                    last_phase = p.to_string();
                }
                // `startup phase=ready` is the success signal — but require
                // an actual ping to confirm the socket is bound and
                // answering, not just that the event was emitted.
                if ev.event == "startup" && ev.phase() == Some("ready") {
                    if matches!(
                        proxy_daemon_result_no_spawn(mati_root, "ping", &serde_json::json!({}))
                            .await,
                        ProxyDaemonResult::Ok(_)
                    ) {
                        return ReadinessOutcome::Ready;
                    }
                    // Event landed but ping not yet succeeding — keep
                    // polling. This window is typically <50ms (event is
                    // emitted just before the accept loop begins).
                }
            }
        }

        // Fallback: if no lifecycle events are landing but a ping happens
        // to work anyway, accept that as ready. Covers the case where the
        // daemon is from a *previous* mati version that doesn't emit
        // `startup phase=ready` (forwards-compat). Also covers daemons
        // running on filesystems where lifecycle.log is unwritable.
        if matches!(
            proxy_daemon_result_no_spawn(mati_root, "ping", &serde_json::json!({})).await,
            ProxyDaemonResult::Ok(_)
        ) {
            return ReadinessOutcome::Ready;
        }

        if last_progress_at.elapsed() >= wedge_threshold {
            return ReadinessOutcome::Wedged {
                last_phase,
                since: last_progress_at.elapsed(),
            };
        }
    }
}

/// Ensure the daemon is reachable. Auto-starts if needed.
///
/// Returns `true` if the daemon responds to a `ping` by the end of the
/// readiness poll. Returns `false` if the daemon could not be reached
/// after spawn + retry.
///
/// Calling this from `proxy_daemon_result` / `proxy_daemon_v2` makes the
/// MCP socket-backed paths self-healing across `mati daemon stop` cycles
/// — previously a stop during init/repair left every subsequent MCP tool
/// call returning `{"error":"<op>: daemon not running"}` until the user
/// manually restarted.
pub async fn ensure_daemon(mati_root: &Path) -> bool {
    // Phase 1: probe current state.
    match proxy_daemon_result_no_spawn(mati_root, "ping", &serde_json::json!({})).await {
        ProxyDaemonResult::Ok(_) => return true,
        ProxyDaemonResult::NotRunning | ProxyDaemonResult::StaleSocket => {}
        ProxyDaemonResult::Unresponsive => {
            // Socket exists + PID alive, but can't connect. Could be:
            //   (a) daemon mid-startup (PID written, socket not yet bound)
            //   (b) recycled PID after MCP crash — stale, safe to clean up
            //   (c) genuinely hung process
            // Wait 300ms to cover (a), then re-probe.
            tokio::time::sleep(Duration::from_millis(300)).await;
            match proxy_daemon_result_no_spawn(mati_root, "ping", &serde_json::json!({})).await {
                ProxyDaemonResult::Ok(_) => return true,
                ProxyDaemonResult::NotRunning | ProxyDaemonResult::StaleSocket => {
                    // proxy_daemon_result cleaned up stale files — fall through to spawn.
                }
                ProxyDaemonResult::Unresponsive => {
                    // Still unresponsive after 300ms. The PID is alive but not
                    // serving our socket — most likely a stale daemon running
                    // an old protocol version, or a recycled PID.
                    //
                    // Use the shared `kill_and_wait` helper so the
                    // synchronous-exit guarantee is identical to
                    // `mati daemon stop`'s kill flow. Without that
                    // guarantee, the old daemon could still hold the
                    // exclusive SurrealKV Store lock when our new spawn
                    // calls `Store::open()` — a deadlock.
                    //
                    // 2s budget: well within the 3000ms hook timeout
                    // (Phase 4 readiness poll adds ~800ms; 2s here keeps
                    // total recovery latency under the ceiling).
                    let stale_pid = super::metadata::read_metadata(mati_root).map(|m| m.pid);
                    if let Some(pid) = stale_pid {
                        let _ = super::metadata::kill_and_wait(pid, Duration::from_secs(2)).await;
                    }
                    let _ = std::fs::remove_file(super::metadata::socket_path(mati_root));
                    let _ = std::fs::remove_file(mati_root.join("mati.pid"));
                }
            }
        }
    }

    // Phase 2: check if another process is already starting the daemon.
    // The daemon writes `mati.starting` before acquiring the Store lock.
    // If another hook already spawned a daemon within the last 5 seconds,
    // wait for it via the state-aware readiness machine instead of
    // spawning a competing instance (which would block on the exclusive
    // Store lock and waste time).
    let starting = mati_root.join("mati.starting");
    if starting.exists() {
        if let Ok(meta) = starting.metadata() {
            if let Ok(modified) = meta.modified() {
                if modified.elapsed().unwrap_or_default() < Duration::from_secs(5) {
                    // Bounded wait: peer is mid-spawn, so the migration
                    // may already be running. Use the full state-aware
                    // budget so a slow migration doesn't cause us to
                    // fall through and start a competing daemon.
                    match wait_for_ready(mati_root, READINESS_HARD_CAP, READINESS_WEDGE_THRESHOLD)
                        .await
                    {
                        ReadinessOutcome::Ready => return true,
                        // Other terminal states fall through to our own spawn
                        // — the peer that wrote the sentinel didn't finish.
                        _ => {}
                    }
                }
            }
        }
    }

    // Test escape hatch: skip the subprocess spawn so unit tests that
    // assert `NotRunning` propagation remain deterministic. Production
    // code paths never set this env var.
    //
    // `cfg!(test)` also short-circuits here so `cargo test --lib` does not
    // need the env var set — otherwise hundreds of unit tests would each
    // spawn a `mati daemon start` subprocess via `current_exe()`, swamping
    // macOS `fseventsd`/`logd` and threatening a kernel watchdog reset.
    if cfg!(test) || std::env::var_os("MATI_DISABLE_AUTO_SPAWN").is_some() {
        return false;
    }

    // Phase 3: spawn daemon.
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return false,
    };

    // Capture stderr to a log file so startup failures are diagnosable.
    let stderr_target = dirs::home_dir()
        .map(|h| h.join(".mati").join("daemon_start.log"))
        .and_then(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
                .ok()
        })
        .map(std::process::Stdio::from)
        .unwrap_or_else(std::process::Stdio::null);

    let _ = std::process::Command::new(&exe)
        .args(["daemon", "start"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(stderr_target)
        .spawn();

    // Phase 4: state-aware readiness wait. Tail `lifecycle.log` for the
    // daemon's `startup phase=ready` event (with ping confirmation) or
    // for a terminal failure / wedge signal. See `wait_for_ready` and
    // the module-level docs for the state machine.
    match wait_for_ready(mati_root, READINESS_HARD_CAP, READINESS_WEDGE_THRESHOLD).await {
        ReadinessOutcome::Ready => true,
        ReadinessOutcome::Failed(_)
        | ReadinessOutcome::Wedged { .. }
        | ReadinessOutcome::HardCap { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::metadata::{publish_metadata, DaemonMetadata, DaemonOwner};
    use crate::mcp::server::proxy_daemon_result;

    /// When the daemon is already running and answers ping, return true fast.
    ///
    /// We bind a real Unix socket inside the tempdir, publish metadata, and
    /// arrange a minimal accept loop that responds with a v2-shaped `ok`
    /// envelope. `proxy_daemon_result` should accept it and `ensure_daemon`
    /// should short-circuit at Phase 1 without ever spawning.
    #[tokio::test]
    async fn ensure_daemon_returns_true_when_daemon_already_running() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();

        // Publish metadata pointing at THIS process's PID — guaranteed alive.
        let mut meta = DaemonMetadata::new(DaemonOwner::Daemon);
        meta.pid = std::process::id();
        publish_metadata(&root, &meta).unwrap();
        let session = meta.session;

        // Stand up a tiny ping-responder on the daemon socket.
        let sock_path = root.join("mati.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let server_handle = tokio::spawn(async move {
            // One connection is enough — Phase 1 probe.
            if let Ok((stream, _)) = listener.accept().await {
                let (reader, mut writer) = stream.into_split();
                let mut br = BufReader::new(reader);
                let mut line = String::new();
                let _ = br.read_line(&mut line).await;
                let resp = serde_json::json!({
                    "v": 2,
                    "id": uuid::Uuid::new_v4(),
                    "session": session,
                    "status": "ok",
                    "data": { "pong": true }
                });
                let mut bytes = serde_json::to_vec(&resp).unwrap();
                bytes.push(b'\n');
                let _ = writer.write_all(&bytes).await;
                let _ = writer.shutdown().await;
            }
        });

        // No spawn needed — the existing socket should respond.
        std::env::set_var("MATI_DISABLE_AUTO_SPAWN", "1");
        let result = ensure_daemon(&root).await;
        std::env::remove_var("MATI_DISABLE_AUTO_SPAWN");

        let _ = server_handle.await;
        assert!(result, "ensure_daemon must return true when ping succeeds");
    }

    /// When no daemon is running and auto-spawn is disabled, ensure_daemon
    /// must return false cleanly without panicking. Exercises Phases 1 and 2.
    #[tokio::test]
    async fn ensure_daemon_returns_false_when_spawn_disabled_and_no_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        std::env::set_var("MATI_DISABLE_AUTO_SPAWN", "1");
        let result = ensure_daemon(dir.path()).await;
        std::env::remove_var("MATI_DISABLE_AUTO_SPAWN");
        assert!(
            !result,
            "ensure_daemon must return false when no daemon is running and spawn is disabled"
        );
    }

    /// Regression: `proxy_daemon_result` with a persistent NotRunning state
    /// must surface NotRunning to the caller (via the auto-spawn path failing
    /// cleanly when MATI_DISABLE_AUTO_SPAWN suppresses Phase 3). Pinned so a
    /// future change that swallows or mutates the failure mode is caught.
    ///
    /// This is the structural test that would have caught the smoke 55/115
    /// regression: before the auto-spawn wiring, every MCP call after a
    /// `mati daemon stop` cycle returned `{"error":"<op>: daemon not running"}`
    /// instead of recovering.
    #[tokio::test]
    async fn proxy_daemon_result_invokes_ensure_daemon_on_persistent_notrunning() {
        let dir = tempfile::TempDir::new().unwrap();
        std::env::set_var("MATI_DISABLE_AUTO_SPAWN", "1");
        let result = proxy_daemon_result(dir.path(), "ping", serde_json::json!({})).await;
        std::env::remove_var("MATI_DISABLE_AUTO_SPAWN");
        assert!(
            matches!(result, ProxyDaemonResult::NotRunning),
            "proxy_daemon_result must return NotRunning when daemon absent and spawn disabled, got {result:?}"
        );
    }

    // ─── Lifecycle event parser ───────────────────────────────────────────────

    #[test]
    fn parse_lifecycle_line_extracts_all_fields() {
        let line = "1234567890\t42\tstartup\tphase=ready elapsed_ms=120";
        let ev = parse_lifecycle_line(line).expect("must parse");
        assert_eq!(ev.ts, 1234567890);
        assert_eq!(ev.pid, 42);
        assert_eq!(ev.event, "startup");
        assert_eq!(ev.detail, "phase=ready elapsed_ms=120");
        assert_eq!(ev.phase(), Some("ready"));
    }

    #[test]
    fn parse_lifecycle_line_tolerates_empty_detail() {
        // The lifecycle log can emit events with no detail (e.g. some legacy
        // emitters). The parser must accept this and not panic.
        let line = "1\t2\tserve_start\t";
        let ev = parse_lifecycle_line(line).expect("must parse with empty detail");
        assert_eq!(ev.event, "serve_start");
        assert_eq!(ev.detail, "");
        assert_eq!(ev.phase(), None);
    }

    #[test]
    fn parse_lifecycle_line_returns_none_on_malformed() {
        // Defense-in-depth: a corrupted log line must not panic the readiness
        // loop. Each malformed shape must yield `None`, never a partial parse.
        assert!(parse_lifecycle_line("garbage with no tabs").is_none());
        assert!(parse_lifecycle_line("not-a-number\t42\tevent\tdetail").is_none());
        assert!(parse_lifecycle_line("123\tnot-a-pid\tevent\tdetail").is_none());
        assert!(parse_lifecycle_line("").is_none());
    }

    #[test]
    fn phase_extracts_value_from_complex_detail() {
        // Detail may contain multiple `key=value` tokens. `phase()` must
        // surface the `phase=` token regardless of position.
        let ev = LifecycleEvent {
            ts: 0,
            pid: 0,
            event: "migration".into(),
            detail: "phase=apply_complete version=2 records_migrated=14 elapsed_ms=820".into(),
        };
        assert_eq!(ev.phase(), Some("apply_complete"));
    }

    #[test]
    fn phase_returns_none_when_no_phase_token() {
        let ev = LifecycleEvent {
            ts: 0,
            pid: 0,
            event: "serve_start".into(),
            detail: "pid=123 owner=daemon".into(),
        };
        assert_eq!(ev.phase(), None);
    }

    // ─── LifecycleTail ────────────────────────────────────────────────────────

    /// Helper: atomically append one event line to `lifecycle.log` under
    /// `root`. Mirrors `record_lifecycle_event`'s format precisely so tests
    /// drive the same parser the production path uses.
    fn write_event(root: &Path, event: &str, detail: &str) {
        use std::io::Write;
        let path = root.join("lifecycle.log");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("open lifecycle.log");
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let pid = std::process::id();
        writeln!(f, "{ts}\t{pid}\t{event}\t{detail}").expect("write event");
    }

    #[test]
    fn tail_opened_at_end_skips_pre_existing_events() {
        // `opened_at_end` must start past historical events. Tests
        // restarts and re-spawns: we only care about events from THIS
        // startup attempt, never previous ones.
        let dir = tempfile::TempDir::new().unwrap();
        write_event(dir.path(), "serve_start", "old=event");
        write_event(dir.path(), "serve_shutdown", "old=event");

        let mut tail = LifecycleTail::opened_at_end(dir.path());
        let evs = tail.poll();
        assert!(
            evs.is_empty(),
            "pre-existing events must not be replayed, got {evs:?}"
        );
    }

    #[test]
    fn tail_picks_up_events_appended_after_open() {
        let dir = tempfile::TempDir::new().unwrap();
        write_event(dir.path(), "serve_start", "older=event");

        let mut tail = LifecycleTail::opened_at_end(dir.path());
        write_event(dir.path(), "startup", "phase=opening_store");
        write_event(dir.path(), "startup", "phase=ready elapsed_ms=210");

        let evs = tail.poll();
        assert_eq!(evs.len(), 2, "must see both new events, got {evs:?}");
        assert_eq!(evs[0].event, "startup");
        assert_eq!(evs[0].phase(), Some("opening_store"));
        assert_eq!(evs[1].phase(), Some("ready"));
    }

    #[test]
    fn tail_handles_missing_file_gracefully() {
        // A daemon may not have written its first event yet. `poll` must
        // return an empty vec — never panic, never error.
        let dir = tempfile::TempDir::new().unwrap();
        let mut tail = LifecycleTail::opened_at_end(dir.path());
        assert!(tail.poll().is_empty());
        // And once the file appears mid-wait, the next poll picks up events.
        write_event(dir.path(), "startup", "phase=ready elapsed_ms=42");
        let evs = tail.poll();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].phase(), Some("ready"));
    }

    #[test]
    fn tail_resets_offset_on_truncation() {
        // Mirrors what would happen if an operator manually wiped
        // lifecycle.log or it got rotated mid-wait. We must NOT
        // double-read content nor panic — just resync to the new end.
        let dir = tempfile::TempDir::new().unwrap();
        write_event(dir.path(), "startup", "phase=opening_store");
        write_event(dir.path(), "startup", "phase=ready elapsed_ms=100");
        let mut tail = LifecycleTail::opened_at_end(dir.path());

        // Truncate underneath us.
        std::fs::write(dir.path().join("lifecycle.log"), b"").unwrap();
        let evs = tail.poll();
        assert!(
            evs.is_empty(),
            "first poll after truncation must yield no events"
        );

        // Subsequent appends are picked up against the reset offset.
        write_event(dir.path(), "startup", "phase=ready elapsed_ms=55");
        let evs = tail.poll();
        assert_eq!(evs.len(), 1, "must see new events after truncation reset");
    }

    // ─── wait_for_ready state machine ─────────────────────────────────────────

    /// Spin up a tiny ping-responder bound on the daemon socket inside
    /// `root` so `wait_for_ready`'s ping confirmation succeeds. Returns the
    /// JoinHandle; drop it to let the listener tear down.
    async fn spawn_ping_responder(root: &Path) -> tokio::task::JoinHandle<()> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        // Match the production socket layout — `proxy_daemon_result_no_spawn`
        // also requires `mati.pid` so the metadata-PID liveness check passes.
        let mut meta = DaemonMetadata::new(DaemonOwner::Daemon);
        meta.pid = std::process::id();
        publish_metadata(root, &meta).unwrap();
        let session = meta.session;

        let sock_path = root.join("mati.sock");
        let _ = std::fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path).expect("bind responder");
        tokio::spawn(async move {
            // Loop so the responder survives multiple readiness ping attempts
            // (wait_for_ready also pings on every iteration as forwards-compat).
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let session = session;
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut br = BufReader::new(reader);
                    let mut line = String::new();
                    let _ = br.read_line(&mut line).await;
                    let resp = serde_json::json!({
                        "v": 2,
                        "id": uuid::Uuid::new_v4(),
                        "session": session,
                        "status": "ok",
                        "data": { "pong": true }
                    });
                    let mut bytes = serde_json::to_vec(&resp).unwrap();
                    bytes.push(b'\n');
                    let _ = writer.write_all(&bytes).await;
                    let _ = writer.shutdown().await;
                });
            }
        })
    }

    #[tokio::test]
    async fn wait_for_ready_returns_ready_when_startup_phase_ready_lands_and_ping_ok() {
        // Happy path: daemon emits the full startup sequence including
        // `startup phase=ready` and its socket answers ping. Must return
        // `Ready` and do so promptly (well under the 5s test hard cap).
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        let responder = spawn_ping_responder(&root).await;

        let emitter_root = root.clone();
        let emitter = tokio::spawn(async move {
            // Stagger the events to simulate a real cold start. Each tick
            // gives wait_for_ready a chance to observe forward progress.
            tokio::time::sleep(Duration::from_millis(30)).await;
            write_event(&emitter_root, "startup", "phase=opening_store");
            tokio::time::sleep(Duration::from_millis(30)).await;
            write_event(&emitter_root, "startup", "phase=store_opened elapsed_ms=20");
            tokio::time::sleep(Duration::from_millis(30)).await;
            write_event(&emitter_root, "startup", "phase=ready elapsed_ms=90");
        });

        let start = Instant::now();
        let outcome = wait_for_ready(&root, Duration::from_secs(5), Duration::from_secs(2)).await;
        let elapsed = start.elapsed();

        let _ = emitter.await;
        responder.abort();
        assert_eq!(outcome, ReadinessOutcome::Ready);
        assert!(
            elapsed < Duration::from_secs(1),
            "happy-path readiness must complete in <1s, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn wait_for_ready_returns_failed_immediately_on_serve_failed_event() {
        // If the daemon emits a terminal failure, we must surface it
        // instantly — never silently wait for the hard cap.
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();

        let emitter_root = root.clone();
        let emitter = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            write_event(&emitter_root, "startup", "phase=opening_store");
            tokio::time::sleep(Duration::from_millis(30)).await;
            write_event(&emitter_root, "serve_failed", "store open: lock contention");
        });

        let start = Instant::now();
        let outcome = wait_for_ready(&root, Duration::from_secs(10), Duration::from_secs(5)).await;
        let elapsed = start.elapsed();
        let _ = emitter.await;

        match outcome {
            ReadinessOutcome::Failed(detail) => {
                assert!(
                    detail.contains("lock contention"),
                    "failure detail must surface the daemon's reason, got {detail:?}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(
            elapsed < Duration::from_secs(2),
            "Failed must surface quickly, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn wait_for_ready_returns_wedged_when_no_events_change_within_threshold() {
        // Simulates a hung migration: daemon writes one phase event then
        // never another. wait_for_ready must return `Wedged` once the
        // configured wedge threshold elapses, well before the hard cap.
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();

        let emitter_root = root.clone();
        let emitter = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            write_event(&emitter_root, "migration", "phase=apply_begin version=2");
            // Then silence — simulating a wedged migration body.
        });

        let start = Instant::now();
        let outcome = wait_for_ready(
            &root,
            Duration::from_secs(10),    // hard cap
            Duration::from_millis(200), // wedge threshold (short for test)
        )
        .await;
        let elapsed = start.elapsed();
        let _ = emitter.await;

        match outcome {
            ReadinessOutcome::Wedged { last_phase, since } => {
                assert_eq!(last_phase, "apply_begin");
                assert!(
                    since >= Duration::from_millis(200),
                    "wedge `since` must be at least the threshold, got {since:?}"
                );
            }
            other => panic!("expected Wedged, got {other:?}"),
        }
        assert!(
            elapsed < Duration::from_secs(2),
            "wedge detection must fire near the wedge threshold, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn wait_for_ready_returns_hard_cap_when_progress_never_signals_ready() {
        // Pathological case: daemon keeps making progress (events keep
        // landing so wedge-detection won't fire) but never emits
        // `startup phase=ready`. wait_for_ready must enforce the
        // absolute hard cap as the last line of defense.
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();

        let emitter_root = root.clone();
        let emitter = tokio::spawn(async move {
            // Emit a fresh event every 30ms — keeps wedge-detection at bay.
            for i in 0..50 {
                tokio::time::sleep(Duration::from_millis(30)).await;
                write_event(
                    &emitter_root,
                    "migration",
                    &format!("phase=apply_progress version=2 records_seen={i}"),
                );
            }
        });

        let start = Instant::now();
        let outcome = wait_for_ready(
            &root,
            Duration::from_millis(250), // hard cap (short for test)
            Duration::from_secs(10),    // wedge threshold (won't fire)
        )
        .await;
        let elapsed = start.elapsed();
        emitter.abort();
        let _ = emitter.await;

        match outcome {
            ReadinessOutcome::HardCap { last_phase } => {
                assert_eq!(
                    last_phase, "apply_progress",
                    "hard-cap outcome must report the most recent phase"
                );
            }
            other => panic!("expected HardCap, got {other:?}"),
        }
        assert!(
            elapsed >= Duration::from_millis(250),
            "hard-cap must elapse before firing, got {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "hard-cap must fire near the cap, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn wait_for_ready_accepts_ping_ok_without_any_lifecycle_events() {
        // Forwards-compat: an older daemon (pre-state-aware-readiness)
        // never emits `startup phase=ready`, but its socket answers ping
        // anyway. wait_for_ready must accept that as ready instead of
        // hanging until the hard cap.
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        let responder = spawn_ping_responder(&root).await;

        let start = Instant::now();
        let outcome = wait_for_ready(&root, Duration::from_secs(5), Duration::from_secs(2)).await;
        let elapsed = start.elapsed();
        responder.abort();

        assert_eq!(outcome, ReadinessOutcome::Ready);
        assert!(
            elapsed < Duration::from_millis(500),
            "ping-fallback readiness must complete near-instantly, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn wait_for_ready_tolerates_corrupted_lifecycle_lines() {
        // A garbled lifecycle.log (binary garbage, partial writes from a
        // different process, etc.) must not crash the readiness loop.
        // The expected behavior: malformed lines are silently dropped,
        // and the wedge timer trips because no valid events were seen.
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();

        // Write garbage directly — bypassing write_event so the lines are
        // intentionally unparseable.
        use std::io::Write;
        let path = root.join("lifecycle.log");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(f, "definitely not a real lifecycle line").unwrap();
        writeln!(f, "\t\t\t").unwrap();
        writeln!(f, "abc\tdef\tghi\tjkl").unwrap();

        let start = Instant::now();
        let outcome =
            wait_for_ready(&root, Duration::from_secs(5), Duration::from_millis(200)).await;
        let elapsed = start.elapsed();

        // Garbled events count as "no forward progress" — wedge timer fires.
        assert!(
            matches!(outcome, ReadinessOutcome::Wedged { .. }),
            "corrupted events must surface as Wedged, got {outcome:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "wedge under garbage must fire near threshold, took {elapsed:?}"
        );
    }
}
