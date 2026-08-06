use super::*;

// ── Daemon socket — hook script bridge ───────────────────────────────────────

/// Unix domain socket path length limit (macOS-compatible).
///
/// Public so the parallel daemon path in `cli::daemon` shares the same
/// value — preventing one path's bound from drifting from the other's.
pub const UNIX_SOCK_PATH_MAX: usize = 104;

/// Max wait for a complete request line per connection.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum number of daemon-socket connections handled concurrently.
///
/// A flood beyond this limit blocks at `accept` (TCP backlog absorbs the
/// surplus); this gives natural backpressure rather than unbounded memory
/// use. 64 is generous for a per-user daemon — typical hook traffic is
/// O(1) concurrent. Public so `cli::daemon` shares the same bound.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Maximum time the boot-time auto-drain (dirty-marker queue) can run
/// before we give up and proceed to serve. Prevents a pathological dirty
/// queue from blocking daemon startup. The dirty marker stays set; the
/// user can run `mati repair` manually.
///
/// Public so `cli::daemon::run_daemon_start` can share the same ceiling.
pub const AUTO_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Race-free shutdown signal for daemon-socket loops.
///
/// `signal()` is idempotent and `wait()` resolves immediately if the signal
/// has already fired. The `enable()` pattern on `Notify::notified()`
/// registers the future before the flag check, so a `signal()` race between
/// flag-set and notify-fire cannot strand a waiter.
///
/// Shared with `cli::daemon` so both the embedded MCP-server socket loop
/// and the headless `mati daemon start` loop use identical shutdown
/// semantics.
#[derive(Default)]
pub struct Shutdown {
    flag: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl Shutdown {
    pub fn new() -> Self {
        Self::default()
    }

    /// Idempotent — safe to call multiple times. Wakes every active waiter.
    pub fn signal(&self) {
        self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub fn is_set(&self) -> bool {
        // SeqCst (matching the store): defense-in-depth correctness on
        // weakly-ordered architectures (ARM/POWER). Without it, the load
        // would rely on Notify's internal mutex acquire to synchronize
        // with `signal()`'s store — which is the pattern in our `wait()`
        // body and works in practice, but depends on Notify's
        // implementation detail. Explicit SC pairing is cheap (one
        // memory barrier at most) and removes the implicit dependency.
        self.flag.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Future resolves once `signal()` has been called. Safe to call
    /// repeatedly; safe to race with concurrent `signal()`.
    pub async fn wait(&self) {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        // Register the receiver BEFORE the flag check so a `signal()` that
        // fires between check and notify cannot be missed.
        notified.as_mut().enable();
        if self.is_set() {
            return;
        }
        notified.await;
    }
}

/// Daemon protocol version (must match `cli::daemon::PROTOCOL_VERSION`).
pub(super) const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
pub(crate) struct SocketRequest {
    pub cmd: String,
    #[allow(dead_code)] // Wire protocol field — must exist for deserialization
    #[serde(default, rename = "v")]
    pub version: Option<u32>,
    #[serde(default)]
    pub args: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct SocketResponse {
    pub(crate) ok: bool,
    #[serde(rename = "v")]
    version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

impl SocketResponse {
    pub(crate) fn ok(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            version: PROTOCOL_VERSION,
            data: Some(data),
            error: None,
        }
    }
    pub(crate) fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            version: PROTOCOL_VERSION,
            data: None,
            error: Some(msg.into()),
        }
    }
}

pub async fn socket_handle_connection(
    graph: Arc<tokio::sync::RwLock<Graph>>,
    policy_matcher: Arc<tokio::sync::RwLock<crate::hooks::policy_match::PolicyMatcherSet>>,
    repo_root: &Path,
    stream: UnixStream,
    peer: super::metadata::PeerContext,
    daemon_session: uuid::Uuid,
) -> Result<()> {
    use super::protocol::MAX_FRAME_SIZE;
    use tokio::io::AsyncReadExt;

    let (reader, mut writer) = stream.into_split();
    let mut buf = String::new();

    // Cap the read at MAX_FRAME_SIZE + 1 bytes so the allocation is bounded
    // before any JSON parsing occurs. If the client sends more data than
    // MAX_FRAME_SIZE before the newline delimiter, `read_line` will stop at
    // the take limit and the size check below will reject the request.
    let limited = reader.take(MAX_FRAME_SIZE as u64 + 1);
    let mut buf_reader = BufReader::new(limited);
    match tokio::time::timeout(READ_TIMEOUT, buf_reader.read_line(&mut buf)).await {
        Ok(Ok(0)) => return Ok(()),
        Ok(Ok(_)) => {}
        Ok(Err(e)) => anyhow::bail!("read error: {e}"),
        Err(_) => anyhow::bail!("read timeout"),
    }

    if buf.len() > MAX_FRAME_SIZE {
        let resp = super::protocol::Response::err(
            uuid::Uuid::nil(),
            super::protocol::ErrorCode::FrameTooLarge,
            format!("request exceeds {MAX_FRAME_SIZE} byte limit"),
        );
        let json = serde_json::to_string(&resp)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        return Ok(());
    }

    let trimmed = buf.trim();

    // V2 protocol ONLY — no v1 fallback on the public wire.
    // The v2 format requires `id` (UUID), `session` (UUID), and `cmd` as
    // a tagged object with `type`. If decode fails, the request is rejected
    // with a protocol error — there is no legacy v1 dispatch path.
    let v2_req = match serde_json::from_str::<super::protocol::Request>(trimmed) {
        Ok(r) => r,
        Err(e) => {
            // Return a v2-shaped error. Use nil UUID since we can't extract
            // the request ID from a malformed payload.
            let resp = super::protocol::Response::err(
                uuid::Uuid::nil(),
                super::protocol::ErrorCode::MalformedRequest,
                format!("invalid v2 request: {e}"),
            );
            let json = serde_json::to_string(&resp)?;
            writer.write_all(json.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            return Ok(());
        }
    };

    let ctx = super::dispatch_v2::RequestContext {
        peer,
        daemon_session,
        repo_root: repo_root.to_path_buf(),
        policy_matcher,
    };
    let resp = super::dispatch_v2::dispatch_v2(&graph, &ctx, v2_req).await;
    let json = serde_json::to_string(&resp)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

/// Build a `RequestContext` for the in-process v1 socket_dispatch path.
///
/// The wire layer (`socket_handle_connection`) carries authentic peer
/// credentials and the daemon session UUID; v1 callers are in-process
/// (e.g. tests), so they synthesize a context with the current process'
/// identity. Used by the mem_* arms which now delegate to native handlers.
pub(super) fn build_v1_dispatch_ctx(repo_root: &Path) -> super::dispatch_v2::RequestContext {
    super::dispatch_v2::RequestContext {
        peer: super::metadata::PeerContext {
            uid: super::metadata::current_euid(),
            pid: Some(std::process::id()),
        },
        daemon_session: uuid::Uuid::nil(),
        repo_root: repo_root.to_path_buf(),
        policy_matcher: Arc::new(tokio::sync::RwLock::new(
            crate::hooks::policy_match::PolicyMatcherSet::empty(),
        )),
    }
}
