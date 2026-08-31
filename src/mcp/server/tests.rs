use super::*;
use crate::store::record::{
    Category, ConfidenceScore, FileRecord, GotchaRecord, Priority, QualityScore, Record,
    RecordLifecycle, RecordSource, RecordVersion, StalenessScore,
};
use crate::store::{PolicyRecord, Store};

fn make_gotcha_record(key: &str, files: &[&str]) -> Record {
    let gotcha = GotchaRecord {
        rule: "test rule".into(),
        reason: "test reason".into(),
        severity: Priority::High,
        affected_files: files.iter().map(|s| s.to_string()).collect(),
        ref_url: None,
        discovered_session: 1_000_000,
        confirmed: true,
        confirmed_content: Default::default(),
    };
    Record {
        key: key.to_string(),
        value: "test rule because test reason".into(),
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

fn make_file_record(path: &str) -> Record {
    let file = FileRecord {
        path: path.to_string(),
        purpose: String::new(),
        entry_points: vec![],
        imports: vec![],
        gotcha_keys: vec![],
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

fn file_gotcha_keys(record: &Record) -> Vec<String> {
    record
        .payload
        .as_ref()
        .and_then(|p| p.get("gotcha_keys"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Test helper: wraps a Store in a Graph + Arc for socket_dispatch.
///
/// Consumes the Store (Graph owns it). Returns the Arc and a reference
/// to access the store through the graph for assertions.
async fn make_test_graph(store: Store) -> Arc<tokio::sync::RwLock<Graph>> {
    let graph = Graph::load(store).await.expect("failed to load test graph");
    Arc::new(tokio::sync::RwLock::new(graph))
}

async fn dispatch_with_graph(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    cmd: &str,
    args: serde_json::Value,
) -> SocketResponse {
    let req = SocketRequest {
        cmd: cmd.to_string(),
        version: Some(PROTOCOL_VERSION),
        args,
    };
    socket_dispatch(graph, Path::new("/tmp/mati-test"), &req).await
}

// ── Regression: gotcha_write via socket syncs file links ─────────────

#[tokio::test]
async fn socket_gotcha_write_adds_keys_to_file_records() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    store
        .put("file:src/a.rs", &make_file_record("src/a.rs"))
        .await
        .unwrap();
    store
        .put("file:src/b.rs", &make_file_record("src/b.rs"))
        .await
        .unwrap();
    let graph = make_test_graph(store).await;

    let record = make_gotcha_record("gotcha:socket-test", &["src/a.rs", "src/b.rs"]);
    let resp = dispatch_with_graph(&graph, "gotcha_write", serde_json::json!({
            "record": record, "new_files": ["src/a.rs", "src/b.rs"], "old_files": [], "is_new": true,
        })).await;
    assert!(resp.ok, "gotcha_write failed: {:?}", resp.error);

    let g = graph.read().await;
    let a = g.store().get("file:src/a.rs").await.unwrap().unwrap();
    let b = g.store().get("file:src/b.rs").await.unwrap().unwrap();
    assert!(file_gotcha_keys(&a).contains(&"gotcha:socket-test".into()));
    assert!(file_gotcha_keys(&b).contains(&"gotcha:socket-test".into()));
}

#[tokio::test]
async fn socket_gotcha_write_edit_removes_key_from_old_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    store
        .put("file:src/a.rs", &make_file_record("src/a.rs"))
        .await
        .unwrap();
    store
        .put("file:src/b.rs", &make_file_record("src/b.rs"))
        .await
        .unwrap();
    let graph = make_test_graph(store).await;

    let record = make_gotcha_record("gotcha:edit-socket", &["src/a.rs"]);
    let resp = dispatch_with_graph(
        &graph,
        "gotcha_write",
        serde_json::json!({
            "record": record, "new_files": ["src/a.rs"], "old_files": [], "is_new": true,
        }),
    )
    .await;
    assert!(resp.ok);

    let record2 = make_gotcha_record("gotcha:edit-socket", &["src/b.rs"]);
    let resp2 = dispatch_with_graph(&graph, "gotcha_write", serde_json::json!({
            "record": record2, "new_files": ["src/b.rs"], "old_files": ["src/a.rs"], "is_new": false,
        })).await;
    assert!(resp2.ok);

    let g = graph.read().await;
    let a = g.store().get("file:src/a.rs").await.unwrap().unwrap();
    let b = g.store().get("file:src/b.rs").await.unwrap().unwrap();
    assert!(!file_gotcha_keys(&a).contains(&"gotcha:edit-socket".into()));
    assert!(file_gotcha_keys(&b).contains(&"gotcha:edit-socket".into()));
}

#[tokio::test]
async fn socket_gotcha_tombstone_removes_keys_from_file_records() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    store
        .put("file:src/a.rs", &make_file_record("src/a.rs"))
        .await
        .unwrap();
    store
        .put("file:src/b.rs", &make_file_record("src/b.rs"))
        .await
        .unwrap();
    let graph = make_test_graph(store).await;

    let record = make_gotcha_record("gotcha:tomb-socket", &["src/a.rs", "src/b.rs"]);
    let resp = dispatch_with_graph(&graph, "gotcha_write", serde_json::json!({
            "record": record, "new_files": ["src/a.rs", "src/b.rs"], "old_files": [], "is_new": true,
        })).await;
    assert!(resp.ok);

    let resp2 = dispatch_with_graph(
        &graph,
        "gotcha_tombstone",
        serde_json::json!({
            "key": "gotcha:tomb-socket", "affected_files": ["src/a.rs", "src/b.rs"],
        }),
    )
    .await;
    assert!(resp2.ok, "gotcha_tombstone failed: {:?}", resp2.error);

    let g = graph.read().await;
    let rec = g.store().get("gotcha:tomb-socket").await.unwrap().unwrap();
    assert!(matches!(rec.lifecycle, RecordLifecycle::Tombstoned { .. }));
    let a = g.store().get("file:src/a.rs").await.unwrap().unwrap();
    let b = g.store().get("file:src/b.rs").await.unwrap().unwrap();
    assert!(file_gotcha_keys(&a).is_empty());
    assert!(file_gotcha_keys(&b).is_empty());
}

#[tokio::test]
async fn socket_gotcha_write_rejects_duplicate_key() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let record1 = make_gotcha_record("gotcha:dup-socket", &["src/a.rs"]);
    store.put("gotcha:dup-socket", &record1).await.unwrap();
    let graph = make_test_graph(store).await;

    let record2 = make_gotcha_record("gotcha:dup-socket", &["src/b.rs"]);
    let resp = dispatch_with_graph(
        &graph,
        "gotcha_write",
        serde_json::json!({
            "record": record2, "new_files": ["src/b.rs"], "old_files": [], "is_new": true,
        }),
    )
    .await;
    assert!(!resp.ok, "duplicate key should be rejected");
    assert!(resp
        .error
        .as_deref()
        .unwrap_or("")
        .contains("already exists"));

    let g = graph.read().await;
    let original = g.store().get("gotcha:dup-socket").await.unwrap().unwrap();
    let payload = original.payload_as::<GotchaRecord>().unwrap();
    assert_eq!(payload.affected_files, vec!["src/a.rs"]);
}

// ── Wire-level size enforcement ────────────────────────────────────

#[tokio::test]
async fn oversized_request_returns_frame_too_large_with_response() {
    use super::super::protocol::MAX_FRAME_SIZE;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = make_test_graph(store).await;

    let (client, server) = UnixStream::pair().unwrap();
    let peer = super::super::metadata::PeerContext {
        uid: 501,
        pid: None,
    };

    // Payload larger than MAX_FRAME_SIZE.
    let oversized = "x".repeat(MAX_FRAME_SIZE + 100);
    let payload = format!("{oversized}\n");

    // Split client: write oversized request, then read response.
    let (client_read, client_write) = client.into_split();

    let write_handle = tokio::spawn(async move {
        let mut w = client_write;
        w.write_all(payload.as_bytes()).await.unwrap();
        w.shutdown().await.unwrap();
    });

    let handle_result = socket_handle_connection(
        graph,
        Arc::new(tokio::sync::RwLock::new(
            crate::hooks::policy_match::PolicyMatcherSet::empty(),
        )),
        dir.path(),
        server,
        peer,
        uuid::Uuid::nil(),
    )
    .await;
    assert!(handle_result.is_ok());

    write_handle.await.unwrap();

    // Read the error response from the server.
    let mut reader = tokio::io::BufReader::new(client_read);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();

    assert_eq!(resp["status"], "err");
    assert_eq!(resp["code"], "frame_too_large");
    assert!(
        resp["message"]
            .as_str()
            .unwrap()
            .contains(&MAX_FRAME_SIZE.to_string()),
        "error message should mention the size limit"
    );
}

#[tokio::test]
async fn normal_sized_request_is_not_rejected_by_size_check() {
    use super::super::protocol::MAX_FRAME_SIZE;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = make_test_graph(store).await;

    let (client, server) = UnixStream::pair().unwrap();
    let peer = super::super::metadata::PeerContext {
        uid: 501,
        pid: None,
    };

    // A valid v2 ping request — well under MAX_FRAME_SIZE.
    let request = serde_json::json!({
        "v": 2,
        "id": uuid::Uuid::new_v4(),
        "session": uuid::Uuid::nil(),
        "cmd": { "type": "ping" }
    });
    let payload = format!("{}\n", serde_json::to_string(&request).unwrap());
    assert!(
        payload.len() < MAX_FRAME_SIZE,
        "test payload should be small"
    );

    let (client_read, client_write) = client.into_split();

    let write_handle = tokio::spawn(async move {
        let mut w = client_write;
        w.write_all(payload.as_bytes()).await.unwrap();
        w.shutdown().await.unwrap();
    });

    let handle_result = socket_handle_connection(
        graph,
        Arc::new(tokio::sync::RwLock::new(
            crate::hooks::policy_match::PolicyMatcherSet::empty(),
        )),
        dir.path(),
        server,
        peer,
        uuid::Uuid::nil(),
    )
    .await;
    assert!(handle_result.is_ok());

    write_handle.await.unwrap();

    // Read response — should be a successful pong, not FrameTooLarge.
    let mut reader = tokio::io::BufReader::new(client_read);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();

    assert_eq!(resp["status"], "ok", "ping should succeed, got: {resp}");
}

#[tokio::test]
async fn policy_write_round_trips_over_socket_while_store_is_held() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = make_test_graph(store).await;
    let (client, server) = UnixStream::pair().unwrap();
    let request = serde_json::json!({
        "v": 2,
        "id": uuid::Uuid::new_v4(),
        "session": uuid::Uuid::nil(),
        "cmd": {
            "type": "policy_write",
            "op": "create",
            "key": "policy:socket",
            "policy": {
                "name": "Socket policy",
                "rule": "Consult first.",
                "reason": "The schema changes because production is live.",
                "scope": "repo",
                "mode": "block",
                "trigger": {"host_glob": "*prod*"},
                "requires": {
                    "key": "schema:orders",
                    "via": ["mem_get"],
                    "freshness": {"ttl_secs": 900}
                },
                "stage": "enforce",
                "severity": "high",
                "created_by": "test"
            }
        }
    });
    let (client_read, mut client_write) = client.into_split();
    client_write
        .write_all(format!("{}\n", request).as_bytes())
        .await
        .unwrap();
    client_write.shutdown().await.unwrap();
    socket_handle_connection(
        graph.clone(),
        Arc::new(tokio::sync::RwLock::new(
            crate::hooks::policy_match::PolicyMatcherSet::empty(),
        )),
        dir.path(),
        server,
        super::super::metadata::PeerContext {
            uid: 501,
            pid: None,
        },
        uuid::Uuid::nil(),
    )
    .await
    .unwrap();

    let mut reader = tokio::io::BufReader::new(client_read);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let response: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(response["status"], "ok");

    let g = graph.read().await;
    let record = g.store().get("policy:socket").await.unwrap().unwrap();
    let policy = record.payload_as::<PolicyRecord>().unwrap();
    assert_eq!(policy.name, "Socket policy");
}

// ── Daemon-restart resilience ──────────────────────────────────────
//
// Regression for the smoke-test failure: after a daemon stop+start,
// the MCP-stdio bridge sees `session_mismatch` (or transient
// `Unresponsive`) on the first call because its cached daemon session
// UUID predates the restart. Without retry, every subsequent
// mem_get/mem_query/mem_bootstrap/mem_set returns a structured error
// that effectively wedges the agent's MCP session.
//
// The fix in `proxy_daemon_result` is one bounded auto-reconnect: the
// helper re-reads daemon metadata fresh (picking up the new session
// UUID) and re-issues the request. This test asserts the reconnect
// succeeds end-to-end and DOES NOT propagate the session_mismatch
// error envelope to the caller.

/// Spawn a tiny daemon-substitute that binds the given socket and
/// answers each connection with the supplied JSON response (one line),
/// then closes the connection. Returns the JoinHandle so the test can
/// await it.
async fn spawn_canned_responder(
    sock_path: std::path::PathBuf,
    responses: Vec<serde_json::Value>,
) -> tokio::task::JoinHandle<()> {
    // Bind in this task synchronously so the caller can issue
    // requests immediately without a sleep race.
    let listener = tokio::net::UnixListener::bind(&sock_path).expect("bind responder socket");
    tokio::spawn(async move {
        for resp in responses {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
            let (reader, mut writer) = stream.into_split();
            // Drain the request line so the peer's `shutdown()` returns Ok.
            let mut buf_reader = tokio::io::BufReader::new(reader);
            let mut line = String::new();
            let _ = tokio::io::AsyncBufReadExt::read_line(&mut buf_reader, &mut line).await;
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(b'\n');
            let _ = tokio::io::AsyncWriteExt::write_all(&mut writer, &bytes).await;
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut writer).await;
        }
    })
}

#[tokio::test]
async fn mcp_call_after_daemon_restart_does_not_kill_transport() {
    // Scenario: the proxy's first attempt hits a daemon whose session
    // UUID does not match (simulating a daemon restart between two
    // tool calls). The fix retries once, re-reads metadata, and the
    // second attempt succeeds.

    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path().to_path_buf();
    let sock_path = root.join("mati.sock");

    // Initial daemon session "before restart". The proxy will read
    // this UUID, but our canned responder pretends not to recognize
    // it (returning session_mismatch). After the retry delay, we
    // rotate metadata to a new UUID — exactly what `mati daemon stop`
    // + `mati daemon start` would do in production.
    let session_before = uuid::Uuid::new_v4();
    let session_after = uuid::Uuid::new_v4();

    let meta_before = super::super::metadata::DaemonMetadata {
        pid: std::process::id(),
        session: session_before,
        owner: super::super::metadata::DaemonOwner::Daemon,
        version: String::new(),
        build: String::new(),
    };
    super::super::metadata::publish_metadata(&root, &meta_before).unwrap();

    // Stage two responses on the same socket: the first is a
    // SessionMismatch err (pre-restart daemon view), the second is a
    // successful pong (post-restart daemon view).
    let responder_handle = spawn_canned_responder(
        sock_path.clone(),
        vec![
            serde_json::json!({
                "v": 2,
                "id": uuid::Uuid::new_v4(),
                "status": "err",
                "code": "session_mismatch",
                "message": "session mismatch: re-read daemon metadata and retry",
            }),
            serde_json::json!({
                "v": 2,
                "id": uuid::Uuid::new_v4(),
                "status": "ok",
                "data": "pong",
            }),
        ],
    )
    .await;

    // Concurrent metadata rotation — fires during the retry delay.
    // Mirrors what a real daemon restart does: writes fresh metadata.
    let root_for_rotate = root.clone();
    let rotate_handle = tokio::spawn(async move {
        // Sleep just less than the proxy's 100ms retry settle so the
        // metadata rewrite is committed before the second attempt.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let meta_after = super::super::metadata::DaemonMetadata {
            pid: std::process::id(),
            session: session_after,
            owner: super::super::metadata::DaemonOwner::Daemon,
            version: String::new(),
            build: String::new(),
        };
        super::super::metadata::publish_metadata(&root_for_rotate, &meta_after).unwrap();
    });

    // Wrap in a tokio timeout: if the retry path is missing, the
    // proxy returns the first attempt's envelope without ever
    // dialing the second responder, which would leave the test
    // hanging on the spare canned response. The timeout converts
    // that latent hang into a deterministic failure with a clear
    // error message.
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        super::proxy_daemon_result(&root, "ping", serde_json::json!({})),
    )
    .await
    .expect("proxy_daemon_result should resolve within 5s — retry path appears wedged");

    rotate_handle.await.unwrap();
    // Drop the responder task — the second canned response may go
    // unconsumed in failure modes. Aborting prevents the test from
    // hanging on `responder_handle.await` in failure mode.
    responder_handle.abort();

    // The proxy must transparently recover: caller sees Ok, not the
    // session_mismatch error envelope from the first attempt.
    match result {
        super::ProxyDaemonResult::Ok(v) => {
            let ok = v.get("ok") == Some(&serde_json::Value::Bool(true));
            let code = v.get("code").and_then(|c| c.as_str()).unwrap_or("");
            assert!(
                ok,
                "second attempt should succeed after metadata rotation, \
                     but caller saw the first attempt's session_mismatch envelope: \
                     ok={ok} code={code:?} v={v}"
            );
        }
        other => panic!(
            "expected Ok(true) after auto-reconnect, got {other:?}; \
                 the daemon-restart retry path is not engaging"
        ),
    }
}

#[tokio::test]
async fn mcp_call_session_mismatch_no_retry_target_returns_envelope() {
    // Negative-side guard: if the second attempt also fails with the
    // same error (e.g. the daemon was not actually restarted), the
    // proxy still returns the structured error envelope to the
    // caller — it does NOT panic, hang, or close the rmcp transport.
    // This preserves the per-call structured-error discipline that
    // keeps Claude's MCP session alive.

    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path().to_path_buf();
    let sock_path = root.join("mati.sock");

    let session = uuid::Uuid::new_v4();
    let meta = super::super::metadata::DaemonMetadata {
        pid: std::process::id(),
        session,
        owner: super::super::metadata::DaemonOwner::Daemon,
        version: String::new(),
        build: String::new(),
    };
    super::super::metadata::publish_metadata(&root, &meta).unwrap();

    // Both attempts get a session_mismatch — emulates a daemon that
    // truly cannot be reconciled (wedged in a state the proxy can't
    // recover from).
    let responder_handle = spawn_canned_responder(
        sock_path.clone(),
        vec![
            serde_json::json!({
                "v": 2,
                "id": uuid::Uuid::new_v4(),
                "status": "err",
                "code": "session_mismatch",
                "message": "session mismatch (1)",
            }),
            serde_json::json!({
                "v": 2,
                "id": uuid::Uuid::new_v4(),
                "status": "err",
                "code": "session_mismatch",
                "message": "session mismatch (2)",
            }),
        ],
    )
    .await;

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        super::proxy_daemon_result(&root, "ping", serde_json::json!({})),
    )
    .await
    .expect("proxy_daemon_result must resolve within 5s");
    responder_handle.abort();

    // The caller MUST get a structured Ok envelope with ok:false +
    // the session_mismatch code, never a panic or transport-killing
    // surprise. socket_call (in tools.rs) renders this to a JSON
    // error string — which is exactly the contract the rmcp loop
    // expects: a String response, not a Result::Err.
    match result {
        super::ProxyDaemonResult::Ok(v) => {
            assert_eq!(v.get("ok"), Some(&serde_json::Value::Bool(false)));
            assert_eq!(
                v.get("code").and_then(|c| c.as_str()),
                Some("session_mismatch")
            );
        }
        other => panic!("expected structured Ok envelope, got {other:?}"),
    }
}

// ── Pass-29 regression: proxy_daemon_result handles side-effecting reads ──
//
// Pre-fix: every Socket-backed `mem_get` and `mem_bootstrap` MCP call
// panicked the rmcp task at `v1_to_v2_command` (no match arm), which
// surfaced to the client as `Transport closed` and wedged Phases 6–17
// of the smoke. The translation layer is the load-bearing artifact
// — pass 27's mock-UnixListener test bypassed it entirely, so the
// bug shipped.
//
// These tests drive `proxy_daemon_result` with the exact strings
// tools.rs sends today. Without the new arms in v1_to_v2_command,
// both panic. With the fix, both return a clean `NotRunning` because
// the socket doesn't exist — proving the translation succeeded
// before the connect attempt.

#[tokio::test]
async fn proxy_daemon_result_handles_mem_get_translation_no_panic() {
    let dir = tempfile::TempDir::new().unwrap();
    // No socket file present — the call must reach the
    // sock_path.exists() guard, which it cannot do if v1_to_v2_command
    // panics first.
    let result = super::proxy_daemon_result(
        dir.path(),
        "mem_get",
        serde_json::json!({ "key": "file:src/main.rs" }),
    )
    .await;
    assert!(
        matches!(result, super::ProxyDaemonResult::NotRunning),
        "mem_get without daemon must return NotRunning, got {result:?}"
    );
}

#[tokio::test]
async fn proxy_daemon_result_handles_mem_bootstrap_translation_no_panic() {
    let dir = tempfile::TempDir::new().unwrap();
    let result = super::proxy_daemon_result(
        dir.path(),
        "mem_bootstrap",
        serde_json::json!({ "context_files": ["src/lib.rs"] }),
    )
    .await;
    assert!(
        matches!(result, super::ProxyDaemonResult::NotRunning),
        "mem_bootstrap without daemon must return NotRunning, got {result:?}"
    );
}

#[tokio::test]
async fn proxy_daemon_v2_typed_path_handles_mem_set_mutations_no_panic() {
    // The Socket-backend mem_set now takes the typed path. With no
    // daemon present, the typed-Command serialize→connect path must
    // surface as a clean NotRunning, never a panic. This is the
    // load-bearing fence: any future caller that accidentally routes
    // gotcha_upsert through the v1 mapper would fail
    // v1_to_v2_command_no_mutations_silently_accepted in protocol.rs;
    // here we make sure the typed path itself is wired end-to-end.
    let dir = tempfile::TempDir::new().unwrap();
    let cmd = super::super::protocol::Command::GotchaConfirm(
        super::super::protocol::GotchaConfirmInput {
            key: "gotcha:test".into(),
            via_elicitation: false,
        },
    );
    let result = super::proxy_daemon_v2(dir.path(), cmd).await;
    assert!(
        matches!(result, super::ProxyDaemonResult::NotRunning),
        "typed proxy_daemon_v2 must return NotRunning when daemon is absent, got {result:?}"
    );
}
