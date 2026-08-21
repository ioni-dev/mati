//! M-07-J: MCP stdio integration test.
//!
//! Spawns `mati serve` as a subprocess and drives all 4 MCP tools over the
//! actual JSON-RPC 2.0 / stdio transport:
//!
//!   - `mem_get`       — direct key lookup (nonexistent key → null, no error)
//!   - `mem_query`     — BM25 text search (empty store → empty results, no error)
//!   - `mem_bootstrap` — context packet assembly (empty store → valid packet, no error)
//!   - `mem_set`       — write enriched knowledge (M-11)
//!
//! The server is given a fresh temporary directory as its CWD so a new store
//! is created in `~/.mati/<slug>/` without touching any real project store.
//!
//! # Protocol notes
//!
//! MCP uses newline-delimited JSON-RPC 2.0 over stdio. The server emits one
//! JSON object per line. After the `initialize` response, the server may also
//! send an `initialized` notification (no `id` field) which is consumed by
//! the `read_until_id` helper.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use tempfile::TempDir;

mod common;

// ── Guard type — kills child on drop ─────────────────────────────────────────

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // Best-effort kill; ignore errors (process may have already exited).
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// ── Reader thread + channel ───────────────────────────────────────────────────

/// Spawn a background thread that reads lines from `stdout` and sends them
/// through the returned channel. This lets the test apply a timeout to what
/// would otherwise be a blocking `read_line` call.
fn spawn_reader(stdout: std::process::ChildStdout) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut buf = String::new();
        loop {
            buf.clear();
            match reader.read_line(&mut buf) {
                Ok(0) => break, // EOF — server exited
                Ok(_) => {
                    let line = buf
                        .trim_end_matches('\n')
                        .trim_end_matches('\r')
                        .to_string();
                    if line.is_empty() {
                        continue; // skip blank lines
                    }
                    if tx.send(line).is_err() {
                        break; // receiver dropped
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Receive the next line from the reader channel, panicking if the 5-second
/// deadline is exceeded.
fn recv_line(rx: &mpsc::Receiver<String>) -> String {
    rx.recv_timeout(Duration::from_secs(5))
        .expect("timeout (5s) waiting for MCP server response — server may have hung or crashed")
}

/// Parse a JSON string, panicking with a helpful message on failure.
fn parse_json(line: &str) -> serde_json::Value {
    serde_json::from_str(line)
        .unwrap_or_else(|e| panic!("MCP server sent invalid JSON: {e}\nLine: {line}"))
}

/// Send a JSON-RPC message followed by a newline, then flush.
fn send(stdin: &mut std::process::ChildStdin, msg: &str) {
    stdin
        .write_all(msg.as_bytes())
        .expect("failed to write to MCP server stdin");
    stdin
        .write_all(b"\n")
        .expect("failed to write newline to MCP server stdin");
    stdin.flush().expect("failed to flush MCP server stdin");
}

/// Read lines until one has the given integer `id`, skipping notifications
/// (which have no `id` field).  Panics on timeout.
fn read_until_id(rx: &mpsc::Receiver<String>, expected_id: u64) -> serde_json::Value {
    loop {
        let line = recv_line(rx);
        let v = parse_json(&line);
        match v.get("id").and_then(|id| id.as_u64()) {
            Some(id) if id == expected_id => return v,
            _ => {
                // Notification or response for a different id — skip.
            }
        }
    }
}

// ── Main test ─────────────────────────────────────────────────────────────────

/// Drive all 4 MCP tools over the real stdio transport.
///
/// Uses a fresh tempdir as the project root so no real store is modified.
#[test]
fn mcp_stdio_all_four_tools() {
    // ── 1. Set up a fresh project directory ──────────────────────────────────
    let project_dir = TempDir::new().expect("failed to create tempdir for MCP test");
    common::isolate_mati_home(); // keep the spawned server's store out of ~/.mati
    let _daemon_guard = common::DaemonGuard::for_mati_home(project_dir.path(), common::mati_home());

    // ── 2. Spawn `mati serve` ─────────────────────────────────────────────────
    let bin = env!("CARGO_BIN_EXE_mati");

    let mut child = Command::new(bin)
        .arg("serve")
        .current_dir(project_dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Redirect stderr to null so tracing output doesn't pollute test output.
        // Comment this out to see server logs when debugging.
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn `mati serve`");

    let stdin = child.stdin.take().expect("mati serve has no stdin handle");
    let stdout = child
        .stdout
        .take()
        .expect("mati serve has no stdout handle");

    // Move `child` into the guard *after* extracting stdin/stdout.
    let _guard = ChildGuard(child);

    let mut stdin = stdin;
    let rx = spawn_reader(stdout);

    // ── 3. initialize ─────────────────────────────────────────────────────────
    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}"#,
    );

    let init_response = read_until_id(&rx, 1);

    assert!(
        init_response.get("error").is_none(),
        "initialize should not return an error: {init_response}"
    );
    assert!(
        init_response.get("result").is_some(),
        "initialize response missing 'result' field: {init_response}"
    );

    // Send the `initialized` notification as required by the MCP protocol.
    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
    );

    // ── 4. tools/list ─────────────────────────────────────────────────────────
    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    );

    let tools_response = read_until_id(&rx, 2);

    assert!(
        tools_response.get("error").is_none(),
        "tools/list should not return an error: {tools_response}"
    );

    let tools = tools_response["result"]["tools"]
        .as_array()
        .expect("tools/list result.tools should be an array");

    let tool_names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .collect();

    for expected in &["mem_get", "mem_query", "mem_bootstrap", "mem_set"] {
        assert!(
            tool_names.contains(expected),
            "tools/list missing {expected}. Got: {tool_names:?}"
        );
    }
    assert_eq!(
        tool_names.len(),
        4,
        "expected exactly 4 tools (hard limit), got {}: {tool_names:?}",
        tool_names.len()
    );

    // Annotations must match traced behavior. mem_query is the only pure read;
    // mem_get and mem_bootstrap write receipts/audit/analytics. destructiveHint
    // is pinned on every write tool because an OMITTED destructiveHint defaults
    // to true — leaving it unset would advertise mem_get as destructive.
    for tool in tools {
        let name = tool["name"].as_str().unwrap_or("");
        let ann = tool.get("annotations");
        let hint = |field: &str| ann.and_then(|a| a.get(field)).and_then(|v| v.as_bool());

        // Zero-network invariant, stated at the protocol level.
        assert_eq!(
            hint("openWorldHint"),
            Some(false),
            "{name} must have openWorldHint=false"
        );

        match name {
            "mem_query" => {
                assert_eq!(
                    hint("readOnlyHint"),
                    Some(true),
                    "mem_query writes nothing — readOnlyHint=true"
                );
            }
            "mem_get" | "mem_bootstrap" => {
                assert_eq!(
                    hint("readOnlyHint"),
                    Some(false),
                    "{name} writes on every call — readOnlyHint=false"
                );
                assert_eq!(
                    hint("destructiveHint"),
                    Some(false),
                    "{name} only appends — destructiveHint must be pinned, not omitted"
                );
                assert_eq!(
                    hint("idempotentHint"),
                    Some(false),
                    "{name} appends a new audit row per call — idempotentHint=false"
                );
            }
            "mem_set" => {
                assert_eq!(
                    hint("readOnlyHint"),
                    Some(false),
                    "mem_set must have readOnlyHint=false"
                );
                assert_eq!(
                    hint("destructiveHint"),
                    Some(true),
                    "mem_set tombstones and overwrites — destructiveHint=true"
                );
            }
            _ => {}
        }
    }

    // ── 5. mem_get — nonexistent key returns null content, no error ───────────
    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mem_get","arguments":{"key":"file:nonexistent"}}}"#,
    );

    let mem_get_response = read_until_id(&rx, 3);

    assert!(
        mem_get_response.get("error").is_none(),
        "mem_get should not return a JSON-RPC error: {mem_get_response}"
    );
    // MCP tool call responses always have a `content` array.
    assert!(
        mem_get_response["result"].get("content").is_some(),
        "mem_get result missing 'content' field: {}",
        mem_get_response["result"]
    );

    // ── 6. mem_query — empty store returns content array, no error ────────────
    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"mem_query","arguments":{"query":"auth","limit":5}}}"#,
    );

    let mem_query_response = read_until_id(&rx, 4);

    assert!(
        mem_query_response.get("error").is_none(),
        "mem_query should not return a JSON-RPC error: {mem_query_response}"
    );
    assert!(
        mem_query_response["result"].get("content").is_some(),
        "mem_query result missing 'content' field: {}",
        mem_query_response["result"]
    );

    // ── 7. mem_bootstrap — empty store returns valid packet with Vector B ─────
    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"mem_bootstrap","arguments":{}}}"#,
    );

    let mem_bootstrap_response = read_until_id(&rx, 5);

    assert!(
        mem_bootstrap_response.get("error").is_none(),
        "mem_bootstrap should not return a JSON-RPC error: {mem_bootstrap_response}"
    );
    let bootstrap_result = &mem_bootstrap_response["result"];
    assert!(
        bootstrap_result.get("content").is_some(),
        "mem_bootstrap result missing 'content' field: {bootstrap_result}"
    );

    // The content must include the [mati] Vector B marker (ARCHITECTURE.md section 6).
    let bootstrap_text = bootstrap_result["content"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|item| item.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("");
    assert!(
        bootstrap_text.contains("[mati]"),
        "mem_bootstrap content should contain '[mati]' Vector B marker. Got: {bootstrap_text}"
    );

    // ── 8. mem_set — write a gotcha record, verify ok response ────────────
    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"mem_set","arguments":{"key":"gotcha:test-write","value":"Never call unwrap in error paths because it panics in production","category":"Gotcha","payload":{"rule":"Never call unwrap in error paths","reason":"Causes panics in production","severity":"High","affected_files":["src/main.rs"],"confirmed":false}}}}"#,
    );

    let mem_set_response = read_until_id(&rx, 6);

    assert!(
        mem_set_response.get("error").is_none(),
        "mem_set should not return a JSON-RPC error: {mem_set_response}"
    );
    assert!(
        mem_set_response["result"].get("content").is_some(),
        "mem_set result missing 'content' field: {}",
        mem_set_response["result"]
    );
    let set_text = mem_set_response["result"]["content"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|item| item.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("");
    assert!(
        set_text.contains("\"ok\"") || set_text.contains("gotcha:test-write"),
        "mem_set should confirm the write. Got: {set_text}"
    );

    // ── 9. Cleanup ────────────────────────────────────────────────────────────
    // `_guard` is dropped here → kill() + wait() called automatically.
    // `project_dir` is dropped here → temp directory cleaned up.
}

// ── Helper: extract text content from MCP tool call response ─────────────────

fn extract_text(response: &serde_json::Value) -> String {
    response["result"]["content"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|item| item.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string()
}

// ── Helper: set up MCP server, return (stdin, rx, _guard, _tempdir, _daemon_guard) ──

fn setup_mcp_server() -> (
    std::process::ChildStdin,
    mpsc::Receiver<String>,
    ChildGuard,
    TempDir,
    common::DaemonGuard,
) {
    // Declare elicitation so the confirm gate can prompt (P4). Tests that need
    // a client without it use `setup_mcp_server_caps("{}")`.
    setup_mcp_server_caps(r#"{"elicitation":{}}"#)
}

fn setup_mcp_server_caps(
    capabilities: &str,
) -> (
    std::process::ChildStdin,
    mpsc::Receiver<String>,
    ChildGuard,
    TempDir,
    common::DaemonGuard,
) {
    let project_dir = TempDir::new().expect("failed to create tempdir");
    common::isolate_mati_home(); // keep the spawned server's store out of ~/.mati
    let daemon_guard = common::DaemonGuard::for_mati_home(project_dir.path(), common::mati_home());
    let bin = env!("CARGO_BIN_EXE_mati");

    let mut child = Command::new(bin)
        .arg("serve")
        .current_dir(project_dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn `mati serve`");

    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let guard = ChildGuard(child);
    let rx = spawn_reader(stdout);

    let mut stdin = stdin;

    // initialize
    send(
        &mut stdin,
        &format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05","capabilities":{capabilities},"clientInfo":{{"name":"test","version":"0.1"}}}}}}"#
        ),
    );
    let init = read_until_id(&rx, 1);
    assert!(init.get("error").is_none(), "initialize failed: {init}");

    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
    );

    // Tuple order matters: fields drop in reverse, so `daemon_guard` (last)
    // runs `mati daemon stop` while `project_dir` (second-to-last) still
    // exists on disk — the stop command needs that cwd to derive the slug.
    (stdin, rx, guard, project_dir, daemon_guard)
}

// ── Helper: call a tool and return the parsed text ───────────────────────────

fn call_tool(
    stdin: &mut std::process::ChildStdin,
    rx: &mpsc::Receiver<String>,
    id: u64,
    name: &str,
    args: &str,
) -> String {
    let msg = format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{args}}}}}"#
    );
    send(stdin, &msg);
    let resp = read_until_id(rx, id);
    assert!(
        resp.get("error").is_none(),
        "tool {name} returned JSON-RPC error: {resp}"
    );
    extract_text(&resp)
}

/// Call `mem_set` confirm, answer the server's inbound `elicitation/create`
/// request with `result` (the JSON for the response `result` field), then
/// return the tool-call response text. The confirm gate blocks on the
/// elicitation reply, so a plain `call_tool` would deadlock here.
fn confirm_with_elicitation(
    stdin: &mut std::process::ChildStdin,
    rx: &mpsc::Receiver<String>,
    id: u64,
    key: &str,
    result: &str,
) -> String {
    let call = format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"mem_set","arguments":{{"action":"confirm","key":"{key}"}}}}}}"#
    );
    send(stdin, &call);
    loop {
        let v = parse_json(&recv_line(rx));
        if v.get("method").and_then(|m| m.as_str()) == Some("elicitation/create") {
            let req_id = v.get("id").cloned().unwrap_or(serde_json::Value::Null);
            send(
                stdin,
                &format!(r#"{{"jsonrpc":"2.0","id":{req_id},"result":{result}}}"#),
            );
            continue;
        }
        if v.get("id").and_then(|i| i.as_u64()) == Some(id) {
            assert!(
                v.get("error").is_none(),
                "confirm returned JSON-RPC error: {v}"
            );
            return extract_text(&v);
        }
    }
}

// ── Test: gotcha lifecycle (write → read → confirm → read → delete → read) ──

#[test]
fn mcp_stdio_gotcha_lifecycle() {
    let (mut stdin, rx, _guard, _dir, _daemon_guard) = setup_mcp_server();

    // Write a gotcha
    let write_text = call_tool(
        &mut stdin,
        &rx,
        10,
        "mem_set",
        r#"{"action":"write","key":"gotcha:lifecycle-test","value":"Test rule because test reason","category":"Gotcha","payload":"{\"rule\":\"Test rule\",\"reason\":\"test reason\",\"severity\":\"normal\",\"affected_files\":[],\"confirmed\":false}","tags":["test"],"priority":"Normal"}"#,
    );
    assert!(
        write_text.contains("\"ok\""),
        "write should succeed: {write_text}"
    );
    assert!(
        write_text.contains("lifecycle-test"),
        "write should echo key: {write_text}"
    );

    // Read it back
    let get_text = call_tool(
        &mut stdin,
        &rx,
        11,
        "mem_get",
        r#"{"key":"gotcha:lifecycle-test"}"#,
    );
    // mem_get may emit either compact (no space) or pretty JSON — accept both
    // so the test isn't coupled to the serializer's whitespace preference.
    assert!(
        get_text.contains("\"confirmed\": false") || get_text.contains("\"confirmed\":false"),
        "should be unconfirmed: {get_text}"
    );
    assert!(
        get_text.contains("\"claude_enrich\"") || get_text.contains("claude_enrich"),
        "source should be claude_enrich: {get_text}"
    );

    // Confirm it — the gate elicits; the developer accepts with confirm=true.
    let confirm_text = confirm_with_elicitation(
        &mut stdin,
        &rx,
        12,
        "gotcha:lifecycle-test",
        r#"{"action":"accept","content":{"confirm":true}}"#,
    );
    assert!(
        confirm_text.contains("\"confirmed\": true") || confirm_text.contains("\"confirmed\":true"),
        "confirm should return confirmed=true: {confirm_text}"
    );

    // Read back — verify confirmed + DeveloperManual
    let confirmed_text = call_tool(
        &mut stdin,
        &rx,
        13,
        "mem_get",
        r#"{"key":"gotcha:lifecycle-test"}"#,
    );
    assert!(
        confirmed_text.contains("\"confirmed\": true")
            || confirmed_text.contains("\"confirmed\":true"),
        "should be confirmed: {confirmed_text}"
    );
    assert!(
        confirmed_text.contains("developer_manual"),
        "source should be developer_manual: {confirmed_text}"
    );

    // Delete (tombstone)
    let delete_text = call_tool(
        &mut stdin,
        &rx,
        14,
        "mem_set",
        r#"{"action":"delete","key":"gotcha:lifecycle-test"}"#,
    );
    assert!(
        delete_text.contains("\"tombstoned\""),
        "delete should return tombstoned: {delete_text}"
    );

    // Read back — should be null
    let tombstoned_text = call_tool(
        &mut stdin,
        &rx,
        15,
        "mem_get",
        r#"{"key":"gotcha:lifecycle-test"}"#,
    );
    assert!(
        tombstoned_text == "null" || tombstoned_text.contains("null"),
        "tombstoned record should return null: {tombstoned_text}"
    );
}

// ── Test: confirm gate — decline keeps the gotcha a draft ────────────────────

#[test]
fn mcp_stdio_confirm_decline_keeps_draft() {
    let (mut stdin, rx, _guard, _dir, _daemon_guard) = setup_mcp_server();

    call_tool(
        &mut stdin,
        &rx,
        30,
        "mem_set",
        r#"{"action":"write","key":"gotcha:decline-test","value":"Rule because reason","category":"Gotcha","payload":"{\"rule\":\"Rule\",\"reason\":\"reason\",\"severity\":\"normal\",\"affected_files\":[],\"confirmed\":false}","tags":["test"],"priority":"Normal"}"#,
    );

    // Developer declines the elicitation — no confirmation reaches the daemon.
    let declined = confirm_with_elicitation(
        &mut stdin,
        &rx,
        31,
        "gotcha:decline-test",
        r#"{"action":"decline"}"#,
    );
    assert!(
        declined.contains("declined"),
        "decline should report declined: {declined}"
    );

    // The gotcha is still an unconfirmed draft.
    let after = call_tool(
        &mut stdin,
        &rx,
        32,
        "mem_get",
        r#"{"key":"gotcha:decline-test"}"#,
    );
    assert!(
        after.contains("\"confirmed\": false") || after.contains("\"confirmed\":false"),
        "declined gotcha must stay unconfirmed: {after}"
    );
}

// ── Test: confirm gate — a client without elicitation is redirected to CLI ────

#[test]
fn mcp_stdio_confirm_without_elicitation_redirects_to_cli() {
    let (mut stdin, rx, _guard, _dir, _daemon_guard) = setup_mcp_server_caps("{}");

    call_tool(
        &mut stdin,
        &rx,
        40,
        "mem_set",
        r#"{"action":"write","key":"gotcha:no-elicit","value":"Rule because reason","category":"Gotcha","payload":"{\"rule\":\"Rule\",\"reason\":\"reason\",\"severity\":\"normal\",\"affected_files\":[],\"confirmed\":false}","tags":["test"],"priority":"Normal"}"#,
    );

    // No elicitation capability → the gate fails closed to the CLI, no prompt.
    let text = call_tool(
        &mut stdin,
        &rx,
        41,
        "mem_set",
        r#"{"action":"confirm","key":"gotcha:no-elicit"}"#,
    );
    assert!(
        text.contains("mati gotcha confirm"),
        "should redirect to the CLI: {text}"
    );

    let after = call_tool(
        &mut stdin,
        &rx,
        42,
        "mem_get",
        r#"{"key":"gotcha:no-elicit"}"#,
    );
    assert!(
        after.contains("\"confirmed\": false") || after.contains("\"confirmed\":false"),
        "gotcha must stay unconfirmed without a human accept: {after}"
    );
}

// ── Test: confirm gate — a non-answering client times out, fails closed ──────

#[test]
fn mcp_stdio_confirm_elicitation_timeout_fails_closed() {
    // A short timeout so the test doesn't wait the 5-minute default. nextest
    // runs each test in its own process, so this env var does not leak.
    std::env::set_var("MATI_CONFIRM_ELICIT_TIMEOUT_MS", "400");
    let (mut stdin, rx, _guard, _dir, _daemon_guard) = setup_mcp_server();

    call_tool(
        &mut stdin,
        &rx,
        60,
        "mem_set",
        r#"{"action":"write","key":"gotcha:wedge","value":"Rule because reason","category":"Gotcha","payload":"{\"rule\":\"Rule\",\"reason\":\"reason\",\"severity\":\"normal\",\"affected_files\":[],\"confirmed\":false}","tags":["test"],"priority":"Normal"}"#,
    );

    // Send the confirm but never answer the elicitation. `read_until_id` skips
    // the server's `elicitation/create` request; the gate must time out and
    // return a rejection rather than hang.
    let text = call_tool(
        &mut stdin,
        &rx,
        61,
        "mem_set",
        r#"{"action":"confirm","key":"gotcha:wedge"}"#,
    );
    assert!(
        text.contains("unconfirmed draft") || text.contains("confirmation failed"),
        "an unanswered elicitation must fail closed: {text}"
    );

    let after = call_tool(&mut stdin, &rx, 62, "mem_get", r#"{"key":"gotcha:wedge"}"#);
    assert!(
        after.contains("\"confirmed\": false") || after.contains("\"confirmed\":false"),
        "gotcha must stay unconfirmed after a timeout: {after}"
    );
}

// ── Test: validation gates ───────────────────────────────────────────────────

#[test]
fn mcp_stdio_validation_gates() {
    let (mut stdin, rx, _guard, _dir, _daemon_guard) = setup_mcp_server();

    // Invalid key prefix
    let text = call_tool(
        &mut stdin,
        &rx,
        20,
        "mem_set",
        r#"{"action":"write","key":"session:invalid","value":"test","category":"File","payload":"{}"}"#,
    );
    // Source: src/mcp/tools/mem_set_command.rs — emitted when the key prefix
    // isn't one of gotcha:/decision:/dev_note:/policy:.
    assert!(
        text.contains("requires key with") || text.contains("must start with"),
        "should reject invalid prefix: {text}"
    );

    // Gotcha key with non-gotcha payload — the rule-field gate fires before
    // category mismatch, so we assert on the actual error path.
    let text = call_tool(
        &mut stdin,
        &rx,
        21,
        "mem_set",
        r#"{"action":"write","key":"gotcha:mismatch","value":"test","category":"File","payload":"{\"purpose\":\"wrong\"}"}"#,
    );
    assert!(
        text.contains("requires non-empty 'rule'") || text.contains("requires category"),
        "should reject mismatch: {text}"
    );

    // Missing gotcha fields. The rule gate fires first; verify it. Then send
    // a second payload with rule but no reason to prove the reason gate also
    // fires (src/mcp/tools/mem_set_command.rs).
    let text = call_tool(
        &mut stdin,
        &rx,
        22,
        "mem_set",
        r#"{"action":"write","key":"gotcha:no-fields","value":"test","category":"Gotcha","payload":"{\"severity\":\"normal\"}"}"#,
    );
    assert!(
        text.contains("'rule'"),
        "should reject missing rule: {text}"
    );
    let text = call_tool(
        &mut stdin,
        &rx,
        222,
        "mem_set",
        r#"{"action":"write","key":"gotcha:no-reason","value":"test","category":"Gotcha","payload":"{\"rule\":\"x\",\"severity\":\"normal\"}"}"#,
    );
    assert!(
        text.contains("'reason'"),
        "should reject missing reason: {text}"
    );

    // Unknown action
    let text = call_tool(
        &mut stdin,
        &rx,
        23,
        "mem_set",
        r#"{"action":"destroy","key":"gotcha:test"}"#,
    );
    assert!(
        text.contains("unknown action"),
        "should reject unknown action: {text}"
    );

    // Delete non-gotcha
    let text = call_tool(
        &mut stdin,
        &rx,
        24,
        "mem_set",
        r#"{"action":"delete","key":"file:test.rs"}"#,
    );
    assert!(
        text.contains("only applies to gotcha"),
        "should reject non-gotcha delete: {text}"
    );

    // Confirm non-existent
    let text = call_tool(
        &mut stdin,
        &rx,
        25,
        "mem_set",
        r#"{"action":"confirm","key":"gotcha:does-not-exist"}"#,
    );
    assert!(
        text.contains("not found"),
        "should reject confirm on missing key: {text}"
    );
}

// ── Test: search modes (text with relevance, tag, graph, semantic gate) ──────

#[test]
fn mcp_stdio_search_modes() {
    let (mut stdin, rx, _guard, _dir, _daemon_guard) = setup_mcp_server();

    // Write two records with different tags
    call_tool(
        &mut stdin,
        &rx,
        30,
        "mem_set",
        r#"{"action":"write","key":"gotcha:search-a","value":"Alpha rule because alpha reason","category":"Gotcha","payload":"{\"rule\":\"Alpha rule\",\"reason\":\"alpha reason\"}","tags":["alpha","shared"],"priority":"Normal"}"#,
    );
    call_tool(
        &mut stdin,
        &rx,
        31,
        "mem_set",
        r#"{"action":"write","key":"gotcha:search-b","value":"Beta rule because beta reason","category":"Gotcha","payload":"{\"rule\":\"Beta rule\",\"reason\":\"beta reason\"}","tags":["beta","shared"],"priority":"Normal"}"#,
    );

    // Text search — should have relevance scores
    let text = call_tool(
        &mut stdin,
        &rx,
        32,
        "mem_query",
        r#"{"query":"alpha","mode":"text","limit":5}"#,
    );
    assert!(
        text.contains("relevance"),
        "text search should include relevance: {text}"
    );
    assert!(
        text.contains("search-a"),
        "text search should find alpha: {text}"
    );

    // Tag search
    let text = call_tool(
        &mut stdin,
        &rx,
        33,
        "mem_query",
        r#"{"query":"shared","mode":"tag","limit":5}"#,
    );
    assert!(
        text.contains("search-a") && text.contains("search-b"),
        "tag search should find both: {text}"
    );

    // Tag search — no match
    let text = call_tool(
        &mut stdin,
        &rx,
        34,
        "mem_query",
        r#"{"query":"zzz-nonexistent","mode":"tag","limit":5}"#,
    );
    assert!(text == "[]", "no-match tag search should return []: {text}");

    // Semantic mode gate
    let text = call_tool(
        &mut stdin,
        &rx,
        35,
        "mem_query",
        r#"{"query":"test","mode":"semantic","limit":5}"#,
    );
    assert!(
        text.contains("semantic") && text.contains("not enabled"),
        "semantic should return feature gate error: {text}"
    );

    // Empty query
    let text = call_tool(
        &mut stdin,
        &rx,
        36,
        "mem_query",
        r#"{"query":"","mode":"text","limit":5}"#,
    );
    assert!(text == "[]", "empty query should return []: {text}");

    // Limit 0
    let text = call_tool(
        &mut stdin,
        &rx,
        37,
        "mem_query",
        r#"{"query":"rule","mode":"text","limit":0}"#,
    );
    assert!(text == "[]", "limit 0 should return []: {text}");

    // Cleanup
    call_tool(
        &mut stdin,
        &rx,
        38,
        "mem_set",
        r#"{"action":"delete","key":"gotcha:search-a"}"#,
    );
    call_tool(
        &mut stdin,
        &rx,
        39,
        "mem_set",
        r#"{"action":"delete","key":"gotcha:search-b"}"#,
    );
}

// ── Test: enforcement-telemetry query modes reach the daemon over the socket ─
//
// These are the reads a sandboxed agent shell cannot make over the CLI (the
// daemon socket is unreachable from the sandbox). Driving them through the
// stdio server proves they are reachable over MCP, which runs outside it.

#[test]
fn mcp_stdio_telemetry_modes() {
    let (mut stdin, rx, _guard, _dir, _daemon_guard) = setup_mcp_server();

    // policy_observations on a fresh store — empty object, not a transport error.
    let text = call_tool(
        &mut stdin,
        &rx,
        50,
        "mem_query",
        r#"{"query":"","mode":"policy_observations","limit":20}"#,
    );
    assert!(
        text == "{}",
        "policy_observations on empty store should be an empty object: {text}"
    );

    // policy_activity honors the `since` window carried over the v1→v2 bridge.
    let text = call_tool(
        &mut stdin,
        &rx,
        51,
        "mem_query",
        r#"{"query":"","mode":"policy_activity","limit":20,"since":7}"#,
    );
    assert!(
        text.contains("\"window_days\":7"),
        "policy_activity must echo the `since` window: {text}"
    );
    assert!(
        text.contains("\"policies\":[]"),
        "policy_activity on empty store should list no policies: {text}"
    );

    // analytics on a fresh store — empty array.
    let text = call_tool(
        &mut stdin,
        &rx,
        52,
        "mem_query",
        r#"{"query":"","mode":"analytics","limit":20}"#,
    );
    assert!(
        text == "[]",
        "analytics on empty store should return []: {text}"
    );
}

// ── Test: write-then-search consistency ──────────────────────────────────────

#[test]
fn mcp_stdio_write_then_search() {
    let (mut stdin, rx, _guard, _dir, _daemon_guard) = setup_mcp_server();

    // Write with a unique sentinel
    call_tool(
        &mut stdin,
        &rx,
        40,
        "mem_set",
        r#"{"action":"write","key":"gotcha:sentinel-zqx99","value":"zqx99_unique_sentinel because consistency test","category":"Gotcha","payload":"{\"rule\":\"zqx99_unique_sentinel\",\"reason\":\"consistency test\"}","tags":["sentinel"],"priority":"Normal"}"#,
    );

    // Immediately search — should find it
    let text = call_tool(
        &mut stdin,
        &rx,
        41,
        "mem_query",
        r#"{"query":"zqx99_unique_sentinel","mode":"text","limit":5}"#,
    );
    assert!(
        text.contains("sentinel-zqx99"),
        "write-then-search should find the record immediately: {text}"
    );
    assert!(
        text.contains("relevance"),
        "should have relevance score: {text}"
    );

    // Delete + verify excluded from search
    call_tool(
        &mut stdin,
        &rx,
        42,
        "mem_set",
        r#"{"action":"delete","key":"gotcha:sentinel-zqx99"}"#,
    );
    let text = call_tool(
        &mut stdin,
        &rx,
        43,
        "mem_query",
        r#"{"query":"zqx99_unique_sentinel","mode":"text","limit":5}"#,
    );
    assert!(
        !text.contains("sentinel-zqx99"),
        "tombstoned record should not appear in search: {text}"
    );
}

// ── Test: result.isError reflects real success/failure ──────────────────────
//
// Regression for the bug where every tool call returned `isError: false`
// regardless of outcome (rejected write, missing record, malformed mode),
// forcing clients to string-match the text body instead of checking the
// protocol-level error flag.

#[test]
fn mcp_stdio_is_error_flag() {
    let (mut stdin, rx, _guard, _dir, _daemon_guard) = setup_mcp_server();

    // A rejected write (unknown mem_set action) must set isError: true.
    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"mem_set","arguments":{"action":"destroy","key":"gotcha:test"}}}"#,
    );
    let resp = read_until_id(&rx, 50);
    assert_eq!(
        resp["result"]["isError"].as_bool(),
        Some(true),
        "rejected mem_set action should set isError=true: {resp}"
    );
    assert!(
        extract_text(&resp).contains("unknown action"),
        "error text should still be present in content: {resp}"
    );

    // Confirming a gotcha that does not exist must also set isError: true.
    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":51,"method":"tools/call","params":{"name":"mem_set","arguments":{"action":"confirm","key":"gotcha:does-not-exist"}}}"#,
    );
    let resp = read_until_id(&rx, 51);
    assert_eq!(
        resp["result"]["isError"].as_bool(),
        Some(true),
        "confirm on missing gotcha should set isError=true: {resp}"
    );

    // A successful write must NOT set isError.
    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":52,"method":"tools/call","params":{"name":"mem_set","arguments":{"action":"write","key":"gotcha:is-error-ok","value":"Rule because reason","category":"Gotcha","payload":"{\"rule\":\"Rule\",\"reason\":\"reason\"}"}}}"#,
    );
    let resp = read_until_id(&rx, 52);
    assert_ne!(
        resp["result"]["isError"].as_bool(),
        Some(true),
        "successful write must not set isError=true: {resp}"
    );

    // A legitimate miss (mem_get on a nonexistent key) is not an error.
    send(
        &mut stdin,
        r#"{"jsonrpc":"2.0","id":53,"method":"tools/call","params":{"name":"mem_get","arguments":{"key":"file:nonexistent-xyz"}}}"#,
    );
    let resp = read_until_id(&rx, 53);
    assert_ne!(
        resp["result"]["isError"].as_bool(),
        Some(true),
        "mem_get miss (null) must not set isError=true: {resp}"
    );
    assert_eq!(extract_text(&resp), "null");
}
