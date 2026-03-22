//! M-07-J: MCP stdio integration test.
//!
//! Spawns `mati serve` as a subprocess and drives all 3 MCP tools over the
//! actual JSON-RPC 2.0 / stdio transport:
//!
//!   - `mem_get`       — direct key lookup (nonexistent key → null, no error)
//!   - `mem_query`     — BM25 text search (empty store → empty results, no error)
//!   - `mem_bootstrap` — context packet assembly (empty store → valid packet, no error)
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
                    let line = buf.trim_end_matches('\n').trim_end_matches('\r').to_string();
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

/// Drive all 3 MCP tools over the real stdio transport.
///
/// Uses a fresh tempdir as the project root so no real store is modified.
#[test]
fn mcp_stdio_all_three_tools() {
    // ── 1. Set up a fresh project directory ──────────────────────────────────
    let project_dir = TempDir::new().expect("failed to create tempdir for MCP test");

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
    let stdout = child.stdout.take().expect("mati serve has no stdout handle");

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

    assert!(
        tool_names.contains(&"mem_get"),
        "tools/list missing mem_get. Got: {tool_names:?}"
    );
    assert!(
        tool_names.contains(&"mem_query"),
        "tools/list missing mem_query. Got: {tool_names:?}"
    );
    assert!(
        tool_names.contains(&"mem_bootstrap"),
        "tools/list missing mem_bootstrap. Got: {tool_names:?}"
    );
    assert_eq!(
        tool_names.len(),
        3,
        "expected exactly 3 tools (hard limit), got {}: {tool_names:?}",
        tool_names.len()
    );

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

    // The content must include the [mati] Vector B marker (ARCHITECTURE.md §6).
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

    // ── 8. Cleanup ────────────────────────────────────────────────────────────
    // `_guard` is dropped here → kill() + wait() called automatically.
    // `project_dir` is dropped here → temp directory cleaned up.
}
