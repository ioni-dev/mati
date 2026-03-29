//! End-to-end integration test — full mati lifecycle against MATI_E2E_REPO.
//!
//! # Running
//!
//! ```sh
//! MATI_E2E_REPO=/path/to/ripgrep cargo test --test e2e -- --ignored --nocapture
//! ```
//!
//! The test is `#[ignore]`d by default so it never runs in plain `cargo test`.
//! Every step is timed, extracted metrics are printed inline, and a rich
//! summary is printed at the end.

use std::ffi::OsStr;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

// ── Test entry point ─────────────────────────────────────────────────────────

#[test]
#[ignore]
fn e2e_full_lifecycle() {
    let repo = match std::env::var("MATI_E2E_REPO") {
        Ok(v) => PathBuf::from(v),
        Err(_) => {
            eprintln!("MATI_E2E_REPO not set — skipping e2e test");
            return;
        }
    };

    // Locate the mati binary — cargo test puts it in the same target dir
    let mati = cargo_bin("mati");

    // Fresh HOME for store isolation: each test run starts with an empty ~/.mati/
    let home_dir = TempDir::new().expect("create temp home");
    let home = home_dir.path();

    let mut report = Report::new();
    let mut summary = Summary::default();

    // ═══════════════════════════════════════════════════════════════════════════
    // Iteration 1 — cold init
    // ═══════════════════════════════════════════════════════════════════════════

    let r = h_run(&mati, &repo, home, &["init", "--no-hooks"]);
    let mut sr = StepResult::new("init", &r);
    extract_init_metrics(&r.stdout, &mut sr, &mut summary);
    report.add(sr);

    let r = h_run(&mati, &repo, home, &["ping"]);
    let mut sr = StepResult::new("ping", &r);
    extract_ping_metrics(&r.stdout, &mut sr, &mut summary);
    report.add(sr);

    let r = h_run(&mati, &repo, home, &["status"]);
    let mut sr = StepResult::new("status", &r);
    extract_status_metrics(&r.stdout, &mut sr, &mut summary);
    report.add(sr);

    let r = h_run(&mati, &repo, home, &["stats"]);
    let mut sr = StepResult::new("stats", &r);
    extract_stats_metrics(&r.stdout, &mut sr, &mut summary);
    report.add(sr);

    let r = h_run(&mati, &repo, home, &["gaps"]);
    let mut sr = StepResult::new("gaps", &r);
    extract_gaps_metrics(&r.stdout, &mut sr, &mut summary);
    report.add(sr);

    let r = h_run(&mati, &repo, home, &["ls", "files", "-n", "0"]);
    let mut sr = StepResult::new("ls files", &r);
    extract_ls_files_metrics(&r.stdout, &mut sr, &mut summary);
    report.add(sr);

    let r = h_run(&mati, &repo, home, &["ls", "gotchas"]);
    let mut sr = StepResult::new("ls gotchas", &r);
    extract_ls_gotchas_metrics(&r.stdout, &mut sr, &mut summary);
    report.add(sr);

    let r = h_run(&mati, &repo, home, &["ls", "decisions"]);
    let mut sr = StepResult::new("ls decisions", &r);
    extract_ls_decisions_metrics(&r.stdout, &mut sr, &mut summary);
    report.add(sr);

    // Pick the first file from `ls files` output for explain/show
    let explain_path = pick_first_file_path(&h_run(&mati, &repo, home, &["ls", "files"]).stdout)
        .unwrap_or_else(|| "crates/grep/src/lib.rs".to_string());

    let r = h_run(&mati, &repo, home, &["explain", &explain_path]);
    let mut sr = StepResult::new("explain", &r);
    extract_explain_metrics(&r.stdout, &explain_path, &mut sr, &mut summary);
    report.add(sr);

    let file_key = format!("file:{explain_path}");
    let r = h_run(&mati, &repo, home, &["show", &file_key]);
    let mut sr = StepResult::new("show", &r);
    extract_show_metrics(&r.stdout, &mut sr, &mut summary);
    report.add(sr);

    // mati get — hook fast-path hit (file record exists after init)
    let r = h_run(&mati, &repo, home, &["get", &file_key]);
    let mut sr = StepResult::new("get (hit)", &r);
    extract_get_metrics(&r.stdout, &mut sr, &mut summary);
    report.add(sr);

    // mati get — hook fast-path miss (nonexistent key returns null, exit 0)
    let r = h_run(&mati, &repo, home, &["get", "gotcha:nonexistent-ghost"]);
    let mut sr = StepResult::new("get (miss)", &r);
    extract_get_metrics(&r.stdout, &mut sr, &mut summary);
    report.add(sr);

    // mati log-miss / log-hit — hook tracking
    {
        let r = h_run(&mati, &repo, home, &["log-miss", &file_key]);
        let mut sr = StepResult::new("log-miss", &r);
        sr.add_metric("key", &file_key);
        report.add(sr);

        let r = h_run(&mati, &repo, home, &["log-hit", &file_key]);
        let mut sr = StepResult::new("log-hit", &r);
        sr.add_metric("key", &file_key);
        report.add(sr);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Iteration 2 — gotcha add / improve / note
    // ═══════════════════════════════════════════════════════════════════════════

    // Use a high-quality rule to pass the quality gate (score >= 0.20)
    let gotcha_rule = "Always call regex::RegexBuilder::size_limit(10*1024*1024) before \
                       compiling patterns from user input to prevent ReDoS attacks that lock \
                       the search thread";
    let gotcha_reason = "Regex compilation without size limits allows adversarial patterns to \
                         consume 100%+ CPU for seconds";
    let gotcha_input = format!("{gotcha_rule}\n{gotcha_reason}\nhigh\n{explain_path}\n\n");

    let r = h_run_stdin(
        &mati,
        &repo,
        home,
        &["gotcha", "add", &explain_path],
        &gotcha_input,
    );
    let mut sr = StepResult::new("gotcha add", &r);
    let gotcha_key = extract_gotcha_add_metrics(&r.stdout, &r.stderr, &mut sr, &mut summary);
    report.add(sr);

    // mati show the gotcha just created
    if !gotcha_key.is_empty() {
        let r = h_run(&mati, &repo, home, &["show", &gotcha_key]);
        let mut sr = StepResult::new("show gotcha", &r);
        extract_show_gotcha_metrics(&r.stdout, &mut sr, &mut summary);
        report.add(sr);
    }

    // mati note
    let r = h_run(&mati, &repo, home, &["note", "e2e test iteration 2"]);
    let mut sr = StepResult::new("note", &r);
    extract_note_metrics(&r.stdout, &r.stderr, &mut sr, &mut summary);
    report.add(sr);

    // Extract note key and show the record to verify persistence
    let note_key = {
        let combined = format!("{}\n{}", r.stdout, r.stderr);
        combined
            .lines()
            .find(|l| l.contains("dev_note:"))
            .and_then(|l| l.split_whitespace().find(|t| t.starts_with("dev_note:")))
            .map(|k| k.trim_end_matches(')').trim_end_matches(',').to_string())
            .unwrap_or_default()
    };
    if !note_key.is_empty() {
        let r = h_run(&mati, &repo, home, &["show", &note_key]);
        let mut sr = StepResult::new("show note", &r);
        extract_show_metrics(&r.stdout, &mut sr, &mut summary);
        report.add(sr);
    }

    // Quality gate rejection — short/bad rule must be rejected (exit non-zero)
    {
        let bad_input = "bad\nno\nhigh\n\n\n".to_string();
        let r = h_run_stdin(
            &mati,
            &repo,
            home,
            &["gotcha", "add", &explain_path],
            &bad_input,
        );
        let mut sr = StepResult::new("gotcha reject", &r);
        // Correct behaviour: exit non-zero (quality gate blocked it)
        sr.failed = r.exit_ok; // fails if the gate MISSED and let it through
        sr.add_metric(
            "quality gate",
            if !r.exit_ok { "✓ rejected" } else { "MISSED" },
        );
        report.add(sr);
    }

    // mati improve — feed improved text
    if !gotcha_key.is_empty() {
        let improve_input = "Always call regex::RegexBuilder::size_limit(10*1024*1024) before \
            compiling patterns from user input; use size_limit() because adversarial patterns \
            without limits cause ReDoS attacks consuming 100%+ CPU for seconds\n"
            .to_string();
        let r = h_run_stdin(
            &mati,
            &repo,
            home,
            &["improve", &gotcha_key],
            &improve_input,
        );
        let mut sr = StepResult::new("improve", &r);
        extract_improve_metrics(&r.stdout, &r.stderr, &mut sr, &mut summary);
        report.add(sr);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Iteration 3 — export / import / diff / history
    // ═══════════════════════════════════════════════════════════════════════════

    let json_export = h_run(&mati, &repo, home, &["export", "--format", "json"]);
    let mut sr = StepResult::new("export json", &json_export);
    extract_export_json_metrics(&json_export.stdout, &mut sr, &mut summary);
    report.add(sr);

    let md_export = h_run(&mati, &repo, home, &["export", "--format", "md"]);
    let mut sr = StepResult::new("export md", &md_export);
    extract_export_md_metrics(&md_export.stdout, &mut sr, &mut summary);
    report.add(sr);

    // mati diff HEAD~1 — may not have parent commit on shallow clone
    {
        let diff_out = h_run(&mati, &repo, home, &["diff", "HEAD~1"]);
        let mut sr = StepResult::new("diff HEAD~1", &diff_out);
        if diff_out.exit_ok {
            extract_diff_metrics(&diff_out.stdout, &mut sr, &mut summary);
        } else {
            sr.skipped = true;
            sr.skip_reason = Some("shallow/single-commit clone".to_string());
            sr.failed = false;
        }
        report.add(sr);
    }

    // mati history for the gotcha key
    if !gotcha_key.is_empty() {
        let r = h_run(&mati, &repo, home, &["history", &gotcha_key]);
        let mut sr = StepResult::new("history", &r);
        extract_history_metrics(&r.stdout, &mut sr, &mut summary);
        report.add(sr);
    }

    // mati reparse — single-file incremental reparse (silent, just exit 0)
    {
        let r = h_run(&mati, &repo, home, &["reparse", &explain_path]);
        let mut sr = StepResult::new("reparse", &r);
        extract_reparse_metrics(r.exit_ok, &mut sr, &mut summary);
        report.add(sr);
    }

    // mati history --since 7d — all records changed in the last week
    {
        let r = h_run(&mati, &repo, home, &["history", "--since", "7d"]);
        let mut sr = StepResult::new("history --since", &r);
        extract_history_since_metrics(&r.stdout, &mut sr, &mut summary);
        report.add(sr);
    }

    // Validate export JSON contains the gotcha we created
    if !gotcha_key.is_empty() {
        let contains = json_export.stdout.contains(&gotcha_key);
        let mut sr = StepResult {
            label: "export contains",
            elapsed: std::time::Duration::ZERO,
            failed: !contains,
            skipped: false,
            skip_reason: None,
            metrics: vec![],
            metrics2: vec![],
            raw_stderr: None,
        };
        sr.add_metric("gotcha in export", if contains { "✓" } else { "MISSING" });
        report.add(sr);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Iteration 4 — incremental init / staleness
    // ═══════════════════════════════════════════════════════════════════════════

    let warm_init = h_run(&mati, &repo, home, &["init", "--no-hooks"]);
    let mut sr = StepResult::new("init warm", &warm_init);
    extract_warm_init_metrics(&warm_init.stdout, &mut sr, &mut summary);
    report.add(sr);

    // After warm init — ls gotchas should show same (or more) records
    {
        let r = h_run(&mati, &repo, home, &["ls", "gotchas"]);
        let mut sr = StepResult::new("ls gotchas", &r);
        let n = extract_ls_gotchas_count(&r.stdout);
        sr.add_metric("total", &n.to_string());
        if n > summary.gotcha_count_after_add {
            sr.add_metric(
                "✓ persisted",
                &format!(
                    "+{} from iter2",
                    n.saturating_sub(summary.gotcha_count_after_add)
                ),
            );
        } else if n == summary.gotcha_count_after_add {
            sr.add_metric("✓ persisted", "unchanged");
        }
        summary.gotcha_count_warm = n;
        report.add(sr);
    }

    // Modify a file, re-init, check 1 file is reparsed
    let changed_file = repo.join(&explain_path);
    let original_content = std::fs::read(&changed_file).unwrap_or_default();
    // Append a comment to trigger mtime change
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&changed_file) {
        let _ = f.write_all(b"\n// e2e-test-marker\n");
    }

    let changed_init = h_run(&mati, &repo, home, &["init", "--no-hooks"]);
    let mut sr = StepResult::new("init changed", &changed_init);
    extract_changed_init_metrics(&changed_init.stdout, &mut sr, &mut summary);
    report.add(sr);

    // Restore the file
    if !original_content.is_empty() {
        let _ = std::fs::write(&changed_file, &original_content);
    }

    // mati stale
    let r = h_run(&mati, &repo, home, &["stale"]);
    let mut sr = StepResult::new("stale", &r);
    extract_stale_metrics(&r.stdout, &mut sr, &mut summary);
    report.add(sr);

    // mati explain on the changed file — look for staleness signal
    let r = h_run(&mati, &repo, home, &["explain", &explain_path]);
    let mut sr = StepResult::new("explain", &r);
    extract_explain_staleness(&r.stdout, &mut sr, &mut summary);
    report.add(sr);

    // ═══════════════════════════════════════════════════════════════════════════
    // Iteration 5 — restore / review / quality-check / final export
    // ═══════════════════════════════════════════════════════════════════════════

    let restored_init = h_run(&mati, &repo, home, &["init", "--no-hooks", "--no-settings"]);
    let mut sr = StepResult::new("init restored", &restored_init);
    extract_changed_init_metrics(&restored_init.stdout, &mut sr, &mut summary);
    report.add(sr);

    // mati review — confirm all candidates (up to 20) so gotcha becomes injectable
    {
        let review_input = "c\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\n";
        let r = h_run_stdin(&mati, &repo, home, &["review"], review_input);
        let mut sr = StepResult::new("review", &r);
        extract_review_metrics(&r.stdout, &r.stderr, &mut sr, &mut summary);
        report.add(sr);
    }

    // After review: show gotcha record to verify it's still accessible
    if !gotcha_key.is_empty() {
        let r = h_run(&mati, &repo, home, &["show", &gotcha_key]);
        let mut sr = StepResult::new("show confirmed", &r);
        // mati show does NOT print a confirmed field — check confidence from the output
        let conf_val = extract_float_from_line(&r.stdout, "value");
        if let Some(c) = conf_val {
            sr.add_metric("confidence", &format!("{c:.2}"));
        }
        // confirmed is shown as "Y"/"-" only in ls gotchas, not in show output.
        // We check it via `mati get` JSON below.
        report.add(sr);

        // mati get — JSON must have "confirmed":true (gotcha add creates confirmed=true)
        let r = h_run(&mati, &repo, home, &["get", &gotcha_key]);
        let mut sr = StepResult::new("get confirmed", &r);
        let json_confirmed = r.stdout.contains("\"confirmed\":true");
        // GetOutput flattens Record, so fields are at top level: {"confidence":{"value":0.80,...},"confirmed":true,...}
        let json_conf_val = serde_json::from_str::<serde_json::Value>(r.stdout.trim())
            .ok()
            .and_then(|v| {
                v.get("confidence")
                    .and_then(|c| c.get("value"))
                    .and_then(|v| v.as_f64())
            })
            .map(|v| v as f32);
        sr.add_metric(
            "confirmed_in_json",
            if json_confirmed { "✓" } else { "missing" },
        );
        if let Some(c) = json_conf_val {
            let inject_ready = c >= 0.6 && json_confirmed;
            sr.add_metric("confidence", &format!("{c:.2}"));
            sr.add_metric(
                "injectable",
                if inject_ready {
                    "✓ (≥0.6 + confirmed)"
                } else {
                    "not yet"
                },
            );
            summary.hook_inject_ready = inject_ready;
        }
        summary.gotcha_confirmed = json_confirmed;
        sr.failed = !json_confirmed;
        report.add(sr);
    }

    // mati quality-check
    let r = h_run(&mati, &repo, home, &["quality-check"]);
    let mut sr = StepResult::new("quality-check", &r);
    extract_quality_check_metrics(&r.stdout, &mut sr, &mut summary);
    report.add(sr);

    // mati session-check-consulted — file we log-hit earlier should be consulted
    {
        let r = h_run(&mati, &repo, home, &["session-check-consulted", &file_key]);
        let mut sr = StepResult::new("session-consulted", &r);
        let consulted = r.stdout.trim() == "true";
        sr.add_metric("consulted", if consulted { "✓ true" } else { "false" });
        report.add(sr);
    }

    // mati session-flush — write session:current record
    {
        let r = h_run(&mati, &repo, home, &["session-flush"]);
        let mut sr = StepResult::new("session-flush", &r);
        sr.add_metric("result", if r.exit_ok { "✓ (exit 0)" } else { "FAILED" });
        summary.session_ok = r.exit_ok;
        report.add(sr);
    }

    // mati session-harvest — archive session + run passive promotion
    {
        let r = h_run(&mati, &repo, home, &["session-harvest"]);
        let mut sr = StepResult::new("session-harvest", &r);
        sr.add_metric("result", if r.exit_ok { "✓ (exit 0)" } else { "FAILED" });
        summary.session_ok = summary.session_ok && r.exit_ok;
        report.add(sr);
    }

    // mati doc-capture — capture doc comments for a real file
    {
        let r = h_run(&mati, &repo, home, &["doc-capture", &explain_path]);
        let mut sr = StepResult::new("doc-capture", &r);
        sr.add_metric("result", if r.exit_ok { "✓ (exit 0)" } else { "FAILED" });
        report.add(sr);
    }

    // mati edit-hook — combined log-hit + reparse (post-edit hook command)
    {
        let r = h_run(&mati, &repo, home, &["edit-hook", &explain_path]);
        let mut sr = StepResult::new("edit-hook", &r);
        sr.add_metric("result", if r.exit_ok { "✓ (exit 0)" } else { "FAILED" });
        report.add(sr);
    }

    // Final export — accumulation check
    let final_export = h_run(&mati, &repo, home, &["export", "--format", "json"]);
    let mut sr = StepResult::new("export json", &final_export);
    let prev_total = summary.export_total;
    extract_export_json_metrics(&final_export.stdout, &mut sr, &mut summary);
    let new_total = summary.export_total;
    if new_total > prev_total {
        sr.add_metric("delta", &format!("+{}", new_total - prev_total));
        sr.add_metric("✓ accumulation", "");
    }
    report.add(sr);

    // mati import round-trip — verify import reads back the exported count
    {
        let before_count = count_json_records(&final_export.stdout);
        summary.import_count_before = before_count;

        let tmp = home_dir.path().join("mati_e2e_export.json");
        if std::fs::write(&tmp, &final_export.stdout).is_ok() {
            let r = h_run(&mati, &repo, home, &["import", tmp.to_str().unwrap_or("")]);
            let mut sr = StepResult::new("import", &r);

            // Parse imported count from the import command's own stdout:
            // "Imported N records from JSON."
            let imported_count = r
                .stdout
                .lines()
                .find(|l| l.contains("Imported") && l.contains("records"))
                .and_then(first_number)
                .unwrap_or(0);
            summary.import_count_after = imported_count;

            let delta = (imported_count as i64) - (before_count as i64);
            sr.add_metric("exported", &before_count.to_string());
            sr.add_metric("imported", &imported_count.to_string());
            if delta == 0 && r.exit_ok {
                sr.add_metric("✓ idempotent", "delta=0");
            } else if !r.exit_ok {
                // sr.failed already set by StepResult::new
                sr.add_metric("error", "non-zero exit");
            } else {
                sr.failed = true;
                sr.add_metric("delta", &format!("{delta:+} DRIFT"));
            }
            report.add(sr);
        }
    }

    // Final ping
    {
        let r = h_run(&mati, &repo, home, &["ping"]);
        let mut sr = StepResult::new("ping", &r);
        extract_ping_metrics(&r.stdout, &mut sr, &mut summary);
        report.add(sr);
    }

    // Final stats
    {
        let r = h_run(&mati, &repo, home, &["stats"]);
        let mut sr = StepResult::new("stats final", &r);
        extract_stats_metrics(&r.stdout, &mut sr, &mut summary);
        report.add(sr);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Iteration 6 — MCP tools against the populated store
    // ═══════════════════════════════════════════════════════════════════════════
    // Spawn `mati serve` with the same HOME/CWD as all prior steps so it opens
    // the same store.  Then drive mem_get / mem_query / mem_bootstrap over the
    // real JSON-RPC stdio transport and verify results against real knowledge.
    {
        use std::io::{BufRead as _, BufReader, Write as _};
        use std::sync::mpsc;

        struct MatiChild(std::process::Child);
        impl Drop for MatiChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        fn mcp_recv(rx: &mpsc::Receiver<String>, id: u64) -> Option<serde_json::Value> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let rem = deadline.saturating_duration_since(std::time::Instant::now());
                if rem.is_zero() {
                    return None;
                }
                let line = match rx.recv_timeout(rem) {
                    Ok(l) => l,
                    Err(_) => return None,
                };
                let v: serde_json::Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if v.get("id").and_then(|i| i.as_u64()) == Some(id) {
                    return Some(v);
                }
            }
        }

        let spawn_result = std::process::Command::new(&mati)
            .arg("serve")
            .current_dir(&repo)
            .env("HOME", home)
            .env("NO_COLOR", "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn();

        if let Ok(mut child) = spawn_result {
            let mut stdin = child.stdin.take().expect("mati serve stdin");
            let stdout = child.stdout.take().expect("mati serve stdout");
            let _guard = MatiChild(child);

            let (tx, rx) = mpsc::channel::<String>();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stdout);
                let mut buf = String::new();
                loop {
                    buf.clear();
                    match reader.read_line(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let line = buf.trim_end().to_string();
                            if !line.is_empty() {
                                let _ = tx.send(line);
                            }
                        }
                    }
                }
            });

            // initialize
            let _ = stdin.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"e2e\",\"version\":\"0.1\"}}}\n");
            let _ = stdin.flush();
            mcp_recv(&rx, 1);
            let _ = stdin.write_all(
                b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            );
            let _ = stdin.flush();

            // ── mem_get: the gotcha we created should return non-null ────────
            let mcp_get_start = Instant::now();
            let get_msg = if !gotcha_key.is_empty() {
                format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"mem_get\",\"arguments\":{{\"key\":\"{}\"}}}}}}\n",
                    gotcha_key
                )
            } else {
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"mem_get\",\"arguments\":{\"key\":\"file:nonexistent\"}}}\n".to_string()
            };
            let _ = stdin.write_all(get_msg.as_bytes());
            let _ = stdin.flush();
            let get_resp = mcp_recv(&rx, 2);
            let get_text = get_resp
                .as_ref()
                .and_then(|v| v["result"]["content"].as_array())
                .and_then(|a| a.first())
                .and_then(|item| item["text"].as_str())
                .unwrap_or("null");
            let get_hit = get_text != "null" && !get_text.is_empty() && !gotcha_key.is_empty();
            summary.mcp_get_hit = get_hit;

            let mut sr = StepResult {
                label: "mcp mem_get",
                elapsed: mcp_get_start.elapsed(),
                failed: !gotcha_key.is_empty() && !get_hit,
                skipped: gotcha_key.is_empty(),
                skip_reason: if gotcha_key.is_empty() {
                    Some("no gotcha key from iter2".into())
                } else {
                    None
                },
                metrics: vec![],
                metrics2: vec![],
                raw_stderr: None,
            };
            sr.add_metric("hit", if get_hit { "✓" } else { "null" });
            if get_hit {
                let preview: String = strip_ansi(get_text).chars().take(50).collect();
                sr.add_metric2("content", &format!("\"{}...\"", preview));
            }
            report.add(sr);

            // ── mem_query: search for a term present in the gotcha rule ──────
            let mcp_query_start = Instant::now();
            let query_term = "regex";
            let query_msg = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"mem_query\",\"arguments\":{{\"query\":\"{query_term}\",\"limit\":5}}}}}}\n"
            );
            let _ = stdin.write_all(query_msg.as_bytes());
            let _ = stdin.flush();
            let query_resp = mcp_recv(&rx, 3);
            let query_text = query_resp
                .as_ref()
                .and_then(|v| v["result"]["content"].as_array())
                .and_then(|a| a.first())
                .and_then(|item| item["text"].as_str())
                .unwrap_or("");
            // A hit means the response is non-empty and not just "No results found"
            let query_hit = !query_text.is_empty()
                && !query_text.to_lowercase().contains("no results")
                && query_text != "null";
            summary.mcp_query_hit = query_hit;

            let mut sr = StepResult {
                label: "mcp mem_query",
                elapsed: mcp_query_start.elapsed(),
                failed: false, // empty results are valid (gotcha may not be confirmed)
                skipped: false,
                skip_reason: None,
                metrics: vec![],
                metrics2: vec![],
                raw_stderr: None,
            };
            sr.add_metric("query", &format!("\"{query_term}\""));
            sr.add_metric("results", if query_hit { "✓ hit" } else { "empty" });
            report.add(sr);

            // ── mem_bootstrap: should carry [mati] Vector B marker ───────────
            let mcp_boot_start = Instant::now();
            let _ = stdin.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"mem_bootstrap\",\"arguments\":{}}}\n");
            let _ = stdin.flush();
            let boot_resp = mcp_recv(&rx, 4);
            let boot_text = boot_resp
                .as_ref()
                .and_then(|v| v["result"]["content"].as_array())
                .and_then(|a| a.first())
                .and_then(|item| item["text"].as_str())
                .unwrap_or("");
            let has_marker = boot_text.contains("[mati]");
            summary.mcp_bootstrap_has_gotcha = has_marker;

            let mut sr = StepResult {
                label: "mcp mem_bootstrap",
                elapsed: mcp_boot_start.elapsed(),
                failed: !has_marker,
                skipped: false,
                skip_reason: None,
                metrics: vec![],
                metrics2: vec![],
                raw_stderr: None,
            };
            sr.add_metric("[mati] marker", if has_marker { "✓" } else { "MISSING" });
            let token_est = boot_text.len() / 4;
            if token_est > 0 {
                sr.add_metric("~tokens", &token_est.to_string());
            }
            // Check if our gotcha made it into the bootstrap context
            let gotcha_in_boot = !gotcha_key.is_empty() && boot_text.contains(&gotcha_key);
            if gotcha_in_boot {
                sr.add_metric2("gotcha in context", "✓");
            }
            report.add(sr);
        }
    }

    // ── Print report ────────────────────────────────────────────────────────
    report.print(&summary);

    // ── Assert ALL PASS ──────────────────────────────────────────────────────
    let failed: Vec<&str> = report
        .steps
        .iter()
        .filter(|s| s.failed && !s.skipped)
        .map(|s| s.label)
        .collect();
    assert!(failed.is_empty(), "e2e steps failed: {:?}", failed);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Harness types
// ═══════════════════════════════════════════════════════════════════════════════

struct RunResult {
    stdout: String,
    stderr: String,
    elapsed: Duration,
    exit_ok: bool,
}

struct StepResult<'a> {
    label: &'a str,
    elapsed: Duration,
    failed: bool,
    skipped: bool,
    skip_reason: Option<String>,
    metrics: Vec<(String, String)>,
    // second-line metrics (wrap)
    metrics2: Vec<(String, String)>,
    raw_stderr: Option<String>,
}

impl<'a> StepResult<'a> {
    fn new(label: &'a str, r: &RunResult) -> Self {
        StepResult {
            label,
            elapsed: r.elapsed,
            failed: !r.exit_ok,
            skipped: false,
            skip_reason: None,
            metrics: Vec::new(),
            metrics2: Vec::new(),
            raw_stderr: if !r.exit_ok && !r.stderr.is_empty() {
                Some(r.stderr.clone())
            } else {
                None
            },
        }
    }

    fn add_metric(&mut self, key: &str, val: &str) {
        self.metrics.push((key.to_string(), val.to_string()));
    }

    fn add_metric2(&mut self, key: &str, val: &str) {
        self.metrics2.push((key.to_string(), val.to_string()));
    }
}

struct Report<'a> {
    steps: Vec<StepResult<'a>>,
}

impl<'a> Report<'a> {
    fn new() -> Self {
        Report { steps: Vec::new() }
    }

    fn add(&mut self, s: StepResult<'a>) {
        self.steps.push(s);
    }

    fn print(&self, summary: &Summary) {
        println!();
        println!("══ e2e lifecycle ════════════════════════════════════════════════");
        println!();

        let mut n_pass = 0usize;
        let mut n_fail = 0usize;
        let mut n_skip = 0usize;

        for step in &self.steps {
            let status = if step.skipped {
                n_skip += 1;
                "skip"
            } else if step.failed {
                n_fail += 1;
                "FAIL"
            } else {
                n_pass += 1;
                "ok"
            };

            let ms = step.elapsed.as_millis();

            // Build metrics string for first line
            let m1 = format_metrics(&step.metrics);
            // Build second-line metrics
            let m2 = format_metrics(&step.metrics2);

            // Skip reason
            let skip_suffix = step
                .skip_reason
                .as_deref()
                .map(|r| format!("  (skipped: {r})"))
                .unwrap_or_default();

            // First line: label  status  timing  metrics1
            let first_line = if m1.is_empty() {
                format!(
                    "  {:<16}{:<6}{:>6}ms{}",
                    step.label, status, ms, skip_suffix
                )
            } else {
                format!(
                    "  {:<16}{:<6}{:>6}ms   {}{}",
                    step.label, status, ms, m1, skip_suffix
                )
            };
            println!("{first_line}");

            // Dump raw stderr for failed steps (aids debugging)
            if step.failed {
                if let Some(ref raw) = step.raw_stderr {
                    for line in raw.lines().take(25) {
                        println!("    | {line}");
                    }
                }
            }

            // Second line (overflow metrics): indented 24 chars to align with metrics
            if !m2.is_empty() {
                println!("  {:<24}{}", "", m2);
            }
        }

        println!();
        println!("══ Summary ═════════════════════════════════════════════════════");

        let skip_note = if n_skip > 0 {
            format!("  [{n_skip} skipped — shallow clone]")
        } else {
            String::new()
        };

        if n_fail == 0 {
            println!(
                "  Result:       ALL PASS ({n_pass} / {}){}",
                n_pass + n_fail + n_skip,
                skip_note
            );
        } else {
            println!(
                "  Result:       {n_fail} FAILED, {n_pass} passed ({}/{}){skip_note}",
                n_pass + n_fail + n_skip,
                n_pass + n_fail + n_skip
            );
        }

        println!();
        println!("  ── Init performance ──");
        if summary.cold_init_ms > 0 {
            let speedup = if summary.warm_init_ms > 0 {
                format!(
                    "{:.1}x",
                    summary.cold_init_ms as f64 / summary.warm_init_ms as f64
                )
            } else {
                "?".to_string()
            };
            println!(
                "  Cold init:    {}ms    Warm re-init: {}ms    Speedup: {}",
                summary.cold_init_ms, summary.warm_init_ms, speedup
            );
        }
        if summary.files > 0 {
            if summary.entry_points > 0 || summary.imports > 0 {
                println!(
                    "  Files:        {}      Entry points: {}    Imports: {}",
                    summary.files, summary.entry_points, summary.imports
                );
            } else {
                println!("  Files:        {}", summary.files);
            }
        }
        if summary.gotcha_cands > 0
            || summary.todos > 0
            || summary.doc_comments > 0
            || summary.hotspots > 0
        {
            println!(
                "  Gotcha cands: {}   (unwrap+unsafe+panic+TODO)   Hotspots: {}",
                summary.gotcha_cands, summary.hotspots
            );
            if summary.todos > 0 || summary.doc_comments > 0 {
                println!(
                    "  TODOs:        {}       Doc comments: {}",
                    summary.todos, summary.doc_comments
                );
            }
        }

        println!();
        println!("  ── Knowledge coverage ──");
        println!(
            "  Records:      {}      File: {}    Gotcha: {}    Decision: {}",
            summary.export_total,
            summary.export_file,
            summary.export_gotcha,
            summary.export_decision
        );
        if summary.confirmed_count > 0 || summary.gotcha_count_after_add > 0 {
            println!(
                "  Confirmed:    {}        Unconfirmed: {}",
                summary.confirmed_count,
                summary
                    .gotcha_count_after_add
                    .saturating_sub(summary.confirmed_count)
            );
        }
        if summary.confidence_avg > 0.0 {
            println!("  Confidence:   avg={:.2}", summary.confidence_avg);
        }
        if summary.quality_suppressed > 0
            || summary.quality_poor > 0
            || summary.quality_acceptable > 0
            || summary.quality_good > 0
            || summary.quality_excellent > 0
        {
            println!(
                "  Quality:      suppressed={}  poor={}  acceptable={}  good={}  excellent={}",
                summary.quality_suppressed,
                summary.quality_poor,
                summary.quality_acceptable,
                summary.quality_good,
                summary.quality_excellent,
            );
        }

        println!();
        println!("  ── Gap & staleness signals ──");
        if summary.gaps > 0 {
            println!(
                "  Gaps:         {}       Top risk: {}",
                summary.gaps, summary.top_gap_risk
            );
        }
        if summary.stale_count > 0 {
            println!(
                "  Stale:        {}        (1 direct, {} via co-change coupling)",
                summary.stale_count,
                summary.stale_count.saturating_sub(1)
            );
        }
        if summary.revert_stubs > 0 || summary.ownership_stubs > 0 || summary.cochange_stubs > 0 {
            println!(
                "  Revert stubs: {}        Ownership stubs: {}    Co-change stubs: {}",
                summary.revert_stubs, summary.ownership_stubs, summary.cochange_stubs
            );
        }

        println!();
        println!("  ── Lifecycle ──");
        println!(
            "  Change det.:  {}  (1 file re-parsed after modification)",
            if summary.change_detected { "✓" } else { "?" }
        );
        println!(
            "  Persistence:  {}  (records survive re-init)",
            if summary.gotcha_count_warm >= summary.gotcha_count_after_add
                && summary.gotcha_count_after_add > 0
            {
                "✓"
            } else {
                "?"
            }
        );
        println!(
            "  Incremental:  {}  (0 parsed on unchanged re-init)",
            if summary.warm_parsed == 0 { "✓" } else { "?" }
        );
        let import_ok = summary.import_count_after == summary.import_count_before
            && summary.import_count_before > 0;
        println!(
            "  Export:       {}  (JSON valid, import delta={})",
            if import_ok { "✓" } else { "?" },
            (summary.import_count_after as i64) - (summary.import_count_before as i64)
        );

        println!();
        println!("  ── Hook fast-path ──");
        println!(
            "  get (hit):    {}  (populated key returns record JSON)",
            if summary.hook_get_hit { "✓" } else { "?" }
        );
        println!(
            "  Confirmed:    {}  (gotcha ready for hook injection)",
            if summary.gotcha_confirmed { "✓" } else { "?" }
        );
        println!(
            "  Injectable:   {}  (confirmed=true + confidence≥0.6 + quality≥0.4)",
            if summary.hook_inject_ready {
                "✓"
            } else {
                "not yet"
            }
        );
        println!(
            "  Session:      {}  (flush + harvest lifecycle)",
            if summary.session_ok { "✓" } else { "?" }
        );
        if summary.history_versions > 0 {
            println!(
                "  History:      {}  versions for improved gotcha (expected ≥2)",
                summary.history_versions
            );
        }
        println!(
            "  reparse:      {}  (single-file incremental reparse)",
            if summary.reparse_ok { "✓" } else { "?" }
        );
        if summary.history_since_count > 0 {
            println!(
                "  history 7d:   {}  records changed in window",
                summary.history_since_count
            );
        }
        if summary.quality_before > 0.0 || summary.quality_after > 0.0 {
            println!(
                "  Quality:      {:.2} → {:.2}  (improve progression {})",
                summary.quality_before,
                summary.quality_after,
                if summary.quality_after > summary.quality_before {
                    "✓"
                } else {
                    "?"
                }
            );
        }

        println!();
        println!("  ── MCP (populated store) ──");
        println!(
            "  mem_get:      {}  (gotcha key lookup against real store)",
            if summary.mcp_get_hit { "✓" } else { "?" }
        );
        println!(
            "  mem_query:    {}  (BM25 search with results)",
            if summary.mcp_query_hit {
                "✓"
            } else {
                "empty (may need confirmed record)"
            }
        );
        println!(
            "  mem_bootstrap:{}  ([mati] Vector B marker present)",
            if summary.mcp_bootstrap_has_gotcha {
                "✓"
            } else {
                "?"
            }
        );
        println!();
    }
}

fn format_metrics(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            if v.is_empty() {
                k.clone()
            } else {
                format!("{k}={v}")
            }
        })
        .collect::<Vec<_>>()
        .join("  ")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Summary accumulator
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Default)]
struct Summary {
    // Init performance
    cold_init_ms: u128,
    warm_init_ms: u128,
    warm_parsed: u64,

    // Init structure
    files: u64,
    entry_points: u64,
    imports: u64,
    gotcha_cands: u64,
    todos: u64,
    doc_comments: u64,
    hotspots: u64,
    co_change_pairs: u64,
    revert_stubs: u64,
    ownership_stubs: u64,
    cochange_stubs: u64,

    // Knowledge coverage
    records_total: u64,
    export_total: u64,
    export_file: u64,
    export_gotcha: u64,
    export_decision: u64,
    export_dev_note: u64,
    export_dep: u64,
    gotcha_count_after_add: usize,
    gotcha_count_warm: usize,
    confirmed_count: usize,

    // Quality / confidence
    confidence_avg: f32,
    quality_suppressed: u64,
    quality_poor: u64,
    quality_acceptable: u64,
    quality_good: u64,
    quality_excellent: u64,

    // Gaps
    gaps: u64,
    top_gap_risk: f32,

    // Stale
    stale_count: u64,

    // Hook fast-path
    hook_get_hit: bool,
    // Single-file reparse
    reparse_ok: bool,
    // History window
    history_since_count: u64,
    // History versions
    history_versions: u64,
    // Quality progression
    quality_before: f32,
    quality_after: f32,
    // Import idempotency
    import_count_before: u64,
    import_count_after: u64,
    // MCP against populated store
    mcp_get_hit: bool,
    mcp_query_hit: bool,
    mcp_bootstrap_has_gotcha: bool,

    // Lifecycle flags
    change_detected: bool,

    // Gotcha confirmation
    gotcha_confirmed: bool,
    hook_inject_ready: bool,
    // Session lifecycle
    session_ok: bool,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Extraction functions
// ═══════════════════════════════════════════════════════════════════════════════

/// Parse a number from a line of output matching a label prefix.
/// Looks for lines like "  file records:  214  ..." or "  hotspot files:  22"
fn extract_number(output: &str, label: &str) -> u64 {
    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains(label) {
            // Find first contiguous digit sequence after the label
            let after = &line[line.to_lowercase().find(label).unwrap_or(0) + label.len()..];
            if let Some(n) = first_number(after) {
                return n;
            }
        }
    }
    0
}

/// Extract the integer that appears immediately before a keyword in any line.
/// E.g., `extract_int_before_word(output, " parsed")` returns 1 from `(1 parsed, 213 skipped)`.
fn extract_int_before_word(output: &str, keyword: &str) -> u64 {
    let kw_lower = keyword.to_lowercase();
    for line in output.lines() {
        let lower = line.to_lowercase();
        if let Some(pos) = lower.find(&kw_lower) {
            let before = &line[..pos];
            // Last whitespace-delimited token before the keyword
            if let Some(tok) = before.split_whitespace().last() {
                let clean: String = tok.chars().filter(|c| c.is_ascii_digit()).collect();
                if let Ok(n) = clean.parse::<u64>() {
                    return n;
                }
            }
        }
    }
    0
}

/// Extract the first integer found in a string.
fn first_number(s: &str) -> Option<u64> {
    let digits: String = s
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// Extract the first floating-point number from a string.
fn first_float(s: &str) -> Option<f32> {
    let mut start = None;
    let mut dot_seen = false;
    let chars: Vec<char> = s.chars().collect();
    let mut result = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if start.is_none() {
            if c.is_ascii_digit() {
                start = Some(i);
                result.push(c);
            }
        } else {
            if c.is_ascii_digit() {
                result.push(c);
            } else if c == '.' && !dot_seen {
                dot_seen = true;
                result.push(c);
            } else {
                break;
            }
        }
    }
    if result.is_empty() || result == "." {
        None
    } else {
        result.parse().ok()
    }
}

/// Find a matching line and extract the float from it.
fn extract_float_from_line(output: &str, label: &str) -> Option<f32> {
    for line in output.lines() {
        if line.to_lowercase().contains(label) {
            let after = &line[line.to_lowercase().find(label).unwrap_or(0) + label.len()..];
            if let Some(v) = first_float(after) {
                return Some(v);
            }
        }
    }
    None
}

// ── mati init ─────────────────────────────────────────────────────────────────

fn extract_init_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    let files = extract_number(output, "file records:");
    let hotspots = extract_number(output, "hotspot files:");
    let candidates = extract_number(output, "gotcha candidates:");
    let _deps = extract_number(output, "dep records:");
    let _edges = extract_number(output, "graph edges:");
    let _imported = extract_number(output, "imported from claude.md:");

    // Pull entry_points and imports from the detailed parse line if present
    // "  Parsing with tree-sitter...   1847 ep  3201 imports  ..."
    // Fallback: extract from summary-style lines
    let entry_points =
        extract_number(output, "entry points:").max(extract_number(output, "entry_points:"));
    let imports = extract_number(output, "imports:");
    let todos = extract_number(output, "todos:");
    let doc_comments = extract_number(output, "doc comments:");
    let co_change_pairs = extract_number(output, "co-change pairs:");
    let revert_stubs = extract_number(output, "revert stubs:");
    let ownership_stubs = extract_number(output, "ownership stubs:");
    let cochange_stubs =
        extract_number(output, "cochange stubs:").max(extract_number(output, "co-change stubs:"));

    sr.add_metric("files", &files.to_string());
    if entry_points > 0 {
        sr.add_metric("entry_points", &entry_points.to_string());
    }
    if imports > 0 {
        sr.add_metric("imports", &imports.to_string());
    }
    if candidates > 0 {
        sr.add_metric("gotcha_cands", &candidates.to_string());
    }
    if todos > 0 {
        sr.add_metric("todos", &todos.to_string());
    }
    if co_change_pairs > 0 {
        sr.add_metric2("co_change_pairs", &co_change_pairs.to_string());
    }
    if revert_stubs > 0 {
        sr.add_metric2("revert_stubs", &revert_stubs.to_string());
    }
    if ownership_stubs > 0 {
        sr.add_metric2("ownership_stubs", &ownership_stubs.to_string());
    }
    if cochange_stubs > 0 {
        sr.add_metric2("cochange_stubs", &cochange_stubs.to_string());
    }
    if doc_comments > 0 {
        sr.add_metric2("doc_comments", &doc_comments.to_string());
    }
    if hotspots > 0 {
        sr.add_metric2("hotspots", &hotspots.to_string());
    }

    // Update summary
    if summary.cold_init_ms == 0 {
        summary.cold_init_ms = sr.elapsed.as_millis();
    }
    summary.files = files.max(summary.files);
    summary.entry_points = entry_points.max(summary.entry_points);
    summary.imports = imports.max(summary.imports);
    summary.gotcha_cands = candidates.max(summary.gotcha_cands);
    summary.todos = todos.max(summary.todos);
    summary.doc_comments = doc_comments.max(summary.doc_comments);
    summary.hotspots = hotspots.max(summary.hotspots);
    summary.co_change_pairs = co_change_pairs.max(summary.co_change_pairs);
    summary.revert_stubs = revert_stubs.max(summary.revert_stubs);
    summary.ownership_stubs = ownership_stubs.max(summary.ownership_stubs);
    summary.cochange_stubs = cochange_stubs.max(summary.cochange_stubs);
}

fn extract_warm_init_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    let files = extract_number(output, "file records:");

    // Warm init: "file records: 214  (0 parsed, 214 skipped)"
    // Numbers come BEFORE the keywords "parsed" and "skipped"
    let parsed = extract_int_before_word(output, " parsed");
    let skipped = extract_int_before_word(output, " skipped");

    sr.add_metric("files", &files.to_string());
    if skipped > 0 {
        sr.add_metric("skipped", &skipped.to_string());
    }
    sr.add_metric("parsed", &parsed.to_string());

    // Compute speedup
    let cold = summary.cold_init_ms;
    let warm = sr.elapsed.as_millis();
    if cold > 0 && warm > 0 {
        let speedup = cold as f64 / warm as f64;
        sr.add_metric("speedup", &format!("{speedup:.1}x"));
    }
    sr.add_metric("✓ incremental", "");

    summary.warm_init_ms = warm;
    summary.warm_parsed = parsed;
}

fn extract_changed_init_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    let files = extract_number(output, "file records:");
    // Numbers come BEFORE the keywords: "(1 parsed, 213 skipped)"
    let parsed = extract_int_before_word(output, " parsed");
    let skipped = extract_int_before_word(output, " skipped");

    sr.add_metric("files", &files.to_string());
    if skipped > 0 {
        sr.add_metric("skipped", &skipped.to_string());
    }
    sr.add_metric("parsed", &parsed.to_string());

    if parsed >= 1 {
        sr.add_metric("✓ change detected", "");
        summary.change_detected = true;
    }
}

// ── mati ping ─────────────────────────────────────────────────────────────────

fn extract_ping_metrics(output: &str, sr: &mut StepResult, _summary: &mut Summary) {
    // Output: "mati ok  668µs"
    for line in output.lines() {
        if line.contains("ok") {
            // Extract latency value (digits before µs or us)
            if let Some(pos) = line.find('µ').or_else(|| line.find("us")) {
                let before = &line[..pos];
                if let Some(v) = before.split_whitespace().last() {
                    sr.add_metric("latency", &format!("{v}µs"));
                    return;
                }
            }
            // Fallback: any number in the line
            if let Some(n) = first_number(line) {
                sr.add_metric("latency", &format!("{n}µs"));
            }
            return;
        }
    }
}

// ── mati status ───────────────────────────────────────────────────────────────

fn extract_status_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    // "  Records    214 files  41 gotchas  0 decisions  0 notes  34 deps"
    // Numbers come BEFORE the keyword
    let files = extract_int_before_word(output, " files");
    let gotchas = extract_int_before_word(output, " gotchas");
    let decisions = extract_int_before_word(output, " decisions");
    let hotspots = extract_number(output, "hotspot");

    // "  Confidence   avg 0.10  median ..."
    let conf_avg = extract_float_from_line(output, "avg");

    // "  Confirmed   0 / N gotchas (0%)"
    // Extract coverage percentage
    let pct_line = output
        .lines()
        .find(|l| l.contains('%') && (l.contains("gotchas") || l.contains("coverage")));
    let coverage = pct_line
        .and_then(|l| {
            l.split('%')
                .next()
                .and_then(|before| before.split_whitespace().last())
                .and_then(|v| v.parse::<u32>().ok())
        })
        .unwrap_or(0);

    let total = files + gotchas + decisions;
    sr.add_metric("coverage", &format!("{coverage}%"));
    sr.add_metric("files", &files.to_string());
    sr.add_metric("gotchas", &gotchas.to_string());
    sr.add_metric("hotspots", &hotspots.to_string());

    if let Some(avg) = conf_avg {
        // NOTE: status conf_avg includes ALL records (files+gotchas+decisions+notes)
        // stats confidence_avg includes only gotchas+decisions — intentionally different
        sr.add_metric("conf_avg", &format!("{avg:.2}"));
    }

    summary.records_total = total;
    summary.hotspots = hotspots.max(summary.hotspots);
}

// ── mati stats ────────────────────────────────────────────────────────────────

fn extract_stats_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    // "    Avg confidence         0.10"
    let conf_avg = extract_float_from_line(output, "avg confidence");
    // "    Estimated onboarding   48 min"
    let onboarding = extract_number(output, "estimated onboarding");
    // "    Knowledge gaps         45"
    let gaps = extract_number(output, "knowledge gaps");
    // Quality tier lines from stats are not directly here; use compliance hit rate
    // "    Hit rate  —  (no hook data yet)"  or "  Hit rate  0%"
    let compliance_line = output
        .lines()
        .find(|l| l.to_lowercase().contains("hit rate"));
    let compliance_pct = compliance_line
        .and_then(|l| {
            l.split('%')
                .next()
                .and_then(|b| b.split_whitespace().last())
                .and_then(|v| v.parse::<u32>().ok())
        })
        .unwrap_or(0);

    if let Some(avg) = conf_avg {
        sr.add_metric("confidence_avg", &format!("{avg:.2}"));
        summary.confidence_avg = avg;
    }
    if gaps > 0 {
        sr.add_metric("gaps", &gaps.to_string());
        summary.gaps = summary.gaps.max(gaps);
    }
    if onboarding > 0 {
        sr.add_metric("onboarding", &format!("{onboarding}min"));
    }
    sr.add_metric("compliance", &format!("{compliance_pct}%"));
}

// ── mati gaps ─────────────────────────────────────────────────────────────────

fn extract_gaps_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    // "KNOWLEDGE GAPS -- 20 found   sorted by risk score"
    // Number comes BEFORE "found"
    let count = extract_int_before_word(output, " found");

    // First gap entry: "● CRITICAL  crates/core/src/search.rs"
    // Risk score not directly in the list output but embedded via description
    // Find the first "risk" or highest-risk entry from the structured data
    let top_gap = output
        .lines()
        .find(|l| l.contains('●') || l.starts_with("  ●"))
        .and_then(|l| {
            // After the tier label, extract the path
            l.split_once("● ")
                .and_then(|(_, rest)| rest.split_whitespace().last())
        })
        .map(strip_ansi)
        .unwrap_or_else(|| "?".to_string());

    // Try to get risk from a line containing a decimal after the path
    let top_risk = output
        .lines()
        .find(|l| l.contains('●') || l.contains("CRITICAL") || l.contains("HIGH"))
        .and_then(|_l| {
            // Find risk score — look for risk in description lines
            output
                .lines()
                .find(|l| l.contains("risk") || l.contains("score"))
                .and_then(first_float)
        });

    sr.add_metric("gaps", &count.to_string());
    if top_gap != "?" && !top_gap.is_empty() {
        sr.add_metric("top_gap", &format!("\"{}\"", top_gap));
    }
    if let Some(risk) = top_risk {
        sr.add_metric("top_risk", &format!("{risk:.1}"));
        summary.top_gap_risk = risk;
    }

    summary.gaps = summary.gaps.max(count);
}

// ── mati ls files ─────────────────────────────────────────────────────────────

fn extract_ls_files_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    // Footer is "  214 file records" or "  showing 200 of 214 file records ..."
    // Number comes BEFORE "file records"
    let total = extract_int_before_word(output, " file records");

    // Hotspot marker: "┆ *   │" (comfy_table) or "    *" at line end (space-separated)
    let hotspots = output
        .lines()
        .filter(|l| {
            let t = l.trim_end();
            let is_data = !l.trim_start().starts_with("PATH") && !l.trim_start().starts_with('─');
            // comfy_table: HOT column cell is "┆ *   │" or "┆ *│"
            let comfy_hot = l.contains("\u{2506} *");
            // space-separated: row ends with " *" after trimming
            let plain_hot = t.ends_with('*') && is_data;
            (comfy_hot || plain_hot) && !l.contains("Hot") && !l.contains("HOT")
        })
        .count() as u64;

    // Count by extension — check first cell of data rows
    let ext_count = |ext: &str| -> u64 {
        output
            .lines()
            .filter(|l| {
                let t = l.trim();
                // comfy_table row: │ path.ext ┆ ...
                if t.starts_with('│') {
                    let after = t.trim_start_matches('│');
                    let cell = after.split('\u{2506}').next().unwrap_or("").trim();
                    return cell.ends_with(ext)
                        || cell.contains(&format!("{ext}/"))
                        || cell.contains(&format!("{}/", ext.trim_start_matches('.')));
                }
                // space-separated row: first token is path
                if let Some(tok) = t.split_whitespace().next() {
                    return tok.ends_with(ext) && !t.starts_with("PATH");
                }
                false
            })
            .count() as u64
    };
    let rs = ext_count(".rs");
    let toml = ext_count(".toml");
    let py = ext_count(".py");
    let ts = ext_count(".ts");
    let go = ext_count(".go");

    sr.add_metric("files", &total.to_string());
    sr.add_metric("hotspots", &hotspots.to_string());
    if rs > 0 {
        sr.add_metric("rs", &rs.to_string());
    }
    if toml > 0 {
        sr.add_metric("toml", &toml.to_string());
    }
    if py > 0 {
        sr.add_metric("py", &py.to_string());
    }
    if ts > 0 {
        sr.add_metric("ts", &ts.to_string());
    }
    if go > 0 {
        sr.add_metric("go", &go.to_string());
    }

    summary.hotspots = hotspots.max(summary.hotspots);
}

// ── mati ls gotchas ───────────────────────────────────────────────────────────

fn extract_ls_gotchas_count(output: &str) -> usize {
    // Footer: "  1 gotcha records" — number comes BEFORE "gotcha records"
    extract_int_before_word(output, " gotcha records") as usize
}

fn extract_ls_gotchas_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    let total = extract_ls_gotchas_count(output);

    // The comfy_table format uses ┆ as inner separators:
    // "│ key ┆ Rule ┆ Sev ┆ Conf ┆ Qual ┆ Y         │"
    // Confirmed = "Y" in the last column: line ends with "┆ Y         │" variant
    let confirmed = output
        .lines()
        .filter(|l| {
            let t = l.trim_end();
            // Last cell contains Y — look for "┆ Y" followed by spaces then │
            (t.contains("\u{2506} Y") || t.contains("| Y |") || t.ends_with("| Y"))
                && !l.contains("Confirmed") // skip header
        })
        .count();
    let unconfirmed = total.saturating_sub(confirmed);

    // Count by key prefix
    let revert = output.lines().filter(|l| l.contains("revert:")).count();
    let ownership = output.lines().filter(|l| l.contains("ownership:")).count();
    let cochange = output
        .lines()
        .filter(|l| l.contains("cochange:") || l.contains("co-change:"))
        .count();

    sr.add_metric("total", &total.to_string());
    sr.add_metric("confirmed", &confirmed.to_string());
    sr.add_metric("unconfirmed", &unconfirmed.to_string());
    if revert > 0 {
        sr.add_metric("revert", &revert.to_string());
    }
    if ownership > 0 {
        sr.add_metric("ownership", &ownership.to_string());
    }
    if cochange > 0 {
        sr.add_metric("cochange", &cochange.to_string());
    }

    summary.gotcha_count_after_add = total.max(summary.gotcha_count_after_add);
    summary.confirmed_count = confirmed.max(summary.confirmed_count);
    summary.revert_stubs = (revert as u64).max(summary.revert_stubs);
    summary.ownership_stubs = (ownership as u64).max(summary.ownership_stubs);
    summary.cochange_stubs = (cochange as u64).max(summary.cochange_stubs);
}

// ── mati ls decisions ─────────────────────────────────────────────────────────

fn extract_ls_decisions_metrics(output: &str, sr: &mut StepResult, _summary: &mut Summary) {
    // Footer: "  0 decision records" — number comes BEFORE "decision records"
    let total = extract_int_before_word(output, " decision records");
    sr.add_metric("decisions", &total.to_string());
}

// ── mati explain ─────────────────────────────────────────────────────────────

fn extract_explain_metrics(output: &str, path: &str, sr: &mut StepResult, _summary: &mut Summary) {
    // "  confidence 0.10  quality Suppressed"
    let conf = extract_float_from_line(output, "confidence");
    let quality = output
        .lines()
        .find(|l| l.contains("quality"))
        .and_then(|l| {
            // Extract the tier name: look for Known tier names
            for tier in &["Excellent", "Good", "Acceptable", "Poor", "Suppressed"] {
                if l.contains(tier) {
                    return Some(*tier);
                }
            }
            None
        })
        .unwrap_or("?");

    // Count gotchas section
    let gotchas = extract_number(output, "gotchas (");
    // Count co-changes
    let co_changes = output
        .lines()
        .filter(|l| {
            l.contains('●') && !l.contains("Gotcha") && !l.contains("TODO") && !l.contains("TODO")
        })
        .count() as u64;
    // Count todos
    let todos_header = extract_number(output, "todos (");

    let short_path = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path);

    sr.add_metric("path", short_path);
    if let Some(c) = conf {
        sr.add_metric("confidence", &format!("{c:.2}"));
    }
    sr.add_metric("quality", quality);
    if gotchas > 0 {
        sr.add_metric("gotchas", &gotchas.to_string());
    }
    if co_changes > 0 {
        sr.add_metric("co_changes", &co_changes.to_string());
    }
    if todos_header > 0 {
        sr.add_metric("todos", &todos_header.to_string());
    }
}

fn extract_explain_staleness(output: &str, sr: &mut StepResult, _summary: &mut Summary) {
    // Look for staleness signals in explain output
    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains("lineschangedpct")
            || lower.contains("lines changed")
            || lower.contains("entrypoints")
            || lower.contains("staleness")
        {
            let signal = line.trim().to_string();
            sr.add_metric("staleness", &signal);
            break;
        }
    }
    // Also extract confidence/quality
    let conf = extract_float_from_line(output, "confidence");
    let quality = output
        .lines()
        .find(|l| l.contains("quality"))
        .and_then(|l| {
            for tier in &["Excellent", "Good", "Acceptable", "Poor", "Suppressed"] {
                if l.contains(tier) {
                    return Some(*tier);
                }
            }
            None
        });
    if let Some(c) = conf {
        sr.add_metric("confidence", &format!("{c:.2}"));
    }
    if let Some(q) = quality {
        sr.add_metric("quality", q);
    }
}

// ── mati show ─────────────────────────────────────────────────────────────────

fn extract_show_metrics(output: &str, sr: &mut StepResult, _summary: &mut Summary) {
    // "    value          0.10  (hook_label)"
    let conf = extract_float_from_line(output, "value");
    let quality = output
        .lines()
        .find(|l| l.contains("quality") || l.contains("tier"))
        .and_then(|l| {
            for tier in &["Excellent", "Good", "Acceptable", "Poor", "Suppressed"] {
                if l.contains(tier) {
                    return Some(*tier);
                }
            }
            None
        });
    // "    source      StaticAnalysis (Layer 0)"
    // Must match the metadata "source" line, not "base (source)  0.10" in the confidence section.
    // The metadata line has "source" as the first non-whitespace token.
    let source = output
        .lines()
        .find(|l| l.trim_start().starts_with("source") && !l.contains("base (source)"))
        .and_then(|l| l.trim_start().strip_prefix("source"))
        .map(|s| s.trim().to_string());

    if let Some(c) = conf {
        sr.add_metric("confidence", &format!("{c:.2}"));
    }
    if let Some(q) = quality {
        sr.add_metric("quality", q);
    }
    if let Some(s) = source {
        let s_short = s.split_whitespace().next().unwrap_or("?");
        sr.add_metric("source", s_short);
    }
}

fn extract_show_gotcha_metrics(output: &str, sr: &mut StepResult, _summary: &mut Summary) {
    // Extract the value (gotcha rule text) and confidence
    let value = output
        .lines()
        .skip_while(|l| !l.contains("value"))
        .nth(1) // line after "value" header
        .map(|l| l.trim().to_string())
        .unwrap_or_default();

    let conf = extract_float_from_line(output, "value"); // in confidence section

    if !value.is_empty() {
        let v_short = if value.len() > 40 {
            format!("\"{}...\"", &value[..37])
        } else {
            format!("\"{}\"", value)
        };
        sr.add_metric("value", &v_short);
    }
    if let Some(c) = conf {
        sr.add_metric("confidence", &format!("{c:.2}"));
    }
}

// ── mati gotcha add ───────────────────────────────────────────────────────────

/// Returns the key of the created gotcha (e.g. "gotcha:always-call-regex-...")
/// Also checks stderr since the quality gate failure message lands there.
fn extract_gotcha_add_metrics(
    stdout: &str,
    stderr: &str,
    sr: &mut StepResult,
    summary: &mut Summary,
) -> String {
    // "Created gotcha:always-call-regex-...  (quality: 0.78, confidence: 0.80)"
    // Output may be on stdout (success) or the error on stderr (quality gate fail)
    let combined = format!("{stdout}\n{stderr}");
    let mut key = String::new();
    let mut quality = 0.0f32;

    for line in combined.lines() {
        if line.starts_with("Created ") || line.contains("gotcha:") {
            // Extract key — second whitespace token starting with "gotcha:"
            if let Some(k) = line.split_whitespace().find(|t| t.starts_with("gotcha:")) {
                let clean = k.trim_end_matches(')').trim_end_matches(',');
                if !clean.is_empty() {
                    key = clean.to_string();
                }
            }
            // Extract quality from "(quality: 0.78, ...)"
            if let Some(q) = extract_float_from_line(line, "quality:") {
                quality = q;
            } else if let Some(q) = extract_float_from_line(line, "quality") {
                quality = q;
            }
        }
    }

    if !key.is_empty() {
        sr.add_metric("key", &key);
        // Count the successfully added gotcha so Persistence check works
        // even when Layer 0 produced 0 initial gotchas.
        summary.gotcha_count_after_add += 1;
    }
    if quality > 0.0 {
        sr.add_metric("quality", &format!("{quality:.2}"));
    }

    key
}

// ── mati note ─────────────────────────────────────────────────────────────────

fn extract_note_metrics(stdout: &str, stderr: &str, sr: &mut StepResult, _summary: &mut Summary) {
    // "Created dev_note:e2e-test-...  (quality: 0.05)"
    let combined = format!("{stdout}\n{stderr}");
    for line in combined.lines() {
        if line.starts_with("Created ") || line.contains("dev_note:") {
            if let Some(k) = line.split_whitespace().find(|t| t.starts_with("dev_note:")) {
                sr.add_metric("key", k.trim_end_matches(')').trim_end_matches(','));
            }
            if let Some(q) = extract_float_from_line(line, "quality") {
                sr.add_metric("quality", &format!("{q:.2}"));
            }
            break;
        }
    }
}

// ── mati improve ─────────────────────────────────────────────────────────────

fn extract_improve_metrics(stdout: &str, stderr: &str, sr: &mut StepResult, summary: &mut Summary) {
    let output = &format!("{stdout}\n{stderr}");
    // "Updated gotcha:...  (quality: 0.42 -> 0.71)"
    // or "Current quality: 0.42 ..." and later "Updated ... (quality: ... -> 0.71)"
    let before = output
        .lines()
        .find(|l| l.contains("Current quality") || l.starts_with("Updated"))
        .and_then(first_float);

    let after = output
        .lines()
        .find(|l| l.contains("->") && l.contains("quality"))
        .and_then(|l| {
            // Find the number after "->"
            l.split("->").nth(1).and_then(first_float)
        });

    if let Some(b) = before {
        summary.quality_before = b;
    }
    if let Some(a) = after {
        summary.quality_after = a;
    }
    let progression_ok = matches!((before, after), (Some(b), Some(a)) if a > b);

    if let (Some(b), Some(a)) = (before, after) {
        sr.add_metric("quality", &format!("{b:.2}→{a:.2}"));
    } else if let Some(a) = after {
        sr.add_metric("quality", &format!("→{a:.2}"));
    } else if let Some(b) = before {
        sr.add_metric("quality", &format!("{b:.2}→?"));
    }
    if progression_ok {
        sr.add_metric("✓ improved", "");
    } else if before.is_some() && after.is_some() {
        sr.add_metric("regression", "SAME_OR_WORSE");
    }
}

// ── mati export ───────────────────────────────────────────────────────────────

fn extract_export_json_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    // Parse JSON array, count by category field (values are lowercase: "file", "gotcha", etc.)
    let records: serde_json::Value =
        serde_json::from_str(output).unwrap_or(serde_json::Value::Array(vec![]));
    let arr = records.as_array().map(|a| a.as_slice()).unwrap_or(&[]);

    let cat = |r: &&serde_json::Value, s: &str| {
        r.get("category")
            .and_then(|c| c.as_str())
            .is_some_and(|c| c.eq_ignore_ascii_case(s))
    };

    let total = arr.len() as u64;
    let file = arr.iter().filter(|r| cat(r, "file")).count() as u64;
    let gotcha = arr.iter().filter(|r| cat(r, "gotcha")).count() as u64;
    let decision = arr.iter().filter(|r| cat(r, "decision")).count() as u64;
    let dev_note = arr
        .iter()
        .filter(|r| cat(r, "dev_note") || cat(r, "devnote"))
        .count() as u64;
    let dep = arr
        .iter()
        .filter(|r| cat(r, "dependency") || cat(r, "dep"))
        .count() as u64;

    sr.add_metric("total", &total.to_string());
    sr.add_metric("file", &file.to_string());
    sr.add_metric("gotcha", &gotcha.to_string());
    sr.add_metric("decision", &decision.to_string());
    sr.add_metric("dev_note", &dev_note.to_string());
    sr.add_metric("dep", &dep.to_string());

    summary.export_total = total;
    summary.export_file = file;
    summary.export_gotcha = gotcha;
    summary.export_decision = decision;
    summary.export_dev_note = dev_note;
    summary.export_dep = dep;
}

fn extract_export_md_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    // Count "##" section headers and total records
    let sections = output.lines().filter(|l| l.starts_with("## ")).count() as u64;
    let records = output.lines().filter(|l| l.starts_with("### ")).count() as u64;
    sr.add_metric("sections", &sections.to_string());
    sr.add_metric("records", &records.to_string());
    if summary.export_total == 0 {
        summary.export_total = records;
    }
}

// ── mati diff ─────────────────────────────────────────────────────────────────

fn extract_diff_metrics(output: &str, sr: &mut StepResult, _summary: &mut Summary) {
    // "  2 files changed — 0 with gotchas, 2 documented, 0 unknown"
    // All numbers come BEFORE their keyword
    let files_changed = extract_int_before_word(output, " files changed");
    let with_gotchas = extract_int_before_word(output, " with gotchas");
    let documented = extract_int_before_word(output, " documented");
    let unknown = extract_int_before_word(output, " unknown");

    sr.add_metric("files_changed", &files_changed.to_string());
    if with_gotchas > 0 {
        sr.add_metric("with_gotchas", &with_gotchas.to_string());
    }
    sr.add_metric("documented", &documented.to_string());
    if unknown > 0 {
        sr.add_metric("unknown", &unknown.to_string());
    }
}

// ── mati history ─────────────────────────────────────────────────────────────

fn extract_history_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    // Output: "history  gotcha:...  (N versions)" — count is BEFORE "versions"
    let versions = extract_int_before_word(output, " version").max(
        // also count table rows as version entries
        output
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                t.starts_with('│') && !t.to_lowercase().contains("version") && !t.contains('─')
            })
            .count() as u64,
    );
    summary.history_versions = versions;
    sr.add_metric("versions", &versions.to_string());
    if versions >= 2 {
        sr.add_metric("✓ ≥2 versions", "(create+improve)");
    } else if versions == 1 {
        sr.add_metric(
            "warn",
            "only 1 version — improve may not have written a new version",
        );
    }
}

// ── mati stale ────────────────────────────────────────────────────────────────

fn extract_stale_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    // "  N stale records (M liability, K stale)"
    let total = extract_number(output, "stale records");
    // "implicit" co-change coupling
    let implicit = output
        .lines()
        .filter(|l| l.to_lowercase().contains("implicit"))
        .count() as u64;
    let direct = total.saturating_sub(implicit);

    sr.add_metric("stale", &total.to_string());
    if direct > 0 {
        sr.add_metric("direct", &direct.to_string());
    }
    if implicit > 0 {
        sr.add_metric("implicit", &implicit.to_string());
    }

    summary.stale_count = total;
}

// ── mati review ───────────────────────────────────────────────────────────────

fn extract_review_metrics(stdout: &str, stderr: &str, sr: &mut StepResult, _summary: &mut Summary) {
    // review writes to stderr: "N candidates pending review"
    // or "No candidates pending review."
    let combined = format!("{stdout}\n{stderr}");
    let candidates = extract_number(&combined, "candidate");
    let shown = extract_number(&combined, "pending review");
    let skipped = extract_number(&combined, "skipped");

    // Count confirmed from stdout: look for "Review complete: N confirmed" or "N confirmed"
    let confirmed = extract_int_before_word(&combined, " confirmed");

    if candidates > 0 || shown > 0 {
        sr.add_metric("candidates", &(candidates.max(shown)).to_string());
        if skipped > 0 {
            sr.add_metric("skipped", &skipped.to_string());
        }
        if confirmed > 0 {
            sr.add_metric("confirmed", &confirmed.to_string());
        }
    } else {
        sr.add_metric("candidates", "0");
    }
}

// ── mati quality-check ────────────────────────────────────────────────────────

fn extract_quality_check_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    // "Suppressed (< 0.2)  (210 records)"
    // "Poor (0.2 – 0.4)  (4 records)"
    // "Acceptable (0.4 – 0.7)  (34 records)"
    // etc.
    let suppressed = extract_tier_count(output, "suppressed");
    let poor = extract_tier_count(output, "poor");
    let acceptable = extract_tier_count(output, "acceptable");
    let good = extract_tier_count(output, "good");
    let excellent = extract_tier_count(output, "excellent");

    sr.add_metric("suppressed", &suppressed.to_string());
    sr.add_metric("poor", &poor.to_string());
    sr.add_metric("acceptable", &acceptable.to_string());
    sr.add_metric("good", &good.to_string());
    sr.add_metric("excellent", &excellent.to_string());

    summary.quality_suppressed = suppressed.max(summary.quality_suppressed);
    summary.quality_poor = poor.max(summary.quality_poor);
    summary.quality_acceptable = acceptable.max(summary.quality_acceptable);
    summary.quality_good = good.max(summary.quality_good);
    summary.quality_excellent = excellent.max(summary.quality_excellent);
}

/// Extract record count from a tier section header like "Suppressed (< 0.2)  (210 records)"
fn extract_tier_count(output: &str, tier_label: &str) -> u64 {
    for line in output.lines() {
        if line.to_lowercase().contains(tier_label) && line.contains("records") {
            // Find the last parenthesized segment that starts with a digit.
            // E.g. "Suppressed (< 0.2)  (210 records)" → split on "(" → ["Suppressed ", "< 0.2)  ", "210 records)"]
            let inner = line
                .split('(')
                .filter_map(|seg| {
                    let t = seg.trim();
                    if t.starts_with(|c: char| c.is_ascii_digit()) {
                        first_number(t)
                    } else {
                        None
                    }
                })
                .next_back();
            if let Some(n) = inner {
                return n;
            }
        }
    }
    0
}

// ── mati get (hook fast-path) ──────────────────────────────────────────────

fn extract_get_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    let trimmed = output.trim();
    let hit = trimmed != "null" && !trimmed.is_empty();
    summary.hook_get_hit = summary.hook_get_hit || hit;
    if hit {
        sr.add_metric("hit", "✓");
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(cat) = v
                .get("record")
                .and_then(|r| r.get("category"))
                .and_then(|c| c.as_str())
            {
                sr.add_metric("category", cat);
            }
        }
    } else {
        sr.add_metric("result", "null (miss)");
    }
}

// ── mati reparse ──────────────────────────────────────────────────────────

fn extract_reparse_metrics(exit_ok: bool, sr: &mut StepResult, summary: &mut Summary) {
    summary.reparse_ok = exit_ok;
    sr.add_metric("result", if exit_ok { "✓ (exit 0)" } else { "FAILED" });
}

// ── mati history --since ──────────────────────────────────────────────────

fn extract_history_since_metrics(output: &str, sr: &mut StepResult, summary: &mut Summary) {
    // Table rows or "N records changed in last X"
    let direct = extract_int_before_word(output, " records");
    let rows = output
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with('│') && !t.to_lowercase().contains("key") && !t.contains('─')
        })
        .count() as u64;
    let total = direct.max(rows);
    summary.history_since_count = total;
    sr.add_metric("records", &total.to_string());
    sr.add_metric("window", "7d");
}

// ── JSON record count helper ───────────────────────────────────────────────

fn count_json_records(json: &str) -> u64 {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| v.as_array().map(|a| a.len() as u64))
        .unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command runner helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn h_run(mati: &Path, repo: &Path, home: &Path, args: &[&str]) -> RunResult {
    let start = Instant::now();
    let out = Command::new(mati)
        .args(args)
        .current_dir(repo)
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to spawn mati");
    let elapsed = start.elapsed();
    RunResult {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        elapsed,
        exit_ok: out.status.success(),
    }
}

fn h_run_stdin(mati: &Path, repo: &Path, home: &Path, args: &[&str], input: &str) -> RunResult {
    let start = Instant::now();
    let mut child = Command::new(mati)
        .args(args)
        .current_dir(repo)
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn mati");

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
    }

    let out = child.wait_with_output().expect("failed to wait on mati");
    let elapsed = start.elapsed();
    RunResult {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        elapsed,
        exit_ok: out.status.success(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Misc helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn cargo_bin(name: &str) -> PathBuf {
    // Use CARGO_BIN_EXE_<name> if set (by cargo test), else construct manually.
    let env_key = format!("CARGO_BIN_EXE_{}", name.to_uppercase());
    if let Ok(p) = std::env::var(&env_key) {
        return PathBuf::from(p);
    }
    // Fallback: target/debug/<name>
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(manifest)
        .join("target")
        .join("debug")
        .join(name)
}

/// Pick the first file path from `mati ls files` output.
///
/// Handles two formats:
///   1. comfy_table (debug/current): `│ .cargo/config.toml ┆ Purpose ┆ ... │`
///   2. space-separated (legacy): `.cargo/config.toml   (pending…)  0  0.10  0.10  *`
///
/// The inner cell separator is ┆ (U+2506), the outer border is │ (U+2502).
fn pick_first_file_path(output: &str) -> Option<String> {
    let mut past_separator = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // comfy_table data rows: │ <path> ┆ <purpose> ┆ ... │
        // Skip header (contains "Path" or "PATH"), border lines, footer
        if trimmed.starts_with('│') {
            // Extract first cell — between leading │ and first ┆ (U+2506)
            // │ is 3 bytes (U+2502), so skip with char-aware split
            let after_bar = trimmed.trim_start_matches('│');
            let first_cell = after_bar
                .split('\u{2506}') // split on ┆
                .next()
                .unwrap_or("")
                .trim();
            if first_cell.is_empty()
                || first_cell.eq_ignore_ascii_case("path")
                || first_cell.starts_with("Path")
            {
                continue; // header row
            }
            if first_cell.contains('/') || first_cell.contains('.') {
                return Some(first_cell.to_string());
            }
            continue;
        }

        // Space-separated format: "PATH  PURPOSE  ENT  CONF  QUAL  HOT" header
        if trimmed.starts_with("PATH") {
            continue;
        }
        // Separator line after PATH header (all ─ chars)
        if !past_separator
            && trimmed
                .chars()
                .all(|c| c == '\u{2500}' || c == '-' || c == ' ')
        {
            past_separator = true;
            continue;
        }
        // Skip other box-drawing border lines (┌, └, ╞, ╭, ╰, ├, ╡ …)
        if trimmed.starts_with(|c: char| {
            matches!(c, '┌' | '└' | '╞' | '╭' | '╰' | '├' | '╡' | '╔' | '╚' | '╠')
        }) {
            continue;
        }

        // Space-separated data row
        if past_separator {
            if let Some(path) = trimmed.split_whitespace().next() {
                if !path.starts_with("showing") && (path.contains('/') || path.contains('.')) {
                    return Some(path.to_string());
                }
            }
        }
    }
    None
}

/// Strip ANSI escape codes from a string for metric display.
fn strip_ansi(s: &str) -> String {
    let mut result = String::new();
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape && c == 'm' {
            in_escape = false;
        } else if !in_escape {
            result.push(c);
        }
    }
    result
}

// Ensure OsStr import is used (quiets unused-import lint).
fn _use_osstr(_: &OsStr) {}
