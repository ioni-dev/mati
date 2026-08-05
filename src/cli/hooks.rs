//! Internal CLI commands invoked by hook scripts (M-09-G).
//!
//! All commands here are hidden from `--help` and called by bash hook scripts
//! in `.claude/hooks/` and `.codex/hooks/`.
//!
//! **Socket-only with fail-open:** Hook commands NEVER open the store directly.
//! They route exclusively through the daemon socket (MCP server or standalone
//! daemon). If the socket is unreachable, they return a safe default and exit 0.
//!
//! This eliminates the TOCTOU race where hooks, the MCP server, and auto-spawned
//! daemons competed for the SurrealKV exclusive flock during session startup.
//!
//! User-facing commands (explain, status, gotcha, etc.) are unaffected — they
//! use `StoreProxy` which has daemon-first, store-fallback semantics.

use anyhow::Result;
use std::{future::Future, time::Duration};

use crate::cli::daemon::{daemon_result, mati_root_for, DaemonResult};
use crate::cli::hook_decide::{log_fail_open_named, HookRunOutcome};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Run a blocking hook operation with a fail-open deadline.
///
/// The timeout drops only the client-side future. The daemon serves each
/// connection independently, so abandoning the response wait cannot interrupt
/// another hook or corrupt the daemon's state.
pub(crate) async fn run_with_deadline<F>(
    hook: &str,
    rel_path: &str,
    deadline_ms: u64,
    reason: &str,
    operation: F,
) -> Result<HookRunOutcome>
where
    F: Future<Output = Result<()>>,
{
    match tokio::time::timeout(Duration::from_millis(deadline_ms), operation).await {
        Ok(result) => result.map(|()| HookRunOutcome::Continue),
        Err(_) => {
            log_fail_open_named(hook, rel_path, reason);
            Ok(HookRunOutcome::Terminate(0))
        }
    }
}

/// Fire-and-forget with a typed v2 Command. Preferred for mutation/side-effecting calls.
async fn hook_fire_v2(cmd: mati_core::mcp::protocol::Command) -> Result<()> {
    let kind = cmd.kind();
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;
    match super::daemon::daemon_v2(&root, cmd).await {
        DaemonResult::Ok(_) => {}
        _ => tracing::debug!("mati {kind}: daemon unreachable — dropping event"),
    }
    Ok(())
}

/// Query the daemon for a boolean value, returning `false` on failure.
///
/// Used by consultation-receipt checks where the conservative default
/// (not consulted) causes hooks to deny or advise — correct fail-open.
async fn hook_query_bool(cmd: &str, args: serde_json::Value) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;
    match daemon_result(&root, cmd, args).await {
        DaemonResult::Ok(resp) => {
            if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                let value = resp.get("data").and_then(|v| v.as_bool()).unwrap_or(false);
                println!("{value}");
            } else {
                // Daemon-side error: consultation state is UNKNOWN, and the
                // daemon is reachable — printing "false" here would make the
                // compliance script record a false ComplianceMiss (and that
                // event WOULD land, unlike the unreachable arm below where
                // the follow-up log command fails too). Scripts compare
                // against the literal "false", so "unknown" means no-op.
                tracing::debug!("mati {cmd}: daemon error — consultation state unknown");
                println!("unknown");
            }
        }
        _ => {
            tracing::debug!("mati {cmd}: daemon unreachable — false");
            println!("false");
        }
    }
    Ok(())
}

// ── M-09-prereq: mati get --json ────────────────────────────────────────────

/// Fetch a record by key. Prints JSON or `"null"`.
///
/// This is the only hook command with custom response handling — it extracts
/// the `data` field from the daemon response and prints it directly.
pub async fn run_get(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    match daemon_result(&root, "get", serde_json::json!({ "key": key })).await {
        DaemonResult::Ok(resp) => {
            // An `{"ok": false}` error envelope also lands here and prints
            // "null" — deliberate: get is a pure read whose script consumers
            // treat null as "no record" (fail-open, no false audit event).
            let json = match resp.get("data") {
                Some(d) if d.is_null() => "null".to_string(),
                Some(d) => d.to_string(),
                None => "null".to_string(),
            };
            println!("{json}");
        }
        _ => {
            tracing::debug!("mati get: daemon unreachable — fail-open (null)");
            println!("null");
        }
    }
    Ok(())
}

// ── Fire-and-forget hook commands ────────────────────────────────────────────

pub async fn run_log_miss(key: &str) -> Result<()> {
    use mati_core::mcp::protocol as p;
    hook_fire_v2(p::Command::SessionLog(p::SessionLogInput {
        event: p::SessionEvent::Miss,
        key: key.to_string(),
        session_id: None,
        actor: None,
        decision_basis_hash: None,
    }))
    .await
}

pub async fn run_log_hit(key: &str) -> Result<()> {
    use mati_core::mcp::protocol as p;
    hook_fire_v2(p::Command::ConsultationHit(p::ConsultationHitInput {
        key: key.to_string(),
        capture_fingerprint: true,
        actor: None,
        session_id: None,
        agent_id: None,
        decision_basis_hash: None,
    }))
    .await
}

pub async fn run_log_compliance_miss(key: &str) -> Result<()> {
    use mati_core::mcp::protocol as p;
    hook_fire_v2(p::Command::SessionLog(p::SessionLogInput {
        event: p::SessionEvent::ComplianceMiss,
        key: key.to_string(),
        session_id: None,
        actor: None,
        decision_basis_hash: None,
    }))
    .await
}

pub async fn run_log_compliance_hit(key: &str) -> Result<()> {
    use mati_core::mcp::protocol as p;
    hook_fire_v2(p::Command::SessionLog(p::SessionLogInput {
        event: p::SessionEvent::ComplianceHit,
        key: key.to_string(),
        session_id: None,
        actor: None,
        decision_basis_hash: None,
    }))
    .await
}

pub async fn run_log_codex_shell_miss(key: &str) -> Result<()> {
    use mati_core::mcp::protocol as p;
    hook_fire_v2(p::Command::SessionLog(p::SessionLogInput {
        event: p::SessionEvent::CodexShellMiss,
        key: key.to_string(),
        session_id: None,
        actor: None,
        decision_basis_hash: None,
    }))
    .await
}

pub async fn run_log_bootstrap(key: &str) -> Result<()> {
    use mati_core::mcp::protocol as p;
    hook_fire_v2(p::Command::SessionLog(p::SessionLogInput {
        event: p::SessionEvent::Bootstrap,
        key: key.to_string(),
        session_id: None,
        actor: None,
        decision_basis_hash: None,
    }))
    .await
}

pub async fn run_log_prompt_nudge(key: &str) -> Result<()> {
    use mati_core::mcp::protocol as p;
    hook_fire_v2(p::Command::SessionLog(p::SessionLogInput {
        event: p::SessionEvent::PromptNudge,
        key: key.to_string(),
        session_id: None,
        actor: None,
        decision_basis_hash: None,
    }))
    .await
}

pub async fn run_session_flush() -> Result<HookRunOutcome> {
    // SessionFlush is one durable transaction, not an enforcement read gate.
    // Allow 5000ms for a slow store commit or daemon scheduling, still half of
    // the old 10s transport stall (10000 - 5000 = 5000ms saved) and long
    // enough to avoid cargo-culting the 2500ms read deadline onto a
    // persistence path. The timer starts after startup; with no 4s ceiling,
    // startup is not added to a host budget here.
    const SESSION_FLUSH_DEADLINE_MS: u64 = 5000;

    // Named for the command, not a hook: both pre-compact.sh and stop.sh run
    // `mati session-flush`, so a hook-shaped label would misattribute every
    // Stop-hook stall to PreCompact. 5000ms clears both — pre-compact's 7s
    // ceiling with startup (5000 + 1050 < 7000), and Stop, which is async and
    // has no ceiling at all.
    run_with_deadline(
        "session-flush",
        "<session-flush>",
        SESSION_FLUSH_DEADLINE_MS,
        "session flush exceeded internal deadline",
        hook_fire_v2(mati_core::mcp::protocol::Command::SessionFlush),
    )
    .await
}

pub async fn run_session_harvest() -> Result<HookRunOutcome> {
    // The scaffold kills SessionEnd at 4s. Startup elapses BEFORE this timer
    // starts (~115ms warm, ~1050ms on a binary not yet page-cached), so it is
    // subtracted from the ceiling, not spent inside the deadline: 4000 - 1050
    // leaves ~2950ms. 2500 matches `HOOK_DEADLINE_MS` and keeps 450ms back.
    // The harvest needs ~2250ms of that — a 2000ms staleness budget plus the
    // round trip — so the deadline fires only when the budget overruns, which
    // it can: the staleness scan gates on record *start*, not completion.
    const SESSION_END_DEADLINE_MS: u64 = 2500;

    run_with_deadline(
        "session-end",
        "<session-harvest>",
        SESSION_END_DEADLINE_MS,
        "session harvest exceeded internal deadline",
        hook_fire_v2(mati_core::mcp::protocol::Command::SessionHarvest),
    )
    .await
}

pub async fn run_session_clear_consults() -> Result<HookRunOutcome> {
    // Clearing receipts is a best-effort scan/delete after compaction. It is
    // not on the enforcement ceiling, but 3000ms bounds a large receipt set
    // without making the advisory cleanup wait through the 10s transport cap
    // (10000 - 3000 = 7000ms saved). The timer starts after startup, and there
    // is no 4s host ceiling to subtract startup from.
    const POST_COMPACT_DEADLINE_MS: u64 = 3000;

    run_with_deadline(
        "post-compact",
        "<session-clear-consults>",
        POST_COMPACT_DEADLINE_MS,
        "post-compact receipt cleanup exceeded internal deadline",
        hook_fire_v2(mati_core::mcp::protocol::Command::SessionClearConsults),
    )
    .await
}

/// Combined log-hit + reparse in a single daemon round-trip.
/// Called by post-edit.sh hook to avoid two separate process spawns.
pub async fn run_edit_hook(path: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let rel = std::path::Path::new(path)
        .strip_prefix(&cwd)
        .map(|r| r.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string());
    hook_fire_v2(mati_core::mcp::protocol::Command::FileEditHook(
        mati_core::mcp::protocol::FileEditHookInput { path: rel },
    ))
    .await
}

/// Path-only doc capture. Daemon reads file from disk.
pub async fn run_doc_capture(path: &str) -> Result<()> {
    // NOTE: stdin content is no longer piped. The v2 DocCapture command is
    // path-only — the daemon reads the file from disk.
    // Drain stdin to avoid broken pipe if the hook script still pipes content.
    use std::io::Read as _;
    let _ = std::io::stdin().read_to_end(&mut Vec::new());
    hook_fire_v2(mati_core::mcp::protocol::Command::DocCapture(
        mati_core::mcp::protocol::DocCaptureInput {
            path: path.to_string(),
        },
    ))
    .await
}

// ── Boolean query hook commands ──────────────────────────────────────────────

pub async fn run_session_check_consulted(key: &str) -> Result<()> {
    hook_query_bool("session_check_consulted", serde_json::json!({ "key": key })).await
}

pub async fn run_session_check_consulted_recent(key: &str, ttl_secs: u64) -> Result<()> {
    hook_query_bool(
        "session_check_consulted_recent",
        serde_json::json!({ "key": key, "ttl_secs": ttl_secs }),
    )
    .await
}

// ── Prompt context (Codex UserPromptSubmit) ──────────────────────────────────

/// Fetch bootstrap context for the given files via a single daemon socket call.
///
/// Used by the Codex UserPromptSubmit hook. Returns the bootstrap markdown
/// injection string (gotchas, co-change pairs, file context) for the given
/// files. Prints empty string on failure (fail-open).
pub async fn run_prompt_context(files: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = crate::cli::daemon::mati_root_for(&cwd)?;
    let cmd = mati_core::mcp::protocol::Command::MemBootstrap(
        mati_core::mcp::protocol::MemBootstrapInput {
            context_files: files.to_vec(),
        },
    );
    match crate::cli::daemon::daemon_v2(&root, cmd).await {
        crate::cli::daemon::DaemonResult::Ok(resp)
            if resp.get("ok") == Some(&serde_json::Value::Bool(true)) =>
        {
            if let Some(data) = resp.get("data") {
                // data is a JSON string containing the bootstrap markdown
                let text = data.as_str().unwrap_or("");
                print!("{text}");
            }
        }
        _ => {
            // Fail-open: no context injected
        }
    }
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use mati_core::store::session::*;
    use mati_core::store::*;
    use tempfile::TempDir;

    fn extract_confirmed(record: &Record) -> bool {
        if record.category != Category::Gotcha {
            return false;
        }
        record
            .payload_as::<GotchaRecord>()
            .map(|g| g.confirmed)
            .unwrap_or(false)
    }

    async fn temp_store() -> (TempDir, Store) {
        crate::cli::ensure_test_home();
        let dir = TempDir::new().expect("tempdir");
        let store = Store::open(dir.path()).await.expect("open store");
        (dir, store)
    }

    #[tokio::test]
    async fn extract_confirmed_returns_true_for_confirmed_gotcha() {
        let mut record = Record {
            key: "gotcha:test".to_string(),
            value: "test".to_string(),
            category: Category::Gotcha,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 0,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: Some(serde_json::json!({
                "rule": "test rule",
                "reason": "test reason",
                "severity": "normal",
                "affected_files": [],
                "confirmed": true
            })),
        };
        assert!(extract_confirmed(&record));
        // Non-gotcha should return false
        record.category = Category::File;
        assert!(!extract_confirmed(&record));
    }

    #[tokio::test]
    async fn upsert_daily_agg_caps_keys_at_100() {
        let (_dir, store) = temp_store().await;
        let agg_key = today_key("analytics:test_cap_");
        for i in 0..120 {
            upsert_daily_agg(&store, &agg_key, &format!("key_{i}"))
                .await
                .unwrap();
        }
        let record = store.get(&agg_key).await.unwrap().unwrap();
        let agg = record.payload_as::<DailyAgg>().unwrap();
        assert_eq!(agg.count, 120);
        assert_eq!(agg.keys.len(), MAX_AGG_KEYS);
        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn promote_gotcha_candidates_confirms_above_threshold() {
        let (_dir, store) = temp_store().await;
        let record = Record {
            key: "gotcha:promote-test".to_string(),
            value: "test".to_string(),
            category: Category::Gotcha,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 0,
            },
            quality: QualityScore::layer0_default(),
            access_count: GOTCHA_PROMOTION_ACCESS_THRESHOLD,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: Some(serde_json::json!({
                "rule": "test rule",
                "reason": "test reason",
                "severity": "normal",
                "affected_files": [],
                "confirmed": false
            })),
        };
        store.put(&record.key, &record).await.unwrap();
        let promoted = mati_core::store::session::promote_gotcha_candidates(&store)
            .await
            .unwrap();
        assert_eq!(promoted, 1);
        let updated = store.get("gotcha:promote-test").await.unwrap().unwrap();
        let gotcha = updated.payload_as::<GotchaRecord>().unwrap();
        assert!(gotcha.confirmed);
        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn stale_review_truncates_to_max() {
        let (_dir, store) = temp_store().await;
        // Create 30 records with staleness in [0.4, 0.7) range
        for i in 0..30 {
            let key = format!("file:test_{i}.rs");
            let record = Record {
                key: key.clone(),
                value: format!("test file {i}"),
                category: Category::File,
                priority: Priority::Normal,
                tags: vec![],
                created_at: 0,
                updated_at: 0,
                ref_url: None,
                staleness: StalenessScore {
                    value: 0.5,
                    tier: StalenessTier::Stale,
                    signals: vec![],
                    computed_at: 0,
                    last_record_sha: String::new(),
                },
                lifecycle: RecordLifecycle::Active,
                version: RecordVersion {
                    device_id: uuid::Uuid::new_v4(),
                    logical_clock: 1,
                    wall_clock: 0,
                },
                quality: QualityScore::layer0_default(),
                access_count: 0,
                last_accessed: 0,
                source: RecordSource::StaticAnalysis,
                confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
                gap_analysis_score: 0.0,
                payload: None,
            };
            store.put(&key, &record).await.unwrap();
        }
        let keys: Vec<String> = (0..30).map(|i| format!("file:test_{i}.rs")).collect();
        let entries = collect_stale_entries(&store, &keys).await.unwrap();
        assert!(entries.len() <= MAX_STALE_REVIEW_ENTRIES);
        store.close().await.unwrap();
    }
}
