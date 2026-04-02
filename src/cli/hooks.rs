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

use crate::cli::daemon::{daemon_result, mati_root_for, DaemonResult};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Fire-and-forget: send a command to the daemon socket, drop silently on failure.
///
/// Used by all hook analytics/logging commands where data loss is acceptable
/// under P9 graceful degradation.
async fn hook_fire_and_forget(cmd: &str, args: serde_json::Value) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;
    match daemon_result(&root, cmd, args).await {
        DaemonResult::Ok(_) => {}
        _ => tracing::debug!("mati {cmd}: daemon unreachable — dropping event"),
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
            let value = resp.get("data").and_then(|v| v.as_bool()).unwrap_or(false);
            println!("{value}");
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
    hook_fire_and_forget("log_miss", serde_json::json!({ "key": key })).await
}

pub async fn run_log_hit(key: &str) -> Result<()> {
    hook_fire_and_forget("log_hit", serde_json::json!({ "key": key })).await
}

pub async fn run_log_compliance_miss(key: &str) -> Result<()> {
    hook_fire_and_forget("log_compliance_miss", serde_json::json!({ "key": key })).await
}

pub async fn run_log_compliance_hit(key: &str) -> Result<()> {
    hook_fire_and_forget("log_compliance_hit", serde_json::json!({ "key": key })).await
}

pub async fn run_log_codex_shell_miss(key: &str) -> Result<()> {
    hook_fire_and_forget("log_codex_shell_miss", serde_json::json!({ "key": key })).await
}

pub async fn run_log_bootstrap(key: &str) -> Result<()> {
    hook_fire_and_forget("log_bootstrap", serde_json::json!({ "key": key })).await
}

pub async fn run_log_prompt_nudge(key: &str) -> Result<()> {
    hook_fire_and_forget("log_prompt_nudge", serde_json::json!({ "key": key })).await
}

pub async fn run_session_flush() -> Result<()> {
    hook_fire_and_forget("session_flush", serde_json::json!({})).await
}

pub async fn run_session_harvest() -> Result<()> {
    hook_fire_and_forget("session_harvest", serde_json::json!({})).await
}

/// Combined log-hit + reparse in a single daemon round-trip.
/// Called by post-edit.sh hook to avoid two separate process spawns.
pub async fn run_edit_hook(path: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    // Normalize to repo-relative. post-edit.sh passes absolute paths;
    // store keys always use relative (e.g. "file:src/main.rs").
    let rel = std::path::Path::new(path)
        .strip_prefix(&cwd)
        .map(|r| r.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string());
    hook_fire_and_forget("edit_hook", serde_json::json!({ "path": rel })).await
}

/// Read file content from stdin, detect doc comment, update file record.
pub async fn run_doc_capture(path: &str) -> Result<()> {
    use std::io::Read as _;
    let mut content = String::new();
    std::io::stdin().read_to_string(&mut content)?;
    hook_fire_and_forget(
        "doc_capture",
        serde_json::json!({ "path": path, "content": content }),
    )
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
    match crate::cli::daemon::daemon_result(
        &root,
        "mem_bootstrap",
        serde_json::json!({ "context_files": files }),
    )
    .await
    {
        crate::cli::daemon::DaemonResult::Ok(resp) => {
            if resp.get("ok") == Some(&serde_json::Value::Bool(true)) {
                if let Some(data) = resp.get("data") {
                    // data is a JSON string containing the bootstrap markdown
                    let text = data.as_str().unwrap_or("");
                    print!("{text}");
                }
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
