use std::collections::HashSet;
use std::io::{self, BufRead, IsTerminal, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::{Args, Subcommand};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, Color, ContentArrangement, Table};
use slugify::slugify;

use mati_core::graph::{EdgeKind, Graph};
use mati_core::health::quality;
use mati_core::store::{
    Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore, Store, TombstoneReason,
};

use crate::cli::daemon::{daemon_result, mati_root_for, DaemonResult};

#[derive(Args)]
pub struct GotchaArgs {
    #[command(subcommand)]
    pub command: GotchaCommand,
}

#[derive(Subcommand)]
pub enum GotchaCommand {
    /// Add a new gotcha for a file
    Add {
        /// File path to add gotcha for (e.g., "src/store/db.rs")
        file: String,
    },
    /// Edit an existing gotcha (pre-filled prompts — empty input keeps current value)
    Edit {
        /// Gotcha key (e.g., "gotcha:session-token-expiry" or just "session-token-expiry")
        key: String,
    },
    /// Delete a gotcha (soft-delete — tombstones the record and removes graph edges)
    Delete {
        /// Gotcha key (e.g., "gotcha:session-token-expiry" or just "session-token-expiry")
        key: String,
    },
}

pub async fn run(args: GotchaArgs) -> Result<()> {
    match args.command {
        GotchaCommand::Add { file } => run_gotcha_add(&file).await,
        GotchaCommand::Edit { key } => run_gotcha_edit(&normalize_key(&key)).await,
        GotchaCommand::Delete { key } => run_gotcha_delete(&normalize_key(&key)).await,
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn normalize_key(key: &str) -> String {
    if key.starts_with("gotcha:") {
        key.to_string()
    } else {
        format!("gotcha:{key}")
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Scan gotcha:* and return records whose affected_files include `file`.
async fn existing_gotchas_for_file(store: &Store, file: &str) -> Result<Vec<Record>> {
    let all = store.scan_prefix("gotcha:").await?;
    Ok(all
        .into_iter()
        .filter(|r| {
            if !matches!(r.lifecycle, RecordLifecycle::Active) {
                return false;
            }
            if let Some(g) = r.payload_as::<GotchaRecord>() {
                g.affected_files.iter().any(|af| af == file)
            } else {
                false
            }
        })
        .collect())
}

fn print_existing_gotchas(records: &[Record], file: &str, use_color: bool) {
    let n = records.len();
    let label = if n == 1 { "gotcha" } else { "gotchas" };

    if use_color {
        eprintln!(
            "\n  {}Existing knowledge for {}{}  ({n} {label})",
            super::colors::BLUE,
            file,
            super::colors::RESET,
        );
    } else {
        eprintln!("\n  Existing knowledge for {file}  ({n} {label})");
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Key"),
            Cell::new("Conf"),
            Cell::new("Rule"),
        ]);

    if !use_color {
        table.force_no_tty();
    }

    for r in records {
        let rule = if let Some(g) = r.payload_as::<GotchaRecord>() {
            g.rule
        } else {
            r.value.clone()
        };
        let truncated = if rule.len() > 60 {
            format!("{}…", &rule[..59])
        } else {
            rule
        };
        table.add_row(vec![
            Cell::new(&r.key).fg(Color::Cyan),
            Cell::new(format!("{:.2}", r.confidence.value)).fg(Color::Grey),
            Cell::new(truncated),
        ]);
    }

    eprintln!("{table}");
}

// ── Daemon helpers ─────────────────────────────────────────────────────────────

/// Return existing gotcha records for `file` via the daemon socket.
/// Falls back to an empty list on any error (display is best-effort).
async fn existing_gotchas_via_daemon(
    root: &std::path::Path,
    file: &str,
) -> Vec<Record> {
    let res = daemon_result(root, "scan_prefix", serde_json::json!({"prefix": "gotcha:"})).await;
    if let DaemonResult::Ok(resp) = res {
        if resp.get("ok") == Some(&serde_json::Value::Bool(true)) {
            if let Some(arr) = resp.get("data").and_then(|v| v.as_array()) {
                return arr
                    .iter()
                    .filter_map(|v| serde_json::from_value::<Record>(v.clone()).ok())
                    .filter(|r| matches!(r.lifecycle, RecordLifecycle::Active))
                    .filter(|r| {
                        r.payload_as::<GotchaRecord>()
                            .map(|g| g.affected_files.iter().any(|af| af == file))
                            .unwrap_or(false)
                    })
                    .collect();
            }
        }
    }
    vec![]
}

/// Write gotcha record + file-record updates + edges through daemon.
/// Returns `Ok(true)` if routed through daemon, `Ok(false)` if no daemon running.
async fn daemon_gotcha_write(
    root: &std::path::Path,
    record: &Record,
    new_files: &[String],
    old_files: &[String],
) -> Result<bool> {
    match daemon_result(root, "gotcha_write", serde_json::json!({
        "record": serde_json::to_value(record)?,
        "new_files": new_files,
        "old_files": old_files,
    })).await {
        DaemonResult::Ok(resp) => {
            if resp.get("ok") == Some(&serde_json::Value::Bool(true)) {
                Ok(true)
            } else {
                let err = resp.get("error").and_then(|v| v.as_str()).unwrap_or("unknown");
                anyhow::bail!("daemon gotcha_write failed: {err}");
            }
        }
        DaemonResult::NotRunning | DaemonResult::StaleSocket => Ok(false),
        DaemonResult::Unresponsive => {
            anyhow::bail!(
                "mati daemon is running but unresponsive — store is locked. \
                 Run `mati daemon stop` and retry."
            );
        }
    }
}

/// Write gotcha directly to store (no daemon). Assumes caller has checked no daemon running.
async fn direct_gotcha_write(
    store: &Store,
    key: &str,
    record: &Record,
    affected_files: &[String],
) -> Result<()> {
    store.put(key, record).await?;
    for af in affected_files {
        let file_key = format!("file:{af}");
        if let Ok(Some(mut file_record)) = store.get(&file_key).await {
            match file_record.payload.as_mut() {
                Some(payload) => {
                    if let Some(arr) = payload.get_mut("gotcha_keys")
                        .and_then(|v| v.as_array_mut())
                    {
                        if !arr.iter().any(|v| v.as_str() == Some(key)) {
                            arr.push(serde_json::Value::String(key.to_string()));
                        }
                    } else if let Some(obj) = payload.as_object_mut() {
                        obj.insert("gotcha_keys".into(), serde_json::json!([key]));
                    }
                }
                None => file_record.payload = Some(serde_json::json!({ "gotcha_keys": [key] })),
            }
            let _ = store.put(&file_key, &file_record).await;
        }
    }
    Ok(())
}

// ── Add ───────────────────────────────────────────────────────────────────────

async fn run_gotcha_add(file: &str) -> Result<()> {
    let use_color = io::stderr().is_terminal();
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    // Check if daemon is alive (holds the exclusive store lock).
    let daemon_alive = matches!(
        daemon_result(&root, "ping", serde_json::json!({})).await,
        DaemonResult::Ok(_)
    );

    // Show existing gotchas for this file before any prompts.
    let existing = if daemon_alive {
        existing_gotchas_via_daemon(&root, file).await
    } else {
        let store = Store::open(&cwd).await?;
        let records = existing_gotchas_for_file(&store, file).await?;
        store.close().await?;
        records
    };

    if !existing.is_empty() {
        print_existing_gotchas(&existing, file, use_color);

        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();

        eprint_prompt("Update an existing record? [key or Enter to add new]: ", use_color);
        let input = read_line(&mut lines)?;

        if !input.is_empty() {
            let key = normalize_key(&input);
            if existing.iter().any(|r| r.key == key) {
                return run_gotcha_edit(&key).await;
            }
            eprintln!("  Key '{key}' not found for this file — adding new record.");
        }
        eprintln!();
    }

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    eprint_prompt("Rule (imperative — what MUST Claude do/avoid): ", use_color);
    let rule = read_line(&mut lines)?;
    if rule.is_empty() {
        anyhow::bail!("rule cannot be empty");
    }

    eprint_prompt("Reason (why — what goes wrong otherwise): ", use_color);
    let reason = read_line(&mut lines)?;

    eprint_prompt("Severity (low/normal/high/critical) [normal]: ", use_color);
    let severity_input = read_line(&mut lines)?;
    let severity = parse_severity(&severity_input);

    eprint_prompt(&format!("Affected files (comma-separated) [{file}]: "), use_color);
    let files_input = read_line(&mut lines)?;
    let affected_files: Vec<String> = if files_input.is_empty() {
        vec![file.to_string()]
    } else {
        files_input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    eprint_prompt("Reference URL (optional): ", use_color);
    let ref_url_input = read_line(&mut lines)?;
    let ref_url = if ref_url_input.is_empty() { None } else { Some(ref_url_input) };

    let now = now_secs();
    let slug = slugify!(&rule, max_length = 40);
    let key = format!("gotcha:{slug}");

    let gotcha = GotchaRecord {
        rule: rule.clone(),
        reason: reason.clone(),
        severity: severity.clone(),
        affected_files: affected_files.clone(),
        ref_url: ref_url.clone(),
        discovered_session: now,
        confirmed: true,
    };

    let value = if reason.is_empty() {
        rule.clone()
    } else {
        format!("{rule} because {reason}")
    };

    let device_id = uuid::Uuid::new_v4();
    let mut record = Record {
        key: key.clone(),
        value,
        payload: serde_json::to_value(&gotcha).ok(),
        category: Category::Gotcha,
        priority: severity,
        tags: vec![],
        created_at: now,
        updated_at: now,
        ref_url,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion { device_id, logical_clock: 1, wall_clock: now },
        quality: QualityScore::developer_entry_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::DeveloperManual,
        confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
        gap_analysis_score: 0.0,
    };

    let score = quality::analyze(&record);
    record.quality = score.clone();

    if quality::below_quality_gate(&score) {
        quality::print_quality_gate_error(&score, use_color);
        anyhow::bail!("record rejected by quality gate (score {:.2})", score.value);
    }
    if score.value < 0.4 {
        quality::print_quality_caveat(&score, use_color);
    }

    if daemon_gotcha_write(&root, &record, &affected_files, &[]).await? {
        // Wrote through daemon — graph edges handled by daemon handler.
    } else {
        // No daemon — direct write + graph edges.
        let store = Store::open(&cwd).await?;
        direct_gotcha_write(&store, &key, &record, &affected_files).await?;
        let mut graph = Graph::load(store).await?;
        for af in &affected_files {
            let file_key = format!("file:{af}");
            graph.add_edge(&file_key, EdgeKind::HasGotcha, &key).await?;
        }
        graph.close().await?;
    }

    println!("Created {key}  (quality: {:.2}, confidence: {:.2})", score.value, record.confidence.value);
    for af in &affected_files {
        println!("  -> file:{af} HasGotcha {key}");
    }
    Ok(())
}

// ── Edit ──────────────────────────────────────────────────────────────────────

async fn run_gotcha_edit(key: &str) -> Result<()> {
    let use_color = io::stderr().is_terminal();
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    // Check daemon first to avoid lock conflict.
    let daemon_alive = matches!(
        daemon_result(&root, "ping", serde_json::json!({})).await,
        DaemonResult::Ok(_)
    );

    // Fetch record — via daemon if alive, direct otherwise.
    let record_json = if daemon_alive {
        match daemon_result(&root, "get", serde_json::json!({"key": key})).await {
            DaemonResult::Ok(resp) => resp.get("data").cloned().unwrap_or(serde_json::Value::Null),
            _ => anyhow::bail!("daemon unreachable while fetching '{key}'"),
        }
    } else {
        let store = Store::open(&cwd).await?;
        let r = store.get(key).await?;
        store.close().await?;
        match r {
            Some(rec) => serde_json::to_value(&rec)?,
            None => serde_json::Value::Null,
        }
    };

    if record_json.is_null() {
        anyhow::bail!("no record found for '{key}'");
    }

    let mut record: Record = serde_json::from_value(record_json)?;

    let old_gotcha: GotchaRecord = match record.payload_as::<GotchaRecord>() {
        Some(g) => g,
        None => anyhow::bail!("'{key}' is not a gotcha record"),
    };

    let old_files: HashSet<String> = old_gotcha.affected_files.iter().cloned().collect();

    // Show current state
    eprintln!();
    if use_color {
        eprintln!(
            "  {}Editing {}{}",
            super::colors::BLUE,
            key,
            super::colors::RESET
        );
    } else {
        eprintln!("  Editing {key}");
    }
    eprintln!("  ─────────────────────────────────────────────────");
    eprintln!("  Rule:     {}", old_gotcha.rule);
    eprintln!("  Reason:   {}", old_gotcha.reason);
    eprintln!("  Severity: {:?}", old_gotcha.severity);
    eprintln!("  Files:    {}", old_gotcha.affected_files.join(", "));
    if let Some(ref u) = old_gotcha.ref_url {
        eprintln!("  Ref:      {u}");
    }
    eprintln!("  (Leave any field blank to keep current value. Enter \"-\" to clear a URL.)");
    eprintln!();

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    eprint_prompt(&format!("Rule [{}]: ", old_gotcha.rule), use_color);
    let rule_input = read_line(&mut lines)?;
    let rule = if rule_input.is_empty() { old_gotcha.rule.clone() } else { rule_input };

    eprint_prompt(&format!("Reason [{}]: ", old_gotcha.reason), use_color);
    let reason_input = read_line(&mut lines)?;
    let reason = if reason_input.is_empty() { old_gotcha.reason.clone() } else { reason_input };

    eprint_prompt(&format!("Severity [{:?}]: ", old_gotcha.severity), use_color);
    let severity_input = read_line(&mut lines)?;
    let severity = if severity_input.is_empty() {
        old_gotcha.severity.clone()
    } else {
        parse_severity(&severity_input)
    };

    let files_display = old_gotcha.affected_files.join(", ");
    eprint_prompt(&format!("Affected files [{files_display}]: "), use_color);
    let files_input = read_line(&mut lines)?;
    let new_affected_files: Vec<String> = if files_input.is_empty() {
        old_gotcha.affected_files.clone()
    } else {
        files_input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    let ref_display = old_gotcha.ref_url.as_deref().unwrap_or("none");
    eprint_prompt(&format!("Reference URL [{ref_display}]: "), use_color);
    let ref_url_input = read_line(&mut lines)?;
    let ref_url = if ref_url_input.is_empty() {
        old_gotcha.ref_url.clone()
    } else if ref_url_input == "-" {
        None
    } else {
        Some(ref_url_input)
    };

    let now = now_secs();
    let updated_gotcha = GotchaRecord {
        rule: rule.clone(),
        reason: reason.clone(),
        severity: severity.clone(),
        affected_files: new_affected_files.clone(),
        ref_url: ref_url.clone(),
        discovered_session: old_gotcha.discovered_session,
        confirmed: old_gotcha.confirmed,
    };

    let value = if reason.is_empty() {
        rule.clone()
    } else {
        format!("{rule} because {reason}")
    };

    record.value = value;
    record.payload = serde_json::to_value(&updated_gotcha).ok();
    record.priority = severity;
    record.ref_url = ref_url;
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;

    let score = quality::analyze(&record);
    record.quality = score.clone();

    if quality::below_quality_gate(&score) {
        quality::print_quality_gate_error(&score, use_color);
        anyhow::bail!("record rejected by quality gate (score {:.2})", score.value);
    }
    if score.value < 0.4 {
        quality::print_quality_caveat(&score, use_color);
    }

    let old_files_vec: Vec<String> = old_files.iter().cloned().collect();
    let new_files_vec: Vec<String> = new_affected_files.clone();
    let new_files: HashSet<String> = new_affected_files.iter().cloned().collect();

    if daemon_gotcha_write(&root, &record, &new_files_vec, &old_files_vec).await? {
        // Wrote through daemon.
    } else {
        let store = Store::open(&cwd).await?;
        direct_gotcha_write(&store, key, &record, &new_files_vec).await?;
        let mut graph = Graph::load(store).await?;
        if old_files != new_files {
            for removed in old_files.difference(&new_files) {
                let file_key = format!("file:{removed}");
                graph.remove_edge(&file_key, &EdgeKind::HasGotcha, key).await?;
            }
            for added in new_files.difference(&old_files) {
                let file_key = format!("file:{added}");
                graph.add_edge(&file_key, EdgeKind::HasGotcha, key).await?;
            }
        }
        graph.close().await?;
    }

    println!("Updated {key}  (quality: {:.2})", score.value);
    Ok(())
}

// ── Delete ────────────────────────────────────────────────────────────────────

async fn run_gotcha_delete(key: &str) -> Result<()> {
    let use_color = io::stderr().is_terminal();
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    let daemon_alive = matches!(
        daemon_result(&root, "ping", serde_json::json!({})).await,
        DaemonResult::Ok(_)
    );

    // Fetch record to display + confirm.
    let record_json = if daemon_alive {
        match daemon_result(&root, "get", serde_json::json!({"key": key})).await {
            DaemonResult::Ok(resp) => resp.get("data").cloned().unwrap_or(serde_json::Value::Null),
            _ => anyhow::bail!("daemon unreachable while fetching '{key}'"),
        }
    } else {
        let store = Store::open(&cwd).await?;
        let r = store.get(key).await?;
        store.close().await?;
        match r {
            Some(rec) => serde_json::to_value(&rec)?,
            None => serde_json::Value::Null,
        }
    };

    if record_json.is_null() {
        anyhow::bail!("no record found for '{key}'");
    }

    let record: Record = serde_json::from_value(record_json)?;

    let gotcha: GotchaRecord = match record.payload_as::<GotchaRecord>() {
        Some(g) => g,
        None => anyhow::bail!("'{key}' is not a gotcha record"),
    };

    // Show what will be deleted
    eprintln!();
    if use_color {
        eprintln!(
            "  {}{}{}",
            super::colors::YELLOW,
            key,
            super::colors::RESET
        );
    } else {
        eprintln!("  {key}");
    }
    eprintln!("  Rule:   {}", gotcha.rule);
    eprintln!("  Reason: {}", gotcha.reason);
    eprintln!("  Files:  {}", gotcha.affected_files.join(", "));
    eprintln!();

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    eprint_prompt(&format!("Delete {key}? [y/N]: "), use_color);
    let confirm = read_line(&mut lines)?;

    if confirm.to_lowercase() != "y" && confirm.to_lowercase() != "yes" {
        println!("Aborted.");
        return Ok(());
    }

    if daemon_alive {
        match daemon_result(&root, "gotcha_tombstone", serde_json::json!({
            "key": key,
            "affected_files": &gotcha.affected_files,
        })).await {
            DaemonResult::Ok(resp) if resp.get("ok") == Some(&serde_json::Value::Bool(true)) => {}
            DaemonResult::Ok(resp) => {
                let err = resp.get("error").and_then(|v| v.as_str()).unwrap_or("unknown");
                anyhow::bail!("daemon gotcha_tombstone failed: {err}");
            }
            DaemonResult::NotRunning | DaemonResult::StaleSocket => {
                let store = Store::open(&cwd).await?;
                direct_delete(store, key, &gotcha.affected_files).await?;
            }
            DaemonResult::Unresponsive => {
                anyhow::bail!(
                    "mati daemon is running but unresponsive — store is locked. \
                     Run `mati daemon stop` and retry."
                );
            }
        }
    } else {
        let store = Store::open(&cwd).await?;
        direct_delete(store, key, &gotcha.affected_files).await?;
    }

    println!("Deleted {key}  (tombstoned, graph edges removed)");
    Ok(())
}

async fn direct_delete(store: Store, key: &str, affected_files: &[String]) -> Result<()> {
    let now = now_secs();
    if let Ok(Some(mut record)) = store.get(key).await {
        record.lifecycle = RecordLifecycle::Tombstoned {
            reason: TombstoneReason::ManualDeletion,
            at: now,
        };
        record.updated_at = now;
        record.version.logical_clock += 1;
        record.version.wall_clock = now;
        store.put(key, &record).await?;
    }
    // Graph::load takes ownership of store; tombstone write must be done first.
    let mut graph = Graph::load(store).await?;
    for af in affected_files {
        let file_key = format!("file:{af}");
        graph.remove_edge(&file_key, &EdgeKind::HasGotcha, key).await?;
    }
    graph.close().await?;
    Ok(())
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn eprint_prompt(msg: &str, use_color: bool) {
    if use_color {
        eprint!(
            "{}{}{} ",
            super::colors::BLUE,
            msg,
            super::colors::RESET
        );
    } else {
        eprint!("{msg} ");
    }
    let _ = io::stderr().flush();
}

fn read_line(lines: &mut io::Lines<io::StdinLock<'_>>) -> Result<String> {
    match lines.next() {
        Some(Ok(line)) => Ok(line.trim().to_string()),
        Some(Err(e)) => Err(e.into()),
        None => Ok(String::new()),
    }
}

fn parse_severity(input: &str) -> Priority {
    match input.to_lowercase().trim() {
        "low" => Priority::Low,
        "high" => Priority::High,
        "critical" | "crit" => Priority::Critical,
        _ => Priority::Normal,
    }
}
