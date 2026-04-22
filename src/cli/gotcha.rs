use std::collections::HashSet;
use std::io::{self, BufRead, IsTerminal, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::{Args, Subcommand};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, Color, ContentArrangement, Table};
use slugify::slugify;

use mati_core::health::quality;
use mati_core::store::{
    Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore,
};

use crate::cli::proxy::StoreProxy;

#[derive(Args)]
pub struct GotchaArgs {
    #[command(subcommand)]
    pub command: GotchaCommand,
}

#[derive(Subcommand)]
pub enum GotchaCommand {
    /// Add a new gotcha for a file
    #[command(
        long_about = "Add a gotcha for a file. Pass -r for quick capture, or omit for interactive mode.\n\n\
                      Quick:       mati gotcha add src/db.rs -r \"Never use unwrap in error paths\"\n\
                      With reason: mati gotcha add src/db.rs -r \"Never use unwrap\" -m \"Causes panics in production\"\n\
                      Interactive: mati gotcha add src/db.rs"
    )]
    Add {
        /// File path to add gotcha for (e.g., "src/store/db.rs")
        file: String,

        /// Rule text — what MUST Claude do/avoid. Skips interactive prompts.
        #[arg(short, long)]
        rule: Option<String>,

        /// Reason — why this matters. Optional with -r.
        #[arg(short = 'm', long)]
        reason: Option<String>,

        /// Severity (low/normal/high/critical). Defaults to normal.
        #[arg(short, long)]
        severity: Option<String>,
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
    /// Confirm a gotcha — activates hook enforcement (non-interactive, no TTY required)
    Confirm {
        /// Gotcha key (e.g., "gotcha:session-token-expiry" or just "session-token-expiry")
        key: String,
    },
}

pub async fn run(args: GotchaArgs) -> Result<()> {
    match args.command {
        GotchaCommand::Add {
            file,
            rule,
            reason,
            severity,
        } => run_gotcha_add(&file, rule, reason, severity).await,
        GotchaCommand::Edit { key } => run_gotcha_edit(&normalize_key(&key)).await,
        GotchaCommand::Delete { key } => run_gotcha_delete(&normalize_key(&key)).await,
        GotchaCommand::Confirm { key } => {
            const NON_GOTCHA_PREFIXES: &[&str] =
                &["file:", "decision:", "dev_note:", "dep:", "stage:"];
            if let Some(prefix) = NON_GOTCHA_PREFIXES.iter().find(|&&p| key.starts_with(p)) {
                let category = prefix.trim_end_matches(':');
                let slug = key.split_once(':').map(|x| x.1).unwrap_or(&key);
                anyhow::bail!(
                    "'{key}' has category '{category}', not 'gotcha'.\n\
                     Pass just the slug (e.g., '{slug}') or the full gotcha: key."
                );
            }
            run_gotcha_confirm(&normalize_key(&key)).await
        }
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
async fn existing_gotchas_for_file(store: &StoreProxy, file: &str) -> Result<Vec<Record>> {
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
        .set_header(vec![Cell::new("Key"), Cell::new("Conf"), Cell::new("Rule")]);

    if !use_color {
        table.force_no_tty();
    }

    for r in records {
        let rule = if let Some(g) = r.payload_as::<GotchaRecord>() {
            g.rule
        } else {
            r.value.clone()
        };
        let truncated = if rule.chars().count() > 60 {
            let cut: String = rule.chars().take(59).collect();
            format!("{cut}…")
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

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Extract `GotchaRecord` from a `Record`, handling PascalCase severity from MCP-written records.
fn extract_gotcha_record(record: &Record) -> Option<GotchaRecord> {
    if let Some(g) = record.payload_as::<GotchaRecord>() {
        return Some(g);
    }
    // Retry with normalized severity (MCP-written records may use PascalCase)
    let mut payload = record.payload.clone()?;
    if let Some(obj) = payload.as_object_mut() {
        if let Some(sev) = obj
            .get("severity")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase())
        {
            obj.insert("severity".to_string(), serde_json::Value::String(sev));
        }
    }
    serde_json::from_value::<GotchaRecord>(payload).ok()
}

fn manual_gotcha_matches(record: &Record, candidate: &GotchaRecord) -> bool {
    if !matches!(record.lifecycle, RecordLifecycle::Active) {
        return false;
    }

    record
        .payload_as::<GotchaRecord>()
        .map(|existing| {
            existing.rule == candidate.rule
                && existing.reason == candidate.reason
                && existing.severity == candidate.severity
                && existing.affected_files == candidate.affected_files
                && existing.ref_url == candidate.ref_url
        })
        .unwrap_or(false)
}

async fn choose_manual_gotcha_key(
    proxy: &StoreProxy,
    slug: &str,
    gotcha: &GotchaRecord,
) -> Result<String> {
    let base_key = format!("gotcha:{slug}");
    let mut suffix = 1usize;

    loop {
        let key = if suffix == 1 {
            base_key.clone()
        } else {
            format!("{base_key}:{suffix}")
        };

        match proxy.get(&key).await? {
            None => {
                return Ok(key);
            }
            Some(existing) if manual_gotcha_matches(&existing, gotcha) => {
                anyhow::bail!(
                    "a matching gotcha already exists as '{key}'. Use `mati gotcha edit {key}` to update it."
                );
            }
            Some(_) => suffix += 1,
        }
    }
}

// ── Add ───────────────────────────────────────────────────────────────────────

async fn run_gotcha_add(
    file: &str,
    inline_rule: Option<String>,
    inline_reason: Option<String>,
    inline_severity: Option<String>,
) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let result =
        run_gotcha_add_inner(&proxy, file, inline_rule, inline_reason, inline_severity).await;
    proxy.close_with_result(result).await
}

async fn run_gotcha_add_inner(
    proxy: &StoreProxy,
    file: &str,
    inline_rule: Option<String>,
    inline_reason: Option<String>,
    inline_severity: Option<String>,
) -> Result<()> {
    let use_color = io::stderr().is_terminal();

    // ── Quick capture path (-r flag) ─────────────────────────────────────
    // Skips all interactive prompts. Defaults: severity=normal, files=[file], no URL.
    if let Some(rule) = inline_rule {
        if rule.is_empty() {
            anyhow::bail!("rule cannot be empty");
        }
        let reason = inline_reason.unwrap_or_default();
        let severity = inline_severity
            .as_deref()
            .map(parse_severity)
            .unwrap_or(Priority::Normal);
        let affected_files = vec![file.to_string()];
        let ref_url = None;

        return finish_gotcha_add(
            proxy,
            &rule,
            &reason,
            severity,
            affected_files,
            ref_url,
            use_color,
        )
        .await;
    }

    // ── Interactive path ─────────────────────────────────────────────────
    // Show existing gotchas for this file before any prompts.
    let existing = existing_gotchas_for_file(proxy, file)
        .await
        .unwrap_or_default();

    if !existing.is_empty() {
        print_existing_gotchas(&existing, file, use_color);

        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();

        eprint_prompt(
            "Update an existing record? [key or Enter to add new]: ",
            use_color,
        );
        let input = read_line(&mut lines)?;

        if !input.is_empty() {
            let key = normalize_key(&input);
            if existing.iter().any(|r| r.key == key) {
                // Proxy will be closed by outer run_gotcha_add.
                // run_gotcha_edit opens its own proxy.
                return run_gotcha_edit(&key).await;
            }
            eprintln!("  Key '{key}' not found for this file — adding new record.");
        }
        eprintln!();
    }

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    eprint_prompt("Rule (what MUST Claude do/avoid): ", use_color);
    let rule = read_line(&mut lines)?;
    if rule.is_empty() {
        anyhow::bail!("rule cannot be empty");
    }

    eprint_prompt(
        "Reason (why — what goes wrong otherwise, or Enter to skip): ",
        use_color,
    );
    let reason = read_line(&mut lines)?;

    // Remaining fields use defaults unless the user opts in
    eprint_prompt(
        &format!("Severity/files/URL? (Enter to accept defaults: normal, {file}) ",),
        use_color,
    );
    let extra_input = read_line(&mut lines)?;

    let (severity, affected_files, ref_url) = if extra_input.is_empty() {
        (Priority::Normal, vec![file.to_string()], None)
    } else {
        // User wants to customize — ask each field
        let severity = parse_severity(&extra_input);

        eprint_prompt(
            &format!("Affected files (comma-separated) [{file}]: "),
            use_color,
        );
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
        let ref_url = if ref_url_input.is_empty() {
            None
        } else {
            Some(ref_url_input)
        };

        (severity, affected_files, ref_url)
    };

    finish_gotcha_add(
        proxy,
        &rule,
        &reason,
        severity,
        affected_files,
        ref_url,
        use_color,
    )
    .await
}

/// Shared record-building and writing logic for both quick and interactive paths.
#[allow(clippy::too_many_arguments)]
async fn finish_gotcha_add(
    proxy: &StoreProxy,
    rule: &str,
    reason: &str,
    severity: Priority,
    affected_files: Vec<String>,
    ref_url: Option<String>,
    use_color: bool,
) -> Result<()> {
    let now = now_secs();
    let slug = slugify!(&rule, max_length = 40);

    let gotcha = GotchaRecord {
        rule: rule.to_string(),
        reason: reason.to_string(),
        severity: severity.clone(),
        affected_files: affected_files.clone(),
        ref_url: ref_url.clone(),
        discovered_session: now,
        confirmed: true,
    };
    let key = choose_manual_gotcha_key(proxy, &slug, &gotcha).await?;

    let value = if reason.is_empty() {
        rule.to_string()
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
        version: RecordVersion {
            device_id,
            logical_clock: 1,
            wall_clock: now,
        },
        quality: QualityScore::developer_entry_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::DeveloperManual,
        confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
        gap_analysis_score: 0.0,
    };
    // `gotcha add` is an explicit developer assertion — count it as one confirmation
    // so that `mati show` reports confirmations=1 and the record is consistent with
    // the confirm path (which also increments confirmation_count).
    record.confidence.confirmation_count = 1;

    let score = quality::analyze(&record);
    record.quality = score.clone();

    if quality::below_quality_gate(&score) {
        quality::print_quality_gate_error(&score, use_color);
        anyhow::bail!("record rejected by quality gate (score {:.2})", score.value);
    }
    if score.value < 0.4 {
        quality::print_quality_caveat(&score, use_color);
    }

    proxy
        .gotcha_write(&record, &[], &affected_files, true)
        .await?;

    println!(
        "Created {key}  (quality: {:.2}, confidence: {:.2})",
        score.value, record.confidence.value
    );
    for af in &affected_files {
        println!("  -> file:{af} HasGotcha {key}");
    }
    Ok(())
}

// ── Edit ──────────────────────────────────────────────────────────────────────

async fn run_gotcha_edit(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let result = run_gotcha_edit_inner(&proxy, key).await;
    proxy.close_with_result(result).await
}

async fn run_gotcha_edit_inner(proxy: &StoreProxy, key: &str) -> Result<()> {
    let use_color = io::stderr().is_terminal();

    let mut record = proxy
        .get(key)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no record found for '{key}'"))?;

    let old_gotcha = extract_gotcha_record(&record)
        .ok_or_else(|| anyhow::anyhow!("'{key}' is not a gotcha record"))?;

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
    let rule = if rule_input.is_empty() {
        old_gotcha.rule.clone()
    } else {
        rule_input
    };

    eprint_prompt(&format!("Reason [{}]: ", old_gotcha.reason), use_color);
    let reason_input = read_line(&mut lines)?;
    let reason = if reason_input.is_empty() {
        old_gotcha.reason.clone()
    } else {
        reason_input
    };

    eprint_prompt(
        &format!("Severity [{:?}]: ", old_gotcha.severity),
        use_color,
    );
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
        rule
    } else {
        format!("{} because {}", updated_gotcha.rule, updated_gotcha.reason)
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

    let old_files_vec: Vec<String> = old_files.into_iter().collect();

    proxy
        .gotcha_write(&record, &old_files_vec, &new_affected_files, false)
        .await?;

    println!("Updated {key}  (quality: {:.2})", score.value);
    Ok(())
}

// ── Delete ────────────────────────────────────────────────────────────────────

async fn run_gotcha_delete(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let result = run_gotcha_delete_inner(&proxy, key).await;
    proxy.close_with_result(result).await
}

async fn run_gotcha_delete_inner(proxy: &StoreProxy, key: &str) -> Result<()> {
    let use_color = io::stderr().is_terminal();

    let record = proxy
        .get(key)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no record found for '{key}'"))?;

    let gotcha = extract_gotcha_record(&record)
        .ok_or_else(|| anyhow::anyhow!("'{key}' is not a gotcha record"))?;

    // Show what will be deleted
    eprintln!();
    if use_color {
        eprintln!("  {}{}{}", super::colors::YELLOW, key, super::colors::RESET);
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

    proxy.gotcha_tombstone(key, &gotcha.affected_files).await?;

    println!("Deleted {key}  (tombstoned, graph edges removed)");
    Ok(())
}

fn eprint_prompt(msg: &str, use_color: bool) {
    if use_color {
        eprint!("{}{}{} ", super::colors::BLUE, msg, super::colors::RESET);
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

// ── Confirm ───────────────────────────────────────────────────────────────────

/// Core confirm logic extracted for testability. Takes a proxy directly.
///
/// After confirming the record, syncs file-record `gotcha_keys` for all
/// affected files. This ensures that gotchas created via mem_set (which
/// previously skipped file-link sync) become visible to `mati diff` and
/// the pre-read hook immediately after confirmation.
pub(crate) async fn confirm_gotcha(proxy: &StoreProxy, key: &str) -> Result<()> {
    let mut record = match proxy.get(key).await? {
        Some(r) => r,
        None => anyhow::bail!("no record found for '{key}'"),
    };

    if record.category != Category::Gotcha {
        anyhow::bail!(
            "'{key}' is not a Gotcha record (category: {:?})",
            record.category
        );
    }

    if !matches!(record.lifecycle, RecordLifecycle::Active) {
        anyhow::bail!("'{key}' is tombstoned — cannot confirm a deleted record");
    }

    if let Some(ref mut payload) = record.payload {
        if let Some(obj) = payload.as_object_mut() {
            if let Some(sev) = obj
                .get("severity")
                .and_then(|v| v.as_str())
                .map(|s| s.to_lowercase())
            {
                obj.insert("severity".to_string(), serde_json::Value::String(sev));
            }
            obj.insert("confirmed".to_string(), serde_json::Value::Bool(true));
        }
    }

    let now = now_secs();
    record.source = RecordSource::DeveloperManual;
    record.confidence.value = ConfidenceScore::base_for_source(&RecordSource::DeveloperManual);
    record.confidence.confirmation_count += 1;
    record.quality = quality::analyze(&record);
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;

    // Extract affected_files for the gotcha_write call.
    let affected_files: Vec<String> = record
        .payload_as::<GotchaRecord>()
        .map(|g| g.affected_files)
        .unwrap_or_default();

    // In socket mode, use the daemon's native GotchaConfirm handler which
    // atomically sets DeveloperManual source + 0.80 confidence + file links
    // and records a `ControlChanged::Confirmed` enforcement event.
    // In direct mode, write via `gotcha_confirm_direct` so the audit stream
    // sees `Confirmed` instead of the generic `Updated` that `gotcha_write`
    // would record.
    if !proxy.is_direct() {
        proxy.daemon_gotcha_confirm(key).await?;
    } else {
        proxy.gotcha_confirm_direct(&record, &affected_files).await?;
    }

    // Propagate confirmation signal to linked file records — their
    // confidence.confirmation_count feeds into log2(count + 2).
    proxy.propagate_confirmation(&affected_files).await;

    Ok(())
}

async fn run_gotcha_confirm(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let result = confirm_gotcha(&proxy, key).await;
    proxy.close_with_result(result).await?;

    let conf = ConfidenceScore::base_for_source(&RecordSource::DeveloperManual);
    println!("Confirmed: {key}  (confidence -> {conf:.2}, hook enforcement active)");
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mati_core::store::gotcha_ops::{ensure_gotcha_key_available, sync_gotcha_file_links};
    use mati_core::store::{FileRecord, Store};
    use tempfile::TempDir;

    fn make_gotcha_record(key: &str) -> Record {
        let now = 1_700_000_000u64;
        let gotcha = GotchaRecord {
            rule: "Always check input".to_string(),
            reason: "unchecked input causes panics".to_string(),
            severity: Priority::High,
            affected_files: vec!["src/main.rs".to_string()],
            ref_url: None,
            discovered_session: now,
            confirmed: false,
        };
        Record {
            key: key.to_string(),
            value: "Always check input because unchecked input causes panics".to_string(),
            payload: serde_json::to_value(&gotcha).ok(),
            category: Category::Gotcha,
            priority: Priority::High,
            tags: vec![],
            created_at: now,
            updated_at: now,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: now,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::ClaudeEnrich,
            confidence: ConfidenceScore::for_new_record(&RecordSource::ClaudeEnrich),
            gap_analysis_score: 0.0,
        }
    }

    fn make_file_record(key: &str, gotcha_keys: Vec<String>) -> Record {
        let now = 1_700_000_000u64;
        let path = key.strip_prefix("file:").unwrap_or(key);
        let file = FileRecord {
            path: path.to_string(),
            purpose: String::new(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys,
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 0,
            last_modified_session: now,
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
        };
        let mut record = Record::layer0_file_stub(key, uuid::Uuid::new_v4(), 1, now);
        record.payload = serde_json::to_value(&file).ok();
        record
    }

    #[tokio::test]
    async fn sync_gotcha_links_adds_and_removes_exact_keys() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put(
                "file:src/old.rs",
                &make_file_record(
                    "file:src/old.rs",
                    vec!["gotcha:shared-rule".to_string(), "gotcha:keep".to_string()],
                ),
            )
            .await
            .unwrap();
        store
            .put(
                "file:src/new.rs",
                &make_file_record("file:src/new.rs", vec![]),
            )
            .await
            .unwrap();

        sync_gotcha_file_links(
            &store,
            "gotcha:shared-rule",
            &["src/old.rs".to_string()],
            &["src/new.rs".to_string()],
        )
        .await
        .unwrap();

        let old = store.get("file:src/old.rs").await.unwrap().unwrap();
        let old_payload = old.payload_as::<FileRecord>().unwrap();
        assert_eq!(old_payload.gotcha_keys, vec!["gotcha:keep".to_string()]);
        assert!(old.updated_at > 1_700_000_000u64);
        assert_eq!(old.version.logical_clock, 2);

        let new = store.get("file:src/new.rs").await.unwrap().unwrap();
        let new_payload = new.payload_as::<FileRecord>().unwrap();
        assert_eq!(
            new_payload.gotcha_keys,
            vec!["gotcha:shared-rule".to_string()]
        );
        assert!(new.updated_at > 1_700_000_000u64);
        assert_eq!(new.version.logical_clock, 2);
    }

    #[tokio::test]
    async fn ensure_gotcha_key_available_rejects_existing_key() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let record = make_gotcha_record("gotcha:always-check");
        store.put("gotcha:always-check", &record).await.unwrap();

        let err = ensure_gotcha_key_available(&store, "gotcha:always-check")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn choose_manual_gotcha_key_adds_suffix_on_collision() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let record = make_gotcha_record("gotcha:always-check-input");
        store
            .put("gotcha:always-check-input", &record)
            .await
            .unwrap();
        store.close().await.unwrap();

        let candidate = GotchaRecord {
            rule: "Always check input".to_string(),
            reason: "different context".to_string(),
            severity: Priority::High,
            affected_files: vec!["src/lib.rs".to_string()],
            ref_url: None,
            discovered_session: now_secs(),
            confirmed: true,
        };

        let proxy = StoreProxy::open(dir.path()).await.unwrap();
        let key = choose_manual_gotcha_key(&proxy, "always-check-input", &candidate)
            .await
            .unwrap();
        assert_eq!(key, "gotcha:always-check-input:2");
        proxy.close().await.unwrap();
    }

    #[tokio::test]
    async fn confirm_sets_confirmed_true() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let record = make_gotcha_record("gotcha:test-confirm");
        store.put("gotcha:test-confirm", &record).await.unwrap();
        store.close().await.unwrap();

        let proxy = StoreProxy::open(dir.path()).await.unwrap();
        confirm_gotcha(&proxy, "gotcha:test-confirm").await.unwrap();

        let updated = proxy.get("gotcha:test-confirm").await.unwrap().unwrap();
        let payload = updated.payload.unwrap();
        assert_eq!(payload["confirmed"], true);
    }

    #[tokio::test]
    async fn confirm_updates_source_to_developer_manual() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let record = make_gotcha_record("gotcha:test-source");
        store.put("gotcha:test-source", &record).await.unwrap();
        store.close().await.unwrap();

        let proxy = StoreProxy::open(dir.path()).await.unwrap();
        confirm_gotcha(&proxy, "gotcha:test-source").await.unwrap();

        let updated = proxy.get("gotcha:test-source").await.unwrap().unwrap();
        assert_eq!(updated.source, RecordSource::DeveloperManual);
        assert!((updated.confidence.value - 0.80).abs() < 0.01);
    }

    #[tokio::test]
    async fn confirm_backfills_missing_file_links() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put(
                "file:src/main.rs",
                &make_file_record("file:src/main.rs", vec![]),
            )
            .await
            .unwrap();
        store
            .put(
                "gotcha:test-backfill",
                &make_gotcha_record("gotcha:test-backfill"),
            )
            .await
            .unwrap();
        store.close().await.unwrap();

        let proxy = StoreProxy::open(dir.path()).await.unwrap();
        confirm_gotcha(&proxy, "gotcha:test-backfill")
            .await
            .unwrap();

        let updated_file = proxy.get("file:src/main.rs").await.unwrap().unwrap();
        let payload = updated_file.payload_as::<FileRecord>().unwrap();
        assert_eq!(
            payload.gotcha_keys,
            vec!["gotcha:test-backfill".to_string()]
        );
    }

    #[tokio::test]
    async fn confirm_fails_on_nonexistent_key() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        store.close().await.unwrap();

        let proxy = StoreProxy::open(dir.path()).await.unwrap();
        let result = confirm_gotcha(&proxy, "gotcha:does-not-exist").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no record found"));
    }
}
