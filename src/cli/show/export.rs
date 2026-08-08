use super::*;

pub async fn run_export(args: ExportArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = StoreProxy::open(&cwd).await?;

    let output = match args.format.as_str() {
        "json" => export_json(&store).await?,
        "md" | "markdown" => export_md(&store).await?,
        other => anyhow::bail!("unknown format '{other}'. Valid: md, json"),
    };

    match args.output {
        Some(path) => std::fs::write(&path, &output)?,
        None => print!("{output}"),
    }
    Ok(())
}

async fn export_json(store: &StoreProxy) -> Result<String> {
    let mut all: Vec<Record> = Vec::new();
    for prefix in &[
        "gotcha:",
        "decision:",
        "file:",
        "stage:",
        "dev_note:",
        "dep:",
        // Policies are user-authored source of truth. Omitting them meant an
        // export was not a backup: a restore came back with every rule gone.
        "policy:",
    ] {
        all.extend(store.scan_prefix(prefix).await?);
    }
    Ok(serde_json::to_string_pretty(&all)?)
}

async fn export_md(store: &StoreProxy) -> Result<String> {
    let mut out = String::from("# mati knowledge export\n\n");

    let sections: &[(&str, &str)] = &[
        ("gotcha:", "Gotchas"),
        ("decision:", "Decisions"),
        ("file:", "Files"),
        ("dev_note:", "Notes"),
        ("dep:", "Dependencies"),
        ("policy:", "Policies"),
    ];

    for &(prefix, heading) in sections {
        let records = store.scan_prefix(prefix).await?;
        if records.is_empty() {
            continue;
        }
        out.push_str(&format!("## {heading}\n\n"));
        for r in &records {
            out.push_str(&format!("### {}\n\n", r.key));
            if !r.value.is_empty() {
                out.push_str(&r.value);
                out.push_str("\n\n");
            }
            out.push_str(&format!(
                "- priority: {:?}\n- confidence: {:.2}\n- quality: {:.2}\n- source: {:?}\n\n",
                r.priority, r.confidence.value, r.quality.value, r.source
            ));
        }
    }

    Ok(out)
}

// ── run_import (M-08-N) ─────────────────────────────────────────────────────

pub async fn run_import(args: ImportArgs) -> Result<()> {
    if args.auto_memory {
        return run_import_auto_memory().await;
    }

    let cwd = std::env::current_dir()?;
    let proxy = super::proxy::StoreProxy::open(&cwd).await?;

    // clap enforces file XOR --auto-memory (`required_unless_present` /
    // `conflicts_with`), so this arm always has a file.
    let path = args
        .file
        .as_ref()
        .expect("clap requires --file unless --auto-memory is set");
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext {
        "json" => {
            let content = std::fs::read_to_string(path)?;
            let records: Vec<Record> = serde_json::from_str(&content)?;
            let (imported, skipped) = import_records_resilient(&proxy, &records).await;
            println!("Imported {imported} records from JSON ({skipped} skipped).");
        }
        "md" => {
            let device_id = mati_core::store::stable_device_id();
            let import = mati_core::analysis::import_claude_md(path, device_id, 1)?;
            let (imported, skipped) = import_records_resilient(&proxy, &import.records).await;
            println!("Imported {imported} records from CLAUDE.md ({skipped} skipped).");
        }
        _ => {
            // Try JSON first, fall back to CLAUDE.md import
            let content = std::fs::read_to_string(path)?;
            if content.trim_start().starts_with('[') || content.trim_start().starts_with('{') {
                let records: Vec<Record> = serde_json::from_str(&content)?;
                let (imported, skipped) = import_records_resilient(&proxy, &records).await;
                println!("Imported {imported} records from JSON ({skipped} skipped).");
            } else {
                let device_id = mati_core::store::stable_device_id();
                let import = mati_core::analysis::import_claude_md(path, device_id, 1)?;
                let (imported, skipped) = import_records_resilient(&proxy, &import.records).await;
                println!("Imported {imported} records from CLAUDE.md ({skipped} skipped).");
            }
        }
    }
    proxy.close().await?;
    Ok(())
}

// ── run_import_auto_memory (F10) ─────────────────────────────────────────────

/// Import Claude Code's auto-memory directory (`~/.claude/projects/<slug>/memory/`)
/// as `dev_note:auto-memory-*` records.
///
/// Never overwrites an existing `dev_note:auto-memory-*` key: a record
/// already in the store means either a prior import already wrote it, or a
/// developer has since edited or deleted it — a re-run must not silently
/// undo that. This makes the command idempotent: running it twice with no
/// store changes in between imports 0 the second time.
///
/// Also sweeps `gotcha:auto-memory-*` records left behind by the earlier
/// (pre-migration) importer, which wrote this channel as unconfirmed gotcha
/// candidates. That was the wrong record type: confirming one made it
/// eligible for global bootstrap injection with no `affected_files` gate,
/// which could crowd out real gotchas under the bootstrap token budget.
/// Unconfirmed legacy records are tombstoned via
/// [`gotcha_ops::apply_gotcha_tombstone`] — the sanctioned mutation path —
/// on every run. A legacy record a developer already confirmed is left
/// alone and reported instead: a developer's explicit confirmation is not
/// something an import should silently undo.
pub async fn run_import_auto_memory() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let dir = mati_core::analysis::auto_memory_dir(&cwd)?;

    let device_id = mati_core::store::stable_device_id();
    let import = mati_core::analysis::import_auto_memory(&dir, device_id, 1)?;

    if import.records.is_empty() && import.skipped_files.is_empty() {
        println!("No auto-memory directory found at {}.", dir.display());
        println!("(Claude Code creates one automatically once it writes its first memory.)");
        return Ok(());
    }

    let proxy = super::proxy::StoreProxy::open(&cwd).await?;

    let result: Result<(u64, u64, usize, usize, Vec<String>)> = async {
        let existing: std::collections::HashSet<String> = proxy
            .scan_prefix("dev_note:")
            .await?
            .into_iter()
            .map(|r| r.key)
            .collect();

        let mut seen_this_run = std::collections::HashSet::new();
        let mut new_records = Vec::with_capacity(import.records.len());
        let mut already_present: usize = 0;
        for record in import.records {
            if existing.contains(&record.key) || !seen_this_run.insert(record.key.clone()) {
                already_present += 1;
                continue;
            }
            new_records.push(record);
        }

        let (imported, rejected) = import_records_resilient(&proxy, &new_records).await;
        let (tombstoned, confirmed_keys) = sweep_legacy_gotcha_records(&proxy).await?;
        Ok((
            imported as u64,
            rejected as u64,
            already_present,
            tombstoned,
            confirmed_keys,
        ))
    }
    .await;

    let (imported, rejected, already_present, tombstoned, confirmed_keys) =
        proxy.close_with_result(result).await?;

    println!(
        "Imported {imported} auto-memory note{} from {}.",
        if imported == 1 { "" } else { "s" },
        dir.display()
    );
    if already_present > 0 {
        println!("  {already_present} already imported previously (skipped, unchanged).");
    }
    if rejected > 0 {
        println!("  {rejected} rejected by the store.");
    }
    if !import.skipped_files.is_empty() {
        println!(
            "  {} memory file(s) skipped (unreadable or empty):",
            import.skipped_files.len()
        );
        for (path, reason) in &import.skipped_files {
            println!("    {}: {reason}", path.display());
        }
    }
    if tombstoned > 0 {
        println!(
            "  {tombstoned} legacy gotcha:auto-memory-* record{} from the old importer tombstoned.",
            if tombstoned == 1 { "" } else { "s" }
        );
    }
    if !confirmed_keys.is_empty() {
        println!(
            "  {} legacy gotcha:auto-memory-* record(s) were confirmed by a developer — left in place:",
            confirmed_keys.len()
        );
        for key in &confirmed_keys {
            println!("    {key}");
        }
        println!("    Review with `mati gotcha delete <key>` if no longer wanted.");
    }
    if imported > 0 {
        println!("Run `mati ls notes` to view them.");
    }
    Ok(())
}

/// Tombstone unconfirmed `gotcha:auto-memory-*` records left by the
/// pre-migration importer. Returns `(tombstoned_count, confirmed_keys_left_in_place)`.
///
/// Confirmed legacy records are never mutated here — only a developer's own
/// `mati gotcha delete` removes those. Already-tombstoned records are
/// skipped (nothing to do).
async fn sweep_legacy_gotcha_records(
    proxy: &super::proxy::StoreProxy,
) -> Result<(usize, Vec<String>)> {
    use mati_core::store::{GotchaRecord, RecordLifecycle};

    let legacy = proxy.scan_prefix("gotcha:auto-memory-").await?;
    let mut tombstoned = 0usize;
    let mut confirmed_keys = Vec::new();

    for record in legacy {
        if !matches!(record.lifecycle, RecordLifecycle::Active) {
            continue;
        }
        let Some(gotcha) = record.payload_as::<GotchaRecord>() else {
            continue;
        };
        if gotcha.confirmed {
            confirmed_keys.push(record.key.clone());
            continue;
        }
        proxy
            .gotcha_tombstone(&record.key, &gotcha.affected_files)
            .await?;
        tombstoned += 1;
    }

    Ok((tombstoned, confirmed_keys))
}

/// Import records via the bulk `RecordImport` v2 command. Routes through one
/// daemon round-trip per 200-record chunk in socket mode, or one atomic
/// `put_batch` in direct mode. Records destined for the sessions tree
/// (`session:`, `analytics:`, `compliance:`, `audit:*`, `graph:edge:*`) are
/// skipped at the boundary — those are daemon-owned runtime state, not
/// user-authored knowledge.
///
/// Returns `(imported, skipped)` counts.
/// Land imported policies inert.
///
/// `mati policy enable <slug>` promotes one named rule the developer is looking
/// at. An import can carry many, from a file they may not have read, so
/// preserving `enforce` would let a single command start enforcing rules nobody
/// reviewed. Content round-trips; the stage does not, matching the `mem_set`
/// boundary where only a deliberate per-policy act promotes.
fn deactivate_imported_policies(records: &[Record]) -> (Vec<Record>, usize) {
    use mati_core::store::{PolicyRecord, PolicyStage};
    let mut demoted = 0usize;
    let out = records
        .iter()
        .map(|record| {
            if !record.key.starts_with("policy:") {
                return record.clone();
            }
            let Some(mut policy) = record.payload_as::<PolicyRecord>() else {
                return record.clone();
            };
            if matches!(policy.stage, PolicyStage::Off) {
                return record.clone();
            }
            policy.stage = PolicyStage::Off;
            let mut record = record.clone();
            if let Ok(payload) = serde_json::to_value(&policy) {
                record.payload = Some(payload);
                demoted += 1;
            }
            record
        })
        .collect();
    (out, demoted)
}

async fn import_records_resilient(
    proxy: &super::proxy::StoreProxy,
    records: &[Record],
) -> (usize, usize) {
    let (records, demoted) = deactivate_imported_policies(records);
    if demoted > 0 {
        println!(
            "  {demoted} imported polic{} set to stage off; promote with `mati policy stage <slug> enforce`.",
            if demoted == 1 { "y" } else { "ies" }
        );
    }
    let records = &records;
    match proxy.import_records(records).await {
        Ok((imported, skipped)) => (imported as usize, skipped as usize),
        Err(e) => {
            eprintln!("  import failed: {e}");
            (0, records.len())
        }
    }
}

// ── run_history (M-14-C stub) ────────────────────────────────────────────────
