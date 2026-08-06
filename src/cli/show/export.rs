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
    let cwd = std::env::current_dir()?;
    let proxy = super::proxy::StoreProxy::open(&cwd).await?;

    let path = &args.file;
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
