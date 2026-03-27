//! Single-file reparse logic (M-12-A) — library entry point.
//!
//! `reparse_impl` is called by both the MCP server's daemon socket (`edit_hook`
//! command) and by the standalone `mati reparse` CLI subcommand.
//!
//! Steps:
//! 1. Read file from disk. Missing → add FileDeleted staleness signal, return.
//! 2. Detect language, construct WalkedFile, run parse_file().
//! 3. Parse failure → log warning, return Ok (graceful degradation P9).
//! 4. Fetch existing file:<path> record.
//! 5. No record → create Layer 0 stub, persist, return.
//! 6. Deserialize record.value as FileRecord, compare structural fields.
//! 7. Nothing changed → return early (no write).
//! 8. Merge new analysis, preserve: purpose, gotcha_keys, decision_keys,
//!    change_frequency, last_author, is_hotspot.
//! 9. Apply staleness + cascade to linked gotchas (M-12-C).
//! 10. Write back.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::analysis::walker::{detect_language, WalkedFile};
use crate::analysis::{parse_file, StaticFileAnalysis};
use crate::health::staleness::{
    apply_reparse_staleness, cascade_staleness_to_gotchas, ReparseDiff,
};
use crate::store::record::{
    Category, ConfidenceScore, FileRecord, QualityScore, Record, RecordLifecycle, RecordSource,
    RecordVersion, StalenessScore, StalenessSignal, StalenessTier,
};
use crate::store::Store;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub async fn reparse_impl(store: &Store, repo_root: &std::path::Path, rel_path: &str) -> Result<()> {
    let abs_path = repo_root.join(rel_path);
    let file_key = format!("file:{rel_path}");
    let now = now_secs();

    // 1. Check if file exists on disk
    if !abs_path.exists() {
        // File deleted — add staleness signal if record exists
        if let Some(mut record) = store.get(&file_key).await? {
            record.staleness.value = 1.0;
            record.staleness.tier = StalenessTier::Tombstone;
            record.staleness.signals.push(StalenessSignal::FileDeleted);
            record.staleness.computed_at = now;
            record.updated_at = now;
            record.version.logical_clock += 1;
            record.version.wall_clock = now;
            store.put(&file_key, &record).await?;
        }
        return Ok(());
    }

    // 2. Detect language and construct WalkedFile
    let language = detect_language(&abs_path);
    let size_bytes = std::fs::metadata(&abs_path)
        .map(|m| m.len())
        .unwrap_or(0);

    let walked = WalkedFile {
        abs_path: abs_path.clone(),
        rel_path: rel_path.to_string(),
        language,
        size_bytes,
        mtime_secs: 0, // reparse always re-reads — mtime not needed
    };

    // 3. Parse file — graceful degradation on failure
    let analysis = match parse_file(&walked) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!("reparse: parse failed for {rel_path}: {e}");
            return Ok(());
        }
    };

    // 4. Fetch existing record
    let existing = store.get(&file_key).await?;

    // 5. No record → create Layer 0 stub
    let Some(mut record) = existing else {
        let file_record = build_file_record_from_analysis(rel_path, &analysis, &walked, now);
        let new_record = Record {
            key: file_key.clone(),
            value: file_record.purpose.clone(),
            payload: serde_json::to_value(&file_record).ok(),
            category: Category::File,
            priority: crate::store::record::Priority::Normal,
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
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
        };
        store.put(&file_key, &new_record).await?;
        return Ok(());
    };

    // 6. Deserialize existing FileRecord from payload, compare
    let old_fr: FileRecord = match record.payload_as::<FileRecord>() {
        Some(fr) => fr,
        None => {
            // Missing or corrupt payload — rebuild from scratch, preserve key metadata
            let file_record = build_file_record_from_analysis(rel_path, &analysis, &walked, now);
            record.value = file_record.purpose.clone();
            record.payload = serde_json::to_value(&file_record).ok();
            record.updated_at = now;
            record.version.logical_clock += 1;
            record.version.wall_clock = now;
            store.put(&file_key, &record).await?;
            return Ok(());
        }
    };

    // 7. Compute diff
    let diff = compute_diff(&old_fr, &analysis);
    if diff.is_empty() {
        return Ok(());
    }

    // 8. Merge: update structural fields, preserve enrichment fields
    let merged = FileRecord {
        path: rel_path.to_string(),
        purpose: old_fr.purpose,
        entry_points: analysis.entry_points,
        imports: analysis.imports,
        gotcha_keys: old_fr.gotcha_keys.clone(),
        decision_keys: old_fr.decision_keys,
        todos: analysis.todos,
        unsafe_count: analysis.unsafe_count,
        unwrap_count: analysis.unwrap_count,
        change_frequency: old_fr.change_frequency,
        last_author: old_fr.last_author,
        is_hotspot: old_fr.is_hotspot,
        token_cost_estimate: (walked.size_bytes / 4).min(u32::MAX as u64) as u32,
        last_modified_session: now,
        content_hash: analysis.content_hash.clone(),
        line_count: analysis.line_count,
    };

    record.value = merged.purpose.clone();
    record.payload = serde_json::to_value(&merged).ok();

    // 9. Apply staleness
    let signals = apply_reparse_staleness(&mut record, &diff);

    // 10. Bump version before cascade (gotchas may reference parent version)
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;

    // 11. Cascade to linked gotchas
    if !signals.is_empty() {
        if let Err(e) = cascade_staleness_to_gotchas(store, &merged).await {
            tracing::warn!("reparse: cascade to gotchas failed for {rel_path}: {e}");
        }
    }

    // 12. Write back
    store.put(&file_key, &record).await?;

    Ok(())
}

/// Build a fresh FileRecord from analysis output (no prior enrichment).
fn build_file_record_from_analysis(
    rel_path: &str,
    analysis: &StaticFileAnalysis,
    walked: &WalkedFile,
    now: u64,
) -> FileRecord {
    FileRecord {
        path: rel_path.to_string(),
        purpose: String::new(),
        entry_points: analysis.entry_points.clone(),
        imports: analysis.imports.clone(),
        gotcha_keys: vec![],
        decision_keys: vec![],
        todos: analysis.todos.clone(),
        unsafe_count: analysis.unsafe_count,
        unwrap_count: analysis.unwrap_count,
        change_frequency: 0,
        last_author: None,
        is_hotspot: false,
        token_cost_estimate: (walked.size_bytes / 4).min(u32::MAX as u64) as u32,
        last_modified_session: now,
        content_hash: analysis.content_hash.clone(),
        line_count: analysis.line_count,
    }
}

/// Compute the structural diff between an old FileRecord and new analysis.
fn compute_diff(old: &FileRecord, new: &StaticFileAnalysis) -> ReparseDiff {
    let old_eps: HashSet<&str> =
        old.entry_points.iter().map(|s| s.as_str()).collect();
    let new_eps: HashSet<&str> =
        new.entry_points.iter().map(|s| s.as_str()).collect();

    let entry_points_added: Vec<String> = new_eps
        .difference(&old_eps)
        .map(|s| s.to_string())
        .collect();
    let entry_points_removed: Vec<String> = old_eps
        .difference(&new_eps)
        .map(|s| s.to_string())
        .collect();

    let old_imports: HashSet<&str> =
        old.imports.iter().map(|s| s.as_str()).collect();
    let new_imports: HashSet<&str> =
        new.imports.iter().map(|s| s.as_str()).collect();

    let imports_added: Vec<String> = new_imports
        .difference(&old_imports)
        .map(|s| s.to_string())
        .collect();
    let imports_removed: Vec<String> = old_imports
        .difference(&new_imports)
        .map(|s| s.to_string())
        .collect();

    let todos_changed = old.todos.len() != new.todos.len()
        || old
            .todos
            .iter()
            .zip(new.todos.iter())
            .any(|(a, b)| a.text != b.text || a.line != b.line);

    let unsafe_delta = new.unsafe_count as i32 - old.unsafe_count as i32;
    let unwrap_delta = new.unwrap_count as i32 - old.unwrap_count as i32;

    ReparseDiff {
        entry_points_added,
        entry_points_removed,
        imports_added,
        imports_removed,
        todos_changed,
        unsafe_delta,
        unwrap_delta,
    }
}
