//! Incremental file reparse — used by `mati reparse`, `edit-hook`, and the MCP
//! server socket handler.
//!
//! Steps:
//! 1. Read file from disk. Missing → add FileDeleted staleness signal, return.
//! 2. Detect language, construct WalkedFile, run parse_file().
//! 3. Parse failure → log warning, return Ok (graceful degradation P9).
//! 4. Fetch existing file:<path> record.
//! 5. No record → create Layer 0 stub, persist, return.
//! 6. Deserialize record.payload as FileRecord, compare structural fields.
//! 7. Nothing changed → return early (no write).
//! 8. Merge new analysis, preserve: purpose, gotcha_keys, decision_keys,
//!    change_frequency, last_author, is_hotspot.
//! 9. Apply staleness + cascade to linked gotchas (M-12-C).
//! 10. Write back.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::analysis::walker::{detect_language, WalkedFile};
use crate::analysis::{parse_file, public_api_symbols, StaticFileAnalysis};
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

/// Re-parse a single file and update its store record in place.
///
/// Called by:
/// - `mati reparse <path>` CLI command
/// - `mati edit-hook <path>` (via daemon socket or direct store)
/// - MCP server socket `edit_hook` handler
///
/// Gracefully degrades on parse failure (P9). Never returns an error for
/// missing files or parse issues — those are logged as warnings.
pub async fn reparse_impl(
    store: &Store,
    repo_root: &std::path::Path,
    rel_path: &str,
) -> Result<()> {
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
    let size_bytes = std::fs::metadata(&abs_path).map(|m| m.len()).unwrap_or(0);

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
        entry_points: public_api_symbols(&analysis),
        imports: analysis.imports.iter().map(|i| i.path.clone()).collect(),
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
        blast_radius: old_fr.blast_radius,
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

/// Compute the reparse result without persisting. Returns the key and updated
/// Record to write, or `None` if no write is needed (file missing, parse
/// failure, or no structural changes).
///
/// The caller is responsible for committing the record (and any audit entry)
/// in a single transaction via `transact_knowledge`.
///
/// Staleness cascade to linked gotchas is NOT included — it is a separate
/// best-effort substep that the caller handles after committing the main write.
pub async fn reparse_staged(
    store: &Store,
    repo_root: &std::path::Path,
    rel_path: &str,
) -> Result<Option<(String, Record)>> {
    let abs_path = repo_root.join(rel_path);
    let file_key = format!("file:{rel_path}");
    let now = now_secs();

    // 1. File deleted — update staleness.
    if !abs_path.exists() {
        if let Some(mut record) = store.get(&file_key).await? {
            record.staleness.value = 1.0;
            record.staleness.tier = StalenessTier::Tombstone;
            record.staleness.signals.push(StalenessSignal::FileDeleted);
            record.staleness.computed_at = now;
            record.updated_at = now;
            record.version.logical_clock += 1;
            record.version.wall_clock = now;
            return Ok(Some((file_key, record)));
        }
        return Ok(None);
    }

    // 2-3. Detect language, parse file.
    let language = detect_language(&abs_path);
    let size_bytes = std::fs::metadata(&abs_path).map(|m| m.len()).unwrap_or(0);
    let walked = WalkedFile {
        abs_path: abs_path.clone(),
        rel_path: rel_path.to_string(),
        language,
        size_bytes,
        mtime_secs: 0,
    };
    let analysis = match parse_file(&walked) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!("reparse_staged: parse failed for {rel_path}: {e}");
            return Ok(None);
        }
    };

    // 4. Fetch existing record.
    let existing = store.get(&file_key).await?;

    // 5. No record → create Layer 0 stub.
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
        return Ok(Some((file_key, new_record)));
    };

    // 6. Deserialize existing payload.
    let old_fr: FileRecord = match record.payload_as::<FileRecord>() {
        Some(fr) => fr,
        None => {
            let file_record = build_file_record_from_analysis(rel_path, &analysis, &walked, now);
            record.value = file_record.purpose.clone();
            record.payload = serde_json::to_value(&file_record).ok();
            record.updated_at = now;
            record.version.logical_clock += 1;
            record.version.wall_clock = now;
            return Ok(Some((file_key, record)));
        }
    };

    // 7. Compute diff — no change means no write.
    let diff = compute_diff(&old_fr, &analysis);
    if diff.is_empty() {
        return Ok(None);
    }

    // 8. Merge structural fields, preserve enrichment.
    let merged = FileRecord {
        path: rel_path.to_string(),
        purpose: old_fr.purpose,
        entry_points: public_api_symbols(&analysis),
        imports: analysis.imports.iter().map(|i| i.path.clone()).collect(),
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
        blast_radius: old_fr.blast_radius,
    };

    record.value = merged.purpose.clone();
    record.payload = serde_json::to_value(&merged).ok();

    // 9-10. Apply staleness, bump version.
    let _signals = apply_reparse_staleness(&mut record, &diff);
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;

    // NOTE: staleness cascade to linked gotchas is NOT done here.
    // The caller handles it as a best-effort substep after committing.

    Ok(Some((file_key, record)))
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
        entry_points: public_api_symbols(analysis),
        imports: analysis.imports.iter().map(|i| i.path.clone()).collect(),
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
        blast_radius: None,
    }
}

/// Compute the structural diff between an old FileRecord and new analysis.
pub fn compute_diff(old: &FileRecord, new: &StaticFileAnalysis) -> ReparseDiff {
    let new_public_api = public_api_symbols(new);
    let old_eps: HashSet<&str> = old.entry_points.iter().map(|s| s.as_str()).collect();
    let new_eps: HashSet<&str> = new_public_api.iter().map(|s| s.as_str()).collect();

    let entry_points_added: Vec<String> = new_eps
        .difference(&old_eps)
        .map(|s| s.to_string())
        .collect();
    let entry_points_removed: Vec<String> = old_eps
        .difference(&new_eps)
        .map(|s| s.to_string())
        .collect();

    let old_imports: HashSet<&str> = old.imports.iter().map(|s| s.as_str()).collect();
    let new_imports: HashSet<&str> = new.imports.iter().map(|s| s.path.as_str()).collect();

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::parser::{ImportKind, ImportStatement};
    use crate::analysis::walker::Language;
    use tempfile::TempDir;

    fn make_old_file_record() -> FileRecord {
        FileRecord {
            path: "src/main.rs".into(),
            purpose: "Main entry point".into(),
            entry_points: vec!["main".into(), "old_fn".into()],
            imports: vec!["std::io".into()],
            gotcha_keys: vec!["gotcha:test".into()],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 1,
            change_frequency: 5,
            last_author: Some("dev".into()),
            is_hotspot: true,
            token_cost_estimate: 100,
            last_modified_session: 1_000_000,
            content_hash: None,
            line_count: 0,
            blast_radius: None,
        }
    }

    fn make_new_analysis() -> StaticFileAnalysis {
        StaticFileAnalysis {
            path: "src/main.rs".into(),
            language: Language::Rust,
            entry_points: vec!["main".into(), "new_fn".into()],
            exported_types: vec![],
            imports: vec![
                ImportStatement::new("std::io", ImportKind::Normal, 1),
                ImportStatement::new("anyhow", ImportKind::Normal, 2),
            ],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            panic_count: 0,
            branch_count: 0,
            module_doc: None,
            content_hash: None,
            line_count: 0,
        }
    }

    #[test]
    fn compute_diff_detects_entry_point_changes() {
        let old = make_old_file_record();
        let new = make_new_analysis();
        let diff = compute_diff(&old, &new);

        assert!(diff.entry_points_added.contains(&"new_fn".to_string()));
        assert!(diff.entry_points_removed.contains(&"old_fn".to_string()));
    }

    #[test]
    fn compute_diff_detects_import_changes() {
        let old = make_old_file_record();
        let new = make_new_analysis();
        let diff = compute_diff(&old, &new);

        assert!(diff.imports_added.contains(&"anyhow".to_string()));
        assert!(diff.imports_removed.is_empty());
    }

    #[test]
    fn compute_diff_detects_unwrap_delta() {
        let old = make_old_file_record();
        let new = make_new_analysis();
        let diff = compute_diff(&old, &new);
        assert_eq!(diff.unwrap_delta, -1);
    }

    #[test]
    fn compute_diff_empty_when_identical() {
        let old = FileRecord {
            path: "src/main.rs".into(),
            purpose: "test".into(),
            entry_points: vec!["main".into()],
            imports: vec!["std::io".into()],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 0,
            last_modified_session: 0,
            content_hash: None,
            line_count: 0,
            blast_radius: None,
        };
        let new = StaticFileAnalysis {
            path: "src/main.rs".into(),
            language: Language::Rust,
            entry_points: vec!["main".into()],
            exported_types: vec![],
            imports: vec![ImportStatement::new("std::io", ImportKind::Normal, 1)],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            panic_count: 0,
            branch_count: 0,
            module_doc: None,
            content_hash: None,
            line_count: 0,
        };
        let diff = compute_diff(&old, &new);
        assert!(diff.is_empty());
    }

    #[tokio::test]
    async fn reparse_creates_stub_for_unknown_file() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::write(repo.join("new_file.rs"), "pub fn hello() {}").unwrap();

        let store = Store::open(repo).await.unwrap();
        reparse_impl(&store, repo, "new_file.rs").await.unwrap();

        let record = store.get("file:new_file.rs").await.unwrap();
        assert!(record.is_some());
        let r = record.unwrap();
        assert_eq!(r.category, Category::File);

        let fr: FileRecord = r.payload_as::<FileRecord>().unwrap();
        assert!(fr.purpose.is_empty());
        assert!(fr.entry_points.contains(&"hello".to_string()));

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn reparse_marks_deleted_file_as_tombstone() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();

        let store = Store::open(repo).await.unwrap();

        let fr = FileRecord {
            path: "gone.rs".into(),
            purpose: String::new(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 0,
            last_modified_session: 0,
            content_hash: None,
            line_count: 0,
            blast_radius: None,
        };
        let record = Record {
            key: "file:gone.rs".into(),
            value: serde_json::to_string(&fr).unwrap(),
            category: Category::File,
            priority: crate::store::record::Priority::Normal,
            tags: vec![],
            created_at: 1_000_000,
            updated_at: 1_000_000,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 1_000_000,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: None,
        };
        store.put("file:gone.rs", &record).await.unwrap();

        reparse_impl(&store, repo, "gone.rs").await.unwrap();

        let updated = store.get("file:gone.rs").await.unwrap().unwrap();
        assert_eq!(updated.staleness.tier, StalenessTier::Tombstone);
        assert!(updated.staleness.value >= 1.0 - f32::EPSILON);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn reparse_preserves_enrichment_fields_and_bumps_staleness() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::write(repo.join("lib.rs"), "pub fn new_fn() {}\npub fn kept() {}").unwrap();

        let store = Store::open(repo).await.unwrap();

        let fr = FileRecord {
            path: "lib.rs".into(),
            purpose: "Core library".into(),
            entry_points: vec!["old_fn".into(), "kept".into()],
            imports: vec![],
            gotcha_keys: vec!["gotcha:important".into()],
            decision_keys: vec!["decision:arch".into()],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 10,
            last_author: Some("ioni".into()),
            is_hotspot: true,
            token_cost_estimate: 50,
            last_modified_session: 1_000_000,
            content_hash: None,
            line_count: 0,
            blast_radius: None,
        };
        let record = Record {
            key: "file:lib.rs".into(),
            value: fr.purpose.clone(),
            payload: serde_json::to_value(&fr).ok(),
            category: Category::File,
            priority: crate::store::record::Priority::Normal,
            tags: vec![],
            created_at: 1_000_000,
            updated_at: 1_000_000,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 1_000_000,
            },
            quality: QualityScore::layer0_default(),
            access_count: 3,
            last_accessed: 1_000_000,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
        };
        store.put("file:lib.rs", &record).await.unwrap();

        reparse_impl(&store, repo, "lib.rs").await.unwrap();

        let updated = store.get("file:lib.rs").await.unwrap().unwrap();
        let updated_fr: FileRecord = updated.payload_as::<FileRecord>().unwrap();

        // Preserved enrichment
        assert_eq!(updated_fr.purpose, "Core library");
        assert_eq!(updated_fr.gotcha_keys, vec!["gotcha:important"]);
        assert_eq!(updated_fr.decision_keys, vec!["decision:arch"]);
        assert_eq!(updated_fr.change_frequency, 10);
        assert_eq!(updated_fr.last_author.as_deref(), Some("ioni"));
        assert!(updated_fr.is_hotspot);

        // Updated structural fields
        assert!(updated_fr.entry_points.contains(&"new_fn".to_string()));
        assert!(updated_fr.entry_points.contains(&"kept".to_string()));
        assert!(!updated_fr.entry_points.contains(&"old_fn".to_string()));
        assert!(updated_fr.content_hash.is_some());
        assert!(updated_fr.line_count > 0);

        // Staleness should have bumped (entry point changes)
        assert!(updated.staleness.value > 0.0);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn reparse_noop_when_no_structural_changes() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::write(repo.join("stable.rs"), "pub fn run() {}").unwrap();

        let store = Store::open(repo).await.unwrap();

        let fr = FileRecord {
            path: "stable.rs".into(),
            purpose: "Stable module".into(),
            entry_points: vec!["run".into()],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 50,
            last_modified_session: 1_000_000,
            content_hash: None,
            line_count: 0,
            blast_radius: None,
        };
        let record = Record {
            key: "file:stable.rs".into(),
            value: fr.purpose.clone(),
            payload: serde_json::to_value(&fr).ok(),
            category: Category::File,
            priority: crate::store::record::Priority::Normal,
            tags: vec![],
            created_at: 1_000_000,
            updated_at: 1_000_000,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 1_000_000,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
        };
        store.put("file:stable.rs", &record).await.unwrap();

        reparse_impl(&store, repo, "stable.rs").await.unwrap();

        // Version should NOT have changed (no write)
        let after = store.get("file:stable.rs").await.unwrap().unwrap();
        assert_eq!(after.version.logical_clock, 1);
        assert_eq!(after.updated_at, 1_000_000);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn reparse_preserves_exported_types_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::write(repo.join("models.rs"), "pub struct Widget;\n").unwrap();

        let store = Store::open(repo).await.unwrap();
        reparse_impl(&store, repo, "models.rs").await.unwrap();

        let record = store.get("file:models.rs").await.unwrap().unwrap();
        let fr: FileRecord = record.payload_as::<FileRecord>().unwrap();
        assert!(fr.entry_points.contains(&"Widget".to_string()));
        assert!(fr.content_hash.is_some());
        assert!(fr.line_count > 0);

        store.close().await.unwrap();
    }
}
