//! Centralized gotcha mutation operations.
//!
//! Every path that creates, edits, or tombstones a gotcha record — CLI direct,
//! daemon socket, MCP server — must go through these functions. They enforce
//! the full invariant: key collision check, record write, file-record link sync,
//! and graph edge management.
//!
//! Keeping this in the library crate (`mati_core::store`) ensures the binary
//! crate (`cli/`) and the MCP server (`mcp/server.rs`) share the same logic.
//!
//! ## Partial-failure behaviour
//!
//! SurrealKV supports multi-key atomic transactions within a single tree.
//! However, gotcha mutations span both the knowledge tree (gotcha records,
//! file-record links) and the sessions tree (graph edges). No single
//! transaction can span both trees — this is mati's two-tree architecture
//! constraint, not a SurrealKV limitation.
//!
//! The v2 protocol handlers in `mcp::handlers` stage knowledge-tree writes
//! (gotcha record + file-link updates + audit) in a single atomic
//! `transact_knowledge` call. Graph edge writes remain best-effort.
//!
//! The functions below are retained for the CLI direct-store path and as
//! building blocks. Their ordering is chosen to minimize damage from a
//! mid-operation failure:
//!
//! 1. **Record write first** — the gotcha record is the source of truth. If
//!    later steps fail, the record exists and a future mutation or manual
//!    `mati review` can reconcile the stale links.
//! 2. **File-record links second** — these are the primary consumer-visible
//!    state. A missing link causes a false-negative (gotcha not shown for a
//!    file); a stale link causes a false-positive. Both are visible in `mati
//!    status` and correctable by re-running `mati gotcha edit`.
//! 3. **Graph edges last** — edges are rebuilt from KV on every `Graph::load`,
//!    so a missing edge is corrected at next graph load as long as the
//!    file-record link is correct.
//!
//! Link-sync and edge-write failures are logged and set a dirty marker via
//! [`super::repair::mark_dirty`]. This makes drift visible in `mati status`
//! and repairable via `mati repair`. The record write is never rolled back,
//! since a partially-linked gotcha is recoverable but a silently lost one
//! is not.
//!
//! See [`super::repair`] for the full consistency model.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::graph::edges::{Edge, EdgeKind};
use crate::store::db::Store;
use crate::store::enforcement::{
    record_event, ControlChangeKind, EnforcementEventType, SubjectKind,
};
use crate::store::record::{Record, RecordLifecycle, TombstoneReason};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Key collision ────────────────────────────────────────────────────────────

/// Bail if `key` already exists as an active record.
///
/// Called before writing a new gotcha to prevent silent overwrites.
pub async fn ensure_gotcha_key_available(store: &Store, key: &str) -> Result<()> {
    if store.get(key).await?.is_some() {
        anyhow::bail!("gotcha key '{key}' already exists; edit the existing record instead");
    }
    Ok(())
}

// ── Full mutation operations ─────────────────────────────────────────────────

/// Write a gotcha record and maintain all related state:
///
/// 1. If `is_new`, check for key collision.
/// 2. Write the record to the store.
/// 3. Sync `gotcha_keys` in affected file records (add to new files, remove
///    from old files).
/// 4. Add `HasGotcha` graph edges for newly-associated files.
/// 5. Remove `HasGotcha` graph edges for disassociated files.
///
/// Steps 1–2 fail hard (the caller sees an error). Steps 3–5 are
/// best-effort: failures are logged but do not roll back the record write.
pub async fn apply_gotcha_write(
    store: &Store,
    record: &Record,
    old_files: &[String],
    new_files: &[String],
    is_new: bool,
) -> Result<()> {
    let key = &record.key;

    // 1. Collision guard — fail hard
    if is_new {
        ensure_gotcha_key_available(store, key).await?;
    }

    // 2. Persist the gotcha record — fail hard
    store.put(key, record).await?;

    // 2b. Record enforcement event — best-effort (advisory mode logged, strict propagated)
    let change_kind = if is_new {
        ControlChangeKind::Created
    } else {
        ControlChangeKind::Updated
    };
    if let Err(e) = record_event(
        store,
        EnforcementEventType::ControlChanged { change_kind },
        SubjectKind::Control,
        key.to_string(),
        "developer".to_string(),
        None,
        if is_new {
            "control_created".to_string()
        } else {
            "control_updated".to_string()
        },
        None,
    )
    .await
    {
        tracing::warn!("gotcha_write: enforcement event recording failed for {key}: {e}");
    }

    // 3. Sync file-record gotcha_keys — best-effort
    if let Err(e) = sync_gotcha_file_links(store, key, old_files, new_files).await {
        tracing::warn!("gotcha_write: file link sync failed for {key}: {e}");
        crate::store::repair::mark_dirty(store, key, &format!("link sync failed: {e}")).await;
    }

    // 4 + 5. Graph edges — best-effort
    let old_set: HashSet<&str> = old_files.iter().map(String::as_str).collect();
    let new_set: HashSet<&str> = new_files.iter().map(String::as_str).collect();

    let ts = now_secs().to_le_bytes();
    for file_path in &new_set {
        if !old_set.contains(*file_path) {
            let file_key = format!("file:{file_path}");
            let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, key.as_str()).to_key();
            if let Err(e) = store.put_raw(&edge_key, &ts).await {
                tracing::warn!("gotcha_write: edge add failed for {file_key} → {key}: {e}");
                crate::store::repair::mark_dirty(store, key, &format!("edge add failed: {e}"))
                    .await;
            }
        }
    }
    for file_path in &old_set {
        if !new_set.contains(*file_path) {
            let file_key = format!("file:{file_path}");
            let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, key.as_str()).to_key();
            if let Err(e) = store.delete(&edge_key).await {
                tracing::warn!("gotcha_write: edge remove failed for {file_key} → {key}: {e}");
                crate::store::repair::mark_dirty(store, key, &format!("edge remove failed: {e}"))
                    .await;
            }
        }
    }

    Ok(())
}

/// Tombstone a gotcha record and clean up all related state:
///
/// 1. Set lifecycle to `Tombstoned`, bump version.
/// 2. Remove `gotcha_keys` entries from all affected file records.
/// 3. Remove all `HasGotcha` graph edges.
///
/// Step 1 fails hard. Steps 2–3 are best-effort: failures are logged but
/// do not un-tombstone the record.
pub async fn apply_gotcha_tombstone(
    store: &Store,
    key: &str,
    affected_files: &[String],
) -> Result<()> {
    // 1. Tombstone the record — fail hard
    match store.get(key).await? {
        Some(mut record) => {
            let now = now_secs();
            record.lifecycle = RecordLifecycle::Tombstoned {
                reason: TombstoneReason::ManualDeletion,
                at: now,
            };
            record.updated_at = now;
            record.version.logical_clock += 1;
            record.version.wall_clock = now;
            store.put(key, &record).await?;
        }
        None => anyhow::bail!("record not found: {key}"),
    }

    // 1b. Record enforcement event for deletion — best-effort
    if let Err(e) = record_event(
        store,
        EnforcementEventType::ControlChanged {
            change_kind: ControlChangeKind::Deleted,
        },
        SubjectKind::Control,
        key.to_string(),
        "developer".to_string(),
        None,
        "control_deleted".to_string(),
        None,
    )
    .await
    {
        tracing::warn!("gotcha_tombstone: enforcement event recording failed for {key}: {e}");
    }

    // 2. Remove gotcha_keys from file records — best-effort
    if let Err(e) = sync_gotcha_file_links(store, key, affected_files, &[]).await {
        tracing::warn!("gotcha_tombstone: file link cleanup failed for {key}: {e}");
        crate::store::repair::mark_dirty(
            store,
            key,
            &format!("tombstone link cleanup failed: {e}"),
        )
        .await;
    }

    // 3. Remove graph edges — best-effort
    for file_path in affected_files {
        let file_key = format!("file:{file_path}");
        let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, key).to_key();
        if let Err(e) = store.delete(&edge_key).await {
            tracing::warn!("gotcha_tombstone: edge remove failed for {file_key} → {key}: {e}");
            crate::store::repair::mark_dirty(
                store,
                key,
                &format!("tombstone edge remove failed: {e}"),
            )
            .await;
        }
    }

    Ok(())
}

/// Persist a confirmed gotcha record and record a `ControlChanged::Confirmed`
/// enforcement event.
///
/// Mirrors the non-collision path of [`apply_gotcha_write`] (record write,
/// file-link sync, graph edges) but emits `Confirmed` instead of `Updated`
/// so the enforcement audit distinguishes user confirmation from edits.
/// Used by the CLI `mati gotcha confirm` direct-mode path and by the legacy
/// socket `gotcha_confirm` command.
pub async fn apply_gotcha_confirm(
    store: &Store,
    record: &Record,
    affected_files: &[String],
) -> Result<()> {
    let key = &record.key;

    // Persist the confirmed record — fail hard.
    store.put(key, record).await?;

    // Record Confirmed enforcement event — best-effort.
    if let Err(e) = record_event(
        store,
        EnforcementEventType::ControlChanged {
            change_kind: ControlChangeKind::Confirmed,
        },
        SubjectKind::Control,
        key.to_string(),
        "developer".to_string(),
        None,
        "control_confirmed".to_string(),
        None,
    )
    .await
    {
        tracing::warn!("gotcha_confirm: enforcement event recording failed for {key}: {e}");
    }

    // Sync file-record gotcha_keys — best-effort. Confirm is purely additive:
    // all affected_files should have the link; none are removed.
    if let Err(e) = sync_gotcha_file_links(store, key, &[], affected_files).await {
        tracing::warn!("gotcha_confirm: file link sync failed for {key}: {e}");
        crate::store::repair::mark_dirty(store, key, &format!("link sync failed: {e}")).await;
    }

    // Graph edges — best-effort.
    let ts = now_secs().to_le_bytes();
    for file_path in affected_files {
        let file_key = format!("file:{file_path}");
        let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, key.as_str()).to_key();
        if let Err(e) = store.put_raw(&edge_key, &ts).await {
            tracing::warn!("gotcha_confirm: edge add failed for {file_key} → {key}: {e}");
            crate::store::repair::mark_dirty(store, key, &format!("edge add failed: {e}")).await;
        }
    }

    Ok(())
}

// ── File-record link sync ────────────────────────────────────────────────────

/// Synchronize `gotcha_keys` in file records with the current affected-file set.
///
/// Adds the gotcha key to files in `new_files` that are not in `old_files`,
/// and removes it from files in `old_files` that are not in `new_files`.
pub async fn sync_gotcha_file_links(
    store: &Store,
    gotcha_key: &str,
    old_files: &[String],
    new_files: &[String],
) -> Result<()> {
    let old_set: HashSet<&str> = old_files.iter().map(String::as_str).collect();
    let new_set: HashSet<&str> = new_files.iter().map(String::as_str).collect();

    for file_path in new_set.difference(&old_set) {
        update_file_gotcha_key(store, file_path, gotcha_key, true).await?;
    }

    for file_path in old_set.difference(&new_set) {
        update_file_gotcha_key(store, file_path, gotcha_key, false).await?;
    }

    Ok(())
}

async fn update_file_gotcha_key(
    store: &Store,
    file_path: &str,
    gotcha_key: &str,
    add: bool,
) -> Result<()> {
    let file_key = format!("file:{file_path}");
    let Some(mut record) = store.get(&file_key).await? else {
        // File record doesn't exist yet. Mark dirty so `mati repair`
        // back-fills the link when the file is later indexed by init.
        if add {
            crate::store::repair::mark_dirty(
                store,
                gotcha_key,
                &format!("file record missing at link-sync time: {file_key}"),
            )
            .await;
        }
        return Ok(());
    };

    let changed = if add {
        add_gotcha_key(&mut record, gotcha_key)
    } else {
        remove_gotcha_key(&mut record, gotcha_key)
    };

    if changed {
        let now = now_secs();
        record.updated_at = now;
        record.version.logical_clock += 1;
        record.version.wall_clock = now;
        store.put(&file_key, &record).await?;
    }

    Ok(())
}

fn add_gotcha_key(record: &mut Record, gotcha_key: &str) -> bool {
    let Some(payload) = record.payload.as_mut() else {
        record.payload = Some(serde_json::json!({ "gotcha_keys": [gotcha_key] }));
        return true;
    };

    if let Some(obj) = payload.as_object_mut() {
        match obj.get_mut("gotcha_keys") {
            Some(existing) => {
                if let Some(arr) = existing.as_array_mut() {
                    if arr.iter().any(|v| v.as_str() == Some(gotcha_key)) {
                        false
                    } else {
                        arr.push(serde_json::Value::String(gotcha_key.to_string()));
                        true
                    }
                } else {
                    *existing = serde_json::json!([gotcha_key]);
                    true
                }
            }
            None => {
                obj.insert("gotcha_keys".into(), serde_json::json!([gotcha_key]));
                true
            }
        }
    } else {
        record.payload = Some(serde_json::json!({ "gotcha_keys": [gotcha_key] }));
        true
    }
}

fn remove_gotcha_key(record: &mut Record, gotcha_key: &str) -> bool {
    let Some(payload) = record.payload.as_mut() else {
        return false;
    };
    let Some(obj) = payload.as_object_mut() else {
        return false;
    };
    let Some(existing) = obj.get_mut("gotcha_keys") else {
        return false;
    };
    let Some(arr) = existing.as_array_mut() else {
        return false;
    };

    let before = arr.len();
    arr.retain(|v| v.as_str() != Some(gotcha_key));
    arr.len() != before
}

// ── Confirmation propagation ─────────────────────────────────────────────────

/// Increment `confirmation_count` on all file records linked to a confirmed gotcha.
///
/// Best-effort: failures are logged but do not fail the confirmation.
/// This propagates the signal that a human verified knowledge about this file,
/// which feeds into the confidence formula via `log2(confirmation_count + 2)`.
pub async fn propagate_confirmation_to_files(store: &Store, affected_files: &[String]) {
    for file_path in affected_files {
        let file_key = format!("file:{file_path}");
        if let Ok(Some(mut file_record)) = store.get(&file_key).await {
            file_record.confidence.confirmation_count += 1;
            let now = now_secs();
            file_record.updated_at = now;
            file_record.version.logical_clock += 1;
            file_record.version.wall_clock = now;
            if let Err(e) = store.put(&file_key, &file_record).await {
                tracing::warn!("propagate_confirmation: failed to update {file_key}: {e}");
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::record::{
        Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, RecordSource,
        RecordVersion, StalenessScore,
    };

    fn make_gotcha_record(key: &str, files: &[&str]) -> Record {
        let gotcha = GotchaRecord {
            rule: "test rule".into(),
            reason: "test reason".into(),
            severity: Priority::High,
            affected_files: files.iter().map(|s| s.to_string()).collect(),
            ref_url: None,
            discovered_session: 1_000_000,
            confirmed: true,
        };
        Record {
            key: key.to_string(),
            value: "test rule because test reason".into(),
            payload: serde_json::to_value(&gotcha).ok(),
            category: Category::Gotcha,
            priority: Priority::High,
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
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
            gap_analysis_score: 0.0,
        }
    }

    fn make_file_record(path: &str) -> Record {
        Record {
            key: format!("file:{path}"),
            value: String::new(),
            payload: Some(serde_json::json!({
                "path": path,
                "purpose": "",
                "entry_points": [],
                "imports": [],
                "gotcha_keys": [],
                "decision_keys": [],
                "todos": [],
                "unsafe_count": 0,
                "unwrap_count": 0,
                "change_frequency": 0,
                "is_hotspot": false,
                "token_cost_estimate": 0,
                "last_modified_session": 0,
                "line_count": 0
            })),
            category: Category::File,
            priority: Priority::Normal,
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
        }
    }

    fn file_gotcha_keys(record: &Record) -> Vec<String> {
        record
            .payload
            .as_ref()
            .and_then(|p| p.get("gotcha_keys"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn ensure_key_available_rejects_existing() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let record = make_gotcha_record("gotcha:exists", &["src/a.rs"]);
        store.put("gotcha:exists", &record).await.unwrap();

        let err = ensure_gotcha_key_available(&store, "gotcha:exists")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));
        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn ensure_key_available_passes_for_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        ensure_gotcha_key_available(&store, "gotcha:new")
            .await
            .unwrap();
        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn apply_write_adds_file_links_and_edges() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Seed file records
        store
            .put("file:src/a.rs", &make_file_record("src/a.rs"))
            .await
            .unwrap();
        store
            .put("file:src/b.rs", &make_file_record("src/b.rs"))
            .await
            .unwrap();

        let record = make_gotcha_record("gotcha:test", &["src/a.rs", "src/b.rs"]);
        let files = vec!["src/a.rs".into(), "src/b.rs".into()];

        apply_gotcha_write(&store, &record, &[], &files, true)
            .await
            .unwrap();

        // Both files should have the gotcha key
        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        let b = store.get("file:src/b.rs").await.unwrap().unwrap();
        assert!(file_gotcha_keys(&a).contains(&"gotcha:test".to_string()));
        assert!(file_gotcha_keys(&b).contains(&"gotcha:test".to_string()));

        // Graph edges should exist
        let edge_keys = store.scan_keys("graph:edge:").await.unwrap();
        let edge_a = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:test").to_key();
        let edge_b = Edge::new("file:src/b.rs", EdgeKind::HasGotcha, "gotcha:test").to_key();
        assert!(edge_keys.contains(&edge_a));
        assert!(edge_keys.contains(&edge_b));

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn apply_write_rejects_collision_when_is_new() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let record = make_gotcha_record("gotcha:dup", &["src/a.rs"]);
        store.put("gotcha:dup", &record).await.unwrap();

        let record2 = make_gotcha_record("gotcha:dup", &["src/b.rs"]);
        let err = apply_gotcha_write(&store, &record2, &[], &["src/b.rs".into()], true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn apply_write_edit_moves_links_between_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put("file:src/a.rs", &make_file_record("src/a.rs"))
            .await
            .unwrap();
        store
            .put("file:src/b.rs", &make_file_record("src/b.rs"))
            .await
            .unwrap();

        // Initial write targeting src/a.rs
        let record = make_gotcha_record("gotcha:move", &["src/a.rs"]);
        apply_gotcha_write(&store, &record, &[], &["src/a.rs".into()], true)
            .await
            .unwrap();

        // Edit: move from src/a.rs to src/b.rs
        let record2 = make_gotcha_record("gotcha:move", &["src/b.rs"]);
        apply_gotcha_write(
            &store,
            &record2,
            &["src/a.rs".into()],
            &["src/b.rs".into()],
            false,
        )
        .await
        .unwrap();

        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        let b = store.get("file:src/b.rs").await.unwrap().unwrap();
        assert!(!file_gotcha_keys(&a).contains(&"gotcha:move".to_string()));
        assert!(file_gotcha_keys(&b).contains(&"gotcha:move".to_string()));

        // Edge should move too
        let edge_keys = store.scan_keys("graph:edge:").await.unwrap();
        let edge_a = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:move").to_key();
        let edge_b = Edge::new("file:src/b.rs", EdgeKind::HasGotcha, "gotcha:move").to_key();
        assert!(!edge_keys.contains(&edge_a));
        assert!(edge_keys.contains(&edge_b));

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn apply_tombstone_cleans_links_and_edges() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put("file:src/a.rs", &make_file_record("src/a.rs"))
            .await
            .unwrap();
        store
            .put("file:src/b.rs", &make_file_record("src/b.rs"))
            .await
            .unwrap();

        // Write gotcha first
        let record = make_gotcha_record("gotcha:del", &["src/a.rs", "src/b.rs"]);
        let files = vec!["src/a.rs".into(), "src/b.rs".into()];
        apply_gotcha_write(&store, &record, &[], &files, true)
            .await
            .unwrap();

        // Tombstone it
        apply_gotcha_tombstone(&store, "gotcha:del", &files)
            .await
            .unwrap();

        // Record should be tombstoned
        let rec = store.get("gotcha:del").await.unwrap().unwrap();
        assert!(matches!(rec.lifecycle, RecordLifecycle::Tombstoned { .. }));

        // File records should have empty gotcha_keys
        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        let b = store.get("file:src/b.rs").await.unwrap().unwrap();
        assert!(file_gotcha_keys(&a).is_empty());
        assert!(file_gotcha_keys(&b).is_empty());

        // Graph edges should be gone
        let edge_keys = store.scan_keys("graph:edge:").await.unwrap();
        let edge_a = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:del").to_key();
        let edge_b = Edge::new("file:src/b.rs", EdgeKind::HasGotcha, "gotcha:del").to_key();
        assert!(!edge_keys.contains(&edge_a));
        assert!(!edge_keys.contains(&edge_b));

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn apply_tombstone_errors_on_missing_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let err = apply_gotcha_tombstone(&store, "gotcha:ghost", &[])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"));

        store.close().await.unwrap();
    }

    /// Simulates the mem_set → sync_gotcha_file_links path: a gotcha is
    /// written directly (as mem_set does), then file links are synced
    /// separately. Verifies that the file record's gotcha_keys are updated.
    #[tokio::test]
    async fn sync_file_links_backfills_after_direct_write() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Seed file record with no gotcha_keys
        store
            .put("file:src/a.rs", &make_file_record("src/a.rs"))
            .await
            .unwrap();

        // Simulate mem_set: write gotcha record directly (no apply_gotcha_write)
        let record = make_gotcha_record("gotcha:mcp-created", &["src/a.rs"]);
        store.put("gotcha:mcp-created", &record).await.unwrap();

        // File should NOT have the link yet (this is the pre-fix state)
        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        assert!(!file_gotcha_keys(&a).contains(&"gotcha:mcp-created".to_string()));

        // Now call sync_gotcha_file_links (what mem_set now does after the fix)
        sync_gotcha_file_links(&store, "gotcha:mcp-created", &[], &["src/a.rs".into()])
            .await
            .unwrap();

        // File should now have the link
        let a2 = store.get("file:src/a.rs").await.unwrap().unwrap();
        assert!(file_gotcha_keys(&a2).contains(&"gotcha:mcp-created".to_string()));

        store.close().await.unwrap();
    }
}
