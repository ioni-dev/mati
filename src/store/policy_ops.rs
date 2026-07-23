//! Centralized mutations for developer-authored local policies.
//!
//! A policy record is the complete source of truth in Milestone 1. The record
//! is committed before its best-effort audit event, and there is no derived
//! index or repair path to maintain.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use globset::Glob;

use super::db::Store;
use super::enforcement::{record_event, ControlChangeKind, EnforcementEventType, SubjectKind};
use super::record::{
    Category, ConfidenceScore, PolicyRecord, PolicyStage, QualityScore, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore, TombstoneReason,
};

/// Typed failure modes for policy mutations, so callers (e.g. the daemon
/// dispatcher) can map them to protocol error codes without matching on the
/// message text.
#[derive(Debug, thiserror::Error)]
pub enum PolicyOpError {
    #[error("invalid policy key '{key}'; expected policy:<slug>")]
    InvalidKey { key: String },
    #[error("record not found: {key}")]
    NotFound { key: String },
    #[error("policy key '{key}' already exists; edit the existing record instead")]
    AlreadyExists { key: String },
    #[error("policy '{key}' is not active")]
    NotActive { key: String },
    #[error("'{key}' is not a policy record")]
    NotAPolicy { key: String },
    #[error("'{key}' has no valid PolicyRecord payload")]
    InvalidPayload { key: String },
    #[error("invalid {field} '{pattern}': {source}")]
    InvalidGlob {
        field: &'static str,
        pattern: String,
        source: globset::Error,
    },
}

/// Validate the glob predicates before a policy can become durable state.
pub fn validate_trigger(trigger: &super::record::PolicyTrigger) -> Result<()> {
    if let Some(pattern) = trigger.host_glob.as_deref() {
        Glob::new(pattern).map_err(|source| PolicyOpError::InvalidGlob {
            field: "host_glob",
            pattern: pattern.to_string(),
            source,
        })?;
    }
    if let Some(pattern) = trigger.target_path_glob.as_deref() {
        Glob::new(pattern).map_err(|source| PolicyOpError::InvalidGlob {
            field: "target_path_glob",
            pattern: pattern.to_string(),
            source,
        })?;
    }
    Ok(())
}

/// Return author-time warnings without changing policy state.
/// Key prefixes `mem_set` will write. A `requires.key` outside this set can
/// never be backed by a record, so telling the author to "store a record there"
/// would be advice they cannot follow.
pub const WRITABLE_KEY_PREFIXES: &[&str] = &["gotcha:", "decision:", "dev_note:", "policy:"];

/// Trigger tools that at least one installed policy adapter evaluates.
pub const ADAPTER_POLICY_TOOLS: &[&str] = &["db_client", "path"];

/// Can a record ever exist at this key?
pub fn key_is_writable(key: &str) -> bool {
    WRITABLE_KEY_PREFIXES
        .iter()
        .any(|prefix| key.starts_with(prefix) && key.len() > prefix.len())
}

pub fn author_warnings(policy: &PolicyRecord, has_backing_record: bool) -> Vec<String> {
    let mut warnings = Vec::new();
    if policy.trigger.tool.as_deref() == Some("file_read") {
        warnings.push(
            "warning: policy trigger tool 'file_read' has no enforcing adapter; Bash file reads are governed by gotchas, so this policy will never be evaluated. Use a gotcha for reads or a db_client/path policy for an adapter-backed action.".into(),
        );
    }
    if let Some(tool) = policy
        .trigger
        .tool
        .as_deref()
        .filter(|tool| !ADAPTER_POLICY_TOOLS.contains(tool))
    {
        warnings.push(format!(
            "warning: policy trigger tool '{tool}' is not a recognized governable category (known: db_client, file_read, path); this policy will never match until such a category is supported."
        ));
    }
    if policy
        .requires
        .via
        .contains(&super::record::ReceiptSource::MemGet)
        && !has_backing_record
    {
        let key = &policy.requires.key;
        if key_is_writable(key) {
            warnings.push(format!(
                "warning: requires.key '{key}' has no backing record; a mem_get on it would mint a receipt without the agent learning anything. Store a record at that key (e.g. the schema doc) so consultation is substantive."
            ));
        } else {
            // The old wording told the author to store a record at a key
            // nothing can write to, which reads as a step they skipped rather
            // than a key they must rename.
            warnings.push(format!(
                "warning: requires.key '{key}' can never hold a record: mem_set writes only {} prefixes. A mem_get on it mints a receipt that teaches the agent nothing. Use a writable key, such as 'decision:{}'.",
                WRITABLE_KEY_PREFIXES.join(", "),
                key.rsplit(':').next().unwrap_or("the-doc")
            ));
        }
    }
    if policy.requires.freshness.fingerprint
        && !policy
            .requires
            .via
            .contains(&super::record::ReceiptSource::MemGet)
    {
        warnings.push("warning: requires.freshness.fingerprint is unsatisfiable without MemGet; DbIntrospection receipts do not carry a content fingerprint.".into());
    }
    if policy.mode == super::record::PolicyMode::Block && policy.requires.key.is_empty() {
        warnings.push(
            "warning: block policy has an empty requires.key; nothing could ever unlock it.".into(),
        );
    }
    warnings
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn ensure_policy_key(key: &str) -> Result<()> {
    if !key.starts_with("policy:") || key.len() == "policy:".len() {
        return Err(PolicyOpError::InvalidKey {
            key: key.to_string(),
        }
        .into());
    }
    Ok(())
}

fn audit_kind(kind: ControlChangeKind) -> &'static str {
    match kind {
        ControlChangeKind::Created => "control_created",
        ControlChangeKind::Updated => "control_updated",
        ControlChangeKind::Deleted => "control_deleted",
        ControlChangeKind::Confirmed => "control_updated",
    }
}

async fn audit(store: &Store, key: &str, kind: ControlChangeKind) {
    if let Err(error) = record_event(
        store,
        EnforcementEventType::ControlChanged { change_kind: kind },
        SubjectKind::Control,
        key.to_string(),
        "developer".to_string(),
        None,
        audit_kind(kind).to_string(),
        None,
    )
    .await
    {
        tracing::warn!("policy_ops: enforcement event recording failed for {key}: {error}");
    }
}

/// Build the neutral universal-record envelope for a policy payload.
pub fn record_for(key: &str, policy: &PolicyRecord) -> Result<Record> {
    ensure_policy_key(key)?;
    let now = now_secs();
    let source = RecordSource::DeveloperManual;
    Ok(Record {
        key: key.to_string(),
        value: policy.rule.clone(),
        category: Category::Policy,
        priority: policy.severity.clone(),
        tags: vec![],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: crate::store::stable_device_id(),
            logical_clock: 1,
            wall_clock: now,
        },
        quality: QualityScore::developer_entry_default(),
        access_count: 0,
        last_accessed: 0,
        source: source.clone(),
        confidence: ConfidenceScore::for_new_record(&source),
        gap_analysis_score: 0.0,
        payload: Some(serde_json::to_value(policy)?),
    })
}

/// Create a policy. The canonical record write fails hard; the audit is best effort.
///
/// An existing *active* policy at this key is rejected. A *tombstoned* one is
/// replaced by the fresh record, so a deleted slug can be recreated.
pub async fn create(store: &Store, key: &str, policy: &PolicyRecord) -> Result<()> {
    validate_trigger(&policy.trigger)?;
    let record = record_for(key, policy)?;
    if let Some(existing) = store.get(key).await? {
        if matches!(existing.lifecycle, RecordLifecycle::Active) {
            return Err(PolicyOpError::AlreadyExists {
                key: key.to_string(),
            }
            .into());
        }
    }
    store.put(key, &record).await?;
    audit(store, key, ControlChangeKind::Created).await;
    Ok(())
}

/// Replace an existing active policy payload.
pub async fn edit(store: &Store, key: &str, policy: &PolicyRecord) -> Result<()> {
    validate_trigger(&policy.trigger)?;
    ensure_policy_key(key)?;
    let mut record = store
        .get(key)
        .await?
        .ok_or_else(|| PolicyOpError::NotFound {
            key: key.to_string(),
        })?;
    if record.category != Category::Policy {
        return Err(PolicyOpError::NotAPolicy {
            key: key.to_string(),
        }
        .into());
    }
    if !matches!(record.lifecycle, RecordLifecycle::Active) {
        return Err(PolicyOpError::NotActive {
            key: key.to_string(),
        }
        .into());
    }
    record.value = policy.rule.clone();
    record.priority = policy.severity.clone();
    record.updated_at = now_secs();
    record.version.logical_clock += 1;
    record.version.wall_clock = record.updated_at;
    record.payload = Some(serde_json::to_value(policy)?);
    store.put(key, &record).await?;
    audit(store, key, ControlChangeKind::Updated).await;
    Ok(())
}

/// Enable or disable an active policy.
pub async fn set_stage(store: &Store, key: &str, stage: PolicyStage) -> Result<()> {
    ensure_policy_key(key)?;
    let mut record = store
        .get(key)
        .await?
        .ok_or_else(|| PolicyOpError::NotFound {
            key: key.to_string(),
        })?;
    let mut policy =
        record
            .payload_as::<PolicyRecord>()
            .ok_or_else(|| PolicyOpError::InvalidPayload {
                key: key.to_string(),
            })?;
    if !matches!(record.lifecycle, RecordLifecycle::Active) {
        return Err(PolicyOpError::NotActive {
            key: key.to_string(),
        }
        .into());
    }
    policy.stage = stage;
    record.payload = Some(serde_json::to_value(&policy)?);
    record.updated_at = now_secs();
    record.version.logical_clock += 1;
    record.version.wall_clock = record.updated_at;
    store.put(key, &record).await?;
    audit(store, key, ControlChangeKind::Updated).await;
    Ok(())
}

/// Tombstone a policy. The tombstone write fails hard; its audit event is best effort.
pub async fn delete(store: &Store, key: &str) -> Result<()> {
    ensure_policy_key(key)?;
    let mut record = store
        .get(key)
        .await?
        .ok_or_else(|| PolicyOpError::NotFound {
            key: key.to_string(),
        })?;
    if !matches!(record.lifecycle, RecordLifecycle::Active) {
        return Err(PolicyOpError::NotActive {
            key: key.to_string(),
        }
        .into());
    }
    let now = now_secs();
    record.lifecycle = RecordLifecycle::Tombstoned {
        reason: TombstoneReason::ManualDeletion,
        at: now,
    };
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;
    store.put(key, &record).await?;
    audit(store, key, ControlChangeKind::Deleted).await;
    Ok(())
}

pub async fn list(store: &Store) -> Result<Vec<Record>> {
    Ok(store
        .scan_prefix("policy:")
        .await?
        .into_iter()
        .filter(|record| matches!(record.lifecycle, RecordLifecycle::Active))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample() -> PolicyRecord {
        PolicyRecord {
            name: "Query safety".into(),
            rule: "Consult the schema first.".into(),
            reason: "Schemas drift because production changes independently.".into(),
            scope: "repo".into(),
            mode: super::super::record::PolicyMode::Block,
            trigger: Default::default(),
            requires: super::super::record::PolicyRequires {
                key: "schema:orders".into(),
                via: vec![super::super::record::ReceiptSource::MemGet],
                freshness: super::super::record::PolicyFreshness {
                    ttl_secs: 900,
                    fingerprint: false,
                },
            },
            stage: PolicyStage::Enforce,
            severity: super::super::record::Priority::High,
            created_by: "developer".into(),
        }
    }

    #[tokio::test]
    async fn lifecycle_emits_control_events_and_tombstones() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let key = "policy:query-safety";
        create(&store, key, &sample()).await.unwrap();
        assert_eq!(list(&store).await.unwrap().len(), 1);
        set_stage(&store, key, PolicyStage::Off).await.unwrap();
        set_stage(&store, key, PolicyStage::Enforce).await.unwrap();
        delete(&store, key).await.unwrap();
        assert!(list(&store).await.unwrap().is_empty());
        let events = super::super::enforcement::scan_enforcement_events(&store, 0, u64::MAX)
            .await
            .unwrap();
        assert_eq!(events.len(), 4);
        assert!(events
            .iter()
            .all(|event| event.subject_kind == SubjectKind::Control && event.subject_key == key));
        let kinds: Vec<_> = events
            .iter()
            .filter_map(|event| match event.event_type {
                EnforcementEventType::ControlChanged { change_kind } => Some(change_kind),
                _ => None,
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                ControlChangeKind::Created,
                ControlChangeKind::Updated,
                ControlChangeKind::Updated,
                ControlChangeKind::Deleted
            ]
        );
    }

    #[tokio::test]
    async fn canonical_failure_happens_before_event() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let error = delete(&store, "policy:missing").await.unwrap_err();
        assert!(error.to_string().contains("record not found"));
        assert!(
            super::super::enforcement::scan_enforcement_events(&store, 0, u64::MAX)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn edit_updates_payload_and_bumps_clock() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let key = "policy:query-safety";
        create(&store, key, &sample()).await.unwrap();

        let mut revised = sample();
        revised.rule = "Always consult the schema before any write.".into();
        revised.severity = super::super::record::Priority::Critical;
        edit(&store, key, &revised).await.unwrap();

        let record = store.get(key).await.unwrap().unwrap();
        let policy = record.payload_as::<PolicyRecord>().unwrap();
        assert_eq!(policy.rule, "Always consult the schema before any write.");
        assert_eq!(record.priority, super::super::record::Priority::Critical);
        assert_eq!(record.version.logical_clock, 2);

        // editing a missing key fails hard
        assert!(edit(&store, "policy:missing", &revised).await.is_err());
    }

    #[tokio::test]
    async fn create_rejects_active_duplicate_but_resurrects_tombstone() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let key = "policy:dup";
        create(&store, key, &sample()).await.unwrap();
        // an active duplicate is rejected
        assert!(create(&store, key, &sample()).await.is_err());
        // after delete, the slug can be recreated
        delete(&store, key).await.unwrap();
        create(&store, key, &sample()).await.unwrap();
        assert_eq!(list(&store).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn create_rejects_malformed_trigger_before_persisting() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let key = "policy:invalid-glob";
        let mut policy = sample();
        policy.trigger.host_glob = Some("[".into());

        let error = create(&store, key, &policy).await.unwrap_err();

        assert!(error.to_string().contains("invalid host_glob"));
        assert!(store.get(key).await.unwrap().is_none());
    }
}
