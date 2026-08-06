use super::*;

// ─────────────────────────────────────────────

/// Store key for the enforcement mode setting.
const ENFORCEMENT_MODE_KEY: &str = "enforcement:mode";

/// Store key for the local policy posture kill switch.
pub(crate) const POLICY_MODE_KEY: &str = "enforcement:policy_mode";

/// Default retention period in days.
const DEFAULT_RETENTION_DAYS: u64 = 365;

/// Store key for the retention period setting.
const RETENTION_DAYS_KEY: &str = "enforcement:retention_days";

/// Read the current enforcement mode from the store.
/// Defaults to Advisory if not set or unreadable.
pub async fn get_enforcement_mode(store: &Store) -> EnforcementMode {
    match store.get_raw_bytes(ENFORCEMENT_MODE_KEY).await {
        Ok(Some(bytes)) => match std::str::from_utf8(&bytes) {
            Ok("strict") => EnforcementMode::Strict,
            _ => EnforcementMode::Advisory,
        },
        _ => EnforcementMode::Advisory,
    }
}

/// Persist the enforcement mode to the store. Returns the previous mode.
/// Records an EnforcementConfigChanged event when the mode actually changes.
pub async fn set_enforcement_mode(store: &Store, mode: EnforcementMode) -> Result<EnforcementMode> {
    let old = get_enforcement_mode(store).await;
    let value = match mode {
        EnforcementMode::Advisory => "advisory",
        EnforcementMode::Strict => "strict",
    };
    store
        .put_raw(ENFORCEMENT_MODE_KEY, value.as_bytes())
        .await?;

    // Record config change event if the mode actually changed. The audit event
    // uses the USER-FACING vocabulary (audit.write_durability / best_effort),
    // even though the internal enum + stored value stay advisory/strict (frozen
    // by the RecordingGap hash contract and the storage round-trip).
    if old != mode {
        let user_label = |m: EnforcementMode| match m {
            EnforcementMode::Advisory => "best_effort",
            EnforcementMode::Strict => "strict",
        };
        // Best-effort — don't fail the config change if event recording fails
        let _ = record_event(
            store,
            EnforcementEventType::EnforcementConfigChanged {
                setting: "audit.write_durability".to_string(),
                old_value: user_label(old).to_string(),
                new_value: user_label(mode).to_string(),
            },
            SubjectKind::Config,
            "enforcement:mode".to_string(),
            "developer".to_string(),
            None,
            "config_changed".to_string(),
            None,
        )
        .await;
    }
    Ok(old)
}

/// Read the policy posture. Policies deny by default when this key is absent
/// or unreadable; `advisory` is an explicit global kill switch.
pub async fn get_policy_mode(store: &Store) -> EnforcementMode {
    match store.get_raw_bytes(POLICY_MODE_KEY).await {
        Ok(Some(bytes)) if bytes.as_slice() == b"advisory" => EnforcementMode::Advisory,
        _ => EnforcementMode::Strict,
    }
}

/// Persist the policy posture and return the previous value.
pub async fn set_policy_mode(store: &Store, mode: EnforcementMode) -> Result<EnforcementMode> {
    let old = get_policy_mode(store).await;
    let value = match mode {
        EnforcementMode::Advisory => "advisory",
        EnforcementMode::Strict => "strict",
    };
    store.put_raw(POLICY_MODE_KEY, value.as_bytes()).await?;
    if old != mode {
        let label = |mode: EnforcementMode| match mode {
            EnforcementMode::Advisory => "advisory",
            EnforcementMode::Strict => "strict",
        };
        let _ = record_event(
            store,
            EnforcementEventType::EnforcementConfigChanged {
                setting: "policy.mode".to_string(),
                old_value: label(old).to_string(),
                new_value: label(mode).to_string(),
            },
            SubjectKind::Config,
            POLICY_MODE_KEY.to_string(),
            "developer".to_string(),
            None,
            "config_changed".to_string(),
            None,
        )
        .await;
    }
    Ok(old)
}

/// Read the configured retention period in days.
pub async fn get_retention_days(store: &Store) -> u64 {
    match store.get_raw_bytes(RETENTION_DAYS_KEY).await {
        Ok(Some(bytes)) => std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_RETENTION_DAYS),
        _ => DEFAULT_RETENTION_DAYS,
    }
}

/// Persist the retention period.
pub async fn set_retention_days(store: &Store, days: u64) -> Result<()> {
    store
        .put_raw(RETENTION_DAYS_KEY, days.to_string().as_bytes())
        .await
}
