//! Read-only aggregation of policy enforcement telemetry.
//!
//! These are pure transforms: callers scan the raw records themselves (the CLI
//! through `StoreProxy`, the MCP `mem_query` handler through `&Store`) and hand
//! the record sets here. Keeping the aggregation math in one place means the
//! `mati policy` CLI and the `mem_query` telemetry modes cannot drift — the same
//! records always produce the same report, whichever door reached them.
//!
//! Nothing here computes a verdict or a recommendation. It exposes the local
//! aggregates the store already holds, with their provenance (`sources`,
//! `last_fired_at`, retention bounds) intact. Reporting on top of these numbers
//! lives outside this repo.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::store::enforcement::{EnforcementEventScan, EnforcementEventType, SubjectKind};
use crate::store::record::{PolicyRecord, PolicyStage, Record, RecordLifecycle};
use crate::store::session::{DailyAgg, PolicyShadowAgg, ShadowObservationAgg, MAX_SHADOW_OBSERVATIONS};

/// Enforcement events are retained for a bounded window; activity claims older
/// than this cannot be made.
pub const POLICY_ACTIVITY_RETENTION_DAYS: u64 = 365;
/// Default look-back window for `mati policy activity` and the `policy_activity`
/// query mode.
pub const POLICY_ACTIVITY_DEFAULT_DAYS: u64 = 30;
/// A newly enabled policy is given this long before `mati doctor` flags it as
/// inactive — a quiet first week is not yet evidence the rule is dead.
pub const POLICY_ACTIVITY_GRACE_DAYS: u64 = 7;

/// Whether a policy has fired in the window, or why the question can't be
/// answered.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityState {
    Fired,
    NoActivity,
    NotMeasurable,
}

/// Per-policy activity over the requested window.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyActivity {
    pub policy: String,
    pub state: ActivityState,
    pub window_days: u64,
    pub window_start: u64,
    pub count: u64,
    pub last_fired_at: Option<u64>,
    pub sources: Vec<String>,
}

/// The full activity report for all active, measurable policies.
#[derive(Debug, Clone, Serialize)]
pub struct ActivityReport {
    pub window_days: u64,
    pub window_start: u64,
    pub window_end: u64,
    pub retention_days: u64,
    pub retention_limited: bool,
    pub retention_note: Option<String>,
    pub policies: Vec<PolicyActivity>,
}

/// Start of the look-back window, in epoch seconds. Saturates so a huge `days`
/// can never underflow past the epoch.
pub fn window_start_secs(now_secs: u64, days: u64) -> u64 {
    now_secs.saturating_sub(days.saturating_mul(86_400))
}

/// Accept either a bare slug (`my-rule`) or a full key (`policy:my-rule`).
fn normalize_policy_key(slug: &str) -> String {
    if slug.starts_with("policy:") {
        slug.to_string()
    } else {
        format!("policy:{slug}")
    }
}

/// Merge the bounded daily shadow aggregates into a per-policy view, optionally
/// filtered to one policy. `shadow_records` is the `analytics:policy_shadow_*`
/// scan; observations are kept sorted and capped at `MAX_SHADOW_OBSERVATIONS`.
pub fn assemble_shadow_observations(
    shadow_records: &[Record],
    slug: Option<&str>,
) -> BTreeMap<String, PolicyShadowAgg> {
    let mut observations: BTreeMap<String, PolicyShadowAgg> = BTreeMap::new();
    for record in shadow_records {
        let agg = record
            .payload_as::<ShadowObservationAgg>()
            .unwrap_or_default();
        for (key, mut policy) in agg.policies {
            let entry = observations.entry(key).or_default();
            entry.count += policy.count;
            entry.observations.append(&mut policy.observations);
            entry
                .observations
                .sort_by_key(|observation| observation.timestamp);
            if entry.observations.len() > MAX_SHADOW_OBSERVATIONS {
                let drop_count = entry.observations.len() - MAX_SHADOW_OBSERVATIONS;
                entry.observations.drain(..drop_count);
            }
        }
    }
    if let Some(slug) = slug {
        let key = normalize_policy_key(slug);
        observations.retain(|policy_key, _| policy_key == &key);
    }
    observations
}

/// Build the activity report from pre-scanned record sets.
///
/// `policy_records` is the `policy:*` scan, `enforcement` a time-bounded
/// enforcement scan over `[window_start, now]`, and the shadow/steer slices are
/// the `analytics:policy_shadow_*` / `analytics:policy_steer_*` scans. Callers
/// must scan enforcement over the same window `window_start_secs(now_secs,
/// days)` produces, or the retention accounting will not line up.
pub fn assemble_activity_report(
    now_secs: u64,
    days: u64,
    policy_records: &[Record],
    enforcement: &EnforcementEventScan,
    shadow_records: &[Record],
    steer_records: &[Record],
    slug: Option<&str>,
) -> ActivityReport {
    let window_start = window_start_secs(now_secs, days);

    let mut policies = BTreeMap::<String, PolicyRecord>::new();
    for record in policy_records {
        if matches!(record.lifecycle, RecordLifecycle::Active) {
            if let Some(policy) = record.payload_as::<PolicyRecord>() {
                if !matches!(policy.stage, PolicyStage::Off) {
                    policies.insert(record.key.clone(), policy);
                }
            }
        }
    }

    let mut counts = BTreeMap::<String, u64>::new();
    let mut last = BTreeMap::<String, u64>::new();
    let mut sources = BTreeMap::<String, BTreeSet<String>>::new();
    for event in &enforcement.events {
        if !matches!(event.subject_kind, SubjectKind::Control)
            || !event.subject_key.starts_with("policy:")
            || !matches!(
                event.event_type,
                EnforcementEventType::Deny | EnforcementEventType::AllowAfterReceipt
            )
        {
            continue;
        }
        let key = event.subject_key.clone();
        *counts.entry(key.clone()).or_default() += 1;
        last.entry(key.clone())
            .and_modify(|value| *value = (*value).max(event.recorded_at_ms / 1000))
            .or_insert(event.recorded_at_ms / 1000);
        sources.entry(key).or_default().insert("enforcement".into());
    }

    for record in shadow_records {
        if record.updated_at < window_start {
            continue;
        }
        let agg = record
            .payload_as::<ShadowObservationAgg>()
            .unwrap_or_default();
        for (key, policy) in agg.policies {
            if policy.count == 0 {
                continue;
            }
            *counts.entry(key.clone()).or_default() += policy.count;
            if let Some(timestamp) = policy.observations.iter().map(|o| o.timestamp).max() {
                last.entry(key.clone())
                    .and_modify(|value| *value = (*value).max(timestamp))
                    .or_insert(timestamp);
            }
            sources.entry(key).or_default().insert("shadow".into());
        }
    }

    for record in steer_records {
        if record.updated_at < window_start {
            continue;
        }
        let Some(agg) = record.payload_as::<DailyAgg>() else {
            continue;
        };
        for (key, count) in agg.key_counts {
            if count == 0 {
                continue;
            }
            *counts.entry(key.clone()).or_default() += count;
            last.entry(key.clone())
                .and_modify(|value| *value = (*value).max(record.updated_at))
                .or_insert(record.updated_at);
            sources.entry(key).or_default().insert("steer".into());
        }
    }

    let retention_limited = enforcement
        .oldest_recorded_at_ms
        .is_some_and(|oldest| window_start.saturating_mul(1000) < oldest);
    let mut report = ActivityReport {
        window_days: days,
        window_start,
        window_end: now_secs,
        retention_days: POLICY_ACTIVITY_RETENTION_DAYS,
        retention_limited,
        retention_note: retention_limited.then(|| format!(
            "requested window predates the oldest retained enforcement event; history is bounded to {} days",
            POLICY_ACTIVITY_RETENTION_DAYS
        )),
        policies: Vec::new(),
    };
    for (key, policy) in policies {
        // The matcher understands file_read, but no adapter routes that action
        // through the policy gate. Unknown tool names have the same absence of
        // a trace. Keep both as not-measurable rather than calling them dead.
        let measurable = match policy.trigger.tool.as_deref() {
            None | Some("db_client") | Some("path") => true,
            Some(_) => false,
        };
        let count = counts.get(&key).copied().unwrap_or(0);
        let state = if !measurable {
            ActivityState::NotMeasurable
        } else if count > 0 {
            ActivityState::Fired
        } else {
            ActivityState::NoActivity
        };
        report.policies.push(PolicyActivity {
            policy: key.clone(),
            state,
            window_days: days,
            window_start,
            count,
            last_fired_at: last.get(&key).copied(),
            sources: sources
                .remove(&key)
                .unwrap_or_default()
                .into_iter()
                .collect(),
        });
    }
    report.policies.sort_by(|a, b| a.policy.cmp(&b.policy));
    if let Some(slug) = slug {
        let key = normalize_policy_key(slug);
        report.policies.retain(|policy| policy.policy == key);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_start_saturates_at_epoch() {
        assert_eq!(window_start_secs(100, 0), 100);
        assert_eq!(window_start_secs(100, 1), 100u64.saturating_sub(86_400));
        assert_eq!(window_start_secs(1_000_000, 1), 1_000_000 - 86_400);
    }

    #[test]
    fn normalize_accepts_bare_and_full_keys() {
        assert_eq!(normalize_policy_key("my-rule"), "policy:my-rule");
        assert_eq!(normalize_policy_key("policy:my-rule"), "policy:my-rule");
    }

    #[test]
    fn empty_inputs_produce_empty_report() {
        let scan = EnforcementEventScan {
            events: Vec::new(),
            oldest_recorded_at_ms: None,
            scanned_keys: 0,
        };
        let report = assemble_activity_report(1_000_000, 30, &[], &scan, &[], &[], None);
        assert!(report.policies.is_empty());
        assert!(!report.retention_limited);
        assert_eq!(report.window_days, 30);
        assert_eq!(report.retention_days, POLICY_ACTIVITY_RETENTION_DAYS);
    }

    #[test]
    fn observations_of_empty_scan_are_empty() {
        assert!(assemble_shadow_observations(&[], None).is_empty());
        assert!(assemble_shadow_observations(&[], Some("anything")).is_empty());
    }
}
