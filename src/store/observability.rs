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
use crate::store::session::{
    DailyAgg, PolicyShadowAgg, ShadowObservationAgg, MAX_SHADOW_OBSERVATIONS,
};

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
/// the `analytics:policy_shadow_*` / `analytics:policy_steer_*` scans.
///
/// The shadow and steer records are window-filtered here (`updated_at <
/// window_start`), but the enforcement events are counted VERBATIM — windowing
/// them is the caller's job, done by scanning only `[window_start_secs(now_secs,
/// days), now]`. Hand this a wider enforcement scan and `count`, `state`, and
/// `last_fired_at` inflate past the window, not just the retention note.
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
    use crate::store::enforcement::EnforcementEvent;
    use crate::store::record::{
        PolicyFreshness, PolicyMode, PolicyRequires, PolicyTrigger, Priority, TombstoneReason,
    };

    /// Build an `analytics:*`-style record with a payload and `updated_at`,
    /// reusing the production analytics-record constructor for field fidelity.
    fn agg_record(key: &str, updated_at: u64, payload: serde_json::Value) -> Record {
        let mut r = crate::store::session::analytics_record(key, String::new());
        r.updated_at = updated_at;
        r.payload = Some(payload);
        r
    }

    fn policy_record(key: &str, tool: Option<&str>, stage: PolicyStage) -> Record {
        let policy = PolicyRecord {
            deny_if: None,
            require: None,
            mints: None,
            name: "n".into(),
            rule: "r".into(),
            reason: "why".into(),
            scope: "s".into(),
            mode: PolicyMode::Block,
            trigger: PolicyTrigger {
                tool: tool.map(String::from),
                ..Default::default()
            },
            requires: PolicyRequires {
                key: "gotcha:x".into(),
                via: vec![],
                freshness: PolicyFreshness {
                    ttl_secs: 900,
                    fingerprint: false,
                },
            },
            stage,
            severity: Priority::High,
            created_by: "test".into(),
        };
        agg_record(key, 0, serde_json::to_value(policy).unwrap())
    }

    fn deny_event(subject_key: &str, recorded_at_ms: u64, seq_no: u64) -> EnforcementEvent {
        EnforcementEvent {
            event_id: format!("evt-{seq_no}"),
            schema_version: 1,
            seq_no,
            recorded_at_ms,
            event_type: EnforcementEventType::Deny,
            event_hash: String::new(),
            prev_hash: String::new(),
            installation_id: "test".into(),
            actor_local: None,
            agent_type: "codex".into(),
            subject_kind: SubjectKind::Control,
            subject_key: subject_key.into(),
            canonical_subject_hash: None,
            receipt_id: None,
            decision_reason_code: "policy_deny".into(),
            decision_basis_hash: None,
            agent_session: None,
            agent_id: None,
            parent_agent_id: None,
        }
    }

    fn scan_of(events: Vec<EnforcementEvent>, oldest: Option<u64>) -> EnforcementEventScan {
        EnforcementEventScan {
            events,
            oldest_recorded_at_ms: oldest,
            scanned_keys: 0,
        }
    }

    fn shadow_record(key: &str, updated_at: u64, policy_key: &str, count: u64) -> Record {
        let mut policies = BTreeMap::new();
        policies.insert(
            policy_key.to_string(),
            PolicyShadowAgg {
                count,
                observations: vec![],
            },
        );
        agg_record(
            key,
            updated_at,
            serde_json::to_value(ShadowObservationAgg { policies }).unwrap(),
        )
    }

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

    #[test]
    fn enforcement_counted_regardless_of_window_but_shadow_is_gated() {
        let now = 1_000_000_000u64;
        let days = 1; // window_start = now - 86_400
        let policy = policy_record("policy:p", Some("db_client"), PolicyStage::Enforce);
        // Enforcement event recorded long before the window: assemble counts it
        // verbatim — windowing is the caller's scan responsibility.
        let old_ms = (now - 10 * 86_400) * 1000;
        let scan = scan_of(vec![deny_event("policy:p", old_ms, 1)], Some(old_ms));
        // Shadow record predating the window: assemble MUST drop it.
        let stale = shadow_record(
            "analytics:policy_shadow_old",
            now - 10 * 86_400,
            "policy:p",
            5,
        );
        let report = assemble_activity_report(now, days, &[policy], &scan, &[stale], &[], None);
        let p = &report.policies[0];
        assert_eq!(
            p.count, 1,
            "enforcement counted despite predating the window"
        );
        assert!(matches!(p.state, ActivityState::Fired));
        assert_eq!(
            p.sources,
            vec!["enforcement".to_string()],
            "the stale shadow record must not add a 'shadow' source"
        );
    }

    #[test]
    fn measurable_state_is_a_pure_function_of_trigger_tool() {
        let now = 2_000_000_000u64;
        let scan = scan_of(
            vec![deny_event("policy:bash", now * 1000, 1)],
            Some(now * 1000),
        );
        let policies = vec![
            policy_record("policy:bash", Some("bash"), PolicyStage::Enforce),
            policy_record("policy:db", Some("db_client"), PolicyStage::Enforce),
            policy_record("policy:none", None, PolicyStage::Enforce),
        ];
        let report = assemble_activity_report(now, 30, &policies, &scan, &[], &[], None);
        let state = |k: &str| {
            report
                .policies
                .iter()
                .find(|p| p.policy == k)
                .unwrap()
                .state
                .clone()
        };
        // Even with a matching Deny, an unmeasurable tool is NotMeasurable —
        // never Fired. This is the one derived field, and it stays mechanical.
        assert!(matches!(state("policy:bash"), ActivityState::NotMeasurable));
        assert!(matches!(state("policy:db"), ActivityState::NoActivity));
        assert!(matches!(state("policy:none"), ActivityState::NoActivity));
    }

    #[test]
    fn stale_shadow_shows_in_observations_but_not_in_activity() {
        let now = 3_000_000_000u64;
        let stale = shadow_record(
            "analytics:policy_shadow_old",
            now - 60 * 86_400,
            "policy:p",
            3,
        );
        // observations: no window filter — the count survives.
        let obs = assemble_shadow_observations(std::slice::from_ref(&stale), None);
        assert_eq!(obs["policy:p"].count, 3);
        // activity (30d): the record predates the window — contributes nothing.
        let report = assemble_activity_report(
            now,
            30,
            &[policy_record(
                "policy:p",
                Some("path"),
                PolicyStage::Enforce,
            )],
            &scan_of(vec![], None),
            &[stale],
            &[],
            None,
        );
        assert_eq!(report.policies[0].count, 0);
        assert!(report.policies[0].sources.is_empty());
    }

    #[test]
    fn off_and_tombstoned_policies_excluded_and_retention_flagged() {
        let now = 4_000_000_000u64;
        let off = policy_record("policy:off", None, PolicyStage::Off);
        let mut dead = policy_record("policy:dead", None, PolicyStage::Enforce);
        dead.lifecycle = RecordLifecycle::Tombstoned {
            reason: TombstoneReason::ManualDeletion,
            at: now,
        };
        let live = policy_record("policy:live", None, PolicyStage::Enforce);
        // A 400-day window starts before the oldest retained event (10 days
        // old) → the requested history predates retention → retention_limited.
        let old_ms = (now - 10 * 86_400) * 1000;
        let scan = scan_of(vec![deny_event("policy:live", old_ms, 1)], Some(old_ms));
        let report = assemble_activity_report(now, 400, &[off, dead, live], &scan, &[], &[], None);
        assert_eq!(report.policies.len(), 1);
        assert_eq!(report.policies[0].policy, "policy:live");
        assert!(report.retention_limited);
        assert!(report.retention_note.is_some());
    }
}
