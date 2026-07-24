//! Pure local-policy predicate compilation and matching.
//!
//! This module owns no store or daemon state. Milestone 3 can place the same
//! compiled [`PolicyMatcherSet`] behind the daemon's live policy set without
//! changing the matching semantics.

use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};

use super::decide::{is_known_action_tool, Action};
use crate::store::{PolicyRecord, PolicyStage, Record, RecordLifecycle};

struct CompiledPolicy {
    key: String,
    policy: PolicyRecord,
    host_glob: Option<GlobMatcher>,
    target_path_glob: Option<GlobMatcher>,
}

/// A set of staged, active policies with their glob predicates compiled.
pub struct PolicyMatcherSet {
    policies: Vec<CompiledPolicy>,
}

/// A policy that matched an [`Action`].
pub struct MatchedPolicy<'a> {
    pub key: &'a str,
    pub policy: &'a PolicyRecord,
}

impl PolicyMatcherSet {
    /// Create an empty matcher set.
    pub fn empty() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Compile active, non-off policy records from universal store records.
    pub fn from_records(records: &[Record]) -> Result<Self> {
        let policies = records.iter().filter_map(|record| {
            if record.category != crate::store::Category::Policy
                || !matches!(record.lifecycle, RecordLifecycle::Active)
            {
                return None;
            }
            let policy = record.payload_as::<PolicyRecord>()?;
            (!matches!(policy.stage, PolicyStage::Off)).then(|| (record.key.clone(), policy))
        });
        Self::from_policies(policies)
    }

    /// Compile active, non-off policy records while isolating bad records.
    ///
    /// A malformed policy must not prevent the daemon from evaluating every
    /// other policy at boot or after a live refresh.
    pub fn from_records_lenient(records: &[Record]) -> Self {
        let mut matcher = Self::empty();
        for record in records {
            if record.category != crate::store::Category::Policy
                || !matches!(record.lifecycle, RecordLifecycle::Active)
            {
                continue;
            }
            let Some(policy) = record.payload_as::<PolicyRecord>() else {
                tracing::warn!(key = %record.key, "skipping policy with invalid payload");
                continue;
            };
            if matches!(policy.stage, PolicyStage::Off) {
                continue;
            }
            match Self::from_policies([(record.key.clone(), policy)]) {
                Ok(mut compiled) => matcher.policies.append(&mut compiled.policies),
                Err(error) => tracing::warn!(
                    key = %record.key,
                    error = %error,
                    "skipping policy that failed matcher compilation"
                ),
            }
        }
        matcher
    }

    /// Compile keyed policy payloads. This is useful to pure callers that have
    /// already separated the universal record envelope.
    pub fn from_policies<I>(policies: I) -> Result<Self>
    where
        I: IntoIterator<Item = (String, PolicyRecord)>,
    {
        let mut compiled = Vec::new();
        for (key, policy) in policies {
            let host_glob = policy
                .trigger
                .host_glob
                .as_deref()
                .map(|pattern| {
                    Glob::new(pattern)
                        .with_context(|| format!("invalid host_glob for policy {key}"))
                        .map(|glob| glob.compile_matcher())
                })
                .transpose()?;
            let target_path_glob = policy
                .trigger
                .target_path_glob
                .as_deref()
                .map(|pattern| {
                    Glob::new(pattern)
                        .with_context(|| format!("invalid target_path_glob for policy {key}"))
                        .map(|glob| glob.compile_matcher())
                })
                .transpose()?;
            compiled.push(CompiledPolicy {
                key,
                policy,
                host_glob,
                target_path_glob,
            });
        }
        Ok(Self { policies: compiled })
    }

    /// Return every policy whose present predicates all match the action.
    pub fn matches(&self, action: &Action) -> Vec<MatchedPolicy<'_>> {
        self.policies
            .iter()
            .filter(|compiled| {
                let trigger = &compiled.policy.trigger;
                let tool_matches = trigger
                    .tool
                    .as_deref()
                    .is_none_or(|tool| is_known_action_tool(tool) && tool == action.tool);
                let host_matches = compiled.host_glob.as_ref().is_none_or(|glob| {
                    action
                        .host
                        .as_deref()
                        .is_some_and(|host| glob.is_match(host))
                });
                let path_matches = compiled.target_path_glob.as_ref().is_none_or(|glob| {
                    action
                        .target_path
                        .iter()
                        .chain(action.files.iter())
                        .any(|path| glob.is_match(path))
                });
                tool_matches && host_matches && path_matches
            })
            .map(|compiled| MatchedPolicy {
                key: &compiled.key,
                policy: &compiled.policy,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::decide::Action;
    use crate::store::{
        PolicyFreshness, PolicyMode, PolicyRequires, PolicyTrigger, Priority, ReceiptSource,
    };

    fn policy(name: &str, trigger: PolicyTrigger) -> PolicyRecord {
        PolicyRecord {
            name: name.into(),
            rule: "Consult the required knowledge first.".into(),
            reason: "The action needs current context because production state changes.".into(),
            scope: "repo".into(),
            mode: PolicyMode::Block,
            trigger,
            requires: PolicyRequires {
                key: "schema:orders".into(),
                via: vec![ReceiptSource::MemGet],
                freshness: PolicyFreshness {
                    ttl_secs: 900,
                    fingerprint: false,
                },
            },
            stage: PolicyStage::Enforce,
            severity: Priority::High,
            created_by: "test".into(),
        }
    }

    fn action(host: Option<&str>, files: &[&str]) -> Action {
        Action {
            tool: "db_client".into(),
            target_path: files.first().map(|path| (*path).into()),
            host: host.map(str::to_string),
            argv: vec!["psql".into()],
            files: files.iter().map(|path| (*path).into()).collect(),
        }
    }

    #[test]
    fn tool_only_policy_matches() {
        let set = PolicyMatcherSet::from_policies([(
            "policy:db".into(),
            policy(
                "DB",
                PolicyTrigger {
                    tool: Some("db_client".into()),
                    ..Default::default()
                },
            ),
        )])
        .unwrap();
        assert_eq!(set.matches(&action(None, &[]))[0].key, "policy:db");
        assert!(set
            .matches(&Action {
                tool: "file_read".into(),
                ..action(None, &[])
            })
            .is_empty());
    }

    #[test]
    fn host_glob_matches_and_rejects_nonmatching_hosts() {
        let set = PolicyMatcherSet::from_policies([(
            "policy:prod".into(),
            policy(
                "Production",
                PolicyTrigger {
                    host_glob: Some("*prod*".into()),
                    ..Default::default()
                },
            ),
        )])
        .unwrap();
        assert_eq!(set.matches(&action(Some("db.prod.internal"), &[])).len(), 1);
        assert!(set
            .matches(&action(Some("db.dev.internal"), &[]))
            .is_empty());
    }

    #[test]
    fn target_path_glob_and_predicates_use_and_semantics() {
        let set = PolicyMatcherSet::from_policies([(
            "policy:sql-prod".into(),
            policy(
                "SQL production",
                PolicyTrigger {
                    tool: Some("db_client".into()),
                    host_glob: Some("*prod*".into()),
                    target_path_glob: Some("**/*.sql".into()),
                },
            ),
        )])
        .unwrap();
        assert_eq!(
            set.matches(&action(Some("prod"), &["migrations/x.sql"]))
                .len(),
            1
        );
        assert!(set
            .matches(&action(Some("dev"), &["migrations/x.sql"]))
            .is_empty());
        assert!(set
            .matches(&action(Some("prod"), &["migrations/x.rs"]))
            .is_empty());
    }

    #[test]
    fn disabled_and_tombstoned_records_are_excluded() {
        let mut disabled = policy("Disabled", PolicyTrigger::default());
        disabled.stage = PolicyStage::Off;
        let mut disabled_record =
            crate::store::policy_ops::record_for("policy:disabled", &disabled).unwrap();
        let tombstone = crate::store::policy_ops::record_for(
            "policy:tombstone",
            &policy("Tombstone", PolicyTrigger::default()),
        )
        .unwrap();
        let mut tombstone = tombstone;
        tombstone.lifecycle = RecordLifecycle::Tombstoned {
            reason: crate::store::TombstoneReason::ManualDeletion,
            at: 1,
        };
        disabled_record.lifecycle = RecordLifecycle::Active;
        let set = PolicyMatcherSet::from_records(&[disabled_record, tombstone]).unwrap();
        assert!(set.matches(&action(None, &[])).is_empty());
    }

    #[test]
    fn unknown_tool_values_never_match() {
        let set = PolicyMatcherSet::from_policies([(
            "policy:unknown".into(),
            policy(
                "Unknown",
                PolicyTrigger {
                    tool: Some("future_tool".into()),
                    ..Default::default()
                },
            ),
        )])
        .unwrap();
        assert!(set.matches(&action(None, &[])).is_empty());
    }

    #[test]
    fn lenient_loader_skips_bad_glob_and_keeps_good_policy() {
        let good = crate::store::policy_ops::record_for(
            "policy:good",
            &policy("Good", PolicyTrigger::default()),
        )
        .unwrap();
        let mut bad_policy = policy(
            "Bad",
            PolicyTrigger {
                host_glob: Some("[".into()),
                ..Default::default()
            },
        );
        bad_policy.stage = PolicyStage::Enforce;
        let bad = crate::store::policy_ops::record_for("policy:bad", &bad_policy).unwrap();

        let matcher = PolicyMatcherSet::from_records_lenient(&[bad, good]);

        assert_eq!(matcher.matches(&action(None, &[])).len(), 1);
        assert_eq!(matcher.matches(&action(None, &[]))[0].key, "policy:good");
    }
}
