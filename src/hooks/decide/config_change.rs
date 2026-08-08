//! Pure invariant checks for Claude Code `ConfigChange` payloads.
//!
//! The platform has already written the new settings value when this check
//! runs. These functions therefore compare that value with mati's expected
//! registrations; they never attempt to compute a diff or infer an old value.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

/// A single mati-owned configuration invariant that was absent or altered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigViolation {
    /// Stable label for the setting or registration that was checked.
    pub setting: String,
    /// The value mati registered or otherwise expects.
    pub old_value: String,
    /// The value present in the new settings content, or `<removed>`.
    pub new_value: String,
}

impl ConfigViolation {
    fn new(
        setting: impl Into<String>,
        old_value: impl Into<String>,
        new_value: impl Into<String>,
    ) -> Self {
        Self {
            setting: setting.into(),
            old_value: old_value.into(),
            new_value: new_value.into(),
        }
    }
}

/// Check every command hook that mati's scaffold registers in project
/// `settings.json`. User hooks can remain alongside these entries.
pub fn project_violations(actual: &Value, expected: &Value) -> Vec<ConfigViolation> {
    let mut violations = Vec::new();
    let Some(expected_events) = expected.get("hooks").and_then(Value::as_object) else {
        return violations;
    };

    for (event_name, expected_entries) in expected_events {
        let Some(expected_entries) = expected_entries.as_array() else {
            continue;
        };
        let actual_entries = actual
            .get("hooks")
            .and_then(|hooks| hooks.get(event_name))
            .and_then(Value::as_array);

        for expected_entry in expected_entries {
            let expected_hooks = expected_entry
                .get("hooks")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            // Every entry sharing this matcher, not just the first. Users add
            // their own hooks beside mati's under the same matcher, and taking
            // only the first meant mati's entry looked repointed to the user's
            // command — a block that repair could never satisfy.
            let matching_entries: Vec<&Value> = actual_entries
                .map(|entries| {
                    entries
                        .iter()
                        .filter(|entry| entry_matches(expected_entry, entry))
                        .collect()
                })
                .unwrap_or_default();

            for expected_hook in expected_hooks {
                let expected_command = expected_hook
                    .get("command")
                    .and_then(Value::as_str)
                    .unwrap_or("<invalid-scaffold-command>");
                // `hooks.<event>[<command>]`, not a dotted join: mati's commands
                // are dotfile paths, so joining with `.` produced
                // `hooks.PreToolUse..claude/hooks/pre-read.sh` in a hash-chained
                // audit record that mati-cloud reads.
                let setting = format!("hooks.{event_name}[{expected_command}]");
                let expected_type = expected_hook
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("command");

                let hooks_of = |entry: &&Value| {
                    entry
                        .get("hooks")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default()
                };

                let actual_hook = matching_entries.iter().flat_map(hooks_of).find(|hook| {
                    hook.get("type").and_then(Value::as_str) == Some(expected_type)
                        && hook.get("command").and_then(Value::as_str) == Some(expected_command)
                });

                let Some(actual_hook) = actual_hook else {
                    let found = matching_entries
                        .iter()
                        .flat_map(hooks_of)
                        .find_map(|hook| {
                            (hook.get("type").and_then(Value::as_str) == Some(expected_type)).then(
                                || {
                                    hook.get("command")
                                        .and_then(Value::as_str)
                                        .unwrap_or("<invalid-command>")
                                        .to_string()
                                },
                            )
                        })
                        .unwrap_or_else(|| "<removed>".to_string());
                    violations.push(ConfigViolation::new(setting, expected_command, found));
                    continue;
                };

                if let Some(expected_timeout) = expected_hook.get("timeout").and_then(Value::as_u64)
                {
                    let actual_timeout = actual_hook.get("timeout").and_then(Value::as_u64);
                    if actual_timeout.is_none_or(|timeout| timeout < expected_timeout) {
                        violations.push(ConfigViolation::new(
                            format!("{setting}.timeout"),
                            expected_timeout.to_string(),
                            actual_hook
                                .get("timeout")
                                .map(value_label)
                                .unwrap_or_else(|| "<removed>".to_string()),
                        ));
                    }
                }
            }
        }
    }
    violations
}

/// The sandbox floor `mati sandbox compile` currently produces, as the guard
/// expects to find it in `.claude/settings.local.json`.
///
/// Ownership differs per surface. Filesystem denies and credential files carry
/// a path, so containment under `repo_root` decides. A denied domain carries
/// none, so `domain_universe` — every `db_client` host glob the policy corpus
/// has named — stands in for it.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedFloor<'a> {
    pub repo_root: &'a Path,
    pub deny_read: &'a BTreeSet<String>,
    pub deny_write: &'a BTreeSet<String>,
    pub credentials_deny: &'a BTreeSet<String>,
    pub credentials_mask: &'a BTreeSet<String>,
    pub denied_domains: &'a BTreeSet<String>,
    pub domain_universe: &'a BTreeSet<String>,
}

/// Check the dynamic sandbox entries that mati materializes in
/// `.claude/settings.local.json`: filesystem denies, credential files, and
/// denied domains. Entries mati does not own remain the user's and are neither
/// required nor reported.
pub fn local_violations(actual: &Value, expected: &ExpectedFloor<'_>) -> Vec<ConfigViolation> {
    let mut violations = Vec::new();
    check_deny_array(
        actual,
        "denyRead",
        expected.repo_root,
        expected.deny_read,
        &mut violations,
    );
    check_deny_array(
        actual,
        "denyWrite",
        expected.repo_root,
        expected.deny_write,
        &mut violations,
    );
    check_credentials(actual, expected, &mut violations);
    check_denied_domains(actual, expected, &mut violations);
    violations
}

fn check_deny_array(
    actual: &Value,
    key: &str,
    repo_root: &Path,
    expected: &BTreeSet<String>,
    violations: &mut Vec<ConfigViolation>,
) {
    let actual_values = actual
        .pointer(&format!("/sandbox/filesystem/{key}"))
        .and_then(Value::as_array);
    for expected_value in expected {
        if actual_values.is_some_and(|values| contains_str(values, expected_value)) {
            continue;
        }
        // Only another mati-owned entry can be what this one was changed to.
        // Naming a user's out-of-repo deny would write a change the user never
        // made into a hash-chained audit log that mati-cloud reports on.
        let found = actual_values
            .and_then(|values| {
                values.iter().filter_map(Value::as_str).find(|value| {
                    Path::new(value).starts_with(repo_root) && !expected.contains(*value)
                })
            })
            .unwrap_or("<removed>");
        violations.push(ConfigViolation::new(
            format!("sandbox.filesystem.{key}"),
            expected_value,
            found,
        ));
    }
}

fn check_credentials(
    actual: &Value,
    expected: &ExpectedFloor<'_>,
    violations: &mut Vec<ConfigViolation>,
) {
    let files = actual
        .pointer("/sandbox/credentials/files")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for (mode, paths) in [
        ("deny", expected.credentials_deny),
        ("mask", expected.credentials_mask),
    ] {
        for path in paths {
            let same_path =
                |entry: &&Value| entry.get("path").and_then(Value::as_str) == Some(path.as_str());
            let intact = files.iter().any(|entry| {
                same_path(&entry) && entry.get("mode").and_then(Value::as_str) == Some(mode)
            });
            if intact {
                continue;
            }
            // The mode is half the protection, so a downgrade counts: the entry
            // is still there and the path still matches, but `deny` refuses the
            // read outright where `mask` only substitutes a sentinel.
            let found = files
                .iter()
                .find(same_path)
                .map(|entry| {
                    format!(
                        "mode={}",
                        entry
                            .get("mode")
                            .and_then(Value::as_str)
                            .unwrap_or("<invalid>")
                    )
                })
                .unwrap_or_else(|| "<removed>".to_string());
            violations.push(ConfigViolation::new(
                format!("sandbox.credentials.files[{mode}]"),
                path,
                found,
            ));
        }
    }
}

fn check_denied_domains(
    actual: &Value,
    expected: &ExpectedFloor<'_>,
    violations: &mut Vec<ConfigViolation>,
) {
    let actual_domains = actual
        .pointer("/sandbox/network/deniedDomains")
        .and_then(Value::as_array);
    for domain in expected.denied_domains {
        if actual_domains.is_some_and(|values| contains_str(values, domain)) {
            continue;
        }
        let found = actual_domains
            .and_then(|values| {
                values.iter().filter_map(Value::as_str).find(|value| {
                    expected.domain_universe.contains(*value)
                        && !expected.denied_domains.contains(*value)
                })
            })
            .unwrap_or("<removed>");
        violations.push(ConfigViolation::new(
            "sandbox.network.deniedDomains",
            domain,
            found,
        ));
    }
}

fn contains_str(values: &[Value], needle: &str) -> bool {
    values.iter().any(|value| value.as_str() == Some(needle))
}

fn entry_matches(expected: &Value, actual: &Value) -> bool {
    ["matcher", "async"]
        .iter()
        .all(|key| match (expected.get(*key), actual.get(*key)) {
            (None, None) => true,
            (Some(expected), Some(actual)) => expected == actual,
            _ => false,
        })
}

fn value_label(value: &Value) -> String {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A user's own hook sitting beside mati's under the same matcher must not
    /// read as mati's entry being repointed. Taking only the first matching
    /// entry reported `<mati command> changed to /my/own/hook.sh`, and no repair
    /// could ever satisfy it — the guard blocked every settings change forever.
    #[test]
    fn user_hook_beside_mati_under_the_same_matcher_is_not_a_violation() {
        let expected = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": ".claude/hooks/pre-bash.sh", "timeout": 4}]
                }]
            }
        });
        let actual = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": "/my/own/hook.sh"}]
                }, {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": ".claude/hooks/pre-bash.sh", "timeout": 4}]
                }]
            }
        });
        assert_eq!(
            project_violations(&actual, &expected),
            Vec::new(),
            "mati's entry is present in a later group; a user hook alongside is not tamper"
        );
    }

    /// The audit `setting` field is read downstream, so it must not carry the
    /// double dot that joining an event name to a dotfile command produced.
    #[test]
    fn violation_setting_label_has_no_double_dot() {
        let expected = json!({
            "hooks": {"PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": ".claude/hooks/pre-bash.sh"}]
            }]}
        });
        let violations = project_violations(&json!({"hooks": {}}), &expected);
        assert_eq!(violations.len(), 1);
        assert!(
            !violations[0].setting.contains(".."),
            "setting label must not contain `..`, got {}",
            violations[0].setting
        );
    }

    fn project_expected() -> Value {
        json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Read|Glob|Grep",
                    "hooks": [{"type": "command", "command": ".claude/hooks/pre-read.sh", "timeout": 4}]
                }, {
                    "matcher": "Edit|Write|NotebookEdit",
                    "hooks": [{"type": "command", "command": ".claude/hooks/pre-edit.sh", "timeout": 4}]
                }],
                "ConfigChange": [{
                    "matcher": "user_settings|project_settings|local_settings|policy_settings|skills",
                    "hooks": [{"type": "command", "command": ".claude/hooks/config-change.sh", "timeout": 4}]
                }]
            }
        })
    }

    fn valid_project() -> Value {
        json!({
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Read|Glob|Grep", "hooks": [{"type": "command", "command": ".claude/hooks/pre-read.sh", "timeout": 4}, {"type": "command", "command": "./custom.sh"}]},
                    {"matcher": "Edit|Write|NotebookEdit", "hooks": [{"type": "command", "command": ".claude/hooks/pre-edit.sh", "timeout": 5}]}
                ],
                "ConfigChange": [{"matcher": "user_settings|project_settings|local_settings|policy_settings|skills", "hooks": [{"type": "command", "command": ".claude/hooks/config-change.sh", "timeout": 5}] }]
            }
        })
    }

    #[test]
    fn intact_entries_allow_and_preserve_user_hooks() {
        assert!(project_violations(&valid_project(), &project_expected()).is_empty());
    }

    #[test]
    fn removed_hooks_key_denies() {
        let actual = json!({});
        assert!(!project_violations(&actual, &project_expected()).is_empty());
    }

    #[test]
    fn empty_hooks_denies() {
        let actual = json!({"hooks": {}});
        assert!(!project_violations(&actual, &project_expected()).is_empty());
    }

    #[test]
    fn removed_event_array_denies_but_unrelated_event_is_irrelevant() {
        let actual = json!({"hooks": {"PreToolUse": valid_project()["hooks"]["PreToolUse"]}});
        assert!(!project_violations(&actual, &project_expected()).is_empty());

        let actual = json!({"hooks": {"ConfigChange": valid_project()["hooks"]["ConfigChange"]}});
        assert!(!project_violations(&actual, &project_expected()).is_empty());
    }

    #[test]
    fn repointed_command_denies_and_reports_new_command() {
        let mut actual = valid_project();
        actual["hooks"]["ConfigChange"][0]["hooks"][0]["command"] = json!("/bin/true");
        let violations = project_violations(&actual, &project_expected());
        assert!(
            violations
                .iter()
                .any(|v| v.old_value == ".claude/hooks/config-change.sh"
                    && v.new_value == "/bin/true")
        );
    }

    #[test]
    fn lower_timeout_denies_but_raise_allows() {
        let mut actual = valid_project();
        actual["hooks"]["ConfigChange"][0]["hooks"][0]["timeout"] = json!(0);
        assert!(!project_violations(&actual, &project_expected()).is_empty());

        actual["hooks"]["ConfigChange"][0]["hooks"][0]["timeout"] = json!(1);
        assert!(!project_violations(&actual, &project_expected()).is_empty());

        actual["hooks"]["ConfigChange"][0]["hooks"][0]["timeout"] = json!(5);
        assert!(project_violations(&actual, &project_expected()).is_empty());
    }

    #[test]
    fn removed_entry_among_other_hooks_denies() {
        let mut actual = valid_project();
        actual["hooks"]["PreToolUse"][0]["hooks"] =
            json!([{"type": "command", "command": "./custom.sh"}]);
        assert!(!project_violations(&actual, &project_expected()).is_empty());
    }

    #[test]
    fn removing_the_guard_entry_itself_denies() {
        let mut actual = valid_project();
        actual["hooks"]["ConfigChange"] = json!([]);
        assert!(!project_violations(&actual, &project_expected()).is_empty());
        assert!(project_violations(&valid_project(), &project_expected()).is_empty());
    }

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|v| (*v).to_string()).collect()
    }

    /// Builds an `ExpectedFloor` over borrowed sets. Every field defaults to
    /// empty, so a test names only the surface it is about.
    #[derive(Default)]
    struct Floor {
        deny_read: BTreeSet<String>,
        deny_write: BTreeSet<String>,
        credentials_deny: BTreeSet<String>,
        credentials_mask: BTreeSet<String>,
        denied_domains: BTreeSet<String>,
        domain_universe: BTreeSet<String>,
    }

    impl Floor {
        fn expected(&self) -> ExpectedFloor<'_> {
            ExpectedFloor {
                repo_root: Path::new("/repo"),
                deny_read: &self.deny_read,
                deny_write: &self.deny_write,
                credentials_deny: &self.credentials_deny,
                credentials_mask: &self.credentials_mask,
                denied_domains: &self.denied_domains,
                domain_universe: &self.domain_universe,
            }
        }
    }

    #[test]
    fn local_entries_allow_user_entries_and_deny_missing_or_repointed_entries() {
        let floor = Floor {
            deny_read: set(&["/repo/secret.txt"]),
            deny_write: set(&["/repo/src/lib.rs"]),
            ..Floor::default()
        };
        let valid = json!({"sandbox": {"filesystem": {
            "denyRead": ["/user/entry", "/repo/secret.txt"],
            "denyWrite": ["/repo/src/lib.rs", "/user/other"]
        }}});
        assert!(local_violations(&valid, &floor.expected()).is_empty());

        let removed = json!({"sandbox": {"filesystem": {
            "denyRead": [], "denyWrite": ["/repo/src/lib.rs"]
        }}});
        assert!(!local_violations(&removed, &floor.expected()).is_empty());

        let repointed = json!({"sandbox": {"filesystem": {
            "denyRead": ["/repo/other.txt"], "denyWrite": ["/repo/src/lib.rs"]
        }}});
        let violations = local_violations(&repointed, &floor.expected());
        assert!(violations.iter().any(|v| v.new_value == "/repo/other.txt"));
    }

    /// A user's out-of-repo deny is not what mati's entry "changed to". Naming
    /// it would put a change the user never made into the audit chain.
    #[test]
    fn removed_deny_beside_a_user_entry_reports_removed_not_the_user_entry() {
        let floor = Floor {
            deny_read: set(&["/repo/secret.txt"]),
            ..Floor::default()
        };
        let actual = json!({"sandbox": {"filesystem": {"denyRead": ["~/.ssh", "/elsewhere/x"]}}});
        let violations = local_violations(&actual, &floor.expected());
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].new_value, "<removed>");
    }

    #[test]
    fn empty_expected_local_floor_allows_empty_or_missing_sandbox() {
        let floor = Floor::default();
        assert!(local_violations(&json!({}), &floor.expected()).is_empty());
        assert!(
            local_violations(&json!({"sandbox": {"filesystem": {}}}), &floor.expected()).is_empty()
        );
    }

    fn credentials(entries: Value) -> Value {
        json!({"sandbox": {"credentials": {"files": entries}}})
    }

    #[test]
    fn intact_credentials_entries_allow_and_preserve_user_entries() {
        let floor = Floor {
            credentials_deny: set(&["/repo/vault/prod.pem"]),
            credentials_mask: set(&["/repo/.env"]),
            ..Floor::default()
        };
        let actual = credentials(json!([
            {"mode": "mask", "path": "~/.aws/credentials"},
            {"mode": "deny", "path": "/repo/vault/prod.pem"},
            {"mode": "mask", "path": "/repo/.env"}
        ]));
        assert!(local_violations(&actual, &floor.expected()).is_empty());
    }

    #[test]
    fn removed_credentials_entry_denies() {
        let floor = Floor {
            credentials_deny: set(&["/repo/vault/prod.pem"]),
            ..Floor::default()
        };
        let actual = credentials(json!([{"mode": "mask", "path": "~/.aws/credentials"}]));
        let violations = local_violations(&actual, &floor.expected());
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].setting, "sandbox.credentials.files[deny]");
        assert_eq!(violations[0].old_value, "/repo/vault/prod.pem");
        assert_eq!(violations[0].new_value, "<removed>");

        // Whole array gone, whole block gone, whole file empty — all removal.
        assert!(
            !local_violations(&json!({"sandbox": {"credentials": {}}}), &floor.expected())
                .is_empty()
        );
        assert!(!local_violations(&json!({}), &floor.expected()).is_empty());
    }

    /// Downgrading `deny` to `mask` leaves an entry at the same path, so a
    /// path-only check reads it as intact. It is not: `deny` refuses the read.
    #[test]
    fn downgraded_credentials_mode_denies_and_reports_the_new_mode() {
        let floor = Floor {
            credentials_deny: set(&["/repo/vault/prod.pem"]),
            ..Floor::default()
        };
        let actual = credentials(json!([{"mode": "mask", "path": "/repo/vault/prod.pem"}]));
        let violations = local_violations(&actual, &floor.expected());
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].new_value, "mode=mask");
    }

    #[test]
    fn repointed_credentials_path_denies() {
        let floor = Floor {
            credentials_mask: set(&["/repo/.env"]),
            ..Floor::default()
        };
        let actual = credentials(json!([{"mode": "mask", "path": "/repo/.env.decoy"}]));
        let violations = local_violations(&actual, &floor.expected());
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].setting, "sandbox.credentials.files[mask]");
        assert_eq!(violations[0].new_value, "<removed>");
    }

    fn domains(entries: Value) -> Value {
        json!({"sandbox": {"network": {"deniedDomains": entries}}})
    }

    #[test]
    fn intact_denied_domain_allows_beside_a_user_domain() {
        let floor = Floor {
            denied_domains: set(&["*.prod.internal"]),
            domain_universe: set(&["*.prod.internal", "*.staging.internal"]),
            ..Floor::default()
        };
        let actual = domains(json!(["user-added.example.com", "*.prod.internal"]));
        assert!(local_violations(&actual, &floor.expected()).is_empty());
    }

    #[test]
    fn removed_denied_domain_denies() {
        let floor = Floor {
            denied_domains: set(&["*.prod.internal"]),
            domain_universe: set(&["*.prod.internal"]),
            ..Floor::default()
        };
        let violations = local_violations(&domains(json!([])), &floor.expected());
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].setting, "sandbox.network.deniedDomains");
        assert_eq!(violations[0].old_value, "*.prod.internal");
        assert_eq!(violations[0].new_value, "<removed>");
        assert!(!local_violations(&json!({}), &floor.expected()).is_empty());
    }

    /// A domain has no path, so ownership comes from the policy corpus. A user
    /// domain left in the array is not the value mati's entry was changed to.
    #[test]
    fn removed_domain_beside_a_user_domain_reports_removed() {
        let floor = Floor {
            denied_domains: set(&["*.prod.internal"]),
            domain_universe: set(&["*.prod.internal", "*.staging.internal"]),
            ..Floor::default()
        };
        let actual = domains(json!(["user-added.example.com"]));
        let violations = local_violations(&actual, &floor.expected());
        assert_eq!(violations[0].new_value, "<removed>");

        // A glob the policy corpus authored IS a repoint, and is named as one.
        let actual = domains(json!(["user-added.example.com", "*.staging.internal"]));
        let violations = local_violations(&actual, &floor.expected());
        assert_eq!(violations[0].new_value, "*.staging.internal");
    }

    /// Every surface at once: stripping the whole sandbox block must produce a
    /// violation for each entry mati compiled, not just the filesystem ones.
    #[test]
    fn stripping_the_whole_sandbox_block_denies_on_every_surface() {
        let floor = Floor {
            deny_read: set(&["/repo/secret.txt"]),
            deny_write: set(&["/repo/src/lib.rs"]),
            credentials_deny: set(&["/repo/vault/prod.pem"]),
            credentials_mask: set(&["/repo/.env"]),
            denied_domains: set(&["*.prod.internal"]),
            domain_universe: set(&["*.prod.internal"]),
        };
        let violations = local_violations(&json!({"other": true}), &floor.expected());
        assert_eq!(violations.len(), 5);
        let settings: Vec<&str> = violations.iter().map(|v| v.setting.as_str()).collect();
        assert!(settings.contains(&"sandbox.filesystem.denyRead"));
        assert!(settings.contains(&"sandbox.filesystem.denyWrite"));
        assert!(settings.contains(&"sandbox.credentials.files[deny]"));
        assert!(settings.contains(&"sandbox.credentials.files[mask]"));
        assert!(settings.contains(&"sandbox.network.deniedDomains"));
        assert!(violations.iter().all(|v| v.new_value == "<removed>"));
    }

    /// mati owning nothing on a surface means the user's entries there are
    /// theirs. Extra entries are not tamper and must not block.
    #[test]
    fn user_only_credentials_and_domains_are_never_judged() {
        let floor = Floor::default();
        let actual = json!({"sandbox": {
            "credentials": {"files": [{"mode": "deny", "path": "~/.aws/credentials"}]},
            "network": {"deniedDomains": ["user-added.example.com"]}
        }});
        assert!(local_violations(&actual, &floor.expected()).is_empty());
    }

    #[test]
    fn successive_values_are_checked_statelessly() {
        let expected = project_expected();
        assert!(project_violations(&valid_project(), &expected).is_empty());
        assert!(!project_violations(&json!({}), &expected).is_empty());
        assert!(project_violations(&valid_project(), &expected).is_empty());
    }
}
