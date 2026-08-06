//! Pure invariant checks for Claude Code `ConfigChange` payloads.
//!
//! The platform has already written the new settings value when this check
//! runs. These functions therefore compare that value with mati's expected
//! registrations; they never attempt to compute a diff or infer an old value.

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

/// Check the dynamic sandbox entries that mati materializes in
/// `.claude/settings.local.json`. Entries outside the repository remain user
/// owned and are not judged here.
pub fn local_violations(
    actual: &Value,
    expected_deny_read: &[String],
    expected_deny_write: &[String],
) -> Vec<ConfigViolation> {
    let mut violations = Vec::new();
    check_local_array(actual, "denyRead", expected_deny_read, &mut violations);
    check_local_array(actual, "denyWrite", expected_deny_write, &mut violations);
    violations
}

fn check_local_array(
    actual: &Value,
    key: &str,
    expected: &[String],
    violations: &mut Vec<ConfigViolation>,
) {
    let actual_values = actual
        .pointer(&format!("/sandbox/filesystem/{key}"))
        .and_then(Value::as_array);
    for expected_value in expected {
        let present = actual_values
            .map(|values| {
                values
                    .iter()
                    .any(|value| value.as_str() == Some(expected_value))
            })
            .unwrap_or(false);
        if !present {
            let found = actual_values
                .and_then(|values| values.iter().find_map(Value::as_str))
                .unwrap_or("<removed>");
            violations.push(ConfigViolation::new(
                format!("sandbox.filesystem.{key}"),
                expected_value,
                found,
            ));
        }
    }
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

    #[test]
    fn local_entries_allow_user_entries_and_deny_missing_or_repointed_entries() {
        let expected_read = vec!["/repo/secret.txt".to_string()];
        let expected_write = vec!["/repo/src/lib.rs".to_string()];
        let valid = json!({"sandbox": {"filesystem": {
            "denyRead": ["/user/entry", "/repo/secret.txt"],
            "denyWrite": ["/repo/src/lib.rs", "/user/other"]
        }}});
        assert!(local_violations(&valid, &expected_read, &expected_write).is_empty());

        let removed = json!({"sandbox": {"filesystem": {
            "denyRead": [], "denyWrite": ["/repo/src/lib.rs"]
        }}});
        assert!(!local_violations(&removed, &expected_read, &expected_write).is_empty());

        let repointed = json!({"sandbox": {"filesystem": {
            "denyRead": ["/repo/other.txt"], "denyWrite": ["/repo/src/lib.rs"]
        }}});
        let violations = local_violations(&repointed, &expected_read, &expected_write);
        assert!(violations.iter().any(|v| v.new_value == "/repo/other.txt"));
    }

    #[test]
    fn empty_expected_local_floor_allows_empty_or_missing_sandbox() {
        assert!(local_violations(&json!({}), &[], &[]).is_empty());
        assert!(local_violations(&json!({"sandbox": {"filesystem": {}}}), &[], &[]).is_empty());
    }

    #[test]
    fn successive_values_are_checked_statelessly() {
        let expected = project_expected();
        assert!(project_violations(&valid_project(), &expected).is_empty());
        assert!(!project_violations(&json!({}), &expected).is_empty());
        assert!(project_violations(&valid_project(), &expected).is_empty());
    }
}
