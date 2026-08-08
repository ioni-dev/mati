use super::*;

use std::io::ErrorKind;
use std::path::Component;

use mati_core::hooks::decide::{self, ConfigViolation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigFileKind {
    Project,
    Local,
}

/// Run the Claude Code `ConfigChange` adapter.
///
/// The hook is stateless: every invocation reads the new file and checks the
/// invariant from scratch. It never compares successive hook invocations.
pub(crate) async fn run_config_change(input: &serde_json::Value) -> Result<()> {
    let source = input.get("source").and_then(|value| value.as_str());
    let file_path = input
        .get("file_path")
        .and_then(|value| value.as_str())
        .unwrap_or("<missing-file-path>");
    let cwd = input
        .get("cwd")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or(std::env::current_dir()?);

    match source {
        // These settings scopes do not carry mati's project registrations.
        Some("user_settings") | Some("skills") => {
            emit_config_decision(ConfigDecision::Allow);
            return Ok(());
        }
        // Claude Code documents this scope as non-blockable. Record it, but
        // always emit allow so the audit does not claim a block that did not occur.
        Some("policy_settings") => {
            record_config_change(
                &cwd,
                file_path,
                "<unavailable>",
                "<policy_settings>",
                "policy_settings changes are platform-non-blockable",
            )
            .await;
            emit_config_decision(ConfigDecision::Allow);
            return Ok(());
        }
        Some("project_settings") | Some("local_settings") => {}
        Some(other) => {
            log_fail_open_named(
                "config-change",
                file_path,
                &format!("unrecognized ConfigChange source: {other}"),
            );
            emit_config_decision(ConfigDecision::Allow);
            return Ok(());
        }
        None => {
            log_fail_open_named(
                "config-change",
                file_path,
                "ConfigChange payload has no source",
            );
            emit_config_decision(ConfigDecision::Allow);
            return Ok(());
        }
    }

    let repo_root = match super::sandbox::repo_root_for(&cwd) {
        Ok(root) => root,
        Err(error) => {
            log_fail_open_named(
                "config-change",
                file_path,
                &format!("cannot determine repository root: {error}"),
            );
            emit_config_decision(ConfigDecision::Allow);
            return Ok(());
        }
    };
    let Some((kind, expected_path)) = owned_config_path(file_path, &cwd, &repo_root) else {
        // A source name alone is not ownership. Only the exact settings file
        // that mati writes is judged against mati's entries.
        emit_config_decision(ConfigDecision::Allow);
        return Ok(());
    };

    let content = match std::fs::read_to_string(&expected_path) {
        Ok(content) => content,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let violation = ConfigViolation {
                setting: expected_path.display().to_string(),
                old_value: "<mati-settings-file>".to_string(),
                new_value: "<removed>".to_string(),
            };
            block_config_change(&cwd, vec![violation]).await;
            return Ok(());
        }
        Err(error) => {
            log_fail_open_named(
                "config-change",
                file_path,
                &format!("settings file unreadable: {error}"),
            );
            emit_config_decision(ConfigDecision::Allow);
            return Ok(());
        }
    };

    let settings: serde_json::Value = match serde_json::from_str(&content) {
        Ok(settings) => settings,
        Err(error) => {
            // P9: a malformed settings file must not brick a session.
            log_fail_open_named(
                "config-change",
                file_path,
                &format!("settings file is malformed JSON: {error}"),
            );
            emit_config_decision(ConfigDecision::Allow);
            return Ok(());
        }
    };

    let violations = match kind {
        ConfigFileKind::Project => {
            let expected = mati_core::scaffold::settings::settings_template();
            decide::project_violations(&settings, &expected)
        }
        ConfigFileKind::Local => {
            let store = match crate::cli::proxy::StoreProxy::open(&cwd).await {
                Ok(store) => store,
                Err(error) => {
                    log_fail_open_named(
                        "config-change",
                        file_path,
                        &format!("cannot load sandbox invariants: {error}"),
                    );
                    emit_config_decision(ConfigDecision::Allow);
                    return Ok(());
                }
            };
            let (expected, _skipped, domain_universe, _warnings) =
                match super::sandbox::compute_rules(&store, &repo_root).await {
                    Ok(result) => result,
                    Err(error) => {
                        log_fail_open_named(
                            "config-change",
                            file_path,
                            &format!("cannot compute sandbox invariants: {error}"),
                        );
                        emit_config_decision(ConfigDecision::Allow);
                        return Ok(());
                    }
                };
            decide::local_violations(
                &settings,
                &decide::ExpectedFloor {
                    repo_root: &repo_root,
                    deny_read: &expected.deny_read,
                    deny_write: &expected.deny_write,
                    credentials_deny: &expected.credentials_deny,
                    credentials_mask: &expected.credentials_mask,
                    denied_domains: &expected.denied_domains,
                    domain_universe: &domain_universe,
                },
            )
        }
    };

    if violations.is_empty() {
        record_config_change(
            &cwd,
            &expected_path.to_string_lossy(),
            "<mati-enforcement>",
            "<intact>",
            "config_change_allowed_intact",
        )
        .await;
        emit_config_decision(ConfigDecision::Allow);
    } else if std::env::var_os("MATI_ALLOW_HOOK_REMOVAL").is_some_and(|value| value == "1") {
        // Deliberate removal. Record it and get out of the way — an anti-tamper
        // control with no sanctioned exit is a control users route around.
        for violation in &violations {
            record_config_change(
                &cwd,
                &violation.setting,
                &violation.old_value,
                &violation.new_value,
                "config_change_removal_authorized",
            )
            .await;
        }
        emit_config_decision(ConfigDecision::Allow);
    } else {
        // Repair before blocking. Claude Code writes the file before asking, so
        // a block alone leaves the stripped file on disk and the next session
        // starts unenforced. Project settings only: restoring sandbox entries in
        // settings.local.json means recompiling rules, which has its own
        // preview-and-drift semantics and must not happen from a hook.
        if matches!(kind, ConfigFileKind::Project) {
            match mati_core::scaffold::settings::restore_mati_entries(&expected_path) {
                Ok(()) => {
                    record_config_change(
                        &cwd,
                        &expected_path.to_string_lossy(),
                        "<stripped>",
                        "<restored>",
                        "config_change_entries_restored",
                    )
                    .await;
                }
                // Fail open on the repair, not on the decision: the block below
                // still stands and the tamper is still recorded.
                Err(error) => log_fail_open_named(
                    "config-change",
                    file_path,
                    &format!("could not restore mati entries: {error}"),
                ),
            }
        }
        block_config_change(&cwd, violations).await;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfigDecision {
    Allow,
    Block(String),
}

async fn block_config_change(cwd: &Path, violations: Vec<ConfigViolation>) {
    let reason = violations
        .iter()
        .map(|violation| {
            format!(
                "{} changed from {} to {}",
                violation.setting, violation.old_value, violation.new_value
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    for violation in &violations {
        record_config_change(
            cwd,
            &violation.setting,
            &violation.old_value,
            &violation.new_value,
            "config_change_tamper_detected",
        )
        .await;
    }
    emit_config_decision(ConfigDecision::Block(format!(
        "mati: settings change not adopted this session; {reason}"
    )));
}

/// Emit the ConfigChange protocol's top-level decision object. This is not
/// the PreToolUse `hookSpecificOutput` shape used by every older mati hook.
fn emit_config_decision(decision: ConfigDecision) {
    println!("{}", format_config_decision(&decision));
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

fn format_config_decision(decision: &ConfigDecision) -> String {
    match decision {
        ConfigDecision::Allow => r#"{"decision":"allow"}"#.to_string(),
        ConfigDecision::Block(reason) => format!(
            r#"{{"decision":"block","reason":"{}"}}"#,
            super::escape_json_string(reason)
        ),
    }
}

fn block_config_path(file_path: &str, cwd: &Path) -> PathBuf {
    let raw = Path::new(file_path);
    let joined = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        cwd.join(raw)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn owned_config_path(
    file_path: &str,
    cwd: &Path,
    repo_root: &Path,
) -> Option<(ConfigFileKind, PathBuf)> {
    let path = block_config_path(file_path, cwd);
    let project = repo_root.join(".claude/settings.json");
    let local = repo_root.join(".claude/settings.local.json");
    // Compare canonically, not lexically. On macOS `/tmp` is a symlink to
    // `/private/tmp`, and a repo reached through a symlinked parent is ordinary.
    // A lexical mismatch reports "not a mati-owned file" and the guard allows
    // the change — failing open on exactly the tamper it exists to catch, with
    // no signal that it happened. `canonicalize_lenient` walks up to a parent
    // that exists, so a deleted settings file still resolves.
    let same_file = |candidate: &Path| -> bool {
        if path == *candidate {
            return true;
        }
        match (
            super::sandbox::canonicalize_lenient(&path),
            super::sandbox::canonicalize_lenient(candidate),
        ) {
            (Some(resolved), Some(resolved_candidate)) => resolved == resolved_candidate,
            _ => false,
        }
    };
    if same_file(&project) {
        Some((ConfigFileKind::Project, project))
    } else if same_file(&local) {
        Some((ConfigFileKind::Local, local))
    } else {
        None
    }
}

async fn record_config_change(
    cwd: &Path,
    setting: &str,
    old_value: &str,
    new_value: &str,
    reason: &str,
) {
    let Ok(mati_root) = mati_root_for(cwd) else {
        return;
    };
    if !ensure_daemon(&mati_root).await {
        return;
    }
    let command = mati_core::mcp::protocol::Command::SandboxAudit(
        mati_core::mcp::protocol::SandboxAuditInput {
            setting: setting.to_string(),
            old_value: old_value.to_string(),
            new_value: new_value.to_string(),
            reason: reason.to_string(),
        },
    );
    let _ = super::daemon::daemon_v2(&mati_root, command).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A settings path reached through a symlink must still be recognised as
    /// mati-owned. Lexical comparison said "not ours" and the guard allowed the
    /// change — a silent bypass on macOS, where `/tmp` is a symlink, and in any
    /// repo reached through a symlinked parent.
    #[test]
    fn owned_path_resolves_through_a_symlinked_repo_root() {
        let real = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(real.path().join(".claude")).expect("claude dir");
        std::fs::write(real.path().join(".claude/settings.json"), "{}").expect("settings");

        let link_parent = tempfile::tempdir().expect("link parent");
        let link = link_parent.path().join("linked-repo");
        std::os::unix::fs::symlink(real.path(), &link).expect("symlink");

        let via_link = link.join(".claude/settings.json");
        assert_eq!(
            owned_config_path(via_link.to_str().unwrap(), real.path(), real.path())
                .map(|(kind, _)| kind),
            Some(ConfigFileKind::Project),
            "a symlinked path must resolve to the mati-owned settings file"
        );
    }

    #[test]
    fn owned_path_requires_actual_file_not_source_alone() {
        let cwd = Path::new("/repo");
        let project = Path::new("/repo").join(".claude/settings.json");
        assert_eq!(
            owned_config_path("/repo/.claude/settings.json", cwd, cwd),
            Some((ConfigFileKind::Project, project))
        );
        assert_eq!(
            owned_config_path("/repo/.claude/other.json", cwd, cwd),
            None
        );
        assert_eq!(
            owned_config_path("/repo/.claude/settings.local.json", cwd, cwd).map(|(kind, _)| kind),
            Some(ConfigFileKind::Local)
        );
    }

    #[test]
    fn top_level_output_is_distinct_from_pre_tool_use_wrapper() {
        assert_eq!(
            format_config_decision(&ConfigDecision::Allow),
            r#"{"decision":"allow"}"#
        );
        assert_eq!(
            format_config_decision(&ConfigDecision::Block("quote \" safely".to_string())),
            r#"{"decision":"block","reason":"quote \" safely"}"#
        );
    }
}
