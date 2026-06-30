//! Install hooks into `.claude/` (M-06-J).
//!
//! Writes `.claude/settings.json` with hook registration and creates
//! the real hook scripts in `.claude/hooks/`.
//!
//! Only writes if `.claude/` already exists — if the user isn't using Claude
//! Code, hooks are skipped.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

/// Hook and MCP server registration for `.claude/settings.json`.
///
/// Contains two top-level keys:
/// - `hooks` — PreToolUse / PostToolUse / PreCompact / PostCompact / SessionEnd / SubagentStart / Stop (ARCHITECTURE.md §10)
/// - `mcpServers` — registers `mati serve` as an MCP stdio server (M-07-I)
const SETTINGS_JSON: &str = r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Glob|Grep",
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/pre-read.sh",
            "timeout": 3000
          }
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/pre-bash.sh",
            "timeout": 3000
          }
        ]
      },
      {
        "matcher": "Edit|Write|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/pre-edit.sh",
            "timeout": 3000
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Read|Glob|Grep",
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/post-read-compliance.sh",
            "async": true
          }
        ]
      },
      {
        "matcher": "Edit|Write|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/post-edit.sh",
            "async": true
          }
        ]
      },
      {
        "matcher": "mcp__mati__mem_get",
        "hooks": [
          { "type": "command", "command": ".claude/hooks/post-memget.sh" }
        ]
      }
    ],
    "PreCompact": [
      {
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/pre-compact.sh"
          }
        ]
      }
    ],
    "PostCompact": [
      {
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/post-compact.sh"
          }
        ]
      }
    ],
    "SessionEnd": [
      {
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/session-end.sh",
            "timeout": 3000
          }
        ]
      }
    ],
    "SubagentStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/subagent-start.sh"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/stop.sh",
            "async": true
          }
        ]
      }
    ]
  },
  "mcpServers": {
    "mati": {
      "command": "mati",
      "args": ["serve"]
    }
  }
}
"#;

/// All hook scripts to install, with their content.
///
/// Each script is a Rust string constant defined in `crate::hooks::*`.
/// Replaces the pass-through stubs from M-06-J with real hook logic (M-09).
pub const HOOK_SCRIPTS: &[(&str, &str)] = &[
    ("pre-read.sh", crate::hooks::pre_read::SCRIPT),
    ("pre-edit.sh", crate::hooks::pre_edit::SCRIPT),
    ("pre-bash.sh", crate::hooks::pre_bash::SCRIPT),
    (
        "post-read-compliance.sh",
        crate::hooks::post_compliance::SCRIPT,
    ),
    ("post-edit.sh", crate::hooks::post_edit::SCRIPT),
    ("pre-compact.sh", crate::hooks::pre_compact::SCRIPT),
    ("post-compact.sh", crate::hooks::post_compact::SCRIPT),
    ("session-end.sh", crate::hooks::session_end::SCRIPT),
    ("subagent-start.sh", crate::hooks::subagent_start::SCRIPT),
    ("stop.sh", crate::hooks::claude_stop::SCRIPT),
    ("post-memget.sh", crate::hooks::post_memget::SCRIPT),
];

/// Outcome of the hook installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallResult {
    /// Hooks and settings.json written successfully.
    Installed {
        /// Number of hook scripts written.
        scripts: usize,
        /// Missing runtime dependencies required by the installed hooks.
        missing_deps: Vec<&'static str>,
    },
    /// `.claude/` directory doesn't exist — user isn't using Claude Code.
    NoClaude,
}

/// Install hook registration and hook scripts into `.claude/`.
///
/// - Merges mati's `hooks` key into existing `.claude/settings.json`,
///   preserving any user-defined settings (permissions, env vars, etc.).
/// - Writes `.mcp.json` to the project root for MCP server registration.
///   Claude Code reads `mcpServers` from `.mcp.json` at the project root;
///   the `mcpServers` key in `.claude/settings.json` is kept as a fallback.
/// - Creates `.claude/hooks/` and writes the real hook scripts.
/// - Existing scripts are overwritten (mati owns these files).
/// - Only proceeds if `.claude/` already exists.
pub fn install_hooks(project_root: &Path) -> Result<InstallResult> {
    let claude_dir = project_root.join(".claude");
    if !claude_dir.is_dir() {
        return Ok(InstallResult::NoClaude);
    }

    // Merge hooks into settings.json, preserving existing user settings.
    let settings_path = claude_dir.join("settings.json");
    merge_hooks_into_settings(&settings_path)
        .with_context(|| format!("failed to update {}", settings_path.display()))?;

    // Write .mcp.json to project root — Claude Code's primary MCP config location.
    let mcp_json_path = project_root.join(".mcp.json");
    write_mcp_json(&mcp_json_path, project_root)
        .with_context(|| format!("failed to write {}", mcp_json_path.display()))?;

    // Create hooks directory and write scripts.
    let hooks_dir = claude_dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("failed to create {}", hooks_dir.display()))?;

    for (name, content) in HOOK_SCRIPTS {
        let path = hooks_dir.join(name);
        write_if_changed(&path, content)
            .with_context(|| format!("failed to write {}", path.display()))?;
        make_executable(&path)?;
    }

    // Write mati binary wrapper so hooks resolve the same binary as MCP.
    super::write_mati_wrapper(&hooks_dir)?;

    let missing_deps = missing_hook_dependencies();

    Ok(InstallResult::Installed {
        scripts: HOOK_SCRIPTS.len(),
        missing_deps,
    })
}

/// Merge mati's hook and MCP server registration into an existing settings.json.
///
/// If the file doesn't exist, writes the full settings. If it exists,
/// parses it, replaces only the `hooks` and `mcpServers` keys, and writes
/// back — preserving all other user settings.
fn merge_hooks_into_settings(path: &Path) -> Result<()> {
    let mut mati_settings: Value = serde_json::from_str(SETTINGS_JSON)?;
    // Use bare command name — portable across machines.
    mati_settings["mcpServers"]["mati"]["command"] = serde_json::Value::String("mati".to_owned());

    let merged = if path.exists() {
        let existing_str = std::fs::read_to_string(path)?;
        let mut existing: Value = serde_json::from_str(&existing_str)
            .unwrap_or_else(|_| Value::Object(serde_json::Map::new()));

        if let Value::Object(ref mut map) = existing {
            merge_hooks(map, &mati_settings["hooks"]);
            // Merge mcpServers: add "mati" entry without clobbering other servers.
            let mati_server = mati_settings["mcpServers"]["mati"].clone();
            if let Some(Value::Object(ref mut servers)) = map.get_mut("mcpServers") {
                servers.insert("mati".to_string(), mati_server);
            } else {
                map.insert(
                    "mcpServers".to_string(),
                    mati_settings["mcpServers"].clone(),
                );
            }
        }
        existing
    } else {
        mati_settings
    };

    let output = serde_json::to_string_pretty(&merged)?;
    write_if_changed(path, &output)?;
    Ok(())
}

fn merge_hooks(root: &mut serde_json::Map<String, Value>, mati_hooks: &Value) {
    let Some(mati_events) = mati_hooks.as_object() else {
        root.insert("hooks".to_string(), mati_hooks.clone());
        return;
    };

    let hooks_value = root
        .entry("hooks".to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));

    let Value::Object(existing_events) = hooks_value else {
        *hooks_value = mati_hooks.clone();
        return;
    };

    for (event_name, mati_entries_value) in mati_events {
        let Some(mati_entries) = mati_entries_value.as_array() else {
            existing_events.insert(event_name.clone(), mati_entries_value.clone());
            continue;
        };

        let owned_commands = mati_hook_commands(mati_entries);
        let existing_entries = existing_events
            .entry(event_name.clone())
            .or_insert_with(|| Value::Array(Vec::new()));

        let Value::Array(existing_entries) = existing_entries else {
            *existing_entries = Value::Array(mati_entries.clone());
            continue;
        };

        existing_entries.retain(|entry| !entry_contains_owned_command(entry, &owned_commands));
        existing_entries.extend(mati_entries.clone());
    }
}

fn mati_hook_commands(entries: &[Value]) -> Vec<String> {
    entries.iter().flat_map(entry_hook_commands).collect()
}

fn entry_hook_commands(entry: &Value) -> Vec<String> {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|hook| hook.get("command").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect()
}

fn entry_contains_owned_command(entry: &Value, owned_commands: &[String]) -> bool {
    entry_hook_commands(entry)
        .iter()
        .any(|command| owned_commands.iter().any(|owned| owned == command))
}

/// Write `.mcp.json` to the project root with the mati MCP server registration.
///
/// Claude Code reads MCP server configuration from `.mcp.json` at the project
/// root — this is the primary mechanism; `mcpServers` in `.claude/settings.json`
/// is kept as a fallback for older Claude Code versions.
///
/// Uses the bare `mati` command (PATH-resolved) so the config is portable
/// across machines. Claude Code sets cwd to the project root when spawning
/// MCP servers, so `mati serve` detects the project automatically.
fn write_mcp_json(path: &Path, _project_root: &Path) -> Result<()> {
    let mati_server = serde_json::json!({
        "command": "mati",
        "args": ["serve"]
    });

    let mut mcp_config = if path.exists() {
        let existing_str = std::fs::read_to_string(path)?;
        serde_json::from_str(&existing_str)
            .unwrap_or_else(|_| Value::Object(serde_json::Map::new()))
    } else {
        Value::Object(serde_json::Map::new())
    };

    if let Value::Object(ref mut map) = mcp_config {
        if let Some(Value::Object(ref mut servers)) = map.get_mut("mcpServers") {
            servers.insert("mati".to_string(), mati_server);
        } else {
            map.insert(
                "mcpServers".to_string(),
                serde_json::json!({ "mati": mati_server }),
            );
        }
    } else {
        mcp_config = serde_json::json!({
            "mcpServers": {
                "mati": mati_server
            }
        });
    }

    let output = serde_json::to_string_pretty(&mcp_config)?;
    write_if_changed(path, &output)?;
    Ok(())
}

fn command_available(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn missing_hook_dependencies() -> Vec<&'static str> {
    missing_hook_dependencies_with(command_available)
}

fn missing_hook_dependencies_with<F>(mut has_cmd: F) -> Vec<&'static str>
where
    F: FnMut(&str) -> bool,
{
    let mut missing = Vec::new();
    if !has_cmd("jq") {
        missing.push("jq");
    }
    if !has_cmd("awk") {
        missing.push("awk");
    }
    missing
}

use super::{make_executable, write_if_changed};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn skips_when_no_claude_dir() {
        let dir = TempDir::new().unwrap();
        let result = install_hooks(dir.path()).unwrap();
        assert_eq!(result, InstallResult::NoClaude);
    }

    #[test]
    fn installs_settings_and_scripts() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();

        let result = install_hooks(dir.path()).unwrap();
        match result {
            InstallResult::Installed { scripts, .. } => assert_eq!(scripts, 11),
            other => panic!("expected Installed, got {other:?}"),
        }

        // settings.json exists and is valid JSON.
        let settings = std::fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&settings).unwrap();
        assert!(parsed["hooks"]["PreToolUse"].is_array());
        assert!(parsed["hooks"]["PostToolUse"].is_array());
        assert!(parsed["hooks"]["PreCompact"].is_array());
        assert!(parsed["hooks"]["PostCompact"].is_array());
        assert!(parsed["hooks"]["SessionEnd"].is_array());
        assert!(parsed["hooks"]["SubagentStart"].is_array());
        assert!(parsed["hooks"]["Stop"].is_array());
        // MCP server registered with portable bare command.
        let cmd = parsed["mcpServers"]["mati"]["command"].as_str().unwrap();
        assert_eq!(cmd, "mati", "command must be bare 'mati' for portability");
        assert_eq!(parsed["mcpServers"]["mati"]["args"][0], "serve");
    }

    #[test]
    fn merges_into_existing_settings_without_clobbering() {
        let dir = TempDir::new().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        // Pre-existing settings with user config.
        let existing = r#"{"permissions": {"allow": ["npm test"]}, "env": {"DEBUG": "true"}}"#;
        std::fs::write(claude_dir.join("settings.json"), existing).unwrap();

        install_hooks(dir.path()).unwrap();

        let settings = std::fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&settings).unwrap();

        // User settings preserved.
        assert_eq!(parsed["permissions"]["allow"][0], "npm test");
        assert_eq!(parsed["env"]["DEBUG"], "true");
        // Hooks added.
        assert!(parsed["hooks"]["PreToolUse"].is_array());
        // MCP server added with portable bare command.
        assert_eq!(parsed["mcpServers"]["mati"]["command"], "mati");
    }

    #[test]
    fn merges_mcp_servers_without_clobbering_existing_servers() {
        let dir = TempDir::new().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        // Pre-existing settings with another MCP server.
        let existing = r#"{"mcpServers": {"other-tool": {"command": "other", "args": ["run"]}}}"#;
        std::fs::write(claude_dir.join("settings.json"), existing).unwrap();

        install_hooks(dir.path()).unwrap();

        let settings = std::fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&settings).unwrap();

        // Existing server preserved.
        assert_eq!(parsed["mcpServers"]["other-tool"]["command"], "other");
        // mati server added alongside with portable bare command.
        assert_eq!(parsed["mcpServers"]["mati"]["command"], "mati");
        assert_eq!(parsed["mcpServers"]["mati"]["args"][0], "serve");
    }

    #[test]
    fn merges_hooks_without_clobbering_unrelated_existing_hooks() {
        let dir = TempDir::new().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        let existing = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Write",
                        "hooks": [
                            {
                                "type": "command",
                                "command": ".claude/hooks/custom-pre-write.sh"
                            }
                        ]
                    }
                ]
            }
        });
        std::fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        install_hooks(dir.path()).unwrap();

        let settings = std::fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&settings).unwrap();
        let pre_tool_use = parsed["hooks"]["PreToolUse"].as_array().unwrap();

        assert!(
            pre_tool_use.iter().any(|entry| {
                entry["hooks"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|hook| hook["command"] == ".claude/hooks/custom-pre-write.sh")
            }),
            "custom existing hook should be preserved"
        );
        assert!(
            pre_tool_use.iter().any(|entry| {
                entry["hooks"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|hook| hook["command"] == ".claude/hooks/pre-read.sh")
            }),
            "mati pre-read hook should be present"
        );
    }

    #[test]
    fn all_hook_scripts_exist_and_are_executable() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();

        install_hooks(dir.path()).unwrap();

        let hooks_dir = dir.path().join(".claude/hooks");
        for (name, _) in HOOK_SCRIPTS {
            let path = hooks_dir.join(name);
            assert!(path.exists(), "missing hook script: {name}");

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o111, 0o111, "{name} should be executable");
            }
        }
    }

    #[test]
    fn pre_hooks_delegate_to_hook_decide() {
        // Enforcement logic is now in Rust (hooks::decide + cli::hook_decide).
        // Shell wrappers just exec the correct hook-decide variant.
        assert!(crate::hooks::pre_read::SCRIPT.contains("exec mati hook-decide claude-pre-read"));
        assert!(crate::hooks::pre_edit::SCRIPT.contains("exec mati hook-decide claude-pre-edit"));
        assert!(crate::hooks::pre_bash::SCRIPT.contains("exec mati hook-decide claude-pre-bash"));
    }

    #[test]
    fn writes_mcp_json_to_project_root() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();

        install_hooks(dir.path()).unwrap();

        let mcp_json_path = dir.path().join(".mcp.json");
        assert!(
            mcp_json_path.exists(),
            ".mcp.json should be written to project root"
        );

        let content = std::fs::read_to_string(&mcp_json_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["mcpServers"]["mati"]["command"], "mati");
        assert_eq!(parsed["mcpServers"]["mati"]["args"][0], "serve");
        // No --path arg — mati serve detects project from cwd.
        assert!(
            parsed["mcpServers"]["mati"]["args"]
                .as_array()
                .unwrap()
                .len()
                == 1,
            "args must only contain 'serve', no --path"
        );
    }

    #[test]
    fn write_mcp_json_preserves_existing_servers() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".mcp.json");
        let existing = serde_json::json!({
            "mcpServers": {
                "other-tool": {
                    "command": "other",
                    "args": ["run"]
                }
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&existing).unwrap()).unwrap();

        write_mcp_json(&path, dir.path()).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["mcpServers"]["other-tool"]["command"], "other");
        assert_eq!(parsed["mcpServers"]["mati"]["command"], "mati");
        assert_eq!(parsed["mcpServers"]["mati"]["args"][0], "serve");
    }

    #[test]
    fn detects_all_hook_runtime_dependencies() {
        let missing = missing_hook_dependencies_with(|cmd| cmd == "jq");
        assert_eq!(missing, vec!["awk"]);

        let missing = missing_hook_dependencies_with(|_| false);
        assert_eq!(missing, vec!["jq", "awk"]);
    }

    #[test]
    fn idempotent_on_rerun() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();

        install_hooks(dir.path()).unwrap();
        let first_content =
            std::fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        let first_mcp = std::fs::read_to_string(dir.path().join(".mcp.json")).unwrap();

        install_hooks(dir.path()).unwrap();
        let second_content =
            std::fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        let second_mcp = std::fs::read_to_string(dir.path().join(".mcp.json")).unwrap();

        assert_eq!(first_content, second_content);
        assert_eq!(first_mcp, second_mcp);
    }

    #[test]
    fn claude_wrapper_exists_and_matches_mcp_config() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        install_hooks(dir.path()).unwrap();

        // Wrapper must exist
        let wrapper_path = dir.path().join(".claude/hooks/mati");
        assert!(
            wrapper_path.exists(),
            ".claude/hooks/mati wrapper must exist"
        );

        let wrapper = std::fs::read_to_string(&wrapper_path).unwrap();
        assert!(wrapper.contains("exec"), "wrapper must use exec");

        // Wrapper uses absolute path (hooks run in restricted shell without ~/.cargo/bin on PATH).
        let exec_line = wrapper.lines().find(|l| l.contains("exec")).unwrap();
        let exec_target = exec_line
            .strip_prefix("exec \"")
            .and_then(|s| s.strip_suffix("\" \"$@\""))
            .expect("exec line must follow format: exec \"<path>\" \"$@\"");
        assert!(
            exec_target.starts_with('/'),
            "wrapper must use absolute path, got: {exec_target}"
        );

        // MCP config uses portable bare command (resolved via PATH by Claude Code).
        let settings = std::fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&settings).unwrap();
        assert_eq!(
            parsed["mcpServers"]["mati"]["command"], "mati",
            "MCP config must use bare 'mati' for portability"
        );
    }

    #[test]
    fn claude_hook_scripts_prepend_hooks_dir_to_path() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        install_hooks(dir.path()).unwrap();

        for (name, _) in HOOK_SCRIPTS {
            let path = dir.path().join(".claude/hooks").join(name);
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("hook script {name} must exist"));
            assert!(
                content.contains("HOOKS_DIR=") && content.contains("export PATH="),
                "hook script {name} must prepend HOOKS_DIR to PATH"
            );
        }
    }
}
