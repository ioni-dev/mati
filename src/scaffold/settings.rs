//! Install hooks into `.claude/` (M-06-J).
//!
//! Writes `.claude/settings.json` with hook registration and creates
//! pass-through stub scripts in `.claude/hooks/`. The stubs unconditionally
//! allow all operations — real hook logic is implemented in M-09.
//!
//! Only writes if `.claude/` already exists — if the user isn't using Claude
//! Code, hooks are skipped.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

/// Hook and MCP server registration for `.claude/settings.json`.
///
/// Contains two top-level keys:
/// - `hooks` — PreToolUse / PostToolUse / PreCompact / SessionEnd (ARCHITECTURE.md §10)
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
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Read|Glob|Grep|Bash",
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/post-read-compliance.sh"
          }
        ]
      },
      {
        "matcher": "Edit|Write|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/post-edit.sh"
          }
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
    "SessionEnd": [
      {
        "hooks": [
          {
            "type": "command",
            "command": ".claude/hooks/session-end.sh"
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
    ("pre-read.sh",             crate::hooks::pre_read::SCRIPT),
    ("pre-bash.sh",             crate::hooks::pre_bash::SCRIPT),
    ("post-read-compliance.sh", crate::hooks::post_compliance::SCRIPT),
    ("post-edit.sh",            crate::hooks::post_edit::SCRIPT),
    ("pre-compact.sh",          crate::hooks::pre_compact::SCRIPT),
    ("session-end.sh",          crate::hooks::session_end::SCRIPT),
];

/// Outcome of the hook installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallResult {
    /// Hooks and settings.json written successfully.
    Installed {
        /// Number of hook scripts written.
        scripts: usize,
        /// True if `jq` was not found on PATH — hooks will fail at runtime.
        jq_missing: bool,
    },
    /// `.claude/` directory doesn't exist — user isn't using Claude Code.
    NoClaude,
}

/// Install hook registration and stub scripts into `.claude/`.
///
/// - Merges mati's `hooks` key into existing `.claude/settings.json`,
///   preserving any user-defined settings (permissions, env vars, etc.).
/// - Creates `.claude/hooks/` and writes pass-through stub scripts.
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

    let jq_missing = !jq_available();

    Ok(InstallResult::Installed {
        scripts: HOOK_SCRIPTS.len(),
        jq_missing,
    })
}

/// Merge mati's hook and MCP server registration into an existing settings.json.
///
/// If the file doesn't exist, writes the full settings. If it exists,
/// parses it, replaces only the `hooks` and `mcpServers` keys, and writes
/// back — preserving all other user settings.
fn merge_hooks_into_settings(path: &Path) -> Result<()> {
    let mati_settings: Value = serde_json::from_str(SETTINGS_JSON)?;

    let merged = if path.exists() {
        let existing_str = std::fs::read_to_string(path)?;
        let mut existing: Value = serde_json::from_str(&existing_str)
            .unwrap_or_else(|_| Value::Object(serde_json::Map::new()));

        if let Value::Object(ref mut map) = existing {
            map.insert("hooks".to_string(), mati_settings["hooks"].clone());
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

/// Check if `jq` is available on PATH.
fn jq_available() -> bool {
    std::process::Command::new("jq")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Write a file only if the content differs from what's on disk.
/// Avoids unnecessary writes and timestamp churn.
fn write_if_changed(path: &Path, content: &str) -> Result<()> {
    if path.exists() {
        if let Ok(existing) = std::fs::read_to_string(path) {
            if existing == content {
                return Ok(());
            }
        }
    }
    std::fs::write(path, content)?;
    Ok(())
}

/// Set the executable bit on a file (Unix only).
#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

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
            InstallResult::Installed { scripts, .. } => assert_eq!(scripts, 6),
            other => panic!("expected Installed, got {other:?}"),
        }

        // settings.json exists and is valid JSON.
        let settings = std::fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&settings).unwrap();
        assert!(parsed["hooks"]["PreToolUse"].is_array());
        assert!(parsed["hooks"]["PostToolUse"].is_array());
        assert!(parsed["hooks"]["PreCompact"].is_array());
        assert!(parsed["hooks"]["SessionEnd"].is_array());
        // MCP server registered.
        assert_eq!(parsed["mcpServers"]["mati"]["command"], "mati");
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
        // MCP server added.
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
        // mati server added alongside.
        assert_eq!(parsed["mcpServers"]["mati"]["command"], "mati");
        assert_eq!(parsed["mcpServers"]["mati"]["args"][0], "serve");
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
    fn pre_hooks_contain_decision_json() {
        // Verify the real hook scripts contain the permissionDecision protocol.
        assert!(crate::hooks::pre_read::SCRIPT.contains("permissionDecision"));
        assert!(crate::hooks::pre_bash::SCRIPT.contains("permissionDecision"));
    }

    #[test]
    fn idempotent_on_rerun() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();

        install_hooks(dir.path()).unwrap();
        let first_content =
            std::fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();

        install_hooks(dir.path()).unwrap();
        let second_content =
            std::fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();

        assert_eq!(first_content, second_content);
    }
}
