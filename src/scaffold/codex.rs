//! Install Codex config, hooks, and skill scaffolding into `.codex/`.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;
use toml_edit::{value, Array, ArrayOfTables, DocumentMut, Item, Table};

const HOOKS_JSON: &str = r#"{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "bash .codex/hooks/session-start.sh"
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "bash .codex/hooks/user-prompt-submit.sh"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash .codex/hooks/pre-bash.sh"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash .codex/hooks/post-bash.sh"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "bash .codex/hooks/stop.sh"
          }
        ]
      }
    ]
  }
}"#;

const MATI_SKILL: &str = r#"---
name: mati
description: Codebase memory layer — gotchas, decisions, and file context that survive developer turnover.
---

# mati

Use `mati` as the codebase memory layer for this repository.

## Required workflow

1. At session start or when entering the repo, call `mem_bootstrap`.
2. Before editing or shell-inspecting an unfamiliar file, call `mem_get("file:<path>")`.
3. Use `mem_query` for broader searches across the knowledge base.
4. When the developer asks to save durable project knowledge, call `mem_set`.
5. Before merge-oriented changes, prefer `mati diff <range>` or the equivalent memory checks.

## mem_set rules

**Gotcha records:**
- Rule MUST start with an imperative verb (Always/Never/Ensure/Do not).
- Reason MUST state causality — what breaks and why.
- Set confirmed=false; run `mati gotcha confirm <key>` after.

**File enrichment:**
- Value and purpose MUST start with a verb (Handles/Manages/Validates).
- Preserve existing structural fields from mem_get — only update purpose and gotcha_keys.

**Confirm routing (use MCP, not CLI — CLI is sandboxed in Codex):**
- Single gotcha: mem_set(action="write") then mem_set(key, action="confirm").
- Single file enrichment: mem_set then mem_set(action="confirm") for each gotcha.
- Batch enrichment: mem_set with confirmed=false. End with "Run `mati review` to confirm."
- To delete a gotcha: mem_set(key, action="delete").

**Quality gate:** records with quality < 0.2 are suppressed. Imperative verb + causality reason = quality >= 0.4.

## Platform semantics

- Codex mode has hard Bash enforcement and soft native-read enforcement.
- Do not assume `mati` can block native file reads in Codex.
- If Bash inspection is blocked, call `mem_get("file:<path>")` first.
"#;

const SKILL_CONFIG_PATH: &str = ".codex/skills/mati/SKILL.md";

pub const CODEX_HOOK_SCRIPTS: &[(&str, &str)] = &[
    (
        "session-start.sh",
        crate::hooks::codex_session_start::SCRIPT,
    ),
    (
        "user-prompt-submit.sh",
        crate::hooks::codex_user_prompt::SCRIPT,
    ),
    ("pre-bash.sh", crate::hooks::codex_pre_bash::SCRIPT),
    ("post-bash.sh", crate::hooks::codex_post_bash::SCRIPT),
    ("stop.sh", crate::hooks::codex_stop::SCRIPT),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexInstallResult {
    Installed {
        scripts: usize,
        missing_deps: Vec<&'static str>,
    },
    NoCodex,
}

pub fn install_codex(project_root: &Path, create_if_missing: bool) -> Result<CodexInstallResult> {
    let codex_dir = project_root.join(".codex");
    if !codex_dir.is_dir() && !create_if_missing {
        return Ok(CodexInstallResult::NoCodex);
    }

    std::fs::create_dir_all(&codex_dir)
        .with_context(|| format!("failed to create {}", codex_dir.display()))?;

    let hooks_path = codex_dir.join("hooks.json");
    merge_hooks_json(&hooks_path)?;

    let config_path = codex_dir.join("config.toml");
    merge_config_toml(&config_path, SKILL_CONFIG_PATH, project_root)?;

    let hooks_dir = codex_dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("failed to create {}", hooks_dir.display()))?;
    for (name, content) in CODEX_HOOK_SCRIPTS {
        let path = hooks_dir.join(name);
        write_if_changed(&path, content)?;
        make_executable(&path)?;
    }

    // Write mati binary wrapper so hooks resolve the same binary as MCP.
    super::write_mati_wrapper(&hooks_dir)?;

    let skill_dir = codex_dir.join("skills").join("mati");
    std::fs::create_dir_all(&skill_dir)
        .with_context(|| format!("failed to create {}", skill_dir.display()))?;
    write_if_changed(&skill_dir.join("SKILL.md"), MATI_SKILL)?;

    Ok(CodexInstallResult::Installed {
        scripts: CODEX_HOOK_SCRIPTS.len(),
        missing_deps: missing_hook_dependencies(),
    })
}

fn merge_hooks_json(path: &Path) -> Result<()> {
    let mati_hooks: Value = serde_json::from_str(HOOKS_JSON)?;
    let merged = if path.exists() {
        let existing_str = std::fs::read_to_string(path)?;
        let mut existing: Value = serde_json::from_str(&existing_str)
            .unwrap_or_else(|_| Value::Object(serde_json::Map::new()));
        if let Value::Object(ref mut map) = existing {
            merge_hooks(map, &mati_hooks["hooks"]);
        }
        existing
    } else {
        mati_hooks
    };

    let output = serde_json::to_string_pretty(&merged)?;
    write_if_changed(path, &output)
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

fn merge_config_toml(path: &Path, skill_path: &str, project_root: &Path) -> Result<()> {
    let mut doc = if path.exists() {
        let existing = std::fs::read_to_string(path)?;
        existing
            .parse::<DocumentMut>()
            .unwrap_or_else(|_| DocumentMut::new())
    } else {
        DocumentMut::new()
    };

    if doc.get("features").is_none() || !doc["features"].is_table() {
        doc["features"] = Item::Table(Table::new());
    }
    doc["features"]["codex_hooks"] = value(true);

    if doc.get("mcp_servers").is_none() || !doc["mcp_servers"].is_table() {
        doc["mcp_servers"] = Item::Table(Table::new());
    }
    if !doc["mcp_servers"]
        .as_table()
        .is_some_and(|t| t.contains_key("mati"))
        || !doc["mcp_servers"]["mati"].is_table()
    {
        doc["mcp_servers"]["mati"] = Item::Table(Table::new());
    }
    doc["mcp_servers"]["mati"]["command"] = value(super::mati_binary_path());
    let mut args = Array::new();
    args.push("serve");
    doc["mcp_servers"]["mati"]["args"] = value(args);
    // Codex spawns MCP servers with CWD=/. The cwd field tells Codex to set
    // the working directory to the project root so `mati serve` derives the
    // correct store slug from current_dir().
    let canonical =
        std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
    doc["mcp_servers"]["mati"]["cwd"] = value(canonical.to_string_lossy().as_ref());

    if doc.get("skills").is_none() || !doc["skills"].is_table() {
        doc["skills"] = Item::Table(Table::new());
    }
    if !doc["skills"]
        .as_table()
        .is_some_and(|t| t.contains_key("config"))
        || !doc["skills"]["config"].is_array_of_tables()
    {
        doc["skills"]["config"] = Item::ArrayOfTables(ArrayOfTables::new());
    }
    let skills = doc["skills"]["config"]
        .as_array_of_tables_mut()
        .expect("skills.config should be an array of tables");
    let existing_index = {
        skills
            .iter()
            .position(|table| table.get("path").and_then(|i| i.as_str()) == Some(skill_path))
    };
    if let Some(index) = existing_index {
        skills.get_mut(index).expect("index should exist")["enabled"] = value(true);
    } else {
        let mut skill = Table::new();
        skill["path"] = value(skill_path);
        skill["enabled"] = value(true);
        skills.push(skill);
    }

    write_if_changed(path, &doc.to_string())
}

fn missing_hook_dependencies() -> Vec<&'static str> {
    let mut missing = Vec::new();
    for cmd in ["jq", "awk"] {
        let ok = std::process::Command::new(cmd)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            missing.push(cmd);
        }
    }
    missing
}

use super::{make_executable, write_if_changed};

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn skips_when_no_codex_dir_in_auto_mode() {
        let dir = TempDir::new().unwrap();
        let result = install_codex(dir.path(), false).unwrap();
        assert_eq!(result, CodexInstallResult::NoCodex);
    }

    #[test]
    fn installs_codex_config_hooks_and_skill() {
        let dir = TempDir::new().unwrap();
        let result = install_codex(dir.path(), true).unwrap();
        match result {
            CodexInstallResult::Installed { scripts, .. } => {
                assert_eq!(scripts, CODEX_HOOK_SCRIPTS.len())
            }
            other => panic!("expected Installed, got {other:?}"),
        }

        let hooks: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join(".codex/hooks.json")).unwrap(),
        )
        .unwrap();
        assert!(hooks["hooks"]["SessionStart"].is_array());
        assert!(hooks["hooks"]["PreToolUse"].is_array());

        let config = std::fs::read_to_string(dir.path().join(".codex/config.toml")).unwrap();
        let doc = config.parse::<DocumentMut>().unwrap();
        assert_eq!(doc["features"]["codex_hooks"].as_bool(), Some(true));
        assert_eq!(
            doc["mcp_servers"]["mati"]["args"][0].as_str(),
            Some("serve")
        );
        assert_eq!(
            doc["skills"]["config"][0]["path"].as_str(),
            Some(SKILL_CONFIG_PATH)
        );
        assert!(dir.path().join(".codex/skills/mati/SKILL.md").exists());
    }

    #[test]
    fn merge_preserves_existing_codex_config_and_hooks() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        std::fs::create_dir_all(&codex_dir).unwrap();
        std::fs::write(
            codex_dir.join("hooks.json"),
            r#"{"hooks":{"PreToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"custom-pre-write.sh"}]}]}}"#,
        )
        .unwrap();
        std::fs::write(
            codex_dir.join("config.toml"),
            "[profiles]\ntrusted = true\n",
        )
        .unwrap();

        install_codex(dir.path(), false).unwrap();

        let hooks: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(codex_dir.join("hooks.json")).unwrap())
                .unwrap();
        let pre = hooks["hooks"]["PreToolUse"].as_array().unwrap();
        assert!(pre.iter().any(|entry| {
            entry["hooks"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|hook| hook["command"] == "custom-pre-write.sh")
        }));

        let config = std::fs::read_to_string(codex_dir.join("config.toml")).unwrap();
        let doc = config.parse::<DocumentMut>().unwrap();
        assert_eq!(doc["profiles"]["trusted"].as_bool(), Some(true));
        assert_eq!(doc["features"]["codex_hooks"].as_bool(), Some(true));
    }

    #[test]
    fn codex_wrapper_contains_absolute_binary_path_matching_mcp_config() {
        let dir = TempDir::new().unwrap();
        install_codex(dir.path(), true).unwrap();

        // Wrapper must exist and be executable
        let wrapper_path = dir.path().join(".codex/hooks/mati");
        assert!(
            wrapper_path.exists(),
            ".codex/hooks/mati wrapper must exist"
        );

        let wrapper = std::fs::read_to_string(&wrapper_path).unwrap();
        assert!(wrapper.contains("exec"), "wrapper must use exec");

        // Extract the exec target from the wrapper
        let exec_line = wrapper.lines().find(|l| l.contains("exec")).unwrap();
        let exec_target = exec_line
            .strip_prefix("exec \"")
            .and_then(|s| s.strip_suffix("\" \"$@\""))
            .expect("exec line must follow format: exec \"<path>\" \"$@\"");

        // MCP config must point to the same binary
        let config = std::fs::read_to_string(dir.path().join(".codex/config.toml")).unwrap();
        let doc = config.parse::<DocumentMut>().unwrap();
        let mcp_command = doc["mcp_servers"]["mati"]["command"]
            .as_str()
            .expect("mcp_servers.mati.command must be a string");

        assert_eq!(
            exec_target, mcp_command,
            "wrapper and MCP config must use the same binary path"
        );

        // MCP args must include "serve"
        let args = doc["mcp_servers"]["mati"]["args"]
            .as_array()
            .expect("mcp_servers.mati.args must be an array");
        let args_str: Vec<&str> = args.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            args_str.contains(&"serve"),
            "args must contain 'serve', got: {args_str:?}"
        );

        // cwd must be set to an absolute project path (Codex spawns with CWD=/)
        let cwd = doc["mcp_servers"]["mati"]["cwd"]
            .as_str()
            .expect("mcp_servers.mati.cwd must be set");
        assert!(
            cwd.starts_with('/'),
            "cwd must be an absolute path, got: {cwd}"
        );
    }

    #[test]
    fn codex_hook_scripts_prepend_hooks_dir_to_path() {
        let dir = TempDir::new().unwrap();
        install_codex(dir.path(), true).unwrap();

        for (name, _) in CODEX_HOOK_SCRIPTS {
            let path = dir.path().join(".codex/hooks").join(name);
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("hook script {name} must exist"));
            assert!(
                content.contains("HOOKS_DIR=") && content.contains("export PATH="),
                "hook script {name} must prepend HOOKS_DIR to PATH"
            );
        }
    }

    #[test]
    fn codex_reinit_updates_wrapper_path() {
        let dir = TempDir::new().unwrap();
        install_codex(dir.path(), true).unwrap();

        // Tamper with the wrapper to simulate a stale binary path
        let wrapper_path = dir.path().join(".codex/hooks/mati");
        std::fs::write(
            &wrapper_path,
            "#!/usr/bin/env bash\nexec \"/old/path/mati\" \"$@\"\n",
        )
        .unwrap();

        // Re-install should overwrite
        install_codex(dir.path(), false).unwrap();
        let wrapper = std::fs::read_to_string(&wrapper_path).unwrap();
        assert!(
            !wrapper.contains("/old/path/mati"),
            "re-init must update the wrapper binary path"
        );
    }
}
