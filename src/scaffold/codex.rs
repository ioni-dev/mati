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
            "command": "bash .codex/hooks/session-start.sh",
            "statusMessage": "Loading project knowledge..."
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
            "command": "bash .codex/hooks/pre-bash.sh",
            "statusMessage": "Checking file knowledge..."
          }
        ]
      },
      {
        "matcher": "apply_patch",
        "hooks": [
          {
            "type": "command",
            "command": "bash .codex/hooks/pre-apply-patch.sh",
            "statusMessage": "Checking file knowledge before edit..."
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
- Set confirmed=false on write; confirm via mem_set(action="confirm") — see Confirm routing below.

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

- Codex PreToolUse hooks block unconsulted file reads via exit 2 + stderr.
- PostToolUse logs compliance for analytics — no context injection.
- Always call `mem_get("file:<path>")` before shell-inspecting a file.

## /mati-enrich — extraction pipeline (v0.2)

The four-stage pipeline below is the operational instruction set for
extracting gotcha candidates during `/mati-enrich`. It supersedes the
brief mem_set rules above for the extraction-specific steps; the
rules above still apply for everything else (manual capture, confirm
routing, etc).

### Stage 1 — Setup (before reading)

1. `mem_query mode="dir_gotchas" query="<dirname-of-file>" limit 5`
   → top 5 confirmed gotchas for that directory as POSITIVE
     EXEMPLARS. If the array is empty (cold start), continue with
     schema-only guidance. Do not use `mode="text"` here: the search
     index carries no `affected_files`, so a directory query returns
     file records instead of gotchas.
2. `mem_get("file:<path>")` — mints the consultation receipt, returns
   existing gotcha_keys, AND returns the `enrichment_depth_hint` field
   (D2-α: one of "fast", "standard", "deep"). Use it to pick the
   tier branch below. If absent (older daemon), default to "deep".
3. **Deep tier only**: call via Bash
   `mati ls tombstoned --dir <dirname-of-file> --recent 30d --json`
   to retrieve NEGATIVE EXEMPLARS — rules that were proposed for
   this directory and then tombstoned. Use them in Stage 2 to
   calibrate AGAINST proposing similar rules. If `count` is 0,
   skip the negative block. Record whether the block was used —
   controls the `with-neg-exemplars` tag in Stage 4.
4. **AST seeding**: call `mati extract-signals --file <path>` via Bash
   for deterministic, AST-aware signal extraction across all 12
   supported languages. Returns JSON
   `{ file, language, signal_count, signals: [{ file_line, tier,
      kind, evidence }, ...] }`. Treat each `file_line` as a SEED that
   Stage 2 must examine. Seeds never replace the file scan — read the
   file in Stage 2 at every tier, whatever `signal_count` says.
   For `panic`, `assert`, and `unwrap_like` signals, `evidence` is a
   bare identifier (`bail`, `expect`), not source text. A candidate
   drafted from that alone passes Stage 3 by construction — the quote
   is the token the extractor matched — and carries an invented
   reason. Take `evidence_quote` from the file, not from `evidence`.
   The extractor also misses signals inside macro bodies, which
   tree-sitter parses as token trees.

### Tier branches (D2)

| Tier      | Positive exemplars | Negative exemplars | Stage 2 file scan |
| --------- | ------------------ | ------------------ | ----------------- |
| fast      | no (schema only)   | no                 | yes               |
| standard  | yes                | no                 | yes               |
| deep      | yes                | yes                | yes               |

`fast` for trivial files (LoC < 100, isolated blast, no cluster).
`standard` is the default. `deep` adds negative exemplars for
hotspot / signal-rich files. Tier gates exemplars only — it never
gates the file scan.

Stage 3 runs at every tier. It is one CLI call per candidate, not a
reasoning pass, so tier does not gate it.

### Stage 2 — Enumeration (maximize recall)

Read the file. Output a JSON array of candidates, using the POSITIVE
EXEMPLARS as calibration for this project's specific bar.

Signal ranking (extract from highest first):
  HIGH:    WARNING / FIXME / HACK / SAFETY / IMPORTANT comments;
           panic!/assert!/expect("…") with non-trivial messages;
           comments explaining "why this looks weird" or "do not".
  MEDIUM:  Defensive guards (early returns, custom error paths);
           non-obvious literal arguments (e.g. with_versioning(true, 0));
           error handling that diverges from the rest of the file.
  LOW:     Raw API usage with no comment context.

Schema (strict JSON):
[
  { "candidate_id": "C1",
    "signal_tier": "high" | "medium" | "low",
    "file_line": "L42",
    "evidence_quote": "exact text from file at that line",
    "draft_rule": "imperative verb + specific target",
    "draft_reason": "what breaks and why",
    "draft_severity": "critical" | "high" | "normal" | "low" } ]

Write each candidate to be Specific (names a concrete API, value, or
pattern — never "be careful" or "review carefully"), Enforceable (a
hook could deny a real mistake on it), Non-obvious (not derivable
from type signatures alone), and Causal (the reason says WHAT breaks,
with "because"/"since"). These shape how you draft a candidate. They
are not a filter — do not drop a candidate for failing them here.

Goal: maximize recall. Weak candidates are OK — filtered next.

### Stage 3 — Evidence verification (deterministic, D-α)

One pass, no rounds. For each candidate, call `mati verify-evidence`
via Bash:
  mati verify-evidence \
    --file <path> \
    --line <candidate.file_line> \
    --quote "<candidate.evidence_quote>" \
    --pattern "<api/literal named in candidate.draft_rule>"
The CLI returns JSON. Parse it:
  { "verified": true, ... }  → keep, add "verified": true
  { "verified": false, ... } → DISCARD (hallucinated citation, or
                                rule generalizes beyond visible scope)
The CLI is the source of truth. Do not second-guess a verdict, and do
not re-run a candidate that already returned one — the check is
deterministic, so a repeat call returns the same answer.

Known limit: the check reads a ±5-line window. It proves the citation
is real, not that the rule follows from it. Keep `draft_rule` anchored
to what is visible at `file_line` — a rule whose claim spans more of
the file than that window passes unverified.

### Stage 4 — Refinement and write

For each verified candidate:

1. Tighten rule: imperative verb first; concrete names not pronouns;
   ≤ 80 chars where possible. If a candidate is still vague after
   tightening — no concrete API, value, or pattern to enforce on —
   drop it here.
2. Verify reason uses "because"/"since"/"as" — add if missing.
3. Assign severity (D-β). One judgment, one deterministic floor:

   3a. SEMANTIC pass — the severity. Judge rule + reason against:
       critical — data loss, corruption, security, unbounded growth
       high     — wrong result, silent failure, race, broken invariant
       normal   — performance, workflow blocker, non-obvious cleanup
       low      — informational, stylistic, minor inconvenience

   3b. KEYWORD FLOOR — deterministic, raises only, never lowers.
       Scan rule + reason case-insensitively for these stems:
         "data loss" / "corrupt" / "security" / "unbounded"  → critical
         "silent" / "race" / "wrong result" / "lost"         → high
       No stem present → no floor.

   3c. severity = the higher of 3a and the floor.
       Tag "severity-disputed" ONLY when the floor RAISED 3a — the
       text names a failure the judgment underrated. No stem matched,
       or 3a already at or above the floor → no tag. The tag flags a
       real conflict for the reviewer; it is not a routine annotation.

4. Call `mem_set`:
     key: `gotcha:<slug>`
     rule, reason, severity (from step 3)
     affected_files: [<path>]
     tags:  ["enriched", "depth:<tier>"]
          + ["signal-source:ast"] (if this candidate's file_line was
            an extract-signals seed) else ["signal-source:llm"]
          + ["with-neg-exemplars"] (if Stage 1 step 3 used negatives)
          + (["severity-disputed"] if step 3c flagged)
     confirmed: false

     `signal-source:*` is per candidate, not per file — it records
     which channel first surfaced the line. The `depth:<tier>` tag
     (D3) drives per-tier accuracy in `mati doctor`.

     This is attribution, not an experiment: Stage 2 sees the seeds
     while scanning, so `signal-source:llm` candidates are not an
     uncontaminated control.

### Notes

- Per-file token budget: ~8K tokens for Stage 2. Stage 3 is CLI
  calls, near-zero tokens. If you exceed the budget, truncate Stage 2
  candidates to top 10 by signal_tier.
- Rust-side quality gate still applies at write time. The pipeline
  maximizes what gets through; the gate enforces the floor.
- Do not add verification passes of your own, and do not spawn a
  subagent to double-check candidates. Stage 3 and the write-time
  quality gate are the only filters. Extra self-review costs tokens
  and suppresses recall without improving precision.
"#;

pub(crate) const SKILL_CONFIG_PATH: &str = ".codex/skills/mati/SKILL.md";

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
    (
        "pre-apply-patch.sh",
        crate::hooks::codex_pre_apply_patch::SCRIPT,
    ),
    ("post-bash.sh", crate::hooks::codex_post_bash::SCRIPT),
    ("stop.sh", crate::hooks::codex_stop::SCRIPT),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexInstallResult {
    Installed { scripts: usize },
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
    })
}

fn merge_hooks_json(path: &Path) -> Result<()> {
    let mati_hooks: Value = serde_json::from_str(HOOKS_JSON)?;
    let merged = if path.exists() {
        let existing_str = std::fs::read_to_string(path)?;
        let mut existing: Value = match serde_json::from_str(&existing_str) {
            Ok(v) => v,
            Err(e) => {
                let bak = path.with_extension("json.bak");
                match std::fs::write(&bak, &existing_str) {
                    Ok(()) => tracing::warn!(
                        "malformed hooks.json, backed up to {} and starting fresh: {e}",
                        bak.display()
                    ),
                    Err(bak_err) => tracing::warn!(
                        "malformed hooks.json, starting fresh (backup failed: {bak_err}): {e}"
                    ),
                }
                Value::Object(serde_json::Map::new())
            }
        };
        if let Value::Object(ref mut map) = existing {
            merge_hooks(map, &mati_hooks["hooks"]);
        } else {
            anyhow::bail!("hooks.json exists but is not a JSON object — cannot merge safely");
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
        match existing.parse::<DocumentMut>() {
            Ok(d) => d,
            Err(e) => {
                let bak = path.with_extension("toml.bak");
                match std::fs::write(&bak, &existing) {
                    Ok(()) => tracing::warn!(
                        "malformed config.toml, backed up to {} and starting fresh: {e}",
                        bak.display()
                    ),
                    Err(bak_err) => tracing::warn!(
                        "malformed config.toml, starting fresh (backup failed: {bak_err}): {e}"
                    ),
                }
                DocumentMut::new()
            }
        }
    } else {
        DocumentMut::new()
    };

    if doc.get("features").is_none() || !doc["features"].is_table() {
        doc["features"] = Item::Table(Table::new());
    }
    // Codex 2026-05+ renamed [features].codex_hooks → [features].hooks.
    // The runtime emits a deprecation warning on the old key. Public docs
    // still document codex_hooks (likely lagging the runtime); the warning
    // is the source of truth. If a future Codex re-deprecates `hooks`,
    // update this line and bump the scaffold installer version.
    doc["features"]["hooks"] = value(true);

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
    doc["mcp_servers"]["mati"]["command"] = value("mati");
    let mut args = Array::new();
    args.push("serve");
    doc["mcp_servers"]["mati"]["args"] = value(args);
    // Codex spawns MCP servers with CWD=/. The cwd field tells Codex to set
    // the working directory to the project root so `mati serve` derives the
    // correct store slug from current_dir().
    let canonical =
        std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
    doc["mcp_servers"]["mati"]["cwd"] = value(canonical.to_string_lossy().as_ref());

    // Codex spawns MCP servers with a clean environment (see the CWD=/ note
    // above), so a non-default MATI_HOME set at init time is NOT inherited by
    // `mati serve`. Capture it into the server's env so the MCP server opens the
    // same store the hooks do. Without this, serve falls back to ~/.mati while
    // hooks (which inherit the session env) use MATI_HOME, and every mem_get
    // reads an empty store — the deny it was meant to clear can never satisfy.
    // Only written when MATI_HOME is actually set, so a default install stays
    // on ~/.mati; an existing env table's other keys are preserved.
    if let Some(mati_home) = std::env::var_os("MATI_HOME") {
        if !doc["mcp_servers"]["mati"]
            .get("env")
            .is_some_and(|e| e.is_table())
        {
            doc["mcp_servers"]["mati"]["env"] = Item::Table(Table::new());
        }
        doc["mcp_servers"]["mati"]["env"]["MATI_HOME"] =
            value(mati_home.to_string_lossy().as_ref());
    }

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
        assert_eq!(doc["features"]["hooks"].as_bool(), Some(true));
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
        assert_eq!(doc["features"]["hooks"].as_bool(), Some(true));
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

        // Wrapper uses absolute path (hooks run in restricted shell).
        assert!(
            exec_target.starts_with('/'),
            "wrapper must use absolute path, got: {exec_target}"
        );

        // MCP config uses portable bare command.
        let config = std::fs::read_to_string(dir.path().join(".codex/config.toml")).unwrap();
        let doc = config.parse::<DocumentMut>().unwrap();
        assert_eq!(
            doc["mcp_servers"]["mati"]["command"].as_str().unwrap(),
            "mati",
            "MCP config must use bare 'mati' for portability"
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

        for (name, content_template) in CODEX_HOOK_SCRIPTS {
            let path = dir.path().join(".codex/hooks").join(name);
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("hook script {name} must exist"));
            // No-op hooks (e.g. user-prompt-submit) don't need HOOKS_DIR.
            if content_template.contains("HOOKS_DIR=") {
                assert!(
                    content.contains("HOOKS_DIR=") && content.contains("export PATH="),
                    "hook script {name} must prepend HOOKS_DIR to PATH"
                );
            }
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

    #[test]
    fn malformed_hooks_json_backed_up_and_replaced() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        std::fs::create_dir_all(&codex_dir).unwrap();

        let malformed = "{not valid json";
        std::fs::write(codex_dir.join("hooks.json"), malformed).unwrap();

        install_codex(dir.path(), false).unwrap();

        // Original malformed content should be backed up
        let bak_path = codex_dir.join("hooks.json.bak");
        assert!(bak_path.exists(), "backup file must exist");
        assert_eq!(std::fs::read_to_string(&bak_path).unwrap(), malformed);

        // Replaced hooks.json must be valid JSON with mati's hooks
        let hooks: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(codex_dir.join("hooks.json")).unwrap())
                .expect("hooks.json must be valid JSON after recovery");
        assert!(hooks["hooks"]["SessionStart"].is_array());
        assert!(hooks["hooks"]["PreToolUse"].is_array());
    }

    #[test]
    fn non_object_hooks_json_causes_error() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        std::fs::create_dir_all(&codex_dir).unwrap();

        std::fs::write(codex_dir.join("hooks.json"), "[1, 2, 3]").unwrap();

        let err = install_codex(dir.path(), false).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not a JSON object"),
            "error must mention 'not a JSON object', got: {msg}"
        );
    }

    #[test]
    fn malformed_config_toml_backed_up_and_replaced() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        std::fs::create_dir_all(&codex_dir).unwrap();

        let malformed = "[broken toml";
        std::fs::write(codex_dir.join("config.toml"), malformed).unwrap();

        install_codex(dir.path(), false).unwrap();

        // Original malformed content should be backed up
        let bak_path = codex_dir.join("config.toml.bak");
        assert!(bak_path.exists(), "backup file must exist");
        assert_eq!(std::fs::read_to_string(&bak_path).unwrap(), malformed);

        // Replaced config.toml must be valid TOML with mati's config
        let config = std::fs::read_to_string(codex_dir.join("config.toml")).unwrap();
        let doc = config
            .parse::<DocumentMut>()
            .expect("config.toml must be valid TOML after recovery");
        assert_eq!(
            doc["features"]["hooks"].as_bool(),
            Some(true),
            "features.hooks must be true"
        );
    }
}
