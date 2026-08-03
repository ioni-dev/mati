//! Write the `/mati-enrich` slash command file (M-06-K).
//!
//! `.claude/CLAUDE.md` (see [`super::claude_md`]) tells Claude to
//! "Run /mati-enrich [path]", but nothing ever wrote
//! `.claude/commands/mati-enrich.md` — so typing the command failed with
//! "no such command" even though the pipeline it should run is fully
//! documented. This scaffolds the missing command file so the slash
//! command actually exists.
//!
//! The body is a thin pointer into `.claude/CLAUDE.md` rather than a copy
//! of the four-stage pipeline: CLAUDE.md is already injected into every
//! turn, so duplicating the pipeline text here would just be a second
//! copy to keep in sync. `.claude/CLAUDE.md`'s own extraction-pipeline
//! section already says it supersedes the brief overview above it — this
//! command file is the trigger, not a second source of truth.

use std::path::Path;

use anyhow::{Context, Result};

use super::write_if_changed;

const COMMAND_BODY: &str = "\
---
description: Enrich a file or directory into the mati knowledge store
argument-hint: [path]
---

Run the mati enrichment pipeline over: $ARGUMENTS

If no path is given, enrich the whole project. Follow the instructions in
this project's `.claude/CLAUDE.md` under \"## /mati-enrich\" and
\"## /mati-enrich — extraction pipeline (v0.2)\" exactly — the four stages
(Setup, Enumeration, Evidence verification, Refinement and write), the
tier branches, and the per-file token budget all apply. Do not skip stages
or add extra verification passes beyond what those sections describe.
";

/// Write `.claude/commands/mati-enrich.md`.
///
/// - If `.claude/` doesn't exist, the user isn't using Claude Code — skip.
/// - Otherwise creates `.claude/commands/` if needed and writes the command
///   file. Idempotent: re-running with the same content is a no-op write
///   (see [`write_if_changed`]).
pub fn write_mati_enrich_command(project_root: &Path) -> Result<WriteResult> {
    let claude_dir = project_root.join(".claude");
    if !claude_dir.is_dir() {
        return Ok(WriteResult::NoClaude);
    }

    let commands_dir = claude_dir.join("commands");
    std::fs::create_dir_all(&commands_dir)
        .with_context(|| format!("failed to create {}", commands_dir.display()))?;

    let path = commands_dir.join("mati-enrich.md");
    let existed = path.exists();
    write_if_changed(&path, COMMAND_BODY)
        .with_context(|| format!("failed to write {}", path.display()))?;

    Ok(if existed {
        WriteResult::AlreadyPresent
    } else {
        WriteResult::Created
    })
}

/// Outcome of the `/mati-enrich` command file write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteResult {
    /// Command file created from scratch.
    Created,
    /// Command file already existed with the current content (or was updated in place).
    AlreadyPresent,
    /// `.claude/` directory doesn't exist — user isn't using Claude Code.
    NoClaude,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn creates_command_file_when_claude_dir_exists() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();

        let result = write_mati_enrich_command(dir.path()).unwrap();
        assert_eq!(result, WriteResult::Created);

        let content =
            std::fs::read_to_string(dir.path().join(".claude/commands/mati-enrich.md")).unwrap();
        assert!(content.contains("description:"));
        assert!(content.contains("argument-hint: [path]"));
        assert!(content.contains("$ARGUMENTS"));
        assert!(content.contains(".claude/CLAUDE.md"));
    }

    #[test]
    fn skips_when_no_claude_dir() {
        let dir = TempDir::new().unwrap();
        assert!(!dir.path().join(".claude").exists());

        let result = write_mati_enrich_command(dir.path()).unwrap();
        assert_eq!(result, WriteResult::NoClaude);
        assert!(!dir.path().join(".claude/commands").exists());
    }

    #[test]
    fn idempotent_on_rerun() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();

        let first = write_mati_enrich_command(dir.path()).unwrap();
        assert_eq!(first, WriteResult::Created);

        let second = write_mati_enrich_command(dir.path()).unwrap();
        assert_eq!(second, WriteResult::AlreadyPresent);

        let content =
            std::fs::read_to_string(dir.path().join(".claude/commands/mati-enrich.md")).unwrap();
        assert_eq!(content, COMMAND_BODY);
    }
}
