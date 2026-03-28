//! Write the CLAUDE.md Vector C stub (M-06-I).
//!
//! `mati init` writes `.claude/CLAUDE.md` with a static injection paragraph
//! that tells Claude the hook system enforces `mem_get` consultation. This is
//! Vector C — framing it as an environmental fact rather than a polite request
//! makes models treat it as a constraint, not a guideline.
//!
//! The stub is **appended** if a `.claude/CLAUDE.md` already exists, and
//! **created** if it does not. The marker comment prevents duplicate writes
//! on re-init.

use std::path::Path;

use anyhow::{Context, Result};

/// Marker comment used to detect whether the Vector C stub has already been
/// written. Checked before appending to prevent duplicates on re-init.
const MARKER: &str = "<!-- mati:vector-c -->";

/// The Vector C injection text (from ARCHITECTURE.md §9).
///
/// Framing: "The PreToolUse hook enforces this" — environmental constraint,
/// not a behavioral suggestion.
const VECTOR_C_STUB: &str = "\
<!-- mati:vector-c -->
## mati context store

This project uses mati. Before reading any file, call mem_get(\"file:<path>\").
High-confidence records (confidence >= 0.6, confirmed=true) replace file reads.
The PreToolUse hook enforces this at the environment level.
Run `mati status` to see current knowledge health.

## mati Knowledge Capture

When the developer says any of these:
- \"add that as a gotcha\" / \"that's a gotcha\" / \"remember this\"
- \"note that down\" / \"mati note: ...\" / \"we decided to...\"

Call mem_set immediately. Do not ask for confirmation.
Single gotcha from developer request: mem_set then `mati gotcha confirm <key>`.
Batch /mati-enrich directory: leave unconfirmed, remind to run `mati review`.

## /mati-enrich

Run /mati-enrich [path] to enrich a file or directory.
Single file: mem_set + `mati gotcha confirm <key>` for each gotcha.
Directory/batch: mem_set only, end with \"Run `mati review` to confirm N gotchas.\"
";

/// Write the Vector C stub to `.claude/CLAUDE.md`.
///
/// - If `.claude/` doesn't exist, the user isn't using Claude Code — skip.
/// - If the file doesn't exist but `.claude/` does, creates it with the stub.
/// - If the file exists but doesn't contain the marker, appends the stub.
/// - If the file already contains the marker, does nothing (idempotent).
pub fn write_claude_md_stub(project_root: &Path) -> Result<WriteResult> {
    let claude_dir = project_root.join(".claude");
    if !claude_dir.is_dir() {
        return Ok(WriteResult::NoClaude);
    }

    let path = claude_dir.join("CLAUDE.md");

    if path.exists() {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;

        if content.contains(MARKER) {
            return Ok(WriteResult::AlreadyPresent);
        }

        // Append with a blank line separator.
        let mut appended = content;
        if !appended.ends_with('\n') {
            appended.push('\n');
        }
        appended.push('\n');
        appended.push_str(VECTOR_C_STUB);

        std::fs::write(&path, appended)
            .with_context(|| format!("failed to write {}", path.display()))?;

        Ok(WriteResult::Appended)
    } else {
        std::fs::write(&path, VECTOR_C_STUB)
            .with_context(|| format!("failed to write {}", path.display()))?;

        Ok(WriteResult::Created)
    }
}

/// Outcome of the Vector C stub write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteResult {
    /// File created from scratch with the stub.
    Created,
    /// Stub appended to an existing file.
    Appended,
    /// Marker already present — no write needed.
    AlreadyPresent,
    /// `.claude/` directory doesn't exist — user isn't using Claude Code.
    NoClaude,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn creates_file_when_claude_dir_exists() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();

        let result = write_claude_md_stub(dir.path()).unwrap();
        assert_eq!(result, WriteResult::Created);

        let content = std::fs::read_to_string(dir.path().join(".claude/CLAUDE.md")).unwrap();
        assert!(content.contains(MARKER));
        assert!(content.contains("mem_get(\"file:<path>\")"));
        assert!(content.contains("PreToolUse hook enforces this"));
    }

    #[test]
    fn skips_when_no_claude_dir() {
        let dir = TempDir::new().unwrap();
        assert!(!dir.path().join(".claude").exists());

        let result = write_claude_md_stub(dir.path()).unwrap();
        assert_eq!(result, WriteResult::NoClaude);
        assert!(!dir.path().join(".claude").exists());
    }

    #[test]
    fn appends_to_existing_file_without_marker() {
        let dir = TempDir::new().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        let existing = "# My Project\n\nExisting instructions.\n";
        std::fs::write(claude_dir.join("CLAUDE.md"), existing).unwrap();

        let result = write_claude_md_stub(dir.path()).unwrap();
        assert_eq!(result, WriteResult::Appended);

        let content = std::fs::read_to_string(claude_dir.join("CLAUDE.md")).unwrap();
        assert!(content.starts_with("# My Project"));
        assert!(content.contains(MARKER));
        assert!(content.contains("Existing instructions."));
    }

    #[test]
    fn idempotent_on_rerun() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();

        let first = write_claude_md_stub(dir.path()).unwrap();
        assert_eq!(first, WriteResult::Created);

        let second = write_claude_md_stub(dir.path()).unwrap();
        assert_eq!(second, WriteResult::AlreadyPresent);

        // Content should not be duplicated.
        let content = std::fs::read_to_string(dir.path().join(".claude/CLAUDE.md")).unwrap();
        let marker_count = content.matches(MARKER).count();
        assert_eq!(marker_count, 1);
    }

    #[test]
    fn appended_stub_has_blank_line_separator() {
        let dir = TempDir::new().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        std::fs::write(claude_dir.join("CLAUDE.md"), "# Title\n").unwrap();

        write_claude_md_stub(dir.path()).unwrap();

        let content = std::fs::read_to_string(claude_dir.join("CLAUDE.md")).unwrap();
        // Should have a blank line between existing content and stub.
        assert!(content.contains("# Title\n\n<!-- mati:vector-c -->"));
    }
}
