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
const END_MARKER: &str = "<!-- /mati:vector-c -->";

/// The Vector C injection text (from ARCHITECTURE.md §9).
///
/// Framing: "The PreToolUse hook enforces this" — environmental constraint,
/// not a behavioral suggestion.
const VECTOR_C_BODY: &str = "\
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

Before enriching each file, call mem_get(\"file:<path>\"). If the record has
source \"claude_enrich\" or \"developer_manual\" and confidence >= 0.60, skip it —
already enriched. Only re-enrich if the user explicitly passes the file path.

Per-file flow: mem_get → Read file → extract purpose + gotchas → mem_set file → mem_set each gotcha.
Single file: mem_set + `mati gotcha confirm <key>` for each gotcha.
Directory/batch: mem_set only (confirmed=false).

When enrichment is complete, print a summary:
  Enriched: X files (Y skipped — already enriched)
  Gotcha candidates extracted: Z
  Run `mati review` to confirm candidates and activate hook enforcement.
  Run `mati stats` to see updated coverage and onboarding score.

## /mati-enrich — extraction pipeline (v0.2)

The four-stage pipeline below is the operational instruction set for
extracting gotcha candidates. It SUPERSEDES the brief overview above
for the actual extraction steps; the intro stays as the high-level
intent. Apply all four stages per file.

### Stage 1 — Setup (before reading)

1. `mem_query mode=\"text\" query=\"<dirname-of-file>\" limit 5`
   → top 5 confirmed gotchas as POSITIVE EXEMPLARS. If zero exist
     (cold start), continue with schema-only guidance.
2. `mem_get(\"file:<path>\")` — mints the consultation receipt, returns
   existing gotcha_keys so duplicates aren't proposed.

### Stage 2 — Enumeration (maximize recall)

Read the file. Output a JSON array of candidates, using the POSITIVE
EXEMPLARS as calibration for this project's specific bar.

Signal ranking (extract from highest first):
  HIGH:    WARNING / FIXME / HACK / SAFETY / IMPORTANT comments;
           panic!/assert!/expect(\"…\") with non-trivial messages;
           comments explaining \"why this looks weird\" or \"do not\".
  MEDIUM:  Defensive guards (early returns, custom error paths);
           non-obvious literal arguments (e.g. with_versioning(true, 0));
           error handling that diverges from the rest of the file.
  LOW:     Raw API usage with no comment context.

Schema (strict JSON, one element per candidate):
[
  { \"candidate_id\": \"C1\",
    \"signal_tier\": \"high\" | \"medium\" | \"low\",
    \"file_line\": \"L42\",
    \"evidence_quote\": \"exact text from file at that line\",
    \"draft_rule\": \"imperative verb + specific target\",
    \"draft_reason\": \"what breaks and why\",
    \"draft_severity\": \"critical\" | \"high\" | \"normal\" | \"low\" } ]

Goal: maximize recall. Weak candidates are OK — filtered next.

### Stage 3 — Critique loop (bounded, 3 rounds)

ROUND 1 — Specificity. Discard candidates failing ANY of:
  Specific    — names a concrete API, value, or pattern
                (NOT \"be careful\", \"review carefully\", \"complex code\")
  Enforceable — could a hook deny a real mistake based on this rule?
  Non-obvious — would a reviewer learn something not derivable from
                type signatures alone?
  Causal      — does the reason state WHAT breaks with \"because\"/\"since\"?

ROUND 2 — Cross-reference verification (DETERMINISTIC, D-α).
For each Round 1 survivor, call `mati verify-evidence` via Bash:
  mati verify-evidence \\
    --file <path> \\
    --line <candidate.file_line> \\
    --quote \"<candidate.evidence_quote>\" \\
    --pattern \"<api/literal named in candidate.draft_rule>\"
The CLI returns JSON. Parse it:
  { \"verified\": true, ... }  → keep, add \"verified\": true
  { \"verified\": false, ... } → DISCARD (hallucinated citation, or
                                  rule generalizes beyond visible scope)
Do NOT trust self-critique here. The CLI is the source of truth.

ROUND 3 — Stability check. If Round 2 == Round 1, proceed. If
Round 2 discarded items, re-run Round 2 on the new survivor set
(cascading discards). Cap at 3 iterations total.

### Stage 4 — Refinement and write

For each verified candidate:

1. Tighten rule: imperative verb first; concrete names not pronouns;
   ≤ 80 chars where possible.
2. Verify reason uses \"because\"/\"since\"/\"as\" — add if missing.
3. Assign severity via HYBRID CLASSIFIER (D-β). Two passes:

   3a. KEYWORD pass (deterministic):
       contains \"panic\" / \"data loss\" / \"corruption\" / \"security\"
         → critical
       contains \"regress\" / \"wrong result\" / \"silent failure\" / \"race\" /
                \"silently\" / \"lose\" / \"lost\" / \"unbounded\" / \"indefinite\"
         → high
       contains \"performance\" / \"warning\" / \"deprecation\" / \"slow\" /
                \"lock\" / \"exclusive\" / \"contention\" / \"stale state\" /
                \"false positive\" / \"inconsistent\"
         → normal
       else
         → low

   3b. SEMANTIC pass (LLM judgment) using rubric:
       critical — data loss, corruption, security, unbounded growth
       high     — wrong result, silent failure, race, broken invariant
       normal   — performance, workflow blocker, non-obvious cleanup
       low      — informational, stylistic, minor inconvenience

   3c. If 3a and 3b agree → use that severity.
       If they disagree → use the HIGHER + add tag \"severity-disputed\".

4. Call `mem_set`:
     key: `gotcha:<slug>`
     rule, reason, severity (from step 3)
     affected_files: [<path>]
     tags: [\"enriched\"] + ([\"severity-disputed\"] if step 3c flagged)
     confirmed: false

### Notes

- Per-file token budget: ~8K tokens for Stages 2-3 combined. If you
  exceed, truncate Stage 2 candidates to top 10 by signal_tier.
- The Rust-side quality gate still applies at write time. The
  pipeline maximizes what gets through; the gate enforces the floor.
";

fn vector_c_stub() -> String {
    format!("{MARKER}\n{VECTOR_C_BODY}\n{END_MARKER}\n")
}

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

    let stub = vector_c_stub();

    if path.exists() {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;

        if let Some(start) = content.find(MARKER) {
            let updated = if let Some(end_rel) = content[start..].find(END_MARKER) {
                let end = start + end_rel + END_MARKER.len();
                let mut next = String::with_capacity(content.len() + stub.len());
                next.push_str(&content[..start]);
                next.push_str(&stub);
                if content[end..].starts_with('\n') {
                    next.push_str(&content[end + 1..]);
                } else {
                    next.push_str(&content[end..]);
                }
                next
            } else {
                let mut next = String::with_capacity(content.len() + stub.len());
                next.push_str(&content[..start]);
                next.push_str(&stub);
                next
            };

            if updated == content {
                return Ok(WriteResult::AlreadyPresent);
            }

            std::fs::write(&path, updated)
                .with_context(|| format!("failed to write {}", path.display()))?;
            return Ok(WriteResult::Updated);
        }

        // Append with a blank line separator.
        let mut appended = content;
        if !appended.ends_with('\n') {
            appended.push('\n');
        }
        appended.push('\n');
        appended.push_str(&stub);

        std::fs::write(&path, appended)
            .with_context(|| format!("failed to write {}", path.display()))?;

        Ok(WriteResult::Appended)
    } else {
        std::fs::write(&path, &stub)
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
    /// Existing scaffold block updated in place.
    Updated,
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
        assert!(content.contains(END_MARKER));
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

    #[test]
    fn updates_existing_legacy_stub_block() {
        let dir = TempDir::new().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        let legacy = format!("{MARKER}\n## old mati block\nstale instructions\n");
        std::fs::write(claude_dir.join("CLAUDE.md"), legacy).unwrap();

        let result = write_claude_md_stub(dir.path()).unwrap();
        assert_eq!(result, WriteResult::Updated);

        let content = std::fs::read_to_string(claude_dir.join("CLAUDE.md")).unwrap();
        assert!(content.contains("## mati context store"));
        assert!(content.contains(END_MARKER));
        assert!(!content.contains("## old mati block"));
    }
}
