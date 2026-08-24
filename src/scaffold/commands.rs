//! Write the `/mati-enrich` slash command file (M-06-K).
//!
//! This file is the source of truth for the four-stage enrichment pipeline.
//! `.claude/CLAUDE.md` (see [`super::claude_md`]) only names the command; it
//! does not carry the pipeline. The reason is cost: a command body loads only
//! when the command runs, while `.claude/CLAUDE.md` loads into every session.
//! Keeping the ~2.3K-token pipeline here instead of in the always-on stub
//! keeps it off every non-enrichment turn (design principle P2: pull on
//! demand). `disable-model-invocation: true` stops the body from auto-loading
//! speculatively — the command still runs when the developer types
//! `/mati-enrich`, and the CLAUDE.md stub is what tells Claude it exists.

use std::path::Path;

use anyhow::{Context, Result};

use super::write_if_changed;

const COMMAND_BODY: &str = "\
---
description: Enrich a file or directory into the mati knowledge store
argument-hint: [path]
disable-model-invocation: true
---

Enrich into the mati knowledge store. Target path(s): $ARGUMENTS
(no path given -> enrich the top hotspot gaps).

## /mati-enrich

Run /mati-enrich [path] to enrich a file or directory.

Before enriching each file, call mem_get(\"file:<path>\"). If the record has
source \"claude_enrich\" or \"developer_manual\" and confidence >= 0.60, skip it —
already enriched. Only re-enrich if the user explicitly passes the file path.

Per-file flow: mem_get → Read file → extract purpose + gotchas → mem_set file → mem_set each gotcha.
Single file: mem_set to write, then mem_set action=\"confirm\" for each gotcha — mati prompts the developer to approve each one.
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

1. `mem_query mode=\"dir_gotchas\" query=\"<dirname-of-file>\" limit 5`
   → top 5 confirmed gotchas for that directory as POSITIVE
     EXEMPLARS. If the array is empty (cold start), continue with
     schema-only guidance. Do not use `mode=\"text\"` here: the search
     index carries no `affected_files`, so a directory query returns
     file records instead of gotchas.
2. `mem_get(\"file:<path>\")` — mints the consultation receipt, returns
   existing gotcha_keys, AND returns the `enrichment_depth_hint` field
   (D2-α: one of \"fast\", \"standard\", \"deep\"). Use it to pick the
   tier branch below. If absent (older daemon), default to \"deep\".
3. **Deep tier only**: call via Bash
   `mati ls tombstoned --dir <dirname-of-file> --recent 30d --json`
   to retrieve NEGATIVE EXEMPLARS — rules that were proposed for
   this directory and then tombstoned. Use them in Stage 2 to
   calibrate AGAINST proposing similar rules. If `count` is 0,
   skip the negative block. Record whether the block was actually
   used — controls the `with-neg-exemplars` tag in Stage 4.
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

Write each candidate to be Specific (names a concrete API, value, or
pattern — never \"be careful\" or \"review carefully\"), Enforceable (a
hook could deny a real mistake on it), Non-obvious (not derivable
from type signatures alone), and Causal (the reason says WHAT breaks,
with \"because\"/\"since\"). These shape how you draft a candidate. They
are not a filter — do not drop a candidate for failing them here.

Goal: maximize recall. Weak candidates are OK — filtered next.

### Stage 3 — Evidence verification (deterministic, D-α)

One pass, no rounds. For each candidate, call `mati verify-evidence`
via Bash:
  mati verify-evidence \\
    --file <path> \\
    --line <candidate.file_line> \\
    --quote \"<candidate.evidence_quote>\" \\
    --pattern \"<api/literal named in candidate.draft_rule>\"
The CLI returns JSON. Parse it:
  { \"verified\": true, ... }  → keep, add \"verified\": true
  { \"verified\": false, ... } → DISCARD (hallucinated citation, or
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
2. Verify reason uses \"because\"/\"since\"/\"as\" — add if missing.
3. Assign severity (D-β). One judgment, one deterministic floor:

   3a. SEMANTIC pass — the severity. Judge rule + reason against:
       critical — data loss, corruption, security, unbounded growth
       high     — wrong result, silent failure, race, broken invariant
       normal   — performance, workflow blocker, non-obvious cleanup
       low      — informational, stylistic, minor inconvenience

   3b. KEYWORD FLOOR — deterministic, raises only, never lowers.
       Scan rule + reason case-insensitively for these stems:
         \"data loss\" / \"corrupt\" / \"security\" / \"unbounded\"  → critical
         \"silent\" / \"race\" / \"wrong result\" / \"lost\"         → high
       No stem present → no floor.

   3c. severity = the higher of 3a and the floor.
       Tag \"severity-disputed\" ONLY when the floor RAISED 3a — the
       text names a failure the judgment underrated. No stem matched,
       or 3a already at or above the floor → no tag. The tag flags a
       real conflict for the reviewer; it is not a routine annotation.

4. Call `mem_set`:
     key: `gotcha:<slug>`
     rule, reason, severity (from step 3)
     affected_files: [<path>]
     tags:  [\"enriched\", \"depth:<tier>\"]
          + [\"signal-source:ast\"] (if this candidate's file_line was
            an extract-signals seed) else [\"signal-source:llm\"]
          + [\"with-neg-exemplars\"] (if Stage 1 step 3 used negatives)
          + ([\"severity-disputed\"] if step 3c flagged)
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
- The Rust-side quality gate still applies at write time. The
  pipeline maximizes what gets through; the gate enforces the floor.
- Do not add verification passes of your own, and do not spawn a
  subagent to double-check candidates. Stage 3 and the write-time
  quality gate are the only filters. Extra self-review costs tokens
  and suppresses recall without improving precision.
";

/// Write `.claude/commands/mati-enrich.md`.
///
/// - If `.claude/` doesn't exist, the user isn't using Claude Code — skip.
/// - Otherwise creates `.claude/commands/` if needed and writes the command
///   file. Idempotent: re-running with the same content is a no-op write
///   (see `write_if_changed`).
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
        assert!(content.contains("disable-model-invocation: true"));
        assert!(content.contains("### Stage 1 — Setup"));
        assert!(content.contains("### Stage 4 — Refinement and write"));
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
