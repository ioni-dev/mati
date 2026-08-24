//! Write the mati capture skills (`.claude/skills/`).
//!
//! Knowledge capture ("remember this") and policy capture ("from now on…") are
//! utterance-triggered: they matter only when the developer says one of a small
//! set of phrases. A skill's description is always in context, but its body
//! loads only when the model invokes it — so the trigger phrases cost ~40 tokens
//! each always-on while the full guidance costs nothing until it fires. The
//! read-gate stays in `.claude/CLAUDE.md` (see [`super::claude_md`]) because it
//! is proactive on every file read and a lazy skill cannot fire ahead of it.
//!
//! Measured: policy capture drops to 0% authored when the guidance leaves
//! always-on context entirely, and returns to 100% as a lazy skill. Gotcha
//! capture is robust either way; the skill is the safe home for its softer
//! triggers ("note that down"). See ARCHITECTURE.md section 2 (P2).

use std::path::Path;

use anyhow::{Context, Result};

use super::write_if_changed;

const GOTCHA_SKILL: &str = "\
---
name: mati-capture-gotcha
description: Use when the developer wants a codebase gotcha remembered — \"add that as a gotcha\", \"that's a gotcha\", \"remember this\", \"note that down\", \"mati note: ...\", or \"we decided to...\". Records it in the mati knowledge store.
---

Call mem_set immediately. Do not ask for confirmation.

Write the record with `mem_set`: key `gotcha:<slug>`, a rule (imperative — what
Claude must do or avoid), a reason (what breaks and why), a severity, and
affected_files.

Single gotcha from a developer request: mem_set to write, then mem_set with
action=\"confirm\" — mati prompts the developer to approve before enforcement
activates.
Batch /mati-enrich directory: leave unconfirmed, remind to run `mati review`.
";

const POLICY_SKILL: &str = "\
---
name: mati-capture-policy
description: Use when the developer sets a standing rule to enforce — \"from now on\", \"always X before Y\", \"never run X without Y\", \"make it a rule\", \"make this a policy\", \"enforce this\", \"add a guardrail\". Captures it as a mati policy.
---

CAPTURE TRIGGERS. Author a policy when the developer either:
- asks explicitly: \"mati policy: ...\", \"make this a policy\", \"create a policy around this\", \"enforce this\", or \"add a guardrail for this\"; or
- states a standing directive implicitly: \"from now on\", \"before you ever\", \"always X before Y\", \"never run X without Y\", or \"make it a rule that\".
In both cases author it without asking for confirmation. Author policies at `off`
and suggest that the developer run `mati policy stage <slug> shadow` to review
what they would catch; promoting one to `enforce` is theirs to do.

NOT EVERY DIRECTIVE IS A POLICY. A policy can only match a governable action
category: `db_client`, `file_read`, or `path`. If the directive does not map to
one of those (for example \"always write better commit messages\"), do not author
a policy whose trigger can never match. Say plainly that it is not enforceable
as a policy and offer to capture it as a gotcha or dev note instead.

LIFECYCLE. To create, or refine a policy, use `mem_set` with a `policy:<slug>`
key. Author it at `off` and suggest that the developer run
`mati policy stage <slug> shadow` to begin review. When the developer asks to
stage, update, disable, or delete, run the matching
`mati policy stage|edit|enable|disable|delete <slug>` command via Bash. The
developer sees a permission prompt and approves it. Promoting a policy to
`enforce` is the developer's decision. Never claim a policy is live unless its
stage is `enforce`. Always dry-run a new or changed predicate with
`mati policy test --trigger`, against both a command that should match and one
that should not, before writing. Never claim a policy is active unless it was
actually enabled.
";

/// The capture skills written into `.claude/skills/<name>/SKILL.md`.
const SKILLS: &[(&str, &str)] = &[
    ("mati-capture-gotcha", GOTCHA_SKILL),
    ("mati-capture-policy", POLICY_SKILL),
];

/// Write the mati capture skills into `.claude/skills/`.
///
/// - If `.claude/` doesn't exist, the user isn't using Claude Code — skip.
/// - Otherwise creates each `.claude/skills/<name>/` and writes `SKILL.md`.
///   Idempotent: unchanged content is a no-op write (see `write_if_changed`).
pub fn write_capture_skills(project_root: &Path) -> Result<WriteResult> {
    let claude_dir = project_root.join(".claude");
    if !claude_dir.is_dir() {
        return Ok(WriteResult::NoClaude);
    }

    let skills_dir = claude_dir.join("skills");
    for (name, body) in SKILLS {
        let dir = skills_dir.join(name);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
        let path = dir.join("SKILL.md");
        write_if_changed(&path, body)
            .with_context(|| format!("failed to write {}", path.display()))?;
    }

    Ok(WriteResult::Written)
}

/// Outcome of the capture-skills write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteResult {
    /// Skills written (created or updated in place).
    Written,
    /// `.claude/` directory doesn't exist — user isn't using Claude Code.
    NoClaude,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn writes_both_skills_when_claude_dir_exists() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();

        let result = write_capture_skills(dir.path()).unwrap();
        assert_eq!(result, WriteResult::Written);

        let gotcha = std::fs::read_to_string(
            dir.path()
                .join(".claude/skills/mati-capture-gotcha/SKILL.md"),
        )
        .unwrap();
        assert!(gotcha.contains("name: mati-capture-gotcha"));
        assert!(gotcha.contains("remember this"));
        assert!(gotcha.contains("mem_set"));

        let policy = std::fs::read_to_string(
            dir.path()
                .join(".claude/skills/mati-capture-policy/SKILL.md"),
        )
        .unwrap();
        assert!(policy.contains("name: mati-capture-policy"));
        assert!(policy.contains("from now on"));
        assert!(policy.contains("NOT EVERY DIRECTIVE IS A POLICY"));
        assert!(policy.contains("policy:<slug>"));
    }

    #[test]
    fn skips_when_no_claude_dir() {
        let dir = TempDir::new().unwrap();
        let result = write_capture_skills(dir.path()).unwrap();
        assert_eq!(result, WriteResult::NoClaude);
        assert!(!dir.path().join(".claude/skills").exists());
    }

    #[test]
    fn idempotent_on_rerun() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();

        write_capture_skills(dir.path()).unwrap();
        let path = dir
            .path()
            .join(".claude/skills/mati-capture-policy/SKILL.md");
        let first = std::fs::read_to_string(&path).unwrap();
        write_capture_skills(dir.path()).unwrap();
        let second = std::fs::read_to_string(&path).unwrap();
        assert_eq!(first, second);
        assert_eq!(second, POLICY_SKILL);
    }
}
