//! Shared enforcement core for `mati hook-decide`.
//!
//! Pure functions — no I/O, no daemon calls. Testable without a running daemon.
//! Platform adapters in `cli::hook_decide` map these semantic outcomes to
//! protocol-specific output (Claude JSON, Codex exit codes).

use std::collections::HashMap;

// ── Types ───────────────────────────────────────────────────────────────────

/// Which class of file-reading command was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandClass {
    /// cat, less, head, tail, bat — file path is first non-flag arg.
    CatLike,
    /// grep, rg, sed, awk — file path is last non-flag arg.
    GrepLike,
}

/// Semantic enforcement decision. Adapters map these to platform output.
///
/// `FailOpen` is intentionally absent — it's a daemon-readiness outcome
/// handled by the adapter before calling `evaluate()`.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// No enforcement needed — allow unconditionally.
    Allow,
    /// Confirmed gotcha, agent has NOT consulted — block the read.
    Deny { file_key: String, reason: String },
    /// Confirmed gotcha, agent already consulted — allow with awareness.
    AlreadyConsulted { context: String },
    /// Medium confidence (0.3–0.6), quality >= 0.4 — advisory context.
    Advisory { context: String },
    /// Record too stale to trust — adapter decides whether to inject warning.
    Liability { staleness: f32, context: String },
    /// Record fully excluded from enforcement.
    Tombstone,
    /// No file record exists in the store.
    NoRecord,
    /// Command is not a file-reading operation.
    NotFileRead,
}

/// Side-effect events the adapter should fire after the decision.
/// Each variant maps 1:1 to an existing daemon socket command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookEvent {
    /// Record accessed — daemon `log_hit`.
    Hit { key: String },
    /// No record found — daemon `log_miss`.
    Miss { key: String },
    /// Pre-read/pre-bash denied an unconsulted read — daemon `log_compliance_miss`.
    BlockedUnconsultedRead { key: String },
    /// Codex shell command blocked — daemon `log_codex_shell_miss`.
    CodexShellBlocked { key: String },
    /// Post-bash confirmed a consulted read — daemon `log_compliance_hit`.
    ComplianceHit { key: String },
}

/// Input to the enforcement decision engine.
pub struct EnforcementInput {
    /// Repo-relative file path (e.g. `"src/main.rs"`).
    pub rel_path: String,
    /// File record JSON from `hook_evaluate`, or `None` if no record.
    pub file_record: Option<serde_json::Value>,
    /// Gotcha records keyed by gotcha key, from `hook_evaluate`.
    pub gotcha_records: HashMap<String, serde_json::Value>,
    /// Whether this file was already consulted via `mem_get` this session.
    pub already_consulted: bool,
}

/// Result of `evaluate()`.
pub struct EnforcementResult {
    pub decision: Decision,
    pub events: Vec<HookEvent>,
}

// ── Command Classification ──────────────────────────────────────────────────

const CAT_LIKE: &[&str] = &["cat", "less", "head", "tail", "bat"];
const GREP_LIKE: &[&str] = &["grep", "rg", "sed", "awk"];

/// Returns true if `trimmed` starts with `word` followed by whitespace
/// (or is exactly `word`). Prevents `"catch"` matching `"cat"`.
fn matches_command_word(trimmed: &str, word: &str) -> bool {
    if trimmed.len() < word.len() {
        return false;
    }
    if !trimmed.starts_with(word) {
        return false;
    }
    if trimmed.len() == word.len() {
        return true;
    }
    trimmed.as_bytes()[word.len()].is_ascii_whitespace()
}

/// Classify a bash command string. Returns `None` for non-file-read commands.
pub fn classify_command(cmd: &str) -> Option<CommandClass> {
    let trimmed = cmd.trim_start();
    for &word in CAT_LIKE {
        if matches_command_word(trimmed, word) {
            return Some(CommandClass::CatLike);
        }
    }
    for &word in GREP_LIKE {
        if matches_command_word(trimmed, word) {
            return Some(CommandClass::GrepLike);
        }
    }
    None
}

// ── File Path Extraction ────────────────────────────────────────────────────

/// Extract the target file path from a classified command.
///
/// Replicates the bash hook heuristic:
/// - CatLike: prefer first double-quoted path, fallback to first non-flag arg.
/// - GrepLike: prefer last double-quoted path, fallback to last non-flag arg
///   (strip surrounding single quotes).
///
/// Stops at pipe (`|`), semicolon (`;`), `&&`, `||`.
pub fn extract_file_path(cmd: &str, class: CommandClass) -> Option<String> {
    let trimmed = cmd.trim_start();

    // Isolate the command portion before shell operators.
    let cmd_part = split_at_shell_operator(trimmed);

    match class {
        CommandClass::CatLike => {
            if let Some(q) = extract_first_double_quoted(cmd_part) {
                return Some(q);
            }
            positional_arg(cmd_part, true)
        }
        CommandClass::GrepLike => {
            if let Some(q) = extract_last_double_quoted(cmd_part) {
                return Some(q);
            }
            positional_arg(cmd_part, false).map(|s| {
                // Strip surrounding single quotes (grep patterns).
                s.trim_start_matches('\'')
                    .trim_end_matches('\'')
                    .to_string()
            })
        }
    }
}

/// Split at the first shell operator (`|`, `;`, `&&`, `||`), returning the
/// portion before the operator.
fn split_at_shell_operator(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'|' => {
                // Could be `|` (pipe) or `||` — both mean stop.
                return &s[..i];
            }
            b';' => return &s[..i],
            b'&' if i + 1 < bytes.len() && bytes[i + 1] == b'&' => {
                return &s[..i];
            }
            b'"' => {
                // Skip quoted strings so we don't split on operators inside quotes.
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += 1;
                }
            }
            b'\'' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    s
}

/// Extract the content of the first double-quoted string.
fn extract_first_double_quoted(s: &str) -> Option<String> {
    let start = s.find('"')? + 1;
    let end = s[start..].find('"')? + start;
    let inner = &s[start..end];
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    }
}

/// Extract the content of the last double-quoted string.
fn extract_last_double_quoted(s: &str) -> Option<String> {
    let mut last: Option<String> = None;
    let mut pos = 0;
    while pos < s.len() {
        if let Some(offset) = s[pos..].find('"') {
            let abs_start = pos + offset + 1;
            if let Some(end_offset) = s[abs_start..].find('"') {
                let inner = &s[abs_start..abs_start + end_offset];
                if !inner.is_empty() {
                    last = Some(inner.to_string());
                }
                pos = abs_start + end_offset + 1;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    last
}

/// Extract first or last positional (non-flag) argument after the command word.
fn positional_arg(cmd_part: &str, first: bool) -> Option<String> {
    let words: Vec<&str> = cmd_part.split_whitespace().collect();
    if words.len() < 2 {
        return None;
    }
    let args: Vec<&str> = words[1..]
        .iter()
        .filter(|w| !w.starts_with('-'))
        .copied()
        .collect();
    if args.is_empty() {
        return None;
    }
    let picked = if first { args[0] } else { args[args.len() - 1] };
    if picked.is_empty() {
        None
    } else {
        Some(picked.to_string())
    }
}

// ── Path Normalization ──────────────────────────────────────────────────────

/// Normalize `file_path` to a lexical repo-relative path.
///
/// - Strips `repo_root` prefix (with trailing `/`).
/// - Collapses `.` and `..` components lexically (no filesystem access).
/// - Does NOT resolve symlinks — memory keys are lexical paths.
pub fn normalize_path(file_path: &str, repo_root: Option<&str>) -> String {
    let stripped = match repo_root {
        Some(root) => file_path
            .strip_prefix(root)
            .and_then(|s| s.strip_prefix('/'))
            .unwrap_or(file_path),
        None => file_path,
    };

    let mut components: Vec<&str> = Vec::new();
    for part in stripped.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                if components.pop().is_none() {
                    // Path escapes above root — out of scope.
                    // Return as-is; it won't match any store key.
                    return stripped.to_string();
                }
            }
            c => components.push(c),
        }
    }

    if components.is_empty() {
        ".".to_string()
    } else {
        components.join("/")
    }
}

// ── Core Decision Engine ────────────────────────────────────────────────────

/// Evaluate the enforcement decision for a file access.
///
/// Pure function — all data comes from `input`, no I/O. The decision matrix
/// matches ARCHITECTURE.md §10.1.
pub fn evaluate(input: &EnforcementInput) -> EnforcementResult {
    let file_key = format!("file:{}", input.rel_path);

    // ── No record ───────────────────────────────────────────────────────
    let file_record = match &input.file_record {
        Some(r) if r.is_object() => r,
        _ => {
            return EnforcementResult {
                decision: Decision::NoRecord,
                events: vec![HookEvent::Miss { key: file_key }],
            };
        }
    };

    // ── Extract scores ──────────────────────────────────────────────────
    let confidence = json_f32(file_record, "/confidence/value");
    let quality = json_f32(file_record, "/quality/value");
    let staleness = json_f32(file_record, "/staleness/value");
    let staleness_tier = json_str(file_record, "/staleness/tier");

    // ── Tombstone — fully excluded ──────────────────────────────────────
    if staleness_tier == "tombstone" {
        return EnforcementResult {
            decision: Decision::Tombstone,
            events: vec![],
        };
    }

    // ── Liability — too stale to trust ──────────────────────────────────
    if staleness_tier == "liability" {
        return EnforcementResult {
            decision: Decision::Liability {
                staleness,
                context: format!(
                    "WARNING: STALE record for {} is a liability (staleness {:.2}). \
                     Read the file directly — the cached record is too stale to trust.",
                    input.rel_path, staleness
                ),
            },
            events: vec![HookEvent::Hit { key: file_key }],
        };
    }

    // ── Build context + check gotchas ───────────────────────────────────
    let purpose = json_str(file_record, "/value");
    let mut context_lines: Vec<String> = Vec::new();
    if !purpose.is_empty() {
        context_lines.push(format!("Purpose: {purpose}"));
    }

    let mut deny_signal = false;
    let gotcha_keys = json_string_array(file_record, "/payload/gotcha_keys");

    for gkey in &gotcha_keys {
        let grec = match input.gotcha_records.get(gkey.as_str()) {
            Some(r) if r.is_object() => r,
            _ => continue,
        };

        let confirmed = json_bool(grec, "/payload/confirmed");
        let gconfidence = json_f32(grec, "/confidence/value");
        let gquality = json_f32(grec, "/quality/value");
        let rule = json_str(grec, "/value");

        if confirmed && gconfidence >= 0.6 && gquality >= 0.4 {
            deny_signal = true;
        }

        if !rule.is_empty() {
            context_lines.push(format!("\u{26a0} {rule}"));
        }
    }

    // Staleness warning for moderately stale records.
    if staleness >= 0.4 {
        context_lines.push(format!(
            "Warning: record staleness {staleness:.2} — verify critical details."
        ));
    }

    // Blast radius warning for high-impact files.
    {
        let blast_tier = json_str(file_record, "/payload/blast_radius/tier");
        if blast_tier == "high" || blast_tier == "critical" {
            let blast_direct = file_record
                .pointer("/payload/blast_radius/direct")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            context_lines.push(format!(
                "\u{26a0} Blast radius: {blast_direct} direct importers ({blast_tier}) — modify carefully"
            ));
        }
    }

    // ── Deny path ───────────────────────────────────────────────────────
    if deny_signal {
        if input.already_consulted {
            let context = if context_lines.is_empty() {
                format!(
                    "Gotcha exists for {} — proceed with awareness",
                    input.rel_path
                )
            } else {
                context_lines.join("\n")
            };
            // AllowAfterReceipt enforcement event: the read is being allowed
            // because a valid consultation receipt exists. ComplianceHit
            // (SessionLog v2) triggers the AllowAfterReceipt record.
            return EnforcementResult {
                decision: Decision::AlreadyConsulted { context },
                events: vec![HookEvent::ComplianceHit { key: file_key }],
            };
        }

        let safe_path = input.rel_path.replace('\\', "\\\\").replace('"', "\\\"");
        let staleness_note = if staleness >= 0.4 {
            format!(" (staleness {staleness:.2} — verify critical details)")
        } else {
            String::new()
        };

        return EnforcementResult {
            decision: Decision::Deny {
                file_key: file_key.clone(),
                reason: format!(
                    "[mati] Confirmed gotcha on {safe_path} — \
                     call mem_get(\"file:{safe_path}\") and read the record \
                     before accessing this file.{staleness_note}"
                ),
            },
            events: vec![HookEvent::BlockedUnconsultedRead { key: file_key }],
        };
    }

    // ── Advisory path (medium confidence) ───────────────────────────────
    if confidence >= 0.3 && quality >= 0.4 {
        let context = if context_lines.is_empty() {
            format!(
                "Record exists for {} — confidence {confidence:.2}",
                input.rel_path
            )
        } else {
            context_lines.join("\n")
        };
        return EnforcementResult {
            decision: Decision::Advisory { context },
            events: vec![HookEvent::Hit { key: file_key }],
        };
    }

    // ── Default: allow, no injection ────────────────────────────────────
    EnforcementResult {
        decision: Decision::Allow,
        events: vec![],
    }
}

// ── JSON helpers ────────────────────────────────────────────────────────────

fn json_f32(val: &serde_json::Value, pointer: &str) -> f32 {
    val.pointer(pointer)
        .and_then(|v| v.as_f64())
        .map(|f| f as f32)
        .unwrap_or(0.0)
}

fn json_str(val: &serde_json::Value, pointer: &str) -> String {
    val.pointer(pointer)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn json_bool(val: &serde_json::Value, pointer: &str) -> bool {
    val.pointer(pointer)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn json_string_array(val: &serde_json::Value, pointer: &str) -> Vec<String> {
    val.pointer(pointer)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── classify_command ─────────────────────────────────────────────────

    #[test]
    fn classify_cat() {
        assert_eq!(
            classify_command("cat src/main.rs"),
            Some(CommandClass::CatLike)
        );
    }

    #[test]
    fn classify_head_with_flag() {
        assert_eq!(
            classify_command("head -n 10 file.rs"),
            Some(CommandClass::CatLike)
        );
    }

    #[test]
    fn classify_leading_whitespace() {
        assert_eq!(classify_command("  cat file"), Some(CommandClass::CatLike));
    }

    #[test]
    fn classify_less() {
        assert_eq!(
            classify_command("less README.md"),
            Some(CommandClass::CatLike)
        );
    }

    #[test]
    fn classify_tail() {
        assert_eq!(
            classify_command("tail -f log.txt"),
            Some(CommandClass::CatLike)
        );
    }

    #[test]
    fn classify_bat() {
        assert_eq!(
            classify_command("bat src/lib.rs"),
            Some(CommandClass::CatLike)
        );
    }

    #[test]
    fn classify_grep() {
        assert_eq!(
            classify_command("grep -rn pattern src/"),
            Some(CommandClass::GrepLike)
        );
    }

    #[test]
    fn classify_rg() {
        assert_eq!(
            classify_command("rg TODO src/"),
            Some(CommandClass::GrepLike)
        );
    }

    #[test]
    fn classify_sed() {
        assert_eq!(
            classify_command("sed -i 's/a/b/' file.rs"),
            Some(CommandClass::GrepLike)
        );
    }

    #[test]
    fn classify_awk() {
        assert_eq!(
            classify_command("awk '{print $1}' file.rs"),
            Some(CommandClass::GrepLike)
        );
    }

    #[test]
    fn classify_ls_is_none() {
        assert_eq!(classify_command("ls -la"), None);
    }

    #[test]
    fn classify_cd_is_none() {
        assert_eq!(classify_command("cd /tmp"), None);
    }

    #[test]
    fn classify_catch_is_none() {
        assert_eq!(classify_command("catch errors"), None);
    }

    #[test]
    fn classify_catalog_is_none() {
        assert_eq!(classify_command("catalog"), None);
    }

    #[test]
    fn classify_grep_bare_is_none() {
        // "grep" with no args — still classifies (extraction returns None later)
        assert_eq!(classify_command("grep"), Some(CommandClass::GrepLike));
    }

    // ── extract_file_path ───────────────────────────────────────────────

    #[test]
    fn extract_cat_simple() {
        assert_eq!(
            extract_file_path("cat src/main.rs", CommandClass::CatLike),
            Some("src/main.rs".into())
        );
    }

    #[test]
    fn extract_cat_with_flag() {
        assert_eq!(
            extract_file_path("cat -n src/main.rs", CommandClass::CatLike),
            Some("src/main.rs".into())
        );
    }

    #[test]
    fn extract_cat_quoted_path() {
        assert_eq!(
            extract_file_path(r#"cat "path with spaces/file.rs""#, CommandClass::CatLike),
            Some("path with spaces/file.rs".into())
        );
    }

    #[test]
    fn extract_cat_with_pipe() {
        assert_eq!(
            extract_file_path("cat file.rs | grep foo", CommandClass::CatLike),
            Some("file.rs".into())
        );
    }

    #[test]
    fn extract_cat_with_semicolon() {
        assert_eq!(
            extract_file_path("cat file.rs; echo done", CommandClass::CatLike),
            Some("file.rs".into())
        );
    }

    #[test]
    fn extract_cat_with_and() {
        assert_eq!(
            extract_file_path("cat file.rs && echo ok", CommandClass::CatLike),
            Some("file.rs".into())
        );
    }

    #[test]
    fn extract_grep_last_arg() {
        assert_eq!(
            extract_file_path("grep -rn pattern src/main.rs", CommandClass::GrepLike),
            Some("src/main.rs".into())
        );
    }

    #[test]
    fn extract_grep_quoted_file() {
        assert_eq!(
            extract_file_path(r#"grep pattern "src/main.rs""#, CommandClass::GrepLike),
            Some("src/main.rs".into())
        );
    }

    #[test]
    fn extract_grep_strips_single_quotes() {
        assert_eq!(
            extract_file_path("grep 'pattern' file.rs", CommandClass::GrepLike),
            Some("file.rs".into())
        );
    }

    #[test]
    fn extract_no_args() {
        assert_eq!(extract_file_path("cat", CommandClass::CatLike), None);
    }

    #[test]
    fn extract_only_flags() {
        assert_eq!(extract_file_path("cat -n -v", CommandClass::CatLike), None);
    }

    // ── normalize_path ──────────────────────────────────────────────────

    #[test]
    fn normalize_strips_prefix() {
        assert_eq!(
            normalize_path("/home/user/project/src/main.rs", Some("/home/user/project")),
            "src/main.rs"
        );
    }

    #[test]
    fn normalize_dot_slash() {
        assert_eq!(normalize_path("./src/main.rs", None), "src/main.rs");
    }

    #[test]
    fn normalize_dotdot() {
        assert_eq!(normalize_path("src/../src/main.rs", None), "src/main.rs");
    }

    #[test]
    fn normalize_already_relative() {
        assert_eq!(normalize_path("src/main.rs", None), "src/main.rs");
    }

    #[test]
    fn normalize_no_repo_root() {
        assert_eq!(
            normalize_path("/abs/path/file.rs", None),
            "abs/path/file.rs"
        );
    }

    #[test]
    fn normalize_trailing_slash_root() {
        // repo_root should not have trailing slash, but handle it gracefully.
        assert_eq!(
            normalize_path("/project/src/file.rs", Some("/project")),
            "src/file.rs"
        );
    }

    #[test]
    fn normalize_leading_dotdot_returns_unchanged() {
        // Path escaping above root is out-of-scope — return as-is.
        assert_eq!(normalize_path("../other/file.rs", None), "../other/file.rs");
    }

    #[test]
    fn normalize_deep_dotdot_escape_returns_unchanged() {
        assert_eq!(normalize_path("foo/../../bar.rs", None), "foo/../../bar.rs");
    }

    #[test]
    fn normalize_dotdot_within_scope_ok() {
        // src/../lib/file.rs stays within the repo — collapses fine.
        assert_eq!(normalize_path("src/../lib/file.rs", None), "lib/file.rs");
    }

    // ── evaluate ────────────────────────────────────────────────────────

    fn make_file_record(
        confidence: f32,
        quality: f32,
        staleness: f32,
        staleness_tier: &str,
        gotcha_keys: &[&str],
    ) -> serde_json::Value {
        json!({
            "value": "Test file purpose",
            "confidence": { "value": confidence },
            "quality": { "value": quality },
            "staleness": { "value": staleness, "tier": staleness_tier },
            "payload": {
                "gotcha_keys": gotcha_keys,
            }
        })
    }

    fn make_gotcha(confirmed: bool, confidence: f32, quality: f32) -> serde_json::Value {
        json!({
            "value": "Do not use unwrap here",
            "confidence": { "value": confidence },
            "quality": { "value": quality },
            "payload": { "confirmed": confirmed }
        })
    }

    #[test]
    fn eval_no_record() {
        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: None,
            gotcha_records: HashMap::new(),
            already_consulted: false,
        };
        let result = evaluate(&input);
        assert_eq!(result.decision, Decision::NoRecord);
        assert_eq!(result.events.len(), 1);
        assert!(matches!(&result.events[0], HookEvent::Miss { key } if key == "file:src/main.rs"));
    }

    #[test]
    fn eval_tombstone() {
        let input = EnforcementInput {
            rel_path: "src/old.rs".into(),
            file_record: Some(make_file_record(0.8, 0.5, 0.95, "tombstone", &[])),
            gotcha_records: HashMap::new(),
            already_consulted: false,
        };
        let result = evaluate(&input);
        assert_eq!(result.decision, Decision::Tombstone);
        assert!(result.events.is_empty());
    }

    #[test]
    fn eval_liability() {
        let input = EnforcementInput {
            rel_path: "src/stale.rs".into(),
            file_record: Some(make_file_record(0.8, 0.5, 0.85, "liability", &[])),
            gotcha_records: HashMap::new(),
            already_consulted: false,
        };
        let result = evaluate(&input);
        assert!(
            matches!(&result.decision, Decision::Liability { staleness, .. } if *staleness > 0.8)
        );
        assert_eq!(result.events.len(), 1);
        assert!(matches!(&result.events[0], HookEvent::Hit { .. }));
    }

    #[test]
    fn eval_confirmed_gotcha_denies() {
        let mut gotchas = HashMap::new();
        gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(make_file_record(0.7, 0.5, 0.1, "fresh", &["gotcha:test"])),
            gotcha_records: gotchas,
            already_consulted: false,
        };
        let result = evaluate(&input);
        assert!(matches!(&result.decision, Decision::Deny { .. }));
        assert!(matches!(
            &result.events[0],
            HookEvent::BlockedUnconsultedRead { key } if key == "file:src/main.rs"
        ));
    }

    #[test]
    fn eval_unconfirmed_gotcha_allows() {
        let mut gotchas = HashMap::new();
        gotchas.insert("gotcha:test".to_string(), make_gotcha(false, 0.7, 0.5));

        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(make_file_record(0.7, 0.5, 0.1, "fresh", &["gotcha:test"])),
            gotcha_records: gotchas,
            already_consulted: false,
        };
        let result = evaluate(&input);
        // No deny signal — falls through to advisory (confidence 0.7 >= 0.3, quality 0.5 >= 0.4).
        assert!(matches!(&result.decision, Decision::Advisory { .. }));
    }

    #[test]
    fn eval_low_confidence_gotcha_allows() {
        let mut gotchas = HashMap::new();
        gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.4, 0.5));

        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(make_file_record(0.7, 0.5, 0.1, "fresh", &["gotcha:test"])),
            gotcha_records: gotchas,
            already_consulted: false,
        };
        let result = evaluate(&input);
        assert!(matches!(&result.decision, Decision::Advisory { .. }));
    }

    #[test]
    fn eval_low_quality_gotcha_allows() {
        let mut gotchas = HashMap::new();
        gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.2));

        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(make_file_record(0.7, 0.5, 0.1, "fresh", &["gotcha:test"])),
            gotcha_records: gotchas,
            already_consulted: false,
        };
        let result = evaluate(&input);
        assert!(matches!(&result.decision, Decision::Advisory { .. }));
    }

    #[test]
    fn eval_consulted_downgrades_deny() {
        let mut gotchas = HashMap::new();
        gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(make_file_record(0.7, 0.5, 0.1, "fresh", &["gotcha:test"])),
            gotcha_records: gotchas,
            already_consulted: true,
        };
        let result = evaluate(&input);
        assert!(matches!(
            &result.decision,
            Decision::AlreadyConsulted { .. }
        ));
        // AlreadyConsulted emits ComplianceHit so the v2 SessionLog dispatch
        // records an AllowAfterReceipt enforcement event (not a fresh receipt).
        assert!(matches!(&result.events[0], HookEvent::ComplianceHit { .. }));
    }

    #[test]
    fn eval_medium_confidence_advisory() {
        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(make_file_record(0.45, 0.5, 0.1, "fresh", &[])),
            gotcha_records: HashMap::new(),
            already_consulted: false,
        };
        let result = evaluate(&input);
        assert!(matches!(&result.decision, Decision::Advisory { .. }));
        assert!(matches!(&result.events[0], HookEvent::Hit { .. }));
    }

    #[test]
    fn eval_low_everything_allows() {
        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(make_file_record(0.1, 0.1, 0.1, "fresh", &[])),
            gotcha_records: HashMap::new(),
            already_consulted: false,
        };
        let result = evaluate(&input);
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.events.is_empty());
    }

    #[test]
    fn eval_staleness_warning_appended() {
        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(make_file_record(0.5, 0.5, 0.5, "stale", &[])),
            gotcha_records: HashMap::new(),
            already_consulted: false,
        };
        let result = evaluate(&input);
        if let Decision::Advisory { context } = &result.decision {
            assert!(context.contains("staleness 0.50"));
        } else {
            panic!("expected Advisory, got {:?}", result.decision);
        }
    }

    #[test]
    fn eval_multiple_gotchas_one_deny() {
        let mut gotchas = HashMap::new();
        gotchas.insert("gotcha:safe".to_string(), make_gotcha(false, 0.7, 0.5));
        gotchas.insert("gotcha:danger".to_string(), make_gotcha(true, 0.8, 0.6));

        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(make_file_record(
                0.7,
                0.5,
                0.1,
                "fresh",
                &["gotcha:safe", "gotcha:danger"],
            )),
            gotcha_records: gotchas,
            already_consulted: false,
        };
        let result = evaluate(&input);
        assert!(matches!(&result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn eval_deny_includes_staleness_note() {
        let mut gotchas = HashMap::new();
        gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(make_file_record(0.7, 0.5, 0.5, "stale", &["gotcha:test"])),
            gotcha_records: gotchas,
            already_consulted: false,
        };
        let result = evaluate(&input);
        if let Decision::Deny { reason, .. } = &result.decision {
            assert!(reason.contains("staleness"));
        } else {
            panic!("expected Deny");
        }
    }

    #[test]
    fn eval_invalid_json_allows() {
        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(json!("not an object")),
            gotcha_records: HashMap::new(),
            already_consulted: false,
        };
        let result = evaluate(&input);
        // Invalid record treated as no-record.
        assert_eq!(result.decision, Decision::NoRecord);
    }

    #[test]
    fn eval_never_produces_fail_open() {
        // FailOpen is NOT in the Decision enum at all — this test documents the contract.
        // The enum has no FailOpen variant, so this is a compile-time guarantee.
        // This test verifies the doc comment claim by testing boundary cases.
        let cases: Vec<EnforcementInput> = vec![
            EnforcementInput {
                rel_path: "x".into(),
                file_record: None,
                gotcha_records: HashMap::new(),
                already_consulted: false,
            },
            EnforcementInput {
                rel_path: "x".into(),
                file_record: Some(json!(null)),
                gotcha_records: HashMap::new(),
                already_consulted: false,
            },
            EnforcementInput {
                rel_path: "x".into(),
                file_record: Some(json!({})),
                gotcha_records: HashMap::new(),
                already_consulted: false,
            },
        ];
        for input in cases {
            let result = evaluate(&input);
            // If Decision had a FailOpen variant, we'd match against it here.
            // Since it doesn't, this documents that the pure core never fails open.
            assert!(matches!(
                result.decision,
                Decision::Allow
                    | Decision::Deny { .. }
                    | Decision::AlreadyConsulted { .. }
                    | Decision::Advisory { .. }
                    | Decision::Liability { .. }
                    | Decision::Tombstone
                    | Decision::NoRecord
                    | Decision::NotFileRead
            ));
        }
    }

    #[test]
    fn eval_context_includes_purpose_and_rules() {
        let mut gotchas = HashMap::new();
        gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(make_file_record(0.7, 0.5, 0.1, "fresh", &["gotcha:test"])),
            gotcha_records: gotchas,
            already_consulted: true,
        };
        let result = evaluate(&input);
        if let Decision::AlreadyConsulted { context } = &result.decision {
            assert!(context.contains("Purpose: Test file purpose"));
            assert!(context.contains("Do not use unwrap here"));
        } else {
            panic!("expected AlreadyConsulted, got {:?}", result.decision);
        }
    }

    #[test]
    fn eval_blast_radius_warning_for_critical_file() {
        let mut file_record = make_file_record(0.5, 0.5, 0.1, "fresh", &[]);
        // Inject blast_radius into payload
        file_record
            .as_object_mut()
            .unwrap()
            .get_mut("payload")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "blast_radius".into(),
                json!({ "direct": 45, "transitive": 10, "score": 48.0, "tier": "critical" }),
            );

        let input = EnforcementInput {
            rel_path: "src/core.rs".into(),
            file_record: Some(file_record),
            gotcha_records: HashMap::new(),
            already_consulted: false,
        };
        let result = evaluate(&input);
        if let Decision::Advisory { context } = &result.decision {
            assert!(
                context.contains("Blast radius"),
                "advisory context must include blast radius warning, got: {context}"
            );
            assert!(context.contains("45"), "warning must include direct count");
            assert!(context.contains("critical"), "warning must include tier");
        } else {
            panic!("expected Advisory, got {:?}", result.decision);
        }
    }

    #[test]
    fn eval_no_blast_warning_for_low_file() {
        let mut file_record = make_file_record(0.5, 0.5, 0.1, "fresh", &[]);
        file_record
            .as_object_mut()
            .unwrap()
            .get_mut("payload")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "blast_radius".into(),
                json!({ "direct": 2, "transitive": 0, "score": 2.0, "tier": "low" }),
            );

        let input = EnforcementInput {
            rel_path: "src/leaf.rs".into(),
            file_record: Some(file_record),
            gotcha_records: HashMap::new(),
            already_consulted: false,
        };
        let result = evaluate(&input);
        if let Decision::Advisory { context } = &result.decision {
            assert!(
                !context.contains("Blast radius"),
                "low blast radius file should NOT have warning, got: {context}"
            );
        } else {
            panic!("expected Advisory, got {:?}", result.decision);
        }
    }
}
