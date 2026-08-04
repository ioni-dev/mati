//! Shared enforcement core for `mati hook-decide`.
//!
//! Pure functions — no I/O, no daemon calls. Testable without a running daemon.
//! Platform adapters in `cli::hook_decide` map these semantic outcomes to
//! protocol-specific output (Claude JSON, Codex exit codes).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── Types ───────────────────────────────────────────────────────────────────

/// Which class of file-reading command was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandClass {
    /// cat, less, head, tail, bat — file path is first non-flag arg.
    CatLike,
    /// grep, rg, sed, awk — file path is last non-flag arg.
    GrepLike,
    /// psql, mysql, redis-cli, mongosh, sqlite3, and other governed DB clients.
    DbClientLike,
}

/// Normalized shape of an agent tool invocation for policy matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    /// Governable category, such as `db_client` or `path`.
    pub tool: String,
    /// Primary target path, when the invocation has one.
    pub target_path: Option<String>,
    /// Host extracted from a DB-client flag or environment assignment.
    pub host: Option<String>,
    /// Shell-normalized argument tokens.
    pub argv: Vec<String>,
    /// All normalized file targets in the invocation.
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowOutcome {
    Block,
    Steer,
}

/// Semantic enforcement decision. Adapters map these to platform output.
///
/// `FailOpen` is intentionally absent — it's a daemon-readiness outcome
/// handled by the adapter before calling `evaluate()`.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// No enforcement needed — allow unconditionally.
    Allow,
    /// A gate blocked the action. `origin` says which gate, so the message
    /// shape and the audit reason code are chosen from the decision rather than
    /// re-derived by sniffing `file_key`'s namespace at each call site.
    Deny {
        file_key: String,
        reason: String,
        origin: DenyOrigin,
    },
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

/// Which gate produced a `Decision::Deny`.
///
/// Each origin already maps 1:1 to a distinct `decision_reason_code` in the
/// enforcement log, so this is information the system requires downstream and
/// used to drop between the decision and the message. Matching on it
/// exhaustively means a new origin cannot silently inherit whatever branch its
/// key prefix happens to land in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyOrigin {
    /// Confirmed gotcha above the enforcement threshold. `file_key` is the
    /// record to consult.
    Gotcha,
    /// Inherited signed-floor consult mandate. `file_key` is the mandated file.
    ConsultMandate,
    /// Local policy. `file_key` is the POLICY key, which is not consultable —
    /// the consultable key lives in `reason`.
    Policy,
}

impl DenyOrigin {
    /// The event that records this deny in the enforcement log.
    ///
    /// Origin and event are chosen together at every deny site, and each event
    /// maps to a distinct `decision_reason_code` downstream. Deriving the event
    /// here means the agent-facing message and the audit chain cannot disagree
    /// about what denied, and a new origin cannot be added without choosing one.
    pub fn deny_event(self, key: String) -> HookEvent {
        match self {
            DenyOrigin::Gotcha => HookEvent::BlockedUnconsultedRead { key },
            DenyOrigin::ConsultMandate => HookEvent::FloorConsultBlocked { key },
            DenyOrigin::Policy => HookEvent::PolicyConsultBlocked { key },
        }
    }
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
    /// Claude edit gate: edit DEFERRED because a recent consultation exists —
    /// records `AllowAfterReceipt` with reason `edit_after_receipt` (Plane 2).
    EditConsulted { key: String },
    /// Claude edit gate: edit DENIED (no recent consult) — records `Deny` with
    /// reason `edit_blocked_unconsulted` (Plane 2).
    EditBlocked { key: String },
    /// Enterprise floor mandate DENIED an unconsulted access to a consult-required path —
    /// records `Deny` with reason `floor_consult_required`, distinct from a local-gotcha deny
    /// so the audit/report can tell an org mandate from a repo rule.
    FloorConsultBlocked { key: String },
    /// Local policy denied an unconsulted governed action.
    PolicyConsultBlocked { key: String },
    /// Local policy allowed a governed action after its receipt was present.
    PolicyConsulted { key: String },
    /// A steer policy injected guidance without changing the action decision.
    PolicySteered { key: String },
    /// A shadow policy would have blocked, but never changes the decision.
    PolicyShadowObserved {
        key: String,
        would: ShadowOutcome,
        action: Option<Action>,
    },
}

/// The I/O-free subset of a daemon policy verdict needed by the hook adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVerdict {
    pub key: String,
    pub rule: String,
    pub requires_key: String,
    pub block: bool,
    pub satisfied: bool,
    pub stage: crate::store::PolicyStage,
}

/// Apply local policy verdicts with escalate-only semantics.
///
/// A non-strict block degrades to steering; a satisfied block records the
/// receipt-backed allow. Existing decisions are never lowered by this layer.
pub fn evaluate_policy_verdicts(verdicts: &[PolicyVerdict], strict: bool) -> EnforcementResult {
    let mut context = Vec::new();
    let mut events = Vec::new();
    let mut denied = None;

    for verdict in verdicts {
        // The matcher already excludes Off; this defensive no-op prevents an
        // unexpected Off verdict from being treated as a steer policy.
        if matches!(verdict.stage, crate::store::PolicyStage::Off) {
            continue;
        }
        if matches!(verdict.stage, crate::store::PolicyStage::Shadow) {
            if !verdict.block {
                events.push(HookEvent::PolicyShadowObserved {
                    key: verdict.key.clone(),
                    would: ShadowOutcome::Steer,
                    action: None,
                });
            } else if !verdict.satisfied {
                events.push(HookEvent::PolicyShadowObserved {
                    key: verdict.key.clone(),
                    would: ShadowOutcome::Block,
                    action: None,
                });
            }
            continue;
        }
        if verdict.block && !verdict.satisfied && strict {
            denied.get_or_insert_with(|| Decision::Deny {
                file_key: verdict.key.clone(),
                reason: format!(
                    "mati: policy {} blocked this action. Consult first: mem_get(\"{}\")",
                    verdict.key, verdict.requires_key
                ),
                origin: DenyOrigin::Policy,
            });
        } else if verdict.block && verdict.satisfied {
            events.push(HookEvent::PolicyConsulted {
                key: verdict.key.clone(),
            });
        } else {
            context.push(verdict.rule.clone());
            events.push(HookEvent::PolicySteered {
                key: verdict.key.clone(),
            });
        }
    }

    if let Some(decision) = denied {
        let denied_key = match &decision {
            Decision::Deny { file_key, .. } => file_key.clone(),
            _ => unreachable!(),
        };
        // Keep shadow observations recorded in this same pass. A developer can
        // stage one policy to shadow while another enforces, and discarding the
        // observation because something else denied would make the rollout
        // measurement silently under-report every action the two both matched.
        //
        // Enforcement-claiming events are dropped instead: PolicyConsulted
        // would write an AllowAfterReceipt for an action that was in fact
        // denied, which would falsify the audit chain. PolicySteered is also
        // dropped because the action did not proceed with that context.
        let mut events: Vec<HookEvent> = events
            .into_iter()
            .filter(|event| matches!(event, HookEvent::PolicyShadowObserved { .. }))
            .collect();
        events.push(DenyOrigin::Policy.deny_event(denied_key));
        return EnforcementResult { decision, events };
    }
    if !context.is_empty() {
        return EnforcementResult {
            decision: Decision::Advisory {
                context: context.join("\n"),
            },
            events,
        };
    }
    EnforcementResult {
        decision: Decision::Allow,
        events,
    }
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
const GREP_LIKE: &[&str] = &["grep", "egrep", "fgrep", "rg", "sed", "awk"];
const DB_CLIENT_LIKE: &[&str] = &[
    "psql",
    "mysql",
    "mariadb",
    "redis-cli",
    "mongosh",
    "mongo",
    "sqlite3",
    "sqlcmd",
];

const ACTION_TOOL_DB_CLIENT: &str = "db_client";
const ACTION_TOOL_FILE_READ: &str = "file_read";
const ACTION_TOOL_PATH: &str = "path";

/// The action categories emitted by the normalizer and accepted by policy
/// matching. Keep this as the single source for author-time recognition too.
pub const KNOWN_ACTION_TOOLS: &[&str] = &[
    ACTION_TOOL_DB_CLIENT,
    ACTION_TOOL_FILE_READ,
    ACTION_TOOL_PATH,
];

/// Return whether a policy trigger names an action category emitted by the
/// normalizer. Unknown values remain valid authoring data, but cannot match.
pub fn is_known_action_tool(tool: &str) -> bool {
    KNOWN_ACTION_TOOLS.contains(&tool)
}

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

/// Command prefixes that wrap the real command without changing what it reads:
/// `sudo cat …`, `env LOG=1 cat …`, `nice cat …`. Stripped before classifying
/// so the read gate sees `cat`, not the wrapper. Wrapper *flags* (e.g.
/// `sudo -u root`) are intentionally NOT parsed here — guessing which take a
/// value risks mis-stripping a real argument, so that narrow case is left as a
/// tracked gap rather than handled unsafely.
const PREFIX_WORDS: &[&str] = &[
    "sudo", "doas", "env", "nice", "ionice", "nohup", "setsid", "stdbuf", "command", "time",
];

/// Is `tok` a `NAME=VALUE` shell environment assignment?
fn is_env_assignment(tok: &str) -> bool {
    match tok.find('=') {
        Some(eq) if eq > 0 => {
            let name = &tok[..eq];
            name.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        _ => false,
    }
}

/// Normalize a command for detection: strip leading env assignments and wrapper
/// prefixes (`sudo`/`env`/`nice`/…), then reduce the command word to its
/// basename (`/bin/cat` → `cat`). Returns the effective command, left-trimmed.
/// Pure; closes the prefix and absolute-path bypass classes for the read gate.
fn effective_command(cmd: &str) -> String {
    let mut rest = cmd.trim_start();
    loop {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let tok = &rest[..end];
        if tok.is_empty() {
            break;
        }
        if is_env_assignment(tok) || PREFIX_WORDS.contains(&tok) {
            rest = rest[end..].trim_start();
            continue;
        }
        break;
    }
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let (word, args) = rest.split_at(end);
    let base = word.rsplit('/').next().unwrap_or(word);
    let mut out = String::with_capacity(base.len() + args.len());
    out.push_str(base);
    out.push_str(args);
    out
}

/// Fuzz-only reexport of the private [`effective_command`]. `cargo fuzz`
/// sets `--cfg fuzzing` automatically, so this compiles only under
/// `cargo fuzz build`/`run` and never in a normal build.
#[cfg(fuzzing)]
pub fn effective_command_for_fuzzing(cmd: &str) -> String {
    effective_command(cmd)
}

/// Classify a bash command string. Returns `None` for non-file-read commands.
pub fn classify_command(cmd: &str) -> Option<CommandClass> {
    let eff = effective_command(cmd);
    let trimmed = eff.as_str();
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
    for &word in DB_CLIENT_LIKE {
        if matches_command_word(trimmed, word) {
            return Some(CommandClass::DbClientLike);
        }
    }
    None
}

/// Return whether a command performs an allowlisted database schema
/// introspection. This is deliberately lexical: it recognizes only bounded
/// SQL/meta-command forms and never infers intent from natural language.
pub fn is_schema_introspection(command: &str) -> bool {
    let normalized = effective_command(split_at_shell_operator(command)).to_ascii_lowercase();
    let tokens = shell_tokens(&normalized);

    if tokens
        .iter()
        .any(|token| token.contains("information_schema"))
    {
        return true;
    }

    for token in &tokens {
        let token = token.trim_matches(|c: char| c.is_ascii_punctuation() && c != '\\');
        if ["describe", "desc"]
            .iter()
            .any(|word| token == *word || token.starts_with(&format!("{word} ")))
        {
            return true;
        }
        if ["\\d", "\\dt", "\\d+", "\\l"].iter().any(|meta| {
            token
                .strip_prefix(meta)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
        }) {
            return true;
        }
    }

    tokens.iter().any(|token| {
        let token = token.trim_matches(|c: char| c.is_ascii_punctuation());
        ["show tables", "show columns", "show schemas"]
            .iter()
            .any(|phrase| token == *phrase || token.starts_with(&format!("{phrase} ")))
    }) || tokens.windows(2).any(|pair| {
        pair[0] == "show"
            && matches!(
                pair[1].trim_matches(|c: char| c.is_ascii_punctuation()),
                "tables" | "columns" | "schemas"
            )
    })
}

// ── File Path Extraction ────────────────────────────────────────────────────

/// Extract the PRIMARY target file path from a classified command — the first
/// file for cat-like, the last positional for grep-like. The single-path
/// companion to [`extract_file_paths`]; see it for the tokenizer + grammar.
pub fn extract_file_path(cmd: &str, class: CommandClass) -> Option<String> {
    let paths = extract_file_paths(cmd, class);
    match class {
        CommandClass::CatLike => paths.into_iter().next(),
        CommandClass::GrepLike => paths.into_iter().next_back(),
        CommandClass::DbClientLike => paths.into_iter().next(),
    }
}

/// Extract ALL target file paths from a classified command, in order. The
/// multi-file companion to [`extract_file_path`] — lets the read gate catch a
/// gotcha on a non-first file (`cat a.rs b.rs`, `grep pat f1 f2`).
///
/// Tokenizes the command shell-style (honoring quotes) and reads files by each
/// command's real grammar:
/// - CatLike (`cat/less/head/tail/bat FILE...`): every positional is a file.
/// - GrepLike (`grep/rg/sed/awk [flags] PATTERN [FILE...]`): the first
///   positional is the search PATTERN; the rest are files (none after the
///   pattern ⇒ stdin, so no files).
///
/// Using real tokens + position — instead of a "the file is whatever's quoted"
/// heuristic — is what lets `grep -r "secret" src/db.rs` resolve to `src/db.rs`
/// (the path) not `secret` (the quoted pattern), while still handling quoted
/// paths that contain spaces. Stops at pipe (`|`), semicolon (`;`), `&&`, `||`.
pub fn extract_file_paths(cmd: &str, class: CommandClass) -> Vec<String> {
    // Same normalization as `classify_command` so prefixes/abs-paths don't
    // throw off extraction (`sudo cat foo` must extract `foo`, not `cat`).
    let eff = effective_command(cmd);
    let cmd_part = split_at_shell_operator(&eff);
    let tokens = shell_tokens(cmd_part);

    match class {
        CommandClass::CatLike => positional_args(&tokens),
        CommandClass::GrepLike => {
            let positionals = positional_args(&tokens);
            if positionals.len() >= 2 {
                positionals[1..].to_vec()
            } else {
                Vec::new()
            }
        }
        CommandClass::DbClientLike => extract_db_file_paths(&tokens),
    }
}

/// Extract DB-client file arguments from `-f/--file` and their `=value` forms.
fn extract_db_file_paths(tokens: &[String]) -> Vec<String> {
    let mut files = Vec::new();
    let mut expects_file = false;
    for token in tokens.iter().skip(1) {
        if expects_file {
            if !token.is_empty() {
                files.push(token.clone());
            }
            expects_file = false;
            continue;
        }
        if token == "-f" || token == "--file" {
            expects_file = true;
        } else if let Some(path) = token.strip_prefix("--file=") {
            if !path.is_empty() {
                files.push(path.to_string());
            }
        } else if let Some(path) = token.strip_prefix("-f=") {
            if !path.is_empty() {
                files.push(path.to_string());
            }
        }
    }
    files
}

/// Extract a DB host from `-h/--host` or a leading environment assignment.
fn extract_db_host(command: &str) -> Option<String> {
    let tokens = shell_tokens(split_at_shell_operator(command));
    let mut expects_host = false;
    let mut env_host = None;
    for token in &tokens {
        if expects_host {
            return (!token.is_empty()).then(|| token.clone());
        }
        if token == "-h" || token == "--host" {
            expects_host = true;
        } else if let Some(host) = token.strip_prefix("--host=") {
            return (!host.is_empty()).then(|| host.to_string());
        } else if let Some(host) = token.strip_prefix("-h=") {
            return (!host.is_empty()).then(|| host.to_string());
        } else if let Some(value) = token.strip_prefix("PGHOST=") {
            if !value.is_empty() {
                env_host = Some(value.to_string());
            }
        } else if let Some(value) = token.strip_prefix("DATABASE_URL=") {
            env_host = database_url_host(value);
        }
    }
    env_host
}

/// Pull the authority host from a DATABASE_URL without introducing a URL
/// parser into the pure command-normalization core.
fn database_url_host(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let authority = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(value)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let host = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let host = host
        .rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
        .map(|(host, _)| host)
        .unwrap_or(host);
    (!host.is_empty()).then(|| host.to_string())
}

/// Normalize a command and/or path into the pure policy-matching action shape.
pub fn normalize_action(command: Option<&str>, target_path: Option<&str>) -> Action {
    let mut action = Action {
        tool: "unknown".to_string(),
        target_path: target_path.map(str::to_string),
        host: None,
        argv: vec![],
        files: target_path.into_iter().map(str::to_string).collect(),
    };

    let Some(command) = command else {
        if action.target_path.is_some() {
            action.tool = "path".to_string();
        }
        return action;
    };

    let effective = effective_command(split_at_shell_operator(command));
    action.argv = shell_tokens(&effective);
    if let Some(class) = classify_command(command) {
        match class {
            CommandClass::DbClientLike => {
                action.tool = ACTION_TOOL_DB_CLIENT.to_string();
                action.host = extract_db_host(command);
                action.files.extend(extract_file_paths(command, class));
            }
            CommandClass::CatLike | CommandClass::GrepLike => {
                action.tool = ACTION_TOOL_FILE_READ.to_string();
                action.files.extend(extract_file_paths(command, class));
            }
        }
    }
    if action.target_path.is_none() {
        action.target_path = action.files.first().cloned();
    }
    if action.tool == "unknown" && action.target_path.is_some() {
        action.tool = ACTION_TOOL_PATH.to_string();
    }
    action
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

/// Split a command into shell-style tokens, honoring single and double quotes
/// (the quotes are stripped from the returned tokens). Not a full shell parser
/// — enough for path extraction: a quoted path keeps its spaces as one token,
/// and a quoted pattern becomes just its inner text. Runs of whitespace are
/// collapsed; an unterminated quote consumes to end of input (best effort).
fn shell_tokens(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' => {
                in_token = true;
                let quote = c;
                for q in chars.by_ref() {
                    if q == quote {
                        break;
                    }
                    cur.push(q);
                }
            }
            c if c.is_whitespace() => {
                if in_token {
                    tokens.push(std::mem::take(&mut cur));
                    in_token = false;
                }
            }
            c => {
                in_token = true;
                cur.push(c);
            }
        }
    }
    if in_token {
        tokens.push(cur);
    }
    tokens
}

/// Positional (non-flag) arguments after the command word, in order. Skips a
/// purely-numeric token that follows a flag — it is the flag's value, not a
/// file (`tail -n 100 file`, `head -c 5 file`).
fn positional_args(tokens: &[String]) -> Vec<String> {
    let mut args = Vec::new();
    let mut prev_was_flag = false;
    for t in tokens.iter().skip(1) {
        if t.starts_with('-') {
            prev_was_flag = true;
            continue;
        }
        if prev_was_flag && !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
            prev_was_flag = false;
            continue;
        }
        prev_was_flag = false;
        if !t.is_empty() {
            args.push(t.clone());
        }
    }
    args
}

// ── apply_patch envelope parsing ────────────────────────────────────────────

/// Maximum number of files a single `apply_patch` is gated against. A patch
/// touching more than this is rare; the cap bounds per-file daemon round-trips
/// so the hook stays well inside its deadline. Files beyond the cap are NOT
/// gated (fail-open bias for the edit path) and the caller logs the truncation.
pub const MAX_APPLY_PATCH_FILES: usize = 50;

/// Extract the target file paths from a Codex `apply_patch` envelope.
///
/// Codex delivers the patch as a single string in `tool_input.command`:
///
/// ```text
/// *** Begin Patch
/// *** Update File: src/a.rs
/// @@ ...
///  context
/// -old
/// +new
/// *** Add File: src/b.rs
/// +contents
/// *** Delete File: src/c.rs
/// *** Move to: src/a_renamed.rs
/// *** End Patch
/// ```
///
/// Markers are matched only at column 0. Diff body lines are prefixed with a
/// space/`+`/`-`/`@@`, so a content line that happens to contain
/// `*** Update File:` (e.g. `+*** Update File: x`) does NOT collide with a real
/// envelope marker. Returns paths in first-seen order with duplicates removed;
/// the caller normalizes each. Add/Update/Delete and the rename source +
/// destination are all included — `evaluate()` allows any path with no
/// confirmed gotcha, so over-collecting is harmless.
///
/// Dedup uses a `HashSet` alongside the ordered `Vec` — a linear `Vec` scan
/// per line makes this O(m^2) in the number of distinct marker lines, which
/// runs uncapped: `MAX_APPLY_PATCH_FILES` is enforced by the caller only
/// after this function returns.
pub fn extract_apply_patch_files(patch: &str) -> Vec<String> {
    const MARKERS: &[&str] = &[
        "*** Update File: ",
        "*** Add File: ",
        "*** Delete File: ",
        "*** Move to: ",
    ];
    let mut files: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for line in patch.lines() {
        for marker in MARKERS {
            if let Some(rest) = line.strip_prefix(marker) {
                let path = rest.trim();
                if !path.is_empty() && seen.insert(path) {
                    files.push(path.to_string());
                }
                break;
            }
        }
    }
    files
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
/// matches ARCHITECTURE.md section 10.1.
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

    // ── Enforcement-off: the source file is gone ─────────────────────────
    // Keyed on the literal `FileDeleted` signal, not the tombstone tier.
    // `semantic_factor` is stubbed at 0.0 (ARCHITECTURE.md section 17), so
    // today only `FileDeleted` reaches tombstone — but once it's live, the
    // other four factors alone can cross 0.9 through ordinary drift. Gating
    // on the tier would silently reopen this bypass for a gotcha that never
    // stopped being true; gating on the signal cannot.
    if json_has_signal(file_record, "/staleness/signals", "file_deleted") {
        // Behaviourally identical to `NoRecord` from the agent's point of
        // view — allow unconditionally, nothing injected — so it shares
        // `NoRecord`'s event. `Hit` is wrong here: it mints a consultation
        // receipt (see `HookEvent::Hit` doc comment and its Codex-path
        // suppression in `cli::hook_decide::platform_events`), which would
        // falsely mark this file "consulted" for a read that delivered no
        // context, and could downgrade a real deny once staleness drops.
        return EnforcementResult {
            decision: Decision::Tombstone,
            events: vec![HookEvent::Miss { key: file_key }],
        };
    }

    // ── Build context + check gotchas ───────────────────────────────────
    // Staleness gates injection, not enforcement: a qualifying gotcha below
    // must deny regardless of `staleness_tier`. The tier only decides what
    // happens to the file record's own (possibly stale) purpose blurb once
    // the gotcha loop below finds nothing to enforce.
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

        // Only confirmed, injectable gotchas contribute to the injected
        // context (P4: unconfirmed gotchas never influence injection). Gating
        // the rule push here also bounds the payload — without it, every
        // attached gotcha, including unconfirmed Layer-0 stubs, was dumped into
        // the context (a single hotspot file with 1k+ stubs produced ~47 KB).
        if confirmed && gconfidence >= 0.6 && gquality >= 0.4 {
            deny_signal = true;
            if !rule.is_empty() {
                context_lines.push(format!("\u{26a0} {rule}"));
            }
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

        // The reason is a SEMANTIC string — JSON escaping is the output
        // layer's job (`escape_json_string` in the adapter). Pre-escaping
        // here double-escapes: a path with a quote would render as `\"` in
        // the message the agent sees.
        let safe_path = &input.rel_path;
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
                origin: DenyOrigin::Gotcha,
            },
            events: vec![DenyOrigin::Gotcha.deny_event(file_key)],
        };
    }

    // ── No qualifying gotcha: staleness now only gates injection ─────────
    if staleness_tier == "tombstone" {
        // `FileDeleted` already returned above. Reachable once
        // `semantic_factor` is live (v0.2) and ordinary drift alone crosses
        // 0.9. The purpose blurb is too degraded to trust at this tier, so
        // it stays fully excluded — same as the pre-reorder Tombstone path,
        // just no longer standing in front of gotcha enforcement.
        return EnforcementResult {
            decision: Decision::Tombstone,
            events: vec![HookEvent::Miss { key: file_key }],
        };
    }

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

/// True if `staleness.signals` carries the literal unit-variant signal
/// (e.g. `"file_deleted"` for `StalenessSignal::FileDeleted`), serialized
/// under serde's default external tagging.
fn json_has_signal(val: &serde_json::Value, pointer: &str, signal: &str) -> bool {
    val.pointer(pointer)
        .and_then(|v| v.as_array())
        .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some(signal)))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── extract_apply_patch_files ────────────────────────────────────────

    #[test]
    fn apply_patch_single_update() {
        let patch =
            "*** Begin Patch\n*** Update File: src/main.rs\n@@\n-old\n+new\n*** End Patch\n";
        assert_eq!(extract_apply_patch_files(patch), vec!["src/main.rs"]);
    }

    #[test]
    fn apply_patch_multi_file_add_update_delete() {
        let patch = "*** Begin Patch\n\
            *** Update File: src/a.rs\n@@\n+x\n\
            *** Add File: src/b.rs\n+y\n\
            *** Delete File: src/c.rs\n\
            *** End Patch\n";
        assert_eq!(
            extract_apply_patch_files(patch),
            vec!["src/a.rs", "src/b.rs", "src/c.rs"]
        );
    }

    #[test]
    fn apply_patch_rename_includes_source_and_destination() {
        let patch =
            "*** Begin Patch\n*** Update File: src/old.rs\n*** Move to: src/new.rs\n@@\n+x\n*** End Patch\n";
        assert_eq!(
            extract_apply_patch_files(patch),
            vec!["src/old.rs", "src/new.rs"]
        );
    }

    #[test]
    fn apply_patch_ignores_marker_inside_diff_body() {
        // A diff line that ADDS text resembling a marker must NOT be parsed as
        // an envelope marker: diff body lines are prefixed (+/-/space), so they
        // never begin at column 0 with "*** ".
        let patch = "*** Begin Patch\n\
            *** Update File: src/real.rs\n@@\n\
            +*** Update File: src/fake.rs\n\
            + *** Add File: src/also_fake.rs\n\
            *** End Patch\n";
        assert_eq!(extract_apply_patch_files(patch), vec!["src/real.rs"]);
    }

    #[test]
    fn apply_patch_dedups_repeated_path() {
        let patch =
            "*** Begin Patch\n*** Update File: src/a.rs\n*** Update File: src/a.rs\n*** End Patch\n";
        assert_eq!(extract_apply_patch_files(patch), vec!["src/a.rs"]);
    }

    #[test]
    fn apply_patch_empty_or_no_markers() {
        assert!(extract_apply_patch_files("").is_empty());
        assert!(extract_apply_patch_files("just some text\nno markers here").is_empty());
        assert!(extract_apply_patch_files("*** Begin Patch\n*** End Patch\n").is_empty());
    }

    #[test]
    fn apply_patch_trims_trailing_whitespace() {
        let patch = "*** Update File: src/spaced.rs   \n";
        assert_eq!(extract_apply_patch_files(patch), vec!["src/spaced.rs"]);
    }

    #[test]
    fn apply_patch_dedup_stays_linear_at_scale() {
        // 50_000 distinct markers, each repeated once (100_000 lines total).
        // At `opt-level = 1` (the [profile.test] setting) the old O(m^2)
        // `Vec::iter().any(...)` scan took ~1.2s for 50_000 distinct paths on
        // dev hardware — 500x the ~2ms this HashSet-backed version takes, and
        // growing quadratically past this point. 50_000 keeps that margin
        // comfortably under nextest's 30s local slow-timeout even if the O(m^2)
        // path is reintroduced, while still being large enough to prove it.
        const N: usize = 50_000;
        let mut patch = String::from("*** Begin Patch\n");
        for i in 0..N {
            patch.push_str(&format!("*** Add File: src/file_{i}.rs\n"));
            patch.push_str(&format!("*** Add File: src/file_{i}.rs\n")); // duplicate marker
        }
        patch.push_str("*** End Patch\n");

        let result = extract_apply_patch_files(&patch);

        assert_eq!(result.len(), N);
        for (i, path) in result.iter().enumerate() {
            assert_eq!(path, &format!("src/file_{i}.rs"));
        }
    }

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
        // Tombstone behaves like NoRecord for the agent (allow, no
        // injection), so it shares NoRecord's event — see `eval_no_record`.
        assert_eq!(result.events.len(), 1);
        assert!(matches!(&result.events[0], HookEvent::Miss { key } if key == "file:src/old.rs"));
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

    /// Staleness gates injection, not enforcement — a qualifying gotcha on
    /// a `tombstone`-tier file (no `FileDeleted` signal) must still deny.
    #[test]
    fn eval_tombstone_with_qualifying_gotcha_denies() {
        let mut gotchas = HashMap::new();
        gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

        let input = EnforcementInput {
            rel_path: "src/old.rs".into(),
            file_record: Some(make_file_record(
                0.8,
                0.5,
                0.95,
                "tombstone",
                &["gotcha:test"],
            )),
            gotcha_records: gotchas,
            already_consulted: false,
        };
        let result = evaluate(&input);
        assert!(
            matches!(&result.decision, Decision::Deny { origin, .. } if *origin == DenyOrigin::Gotcha),
            "got {:?}",
            result.decision
        );
    }

    /// Same rule, `liability` tier.
    #[test]
    fn eval_liability_with_qualifying_gotcha_denies() {
        let mut gotchas = HashMap::new();
        gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

        let input = EnforcementInput {
            rel_path: "src/stale.rs".into(),
            file_record: Some(make_file_record(
                0.8,
                0.5,
                0.85,
                "liability",
                &["gotcha:test"],
            )),
            gotcha_records: gotchas,
            already_consulted: false,
        };
        let result = evaluate(&input);
        assert!(
            matches!(&result.decision, Decision::Deny { origin, .. } if *origin == DenyOrigin::Gotcha),
            "got {:?}",
            result.decision
        );
    }

    /// `FileDeleted` is the one signal that still bypasses enforcement —
    /// there is no file left to protect. It wins over a maximally-valid
    /// confirmed gotcha, unlike the tier alone (see the two tests above).
    #[test]
    fn eval_file_deleted_bypasses_qualifying_gotcha() {
        let mut gotchas = HashMap::new();
        gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

        let mut file_record = make_file_record(0.8, 0.5, 0.95, "tombstone", &["gotcha:test"]);
        file_record["staleness"]["signals"] = json!(["file_deleted"]);

        let input = EnforcementInput {
            rel_path: "src/deleted.rs".into(),
            file_record: Some(file_record),
            gotcha_records: gotchas,
            already_consulted: false,
        };
        let result = evaluate(&input);
        assert_eq!(
            result.decision,
            Decision::Tombstone,
            "FileDeleted must bypass even a qualifying gotcha; got {:?}",
            result.decision
        );
        assert_eq!(result.events.len(), 1);
        assert!(
            matches!(&result.events[0], HookEvent::Miss { key } if key == "file:src/deleted.rs")
        );
    }

    /// The gate matches a hand-written string; this pins that the real enum
    /// serializes to that same string. Without it the helper and its tests
    /// could agree on a spelling serde never emits, and the only enforcement
    /// bypass would silently never fire on a genuinely deleted file.
    #[test]
    fn file_deleted_signal_serializes_to_the_string_the_gate_matches() {
        use crate::store::record::StalenessSignal;

        let signal = serde_json::to_value(StalenessSignal::FileDeleted).unwrap();
        assert_eq!(signal, json!("file_deleted"));

        let record = json!({ "staleness": { "signals": [signal] } });
        assert!(json_has_signal(
            &record,
            "/staleness/signals",
            "file_deleted"
        ));
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

    /// A gotcha whose code has drifted since it was confirmed must keep
    /// denying. Content drift (`health::drift`) is reported by `mati stale` and
    /// `mati doctor`; it is deliberately not visible to this function and does
    /// not touch `staleness`/`confidence`/`quality`/`confirmed` at all — the
    /// gotcha loop runs regardless of the file's staleness tier, so drift
    /// has no path to disable enforcement even indirectly.
    ///
    /// The mismatch below is the real shape: `confirmed_content` was stamped at
    /// confirm time, the file record's `content_hash` moved on since. Both
    /// records carry it; the decision is identical to `eval_confirmed_gotcha_denies`.
    #[test]
    fn eval_drifted_gotcha_still_denies() {
        let mut gotcha = make_gotcha(true, 0.7, 0.5);
        gotcha["payload"]["confirmed_content"] = json!({ "src/main.rs": "STAMPED_AT_CONFIRM" });

        let mut file_record = make_file_record(0.7, 0.5, 0.1, "fresh", &["gotcha:test"]);
        file_record["payload"]["content_hash"] = json!("CHANGED_SINCE");

        let mut gotchas = HashMap::new();
        gotchas.insert("gotcha:test".to_string(), gotcha);

        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(file_record),
            gotcha_records: gotchas,
            already_consulted: false,
        };
        let result = evaluate(&input);
        assert!(
            matches!(&result.decision, Decision::Deny { origin, .. } if *origin == DenyOrigin::Gotcha),
            "a drifted gotcha must still deny — drift reports, it never disables the gate; got {:?}",
            result.decision
        );
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
        // P4: the unconfirmed gotcha's rule must NOT leak into the injected
        // context — only confirmed gotchas contribute to injection.
        match &result.decision {
            Decision::Advisory { context } => assert!(
                !context.contains("Do not use unwrap here"),
                "unconfirmed gotcha rule leaked into injected context: {context:?}"
            ),
            other => panic!("expected Advisory, got {other:?}"),
        }
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

    // ── detection hardening: prefixes, abs-path, numeric flag values ──────

    #[test]
    fn classify_strips_sudo_prefix() {
        assert_eq!(
            classify_command("sudo cat src/secret.rs"),
            Some(CommandClass::CatLike)
        );
    }

    #[test]
    fn classify_strips_env_assignment_prefix() {
        assert_eq!(
            classify_command("env LOG=1 cat src/secret.rs"),
            Some(CommandClass::CatLike)
        );
        assert_eq!(
            classify_command("LOG=1 DEBUG=2 cat src/secret.rs"),
            Some(CommandClass::CatLike)
        );
    }

    #[test]
    fn classify_reduces_absolute_path_to_basename() {
        assert_eq!(
            classify_command("/bin/cat src/secret.rs"),
            Some(CommandClass::CatLike)
        );
    }

    #[test]
    fn classify_prefix_on_non_read_stays_none() {
        // Stripping a wrapper must not invent a read: `sudo rm` is still not one.
        assert_eq!(classify_command("sudo rm -rf build"), None);
        assert_eq!(classify_command("env X=1 ls"), None);
    }

    #[test]
    fn extract_through_sudo_prefix() {
        assert_eq!(
            extract_file_path("sudo cat src/secret.rs", CommandClass::CatLike),
            Some("src/secret.rs".to_string())
        );
    }

    #[test]
    fn extract_through_abs_path() {
        assert_eq!(
            extract_file_path("/bin/cat src/secret.rs", CommandClass::CatLike),
            Some("src/secret.rs".to_string())
        );
    }

    #[test]
    fn extract_skips_numeric_flag_value() {
        // The `100`/`5` are arguments to `-n`/`-c`, not the file.
        assert_eq!(
            extract_file_path("tail -n 100 src/secret.rs", CommandClass::CatLike),
            Some("src/secret.rs".to_string())
        );
        assert_eq!(
            extract_file_path("head -c 5 src/secret.rs", CommandClass::CatLike),
            Some("src/secret.rs".to_string())
        );
    }

    #[test]
    fn extract_keeps_attached_numeric_flag() {
        // `-5` is itself a flag (starts with '-'), already filtered; path follows.
        assert_eq!(
            extract_file_path("head -5 src/db.rs", CommandClass::CatLike),
            Some("src/db.rs".to_string())
        );
    }

    #[test]
    fn sudo_with_flags_is_a_known_gap() {
        // Documents the boundary of the prefix fix: wrapper-flag arity is
        // ambiguous (`-u` takes a value), so this is intentionally NOT handled.
        // Pinned so a future change that closes it also updates the eval
        // baseline (tests/fixtures/eval/baseline.json :: adv-sudo-uroot-cat).
        assert_eq!(classify_command("sudo -u root cat src/secret.rs"), None);
    }

    // ── quote-aware tokenizer: grep grammar (pattern vs path) ─────────────

    #[test]
    fn extract_grep_quoted_pattern_picks_the_path() {
        // The quoted token is the PATTERN; the file is the last positional.
        assert_eq!(
            extract_file_path("grep -r \"secret\" src/db.rs", CommandClass::GrepLike),
            Some("src/db.rs".to_string())
        );
        assert_eq!(
            extract_file_path("grep \"pat\" \"src/db.rs\"", CommandClass::GrepLike),
            Some("src/db.rs".to_string())
        );
    }

    #[test]
    fn extract_grep_without_file_reads_stdin() {
        // Only a pattern, no file -> no path to gate.
        assert_eq!(
            extract_file_path("grep \"secret\"", CommandClass::GrepLike),
            None
        );
    }

    #[test]
    fn extract_cat_quoted_path_with_spaces() {
        // The tokenizer keeps a quoted path's spaces as a single token.
        assert_eq!(
            extract_file_path("cat \"src/with space.rs\"", CommandClass::CatLike),
            Some("src/with space.rs".to_string())
        );
    }

    #[test]
    fn shell_tokens_honor_quotes() {
        assert_eq!(
            shell_tokens("grep -r \"a b\" file.rs"),
            vec!["grep", "-r", "a b", "file.rs"]
        );
        assert_eq!(
            shell_tokens("awk '{print $1}' src/db.rs"),
            vec!["awk", "{print $1}", "src/db.rs"]
        );
    }

    // ── multi-file extraction (`cat a.rs b.rs`, `grep pat f1 f2`) ─────────

    #[test]
    fn extract_file_paths_cat_returns_all_files() {
        assert_eq!(
            extract_file_paths("cat src/a.rs src/b.rs", CommandClass::CatLike),
            vec!["src/a.rs", "src/b.rs"]
        );
        assert_eq!(
            extract_file_paths("cat -n src/only.rs", CommandClass::CatLike),
            vec!["src/only.rs"]
        );
    }

    #[test]
    fn extract_file_paths_grep_drops_the_pattern() {
        // grep PATTERN FILE... — the pattern is not a file.
        assert_eq!(
            extract_file_paths("grep -i secret src/a.rs src/b.rs", CommandClass::GrepLike),
            vec!["src/a.rs", "src/b.rs"]
        );
        // Only a pattern, no file -> no paths.
        assert!(extract_file_paths("grep secret", CommandClass::GrepLike).is_empty());
    }

    #[test]
    fn extract_file_path_is_the_primary_of_paths() {
        // singular = first cat file / last grep file.
        assert_eq!(
            extract_file_path("cat a.rs b.rs", CommandClass::CatLike).as_deref(),
            Some("a.rs")
        );
        assert_eq!(
            extract_file_path("grep pat f1 f2", CommandClass::GrepLike).as_deref(),
            Some("f2")
        );
    }

    // ── policy Action normalization ────────────────────────────────────

    #[test]
    fn classify_db_client_with_prefix_and_absolute_basename() {
        assert_eq!(
            classify_command("sudo /usr/bin/psql -h db.prod.internal"),
            Some(CommandClass::DbClientLike)
        );
    }

    #[test]
    fn schema_introspection_allowlist_matches_supported_forms() {
        for command in [
            "psql -c \"SELECT * FROM information_schema.columns\"",
            "psql -c \"\\d orders\"",
            "psql -c \"\\dt\"",
            "psql -c \"\\d+ orders\"",
            "psql -c \"\\l\"",
            "mysql -e 'DESCRIBE orders'",
            "mysql -e 'DESC orders'",
            "mysql -e 'SHOW TABLES'",
            "mysql -e 'SHOW COLUMNS FROM orders'",
            "mysql -e 'SHOW SCHEMAS'",
        ] {
            assert!(
                is_schema_introspection(command),
                "expected match: {command}"
            );
        }
    }

    #[test]
    fn schema_introspection_does_not_match_mutating_sql() {
        assert!(!is_schema_introspection(
            "psql -c \"UPDATE orders SET status = 'x'\""
        ));
        assert!(!is_schema_introspection("psql -c \"SELECT * FROM orders\""));
    }

    #[test]
    fn schema_introspection_pins_bounded_parser_gaps() {
        // The classifier intentionally does not interpret shell expansion or
        // natural-language descriptions as schema inspection.
        assert!(!is_schema_introspection("psql -c \"echo describe orders\""));
        assert!(!is_schema_introspection("psql -c \"\\drop orders\""));
        // Like the rest of the classifier, only the first shell segment is
        // considered; pin that accepted residual behavior.
        assert!(is_schema_introspection("psql -c \"SHOW TABLES\" | cat"));
    }

    // ── wrapped-db-client deadlock signature ───────────────────────────
    //
    // A wrapper `PreToolUse` hook (e.g. `rtk`) can rewrite `psql …` to
    // `rtk psql …` before mati's post-bash hook sees it. `rtk` is not in
    // `PREFIX_WORDS`, so `classify_command`/`normalize_action` see an
    // unrecognized leading word and never reach `db_client`, even though
    // `is_schema_introspection` still matches every token in the string.
    // `run_post_bash_introspection` detects exactly this pair of outcomes
    // on the SAME command text — no cross-invocation correlation needed.

    #[test]
    fn wrapped_db_client_passes_introspection_but_fails_classification() {
        let command = r#"rtk psql -h prod -c "\d orders""#;
        assert!(
            is_schema_introspection(command),
            "the wrapped command is still recognizable introspection"
        );
        assert_ne!(
            normalize_action(Some(command), None).tool,
            "db_client",
            "the unrecognized 'rtk' prefix must block db_client classification \
             — this mismatch is the deadlock's detectable signature"
        );
    }

    #[test]
    fn sudo_wrapped_db_client_is_not_the_deadlock_signature() {
        // Control: sudo IS in PREFIX_WORDS, so this command must classify
        // normally and never trip the detector — it still mints as before.
        let command = r#"sudo psql -c "\d orders""#;
        assert!(is_schema_introspection(command));
        assert_eq!(normalize_action(Some(command), None).tool, "db_client");
    }

    #[test]
    fn non_introspection_command_is_not_the_deadlock_signature() {
        // A plain, non-introspection command never trips the detector,
        // classified or not — this is the separate silent-miss variant the
        // detector deliberately does not cover.
        assert!(!is_schema_introspection(
            "rtk psql -c \"SELECT * FROM orders\""
        ));
        assert!(!is_schema_introspection("rtk ls -la"));
    }

    #[test]
    fn normalize_db_action_extracts_host_and_file_flag() {
        let action = normalize_action(
            Some("sudo psql -h db.prod.internal -f migrations/orders.sql -c select"),
            None,
        );
        assert_eq!(action.tool, "db_client");
        assert_eq!(action.host.as_deref(), Some("db.prod.internal"));
        assert_eq!(action.files, vec!["migrations/orders.sql"]);
        assert_eq!(action.target_path.as_deref(), Some("migrations/orders.sql"));
        assert_eq!(action.argv.first().map(String::as_str), Some("psql"));
    }

    #[test]
    fn normalize_db_action_extracts_host_from_environment_assignment() {
        let action = normalize_action(Some("PGHOST=a psql -c \"select 1\""), None);
        assert_eq!(action.tool, "db_client");
        assert_eq!(action.host.as_deref(), Some("a"));
        assert!(action.files.is_empty());

        let explicit_action = normalize_action(Some("PGHOST=a psql -h b -c select"), None);
        assert_eq!(explicit_action.host.as_deref(), Some("b"));

        let url_action = normalize_action(
            Some("DATABASE_URL=postgres://db.prod.internal/orders psql -c select"),
            None,
        );
        assert_eq!(url_action.host.as_deref(), Some("db.prod.internal"));

        let port_action = normalize_action(
            Some("DATABASE_URL=postgres://db.prod.internal:5432/orders psql -c select"),
            None,
        );
        assert_eq!(port_action.host.as_deref(), Some("db.prod.internal"));

        let ipv6_action = normalize_action(
            Some("DATABASE_URL=postgres://[::1]/orders psql -c select"),
            None,
        );
        assert_eq!(ipv6_action.host.as_deref(), Some("[::1]"));
    }

    #[test]
    fn normalize_path_action_sets_target_path_without_command() {
        let action = normalize_action(None, Some("migrations/orders.sql"));
        assert_eq!(
            action,
            Action {
                tool: "path".into(),
                target_path: Some("migrations/orders.sql".into()),
                host: None,
                argv: vec![],
                files: vec!["migrations/orders.sql".into()],
            }
        );
        assert_eq!(normalize_action(Some("ls -la"), Some("x.sql")).tool, "path");
    }

    #[test]
    fn db_client_file_grammar_supports_attached_file_values() {
        assert_eq!(
            extract_file_paths(
                "psql --file=migrations/a.sql -f migrations/b.sql",
                CommandClass::DbClientLike
            ),
            vec!["migrations/a.sql", "migrations/b.sql"]
        );
    }

    fn policy(block: bool, satisfied: bool, rule: &str) -> PolicyVerdict {
        PolicyVerdict {
            key: "policy:prod-query".into(),
            rule: rule.into(),
            requires_key: "schema:orders".into(),
            block,
            satisfied,
            stage: crate::store::PolicyStage::Enforce,
        }
    }

    #[test]
    fn policy_block_unsatisfied_denies_in_strict_mode() {
        let result = evaluate_policy_verdicts(&[policy(true, false, "Consult first.")], true);
        assert!(matches!(result.decision, Decision::Deny { .. }));
        assert_eq!(
            result.events,
            vec![HookEvent::PolicyConsultBlocked {
                key: "policy:prod-query".into()
            }]
        );
    }

    #[test]
    fn shadow_would_block_is_observation_only() {
        let mut verdict = policy(true, false, "Consult first.");
        verdict.stage = crate::store::PolicyStage::Shadow;
        let shadow = evaluate_policy_verdicts(&[verdict], true);
        let none = evaluate_policy_verdicts(&[], true);
        assert_eq!(shadow.decision, none.decision);
        assert_eq!(
            shadow.events,
            vec![HookEvent::PolicyShadowObserved {
                key: "policy:prod-query".into(),
                would: ShadowOutcome::Block,
                action: None,
            }]
        );
    }

    /// A deny must not erase a shadow observation gathered in the same pass:
    /// staging one policy while another enforces is the normal rollout, and
    /// dropping the observation makes the measurement under-report silently.
    #[test]
    fn a_deny_preserves_shadow_observations_from_the_same_pass() {
        let mut shadowed = policy(true, false, "Observe only.");
        shadowed.key = "policy:shadowed".into();
        shadowed.stage = crate::store::PolicyStage::Shadow;
        let mut blocking = policy(true, false, "Consult first.");
        blocking.key = "policy:blocking".into();
        let result = evaluate_policy_verdicts(&[shadowed, blocking], true);

        assert!(matches!(result.decision, Decision::Deny { .. }));
        assert!(
            result.events.iter().any(|e| matches!(
                e,
                HookEvent::PolicyShadowObserved { key, .. } if key == "policy:shadowed"
            )),
            "shadow observation lost to the deny: {:?}",
            result.events
        );
        assert!(
            result
                .events
                .iter()
                .any(|e| matches!(e, HookEvent::PolicyConsultBlocked { .. })),
            "deny must still record the block"
        );
    }

    /// The other half: an enforcement-claiming event must NOT survive a deny,
    /// or a satisfied block would write an AllowAfterReceipt for an action that
    /// was denied.
    #[test]
    fn a_deny_drops_enforcement_events_from_the_same_pass() {
        let mut satisfied = policy(true, true, "Already consulted.");
        satisfied.key = "policy:satisfied".into();
        let mut blocking = policy(true, false, "Consult first.");
        blocking.key = "policy:blocking".into();
        let result = evaluate_policy_verdicts(&[satisfied, blocking], true);

        assert!(matches!(result.decision, Decision::Deny { .. }));
        assert!(
            !result
                .events
                .iter()
                .any(|e| matches!(e, HookEvent::PolicyConsulted { .. })),
            "a denied action must not also claim a receipt-backed allow: {:?}",
            result.events
        );
    }

    #[test]
    fn shadow_satisfied_block_is_allowed_without_observation() {
        let mut verdict = policy(true, true, "Consult first.");
        verdict.stage = crate::store::PolicyStage::Shadow;
        let result = evaluate_policy_verdicts(&[verdict], true);
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.events.is_empty());
    }

    #[test]
    fn policy_block_satisfied_allows_and_records_receipt() {
        let result = evaluate_policy_verdicts(&[policy(true, true, "Consult first.")], true);
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(
            result.events,
            vec![HookEvent::PolicyConsulted {
                key: "policy:prod-query".into()
            }]
        );
    }

    #[test]
    fn policy_steer_injects_context_without_denying() {
        let result = evaluate_policy_verdicts(&[policy(false, true, "Consult first.")], true);
        assert_eq!(
            result.decision,
            Decision::Advisory {
                context: "Consult first.".into()
            }
        );
        assert_eq!(
            result.events,
            vec![HookEvent::PolicySteered {
                key: "policy:prod-query".into()
            }]
        );
    }

    #[test]
    fn shadow_steer_records_observation_without_context() {
        let mut verdict = policy(false, true, "Steer this action.");
        verdict.stage = crate::store::PolicyStage::Shadow;
        let result = evaluate_policy_verdicts(&[verdict], true);
        assert_eq!(result.decision, Decision::Allow);
        assert!(matches!(
            result.events.as_slice(),
            [HookEvent::PolicyShadowObserved {
                would: ShadowOutcome::Steer,
                ..
            }]
        ));
    }

    #[test]
    fn policy_block_degrades_to_steer_in_advisory_mode() {
        let result = evaluate_policy_verdicts(&[policy(true, false, "Consult first.")], false);
        assert_eq!(
            result.decision,
            Decision::Advisory {
                context: "Consult first.".into()
            }
        );
    }

    #[test]
    fn no_policy_verdicts_allow() {
        let result = evaluate_policy_verdicts(&[], true);
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.events.is_empty());
    }

    #[test]
    fn known_action_tools_are_distinguished_from_unknown_tools() {
        assert!(is_known_action_tool("db_client"));
        assert!(is_known_action_tool("file_read"));
        assert!(is_known_action_tool("path"));
        assert!(!is_known_action_tool("dbclient"));
        assert!(!is_known_action_tool("db-client"));
    }

    #[test]
    fn multi_policy_deny_only_records_the_blocking_policy() {
        let verdicts = vec![
            PolicyVerdict {
                key: "policy:A".into(),
                rule: "A was consulted.".into(),
                requires_key: "schema:a".into(),
                block: true,
                satisfied: true,
                stage: crate::store::PolicyStage::Enforce,
            },
            PolicyVerdict {
                key: "policy:S".into(),
                rule: "Steer this action.".into(),
                requires_key: "schema:s".into(),
                block: false,
                satisfied: true,
                stage: crate::store::PolicyStage::Enforce,
            },
            PolicyVerdict {
                key: "policy:B".into(),
                rule: "B must be consulted.".into(),
                requires_key: "schema:b".into(),
                block: true,
                satisfied: false,
                stage: crate::store::PolicyStage::Enforce,
            },
        ];
        let result = evaluate_policy_verdicts(&verdicts, true);
        assert!(matches!(result.decision, Decision::Deny { .. }));
        // An AllowAfterReceipt alongside Deny would be a false "allowed" record.
        assert_eq!(
            result.events,
            vec![HookEvent::PolicyConsultBlocked {
                key: "policy:B".into()
            }]
        );
    }

    // ── Regression suite: enforcement never silently disables ─────────────

    /// Pins every edge of the one boundary that decides whether mati enforces.
    ///
    /// `evaluate` denies through exactly one path: the gotcha loop near the top
    /// of the function, guarded by
    /// `confirmed && gconfidence >= 0.6 && gquality >= 0.4`. The loop always
    /// runs first — a file's staleness tier no longer gates it, so `Liability`
    /// and `Tombstone` no longer shield an otherwise-qualifying gotcha (see
    /// `liability_tier_does_not_shield_a_qualifying_gotcha` and
    /// `tombstone_tier_without_file_deleted_does_not_shield_a_qualifying_gotcha`
    /// below). The one bypass that still runs before the loop is the literal
    /// `StalenessSignal::FileDeleted` signal: the source file is gone, so
    /// there is nothing left to enforce against (see
    /// `eval_file_deleted_bypasses_qualifying_gotcha`).
    ///
    /// That gives three independent kinds of change that convert a denying
    /// gotcha into an allow with no compile error, no panic, and nothing in the
    /// diff that reads as "turn enforcement off":
    ///
    /// 1. lowering a gotcha's confidence below 0.6;
    /// 2. lowering its quality below 0.4;
    /// 3. clearing `confirmed`.
    ///
    /// A file's staleness tier used to be a fourth: raising it into
    /// `liability` or `tombstone` returned before the gotcha loop ever ran.
    /// Three separate agents reached for that change in a single day
    /// (2026-07-24) and no test would have caught any of them — the reason
    /// the loop now runs first, ahead of the tier checks. `health::drift`
    /// documents the same trap from the other side, and stays out of the
    /// staleness composite precisely so it cannot trip it.
    ///
    /// Read a failure here as "the gate moved", not as "this test is stale".
    /// A deliberate threshold change must also update CLAUDE.md's hook decision
    /// matrix and ARCHITECTURE.md section 10.1 — the numbers below are copies of
    /// that matrix, not independent constants.
    mod gate_never_silently_disables {
        use super::*;

        /// The documented gotcha-deny thresholds (CLAUDE.md, "Hook decision
        /// matrix"). Duplicated here on purpose: a change to `evaluate` that
        /// does not also change these fails the suite.
        const DENY_MIN_CONFIDENCE: f32 = 0.6;
        const DENY_MIN_QUALITY: f32 = 0.4;

        /// The canonical valid confirmed gotcha: confirmed, exactly at both
        /// thresholds, attached to a fresh file record. This is the weakest
        /// input that must still deny — every stronger one is a superset.
        fn canonical_valid_confirmed_gotcha() -> EnforcementInput {
            input_with_gotcha(true, DENY_MIN_CONFIDENCE, DENY_MIN_QUALITY, "fresh")
        }

        fn input_with_gotcha(
            confirmed: bool,
            gconfidence: f32,
            gquality: f32,
            file_tier: &str,
        ) -> EnforcementInput {
            let mut gotchas = HashMap::new();
            gotchas.insert(
                "gotcha:test".to_string(),
                make_gotcha(confirmed, gconfidence, gquality),
            );
            // File-level scores are deliberately healthy so that only the
            // gotcha's own fields and the file's staleness tier can move the
            // decision.
            let staleness = match file_tier {
                "liability" => 0.85,
                "tombstone" => 0.95,
                _ => 0.1,
            };
            EnforcementInput {
                rel_path: "src/main.rs".into(),
                file_record: Some(make_file_record(
                    0.7,
                    0.5,
                    staleness,
                    file_tier,
                    &["gotcha:test"],
                )),
                gotcha_records: gotchas,
                already_consulted: false,
            }
        }

        /// The anchor. If this ever stops denying, mati has stopped enforcing.
        #[test]
        fn canonical_valid_confirmed_gotcha_denies() {
            let result = evaluate(&canonical_valid_confirmed_gotcha());
            match &result.decision {
                Decision::Deny { origin, reason, .. } => {
                    assert_eq!(
                        *origin,
                        DenyOrigin::Gotcha,
                        "a confirmed gotcha must deny with DenyOrigin::Gotcha"
                    );
                    assert!(
                        reason.contains("mem_get"),
                        "the deny reason must tell the agent how to clear the gate: {reason}"
                    );
                }
                other => panic!(
                    "ENFORCEMENT DISABLED: the canonical valid confirmed gotcha \
                     (confirmed=true, confidence={DENY_MIN_CONFIDENCE}, \
                     quality={DENY_MIN_QUALITY}, fresh file) produced {other:?} \
                     instead of Deny"
                ),
            }
            assert!(
                matches!(
                    &result.events[0],
                    HookEvent::BlockedUnconsultedRead { key } if key == "file:src/main.rs"
                ),
                "a deny must emit BlockedUnconsultedRead so the enforcement \
                 event log records it; got {:?}",
                result.events
            );
        }

        /// Confidence boundary: `>=`, not `>`. Exactly 0.6 denies.
        #[test]
        fn confidence_exactly_at_threshold_denies() {
            for quality in [DENY_MIN_QUALITY, 0.5, 1.0] {
                let input = input_with_gotcha(true, DENY_MIN_CONFIDENCE, quality, "fresh");
                assert!(
                    matches!(evaluate(&input).decision, Decision::Deny { .. }),
                    "confidence exactly {DENY_MIN_CONFIDENCE} (quality {quality}) must deny — \
                     the matrix is `confidence >= {DENY_MIN_CONFIDENCE}`, not `>`"
                );
            }
        }

        /// One ULP-scale step below the threshold must not deny. Pins the
        /// comparison direction: an accidental `>` -> `>=` flip on the other
        /// side of the boundary shows up here.
        #[test]
        fn confidence_just_below_threshold_does_not_deny() {
            for confidence in [DENY_MIN_CONFIDENCE - f32::EPSILON, 0.59, 0.0] {
                let input = input_with_gotcha(true, confidence, 0.5, "fresh");
                let decision = evaluate(&input).decision;
                assert!(
                    !matches!(decision, Decision::Deny { .. }),
                    "confidence {confidence} is below {DENY_MIN_CONFIDENCE} and must not deny; \
                     got {decision:?}"
                );
            }
        }

        /// Quality boundary: `>=`, not `>`. Exactly 0.4 denies.
        #[test]
        fn quality_exactly_at_threshold_denies() {
            for confidence in [DENY_MIN_CONFIDENCE, 0.8, 1.0] {
                let input = input_with_gotcha(true, confidence, DENY_MIN_QUALITY, "fresh");
                assert!(
                    matches!(evaluate(&input).decision, Decision::Deny { .. }),
                    "quality exactly {DENY_MIN_QUALITY} (confidence {confidence}) must deny — \
                     the matrix is `quality >= {DENY_MIN_QUALITY}`, not `>`"
                );
            }
        }

        #[test]
        fn quality_just_below_threshold_does_not_deny() {
            for quality in [DENY_MIN_QUALITY - f32::EPSILON, 0.39, 0.0] {
                let input = input_with_gotcha(true, 0.8, quality, "fresh");
                let decision = evaluate(&input).decision;
                assert!(
                    !matches!(decision, Decision::Deny { .. }),
                    "quality {quality} is below {DENY_MIN_QUALITY} and must not deny; \
                     got {decision:?}"
                );
            }
        }

        /// `confirmed` is the whole difference between a Layer 0 stub and a
        /// control. Same scores, opposite outcomes — clearing the flag anywhere
        /// upstream disables the gate for that record.
        #[test]
        fn confirmed_flag_alone_decides_deny_versus_allow() {
            let confirmed = evaluate(&input_with_gotcha(
                true,
                DENY_MIN_CONFIDENCE,
                DENY_MIN_QUALITY,
                "fresh",
            ))
            .decision;
            let unconfirmed = evaluate(&input_with_gotcha(
                false,
                DENY_MIN_CONFIDENCE,
                DENY_MIN_QUALITY,
                "fresh",
            ))
            .decision;

            assert!(
                matches!(confirmed, Decision::Deny { .. }),
                "confirmed=true at both thresholds must deny; got {confirmed:?}"
            );
            assert!(
                !matches!(unconfirmed, Decision::Deny { .. }),
                "confirmed=false must never deny — unconfirmed records are Layer 0 \
                 stubs (P4); got {unconfirmed:?}"
            );
        }

        /// Staleness gates injection, not enforcement — a maximally-valid
        /// confirmed gotcha on a `liability`-tier file must still deny. This
        /// used to be a documented trap (the tier returned before the gotcha
        /// loop ever ran); it is pinned here the other way now, so a
        /// regression back to the old short-circuit fails loudly instead of
        /// silently reopening it.
        #[test]
        fn liability_tier_does_not_shield_a_qualifying_gotcha() {
            let input = input_with_gotcha(true, 1.0, 1.0, "liability");
            let result = evaluate(&input);
            assert!(
                matches!(&result.decision, Decision::Deny { origin, .. } if *origin == DenyOrigin::Gotcha),
                "a qualifying gotcha on a `liability` file must still deny; \
                 got {:?}. If this now allows, enforcement coverage SHRANK — \
                 update CLAUDE.md and ARCHITECTURE.md section 10.1 rather than \
                 this assertion alone",
                result.decision
            );
            assert_eq!(
                result.events.len(),
                1,
                "expected exactly one event; got {:?}",
                result.events
            );
            assert!(matches!(
                &result.events[0],
                HookEvent::BlockedUnconsultedRead { key } if key == "file:src/main.rs"
            ));
        }

        /// Same rule, harder edge: tier `tombstone` *without* a `FileDeleted`
        /// signal (not reachable today — `semantic_factor` is stubbed at 0.0
        /// — but reachable once v0.2 unstubs it) must not shield a qualifying
        /// gotcha either. Only the literal `FileDeleted` signal disables
        /// enforcement; see `eval_file_deleted_bypasses_qualifying_gotcha`.
        #[test]
        fn tombstone_tier_without_file_deleted_does_not_shield_a_qualifying_gotcha() {
            let input = input_with_gotcha(true, 1.0, 1.0, "tombstone");
            let result = evaluate(&input);
            assert!(
                matches!(&result.decision, Decision::Deny { origin, .. } if *origin == DenyOrigin::Gotcha),
                "a qualifying gotcha on a `tombstone`-tier file with no \
                 `FileDeleted` signal must still deny; got {:?}",
                result.decision
            );
            assert_eq!(
                result.events.len(),
                1,
                "expected exactly one event; got {:?}",
                result.events
            );
            assert!(matches!(
                &result.events[0],
                HookEvent::BlockedUnconsultedRead { key } if key == "file:src/main.rs"
            ));
        }

        /// Raising staleness *without* crossing into `liability`/`tombstone`
        /// must not weaken the deny. Guards the near-miss of the trap above.
        #[test]
        fn stale_but_not_liability_still_denies() {
            let mut input = canonical_valid_confirmed_gotcha();
            input.file_record = Some(make_file_record(0.7, 0.5, 0.65, "stale", &["gotcha:test"]));
            let decision = evaluate(&input).decision;
            assert!(
                matches!(decision, Decision::Deny { .. }),
                "a `stale` file still enforces its confirmed gotchas; got {decision:?}"
            );
        }

        /// End-to-end with the real drift detector rather than a hand-built
        /// JSON shape: build records that `health::drift::detect_drift`
        /// actually reports as drifted, then feed those same records to the
        /// gate and require a Deny.
        ///
        /// `eval_drifted_gotcha_still_denies` above pins the same rule against
        /// a synthetic payload; this one proves the two modules agree on the
        /// record shape, so a change to `confirmed_content` / `content_hash`
        /// cannot make drift detection and enforcement drift apart.
        #[test]
        fn drift_detected_by_health_drift_still_denies() {
            use crate::health::drift::{current_content_hashes, detect_drift};
            use crate::store::record::{
                Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, Record,
                RecordLifecycle, RecordSource, RecordVersion, StalenessScore,
            };
            use std::collections::BTreeMap;

            fn base(key: &str) -> Record {
                Record {
                    key: key.to_string(),
                    value: "Do not use unwrap here".into(),
                    payload: None,
                    category: Category::Gotcha,
                    priority: Priority::High,
                    tags: vec![],
                    created_at: 1_000_000,
                    updated_at: 1_000_000,
                    ref_url: None,
                    staleness: StalenessScore::fresh(),
                    lifecycle: RecordLifecycle::Active,
                    version: RecordVersion {
                        device_id: uuid::Uuid::new_v4(),
                        logical_clock: 1,
                        wall_clock: 1_000_000,
                    },
                    quality: QualityScore::layer0_default(),
                    access_count: 0,
                    last_accessed: 0,
                    source: RecordSource::DeveloperManual,
                    confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
                    gap_analysis_score: 0.0,
                }
            }

            let mut stamp = BTreeMap::new();
            stamp.insert("src/main.rs".to_string(), "STAMPED_AT_CONFIRM".to_string());
            let mut gotcha_record = base("gotcha:test");
            gotcha_record.payload = serde_json::to_value(GotchaRecord {
                rule: "Do not use unwrap here".into(),
                reason: "because it panics on the hook path".into(),
                severity: Priority::High,
                affected_files: vec!["src/main.rs".into()],
                ref_url: None,
                discovered_session: 1_000_000,
                confirmed: true,
                confirmed_content: stamp,
            })
            .ok();
            gotcha_record.confidence.value = DENY_MIN_CONFIDENCE;
            gotcha_record.quality.value = DENY_MIN_QUALITY;

            let mut file_record = base("file:src/main.rs");
            file_record.category = Category::File;
            file_record.payload = Some(json!({
                "path": "src/main.rs",
                "content_hash": "CHANGED_SINCE",
                "gotcha_keys": ["gotcha:test"],
            }));

            // 1. The drift detector must actually see this as drifted,
            //    otherwise step 2 proves nothing.
            let hashes = current_content_hashes(std::slice::from_ref(&file_record));
            let drifted = detect_drift(std::slice::from_ref(&gotcha_record), &hashes);
            assert_eq!(
                drifted.len(),
                1,
                "fixture must be drifted for this test to mean anything; got {drifted:?}"
            );

            // 2. The same records, through the gate, must still deny.
            let mut gotchas = HashMap::new();
            gotchas.insert(
                "gotcha:test".to_string(),
                serde_json::to_value(&gotcha_record).expect("gotcha record serializes"),
            );
            let input = EnforcementInput {
                rel_path: "src/main.rs".into(),
                file_record: Some(
                    serde_json::to_value(&file_record).expect("file record serializes"),
                ),
                gotcha_records: gotchas,
                already_consulted: false,
            };
            let decision = evaluate(&input).decision;
            assert!(
                matches!(&decision, Decision::Deny { origin, .. } if *origin == DenyOrigin::Gotcha),
                "a gotcha `health::drift` reports as drifted must still deny — drift \
                 reports, it never disables the gate; got {decision:?}"
            );
        }
    }
}
