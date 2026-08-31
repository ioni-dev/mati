//! Shared enforcement core for `mati hook-decide`.
//!
//! Pure functions — no I/O, no daemon calls. Testable without a running daemon.
//! Platform adapters in `cli::hook_decide` map these semantic outcomes to
//! protocol-specific output (Claude JSON, Codex exit codes).

mod classification;
mod config_change;
mod envelope;
mod file_changed;
mod instructions_loaded;
mod json_helpers;
mod path_extraction;
mod path_normalize;

#[cfg(test)]
mod tests;

#[cfg(fuzzing)]
pub use classification::effective_command_for_fuzzing;
pub use classification::{
    classify_command, is_known_action_tool, is_schema_introspection, restores_read_floor,
    KNOWN_ACTION_TOOLS,
};
pub use config_change::{local_violations, project_violations, ConfigViolation, ExpectedFloor};
pub use envelope::{extract_apply_patch_files, MAX_APPLY_PATCH_FILES};
pub use file_changed::{parse_file_changed, FileChangedPayload};
pub use instructions_loaded::{parse_instructions_loaded, InstructionsLoadedPayload};
pub use json_helpers::has_file_deleted_signal;
pub use path_extraction::{extract_file_path, extract_file_paths, normalize_action};
pub use path_normalize::normalize_path;

// Cross-submodule internals, not part of the public API: classification.rs
// and path_extraction.rs each call a private helper the other defines, and
// evaluate() below calls json_helpers.rs's payload readers directly.
use classification::{
    effective_command, ACTION_TOOL_DB_CLIENT, ACTION_TOOL_FILE_READ, ACTION_TOOL_PATH,
    GIT_VALUE_FLAGS,
};
#[cfg(test)]
use json_helpers::json_has_signal;
use json_helpers::{any_qualifying_gotcha, json_bool, json_f32, json_str, json_string_array};
#[cfg(test)]
use path_extraction::MAX_INTERPRETER_PATHS;
use path_extraction::{shell_segments, shell_tokens, split_at_shell_operator};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── Types ───────────────────────────────────────────────────────────────────

/// Which class of file-reading or path-mutating command was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandClass {
    /// cat, less, head, tail, bat — file path is first non-flag arg.
    CatLike,
    /// grep, rg, sed, awk — file path is last non-flag arg.
    GrepLike,
    /// psql, mysql, redis-cli, mongosh, sqlite3, and other governed DB clients.
    DbClientLike,
    /// rm, mv, rmdir, shred — every positional is a target path. Normalizes to
    /// `tool=path`, so a `target_path_glob` policy gates deletes and moves the
    /// same way it gates edits.
    PathMutating,
    /// `git show HEAD:f`, `git cat-file -p rev:f`, `git diff -- f`,
    /// `git log -p -- f`, `git blame f`, `git grep pat -- f` — content reaches
    /// the agent from the object store, so the working-tree path never appears
    /// as a bare argument. Normalizes to `file_read`.
    VcsRead,
    /// `cp f /tmp/x`, `install`, `ln`, `rsync`, `dd if=f` — every argument but
    /// the destination is a read. Normalizes to `file_read`.
    CopyLike,
    /// `python3 -c "open('f').read()"`, `perl -e`, `node -e`, and heredoc
    /// bodies fed to an interpreter. The path is a string literal inside
    /// source, not an argument. Normalizes to `file_read`; a write through the
    /// same route is gated as a read, since consultation is what the gate
    /// requires either way.
    InterpreterSource,
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
    /// Local policy `deny_if` matched the action's content. Unconditional — no
    /// consult unlocks it. `file_key` is the policy key.
    PolicyContentDenied,
    /// Local policy `require` was NOT satisfied — the action fell outside an
    /// allowlist or missed a required-content predicate. Unconditional, the
    /// polarity mirror of `PolicyContentDenied`. `file_key` is the policy key.
    PolicyRequirementUnmet,
    /// Tier 1 session lockdown: this actor was denied a file earlier in the
    /// session and still owes its receipt, so every command and read is denied
    /// until that receipt exists. `file_key` is the owed — and consultable —
    /// file key, not anything read from the command being denied.
    SessionLockdown,
    /// Tier 2 read floor: a command that would return a sealed file to a
    /// readable state, run while that file's receipt is outstanding.
    /// `file_key` is the sealed — and consultable — file key.
    SealFloor,
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
            DenyOrigin::PolicyContentDenied => HookEvent::PolicyContentBlocked { key },
            DenyOrigin::PolicyRequirementUnmet => HookEvent::PolicyRequirementBlocked { key },
            DenyOrigin::SessionLockdown => HookEvent::LockdownBlocked { key },
            DenyOrigin::SealFloor => HookEvent::SealFloorBlocked { key },
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
    /// An unclassified command mentioned a literal from an active policy.
    UnclassifiedPolicyLiteralBypass { key: String },
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
    /// Local policy `deny_if` denied a governed action on its content — daemon
    /// records a `Deny` with reason `policy_content_denied`.
    PolicyContentBlocked { key: String },
    /// Local policy `require` denied a governed action that fell outside its
    /// allowlist / missed a required-content predicate — daemon records a
    /// `Deny` with reason `policy_requirement_unmet`.
    PolicyRequirementBlocked { key: String },
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
    /// Tier 1 session lockdown denied a Bash command that named no governed
    /// path, because the session still owes a receipt on `key`.
    LockdownBlocked { key: String },
    /// Tier 2 denied a command that would have lifted the read floor on the
    /// sealed file `key`, whose receipt is still outstanding.
    SealFloorBlocked { key: String },
    /// The `FileDeleted` bypass fired on a caller-confirmed deletion
    /// (`file_exists: Some(false)`) that also suppressed a deny a qualifying
    /// confirmed gotcha would otherwise have produced. Unlike the plain
    /// `Miss` the bypass ordinarily emits, this reaches the hash-chained
    /// enforcement log as `BypassDetected` — enforcement was suppressed, not
    /// merely a cache miss.
    TombstoneBypassedDeny { key: String },
    /// An access no file gate ever saw was allowed. `key` names the surface it
    /// came in on, not a file — there is no path, which is the point.
    PathlessAllow { key: String },
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
    /// Outcome of the policy's `deny_if` predicate. Independent of
    /// `satisfied`/`requires`, and never lowered by the schema-introspection
    /// exemption (that gate lives upstream and is not applied to this field).
    pub content: crate::store::ContentOutcome,
    /// Outcome of the policy's `require` predicate — the allowlist mirror of
    /// `content`. `Deny`/`Warn` means the requirement was MISSED. Evaluated
    /// after `content`, so a `deny_if` match takes precedence.
    pub require_content: crate::store::ContentOutcome,
}

/// Apply local policy verdicts with escalate-only semantics.
///
/// A non-strict block degrades to steering; a satisfied block records the
/// receipt-backed allow. Existing decisions are never lowered by this layer.
pub fn evaluate_policy_verdicts(verdicts: &[PolicyVerdict], strict: bool) -> EnforcementResult {
    /// The first enforcing block of this pass, carried as the deny's own
    /// fields instead of a `Decision`. A `Decision` here can hold a variant
    /// the deny path cannot honor, and the only recovery from that in a hook
    /// is a panic — which is neither a deny nor a recorded allow.
    struct PolicyDeny {
        key: String,
        reason: String,
        origin: DenyOrigin,
    }

    let mut context = Vec::new();
    let mut events = Vec::new();
    let mut denied: Option<PolicyDeny> = None;

    for verdict in verdicts {
        // The matcher already excludes Off; this defensive no-op prevents an
        // unexpected Off verdict from being treated as a steer policy.
        if matches!(verdict.stage, crate::store::PolicyStage::Off) {
            continue;
        }
        if matches!(verdict.stage, crate::store::PolicyStage::Shadow) {
            // `deny_if` (content) is observed first; if it did not fire, the
            // `require` mirror is; only when neither predicate is present does
            // the consult gate decide the shadow outcome.
            let would = match verdict.content {
                crate::store::ContentOutcome::Deny => Some(ShadowOutcome::Block),
                crate::store::ContentOutcome::Warn => Some(ShadowOutcome::Steer),
                crate::store::ContentOutcome::Inert | crate::store::ContentOutcome::None => {
                    match verdict.require_content {
                        crate::store::ContentOutcome::Deny => Some(ShadowOutcome::Block),
                        crate::store::ContentOutcome::Warn => Some(ShadowOutcome::Steer),
                        // A require predicate that matched observes nothing.
                        crate::store::ContentOutcome::Inert => None,
                        crate::store::ContentOutcome::None => {
                            // A deny_if that was present but inert observes
                            // nothing; only a policy with neither content
                            // predicate falls to the consult gate.
                            if !matches!(verdict.content, crate::store::ContentOutcome::None) {
                                None
                            } else if !verdict.block {
                                Some(ShadowOutcome::Steer)
                            } else if !verdict.satisfied {
                                Some(ShadowOutcome::Block)
                            } else {
                                None
                            }
                        }
                    }
                }
            };
            if let Some(would) = would {
                events.push(HookEvent::PolicyShadowObserved {
                    key: verdict.key.clone(),
                    would,
                    action: None,
                });
            }
            continue;
        }
        // The content axis governs first — independent of `satisfied`/`requires`,
        // never lowered by the schema-introspection exemption (upstream). A
        // content policy speaks ONLY through its predicate: on a non-match
        // (`Inert`) it neither denies nor steers. `deny_if` (content) is checked
        // before `require` (require_content); a `deny_if` match takes precedence.
        let deny_if_present = !matches!(verdict.content, crate::store::ContentOutcome::None);
        match verdict.content {
            crate::store::ContentOutcome::Deny if strict => {
                denied.get_or_insert_with(|| PolicyDeny {
                    key: verdict.key.clone(),
                    reason: format!(
                        "mati: policy {} denied this action: its content matches a deny rule.",
                        verdict.key
                    ),
                    origin: DenyOrigin::PolicyContentDenied,
                });
                continue;
            }
            // Steer warns; a Deny under the global kill-switch (`!strict`)
            // degrades to the same warning.
            crate::store::ContentOutcome::Deny | crate::store::ContentOutcome::Warn => {
                context.push(verdict.rule.clone());
                events.push(HookEvent::PolicySteered {
                    key: verdict.key.clone(),
                });
                continue;
            }
            // deny_if absent or inert — fall through to the require mirror.
            crate::store::ContentOutcome::Inert | crate::store::ContentOutcome::None => {}
        }
        // `require` denies UNLESS its predicate matched (allowlist mirror): a
        // `Deny`/`Warn` here means the requirement was MISSED.
        match verdict.require_content {
            crate::store::ContentOutcome::Deny if strict => {
                denied.get_or_insert_with(|| PolicyDeny {
                    key: verdict.key.clone(),
                    reason: format!(
                        "mati: policy {} denied this action: it does not satisfy a required rule.",
                        verdict.key
                    ),
                    origin: DenyOrigin::PolicyRequirementUnmet,
                });
                continue;
            }
            crate::store::ContentOutcome::Deny | crate::store::ContentOutcome::Warn => {
                context.push(verdict.rule.clone());
                events.push(HookEvent::PolicySteered {
                    key: verdict.key.clone(),
                });
                continue;
            }
            // Requirement satisfied — the policy spoke and is content with it.
            crate::store::ContentOutcome::Inert => continue,
            crate::store::ContentOutcome::None => {
                // No require predicate. If deny_if was present but inert, the
                // content axis already spoke (nothing) — do not fall to the
                // consult gate. Only a policy with NEITHER content predicate
                // reaches consult.
                if deny_if_present {
                    continue;
                }
            }
        }
        if verdict.block && !verdict.satisfied && strict {
            denied.get_or_insert_with(|| PolicyDeny {
                key: verdict.key.clone(),
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

    if let Some(deny) = denied {
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
        events.push(deny.origin.deny_event(deny.key.clone()));
        return EnforcementResult {
            decision: Decision::Deny {
                file_key: deny.key,
                reason: deny.reason,
                origin: deny.origin,
            },
            events,
        };
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
    /// Caller's own observation of whether `rel_path` exists on disk, checked
    /// ONLY when the caller saw a `FileDeleted` staleness signal (that signal
    /// is a stale snapshot — cleared only by the staleness sweep, so it can
    /// outlive a delete-then-restore by many sessions). `None` means the
    /// caller did not check (preserves prior behavior: the signal alone
    /// bypasses enforcement). `Some(true)` means the path exists, so the
    /// signal is stale and must NOT bypass enforcement. `Some(false)` means
    /// the caller confirmed the path is really gone.
    pub file_exists: Option<bool>,
}

/// Result of `evaluate()`.
pub struct EnforcementResult {
    pub decision: Decision,
    pub events: Vec<HookEvent>,
}

// ── Tier 1 session lockdown ─────────────────────────────────────────────────

/// The deny every command and read gets while the session owes `owed_key`.
///
/// Tier 1 answers a decidable question — does this session owe a receipt? —
/// instead of the undecidable one a classifier asks, which is what file a
/// command string will open. Measured 2026-08-29: every red-team run that
/// eventually reached a gated file was denied four times first, then built the
/// filename from pieces (`"ke" + "ys.py"`). Nothing here is parsed, so that
/// construction has nothing to defeat.
pub fn lockdown_result(owed_key: &str) -> EnforcementResult {
    let path = owed_key.strip_prefix("file:").unwrap_or(owed_key);
    EnforcementResult {
        decision: Decision::Deny {
            file_key: owed_key.to_string(),
            reason: format!(
                "[mati] Session locked: {path} was denied earlier and has not been \
                 consulted. Every read and command is denied until you call \
                 mem_get(\"{owed_key}\")."
            ),
            origin: DenyOrigin::SessionLockdown,
        },
        events: vec![DenyOrigin::SessionLockdown.deny_event(owed_key.to_string())],
    }
}

// ── Tier 2 read floor ───────────────────────────────────────────────────────

/// The deny a floor-restoring command gets while `sealed_key` is still owed.
///
/// Measured 2026-08-30: `chmod`, `git checkout`/`restore` with a pathspec,
/// `git reset --hard`, `git worktree add` and `git clone` each returned a
/// mode-`000` file to a readable state, and the last two did it by making a
/// second tree rather than by naming the file at all. So the gate asks the
/// decidable question — is anything sealed whose receipt is outstanding —
/// rather than which path the command will touch.
pub fn seal_floor_result(sealed_key: &str) -> EnforcementResult {
    let path = sealed_key.strip_prefix("file:").unwrap_or(sealed_key);
    EnforcementResult {
        decision: Decision::Deny {
            file_key: sealed_key.to_string(),
            reason: format!(
                "[mati] {path} is sealed and has not been consulted. Commands that \
                 would restore it — chmod, cp, mv, ln, rm, install, rsync, git \
                 checkout, git restore, git reset --hard, git worktree add, git \
                 clone — are denied until you call mem_get(\"{sealed_key}\"), \
                 which unseals it."
            ),
            origin: DenyOrigin::SealFloor,
        },
        events: vec![DenyOrigin::SealFloor.deny_event(sealed_key.to_string())],
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
    //
    // The signal itself is a stale snapshot: it is cleared only by the
    // staleness sweep, which can be many sessions away from a given record's
    // turn. `input.file_exists == Some(true)` is the caller's own fresher
    // observation that the path is back — in that case fall through to the
    // ordinary gotcha loop below instead of bypassing on stale information.
    if has_file_deleted_signal(file_record) && input.file_exists != Some(true) {
        // Behaviourally identical to `NoRecord` from the agent's point of
        // view — allow unconditionally, nothing injected — so it shares
        // `NoRecord`'s event, UNLESS the bypass is suppressing a real deny.
        // `Hit` is wrong here: it mints a consultation receipt (see
        // `HookEvent::Hit` doc comment and its Codex-path suppression in
        // `cli::hook_decide::platform_events`), which would falsely mark
        // this file "consulted" for a read that delivered no context, and
        // could downgrade a real deny once staleness drops.
        //
        // Computed here, before the return, and used ONLY to pick the event
        // — the decision below stays `Tombstone` (allow) either way. Denying
        // instead would create an unclearable phantom: the file that would
        // need denying does not exist, so the `mem_get` that clears a deny
        // can never run against it.
        let would_have_denied = input.file_exists == Some(false)
            && any_qualifying_gotcha(
                &json_string_array(file_record, "/payload/gotcha_keys"),
                &input.gotcha_records,
            );
        let event = if would_have_denied {
            HookEvent::TombstoneBypassedDeny { key: file_key }
        } else {
            HookEvent::Miss { key: file_key }
        };
        return EnforcementResult {
            decision: Decision::Tombstone,
            events: vec![event],
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

/// True when printing this file's contents must be refused for want of a
/// consultation receipt, given a `hook_evaluate` bundle.
///
/// For mati's own content-emitting commands. They are not shell commands, so
/// [`classify_command`] never sees them and the read gate never fires; without
/// this an agent reaches a gated file's bytes through mati itself.
///
/// Narrower than [`evaluate`] on purpose. No `FileDeleted` bypass: a caller
/// about to open the file has observed the path present, which is the case
/// that falls through to the ordinary gotcha check anyway. No advisory,
/// staleness or policy handling: the only question is whether to print bytes,
/// and everything below a deny prints them.
pub fn read_needs_receipt(eval_data: &serde_json::Value) -> bool {
    if json_bool(eval_data, "/consulted") {
        return false;
    }
    let Some(file_record) = eval_data.get("file_record").filter(|v| v.is_object()) else {
        return false;
    };
    let gotcha_records: HashMap<String, serde_json::Value> = eval_data
        .get("gotcha_records")
        .and_then(|v| v.as_object())
        .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    any_qualifying_gotcha(
        &json_string_array(file_record, "/payload/gotcha_keys"),
        &gotcha_records,
    )
}
