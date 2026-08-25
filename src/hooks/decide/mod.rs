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
    classify_command, is_known_action_tool, is_schema_introspection, KNOWN_ACTION_TOOLS,
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
};
#[cfg(test)]
use json_helpers::json_has_signal;
use json_helpers::{any_qualifying_gotcha, json_bool, json_f32, json_str, json_string_array};
use path_extraction::{shell_tokens, split_at_shell_operator};

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
    /// The `FileDeleted` bypass fired on a caller-confirmed deletion
    /// (`file_exists: Some(false)`) that also suppressed a deny a qualifying
    /// confirmed gotcha would otherwise have produced. Unlike the plain
    /// `Miss` the bypass ordinarily emits, this reaches the hash-chained
    /// enforcement log as `BypassDetected` — enforcement was suppressed, not
    /// merely a cache miss.
    TombstoneBypassedDeny { key: String },
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
            let would = match verdict.content {
                crate::store::ContentOutcome::Deny => Some(ShadowOutcome::Block),
                crate::store::ContentOutcome::Warn => Some(ShadowOutcome::Steer),
                // A content predicate that did not match observes nothing.
                crate::store::ContentOutcome::Inert => None,
                crate::store::ContentOutcome::None => {
                    if !verdict.block {
                        Some(ShadowOutcome::Steer)
                    } else if !verdict.satisfied {
                        Some(ShadowOutcome::Block)
                    } else {
                        None
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
        // The content predicate governs first — independent of
        // `satisfied`/`requires`, never lowered by the schema-introspection
        // exemption (upstream). A content policy speaks ONLY through its
        // predicate: on a non-match (`Inert`) it neither denies nor steers.
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
            crate::store::ContentOutcome::Inert => continue,
            crate::store::ContentOutcome::None => {}
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
