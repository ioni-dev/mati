//! Command-building support for the mem_set tool method.

use super::*;

/// Map a `MemSetParams` request to a typed v2 [`Command`] for daemon dispatch.
///
/// Returns `Err(String)` when the request cannot be expressed as a typed
/// Command — the caller renders this into a JSON error envelope rather
/// than panicking the MCP transport.
///
/// # Routing rules
///
/// - `action = "confirm"` / `"delete"` → key MUST start with `gotcha:`;
///   policy lifecycle changes use the human-only `mati policy` commands.
///   This mirrors the Direct path's `mem_set_confirm` / `mem_set_delete`
///   guards (tools.rs:~1058).
/// - `action = "write"` (default) routes by key prefix:
///   - `gotcha:*`   → [`Command::GotchaUpsert`]
///   - `decision:*` → [`Command::DecisionUpsert`]
///   - `dev_note:*` → [`Command::DevNoteUpsert`]
///   - `policy:*`   → [`Command::PolicyWrite`] (create only)
///   - other        → error (file: writes have no public typed Command —
///     file records are managed by the static-analysis pipeline +
///     `file_enrich` / `file_reparse`, not direct mem_set).
pub(super) fn build_mem_set_command(params: &MemSetParams) -> Result<Command, String> {
    match params.action.as_str() {
        "confirm" => {
            if params.key.starts_with("policy:") {
                return Err("policies are activated with `mati policy enable <slug>`".into());
            }
            if !params.key.starts_with("gotcha:") {
                return Err("confirm action only applies to gotcha: keys".into());
            }
            Ok(Command::GotchaConfirm(GotchaConfirmInput {
                key: params.key.clone(),
                via_elicitation: false,
            }))
        }
        "delete" => {
            if params.key.starts_with("policy:") {
                return Err("policies are removed with `mati policy delete <slug>`".into());
            }
            if !params.key.starts_with("gotcha:") {
                return Err("delete action only applies to gotcha: keys".into());
            }
            Ok(Command::GotchaTombstone(GotchaTombstoneInput {
                key: params.key.clone(),
            }))
        }
        "write" | "" => build_mem_set_write_command(params),
        other => Err(format!(
            "unknown action: {other}. Valid: write, confirm, delete"
        )),
    }
}

fn build_mem_set_write_command(params: &MemSetParams) -> Result<Command, String> {
    // Some MCP clients (Codex) send the payload as a JSON-encoded string;
    // mirror the Direct-path normalization (tools.rs ~860).
    let payload = match &params.payload {
        serde_json::Value::String(s) => {
            serde_json::from_str::<serde_json::Value>(s).unwrap_or_else(|_| params.payload.clone())
        }
        other => other.clone(),
    };

    let priority = parse_protocol_priority(&params.priority);

    if let Some(slug) = params.key.strip_prefix("policy:") {
        if slug.is_empty() {
            return Err("policy key must not be just the prefix".into());
        }
        let mut policy: crate::store::PolicyRecord =
            serde_json::from_value(payload).map_err(|error| {
                format!("policy payload must deserialize into PolicyRecord: {error}")
            })?;
        // Agents may create or edit only off policies. Shadow and enforce are
        // developer-controlled and agent-immutable.
        if !matches!(policy.stage, crate::store::PolicyStage::Off) {
            policy.stage = crate::store::PolicyStage::Off;
        }
        return Ok(Command::PolicyWrite(
            crate::mcp::protocol::PolicyWriteInput {
                op: crate::mcp::protocol::PolicyWriteOp::Create,
                key: params.key.clone(),
                policy: Some(policy),
                stage: None,
            },
        ));
    }

    if let Some(stripped) = params.key.strip_prefix("gotcha:") {
        if stripped.is_empty() {
            return Err("gotcha key must not be just the prefix".into());
        }
        let rule = field_string(&payload, "rule")
            .ok_or_else(|| "gotcha payload requires non-empty 'rule'".to_string())?;
        let reason = field_string(&payload, "reason")
            .ok_or_else(|| "gotcha payload requires non-empty 'reason'".to_string())?;
        let severity = parse_protocol_severity(payload.get("severity").and_then(|v| v.as_str()));
        let affected_files = field_string_list(&payload, "affected_files");
        let ref_url = payload
            .get("ref_url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        return Ok(Command::GotchaUpsert(GotchaDraftInput {
            key: params.key.clone(),
            rule,
            reason,
            severity,
            affected_files,
            ref_url,
            tags: params.tags.clone(),
            priority,
            // An agent writes drafts. Enforcement requires the separate
            // `confirm` action, which is the developer's call (P4).
            source: None,
            confirmed: false,
        }));
    }

    if let Some(slug) = params.key.strip_prefix("decision:") {
        if slug.is_empty() {
            return Err("decision key must not be just the prefix".into());
        }
        let summary = field_string(&payload, "summary")
            .ok_or_else(|| "decision payload requires non-empty 'summary'".to_string())?;
        let rationale = field_string(&payload, "rationale")
            .ok_or_else(|| "decision payload requires non-empty 'rationale'".to_string())?;
        return Ok(Command::DecisionUpsert(DecisionUpsertInput {
            slug: slug.to_string(),
            value: params.value.clone(),
            summary,
            rationale,
            tags: params.tags.clone(),
            priority,
        }));
    }

    if let Some(stripped) = params.key.strip_prefix("dev_note:") {
        if stripped.is_empty() {
            return Err("dev_note key must not be just the prefix".into());
        }
        if params.value.is_empty() {
            return Err("dev_note requires non-empty value".into());
        }
        return Ok(Command::DevNoteUpsert(DevNoteUpsertInput {
            key: Some(params.key.clone()),
            text: params.value.clone(),
            tags: params.tags.clone(),
            priority,
        }));
    }

    Err("mem_set write requires key with gotcha:/decision:/dev_note:/policy: prefix".into())
}

fn field_string(payload: &serde_json::Value, field: &str) -> Option<String> {
    payload
        .get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

fn field_string_list(payload: &serde_json::Value, field: &str) -> Vec<String> {
    payload
        .get(field)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_protocol_priority(s: &str) -> proto::Priority {
    match s {
        "Critical" | "critical" => proto::Priority::Critical,
        "High" | "high" => proto::Priority::High,
        "Low" | "low" => proto::Priority::Low,
        _ => proto::Priority::Normal,
    }
}

fn parse_protocol_severity(s: Option<&str>) -> proto::Severity {
    match s.map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("critical") => proto::Severity::Critical,
        Some("high") => proto::Severity::High,
        Some("low") => proto::Severity::Low,
        _ => proto::Severity::Normal,
    }
}
