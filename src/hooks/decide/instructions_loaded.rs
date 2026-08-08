//! Pure parsing for Claude Code's `InstructionsLoaded` hook event.

use serde::{Deserialize, Serialize};

/// The payload captured from Claude Code 2.1.223's `InstructionsLoaded` event.
///
/// Keep this shape aligned with the installed platform contract. The adapter
/// records the payload as received; it does not make an enforcement decision.
///
/// Unlike the MCP input DTOs, this deliberately does NOT `deny_unknown_fields`:
/// those parse untrusted client input, this parses a platform payload that gains
/// fields between Claude Code releases. Rejecting one would stop the audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionsLoadedPayload {
    pub session_id: String,
    pub transcript_path: String,
    pub cwd: String,
    pub hook_event_name: String,
    pub file_path: String,
    pub memory_type: String,
    pub load_reason: String,
}

/// Parse one raw `InstructionsLoaded` hook payload.
///
/// Invalid or unrelated payloads return `None` so the hook can fail open
/// without recording a misleading event.
pub fn parse_instructions_loaded(input: &serde_json::Value) -> Option<InstructionsLoadedPayload> {
    let payload: InstructionsLoadedPayload = serde_json::from_value(input.clone()).ok()?;
    (payload.hook_event_name == "InstructionsLoaded").then_some(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn payload() -> serde_json::Value {
        json!({
            "session_id": "session-123",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": "/repo",
            "hook_event_name": "InstructionsLoaded",
            "file_path": "/repo/.claude/CLAUDE.md",
            "memory_type": "Project",
            "load_reason": "session_start"
        })
    }

    #[test]
    fn parses_captured_platform_shape() {
        let parsed = parse_instructions_loaded(&payload()).expect("payload should parse");
        assert_eq!(parsed.file_path, "/repo/.claude/CLAUDE.md");
        assert_eq!(parsed.load_reason, "session_start");
    }

    #[test]
    fn rejects_other_hook_events() {
        let mut value = payload();
        value["hook_event_name"] = json!("SessionStart");
        assert!(parse_instructions_loaded(&value).is_none());
    }

    #[test]
    fn rejects_missing_or_wrongly_typed_fields() {
        let mut missing = payload();
        missing.as_object_mut().unwrap().remove("file_path");
        assert!(parse_instructions_loaded(&missing).is_none());

        let mut wrong_type = payload();
        wrong_type["load_reason"] = json!(42);
        assert!(parse_instructions_loaded(&wrong_type).is_none());
    }

    /// A Claude Code release that adds a field must not silence the audit.
    #[test]
    fn accepts_unknown_fields() {
        let mut value = payload();
        value["future_platform_field"] = json!(true);
        let parsed = parse_instructions_loaded(&value).expect("unknown fields must not reject");
        assert_eq!(parsed.file_path, "/repo/.claude/CLAUDE.md");
    }
}
