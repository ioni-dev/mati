//! Pure parsing for Claude Code's `FileChanged` hook event.

use serde::{Deserialize, Serialize};

/// The payload captured from Claude Code 2.1.223's `FileChanged` event.
///
/// Unlike the MCP input DTOs, this deliberately does NOT `deny_unknown_fields`:
/// those parse untrusted client input, this parses a platform payload that gains
/// fields between Claude Code releases. Rejecting one would stop the freshness
/// updates with no signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChangedPayload {
    pub session_id: String,
    pub transcript_path: String,
    pub cwd: String,
    /// Absent when the watcher fires outside a prompt turn.
    #[serde(default)]
    pub prompt_id: Option<String>,
    pub hook_event_name: String,
    /// Absolute, and echoed back in the exact spelling mati handed to
    /// `watchPaths` — Claude Code does not canonicalize it. Resolve symlinks
    /// on both sides before comparing it to a repo root.
    pub file_path: String,
    /// chokidar event: `add`, `change`, or `unlink`.
    pub event: String,
}

/// Parse one raw `FileChanged` hook payload.
///
/// Invalid or unrelated payloads return `None` so the hook can fail open
/// without reparsing a path it did not understand.
pub fn parse_file_changed(input: &serde_json::Value) -> Option<FileChangedPayload> {
    let payload: FileChangedPayload = serde_json::from_value(input.clone()).ok()?;
    (payload.hook_event_name == "FileChanged").then_some(payload)
}

impl FileChangedPayload {
    /// Whether this event should drive a reparse.
    ///
    /// `add` and `change` only. `unlink` is deliberately ignored: it would set
    /// the `FileDeleted` staleness signal and pin the record at the `Tombstone`
    /// tier, and `apply_reparse_staleness` only saturates upward — so a save
    /// that lands as delete-then-create would suppress that file's context
    /// injection for good. Real deletions are still caught by `mati init` and
    /// `mati repair`, and the read gate stats the file live before honouring
    /// the signal (`hooks::decide::evaluate`).
    pub fn drives_reparse(&self) -> bool {
        matches!(self.event.as_str(), "add" | "change")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn payload() -> serde_json::Value {
        json!({
            "session_id": "session-123",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": "/private/tmp/repo",
            "prompt_id": "prompt-456",
            "hook_event_name": "FileChanged",
            "file_path": "/tmp/repo/src/main.rs",
            "event": "change"
        })
    }

    #[test]
    fn parses_captured_platform_shape() {
        let parsed = parse_file_changed(&payload()).expect("payload should parse");
        assert_eq!(parsed.file_path, "/tmp/repo/src/main.rs");
        assert_eq!(parsed.event, "change");
        assert_eq!(parsed.prompt_id.as_deref(), Some("prompt-456"));
    }

    /// The watcher fires outside a prompt turn too, and the field is optional
    /// in the platform schema.
    #[test]
    fn parses_without_prompt_id() {
        let mut value = payload();
        value.as_object_mut().unwrap().remove("prompt_id");
        assert!(parse_file_changed(&value).is_some());
    }

    #[test]
    fn rejects_other_hook_events() {
        let mut value = payload();
        value["hook_event_name"] = json!("SessionStart");
        assert!(parse_file_changed(&value).is_none());
    }

    #[test]
    fn rejects_missing_or_wrongly_typed_fields() {
        let mut missing = payload();
        missing.as_object_mut().unwrap().remove("file_path");
        assert!(parse_file_changed(&missing).is_none());

        let mut wrong_type = payload();
        wrong_type["event"] = json!(3);
        assert!(parse_file_changed(&wrong_type).is_none());
    }

    /// A Claude Code release that adds a field must not stop the freshness path.
    #[test]
    fn accepts_unknown_fields() {
        let mut value = payload();
        value["future_platform_field"] = json!(true);
        assert!(parse_file_changed(&value).is_some());
    }

    #[test]
    fn only_add_and_change_drive_a_reparse() {
        for (event, expected) in [
            ("change", true),
            ("add", true),
            ("unlink", false),
            ("addDir", false),
        ] {
            let mut value = payload();
            value["event"] = json!(event);
            let parsed = parse_file_changed(&value).expect("payload should parse");
            assert_eq!(parsed.drives_reparse(), expected, "event {event}");
        }
    }
}
