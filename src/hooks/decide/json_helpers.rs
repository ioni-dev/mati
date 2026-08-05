//! JSON-payload helpers for the decision engine. Pure, no I/O.

use super::*;

// ── JSON helpers ────────────────────────────────────────────────────────────

pub(super) fn json_f32(val: &serde_json::Value, pointer: &str) -> f32 {
    val.pointer(pointer)
        .and_then(|v| v.as_f64())
        .map(|f| f as f32)
        .unwrap_or(0.0)
}

pub(super) fn json_str(val: &serde_json::Value, pointer: &str) -> String {
    val.pointer(pointer)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

pub(super) fn json_bool(val: &serde_json::Value, pointer: &str) -> bool {
    val.pointer(pointer)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

pub(super) fn json_string_array(val: &serde_json::Value, pointer: &str) -> Vec<String> {
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
pub(super) fn json_has_signal(val: &serde_json::Value, pointer: &str, signal: &str) -> bool {
    val.pointer(pointer)
        .and_then(|v| v.as_array())
        .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some(signal)))
}

/// True if `file_record` carries the `FileDeleted` staleness signal.
///
/// I/O-free — this only inspects JSON already in hand. It exists so an
/// impure caller can decide whether a stat is worth paying for (only when
/// this returns true) before populating [`EnforcementInput::file_exists`],
/// without duplicating the signal's pointer path and string spelling.
pub fn has_file_deleted_signal(file_record: &serde_json::Value) -> bool {
    json_has_signal(file_record, "/staleness/signals", "file_deleted")
}

/// True if any gotcha in `gotcha_keys` qualifies for enforcement under the
/// same test the main gotcha loop in [`evaluate`] uses: `confirmed &&
/// confidence >= 0.6 && quality >= 0.4`.
pub(super) fn any_qualifying_gotcha(
    gotcha_keys: &[String],
    gotcha_records: &HashMap<String, serde_json::Value>,
) -> bool {
    gotcha_keys.iter().any(|gkey| {
        gotcha_records
            .get(gkey.as_str())
            .filter(|grec| grec.is_object())
            .is_some_and(|grec| {
                json_bool(grec, "/payload/confirmed")
                    && json_f32(grec, "/confidence/value") >= 0.6
                    && json_f32(grec, "/quality/value") >= 0.4
            })
    })
}
