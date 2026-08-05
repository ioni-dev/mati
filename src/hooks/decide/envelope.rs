//! Codex apply_patch envelope parsing. Pure, no I/O.

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
