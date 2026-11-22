use std::collections::BTreeSet;

use mati_core::store::{GotchaRecord, Record, RecordLifecycle};

// ── Display helpers ─────────────────────────────────────────────────────────

/// Returns `true` if the file path looks like a code file worth showing in
/// the hotspot/co-change display. Filters out documentation, license, config,
/// and other non-code files that add noise to the first-run output.
///
/// Only affects display — the underlying analysis and records are unchanged.
pub(crate) fn is_code_file(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path);

    // Exclude well-known non-code files by exact name
    const EXCLUDED_NAMES: &[&str] = &[
        "README.md",
        "README",
        "readme.md",
        "CHANGELOG.md",
        "CHANGES.md",
        "HISTORY.md",
        "LICENSE",
        "LICENSE.md",
        "LICENSE-MIT",
        "LICENSE-APACHE",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "AGENTS.md",
        "CLAUDE.md",
        "CODEX.md",
        ".gitignore",
        ".gitattributes",
    ];
    if EXCLUDED_NAMES.contains(&basename) {
        return false;
    }

    // Require a code-related extension
    const CODE_EXTENSIONS: &[&str] = &[
        "rs", "go", "py", "ts", "tsx", "js", "jsx", "java", "kt", "swift", "c", "cpp", "h", "hpp",
        "cs", "rb", "php", "ex", "exs", "zig", "hs", "ml", "scala", "clj", "toml", "yaml", "yml",
        "json", "sql", "sh", "bash", "proto",
    ];
    match path.rsplit('.').next() {
        Some(ext) => CODE_EXTENSIONS.contains(&ext),
        None => false,
    }
}

/// Files a gotcha can deny today: active, confirmed, confidence >= 0.6 and
/// quality >= 0.4 — the hook decision matrix (ARCHITECTURE.md section 10.1).
pub(crate) fn gated_files(gotchas: &[Record]) -> BTreeSet<String> {
    gotchas
        .iter()
        .filter(|r| matches!(r.lifecycle, RecordLifecycle::Active))
        .filter(|r| r.confidence.value >= 0.6 && r.quality.value >= 0.4)
        .filter_map(|r| r.payload_as::<GotchaRecord>())
        .filter(|g| g.confirmed)
        .flat_map(|g| g.affected_files)
        .collect()
}

pub(crate) fn coverage_line(gated: usize, total: usize, ungated_hotspots: usize) -> String {
    if gated == 0 {
        return format!(
            "0 of {total} files gated. Nothing is denied until a file has a confirmed gotcha (mati review)."
        );
    }
    let line = format!("{gated} of {total} files gated by a confirmed gotcha.");
    match ungated_hotspots {
        0 => line,
        1 => format!("{line} 1 hotspot file has none."),
        n => format!("{line} {n} hotspot files have none."),
    }
}
