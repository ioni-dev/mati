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
