//! Lexical path normalization to repo-relative form. Pure, no I/O.

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

    // Still absolute here means the path is outside the repo. Keep it absolute:
    // splitting on '/' drops the leading empty component, and rejoining without
    // it mints a key like `file:Users/ioni/x` that looks repo-relative, matches
    // no record, and lands in the miss aggregate as a path that never existed.
    let absolute = stripped.starts_with('/');

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

    match (components.is_empty(), absolute) {
        (true, true) => "/".to_string(),
        (true, false) => ".".to_string(),
        (false, true) => format!("/{}", components.join("/")),
        (false, false) => components.join("/"),
    }
}
