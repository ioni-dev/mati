//! Dependency parsing — Layer 0 manifest extraction.
//!
//! Reads `Cargo.toml`, `package.json`, and `go.mod` from walked files to produce
//! `dep:*` records. No tree-sitter needed — just `serde_json` (package.json) and
//! line parsing (Cargo.toml, go.mod).
//!
//! # Performance
//!
//! Pure I/O + string parsing. Typical projects: <2ms for ~20 deps.
//!
//! # Graceful degradation (P9)
//!
//! All errors degrade silently — unreadable or malformed manifests are skipped
//! with a `warn!`. Never fatal.

use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use tracing::warn;

use super::walker::WalkedFile;

// ── Public types ────────────────────────────────────────────────────────────

/// A single dependency extracted from a manifest file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepEntry {
    /// Dependency ecosystem — used as part of the canonical dep:* key.
    pub ecosystem: DepEcosystem,
    /// Dependency name (crate name, npm package, Go module path).
    pub name: String,
    /// Version resolution — explicit string or workspace-inherited.
    pub version: DepVersion,
    /// Which manifest declared this dependency.
    pub manifest: ManifestKind,
    /// Whether this is a dev/test dependency.
    pub dev: bool,
}

/// Canonical dependency ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DepEcosystem {
    Cargo,
    Npm,
    Go,
}

impl DepEcosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::Go => "go",
        }
    }
}

/// How a dependency version is declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepVersion {
    /// Explicit version string (may be range, "*", or exact).
    Declared(String),
    /// Inherited from `[workspace.dependencies]` via `dep.workspace = true`.
    Workspace,
}

/// Kind of manifest file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    CargoToml,
    PackageJson,
    GoMod,
}

/// All dependencies discovered in a repository.
#[derive(Debug, Clone)]
pub struct DepSignals {
    /// Deduplicated dependency entries.
    pub deps: Vec<DepEntry>,
    /// Which manifest files were found and parsed.
    pub manifests_found: Vec<(ManifestKind, String)>,
}

/// Build the canonical `dep:*` record key for a dependency.
pub fn dep_record_key(dep: &DepEntry) -> String {
    format!("dep:{}:{}", dep.ecosystem.as_str(), dep.name)
}

/// Extract the display name from a `dep:*` key.
///
/// Supports both the new `dep:<ecosystem>:<name>` format and the legacy
/// `dep:<name>` form so read paths stay compatible with old stores.
pub fn dep_display_name_from_key(key: &str) -> &str {
    let Some(rest) = key.strip_prefix("dep:") else {
        return key;
    };
    match rest.split_once(':') {
        Some(("cargo" | "npm" | "go", name)) => name,
        _ => rest,
    }
}

/// Extract ecosystem + display name from a `dep:*` key when available.
pub fn parse_dep_key(key: &str) -> Option<(Option<DepEcosystem>, &str)> {
    let rest = key.strip_prefix("dep:")?;
    match rest.split_once(':') {
        Some(("cargo", name)) => Some((Some(DepEcosystem::Cargo), name)),
        Some(("npm", name)) => Some((Some(DepEcosystem::Npm), name)),
        Some(("go", name)) => Some((Some(DepEcosystem::Go), name)),
        _ => Some((None, rest)),
    }
}

impl DepSignals {
    /// Empty result — used when no manifests are found.
    pub fn empty() -> Self {
        Self {
            deps: Vec::new(),
            manifests_found: Vec::new(),
        }
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Parse all manifest files found by the walker.
///
/// Looks for `Cargo.toml`, `package.json`, `go.mod` in `walked_files`.
/// Sync, pure I/O. Returns `DepSignals::empty()` on any systemic error (P9).
///
/// Deduplication: if the same dep identity appears from multiple manifests,
/// the entry from the shallowest (fewest path separators) manifest wins.
pub fn parse_dependencies(repo_path: &Path, walked_files: &[WalkedFile]) -> Result<DepSignals> {
    // Discover manifests, sorted by depth (shallowest first for dedup priority).
    let mut manifests: Vec<(ManifestKind, &str)> = walked_files
        .iter()
        .filter_map(|f| {
            filename_to_manifest_kind(&f.rel_path).map(|kind| (kind, f.rel_path.as_str()))
        })
        .collect();

    if manifests.is_empty() {
        return Ok(DepSignals::empty());
    }

    // Sort by depth (number of '/' separators) so root manifests come first.
    manifests.sort_by_key(|(_, path)| path.matches('/').count());

    let mut all_deps: Vec<DepEntry> = Vec::new();
    let mut manifests_found: Vec<(ManifestKind, String)> = Vec::new();

    for (kind, rel_path) in &manifests {
        let abs_path = repo_path.join(rel_path);
        let content = match std::fs::read_to_string(&abs_path) {
            Ok(c) => c,
            Err(e) => {
                warn!("deps: cannot read {rel_path}: {e}");
                continue;
            }
        };

        let entries = match kind {
            ManifestKind::CargoToml => parse_cargo_toml(&content),
            ManifestKind::PackageJson => parse_package_json(&content),
            ManifestKind::GoMod => parse_go_mod(&content),
        };

        all_deps.extend(entries);
        manifests_found.push((*kind, rel_path.to_string()));
    }

    // Dedup by canonical dependency identity — first occurrence wins
    // (shallowest manifest due to sort).
    let mut seen = HashSet::new();
    let mut deduped: Vec<DepEntry> = Vec::with_capacity(all_deps.len());

    for dep in all_deps {
        if seen.insert((dep.ecosystem, dep.name.clone())) {
            deduped.push(dep);
        }
    }

    // Sort by name for deterministic output.
    deduped.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    Ok(DepSignals {
        deps: deduped,
        manifests_found,
    })
}

// ── Internal parsers ────────────────────────────────────────────────────────

/// Determine manifest kind from a repo-relative path.
fn filename_to_manifest_kind(rel_path: &str) -> Option<ManifestKind> {
    let filename = rel_path.rsplit('/').next().unwrap_or(rel_path);
    match filename {
        "Cargo.toml" => Some(ManifestKind::CargoToml),
        "package.json" => Some(ManifestKind::PackageJson),
        "go.mod" => Some(ManifestKind::GoMod),
        _ => None,
    }
}

/// Parse `Cargo.toml` via line-based section parsing.
///
/// Handles `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`,
/// and dotted table forms like `[dependencies.serde]`.
/// Supports: `name = "version"`, `name = { version = "..." }`, `name.workspace = true`.
fn parse_cargo_toml(content: &str) -> Vec<DepEntry> {
    let mut deps = Vec::new();

    #[derive(Clone, Copy)]
    enum Section {
        None,
        Dependencies,
        DevDependencies,
        BuildDependencies,
    }

    let mut section = Section::None;
    // When inside a `[dependencies.X]` table, the dep name from the header.
    let mut table_dep_name: Option<String> = None;
    let mut table_dev = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // Detect section headers — strip exactly one bracket from each end.
        if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            // Skip TOML array-of-tables `[[...]]`
            let header =
                if let Some(inner2) = inner.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                    // Flush any pending table dep before switching sections.
                    if let Some(name) = table_dep_name.take() {
                        deps.push(DepEntry {
                            name,
                            ecosystem: DepEcosystem::Cargo,
                            version: DepVersion::Declared(String::new()),
                            manifest: ManifestKind::CargoToml,
                            dev: table_dev,
                        });
                    }
                    section = Section::None;
                    let _ = inner2;
                    continue;
                } else {
                    inner.trim()
                };

            // Flush any pending table dep before switching sections.
            if let Some(name) = table_dep_name.take() {
                deps.push(DepEntry {
                    ecosystem: DepEcosystem::Cargo,
                    name,
                    version: DepVersion::Declared(String::new()),
                    manifest: ManifestKind::CargoToml,
                    dev: table_dev,
                });
            }

            // Check for dotted table form: `[dependencies.serde]`
            if let Some(dep_name) = header.strip_prefix("dependencies.") {
                section = Section::Dependencies;
                table_dep_name = Some(dep_name.to_string());
                table_dev = false;
                continue;
            }
            if let Some(dep_name) = header.strip_prefix("dev-dependencies.") {
                section = Section::DevDependencies;
                table_dep_name = Some(dep_name.to_string());
                table_dev = true;
                continue;
            }
            if let Some(dep_name) = header.strip_prefix("build-dependencies.") {
                section = Section::BuildDependencies;
                table_dep_name = Some(dep_name.to_string());
                table_dev = true;
                continue;
            }

            section = match header {
                "dependencies" => Section::Dependencies,
                "dev-dependencies" => Section::DevDependencies,
                "build-dependencies" => Section::BuildDependencies,
                _ => Section::None,
            };
            continue;
        }

        // Skip outside dependency sections
        let dev = match section {
            Section::None => continue,
            Section::Dependencies => false,
            Section::DevDependencies => true,
            Section::BuildDependencies => true,
        };

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Inside a `[dependencies.X]` table — look for `version = "..."`.
        if let Some(ref dep_name) = table_dep_name {
            if let Some((key, val)) = trimmed.split_once('=') {
                let key = key.trim();
                let val = val.trim();
                if key == "version" {
                    if let Some(version) = extract_quoted_string(val) {
                        deps.push(DepEntry {
                            ecosystem: DepEcosystem::Cargo,
                            name: dep_name.clone(),
                            version: DepVersion::Declared(version),
                            manifest: ManifestKind::CargoToml,
                            dev,
                        });
                        table_dep_name = None;
                    }
                } else if key == "workspace" && val.trim() == "true" {
                    deps.push(DepEntry {
                        ecosystem: DepEcosystem::Cargo,
                        name: dep_name.clone(),
                        version: DepVersion::Workspace,
                        manifest: ManifestKind::CargoToml,
                        dev,
                    });
                    table_dep_name = None;
                }
            }
            continue;
        }

        // Parse: name = "version" | name = { version = "..." } | name.workspace = true
        if let Some((name_part, value_part)) = trimmed.split_once('=') {
            let name = name_part.trim();
            let value = value_part.trim();

            // Handle `name.workspace = true` — extract dep name
            if let Some((dep_name, sub_key)) = name.split_once('.') {
                let dep_name = dep_name.trim();
                let sub_key = sub_key.trim();
                if sub_key == "workspace" && !dep_name.is_empty() {
                    deps.push(DepEntry {
                        ecosystem: DepEcosystem::Cargo,
                        name: dep_name.to_string(),
                        version: DepVersion::Workspace,
                        manifest: ManifestKind::CargoToml,
                        dev,
                    });
                }
                continue;
            }

            if name.is_empty() {
                continue;
            }

            let version = if value.starts_with('"') {
                // Simple form: name = "version"
                extract_quoted_string(value)
            } else if value.starts_with('{') {
                // Inline table: name = { version = "...", ... }
                extract_version_from_inline_table(value)
            } else {
                // Unknown form — skip
                continue;
            };

            if let Some(version) = version {
                deps.push(DepEntry {
                    ecosystem: DepEcosystem::Cargo,
                    name: name.to_string(),
                    version: DepVersion::Declared(version),
                    manifest: ManifestKind::CargoToml,
                    dev,
                });
            }
        }
    }

    // Flush any trailing table dep (file ended inside a `[dependencies.X]` block).
    if let Some(name) = table_dep_name {
        deps.push(DepEntry {
            name,
            ecosystem: DepEcosystem::Cargo,
            version: DepVersion::Declared(String::new()),
            manifest: ManifestKind::CargoToml,
            dev: table_dev,
        });
    }

    deps
}

/// Parse `package.json` via serde_json.
fn parse_package_json(content: &str) -> Vec<DepEntry> {
    let parsed: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut deps = Vec::new();

    if let Some(obj) = parsed.get("dependencies").and_then(|v| v.as_object()) {
        for (name, version) in obj {
            deps.push(DepEntry {
                ecosystem: DepEcosystem::Npm,
                name: name.clone(),
                version: DepVersion::Declared(version.as_str().unwrap_or("*").to_string()),
                manifest: ManifestKind::PackageJson,
                dev: false,
            });
        }
    }

    if let Some(obj) = parsed.get("devDependencies").and_then(|v| v.as_object()) {
        for (name, version) in obj {
            deps.push(DepEntry {
                ecosystem: DepEcosystem::Npm,
                name: name.clone(),
                version: DepVersion::Declared(version.as_str().unwrap_or("*").to_string()),
                manifest: ManifestKind::PackageJson,
                dev: true,
            });
        }
    }

    deps
}

/// Parse `go.mod` via line-based parsing.
///
/// Handles both multi-line `require ( ... )` blocks and single-line `require module version`.
fn parse_go_mod(content: &str) -> Vec<DepEntry> {
    let mut deps = Vec::new();
    let mut in_require_block = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("require (") || trimmed == "require(" {
            in_require_block = true;
            continue;
        }

        if in_require_block {
            if trimmed == ")" {
                in_require_block = false;
                continue;
            }

            // Lines inside require block: `module/path v1.2.3 // indirect`
            if let Some(dep) = parse_go_require_line(trimmed) {
                deps.push(dep);
            }
            continue;
        }

        // Single-line require: `require module/path v1.2.3`
        if let Some(rest) = trimmed.strip_prefix("require ") {
            let rest = rest.trim();
            if let Some(dep) = parse_go_require_line(rest) {
                deps.push(dep);
            }
        }
    }

    deps
}

// ── String extraction helpers ───────────────────────────────────────────────

/// Extract a quoted string: `"value"` → `Some("value")`.
fn extract_quoted_string(s: &str) -> Option<String> {
    let s = s.trim();
    if s.starts_with('"') && s.len() > 1 {
        if let Some(end) = s[1..].find('"') {
            return Some(s[1..1 + end].to_string());
        }
    }
    None
}

/// Extract `version` from an inline TOML table: `{ version = "1.0", features = [...] }`.
fn extract_version_from_inline_table(s: &str) -> Option<String> {
    // Find `version = "..."` inside the braces.
    let inner = s.trim().trim_start_matches('{').trim_end_matches('}');
    for part in inner.split(',') {
        let part = part.trim();
        if let Some((key, val)) = part.split_once('=') {
            if key.trim() == "version" {
                return extract_quoted_string(val);
            }
        }
    }
    None
}

/// Parse a single go.mod require line: `module/path v1.2.3` or `module/path v1.2.3 // indirect`.
fn parse_go_require_line(line: &str) -> Option<DepEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with("//") {
        return None;
    }

    // Strip trailing comment
    let without_comment = if let Some(idx) = line.find("//") {
        line[..idx].trim()
    } else {
        line
    };

    let mut parts = without_comment.split_whitespace();
    let module = parts.next()?;
    let version = parts.next().unwrap_or("").to_string();

    Some(DepEntry {
        ecosystem: DepEcosystem::Go,
        name: module.to_string(),
        version: DepVersion::Declared(version),
        manifest: ManifestKind::GoMod,
        dev: false,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn find_dep<'a>(deps: &'a [DepEntry], name: &str) -> Option<&'a DepEntry> {
        deps.iter().find(|d| d.name == name)
    }

    fn write(dir: &Path, rel: &str, content: &str) {
        let full = dir.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, content).unwrap();
    }

    fn walked_file(rel_path: &str) -> WalkedFile {
        WalkedFile {
            abs_path: PathBuf::from(rel_path),
            rel_path: rel_path.to_string(),
            language: super::super::walker::Language::Unknown,
            size_bytes: 0,
            mtime_secs: 0,
        }
    }

    // ── Cargo.toml ──────────────────────────────────────────────────────────

    #[test]
    fn cargo_toml_basic() {
        let deps = parse_cargo_toml(
            r#"
[package]
name = "my-crate"
version = "0.1.0"

[dependencies]
serde = "1.0"
anyhow = "1.0"
tokio = "1.40"
"#,
        );

        assert_eq!(deps.len(), 3);
        let serde = find_dep(&deps, "serde").unwrap();
        assert_eq!(serde.ecosystem, DepEcosystem::Cargo);
        assert_eq!(serde.version, DepVersion::Declared("1.0".into()));
        assert_eq!(serde.manifest, ManifestKind::CargoToml);
        assert!(!serde.dev);
    }

    #[test]
    fn cargo_toml_inline_table() {
        let deps = parse_cargo_toml(
            r#"
[dependencies]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.40", features = ["full"] }
"#,
        );

        assert_eq!(deps.len(), 2);
        let serde = find_dep(&deps, "serde").unwrap();
        assert_eq!(serde.version, DepVersion::Declared("1.0".into()));
        let tokio = find_dep(&deps, "tokio").unwrap();
        assert_eq!(tokio.version, DepVersion::Declared("1.40".into()));
    }

    #[test]
    fn cargo_toml_dev_deps() {
        let deps = parse_cargo_toml(
            r#"
[dependencies]
serde = "1.0"

[dev-dependencies]
tempfile = "3.10"
criterion = "0.5"
"#,
        );

        assert_eq!(deps.len(), 3);
        let serde = find_dep(&deps, "serde").unwrap();
        assert!(!serde.dev);
        let tempfile = find_dep(&deps, "tempfile").unwrap();
        assert!(tempfile.dev);
        let criterion = find_dep(&deps, "criterion").unwrap();
        assert!(criterion.dev);
    }

    #[test]
    fn cargo_toml_build_deps() {
        let deps = parse_cargo_toml(
            r#"
[build-dependencies]
cc = "1.0"
"#,
        );

        assert_eq!(deps.len(), 1);
        let cc = find_dep(&deps, "cc").unwrap();
        assert!(cc.dev, "build-dependencies should be flagged as dev");
    }

    #[test]
    fn cargo_toml_workspace_dep() {
        let deps = parse_cargo_toml(
            r#"
[dependencies]
serde.workspace = true
tokio.workspace = true
"#,
        );

        assert_eq!(deps.len(), 2);
        let serde = find_dep(&deps, "serde").unwrap();
        assert_eq!(serde.version, DepVersion::Workspace);
    }

    #[test]
    fn cargo_toml_table_form() {
        let deps = parse_cargo_toml(
            r#"
[dependencies.serde]
version = "1.0"
features = ["derive"]

[dependencies.tokio]
version = "1.40"
features = ["full"]

[dev-dependencies.tempfile]
version = "3.10"
"#,
        );

        assert_eq!(deps.len(), 3);
        let serde = find_dep(&deps, "serde").unwrap();
        assert_eq!(serde.version, DepVersion::Declared("1.0".into()));
        assert!(!serde.dev);
        let tokio = find_dep(&deps, "tokio").unwrap();
        assert_eq!(tokio.version, DepVersion::Declared("1.40".into()));
        let tempfile = find_dep(&deps, "tempfile").unwrap();
        assert!(tempfile.dev);
    }

    #[test]
    fn cargo_toml_empty() {
        let deps = parse_cargo_toml(
            r#"
[package]
name = "empty"
version = "0.1.0"
"#,
        );

        assert!(deps.is_empty());
    }

    // ── package.json ────────────────────────────────────────────────────────

    #[test]
    fn package_json_basic() {
        let deps = parse_package_json(
            r#"{
  "name": "my-app",
  "dependencies": {
    "react": "^18.0.0",
    "express": "~4.18.0"
  },
  "devDependencies": {
    "jest": "^29.0.0",
    "typescript": "^5.0.0"
  }
}"#,
        );

        assert_eq!(deps.len(), 4);
        let react = find_dep(&deps, "react").unwrap();
        assert_eq!(react.ecosystem, DepEcosystem::Npm);
        assert_eq!(react.version, DepVersion::Declared("^18.0.0".into()));
        assert!(!react.dev);
        assert_eq!(react.manifest, ManifestKind::PackageJson);

        let jest = find_dep(&deps, "jest").unwrap();
        assert!(jest.dev);
    }

    #[test]
    fn package_json_no_deps() {
        let deps = parse_package_json(r#"{"name": "empty-app", "version": "1.0.0"}"#);
        assert!(deps.is_empty());
    }

    #[test]
    fn package_json_malformed() {
        let deps = parse_package_json("{ this is not json }");
        assert!(
            deps.is_empty(),
            "malformed JSON should return empty, not error"
        );
    }

    // ── go.mod ──────────────────────────────────────────────────────────────

    #[test]
    fn go_mod_basic() {
        let deps = parse_go_mod(
            r#"
module github.com/example/myapp

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/lib/pq v1.10.9
	golang.org/x/sync v0.5.0
)
"#,
        );

        assert_eq!(deps.len(), 3);
        let gin = find_dep(&deps, "github.com/gin-gonic/gin").unwrap();
        assert_eq!(gin.ecosystem, DepEcosystem::Go);
        assert_eq!(gin.version, DepVersion::Declared("v1.9.1".into()));
        assert_eq!(gin.manifest, ManifestKind::GoMod);
        assert!(!gin.dev);
    }

    #[test]
    fn go_mod_single_require() {
        let deps = parse_go_mod(
            r#"
module github.com/example/myapp

go 1.21

require github.com/lib/pq v1.10.9
"#,
        );

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "github.com/lib/pq");
        assert_eq!(deps[0].version, DepVersion::Declared("v1.10.9".into()));
    }

    #[test]
    fn go_mod_indirect() {
        let deps = parse_go_mod(
            r#"
require (
	github.com/direct/dep v1.0.0
	github.com/indirect/dep v2.0.0 // indirect
)
"#,
        );

        assert_eq!(deps.len(), 2, "indirect deps should still be included");
        assert!(find_dep(&deps, "github.com/indirect/dep").is_some());
    }

    #[test]
    fn go_mod_empty() {
        let deps = parse_go_mod(
            r#"
module github.com/example/myapp

go 1.21
"#,
        );

        assert!(deps.is_empty());
    }

    // ── Integration tests ───────────────────────────────────────────────────

    #[test]
    fn parse_dependencies_integration() {
        let dir = TempDir::new().unwrap();

        write(
            dir.path(),
            "Cargo.toml",
            r#"
[dependencies]
serde = "1.0"
anyhow = "1.0"
"#,
        );

        write(
            dir.path(),
            "package.json",
            r#"{"dependencies": {"react": "^18.0.0"}}"#,
        );

        write(
            dir.path(),
            "go.mod",
            r#"
module example.com/app

require github.com/gin-gonic/gin v1.9.1
"#,
        );

        let walked = vec![
            walked_file("Cargo.toml"),
            walked_file("package.json"),
            walked_file("go.mod"),
        ];

        let signals = parse_dependencies(dir.path(), &walked).unwrap();

        assert_eq!(signals.manifests_found.len(), 3);
        assert_eq!(signals.deps.len(), 4);
        assert!(find_dep(&signals.deps, "serde").is_some());
        assert!(find_dep(&signals.deps, "react").is_some());
        assert!(find_dep(&signals.deps, "github.com/gin-gonic/gin").is_some());
    }

    #[test]
    fn no_manifests_returns_empty() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "src/main.rs", "fn main() {}");

        let walked = vec![walked_file("src/main.rs")];
        let signals = parse_dependencies(dir.path(), &walked).unwrap();

        assert!(signals.deps.is_empty());
        assert!(signals.manifests_found.is_empty());
    }

    #[test]
    fn dedup_across_manifests() {
        let dir = TempDir::new().unwrap();

        // Root Cargo.toml has serde 1.0
        write(
            dir.path(),
            "Cargo.toml",
            r#"
[dependencies]
serde = "1.0"
"#,
        );

        // Nested crate also has serde but different version
        write(
            dir.path(),
            "subcrate/Cargo.toml",
            r#"
[dependencies]
serde = "1.1"
anyhow = "1.0"
"#,
        );

        let walked = vec![
            walked_file("Cargo.toml"),
            walked_file("subcrate/Cargo.toml"),
        ];

        let signals = parse_dependencies(dir.path(), &walked).unwrap();

        // serde should appear only once, from root (shallowest)
        let serde_entries: Vec<&DepEntry> =
            signals.deps.iter().filter(|d| d.name == "serde").collect();
        assert_eq!(serde_entries.len(), 1, "serde should be deduplicated");
        assert_eq!(
            serde_entries[0].version,
            DepVersion::Declared("1.0".into()),
            "root manifest should win"
        );

        // anyhow only in subcrate — should still be included
        assert!(find_dep(&signals.deps, "anyhow").is_some());
    }

    #[test]
    fn same_name_in_different_ecosystems_do_not_collapse() {
        let dir = TempDir::new().unwrap();

        write(
            dir.path(),
            "Cargo.toml",
            r#"
[dependencies]
react = "1.0"
"#,
        );

        write(
            dir.path(),
            "package.json",
            r#"{"dependencies": {"react": "^18.0.0"}}"#,
        );

        let walked = vec![walked_file("Cargo.toml"), walked_file("package.json")];
        let signals = parse_dependencies(dir.path(), &walked).unwrap();

        let react_entries: Vec<&DepEntry> =
            signals.deps.iter().filter(|d| d.name == "react").collect();
        assert_eq!(
            react_entries.len(),
            2,
            "cross-ecosystem names must not collapse"
        );
        assert!(react_entries
            .iter()
            .any(|d| d.ecosystem == DepEcosystem::Cargo));
        assert!(react_entries
            .iter()
            .any(|d| d.ecosystem == DepEcosystem::Npm));
    }

    #[test]
    fn dep_key_helpers_support_new_and_legacy_formats() {
        let dep = DepEntry {
            ecosystem: DepEcosystem::Cargo,
            name: "serde".into(),
            version: DepVersion::Declared("1.0".into()),
            manifest: ManifestKind::CargoToml,
            dev: false,
        };

        assert_eq!(dep_record_key(&dep), "dep:cargo:serde");
        assert_eq!(dep_display_name_from_key("dep:cargo:serde"), "serde");
        assert_eq!(dep_display_name_from_key("dep:serde"), "serde");
        assert_eq!(
            parse_dep_key("dep:npm:react"),
            Some((Some(DepEcosystem::Npm), "react"))
        );
        assert_eq!(parse_dep_key("dep:serde"), Some((None, "serde")));
    }
}
