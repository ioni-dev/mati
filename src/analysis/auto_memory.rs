//! Auto-memory import — parse Claude Code's per-project memory directory
//! into gotcha candidates (F10).
//!
//! Claude Code writes free-form notes to
//! `~/.claude/projects/<project-slug>/memory/`: an index file `MEMORY.md`
//! plus one `.md` file per memory, each with `---`-delimited frontmatter and
//! a markdown body. That channel is model-authored, unconfirmed, and
//! unscored — this module turns each memory file into a `confirmed: false`
//! gotcha candidate that flows through `mati review` like any other Layer 0
//! stub. It never writes back to the source directory.
//!
//! The frontmatter shape below was read directly off this project's own
//! memory directory, not off any spec:
//!
//! ```text
//! ---
//! name: project-store-daemon-single-owner
//! description: "Store/daemon single-owner invariant: defect found ..."
//! metadata:
//!   node_type: memory
//!   type: project
//!   originSessionId: 95126fa6-3d8c-49e1-90de-ca652782c6d1
//!   modified: 2026-08-02T03:33:27.084Z
//! ---
//!
//! body markdown...
//! ```
//!
//! `modified` and `originSessionId` are sometimes absent (older memories
//! predate those fields). Frontmatter is parsed by hand instead of pulling
//! in a YAML crate — the shape is a handful of flat `key: value` lines plus
//! one nested `metadata:` block, and the format is unversioned upstream, so
//! unrecognized keys are ignored rather than rejected. A file this parser
//! can't make sense of is skipped, not dropped silently — see
//! [`AutoMemoryImport::skipped_files`].

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use slugify::slugify;

use crate::store::record::{
    Category, ConfidenceScore, DeviceId, GotchaRecord, Priority, QualityScore, Record,
    RecordLifecycle, RecordSource, RecordVersion, StalenessScore,
};

/// Result of importing a project's auto-memory directory.
pub struct AutoMemoryImport {
    /// One `gotcha:auto-memory-*` candidate record per memory file that
    /// parsed cleanly.
    pub records: Vec<Record>,
    /// Files that could not be read or carried no usable content, paired
    /// with a human-readable reason. Never aborts the run.
    pub skipped_files: Vec<(PathBuf, String)>,
}

/// Locate `~/.claude/projects/<project-slug>/memory/` for a project root.
///
/// The slug is Claude Code's own directory naming: the project's absolute
/// path with every `/` replaced by `-` (verified against this project's own
/// `~/.claude/projects/-Users-...-mati/` directory). `project_root` is
/// expected to already be absolute (callers pass `std::env::current_dir()`);
/// this does not canonicalize or resolve symlinks, so a path Claude Code saw
/// through a different symlink alias would miss.
pub fn auto_memory_dir(project_root: &Path) -> Result<PathBuf> {
    let slug = project_root.to_string_lossy().replace('/', "-");
    let home = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine home directory (HOME not set)"))?;
    Ok(home
        .join(".claude")
        .join("projects")
        .join(slug)
        .join("memory"))
}

/// Parse every memory file in `dir` into a gotcha-candidate record.
///
/// Returns an empty result (not an error) if `dir` doesn't exist — no
/// auto-memory directory is a normal state, not a failure. `MEMORY.md`
/// itself is the index and is skipped, not parsed as a memory.
pub fn import_auto_memory(
    dir: &Path,
    device_id: DeviceId,
    logical_clock_start: u64,
) -> Result<AutoMemoryImport> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AutoMemoryImport {
                records: vec![],
                skipped_files: vec![],
            });
        }
        Err(e) => return Err(e.into()),
    };

    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().and_then(|e| e.to_str()) == Some("md")
                && p.file_name().and_then(|n| n.to_str()) != Some("MEMORY.md")
        })
        .collect();
    // Deterministic order: directory iteration order is unspecified, and
    // stable output makes a re-run diffable and this module's tests reliable.
    paths.sort();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut records = Vec::with_capacity(paths.len());
    let mut skipped_files = Vec::new();
    let mut clock = logical_clock_start;

    for path in &paths {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                skipped_files.push((path.clone(), e.to_string()));
                continue;
            }
        };
        match parse_memory_file(&content) {
            Some(parsed) => {
                records.push(memory_to_record(&parsed, path, device_id, clock, now));
                clock += 1;
            }
            None => skipped_files.push((
                path.clone(),
                "no frontmatter description and no body content".to_string(),
            )),
        }
    }

    Ok(AutoMemoryImport {
        records,
        skipped_files,
    })
}

// ── Frontmatter parsing ──────────────────────────────────────────────────────

struct ParsedMemory {
    name: Option<String>,
    description: Option<String>,
    memo_type: Option<String>,
    body: String,
}

/// Parse one memory file's frontmatter + body.
///
/// Returns `None` when there is nothing worth writing: no description and
/// an empty body. Missing or malformed frontmatter degrades to "no name, no
/// description" rather than failing outright — the body still carries the
/// note.
fn parse_memory_file(content: &str) -> Option<ParsedMemory> {
    let (frontmatter, body) = split_frontmatter(content);
    let body = body.trim().to_string();

    let mut name = None;
    let mut description = None;
    let mut memo_type = None;

    if let Some(fm) = frontmatter {
        for line in fm.lines() {
            if line.starts_with(char::is_whitespace) {
                // Nested block (currently only `metadata:`). The only
                // sub-key this importer reads is `type` — the rest
                // (node_type, originSessionId, modified) don't map to
                // anything a gotcha candidate carries.
                if let Some((key, val)) = split_yaml_kv(line.trim_start()) {
                    if key == "type" {
                        memo_type = Some(val);
                    }
                }
                continue;
            }
            if let Some((key, val)) = split_yaml_kv(line) {
                match key.as_str() {
                    "name" => name = Some(val),
                    "description" => description = Some(val),
                    _ => {} // unknown top-level key — ignore, don't reject the file
                }
            }
        }
    }

    if description.as_deref().unwrap_or("").trim().is_empty() && body.is_empty() {
        return None;
    }

    Some(ParsedMemory {
        name,
        description,
        memo_type,
        body,
    })
}

/// Split `---`-delimited frontmatter from the body.
///
/// Returns `(None, content)` unchanged if the file doesn't open with a
/// `---` line, or if no closing `---` is found (malformed frontmatter) — in
/// both cases the whole file is treated as body text rather than discarded.
fn split_frontmatter(content: &str) -> (Option<String>, String) {
    let mut lines = content.lines();
    match lines.next() {
        Some("---") => {}
        _ => return (None, content.to_string()),
    }

    let mut fm_lines = Vec::new();
    let mut closed = false;
    for line in lines.by_ref() {
        if line == "---" {
            closed = true;
            break;
        }
        fm_lines.push(line);
    }

    if !closed {
        return (None, content.to_string());
    }

    let body: Vec<&str> = lines.collect();
    (Some(fm_lines.join("\n")), body.join("\n"))
}

/// Split a single frontmatter line into `key`/`value`, unquoting the value
/// if it's YAML double-quoted. Returns `None` for lines with no value (e.g.
/// `metadata:`, which just opens a nested block).
fn split_yaml_kv(line: &str) -> Option<(String, String)> {
    let (key, rest) = line.split_once(':')?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    let val = rest.trim();
    if val.is_empty() {
        return None;
    }
    Some((key.to_string(), unquote_yaml_value(val)))
}

/// Strip a YAML double-quoted value and unescape `\"`.
///
/// Values are single-line in every sample this was built against — a
/// frontmatter description containing a literal `:` (which would otherwise
/// break `split_yaml_kv`'s first-colon split) is exactly why the real files
/// quote it, e.g. `"Store/daemon single-owner invariant: defect found..."`.
fn unquote_yaml_value(val: &str) -> String {
    if val.len() >= 2 && val.starts_with('"') && val.ends_with('"') {
        val[1..val.len() - 1].replace("\\\"", "\"")
    } else {
        val.to_string()
    }
}

// ── Record construction ──────────────────────────────────────────────────────

fn memory_to_record(
    parsed: &ParsedMemory,
    path: &Path,
    device_id: DeviceId,
    logical_clock: u64,
    now: u64,
) -> Record {
    let file_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("memory");
    let base_name = parsed
        .name
        .clone()
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| file_stem.to_string());
    let slug = slugify!(&base_name, max_length = 60);
    let key = format!("gotcha:auto-memory-{slug}");

    let (rule, reason) = rule_and_reason(parsed);

    let value = if reason.is_empty() {
        rule.clone()
    } else {
        format!("{rule} because {reason}")
    };

    let mut tags = vec!["source:auto-memory".to_string()];
    if let Some(t) = parsed.memo_type.as_deref().filter(|t| !t.is_empty()) {
        tags.push(format!("auto-memory:{t}"));
    }

    let gotcha = GotchaRecord {
        rule,
        reason,
        severity: Priority::Normal,
        affected_files: vec![],
        ref_url: None,
        discovered_session: 0,
        confirmed: false,
        confirmed_content: Default::default(),
    };

    let mut record = Record {
        key,
        value,
        category: Category::Gotcha,
        priority: Priority::Normal,
        tags,
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id,
            logical_clock,
            wall_clock: now,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::Import,
        confidence: ConfidenceScore::for_new_record(&RecordSource::Import),
        gap_analysis_score: 0.0,
        payload: serde_json::to_value(&gotcha).ok(),
    };
    record.quality = crate::health::quality::analyze(&record);
    record
}

/// Prefer the frontmatter description as the rule (it already reads like a
/// summary in every sample) with the full body as the reason. Falls back to
/// the body's first non-empty line when there's no description at all.
fn rule_and_reason(parsed: &ParsedMemory) -> (String, String) {
    if let Some(d) = parsed.description.as_ref().filter(|d| !d.trim().is_empty()) {
        return (d.clone(), parsed.body.clone());
    }

    let mut lines = parsed.body.lines();
    let first = lines
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
        .to_string();
    let rest = lines.collect::<Vec<_>>().join("\n").trim().to_string();

    if first.is_empty() {
        ("untitled auto-memory note".to_string(), rest)
    } else {
        (first, rest)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
---
name: project-ci-unavailable
description: \"GitHub Actions minutes are exhausted and won't be renewed — local gates are the only validation\"
metadata:
  node_type: memory
  type: project
  originSessionId: 1a0cfc6e-b7d8-458a-b26b-fb6c9f69100f
  modified: 2026-08-07T01:13:09.131Z
---

As of 2026-08-04 the mati repo's GitHub Actions quota is exhausted.

**Why:** deliberate cost decision.
";

    // ── split_frontmatter ────────────────────────────────────────────────────

    #[test]
    fn split_frontmatter_extracts_both_parts() {
        let (fm, body) = split_frontmatter(SAMPLE);
        let fm = fm.expect("frontmatter present");
        assert!(fm.contains("name: project-ci-unavailable"));
        assert!(fm.contains("  type: project"));
        assert!(body.trim_start().starts_with("As of 2026-08-04"));
        assert!(body.contains("**Why:**"));
    }

    #[test]
    fn split_frontmatter_missing_delimiter_returns_whole_file_as_body() {
        let content = "Just a plain note, no frontmatter.\nSecond line.";
        let (fm, body) = split_frontmatter(content);
        assert!(fm.is_none());
        assert_eq!(body, content);
    }

    #[test]
    fn split_frontmatter_unclosed_block_returns_whole_file_as_body() {
        let content = "---\nname: broken\nno closing delimiter here";
        let (fm, body) = split_frontmatter(content);
        assert!(fm.is_none());
        assert_eq!(body, content);
    }

    // ── split_yaml_kv / unquote_yaml_value ──────────────────────────────────

    #[test]
    fn split_yaml_kv_unquoted() {
        let (k, v) = split_yaml_kv("name: project-ci-unavailable").unwrap();
        assert_eq!(k, "name");
        assert_eq!(v, "project-ci-unavailable");
    }

    #[test]
    fn split_yaml_kv_quoted_with_embedded_colon() {
        let (k, v) = split_yaml_kv(
            "description: \"Store/daemon single-owner invariant: defect found 2026-07-23\"",
        )
        .unwrap();
        assert_eq!(k, "description");
        assert_eq!(
            v,
            "Store/daemon single-owner invariant: defect found 2026-07-23"
        );
    }

    #[test]
    fn split_yaml_kv_quoted_with_escaped_quotes() {
        let (k, v) =
            split_yaml_kv("description: \"do not \\\"fix\\\" them without asking\"").unwrap();
        assert_eq!(k, "description");
        assert_eq!(v, "do not \"fix\" them without asking");
    }

    #[test]
    fn split_yaml_kv_nested_block_opener_has_no_value() {
        assert!(split_yaml_kv("metadata: ").is_none());
        assert!(split_yaml_kv("metadata:").is_none());
    }

    // ── parse_memory_file ────────────────────────────────────────────────────

    #[test]
    fn parse_memory_file_reads_name_description_type_and_body() {
        let parsed = parse_memory_file(SAMPLE).expect("sample parses");
        assert_eq!(parsed.name.as_deref(), Some("project-ci-unavailable"));
        assert_eq!(
            parsed.description.as_deref(),
            Some("GitHub Actions minutes are exhausted and won't be renewed — local gates are the only validation")
        );
        assert_eq!(parsed.memo_type.as_deref(), Some("project"));
        assert!(parsed.body.contains("**Why:**"));
    }

    #[test]
    fn parse_memory_file_no_frontmatter_still_uses_body() {
        let parsed = parse_memory_file("Just a plain note with real content.")
            .expect("body-only content still parses");
        assert!(parsed.name.is_none());
        assert!(parsed.description.is_none());
        assert_eq!(parsed.body, "Just a plain note with real content.");
    }

    #[test]
    fn parse_memory_file_empty_everything_is_none() {
        let content = "---\nname: empty\n---\n\n";
        assert!(parse_memory_file(content).is_none());
    }

    #[test]
    fn parse_memory_file_unknown_frontmatter_keys_are_ignored() {
        let content = "\
---
name: has-extra-field
description: \"a real description\"
future_field: something new upstream added
---

body text here
";
        let parsed = parse_memory_file(content).expect("unknown keys don't reject the file");
        assert_eq!(parsed.description.as_deref(), Some("a real description"));
    }

    // ── rule_and_reason ──────────────────────────────────────────────────────

    #[test]
    fn rule_and_reason_prefers_description() {
        let parsed = ParsedMemory {
            name: None,
            description: Some("Do the thing.".to_string()),
            memo_type: None,
            body: "Full body text.".to_string(),
        };
        let (rule, reason) = rule_and_reason(&parsed);
        assert_eq!(rule, "Do the thing.");
        assert_eq!(reason, "Full body text.");
    }

    #[test]
    fn rule_and_reason_falls_back_to_first_body_line() {
        let parsed = ParsedMemory {
            name: None,
            description: None,
            memo_type: None,
            body: "First line is the rule.\nRest is reason.\nMore reason.".to_string(),
        };
        let (rule, reason) = rule_and_reason(&parsed);
        assert_eq!(rule, "First line is the rule.");
        assert_eq!(reason, "Rest is reason.\nMore reason.");
    }

    // ── memory_to_record / import_auto_memory ───────────────────────────────

    #[test]
    fn memory_to_record_is_unconfirmed_and_tagged() {
        let parsed = parse_memory_file(SAMPLE).unwrap();
        let record = memory_to_record(
            &parsed,
            Path::new("/home/x/.claude/projects/foo/memory/project_ci_unavailable.md"),
            uuid::Uuid::nil(),
            1,
            1000,
        );
        assert_eq!(record.category, Category::Gotcha);
        assert!(record.key.starts_with("gotcha:auto-memory-"));
        assert!(record.tags.contains(&"source:auto-memory".to_string()));
        assert!(record.tags.contains(&"auto-memory:project".to_string()));

        let gotcha: GotchaRecord = record.payload_as().expect("GotchaRecord payload");
        assert!(
            !gotcha.confirmed,
            "auto-memory import must never auto-confirm"
        );
        assert!(gotcha.affected_files.is_empty());
    }

    #[test]
    fn import_auto_memory_missing_dir_returns_empty_not_error() {
        let result = import_auto_memory(Path::new("/nonexistent/memory/dir"), uuid::Uuid::nil(), 0);
        let import = result.unwrap();
        assert!(import.records.is_empty());
        assert!(import.skipped_files.is_empty());
    }

    #[test]
    fn import_auto_memory_skips_index_and_malformed_but_keeps_going() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("MEMORY.md"), "- [Title](x.md) — desc\n").unwrap();
        std::fs::write(dir.path().join("good.md"), SAMPLE).unwrap();
        std::fs::write(dir.path().join("empty.md"), "---\nname: empty\n---\n\n").unwrap();

        let import = import_auto_memory(dir.path(), uuid::Uuid::nil(), 0).unwrap();
        assert_eq!(
            import.records.len(),
            1,
            "MEMORY.md excluded, empty.md skipped"
        );
        assert_eq!(import.skipped_files.len(), 1);
        assert_eq!(import.skipped_files[0].0.file_name().unwrap(), "empty.md");
    }

    #[test]
    fn import_auto_memory_unreadable_file_is_skipped_not_fatal() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("good.md"), SAMPLE).unwrap();
        // A directory with a .md extension can't be read_to_string'd —
        // simulates an unreadable/corrupt entry without touching permissions.
        std::fs::create_dir(dir.path().join("bad.md")).unwrap();

        let import = import_auto_memory(dir.path(), uuid::Uuid::nil(), 0).unwrap();
        assert_eq!(import.records.len(), 1);
        assert_eq!(import.skipped_files.len(), 1);
    }

    #[test]
    fn auto_memory_dir_replaces_slashes_with_dashes() {
        // Matches this project's own observed directory:
        // ~/.claude/projects/-Users-ioni-Documents-Tools-projects-mati-projects-mati/memory/
        let home = dirs::home_dir().unwrap();
        let dir = auto_memory_dir(Path::new(
            "/Users/ioni/Documents/Tools-projects/mati-projects/mati",
        ))
        .unwrap();
        assert_eq!(
            dir,
            home.join(".claude")
                .join("projects")
                .join("-Users-ioni-Documents-Tools-projects-mati-projects-mati")
                .join("memory")
        );
    }
}
