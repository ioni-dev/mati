//! CLAUDE.md import — parse sections into mati records (M-06-H).
//!
//! Reads a project's CLAUDE.md file, splits it by `## ` headings, and maps
//! each section to a [`Record`] with the correct [`Category`] based on the
//! heading text.
//!
//! Section-to-category mapping (from ARCHITECTURE.md §12.1):
//!
//! ```text
//! "## Gotchas" / "## Known Issues"          → Category::Gotcha
//! "## Architecture" / "## Overview"         → Category::DevNote
//! "## Decisions" / "## ADR"                 → Category::Decision
//! "## Current Sprint" / "## Status"         → Category::Stage
//! All others                                → Category::DevNote
//! ```
//!
//! Records use `RecordSource::Import` (confidence 0.70) and quality 0.50
//! (Acceptable) — human-written content that hasn't been through the quality
//! analyzer yet.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use uuid::Uuid;

use crate::store::record::{
    Category, ConfidenceScore, Priority, QualityScore, QualityTier, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore,
};

/// A section parsed from a CLAUDE.md file.
#[derive(Debug, Clone)]
pub struct ParsedSection {
    /// The `## ` heading text (without the `## ` prefix).
    pub heading: String,
    /// The body text below the heading (trimmed).
    pub body: String,
    /// Mapped category from the heading.
    pub category: Category,
}

/// Result of importing a CLAUDE.md file.
pub struct ClaudeMdImport {
    /// Records ready for `Store::put_batch`.
    pub records: Vec<Record>,
}

/// Parse a CLAUDE.md file and produce records from its sections.
///
/// Returns `Ok` with an empty `ClaudeMdImport` if the file doesn't exist.
/// Returns `Err` only on I/O errors other than not-found.
pub fn import_claude_md(
    path: &Path,
    device_id: Uuid,
    logical_clock_start: u64,
) -> Result<ClaudeMdImport> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ClaudeMdImport { records: vec![] });
        }
        Err(e) => return Err(e.into()),
    };

    let sections = parse_sections(&content);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let records: Vec<Record> = sections
        .iter()
        .filter(|s| !s.body.is_empty())
        .enumerate()
        .map(|(i, section)| {
            section_to_record(section, device_id, logical_clock_start + i as u64, now)
        })
        .collect();

    Ok(ClaudeMdImport { records })
}

/// Split markdown content into sections by `## ` headings.
///
/// The content before the first `## ` heading is ignored (typically the
/// `# Title` and introductory text).
fn parse_sections(content: &str) -> Vec<ParsedSection> {
    let mut sections = Vec::new();
    let mut current_heading: Option<String> = None;
    let mut current_body = String::new();

    for line in content.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            // Flush the previous section.
            if let Some(h) = current_heading.take() {
                let body = current_body.trim().to_string();
                let category = heading_to_category(&h);
                sections.push(ParsedSection {
                    heading: h,
                    body,
                    category,
                });
                current_body.clear();
            }
            current_heading = Some(heading.trim().to_string());
        } else if current_heading.is_some() {
            // Skip sub-headings (### etc) as section delimiters — they're
            // part of the current section's body.
            current_body.push_str(line);
            current_body.push('\n');
        }
    }

    // Flush the last section.
    if let Some(h) = current_heading {
        let body = current_body.trim().to_string();
        let category = heading_to_category(&h);
        sections.push(ParsedSection {
            heading: h,
            body,
            category,
        });
    }

    sections
}

/// Map a `## ` heading to a record category.
///
/// Matching is case-insensitive and uses keyword containment — "## Known
/// Gotchas and Issues" matches both "gotcha" and "issue" patterns.
fn heading_to_category(heading: &str) -> Category {
    let lower = heading.to_lowercase();

    if lower.contains("gotcha") || lower.contains("known issue") || lower.contains("known bug") {
        Category::Gotcha
    } else if lower.contains("decision") || lower.contains("adr") {
        Category::Decision
    } else if lower.contains("sprint") || lower.contains("status") || lower.contains("current stage") {
        Category::Stage
    } else {
        Category::DevNote
    }
}

/// Generate a record key from a section heading and category.
fn section_key(heading: &str, category: &Category) -> String {
    let prefix = match category {
        Category::Gotcha => "gotcha",
        Category::Decision => "decision",
        Category::Stage => "stage",
        Category::DevNote => "dev_note",
        _ => "dev_note",
    };

    // Slugify the heading: lowercase, replace non-alphanumeric with hyphens,
    // collapse runs of hyphens, trim leading/trailing hyphens.
    let slug: String = heading
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");

    format!("{prefix}:claude-md-{slug}")
}

/// Convert a parsed section into a Record.
fn section_to_record(
    section: &ParsedSection,
    device_id: Uuid,
    logical_clock: u64,
    now: u64,
) -> Record {
    let key = section_key(&section.heading, &section.category);

    Record {
        key,
        value: section.body.clone(),
        category: section.category.clone(),
        priority: match section.category {
            Category::Gotcha => Priority::High,
            Category::Decision => Priority::Normal,
            Category::Stage => Priority::Normal,
            _ => Priority::Normal,
        },
        tags: vec!["claude-md-import".to_string()],
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
        quality: QualityScore {
            value: 0.50,
            tier: QualityTier::Acceptable,
            signals: vec![],
            computed_at: now,
        },
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::Import,
        confidence: ConfidenceScore::for_new_record(&RecordSource::Import),
        gap_analysis_score: 0.0,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_sections ──────────────────────────────────────────────────────

    #[test]
    fn parse_sections_splits_by_h2() {
        let md = "\
# Title

Intro paragraph.

## Gotchas

Don't do X.

## Architecture

This is how it works.
";
        let sections = parse_sections(md);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].heading, "Gotchas");
        assert_eq!(sections[0].body, "Don't do X.");
        assert_eq!(sections[1].heading, "Architecture");
        assert!(sections[1].body.contains("This is how it works."));
    }

    #[test]
    fn parse_sections_ignores_content_before_first_h2() {
        let md = "\
# Project

Some intro.

More intro.

## First Section

Body here.
";
        let sections = parse_sections(md);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].heading, "First Section");
    }

    #[test]
    fn parse_sections_includes_h3_in_body() {
        let md = "\
## Overview

### Subsection

Detail here.
";
        let sections = parse_sections(md);
        assert_eq!(sections.len(), 1);
        assert!(sections[0].body.contains("### Subsection"));
        assert!(sections[0].body.contains("Detail here."));
    }

    #[test]
    fn parse_sections_empty_body_included() {
        let md = "\
## Empty

## Has Content

Real content.
";
        let sections = parse_sections(md);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].body, "");
        assert_eq!(sections[1].body, "Real content.");
    }

    #[test]
    fn parse_sections_no_h2_returns_empty() {
        let md = "# Title\n\nJust a title and body.\n";
        let sections = parse_sections(md);
        assert!(sections.is_empty());
    }

    // ── heading_to_category ─────────────────────────────────────────────────

    #[test]
    fn heading_gotchas_maps_to_gotcha() {
        assert_eq!(heading_to_category("Gotchas"), Category::Gotcha);
        assert_eq!(heading_to_category("Known Issues"), Category::Gotcha);
        assert_eq!(heading_to_category("Known Gotchas"), Category::Gotcha);
        assert_eq!(heading_to_category("known bug list"), Category::Gotcha);
    }

    #[test]
    fn heading_decisions_maps_to_decision() {
        assert_eq!(heading_to_category("Decisions"), Category::Decision);
        assert_eq!(heading_to_category("ADR"), Category::Decision);
        assert_eq!(heading_to_category("Architecture Decision Records"), Category::Decision);
    }

    #[test]
    fn heading_status_maps_to_stage() {
        assert_eq!(heading_to_category("Current Sprint"), Category::Stage);
        assert_eq!(heading_to_category("Status"), Category::Stage);
        assert_eq!(heading_to_category("Current Stage"), Category::Stage);
    }

    #[test]
    fn heading_other_maps_to_dev_note() {
        assert_eq!(heading_to_category("Architecture"), Category::DevNote);
        assert_eq!(heading_to_category("Overview"), Category::DevNote);
        assert_eq!(heading_to_category("Stack"), Category::DevNote);
        assert_eq!(heading_to_category("Random Section"), Category::DevNote);
    }

    #[test]
    fn heading_case_insensitive() {
        assert_eq!(heading_to_category("GOTCHAS"), Category::Gotcha);
        assert_eq!(heading_to_category("decisions"), Category::Decision);
        assert_eq!(heading_to_category("CURRENT SPRINT"), Category::Stage);
    }

    // ── section_key ─────────────────────────────────────────────────────────

    #[test]
    fn section_key_slugifies_heading() {
        assert_eq!(
            section_key("Known Gotchas", &Category::Gotcha),
            "gotcha:claude-md-known-gotchas"
        );
        assert_eq!(
            section_key("Architecture Decisions", &Category::Decision),
            "decision:claude-md-architecture-decisions"
        );
        assert_eq!(
            section_key("Current Stage", &Category::Stage),
            "stage:claude-md-current-stage"
        );
    }

    #[test]
    fn section_key_collapses_special_chars() {
        assert_eq!(
            section_key("What's New — v2.0", &Category::DevNote),
            "dev_note:claude-md-what-s-new-v2-0"
        );
    }

    // ── section_to_record ───────────────────────────────────────────────────

    #[test]
    fn section_to_record_has_correct_source_and_confidence() {
        let section = ParsedSection {
            heading: "Gotchas".to_string(),
            body: "Don't do X.".to_string(),
            category: Category::Gotcha,
        };
        let record = section_to_record(&section, Uuid::nil(), 1, 1000);

        assert_eq!(record.source, RecordSource::Import);
        assert_eq!(record.confidence.value, 0.70);
        assert_eq!(record.quality.value, 0.50);
        assert_eq!(record.quality.tier, QualityTier::Acceptable);
        assert_eq!(record.tags, vec!["claude-md-import"]);
    }

    #[test]
    fn gotcha_section_gets_high_priority() {
        let section = ParsedSection {
            heading: "Gotchas".to_string(),
            body: "Watch out.".to_string(),
            category: Category::Gotcha,
        };
        let record = section_to_record(&section, Uuid::nil(), 1, 1000);
        assert_eq!(record.priority, Priority::High);
    }

    #[test]
    fn decision_section_gets_normal_priority() {
        let section = ParsedSection {
            heading: "Decisions".to_string(),
            body: "We chose X.".to_string(),
            category: Category::Decision,
        };
        let record = section_to_record(&section, Uuid::nil(), 1, 1000);
        assert_eq!(record.priority, Priority::Normal);
    }

    // ── import_claude_md ────────────────────────────────────────────────────

    #[test]
    fn import_missing_file_returns_empty() {
        let result = import_claude_md(Path::new("/nonexistent/CLAUDE.md"), Uuid::nil(), 0);
        let import = result.unwrap();
        assert_eq!(import.records.len(), 0);
    }

    #[test]
    fn import_real_file_produces_records() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("CLAUDE.md");
        std::fs::write(
            &path,
            "\
# My Project

Intro.

## Gotchas

Never call foo() before bar().

## Decisions

We use SurrealKV for persistence.

## Current Stage

Building v0.1.

## Stack

Rust + tokio.
",
        )
        .unwrap();

        let import = import_claude_md(&path, Uuid::nil(), 100).unwrap();
        assert_eq!(import.records.len(), 4);

        // Check categories.
        assert_eq!(import.records[0].category, Category::Gotcha);
        assert_eq!(import.records[1].category, Category::Decision);
        assert_eq!(import.records[2].category, Category::Stage);
        assert_eq!(import.records[3].category, Category::DevNote);

        // Check keys use correct prefixes.
        assert!(import.records[0].key.starts_with("gotcha:claude-md-"));
        assert!(import.records[1].key.starts_with("decision:claude-md-"));
        assert!(import.records[2].key.starts_with("stage:claude-md-"));
        assert!(import.records[3].key.starts_with("dev_note:claude-md-"));

        // Check logical clocks are sequential.
        assert_eq!(import.records[0].version.logical_clock, 100);
        assert_eq!(import.records[1].version.logical_clock, 101);
        assert_eq!(import.records[2].version.logical_clock, 102);
        assert_eq!(import.records[3].version.logical_clock, 103);
    }

    #[test]
    fn import_skips_empty_sections() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("CLAUDE.md");
        std::fs::write(
            &path,
            "\
## Empty Section

## Has Content

Real content here.
",
        )
        .unwrap();

        let import = import_claude_md(&path, Uuid::nil(), 0).unwrap();
        assert_eq!(import.records.len(), 1);
        assert_eq!(import.records[0].value, "Real content here.");
    }
}
