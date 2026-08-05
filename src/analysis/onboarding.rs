//! Onboarding import (idea 2.2) — propose gotcha *candidates* by mining
//! artifacts that already exist in a repo: CODEOWNERS ownership rules and
//! load-bearing / security marker comments.
//!
//! Each candidate is a `confirmed: false` [`GotchaRecord`] stub
//! (`RecordSource::Import`) that surfaces in `mati review` for a developer to
//! approve — turning the blank-slate "confirm your gotchas" step into "here are
//! N candidates we found." This module is **pure**: parsing and record
//! construction take string content and emit [`Record`]s; file discovery and
//! store I/O live in the `mati suggest` CLI command.

use globset::{GlobBuilder, GlobSetBuilder};
use uuid::Uuid;

use crate::store::record::{
    Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, QualityTier, Record,
    RecordSource,
};

/// Load-bearing / security markers we treat as strong, unambiguous signals.
/// Deliberately narrow (no `TODO`/`FIXME`/`HACK`) to keep candidate quality high.
const MARKERS: &[&str] = &[
    "DO NOT REMOVE",
    "DO NOT EDIT",
    "DO NOT MODIFY",
    "DO NOT DELETE",
    "SECURITY:",
    "SECURITY-CRITICAL",
];

/// Skip lines longer than this (minified / generated) to limit false positives.
const MAX_LINE_LEN: usize = 400;

/// Cap total marker candidates so a large repo can't flood `mati review`.
pub const MAX_MARKER_CANDIDATES: usize = 200;

/// Cap the number of concrete files attached to one CODEOWNERS candidate.
pub const MAX_CODEOWNERS_AFFECTED_FILES: usize = 50;

// ── CODEOWNERS ────────────────────────────────────────────────────────────────

/// A parsed CODEOWNERS entry: a path pattern and its owners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerRule {
    pub pattern: String,
    pub owners: Vec<String>,
}

/// Parse CODEOWNERS content into `(pattern, owners)` rules. Ignores comments
/// (`#`) and blank lines; a valid line is `<pattern> <owner...>` with ≥1 owner.
pub fn parse_codeowners(content: &str) -> Vec<OwnerRule> {
    let mut rules = Vec::new();
    for raw in content.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(pattern) = parts.next() else {
            continue;
        };
        let owners: Vec<String> = parts.map(str::to_string).collect();
        if owners.is_empty() {
            continue;
        }
        rules.push(OwnerRule {
            pattern: pattern.to_string(),
            owners,
        });
    }
    rules
}

// ── Marker comments ───────────────────────────────────────────────────────────

/// A marker-comment hit in a source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerHit {
    pub path: String,
    pub line: usize,
    pub marker: String,
    pub text: String,
}

/// Scan one file's content for load-bearing / security markers (case-insensitive).
pub fn scan_markers(path: &str, content: &str) -> Vec<MarkerHit> {
    let mut hits = Vec::new();
    for (i, raw) in content.lines().enumerate() {
        if raw.len() > MAX_LINE_LEN {
            continue;
        }
        let upper = raw.to_uppercase();
        if let Some(marker) = MARKERS.iter().find(|m| upper.contains(**m)) {
            hits.push(MarkerHit {
                path: path.to_string(),
                line: i + 1,
                marker: (*marker).to_string(),
                text: raw.trim().to_string(),
            });
        }
    }
    hits
}

// ── Candidate record construction ─────────────────────────────────────────────

/// Build one `confirmed: false` gotcha candidate Record. Mirrors the Layer-0
/// stub pattern used by `init`'s git-signal candidates.
#[allow(clippy::too_many_arguments)]
fn candidate_record(
    key: String,
    rule: String,
    reason: String,
    severity: Priority,
    affected_files: Vec<String>,
    tags: Vec<String>,
    device_id: Uuid,
    logical_clock: u64,
    now: u64,
) -> Record {
    let gotcha = GotchaRecord {
        rule: rule.clone(),
        reason,
        severity: severity.clone(),
        affected_files,
        ref_url: None,
        discovered_session: now,
        confirmed: false,
        confirmed_content: Default::default(),
    };
    let mut rec = Record::layer0_file_stub(&key, device_id, logical_clock, now);
    rec.category = Category::Gotcha;
    rec.source = RecordSource::Import;
    rec.priority = severity;
    rec.value = rule;
    rec.quality = QualityScore {
        value: 0.50,
        tier: QualityTier::Acceptable,
        signals: vec![],
        computed_at: now,
    };
    // `for_new_record(Import)` sits below the 0.80 "confirmed" floor, so the
    // stub stays a candidate until a developer confirms it.
    rec.confidence = ConfidenceScore::for_new_record(&RecordSource::Import);
    rec.tags = tags;
    rec.payload = serde_json::to_value(&gotcha).ok();
    rec
}

/// Translate a CODEOWNERS pattern into a glob. Gitignore semantics: a leading
/// `/` only anchors, a trailing `/` means "everything under", and a pattern
/// with no `/` at all matches at any depth.
fn codeowners_glob_pattern(pattern: &str) -> String {
    let pattern = pattern.strip_prefix('/').unwrap_or(pattern);
    if pattern == "*" {
        return "**".to_string();
    }
    if pattern.ends_with('/') {
        return format!("{pattern}**");
    }
    if pattern.contains('/') {
        pattern.to_string()
    } else {
        format!("**/{pattern}")
    }
}

/// Expand one CODEOWNERS pattern into the concrete repo-relative paths it
/// owns. `None` when nothing matches or the match set exceeds
/// [`MAX_CODEOWNERS_AFFECTED_FILES`] — both mean "not a per-file gotcha".
pub(crate) fn expand_codeowners_pattern(
    pattern: &str,
    repo_files: &[String],
) -> Option<Vec<String>> {
    // A pattern that names a directory owns everything under it, and nothing
    // in the pattern says which it is — so match the path and its subtree.
    let base = codeowners_glob_pattern(pattern);
    let subtree = format!("{base}/**");
    let mut builder = GlobSetBuilder::new();
    for expr in [base.as_str(), subtree.as_str()] {
        builder.add(
            GlobBuilder::new(expr)
                .literal_separator(false)
                .build()
                .ok()?,
        );
    }
    let globset = builder.build().ok()?;

    let mut matches: Vec<String> = repo_files
        .iter()
        .filter(|path| globset.is_match(path))
        .cloned()
        .collect();
    matches.sort();
    matches.dedup();
    if matches.is_empty() || matches.len() > MAX_CODEOWNERS_AFFECTED_FILES {
        None
    } else {
        Some(matches)
    }
}

/// Candidate records from CODEOWNERS rules (ownership coordination gotchas).
/// A rule whose pattern does not expand to a bounded set of real files is
/// dropped: `affected_files` must hold paths the `file:*` index can match.
pub fn codeowners_candidates(
    rules: &[OwnerRule],
    repo_files: &[String],
    device_id: Uuid,
    clock_start: u64,
    now: u64,
) -> Vec<Record> {
    rules
        .iter()
        .enumerate()
        .filter_map(|(i, r)| {
            let affected_files = expand_codeowners_pattern(&r.pattern, repo_files)?;
            let owners = r.owners.join(", ");
            let rule = format!(
                "`{}` is owned by {} (CODEOWNERS) — coordinate changes with them.",
                r.pattern, owners
            );
            let reason = format!("Listed in CODEOWNERS: {} → {}.", r.pattern, owners);
            let key = format!("gotcha:codeowners:{}", r.pattern);
            Some(candidate_record(
                key,
                rule,
                reason,
                Priority::Normal,
                affected_files,
                vec!["codeowners".into(), "auto-generated".into()],
                device_id,
                clock_start + i as u64,
                now,
            ))
        })
        .collect()
}

/// Candidate records from marker hits (capped at [`MAX_MARKER_CANDIDATES`]).
pub fn marker_candidates(
    hits: &[MarkerHit],
    device_id: Uuid,
    clock_start: u64,
    now: u64,
) -> Vec<Record> {
    hits.iter()
        .take(MAX_MARKER_CANDIDATES)
        .enumerate()
        .map(|(i, h)| {
            let rule = format!(
                "`{}` carries a `{}` marker at line {} — preserve it through edits.",
                h.path, h.marker, h.line
            );
            let reason = format!("Developer marker in source: {}", h.text);
            let key = format!("gotcha:marker:{}:{}", h.path, h.line);
            // Load-bearing / security markers are high severity by definition.
            candidate_record(
                key,
                rule,
                reason,
                Priority::High,
                vec![h.path.clone()],
                vec!["code-marker".into(), "auto-generated".into()],
                device_id,
                clock_start + i as u64,
                now,
            )
        })
        .collect()
}

/// Build all onboarding candidates from already-read artifact content. Pure:
/// `codeowners` is the CODEOWNERS file content (if found) and `files` is a list
/// of `(repo-relative path, content)` pairs to scan for markers.
pub fn build_candidates(
    codeowners: Option<&str>,
    files: &[(String, String)],
    device_id: Uuid,
    clock_start: u64,
    now: u64,
) -> Vec<Record> {
    let mut out = Vec::new();
    let mut clock = clock_start;

    if let Some(content) = codeowners {
        let rules = parse_codeowners(content);
        let repo_files: Vec<String> = files.iter().map(|(path, _)| path.clone()).collect();
        let recs = codeowners_candidates(&rules, &repo_files, device_id, clock, now);
        // Clocks are assigned by rule index, so skipped rules leave gaps —
        // advance past every rule, not just the ones that produced a record.
        clock += rules.len() as u64;
        out.extend(recs);
    }

    let mut hits = Vec::new();
    for (path, content) in files {
        hits.extend(scan_markers(path, content));
    }
    out.extend(marker_candidates(&hits, device_id, clock, now));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev() -> Uuid {
        Uuid::nil()
    }

    fn is_unconfirmed_gotcha(rec: &Record) -> bool {
        rec.category == Category::Gotcha
            && rec.source == RecordSource::Import
            && rec
                .payload
                .as_ref()
                .and_then(|p| serde_json::from_value::<GotchaRecord>(p.clone()).ok())
                .is_some_and(|g| !g.confirmed)
    }

    #[test]
    fn parse_codeowners_ignores_comments_and_blank_and_ownerless() {
        let content = "\
# comment\n\
\n\
src/payments/** @pay-team @alice\n\
docs/   # trailing comment\n\
*.rs @rustfolk\n";
        let rules = parse_codeowners(content);
        assert_eq!(rules.len(), 2, "ownerless `docs/` line is skipped");
        assert_eq!(rules[0].pattern, "src/payments/**");
        assert_eq!(rules[0].owners, vec!["@pay-team", "@alice"]);
        assert_eq!(rules[1].pattern, "*.rs");
    }

    #[test]
    fn scan_markers_is_case_insensitive_and_skips_long_lines() {
        let content = "\
let x = 1;\n\
// do not remove: load-bearing init order\n\
// SECURITY: validate before deref\n\
let normal = 2;\n";
        let hits = scan_markers("src/lib.rs", content);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].marker, "DO NOT REMOVE");
        assert_eq!(hits[0].line, 2);
        assert_eq!(hits[1].marker, "SECURITY:");

        // Over-long (minified) lines are skipped.
        let long = format!("// DO NOT REMOVE {}", "x".repeat(MAX_LINE_LEN));
        assert!(scan_markers("min.js", &long).is_empty());
    }

    #[test]
    fn codeowners_candidates_are_unconfirmed_gotchas_keyed_by_pattern() {
        let rules = parse_codeowners("src/payments/** @pay-team\n");
        let repo_files = vec![
            "src/payments/card.rs".to_string(),
            "src/payments/wallet.rs".to_string(),
        ];
        let recs = codeowners_candidates(&rules, &repo_files, dev(), 0, 100);
        assert_eq!(recs.len(), 1);
        assert!(is_unconfirmed_gotcha(&recs[0]));
        assert_eq!(recs[0].key, "gotcha:codeowners:src/payments/**");
        let g: GotchaRecord = serde_json::from_value(recs[0].payload.clone().unwrap()).unwrap();
        assert_eq!(
            g.affected_files,
            vec![
                "src/payments/card.rs".to_string(),
                "src/payments/wallet.rs".to_string()
            ]
        );
        assert!(!g.confirmed);
    }

    #[test]
    fn codeowners_patterns_translate_to_globs() {
        let cases = [
            ("*", "**"),
            ("docs/", "docs/**"),
            ("/build/logs/", "build/logs/**"),
            ("src/payments/**", "src/payments/**"),
            ("*.js", "**/*.js"),
            ("docs/API.md", "docs/API.md"),
        ];
        for (pattern, expected) in cases {
            assert_eq!(codeowners_glob_pattern(pattern), expected);
        }
    }

    #[test]
    fn codeowners_expansion_matches_scoped_paths_and_skips_empty() {
        let files = vec![
            "docs/API.md".to_string(),
            "docs/guide.md".to_string(),
            "src/docs/guide.md".to_string(),
            "src/main.rs".to_string(),
        ];
        assert_eq!(
            expand_codeowners_pattern("docs/", &files),
            Some(vec!["docs/API.md".to_string(), "docs/guide.md".to_string()])
        );
        assert_eq!(expand_codeowners_pattern("missing/*.rs", &files), None);
        // A bare name carries no trailing slash, but still owns its subtree —
        // and, being unanchored, every `docs` directory at any depth.
        assert_eq!(
            expand_codeowners_pattern("docs", &files),
            Some(vec![
                "docs/API.md".to_string(),
                "docs/guide.md".to_string(),
                "src/docs/guide.md".to_string()
            ])
        );
        let rules = parse_codeowners("missing/*.rs @team\n");
        assert!(codeowners_candidates(&rules, &files, dev(), 0, 100).is_empty());
    }

    #[test]
    fn codeowners_expansion_skips_over_cap_and_repo_wide_star() {
        let files: Vec<String> = (0..=MAX_CODEOWNERS_AFFECTED_FILES)
            .map(|i| format!("src/f{i}.rs"))
            .collect();
        assert_eq!(expand_codeowners_pattern("src/**", &files), None);
        assert_eq!(expand_codeowners_pattern("*", &files), None);
        let over_cap = parse_codeowners("src/** @team\n");
        let repo_wide = parse_codeowners("* @team\n");
        assert!(codeowners_candidates(&over_cap, &files, dev(), 0, 100).is_empty());
        assert!(codeowners_candidates(&repo_wide, &files, dev(), 0, 100).is_empty());
    }

    #[test]
    fn marker_candidates_cap_and_key_format() {
        // Build more hits than the cap.
        let hits: Vec<MarkerHit> = (0..MAX_MARKER_CANDIDATES + 50)
            .map(|i| MarkerHit {
                path: format!("src/f{i}.rs"),
                line: i + 1,
                marker: "DO NOT REMOVE".into(),
                text: "// DO NOT REMOVE".into(),
            })
            .collect();
        let recs = marker_candidates(&hits, dev(), 0, 100);
        assert_eq!(recs.len(), MAX_MARKER_CANDIDATES, "capped");
        assert_eq!(recs[0].key, "gotcha:marker:src/f0.rs:1");
        assert_eq!(recs[0].priority, Priority::High);
        assert!(is_unconfirmed_gotcha(&recs[0]));
    }

    #[test]
    fn build_candidates_combines_both_sources() {
        let files = vec![(
            "src/auth.rs".to_string(),
            "// SECURITY: constant-time compare\n".to_string(),
        )];
        let recs = build_candidates(Some("src/** @team\n"), &files, dev(), 0, 100);
        assert_eq!(recs.len(), 2);
        assert!(recs.iter().all(is_unconfirmed_gotcha));
        assert!(recs.iter().any(|r| r.key.starts_with("gotcha:codeowners:")));
        assert!(recs.iter().any(|r| r.key.starts_with("gotcha:marker:")));
        // Logical clocks are distinct (no collisions across sources).
        let clocks: std::collections::HashSet<u64> =
            recs.iter().map(|r| r.version.logical_clock).collect();
        assert_eq!(clocks.len(), recs.len());

        let codeowners = recs
            .iter()
            .find(|r| r.key == "gotcha:codeowners:src/**")
            .unwrap();
        let gotcha: GotchaRecord =
            serde_json::from_value(codeowners.payload.clone().unwrap()).unwrap();
        assert_eq!(gotcha.affected_files, vec!["src/auth.rs"]);
    }
}
