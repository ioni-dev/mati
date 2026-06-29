//! `mati search <terms>` (idea 2.1) — keyword search across the knowledge base
//! (gotchas, decisions, notes, files, stages).
//!
//! Scan-based and **always fresh**: it reads current records and ranks them by a
//! simple term-frequency score, with no dependency on the daemon's lazily-built
//! search index (which can lag, and is built only on MCP-server startup).
//! Matching is case-insensitive keyword/substring (no stemming); reusing the
//! `crate::search` FTS engine for stemming/ranking is a possible future upgrade.

use anyhow::Result;
use clap::Args;

use mati_core::store::record::{Category, Record};

use crate::cli::proxy::StoreProxy;

/// Record key prefixes that hold searchable knowledge (one tree each — see
/// `store::db`). Hardcoded because they are a stable, frozen part of the schema.
const RECORD_PREFIXES: &[&str] = &["gotcha:", "decision:", "dev_note:", "file:", "stage:"];

#[derive(Args)]
pub struct SearchArgs {
    /// Search terms (matched case-insensitively across key, text, and tags)
    #[arg(required = true)]
    pub query: Vec<String>,

    /// Maximum number of results
    #[arg(long, short = 'n', default_value_t = 20)]
    pub limit: usize,

    /// Restrict to one category (gotcha, decision, dev_note, file, stage)
    #[arg(long)]
    pub category: Option<String>,

    /// Emit JSON instead of the human view
    #[arg(long)]
    pub json: bool,
}

pub async fn run(args: SearchArgs) -> Result<()> {
    let terms: Vec<String> = args
        .query
        .iter()
        .flat_map(|q| q.split_whitespace())
        .map(str::to_lowercase)
        .collect();
    if terms.is_empty() {
        anyhow::bail!("provide one or more search terms, e.g. `mati search fraud check`");
    }

    let prefixes = resolve_prefixes(args.category.as_deref())?;

    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let mut records = Vec::new();
    for prefix in &prefixes {
        records.extend(proxy.scan_prefix(prefix).await?);
    }

    let mut scored: Vec<(u32, Record)> = records
        .into_iter()
        .filter_map(|r| {
            let s = score(&r, &terms);
            (s > 0).then_some((s, r))
        })
        .collect();
    // Highest score first; ties broken by key for deterministic output.
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.key.cmp(&b.1.key)));
    scored.truncate(args.limit);

    if args.json {
        let out: Vec<_> = scored
            .iter()
            .map(|(s, r)| {
                serde_json::json!({
                    "score": s,
                    "key": r.key,
                    "category": r.category,
                    "value": r.value,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let joined = terms.join(" ");
    if scored.is_empty() {
        println!("No matches for \"{joined}\".");
        return Ok(());
    }
    println!("{} result(s) for \"{joined}\":\n", scored.len());
    for (s, r) in &scored {
        println!("  {:<42} [{}]", r.key, category_label(&r.category));
        println!("      {}  (score {s})", snippet(&r.value, 100));
    }
    Ok(())
}

/// Resolve which category trees to scan. `None` => all record categories.
fn resolve_prefixes(category: Option<&str>) -> Result<Vec<String>> {
    match category {
        None => Ok(RECORD_PREFIXES.iter().map(|s| s.to_string()).collect()),
        Some(cat) => {
            let p = format!("{}:", cat.trim_end_matches(':'));
            if RECORD_PREFIXES.contains(&p.as_str()) {
                Ok(vec![p])
            } else {
                anyhow::bail!(
                    "unknown category '{cat}' (expected one of: gotcha, decision, dev_note, file, stage)"
                )
            }
        }
    }
}

/// Term-frequency relevance score. Matches in the key weigh most, then the body,
/// then tags; a coverage bonus rewards records that hit more distinct terms.
/// Returns 0 when no term matches (the record is then excluded).
fn score(record: &Record, terms: &[String]) -> u32 {
    let key = record.key.to_lowercase();
    let value = record.value.to_lowercase();
    let tags = record.tags.join(" ").to_lowercase();

    let mut total = 0u32;
    let mut matched_terms = 0u32;
    for term in terms {
        let k = count_occurrences(&key, term);
        let v = count_occurrences(&value, term);
        let t = count_occurrences(&tags, term);
        if k + v + t > 0 {
            matched_terms += 1;
        }
        total += k * 3 + v * 2 + t;
    }
    if matched_terms == 0 {
        0
    } else {
        total + matched_terms * 5
    }
}

fn count_occurrences(haystack: &str, needle: &str) -> u32 {
    if needle.is_empty() {
        return 0;
    }
    haystack.matches(needle).count() as u32
}

/// One-line, length-bounded preview of a record's body (char-safe).
fn snippet(s: &str, max: usize) -> String {
    let one_line = s.replace('\n', " ");
    let trimmed = one_line.trim();
    if trimmed.chars().count() <= max {
        trimmed.to_string()
    } else {
        let head: String = trimmed.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

fn category_label(c: &Category) -> &'static str {
    match c {
        Category::Gotcha => "gotcha",
        Category::File => "file",
        Category::Decision => "decision",
        Category::Stage => "stage",
        Category::Dependency => "dependency",
        Category::DevNote => "note",
        Category::Session => "session",
        Category::Analytics => "analytics",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(key: &str, value: &str, tags: &[&str]) -> Record {
        let mut r = Record::layer0_file_stub(key, uuid::Uuid::nil(), 0, 0);
        r.value = value.to_string();
        r.tags = tags.iter().map(|s| s.to_string()).collect();
        r
    }

    #[test]
    fn score_zero_when_no_term_matches() {
        let r = rec("gotcha:x", "nothing relevant here", &[]);
        assert_eq!(score(&r, &["fraud".into()]), 0);
    }

    #[test]
    fn key_matches_outweigh_body_matches() {
        let in_key = rec("gotcha:fraud-check", "unrelated body", &[]);
        let in_body = rec("gotcha:x", "fraud appears in the body", &[]);
        assert!(
            score(&in_key, &["fraud".into()]) > score(&in_body, &["fraud".into()]),
            "a key hit should rank above a body hit"
        );
    }

    #[test]
    fn more_distinct_terms_matched_ranks_higher() {
        let both = rec("gotcha:x", "fraud detection model", &[]);
        let one = rec("gotcha:y", "fraud fraud fraud", &[]); // many hits, one term
        assert!(
            score(&both, &["fraud".into(), "model".into()])
                > score(&one, &["fraud".into(), "model".into()]),
            "covering 2 terms beats hammering 1"
        );
    }

    #[test]
    fn count_occurrences_is_case_insensitive_via_lowered_inputs() {
        assert_eq!(count_occurrences("a b a b a", "a"), 3);
        assert_eq!(count_occurrences("abc", ""), 0);
    }

    #[test]
    fn snippet_is_char_safe_and_bounded() {
        let s = snippet("line one\nline two that is quite long", 10);
        assert!(!s.contains('\n'));
        assert!(s.chars().count() <= 10);
        // Multi-byte chars must not panic or split.
        let u = snippet("héllo wörld ☃ snowman everywhere", 8);
        assert!(u.chars().count() <= 8);
    }

    #[test]
    fn resolve_prefixes_validates_category() {
        assert_eq!(resolve_prefixes(None).unwrap().len(), RECORD_PREFIXES.len());
        assert_eq!(resolve_prefixes(Some("gotcha")).unwrap(), vec!["gotcha:"]);
        assert_eq!(
            resolve_prefixes(Some("decision:")).unwrap(),
            vec!["decision:"]
        );
        assert!(resolve_prefixes(Some("bogus")).is_err());
    }

    #[test]
    fn category_label_covers_all_variants() {
        for c in [
            Category::Gotcha,
            Category::File,
            Category::Decision,
            Category::Stage,
            Category::Dependency,
            Category::DevNote,
            Category::Session,
            Category::Analytics,
        ] {
            assert!(!category_label(&c).is_empty());
        }
    }
}
