//! Knowledge gap analyzer (M-10-C + M-10-D).
//!
//! Scans the store for all 8 [`GapType`] variants and returns gaps sorted by
//! descending `risk_score`. The severity formula follows ARCHITECTURE.md §13.2:
//!
//! ```text
//! risk_score = change_frequency * (1 - coverage_score)
//! ```
//!
//! Coverage depends on gap type (see [`coverage_for_gap`]).

use anyhow::Result;

use crate::store::{FileRecord, GapType, KnowledgeGap, Record, RecordSource, Store};

// ── Coverage constants (ARCHITECTURE.md §13.2) ─────────────────────────────

const COVERAGE_HOT_FILE_NO_RECORD: f32 = 0.0;
const COVERAGE_HOT_FILE_NO_PURPOSE: f32 = 0.3;
const COVERAGE_HOT_FILE_NO_GOTCHAS: f32 = 0.5;
const COVERAGE_FREQUENTLY_READ_NO_ENRICH: f32 = 0.2;
const COVERAGE_ORPHANED_DECISION: f32 = 0.0;
const COVERAGE_DEPENDENCY_UNKNOWN: f32 = 0.0;
// Used only in tests + coverage_for_gap until CoChangePairUnmapped detection is implemented.
#[cfg(test)]
const COVERAGE_CO_CHANGE_PAIR_UNMAPPED: f32 = 0.0;
const COVERAGE_STALE_HOTSPOT: f32 = 0.3;

// ── Public API ──────────────────────────────────────────────────────────────

/// Scan the store for knowledge gaps across all 8 gap types.
///
/// Returns gaps sorted by `risk_score` descending (highest risk first).
pub async fn analyze(store: &Store) -> Result<Vec<KnowledgeGap>> {
    let mut gaps = Vec::new();

    // Scan all file records once — reused by multiple detectors.
    let file_records = store.scan_prefix("file:").await?;

    detect_hot_file_no_record(&file_records, &mut gaps);
    detect_hot_file_no_purpose(&file_records, &mut gaps);
    detect_hot_file_no_gotchas(&file_records, &mut gaps);
    detect_frequently_read_no_enrich(&file_records, &mut gaps);
    detect_orphaned_decisions(store, &mut gaps).await?;
    detect_dependency_unknown(store, &mut gaps).await?;
    // CoChangePairUnmapped skipped for v0.1 — needs graph edge analysis.
    detect_stale_hotspots(&file_records, &mut gaps);

    // Highest risk first.
    gaps.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal));
    Ok(gaps)
}

// ── Risk score computation ──────────────────────────────────────────────────

/// Compute risk score per ARCHITECTURE.md §13.2.
fn risk_score(change_frequency: f32, coverage: f32) -> f32 {
    change_frequency * (1.0 - coverage)
}

/// Return the coverage constant for a gap type.
#[cfg(test)]
fn coverage_for_gap(gap_type: &GapType) -> f32 {
    match gap_type {
        GapType::HotFileNoRecord => COVERAGE_HOT_FILE_NO_RECORD,
        GapType::HotFileNoPurpose => COVERAGE_HOT_FILE_NO_PURPOSE,
        GapType::HotFileNoGotchas => COVERAGE_HOT_FILE_NO_GOTCHAS,
        GapType::FrequentlyReadNoEnrich => COVERAGE_FREQUENTLY_READ_NO_ENRICH,
        GapType::OrphanedDecision => COVERAGE_ORPHANED_DECISION,
        GapType::DependencyUnknown => COVERAGE_DEPENDENCY_UNKNOWN,
        GapType::CoChangePairUnmapped => COVERAGE_CO_CHANGE_PAIR_UNMAPPED,
        GapType::StaleHotspot => COVERAGE_STALE_HOTSPOT,
    }
}

// ── Description + action hint generators ────────────────────────────────────

fn description_for_gap(gap_type: &GapType, key: &str) -> String {
    match gap_type {
        GapType::HotFileNoRecord => {
            format!("Hot file {key} has no knowledge record — high churn with zero context")
        }
        GapType::HotFileNoPurpose => {
            format!("Hot file {key} has a record but no purpose — Claude cannot explain what it does")
        }
        GapType::HotFileNoGotchas => {
            format!("Hot file {key} has no gotchas — frequently changed with no documented traps")
        }
        GapType::FrequentlyReadNoEnrich => {
            format!("{key} is read by Claude but never enriched past Layer 0")
        }
        GapType::OrphanedDecision => {
            format!("Decision {key} has no affected files — cannot be surfaced by hooks")
        }
        GapType::DependencyUnknown => {
            format!("Dependency {key} has no confirmed gotchas — upgrade risks are invisible")
        }
        GapType::CoChangePairUnmapped => {
            format!("{key} co-changes frequently with another file but has no graph edge")
        }
        GapType::StaleHotspot => {
            format!("Hot file {key} has stale knowledge — record may be outdated after recent changes")
        }
    }
}

fn action_hint_for_gap(gap_type: &GapType, key: &str) -> String {
    // Strip the namespace prefix to get the bare path/slug for CLI commands.
    let bare = key.splitn(2, ':').nth(1).unwrap_or(key);

    match gap_type {
        GapType::HotFileNoRecord => {
            format!("mati show {bare}  # creates a stub, then: mati enrich {bare}")
        }
        GapType::HotFileNoPurpose => {
            format!("mati enrich {bare}")
        }
        GapType::HotFileNoGotchas => {
            format!("mati gotcha add --file {bare}")
        }
        GapType::FrequentlyReadNoEnrich => {
            format!("mati enrich {bare}")
        }
        GapType::OrphanedDecision => {
            format!("mati show {bare}  # review and link affected files")
        }
        GapType::DependencyUnknown => {
            format!("mati gotcha add --dep {bare}")
        }
        GapType::CoChangePairUnmapped => {
            format!("mati show {bare}  # review co-change pairs")
        }
        GapType::StaleHotspot => {
            format!("mati enrich --refresh {bare}")
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Check whether `needle` appears as a standalone word in `haystack`.
/// Word boundaries are any character that is not alphanumeric, `-`, or `_`.
fn contains_word(haystack: &str, needle: &str) -> bool {
    haystack
        .split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
        .any(|word| word == needle)
}

// ── Gap type detectors ──────────────────────────────────────────────────────

/// Parse a `FileRecord` from a `Record`'s value field. Returns `None` if the
/// value is not valid JSON or does not deserialize to a `FileRecord`.
fn parse_file_record(record: &Record) -> Option<FileRecord> {
    serde_json::from_str(&record.value).ok()
}

/// HotFileNoRecord: hotspot files where `is_hotspot=true` but the record's
/// value is empty (no FileRecord data at all). In practice, a file: record
/// with an empty value means Layer 0 created the key but wrote no content.
fn detect_hot_file_no_record(file_records: &[Record], gaps: &mut Vec<KnowledgeGap>) {
    for record in file_records {
        if record.value.is_empty() {
            // No FileRecord data — try to get change_frequency from parsed
            // FileRecord. Since the value is empty here, fall back to 1.0.
            let freq = parse_file_record(record)
                .map(|fr| fr.change_frequency as f32)
                .unwrap_or(1.0);
            let gap = KnowledgeGap {
                key: record.key.clone(),
                gap_type: GapType::HotFileNoRecord,
                risk_score: risk_score(freq, COVERAGE_HOT_FILE_NO_RECORD),
                description: description_for_gap(&GapType::HotFileNoRecord, &record.key),
                action_hint: action_hint_for_gap(&GapType::HotFileNoRecord, &record.key),
            };
            gaps.push(gap);
            continue;
        }

        if let Some(fr) = parse_file_record(record) {
            // File has a parsed record — handled by other detectors. But if
            // is_hotspot is true and everything else is empty, it's still a gap.
            if fr.is_hotspot
                && fr.purpose.is_empty()
                && fr.gotcha_keys.is_empty()
                && fr.entry_points.is_empty()
            {
                let gap = KnowledgeGap {
                    key: record.key.clone(),
                    gap_type: GapType::HotFileNoRecord,
                    risk_score: risk_score(fr.change_frequency as f32, COVERAGE_HOT_FILE_NO_RECORD),
                    description: description_for_gap(&GapType::HotFileNoRecord, &record.key),
                    action_hint: action_hint_for_gap(&GapType::HotFileNoRecord, &record.key),
                };
                gaps.push(gap);
            }
        }
    }
}

/// HotFileNoPurpose: hotspot files with a record but empty `purpose`.
fn detect_hot_file_no_purpose(file_records: &[Record], gaps: &mut Vec<KnowledgeGap>) {
    for record in file_records {
        let Some(fr) = parse_file_record(record) else { continue };
        if !fr.is_hotspot || !fr.purpose.is_empty() {
            continue;
        }
        // Skip if already caught as HotFileNoRecord (completely empty).
        if fr.gotcha_keys.is_empty() && fr.entry_points.is_empty() {
            continue;
        }
        gaps.push(KnowledgeGap {
            key: record.key.clone(),
            gap_type: GapType::HotFileNoPurpose,
            risk_score: risk_score(fr.change_frequency as f32, COVERAGE_HOT_FILE_NO_PURPOSE),
            description: description_for_gap(&GapType::HotFileNoPurpose, &record.key),
            action_hint: action_hint_for_gap(&GapType::HotFileNoPurpose, &record.key),
        });
    }
}

/// HotFileNoGotchas: hotspot files with a purpose but no linked gotchas.
fn detect_hot_file_no_gotchas(file_records: &[Record], gaps: &mut Vec<KnowledgeGap>) {
    for record in file_records {
        let Some(fr) = parse_file_record(record) else { continue };
        if !fr.is_hotspot || fr.purpose.is_empty() || !fr.gotcha_keys.is_empty() {
            continue;
        }
        gaps.push(KnowledgeGap {
            key: record.key.clone(),
            gap_type: GapType::HotFileNoGotchas,
            risk_score: risk_score(fr.change_frequency as f32, COVERAGE_HOT_FILE_NO_GOTCHAS),
            description: description_for_gap(&GapType::HotFileNoGotchas, &record.key),
            action_hint: action_hint_for_gap(&GapType::HotFileNoGotchas, &record.key),
        });
    }
}

/// FrequentlyReadNoEnrich: files with `access_count > 0` and
/// `source == StaticAnalysis` — Claude is reading them but they have not
/// been enriched past Layer 0.
fn detect_frequently_read_no_enrich(file_records: &[Record], gaps: &mut Vec<KnowledgeGap>) {
    for record in file_records {
        if record.access_count == 0 || record.source != RecordSource::StaticAnalysis {
            continue;
        }
        let freq = parse_file_record(record)
            .map(|fr| fr.change_frequency as f32)
            .unwrap_or(1.0);
        gaps.push(KnowledgeGap {
            key: record.key.clone(),
            gap_type: GapType::FrequentlyReadNoEnrich,
            risk_score: risk_score(freq, COVERAGE_FREQUENTLY_READ_NO_ENRICH),
            description: description_for_gap(&GapType::FrequentlyReadNoEnrich, &record.key),
            action_hint: action_hint_for_gap(&GapType::FrequentlyReadNoEnrich, &record.key),
        });
    }
}

/// OrphanedDecision: `decision:*` records whose value JSON has empty
/// `affected_files` (or is not parseable as a structure with that field).
async fn detect_orphaned_decisions(store: &Store, gaps: &mut Vec<KnowledgeGap>) -> Result<()> {
    let decisions = store.scan_prefix("decision:").await?;
    for record in &decisions {
        let is_orphaned = match serde_json::from_str::<serde_json::Value>(&record.value) {
            Ok(v) => {
                let affected = v.get("affected_files");
                match affected {
                    None => true,
                    Some(arr) => arr.as_array().map_or(true, |a| a.is_empty()),
                }
            }
            // Non-JSON value — plain text decision, no affected files at all.
            Err(_) => true,
        };

        if !is_orphaned {
            continue;
        }

        // For orphaned decisions, change_frequency = decision age in days / 30.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age_days = now.saturating_sub(record.created_at) / 86400;
        let freq = age_days as f32 / 30.0;

        gaps.push(KnowledgeGap {
            key: record.key.clone(),
            gap_type: GapType::OrphanedDecision,
            risk_score: risk_score(freq, COVERAGE_ORPHANED_DECISION),
            description: description_for_gap(&GapType::OrphanedDecision, &record.key),
            action_hint: action_hint_for_gap(&GapType::OrphanedDecision, &record.key),
        });
    }
    Ok(())
}

/// DependencyUnknown: `dep:*` records with no confirmed gotchas linked.
/// We check whether any `gotcha:*` record references this dependency.
async fn detect_dependency_unknown(store: &Store, gaps: &mut Vec<KnowledgeGap>) -> Result<()> {
    let deps = store.scan_prefix("dep:").await?;
    let gotchas = store.scan_prefix("gotcha:").await?;

    // Build a set of dep names that have at least one confirmed gotcha referencing them.
    let mut deps_with_gotchas = std::collections::HashSet::new();
    for gotcha in &gotchas {
        if let Ok(gr) = serde_json::from_str::<serde_json::Value>(&gotcha.value) {
            // Check if this gotcha's affected_files mentions the dep, or if
            // the gotcha key itself contains the dep name.
            if let Some(confirmed) = gr.get("confirmed") {
                if confirmed.as_bool() != Some(true) {
                    continue;
                }
            }
            // A gotcha that references a dep typically has the dep name in its key
            // or affected_files. Use word-boundary matching to avoid false positives
            // from substring matches (e.g. "go" matching "google").
            for dep_rec in &deps {
                let dep_name = dep_rec.key.strip_prefix("dep:").unwrap_or(&dep_rec.key);
                if gotcha.key.contains(&format!("dep:{dep_name}"))
                    || contains_word(&gotcha.value, dep_name)
                {
                    deps_with_gotchas.insert(dep_rec.key.clone());
                }
            }
        }
    }

    // Scan file records to count how many files use each dep.
    let file_records = store.scan_prefix("file:").await?;
    let mut dep_usage_count: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for file_rec in &file_records {
        if let Some(fr) = parse_file_record(file_rec) {
            for import in &fr.imports {
                for dep_rec in &deps {
                    let dep_name = dep_rec.key.strip_prefix("dep:").unwrap_or(&dep_rec.key);
                    if import.contains(dep_name) {
                        *dep_usage_count.entry(dep_rec.key.clone()).or_default() += 1;
                    }
                }
            }
        }
    }

    for dep in &deps {
        if deps_with_gotchas.contains(&dep.key) {
            continue;
        }
        // change_frequency = number of files using the dep.
        let freq = dep_usage_count.get(&dep.key).copied().unwrap_or(1) as f32;
        gaps.push(KnowledgeGap {
            key: dep.key.clone(),
            gap_type: GapType::DependencyUnknown,
            risk_score: risk_score(freq, COVERAGE_DEPENDENCY_UNKNOWN),
            description: description_for_gap(&GapType::DependencyUnknown, &dep.key),
            action_hint: action_hint_for_gap(&GapType::DependencyUnknown, &dep.key),
        });
    }
    Ok(())
}

/// StaleHotspot: hotspot files with `staleness.value >= 0.5`.
fn detect_stale_hotspots(file_records: &[Record], gaps: &mut Vec<KnowledgeGap>) {
    for record in file_records {
        // Skip records where staleness was never computed (sentinel value).
        if record.staleness.computed_at == 0 {
            continue;
        }
        if record.staleness.value < 0.5 {
            continue;
        }
        let Some(fr) = parse_file_record(record) else { continue };
        if !fr.is_hotspot {
            continue;
        }
        gaps.push(KnowledgeGap {
            key: record.key.clone(),
            gap_type: GapType::StaleHotspot,
            risk_score: risk_score(fr.change_frequency as f32, COVERAGE_STALE_HOTSPOT),
            description: description_for_gap(&GapType::StaleHotspot, &record.key),
            action_hint: action_hint_for_gap(&GapType::StaleHotspot, &record.key),
        });
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Risk score computation ──────────────────────────────────────────

    #[test]
    fn risk_score_zero_coverage_uses_full_frequency() {
        let score = risk_score(50.0, 0.0);
        assert!((score - 50.0).abs() < f32::EPSILON);
    }

    #[test]
    fn risk_score_full_coverage_is_zero() {
        let score = risk_score(50.0, 1.0);
        assert!((score - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn risk_score_partial_coverage() {
        // change_frequency=40, coverage=0.3 -> 40 * 0.7 = 28.0
        let score = risk_score(40.0, 0.3);
        assert!((score - 28.0).abs() < 0.01);
    }

    #[test]
    fn risk_score_hot_file_no_record() {
        // is_hotspot with change_frequency=100, coverage=0.0 -> 100.0
        let score = risk_score(100.0, COVERAGE_HOT_FILE_NO_RECORD);
        assert!((score - 100.0).abs() < f32::EPSILON);
    }

    #[test]
    fn risk_score_hot_file_no_purpose() {
        // change_frequency=80, coverage=0.3 -> 80 * 0.7 = 56.0
        let score = risk_score(80.0, COVERAGE_HOT_FILE_NO_PURPOSE);
        assert!((score - 56.0).abs() < 0.01);
    }

    #[test]
    fn risk_score_hot_file_no_gotchas() {
        // change_frequency=60, coverage=0.5 -> 60 * 0.5 = 30.0
        let score = risk_score(60.0, COVERAGE_HOT_FILE_NO_GOTCHAS);
        assert!((score - 30.0).abs() < f32::EPSILON);
    }

    #[test]
    fn risk_score_frequently_read_no_enrich() {
        // change_frequency=20, coverage=0.2 -> 20 * 0.8 = 16.0
        let score = risk_score(20.0, COVERAGE_FREQUENTLY_READ_NO_ENRICH);
        assert!((score - 16.0).abs() < 0.01);
    }

    #[test]
    fn risk_score_orphaned_decision() {
        // age_days=90, freq = 90/30 = 3.0, coverage=0.0 -> 3.0
        let freq = 90.0 / 30.0;
        let score = risk_score(freq, COVERAGE_ORPHANED_DECISION);
        assert!((score - 3.0).abs() < f32::EPSILON);
    }

    #[test]
    fn risk_score_dependency_unknown() {
        // 5 files use the dep, coverage=0.0 -> 5.0
        let score = risk_score(5.0, COVERAGE_DEPENDENCY_UNKNOWN);
        assert!((score - 5.0).abs() < f32::EPSILON);
    }

    #[test]
    fn risk_score_stale_hotspot() {
        // change_frequency=45, coverage=0.3 -> 45 * 0.7 = 31.5
        let score = risk_score(45.0, COVERAGE_STALE_HOTSPOT);
        assert!((score - 31.5).abs() < 0.01);
    }

    // ── Coverage constants ──────────────────────────────────────────────

    #[test]
    fn coverage_for_gap_returns_correct_values() {
        assert!((coverage_for_gap(&GapType::HotFileNoRecord) - 0.0).abs() < f32::EPSILON);
        assert!((coverage_for_gap(&GapType::HotFileNoPurpose) - 0.3).abs() < f32::EPSILON);
        assert!((coverage_for_gap(&GapType::HotFileNoGotchas) - 0.5).abs() < f32::EPSILON);
        assert!((coverage_for_gap(&GapType::FrequentlyReadNoEnrich) - 0.2).abs() < f32::EPSILON);
        assert!((coverage_for_gap(&GapType::OrphanedDecision) - 0.0).abs() < f32::EPSILON);
        assert!((coverage_for_gap(&GapType::DependencyUnknown) - 0.0).abs() < f32::EPSILON);
        assert!((coverage_for_gap(&GapType::CoChangePairUnmapped) - 0.0).abs() < f32::EPSILON);
        assert!((coverage_for_gap(&GapType::StaleHotspot) - 0.3).abs() < f32::EPSILON);
    }

    // ── Description generation ──────────────────────────────────────────

    #[test]
    fn description_contains_key() {
        let desc = description_for_gap(&GapType::HotFileNoRecord, "file:src/main.rs");
        assert!(desc.contains("file:src/main.rs"));
    }

    #[test]
    fn description_per_gap_type() {
        let cases = [
            (GapType::HotFileNoRecord, "no knowledge record"),
            (GapType::HotFileNoPurpose, "no purpose"),
            (GapType::HotFileNoGotchas, "no gotchas"),
            (GapType::FrequentlyReadNoEnrich, "never enriched"),
            (GapType::OrphanedDecision, "no affected files"),
            (GapType::DependencyUnknown, "no confirmed gotchas"),
            (GapType::CoChangePairUnmapped, "co-changes"),
            (GapType::StaleHotspot, "stale knowledge"),
        ];
        for (gap_type, expected_substr) in &cases {
            let desc = description_for_gap(gap_type, "file:test.rs");
            assert!(
                desc.contains(expected_substr),
                "expected {:?} description to contain '{}', got: {}",
                gap_type, expected_substr, desc
            );
        }
    }

    // ── Action hint generation ──────────────────────────────────────────

    #[test]
    fn action_hint_strips_prefix() {
        let hint = action_hint_for_gap(&GapType::HotFileNoPurpose, "file:src/main.rs");
        assert!(hint.contains("src/main.rs"), "hint should contain bare path: {hint}");
        assert!(!hint.contains("file:src/"), "hint should not contain file: prefix: {hint}");
    }

    #[test]
    fn action_hint_suggests_mati_command() {
        let hint = action_hint_for_gap(&GapType::HotFileNoGotchas, "file:src/lib.rs");
        assert!(hint.starts_with("mati "), "hint should suggest a mati command: {hint}");
    }

    #[test]
    fn action_hint_per_gap_type() {
        let cases = [
            (GapType::HotFileNoRecord, "file:src/a.rs", "enrich"),
            (GapType::HotFileNoPurpose, "file:src/b.rs", "enrich"),
            (GapType::HotFileNoGotchas, "file:src/c.rs", "gotcha add"),
            (GapType::FrequentlyReadNoEnrich, "file:src/d.rs", "enrich"),
            (GapType::OrphanedDecision, "decision:use-surrealkv", "show"),
            (GapType::DependencyUnknown, "dep:serde", "gotcha add"),
            (GapType::StaleHotspot, "file:src/e.rs", "enrich"),
        ];
        for (gap_type, key, expected_cmd) in &cases {
            let hint = action_hint_for_gap(gap_type, key);
            assert!(
                hint.contains(expected_cmd),
                "expected {:?} hint to contain '{}', got: {}",
                gap_type, expected_cmd, hint
            );
        }
    }

    // ── KnowledgeGap struct construction ────────────────────────────────

    #[test]
    fn gap_fields_are_populated() {
        let gap = KnowledgeGap {
            key: "file:src/store/db.rs".into(),
            gap_type: GapType::HotFileNoRecord,
            risk_score: risk_score(100.0, COVERAGE_HOT_FILE_NO_RECORD),
            description: description_for_gap(&GapType::HotFileNoRecord, "file:src/store/db.rs"),
            action_hint: action_hint_for_gap(&GapType::HotFileNoRecord, "file:src/store/db.rs"),
        };
        assert_eq!(gap.key, "file:src/store/db.rs");
        assert_eq!(gap.gap_type, GapType::HotFileNoRecord);
        assert!((gap.risk_score - 100.0).abs() < f32::EPSILON);
        assert!(!gap.description.is_empty());
        assert!(gap.action_hint.starts_with("mati "));
    }

    // ── Sorting ─────────────────────────────────────────────────────────

    #[test]
    fn gaps_sort_by_risk_descending() {
        let mut gaps = vec![
            KnowledgeGap {
                key: "file:low.rs".into(),
                gap_type: GapType::HotFileNoGotchas,
                risk_score: 10.0,
                description: String::new(),
                action_hint: String::new(),
            },
            KnowledgeGap {
                key: "file:high.rs".into(),
                gap_type: GapType::HotFileNoRecord,
                risk_score: 100.0,
                description: String::new(),
                action_hint: String::new(),
            },
            KnowledgeGap {
                key: "file:mid.rs".into(),
                gap_type: GapType::HotFileNoPurpose,
                risk_score: 50.0,
                description: String::new(),
                action_hint: String::new(),
            },
        ];
        gaps.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal));

        assert_eq!(gaps[0].key, "file:high.rs");
        assert_eq!(gaps[1].key, "file:mid.rs");
        assert_eq!(gaps[2].key, "file:low.rs");
    }
}
