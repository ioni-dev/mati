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

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::store::{FileRecord, GapType, KnowledgeGap, Record, RecordSource};

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
const COVERAGE_HOT_FILE_NO_TESTS: f32 = 0.0;
const COVERAGE_HIGH_FAN_IN_NO_CONTRACT: f32 = 0.0;

/// Minimum number of importers for a file to be flagged as high fan-in.
const FAN_IN_THRESHOLD: usize = 5;

// ── Public API ──────────────────────────────────────────────────────────────

/// Scan the store for knowledge gaps across all gap types.
///
/// Accepts pre-loaded record slices to avoid redundant store scans when
/// called from `mati stats` or `mati gaps` which already have the data.
///
/// `fan_in` maps `file:<path>` keys to their import fan-in count (number of
/// files that import them). Pass an empty map if graph data is unavailable —
/// `HighFanInNoContract` detection is skipped in that case.
///
/// Returns gaps sorted by `risk_score` descending (highest risk first).
pub fn analyze(
    file_records: &[Record],
    gotchas: &[Record],
    decisions: &[Record],
    deps: &[Record],
    fan_in: &HashMap<String, usize>,
) -> Vec<KnowledgeGap> {
    let mut gaps = Vec::new();

    detect_hot_file_no_record(file_records, &mut gaps);
    detect_hot_file_no_purpose(file_records, &mut gaps);
    detect_hot_file_no_gotchas(file_records, &mut gaps);
    detect_frequently_read_no_enrich(file_records, &mut gaps);
    detect_orphaned_decisions(decisions, &mut gaps);
    detect_dependency_unknown(file_records, gotchas, deps, &mut gaps);
    // CoChangePairUnmapped skipped for v0.1 — needs graph edge analysis.
    detect_stale_hotspots(file_records, &mut gaps);
    detect_hot_file_no_tests(file_records, &mut gaps);
    if !fan_in.is_empty() {
        detect_high_fan_in_no_contract(file_records, fan_in, &mut gaps);
    }

    // Highest risk first.
    gaps.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal));
    gaps
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
        GapType::HotFileNoTests => COVERAGE_HOT_FILE_NO_TESTS,
        GapType::HighFanInNoContract => COVERAGE_HIGH_FAN_IN_NO_CONTRACT,
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
        GapType::HotFileNoTests => {
            format!("Hot file {key} has no test file — high-churn code with no visible test coverage")
        }
        GapType::HighFanInNoContract => {
            format!("{key} is imported by many files but has no gotchas or decisions — interface contracts are undocumented")
        }
    }
}

fn action_hint_for_gap(gap_type: &GapType, key: &str) -> String {
    // Strip the namespace prefix to get the bare path/slug for CLI commands.
    let bare = key.split_once(':').map_or(key, |(_, rest)| rest);

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
        GapType::HotFileNoTests => {
            format!("add tests for {bare} before the next change")
        }
        GapType::HighFanInNoContract => {
            format!("mati gotcha add {bare}  # document interface contracts and invariants")
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

/// Parse a `FileRecord` from a `Record`'s payload. Returns `None` if absent.
fn parse_file_record(record: &Record) -> Option<FileRecord> {
    record.payload_as::<FileRecord>()
}

/// HotFileNoRecord: hotspot files where `is_hotspot=true` but the record has
/// no FileRecord payload at all (i.e. Layer 0 never populated the file: key).
///
/// NOTE: `record.value` is the human-authored text field and is intentionally
/// empty for all Layer 0 stubs — it cannot be used to detect missing payload.
/// After the MessagePack migration, FileRecord lives in `record.payload`.
fn detect_hot_file_no_record(file_records: &[Record], gaps: &mut Vec<KnowledgeGap>) {
    for record in file_records {
        match parse_file_record(record) {
            None => {
                // No FileRecord payload at all — genuine empty stub.
                let gap = KnowledgeGap {
                    key: record.key.clone(),
                    gap_type: GapType::HotFileNoRecord,
                    risk_score: risk_score(1.0, COVERAGE_HOT_FILE_NO_RECORD),
                    description: description_for_gap(&GapType::HotFileNoRecord, &record.key),
                    action_hint: action_hint_for_gap(&GapType::HotFileNoRecord, &record.key),
                };
                gaps.push(gap);
            }
            Some(fr) => {
                // File has a FileRecord — handled by other detectors. But if
                // is_hotspot is true and everything else is empty, it's a gap.
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
fn detect_orphaned_decisions(decisions: &[Record], gaps: &mut Vec<KnowledgeGap>) {
    for record in decisions {
        let is_orphaned = match &record.payload {
            Some(v) => {
                let affected = v.get("affected_files");
                match affected {
                    None => true,
                    Some(arr) => arr.as_array().is_none_or(Vec::is_empty),
                }
            }
            // No payload — decision has no structured data, treat as orphaned.
            None => true,
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
}

/// DependencyUnknown: `dep:*` records with no confirmed gotchas linked.
/// We check whether any `gotcha:*` record references this dependency.
fn detect_dependency_unknown(
    file_records: &[Record],
    gotchas: &[Record],
    deps: &[Record],
    gaps: &mut Vec<KnowledgeGap>,
) {
    // Pre-compute dep names once to avoid repeated strip_prefix in hot loops.
    let dep_names: Vec<(&str, &str)> = deps
        .iter()
        .map(|d| (d.key.as_str(), d.key.strip_prefix("dep:").unwrap_or(&d.key)))
        .collect();

    // Build a set of dep keys that have at least one confirmed gotcha referencing them.
    let mut deps_with_gotchas = std::collections::HashSet::new();
    for gotcha in gotchas {
        if let Some(gr) = &gotcha.payload {
            if let Some(confirmed) = gr.get("confirmed") {
                if confirmed.as_bool() != Some(true) {
                    continue;
                }
            }
            // A gotcha that references a dep typically has the dep name in its key
            // or value. Use word-boundary matching to avoid false positives
            // from substring matches (e.g. "go" matching "google").
            for (dep_key, dep_name) in &dep_names {
                if gotcha.key.contains(dep_key) || contains_word(&gotcha.value, dep_name) {
                    deps_with_gotchas.insert(*dep_key);
                }
            }
        }
    }

    // Count how many files use each dep (by checking imports).
    let mut dep_usage_count: std::collections::HashMap<&str, u32> =
        std::collections::HashMap::new();
    for file_rec in file_records {
        if let Some(fr) = parse_file_record(file_rec) {
            for import in &fr.imports {
                for (dep_key, dep_name) in &dep_names {
                    if import.contains(dep_name) {
                        *dep_usage_count.entry(dep_key).or_default() += 1;
                    }
                }
            }
        }
    }

    for (dep_key, _) in &dep_names {
        if deps_with_gotchas.contains(dep_key) {
            continue;
        }
        let freq = dep_usage_count.get(dep_key).copied().unwrap_or(1) as f32;
        gaps.push(KnowledgeGap {
            key: dep_key.to_string(),
            gap_type: GapType::DependencyUnknown,
            risk_score: risk_score(freq, COVERAGE_DEPENDENCY_UNKNOWN),
            description: description_for_gap(&GapType::DependencyUnknown, dep_key),
            action_hint: action_hint_for_gap(&GapType::DependencyUnknown, dep_key),
        });
    }
}

/// HotFileNoTests: hotspot files with no corresponding test file in the repo.
///
/// Checks language-appropriate test file naming conventions against the set
/// of all known file paths. Only flags hotspots — low-churn files are excluded
/// to keep signal-to-noise high.
fn detect_hot_file_no_tests(file_records: &[Record], gaps: &mut Vec<KnowledgeGap>) {
    // Build lookup set of all known paths (strip "file:" prefix).
    let all_paths: HashSet<&str> = file_records
        .iter()
        .filter_map(|r| r.key.strip_prefix("file:"))
        .collect();

    for record in file_records {
        let Some(fr) = parse_file_record(record) else { continue };
        if !fr.is_hotspot {
            continue;
        }
        let path = record.key.strip_prefix("file:").unwrap_or(&record.key);
        if has_test_file(path, &all_paths) {
            continue;
        }
        gaps.push(KnowledgeGap {
            key: record.key.clone(),
            gap_type: GapType::HotFileNoTests,
            risk_score: risk_score(fr.change_frequency as f32, COVERAGE_HOT_FILE_NO_TESTS),
            description: description_for_gap(&GapType::HotFileNoTests, &record.key),
            action_hint: action_hint_for_gap(&GapType::HotFileNoTests, path),
        });
    }
}

/// Return `true` if a test file for `path` exists in `all_paths`.
///
/// Checks language-appropriate conventions:
/// - Rust:       `{stem}_test.rs`, `tests/{path}`
/// - Go:         `{stem}_test.go`  (same directory, Go convention)
/// - TypeScript/JS: `{stem}.test.{ext}`, `{stem}.spec.{ext}`, `__tests__/{stem}.{ext}`
/// - Python:     `test_{stem}.py`, `{stem}_test.py`, `tests/{path}`
fn has_test_file(path: &str, all_paths: &HashSet<&str>) -> bool {
    let p = Path::new(path);
    let stem = match p.file_stem().and_then(|s| s.to_str()) {
        Some(s) => s,
        None => return false,
    };
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
    let parent = p.parent().and_then(|p| p.to_str()).unwrap_or("");

    let join = |dir: &str, name: &str| -> String {
        if dir.is_empty() { name.to_string() } else { format!("{dir}/{name}") }
    };

    let candidates: &[String] = &[
        // Rust
        join(parent, &format!("{stem}_test.rs")),
        join(parent, &format!("{stem}_tests.rs")),
        format!("tests/{path}"),
        // Go
        join(parent, &format!("{stem}_test.go")),
        // TypeScript / JavaScript
        join(parent, &format!("{stem}.test.{ext}")),
        join(parent, &format!("{stem}.spec.{ext}")),
        join(parent, &format!("__tests__/{stem}.{ext}")),
        format!("tests/{path}"),
        format!("test/{path}"),
        // Python
        join(parent, &format!("test_{stem}.{ext}")),
        join(parent, &format!("{stem}_test.{ext}")),
        format!("tests/{path}"),
    ];

    candidates.iter().any(|c| all_paths.contains(c.as_str()))
}

/// HighFanInNoContract: files imported by >= FAN_IN_THRESHOLD others with no
/// gotchas or decisions linked. High fan-in = high blast radius; undocumented
/// contracts are invisible to both developers and Claude.
fn detect_high_fan_in_no_contract(
    file_records: &[Record],
    fan_in: &HashMap<String, usize>,
    gaps: &mut Vec<KnowledgeGap>,
) {
    for record in file_records {
        let count = match fan_in.get(&record.key) {
            Some(&n) if n >= FAN_IN_THRESHOLD => n,
            _ => continue,
        };
        let Some(fr) = parse_file_record(record) else { continue };
        // Skip files that already have documented contracts.
        if !fr.gotcha_keys.is_empty() || !fr.decision_keys.is_empty() {
            continue;
        }
        let bare = record.key.strip_prefix("file:").unwrap_or(&record.key);
        gaps.push(KnowledgeGap {
            key: record.key.clone(),
            gap_type: GapType::HighFanInNoContract,
            // Use fan-in count as the "frequency" — more importers = higher blast radius.
            risk_score: risk_score(count as f32, COVERAGE_HIGH_FAN_IN_NO_CONTRACT),
            description: format!(
                "{} is imported by {count} files — no interface contract documented",
                record.key
            ),
            action_hint: action_hint_for_gap(&GapType::HighFanInNoContract, bare),
        });
    }
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

    use crate::store::{
        Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle, RecordSource,
        RecordVersion, StalenessScore,
    };

    // ── Test helpers ────────────────────────────────────────────────────

    fn make_file_record_with(key: &str, fr: FileRecord) -> Record {
        Record {
            key: key.to_string(),
            value: fr.purpose.clone(),
            payload: serde_json::to_value(&fr).ok(),
            category: Category::File,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 1_000_000,
            updated_at: 1_000_000,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 1_000_000,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
        }
    }

    fn hotspot_fr(path: &str, change_frequency: u32) -> FileRecord {
        FileRecord {
            path: path.to_string(),
            purpose: "Does important things".to_string(),
            entry_points: vec!["run".to_string()],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency,
            last_author: None,
            is_hotspot: true,
            token_cost_estimate: 100,
            last_modified_session: 0,
            content_hash: None,
            line_count: 0,
        }
    }

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

    // ── HotFileNoTests ──────────────────────────────────────────────────

    #[test]
    fn hot_file_no_tests_flags_hotspot_without_test_file() {
        let fr = hotspot_fr("src/auth.rs", 20);
        let records = vec![make_file_record_with("file:src/auth.rs", fr)];
        let mut gaps = vec![];
        detect_hot_file_no_tests(&records, &mut gaps);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].gap_type, GapType::HotFileNoTests);
        assert_eq!(gaps[0].key, "file:src/auth.rs");
    }

    #[test]
    fn hot_file_no_tests_skips_non_hotspot() {
        let mut fr = hotspot_fr("src/util.rs", 20);
        fr.is_hotspot = false;
        let records = vec![make_file_record_with("file:src/util.rs", fr)];
        let mut gaps = vec![];
        detect_hot_file_no_tests(&records, &mut gaps);
        assert!(gaps.is_empty());
    }

    #[test]
    fn hot_file_no_tests_suppressed_when_rust_test_file_exists() {
        let hotspot = make_file_record_with("file:src/auth.rs", hotspot_fr("src/auth.rs", 20));
        let test_fr = FileRecord {
            path: "src/auth_test.rs".to_string(),
            is_hotspot: false,
            ..hotspot_fr("src/auth_test.rs", 0)
        };
        let test_rec = make_file_record_with("file:src/auth_test.rs", test_fr);
        let records = vec![hotspot, test_rec];
        let mut gaps = vec![];
        detect_hot_file_no_tests(&records, &mut gaps);
        assert!(gaps.is_empty(), "should not flag when auth_test.rs exists");
    }

    #[test]
    fn hot_file_no_tests_suppressed_when_tests_dir_mirror_exists() {
        let hotspot = make_file_record_with("file:src/auth.rs", hotspot_fr("src/auth.rs", 20));
        let mirror_fr = FileRecord {
            path: "tests/src/auth.rs".to_string(),
            is_hotspot: false,
            ..hotspot_fr("tests/src/auth.rs", 0)
        };
        let mirror_rec = make_file_record_with("file:tests/src/auth.rs", mirror_fr);
        let records = vec![hotspot, mirror_rec];
        let mut gaps = vec![];
        detect_hot_file_no_tests(&records, &mut gaps);
        assert!(gaps.is_empty(), "should not flag when tests/src/auth.rs exists");
    }

    #[test]
    fn hot_file_no_tests_suppressed_when_ts_spec_file_exists() {
        let hotspot_fr_ts = FileRecord {
            path: "src/parser.ts".to_string(),
            is_hotspot: true,
            ..hotspot_fr("src/parser.ts", 15)
        };
        let hotspot = make_file_record_with("file:src/parser.ts", hotspot_fr_ts);
        let spec_fr = FileRecord {
            path: "src/parser.spec.ts".to_string(),
            is_hotspot: false,
            ..hotspot_fr("src/parser.spec.ts", 0)
        };
        let spec_rec = make_file_record_with("file:src/parser.spec.ts", spec_fr);
        let records = vec![hotspot, spec_rec];
        let mut gaps = vec![];
        detect_hot_file_no_tests(&records, &mut gaps);
        assert!(gaps.is_empty(), "should not flag when parser.spec.ts exists");
    }

    #[test]
    fn hot_file_no_tests_risk_score_uses_change_frequency() {
        let fr = hotspot_fr("src/hot.rs", 50);
        let records = vec![make_file_record_with("file:src/hot.rs", fr)];
        let mut gaps = vec![];
        detect_hot_file_no_tests(&records, &mut gaps);
        assert_eq!(gaps.len(), 1);
        // coverage = 0.0, risk = 50 * 1.0 = 50.0
        assert!((gaps[0].risk_score - 50.0).abs() < f32::EPSILON);
    }

    #[test]
    fn hot_file_no_tests_suppressed_when_jest_tests_dir_exists() {
        let hotspot_fr_js = FileRecord {
            path: "src/auth.ts".to_string(),
            is_hotspot: true,
            ..hotspot_fr("src/auth.ts", 15)
        };
        let hotspot = make_file_record_with("file:src/auth.ts", hotspot_fr_js);
        let jest_fr = FileRecord {
            path: "src/__tests__/auth.ts".to_string(),
            is_hotspot: false,
            ..hotspot_fr("src/__tests__/auth.ts", 0)
        };
        let jest_rec = make_file_record_with("file:src/__tests__/auth.ts", jest_fr);
        let records = vec![hotspot, jest_rec];
        let mut gaps = vec![];
        detect_hot_file_no_tests(&records, &mut gaps);
        assert!(gaps.is_empty(), "should not flag when src/__tests__/auth.ts exists");
    }

    #[test]
    fn hot_file_no_tests_suppressed_when_go_test_file_exists() {
        let hotspot_fr_go = FileRecord {
            path: "pkg/store/db.go".to_string(),
            is_hotspot: true,
            ..hotspot_fr("pkg/store/db.go", 10)
        };
        let hotspot = make_file_record_with("file:pkg/store/db.go", hotspot_fr_go);
        let test_fr = FileRecord {
            path: "pkg/store/db_test.go".to_string(),
            is_hotspot: false,
            ..hotspot_fr("pkg/store/db_test.go", 0)
        };
        let test_rec = make_file_record_with("file:pkg/store/db_test.go", test_fr);
        let records = vec![hotspot, test_rec];
        let mut gaps = vec![];
        detect_hot_file_no_tests(&records, &mut gaps);
        assert!(gaps.is_empty(), "should not flag when db_test.go exists");
    }

    // ── HighFanInNoContract ─────────────────────────────────────────────

    #[test]
    fn high_fan_in_flags_file_above_threshold_with_no_contracts() {
        let fr = hotspot_fr("src/core.rs", 10);
        let records = vec![make_file_record_with("file:src/core.rs", fr)];
        let fan_in = HashMap::from([("file:src/core.rs".to_string(), 8)]);
        let mut gaps = vec![];
        detect_high_fan_in_no_contract(&records, &fan_in, &mut gaps);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].gap_type, GapType::HighFanInNoContract);
        assert_eq!(gaps[0].key, "file:src/core.rs");
    }

    #[test]
    fn high_fan_in_skips_file_below_threshold() {
        let fr = hotspot_fr("src/core.rs", 10);
        let records = vec![make_file_record_with("file:src/core.rs", fr)];
        // 4 importers — below FAN_IN_THRESHOLD (5)
        let fan_in = HashMap::from([("file:src/core.rs".to_string(), 4)]);
        let mut gaps = vec![];
        detect_high_fan_in_no_contract(&records, &fan_in, &mut gaps);
        assert!(gaps.is_empty());
    }

    #[test]
    fn high_fan_in_skips_file_with_gotcha_keys() {
        let mut fr = hotspot_fr("src/core.rs", 10);
        fr.gotcha_keys = vec!["gotcha:core-invariant".to_string()];
        let records = vec![make_file_record_with("file:src/core.rs", fr)];
        let fan_in = HashMap::from([("file:src/core.rs".to_string(), 10)]);
        let mut gaps = vec![];
        detect_high_fan_in_no_contract(&records, &fan_in, &mut gaps);
        assert!(gaps.is_empty(), "gotcha_keys present — should not flag");
    }

    #[test]
    fn high_fan_in_skips_file_with_decision_keys() {
        let mut fr = hotspot_fr("src/core.rs", 10);
        fr.decision_keys = vec!["decision:use-surrealkv".to_string()];
        let records = vec![make_file_record_with("file:src/core.rs", fr)];
        let fan_in = HashMap::from([("file:src/core.rs".to_string(), 10)]);
        let mut gaps = vec![];
        detect_high_fan_in_no_contract(&records, &fan_in, &mut gaps);
        assert!(gaps.is_empty(), "decision_keys present — should not flag");
    }

    #[test]
    fn high_fan_in_risk_score_uses_fan_in_count() {
        let fr = hotspot_fr("src/core.rs", 10);
        let records = vec![make_file_record_with("file:src/core.rs", fr)];
        let fan_in = HashMap::from([("file:src/core.rs".to_string(), 7)]);
        let mut gaps = vec![];
        detect_high_fan_in_no_contract(&records, &fan_in, &mut gaps);
        assert_eq!(gaps.len(), 1);
        // coverage = 0.0, risk = 7 * 1.0 = 7.0
        assert!((gaps[0].risk_score - 7.0).abs() < f32::EPSILON);
    }

    #[test]
    fn high_fan_in_skipped_when_fan_in_map_is_empty() {
        let fr = hotspot_fr("src/core.rs", 10);
        let records = vec![make_file_record_with("file:src/core.rs", fr)];
        // analyze() skips detect_high_fan_in_no_contract when map is empty
        let gaps = analyze(&records, &[], &[], &[], &HashMap::new());
        assert!(!gaps.iter().any(|g| g.gap_type == GapType::HighFanInNoContract));
    }

    #[test]
    fn high_fan_in_description_mentions_importer_count() {
        let fr = hotspot_fr("src/core.rs", 10);
        let records = vec![make_file_record_with("file:src/core.rs", fr)];
        let fan_in = HashMap::from([("file:src/core.rs".to_string(), 6)]);
        let mut gaps = vec![];
        detect_high_fan_in_no_contract(&records, &fan_in, &mut gaps);
        assert_eq!(gaps.len(), 1);
        assert!(gaps[0].description.contains("6"), "description should mention importer count");
    }

    // ── Sorting ─────────────────────────────────────────────────────────

    #[test]
    fn gaps_sort_by_risk_descending() {
        let mut gaps = [
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
