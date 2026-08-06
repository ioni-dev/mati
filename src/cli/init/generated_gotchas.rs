use super::*;

// ── CODEOWNERS onboarding candidates (idea 2.2) ──────────────────────────────

/// Build CODEOWNERS ownership candidate records, skipping any key that already
/// exists so a re-init never resets a confirmation/edit. Marker candidates are
/// left to the on-demand `mati suggest` (they need a full file-content read,
/// which would blow init's scan budget).
pub(crate) async fn build_codeowners_candidates(
    root: &std::path::Path,
    store: &Store,
    repo_files: &[String],
    device_id: Uuid,
    clock_start: u64,
    now: u64,
) -> Vec<Record> {
    use mati_core::analysis::onboarding;
    let Some(content) = crate::cli::suggest::read_codeowners(root) else {
        return Vec::new();
    };
    let rules = onboarding::parse_codeowners(&content);
    let candidates =
        onboarding::codeowners_candidates(&rules, repo_files, device_id, clock_start, now);
    if candidates.is_empty() {
        return Vec::new();
    }
    let existing: std::collections::HashSet<String> =
        match store.scan_prefix("gotcha:codeowners:").await {
            Ok(records) => records.into_iter().map(|r| r.key).collect(),
            Err(_) => std::collections::HashSet::new(),
        };
    candidates
        .into_iter()
        .filter(|r| !existing.contains(&r.key))
        .collect()
}

// ── Co-change gotcha generation ───────────────────────────────────────────────

/// One auto-generated gotcha derived from a co-change signal.
pub(crate) struct CoChangeGotcha {
    /// The store key: `gotcha:cochange:{source}|{target}`
    pub(crate) key: String,
    /// Repo-relative path of the file this gotcha attaches to.
    pub(crate) source_path: String,
    /// The fully-built Record, ready for `put_batch`.
    pub(crate) record: Record,
}

/// Derive directional co-change gotchas from git history signals.
///
/// For each `(a, b, count)` pair already filtered at `ratio >= CO_CHANGE_THRESHOLD`:
/// - Computes `ratio_a = count / freq_a` and `ratio_b = count / freq_b`.
/// - Creates a gotcha on file A if `ratio_a >= 0.70`, and one on file B if
///   `ratio_b >= 0.70`. Asymmetric pairs produce only the constrained direction.
///
/// The rule text uses per-file denominators so the numbers are always accurate
/// from the reader's perspective: "changed together in 47/60 commits (78%)".
///
/// Volume cap: at most 5 gotchas per source file, ordered by co-change count.
pub(crate) fn build_cochange_gotchas(
    signals: &mati_core::analysis::GitSignals,
    device_id: Uuid,
    logical_clock_start: u64,
    now: u64,
) -> Vec<CoChangeGotcha> {
    const THRESHOLD: f64 = 0.70;
    const STRONG_RATIO: f64 = 0.90;
    const STRONG_COUNT: u32 = 20;
    const MAX_PER_FILE: usize = 5;
    // At least 3 co-changes required before generating a gotcha.
    // Eliminates "1/1 (100%)" noise on young repos where every commit
    // touched multiple files — the signal has no statistical weight.
    const MIN_COUNT: u32 = 3;

    // Expand each unordered pair into up to two directed edges.
    // Each candidate: (source_path, target_path, count, ratio_from_source_pov)
    let mut candidates: Vec<(String, String, u32, f64)> = Vec::new();

    for (a, b, count) in &signals.co_change_pairs {
        let freq_a = match signals.change_frequency.get(a) {
            Some(&f) if f > 0 => f as f64,
            _ => continue,
        };
        let freq_b = match signals.change_frequency.get(b) {
            Some(&f) if f > 0 => f as f64,
            _ => continue,
        };
        let ratio_a = *count as f64 / freq_a;
        let ratio_b = *count as f64 / freq_b;

        if ratio_a >= THRESHOLD && *count >= MIN_COUNT {
            candidates.push((a.clone(), b.clone(), *count, ratio_a));
        }
        if ratio_b >= THRESHOLD && *count >= MIN_COUNT {
            candidates.push((b.clone(), a.clone(), *count, ratio_b));
        }
    }

    // Sort: group by source file, then descending count within each group
    // so the cap keeps the strongest signals per file.
    candidates.sort_by(|x, y| x.0.cmp(&y.0).then(y.2.cmp(&x.2)));

    let mut per_source_count: HashMap<String, usize> = HashMap::new();
    let mut clock_offset: u64 = 0;
    let mut result: Vec<CoChangeGotcha> = Vec::new();

    for (source, target, count, ratio) in candidates {
        let seen = per_source_count.entry(source.clone()).or_insert(0);
        if *seen >= MAX_PER_FILE {
            continue;
        }
        *seen += 1;

        let freq_source = signals.change_frequency.get(&source).copied().unwrap_or(1);
        let pct = (ratio * 100.0).round() as u32;

        let rule = format!(
            "Always check `{target}` when editing this file — changed together in {count}/{freq_source} commits ({pct}%).",
        );
        let reason = "Co-change signal from git history — modifying one without the other is a known source of bugs.".to_string();

        let (quality, conf_value, severity) = if ratio >= STRONG_RATIO && count >= STRONG_COUNT {
            (QualityScore::cochange_strong(), 0.65_f32, Priority::High)
        } else {
            (QualityScore::cochange_default(), 0.45_f32, Priority::Normal)
        };

        // Cochange gotchas are Layer 0 stubs derived from git history, not
        // developer-confirmed. They surface as candidates in `mati review` and
        // appear in graph queries / blast radius, but they never trigger hook
        // injection until a developer confirms them via `mati gotcha confirm`.
        // Marking these `confirmed: true` would break the schema invariant
        // "confirmed → confidence >= 0.80" (these sit at 0.45 / 0.65).
        let gotcha = GotchaRecord {
            rule: rule.clone(),
            reason,
            severity: severity.clone(),
            affected_files: vec![source.clone()],
            ref_url: None,
            discovered_session: now,
            confirmed: false,
            confirmed_content: Default::default(),
        };

        let key = format!("gotcha:cochange:{source}|{target}");
        let mut rec =
            Record::layer0_file_stub(&key, device_id, logical_clock_start + clock_offset, now);
        rec.category = Category::Gotcha;
        rec.source = RecordSource::StaticAnalysis;
        rec.priority = severity;
        rec.value = rule;
        rec.quality = quality;
        rec.confidence.value = conf_value;
        rec.tags = vec!["co-change".to_string(), "auto-generated".to_string()];
        rec.payload = serde_json::to_value(&gotcha).ok();
        clock_offset += 1;

        result.push(CoChangeGotcha {
            key,
            source_path: source,
            record: rec,
        });
    }

    result
}

// ── Revert gotcha generation ──────────────────────────────────────────────────

/// One auto-generated gotcha stub derived from a revert signal.
pub(crate) struct RevertGotcha {
    /// The store key: `gotcha:revert:{path}`
    pub(crate) key: String,
    /// Repo-relative path of the file this gotcha attaches to.
    pub(crate) source_path: String,
    /// The fully-built Record, ready for `put_batch`.
    pub(crate) record: Record,
}

/// Derive revert-instability gotcha stubs from git history signals.
///
/// A `confirmed=false` stub is created for each file with a revert rate >=
/// `MIN_REVERT_RATE` AND at least `MIN_REVERTS` absolute revert commits.
/// The absolute floor prevents a single revert on a new file (e.g. 1/5 = 20%)
/// from triggering. These surface in `mati review` for developer confirmation.
pub(crate) fn build_revert_gotchas(
    signals: &mati_core::analysis::GitSignals,
    change_frequency: &std::collections::HashMap<String, u32>,
    device_id: Uuid,
    logical_clock_start: u64,
    now: u64,
) -> Vec<RevertGotcha> {
    const MIN_REVERTS: u32 = 2;
    const MIN_REVERT_RATE: f32 = 0.05;

    let mut candidates: Vec<(&String, u32, f32)> = signals
        .revert_counts
        .iter()
        .filter_map(|(path, &count)| {
            if count < MIN_REVERTS {
                return None;
            }
            let total = *change_frequency.get(path).unwrap_or(&0);
            if total == 0 {
                return None;
            }
            let rate = count as f32 / total as f32;
            if rate >= MIN_REVERT_RATE {
                Some((path, count, rate))
            } else {
                None
            }
        })
        .collect();

    // Highest rate first; break ties by count then alphabetically.
    candidates.sort_by(|a, b| {
        b.2.partial_cmp(&a.2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.0.cmp(b.0))
    });

    let mut result: Vec<RevertGotcha> = Vec::new();

    for (clock_offset, (path, count, rate)) in candidates.into_iter().enumerate() {
        let clock_offset = clock_offset as u64;
        let pct = (rate * 100.0).round() as u32;
        let rule = format!(
            "High revert rate ({pct}% of commits, {count} reverts) — this interface has been broken and undone repeatedly. Test carefully before touching.",
        );
        let reason =
            "Repeated reverts in git history indicate contested or fragile logic.".to_string();

        let gotcha = GotchaRecord {
            rule: rule.clone(),
            reason,
            severity: Priority::Normal,
            affected_files: vec![path.clone()],
            ref_url: None,
            discovered_session: now,
            confirmed: false,
            confirmed_content: Default::default(),
        };

        let key = format!("gotcha:revert:{path}");
        let mut rec =
            Record::layer0_file_stub(&key, device_id, logical_clock_start + clock_offset, now);
        rec.category = Category::Gotcha;
        rec.source = RecordSource::StaticAnalysis;
        rec.priority = Priority::Normal;
        rec.value = rule;
        rec.quality = QualityScore::cochange_default();
        rec.confidence.value = 0.35;
        rec.tags = vec!["revert".to_string(), "auto-generated".to_string()];
        rec.payload = serde_json::to_value(&gotcha).ok();

        result.push(RevertGotcha {
            key,
            source_path: path.clone(),
            record: rec,
        });
    }

    result
}

// ── Ownership concentration gotcha generation ─────────────────────────────────

/// One auto-generated gotcha stub derived from an ownership concentration signal.
pub(crate) struct OwnershipGotcha {
    /// The store key: `gotcha:ownership:{path}`
    pub(crate) key: String,
    /// Repo-relative path of the file this gotcha attaches to.
    pub(crate) source_path: String,
    /// The fully-built Record, ready for `put_batch`.
    pub(crate) record: Record,
}

/// Derive ownership-concentration gotcha stubs from git history signals.
///
/// A `confirmed=false` stub is created for each hotspot file where a single
/// author contributed >= `CONCENTRATION_THRESHOLD` of all commits. This signals
/// a knowledge silo: if that person leaves, context for the file is lost.
pub(crate) fn build_ownership_gotchas(
    signals: &mati_core::analysis::GitSignals,
    device_id: Uuid,
    logical_clock_start: u64,
    now: u64,
) -> Vec<OwnershipGotcha> {
    // >80% of commits by one author — strong silo signal.
    const CONCENTRATION_THRESHOLD: f64 = 0.80;
    // Require at least 5 commits before flagging — avoids noise on new files.
    const MIN_COMMITS: u32 = 5;

    let hotspot_set: std::collections::HashSet<&String> = signals.hotspot_files.iter().collect();

    let mut candidates: Vec<(&String, String, u32, f64)> = Vec::new();

    for (path, author_counts) in &signals.author_commit_counts {
        // Only flag hotspot files — low-traffic files aren't a meaningful silo risk.
        if !hotspot_set.contains(path) {
            continue;
        }

        let total: u32 = author_counts.values().sum();
        if total < MIN_COMMITS {
            continue;
        }

        if let Some((top_author, &top_count)) = author_counts.iter().max_by_key(|(_, &c)| c) {
            let ratio = top_count as f64 / total as f64;
            if ratio >= CONCENTRATION_THRESHOLD {
                candidates.push((path, top_author.clone(), top_count, ratio));
            }
        }
    }

    // Highest concentration first; break ties alphabetically by path.
    candidates.sort_by(|a, b| {
        b.3.partial_cmp(&a.3)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(b.0))
    });

    let mut result: Vec<OwnershipGotcha> = Vec::new();

    for (clock_offset, (path, top_author, top_count, ratio)) in candidates.into_iter().enumerate() {
        let clock_offset = clock_offset as u64;
        let total = signals
            .change_frequency
            .get(path)
            .copied()
            .unwrap_or(top_count);
        let pct = (ratio * 100.0).round() as u32;

        let rule = format!(
            "{pct}% of commits by {top_author} ({top_count}/{total}) — key person dependency on this hotspot file.",
        );
        let reason = "Single-author dominance on a high-traffic file is a knowledge silo risk — context may be lost if that person is unavailable.".to_string();

        let gotcha = GotchaRecord {
            rule: rule.clone(),
            reason,
            severity: Priority::Normal,
            affected_files: vec![path.clone()],
            ref_url: None,
            discovered_session: now,
            confirmed: false,
            confirmed_content: Default::default(),
        };

        let key = format!("gotcha:ownership:{path}");
        let mut rec =
            Record::layer0_file_stub(&key, device_id, logical_clock_start + clock_offset, now);
        rec.category = Category::Gotcha;
        rec.source = RecordSource::StaticAnalysis;
        rec.priority = Priority::Normal;
        rec.value = rule;
        rec.quality = QualityScore::cochange_default();
        rec.confidence.value = 0.40;
        rec.tags = vec!["ownership".to_string(), "auto-generated".to_string()];
        rec.payload = serde_json::to_value(&gotcha).ok();

        result.push(OwnershipGotcha {
            key,
            source_path: path.clone(),
            record: rec,
        });
    }

    result
}

/// Build a minimal sessions-tree Record for a parse-cache blob.
///
/// Used for `parse:mtime_index` (JSON blob) — Eventual durability, sessions tree.
#[allow(dead_code)]
fn make_hash_record(key: &str, hash: &str, device_id: Uuid, now: u64) -> Record {
    Record {
        key: key.to_string(),
        value: hash.to_string(),
        category: Category::Analytics,
        priority: Priority::Normal,
        tags: vec![],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id,
            logical_clock: 1,
            wall_clock: now,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
        payload: None,
    }
}

pub(crate) fn stale_dependency_keys(existing: &[Record], new_keys: &HashSet<&str>) -> Vec<String> {
    existing
        .iter()
        .filter(|rec| rec.category == Category::Dependency)
        .filter(|rec| !new_keys.contains(rec.key.as_str()))
        .map(|rec| rec.key.clone())
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────
