use super::*;

// ── Factor functions ────────────────────────────────────────────────────────

/// Time factor: linear ramp from 0.0 to 1.0 over TIME_STALE_DAYS.
///
/// Uses `max(updated_at, last_accessed)` as the reference timestamp, NOT
/// `computed_at` (which is when staleness was last recalculated, not when the
/// record was last meaningfully touched).
pub(crate) fn time_factor(record: &Record, now: u64) -> f32 {
    let last_touch = record.updated_at.max(record.last_accessed);
    if last_touch == 0 || last_touch >= now {
        return 0.0;
    }

    let elapsed_secs = (now - last_touch) as f64;
    let elapsed_days = elapsed_secs / SECS_PER_DAY;
    let factor = (elapsed_days / TIME_STALE_DAYS).min(1.0);

    factor as f32
}

/// Semantic factor: placeholder for v0.1 — always returns 0.0.
///
/// In v0.2+ this will use candle embeddings to measure semantic drift between
/// the record's content and the current file content.
pub(crate) fn semantic_factor() -> f32 {
    0.0
}

/// Dependency factor: checks if any imports in the file record reference
/// dependencies whose versions have been bumped since the record was last
/// updated.
///
/// LIMITATION (v0.1): Only parses Rust `use` statements from `FileRecord.imports`.
/// Other languages (TypeScript, Python, Go) will be supported when their import
/// parsers emit normalized dependency names.
pub(crate) fn dep_factor(
    file_record: Option<&FileRecord>,
    dep_cache: &HashMap<String, Record>,
) -> f32 {
    let fr = match file_record {
        Some(fr) => fr,
        None => return 0.0,
    };

    if fr.imports.is_empty() || dep_cache.is_empty() {
        return 0.0;
    }

    let mut bumped_count = 0u32;
    let mut checked_count = 0u32;

    for import in &fr.imports {
        let dep_record = dep_lookup_keys(import)
            .into_iter()
            .find_map(|key| dep_cache.get(&key));

        if let Some(dep_record) = dep_record {
            checked_count += 1;

            // Check if the dep was updated more recently than the file record.
            if dep_record.updated_at > fr.last_modified_session {
                // Check for DependencyBumped signal on the dep record.
                let has_bump_signal = dep_record
                    .staleness
                    .signals
                    .iter()
                    .any(|s| matches!(s, StalenessSignal::DependencyBumped { .. }));
                if has_bump_signal || dep_record.updated_at > fr.last_modified_session + 1 {
                    bumped_count += 1;
                }
            }
        }
    }

    if checked_count == 0 {
        return 0.0;
    }

    // More bumped deps -> higher staleness. Cap at 1.0.
    let ratio = bumped_count as f32 / checked_count as f32;
    ratio.min(1.0)
}

pub(crate) fn dep_lookup_keys(import: &str) -> Vec<String> {
    let mut keys = Vec::new();

    if let Some(crate_name) = import
        .split("::")
        .next()
        .filter(|name| *name != import || import.contains("::"))
    {
        push_dep_key(&mut keys, "cargo", crate_name);
        keys.push(format!("dep:{crate_name}"));
    }

    if let Some(package_name) = npm_package_name(import) {
        push_dep_key(&mut keys, "npm", package_name);
        keys.push(format!("dep:{package_name}"));
    }

    for module_name in go_module_candidates(import) {
        push_dep_key(&mut keys, "go", &module_name);
        keys.push(format!("dep:{module_name}"));
    }

    keys
}

pub(crate) fn push_dep_key(keys: &mut Vec<String>, ecosystem: &str, name: &str) {
    let key = format!("dep:{ecosystem}:{name}");
    if !keys.contains(&key) {
        keys.push(key);
    }
}

pub(crate) fn npm_package_name(import: &str) -> Option<&str> {
    if import.is_empty()
        || import.starts_with('.')
        || import.starts_with('/')
        || import.contains("::")
        || first_path_segment(import).is_some_and(|seg| seg.contains('.'))
    {
        return None;
    }

    if import.starts_with('@') {
        let mut segments = import.split('/');
        let scope = segments.next()?;
        let package = segments.next()?;
        let len = scope.len() + 1 + package.len();
        Some(&import[..len])
    } else {
        first_path_segment(import)
    }
}

pub(crate) fn go_module_candidates(import: &str) -> Vec<String> {
    if import.is_empty()
        || import.starts_with('.')
        || import.starts_with('/')
        || import.contains("::")
        || !first_path_segment(import).is_some_and(|seg| seg.contains('.'))
    {
        return Vec::new();
    }

    let segments: Vec<&str> = import.split('/').collect();
    let mut modules = Vec::new();
    for len in (2..=segments.len()).rev() {
        let module = segments[..len].join("/");
        if !modules.contains(&module) {
            modules.push(module);
        }
    }
    modules
}

pub(crate) fn first_path_segment(import: &str) -> Option<&str> {
    import
        .split('/')
        .next()
        .filter(|segment| !segment.is_empty())
}

/// Cascade factor: for file records, check if linked gotchas/decisions are stale.
/// For gotcha records, check if affected_files have stale records.
pub(crate) async fn cascade_factor(
    record: &Record,
    file_record: Option<&FileRecord>,
    store: &Store,
) -> f32 {
    match record.category {
        Category::File => {
            let fr = match file_record {
                Some(fr) => fr,
                None => return 0.0,
            };

            let linked_keys: Vec<&str> = fr
                .gotcha_keys
                .iter()
                .chain(fr.decision_keys.iter())
                .map(|s| s.as_str())
                .collect();

            if linked_keys.is_empty() {
                return 0.0;
            }

            let mut stale_count = 0u32;
            for key in &linked_keys {
                if let Ok(Some(linked)) = store.get(key).await {
                    if linked.staleness.value >= 0.4 {
                        stale_count += 1;
                    }
                }
            }

            if stale_count == 0 {
                return 0.0;
            }

            let ratio = stale_count as f32 / linked_keys.len() as f32;
            ratio.min(1.0)
        }
        Category::Gotcha => {
            // Parse the gotcha to find affected_files.
            let gotcha: Option<GotchaRecord> = record.payload_as::<GotchaRecord>();
            let gotcha = match gotcha {
                Some(g) => g,
                None => return 0.0,
            };

            if gotcha.affected_files.is_empty() {
                return 0.0;
            }

            let mut stale_count = 0u32;
            for path in &gotcha.affected_files {
                let file_key = format!("file:{path}");
                if let Ok(Some(file_rec)) = store.get(&file_key).await {
                    if file_rec.staleness.value >= 0.4 {
                        stale_count += 1;
                    }
                }
            }

            if stale_count == 0 {
                return 0.0;
            }

            let ratio = stale_count as f32 / gotcha.affected_files.len() as f32;
            ratio.min(1.0)
        }
        _ => 0.0,
    }
}
