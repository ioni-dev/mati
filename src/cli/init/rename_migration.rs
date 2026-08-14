use super::*;

// ── Rename migration ─────────────────────────────────────────────────────────

/// Marks a gotcha whose `affected_files` this pass re-keyed onto a renamed path.
///
/// A rename is a mechanical fact; whether the *rule* still holds at the new path
/// is not. The obvious alternative — dropping confidence — would push the record
/// under the 0.6 gate and disable enforcement, which is the failure mode this
/// whole pass exists to fix. So the gotcha keeps enforcing and carries a flag
/// instead. Bare kebab-case to match the other review markers
/// (`severity-disputed`, `crown-jewel`).
pub(crate) const TAG_PATH_MIGRATED: &str = "path-migrated";

/// Auto-generated Layer-0 gotchas, regenerated from fresh git signals on every
/// init and tombstoned when their signal drops out (§8c). Their `affected_files`
/// are already derived from current paths.
pub(crate) fn is_auto_gotcha(key: &str) -> bool {
    key.starts_with("gotcha:cochange:")
        || key.starts_with("gotcha:revert:")
        || key.starts_with("gotcha:ownership:")
}

/// A planned `affected_files` rewrite for one gotcha.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RenameMigration {
    pub(super) key: String,
    /// `affected_files` exactly as stored — what `sync_gotcha_file_links` needs
    /// in order to unlink the old `file:*` records, legacy spellings included.
    pub(super) old_files: Vec<String>,
    /// The rewritten list, normalized through the write-side normalizer.
    pub(super) new_files: Vec<String>,
    /// The (old, new) pairs this record actually followed.
    pub(super) followed: Vec<(String, String)>,
}

/// One applied migration, for the init summary.
pub(crate) struct AppliedRename {
    pub(super) key: String,
    pub(super) followed: Vec<(String, String)>,
    /// The gotcha compiles into the sandbox deny floor (`cli::sandbox`), whose
    /// materialized copy still names the old path.
    pub(super) sandbox_tagged: bool,
}

/// Plan the `affected_files` rewrites implied by `renames`. Pure apart from the
/// `exists()` probes, which are what make the plan safe.
///
/// `renames` is `GitSignals::recent_renames` — despite the name, every rename
/// git2 detected across the whole `MAX_COMMITS` window, newest first
/// (`analysis::git` walks with `Sort::TIME`). That is the right window here:
/// following an old rename is still correct as long as the two disk probes
/// below hold, and narrowing it would only lose migrations. Cost is bounded by
/// the number of renames, not by history length.
pub(crate) fn plan_rename_migrations(
    renames: &[(String, String)],
    gotchas: &[Record],
    root: &std::path::Path,
) -> Vec<RenameMigration> {
    if renames.is_empty() {
        return Vec::new();
    }

    // old → new. The first decision for a given `old` is final, so a path
    // renamed away more than once follows its newest move and duplicate deltas
    // (the same rename replayed across commits) collapse.
    //
    // Two probes decide whether a pair is followable:
    //   * `old` still on disk — a copy rather than a move, or the path was
    //     re-created since. The gotcha still describes a real file; leave it.
    //   * `new` missing — the target moved on again or is gone. Nothing to
    //     point the gotcha at, and rewriting would only relocate the orphan.
    let mut moves: HashMap<&str, &str> = HashMap::new();
    let mut decided: HashSet<&str> = HashSet::new();
    for (old, new) in renames {
        if old == new || !decided.insert(old.as_str()) {
            continue;
        }
        if root.join(old).exists() || !root.join(new).exists() {
            continue;
        }
        moves.insert(old.as_str(), new.as_str());
    }
    if moves.is_empty() {
        return Vec::new();
    }

    let mut plans = Vec::new();
    for rec in gotchas {
        if !matches!(rec.lifecycle, RecordLifecycle::Active) || is_auto_gotcha(&rec.key) {
            continue;
        }
        let Some(g) = rec.payload_as::<GotchaRecord>() else {
            continue; // CLAUDE.md-imported gotchas carry no affected_files.
        };

        let mut followed: Vec<(String, String)> = Vec::new();
        let rewritten: Vec<String> = g
            .affected_files
            .iter()
            .map(|f| match moves.get(f.as_str()) {
                Some(new) => {
                    followed.push((f.clone(), (*new).to_string()));
                    (*new).to_string()
                }
                None => f.clone(),
            })
            .collect();
        if followed.is_empty() {
            // Nothing named a renamed path — the steady state on every re-init
            // once a rename has been followed, so this pass is a no-op then.
            continue;
        }

        // Through the write-side normalizer, against init's own root rather
        // than a cwd-discovered one, so the stored strings are the ones the
        // read gate looks up. It also collapses duplicates, which is what
        // makes a gotcha already naming BOTH the old and the new path resolve
        // to a single entry instead of listing the target twice.
        let new_files = mati_core::store::gotcha_ops::normalize_affected_files_with_root(
            &rewritten,
            root.to_str(),
        );
        if new_files == g.affected_files {
            continue;
        }

        plans.push(RenameMigration {
            key: rec.key.clone(),
            old_files: g.affected_files.clone(),
            new_files,
            followed,
        });
    }
    plans
}

/// Apply the planned rewrites: re-key each gotcha, move its `file:*` links and
/// `HasGotcha` edges, and retire the orphaned `file:<old>` records.
///
/// `gotchas` is updated in place from the store so §8c back-fills the new paths.
pub(crate) async fn migrate_renamed_gotchas(
    store: &Store,
    root: &std::path::Path,
    renames: &[(String, String)],
    gotchas: &mut [Record],
) -> Vec<AppliedRename> {
    let plans = plan_rename_migrations(renames, gotchas, root);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut applied = Vec::new();
    for plan in plans {
        let Some(rec) = gotchas.iter_mut().find(|r| r.key == plan.key) else {
            continue;
        };

        // Rule text, confidence and quality are left exactly as they were.
        // Only the binding moved; re-scoring here would change enforcement.
        let sandbox_tagged = rec
            .tags
            .iter()
            .any(|t| t == super::sandbox::TAG_DENY_WRITE || t == super::sandbox::TAG_DENY_READ);
        if !rec.tags.iter().any(|t| t == TAG_PATH_MIGRATED) {
            rec.tags.push(TAG_PATH_MIGRATED.to_string());
        }
        rec.updated_at = now;
        rec.version.logical_clock += 1;
        rec.version.wall_clock = now;

        // `apply_gotcha_write` rather than a bare `sync_gotcha_file_links`:
        // it is the centralized mutation path (CLAUDE.md), and it also patches
        // the payload's `affected_files` from `new_files`, moves the HasGotcha
        // edges, records the `ControlChanged::Updated` enforcement event, and
        // carries the dirty-marker cancellation guard.
        if let Err(e) = mati_core::store::gotcha_ops::apply_gotcha_write(
            store,
            root,
            rec,
            &plan.old_files,
            &plan.new_files,
            false,
        )
        .await
        {
            tracing::warn!("init: rename migration failed for {}: {e}", plan.key);
            continue;
        }

        // Re-read so §8c sees what was actually persisted rather than this
        // record's pre-migration payload.
        if let Ok(Some(fresh)) = store.get(&plan.key).await {
            *rec = fresh;
        }

        // Retire the orphaned `file:<old>`. The link sync above already removed
        // this gotcha from it; delete the record outright once nothing else
        // references it and nothing exists at that path. Leaving it is not
        // neutral — `StalenessAnalyzer` tombstones a vanished file, and the gate
        // passes a tombstoned record through unconditionally, so a later
        // re-creation of that path would inherit a silent allow. `NoRecord`
        // logs a miss instead, which is the honest state.
        for (old, _) in &plan.followed {
            if root.join(old).exists() {
                continue;
            }
            let file_key = format!("file:{old}");
            let still_linked = match store.get(&file_key).await {
                Ok(Some(r)) => r
                    .payload_as::<FileRecord>()
                    .map(|f| !f.gotcha_keys.is_empty())
                    .unwrap_or(true),
                _ => continue,
            };
            if !still_linked {
                if let Err(e) = store.delete(&file_key).await {
                    tracing::warn!("init: retiring orphaned {file_key} failed: {e}");
                }
            }
        }

        applied.push(AppliedRename {
            key: plan.key,
            followed: plan.followed,
            sandbox_tagged,
        });
    }
    applied
}
