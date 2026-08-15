use super::*;

// ── Key collision ────────────────────────────────────────────────────────────

/// Bail if `key` already exists as an active record.
///
/// Called before writing a new gotcha to prevent silent overwrites.
pub async fn ensure_gotcha_key_available(store: &Store, key: &str) -> Result<()> {
    if store.get(key).await?.is_some() {
        anyhow::bail!("gotcha key '{key}' already exists; edit the existing record instead");
    }
    Ok(())
}

// ── Full mutation operations ─────────────────────────────────────────────────

/// Write a gotcha record and maintain all related state:
///
/// 1. If `is_new`, check for key collision.
/// 2. Write the record to the store.
/// 3. Sync `gotcha_keys` in affected file records (add to new files, remove
///    from old files).
/// 4. Add `HasGotcha` graph edges for newly-associated files.
/// 5. Remove `HasGotcha` graph edges for disassociated files.
///
/// Steps 1–2 fail hard (the caller sees an error). Steps 3–5 are
/// best-effort: failures are logged but do not roll back the record write.
///
/// `new_files` and the record's payload `affected_files` are normalized first
/// (see [`normalize_affected_files`]) so the stored paths are the ones the read
/// gate looks up. `old_files` is deliberately left verbatim: it describes what
/// the derived indexes actually contain — possibly an unnormalized legacy
/// spelling — and [`sync_gotcha_file_links`] needs the real key to unlink.
///
/// If `record` arrives `Tombstoned`, steps 3–5 diff against an empty old-file
/// set instead of the caller's `old_files`: `apply_gotcha_tombstone` already
/// tore down every link and edge, so the caller's `old_files` no longer
/// describes what the indexes hold, and diffing against it would no-op on an
/// unchanged `affected_files`, leaving the resurrected record unlinked.
///
/// `repo_root` is the root the store's slug was keyed on
/// ([`crate::store::slug_root`]) — what a confirmed record's content stamp is
/// hashed against.
pub async fn apply_gotcha_write(
    store: &Store,
    repo_root: &Path,
    record: &Record,
    old_files: &[String],
    new_files: &[String],
    is_new: bool,
) -> Result<()> {
    let new_files = &normalize_affected_files(new_files, repo_root);
    let mut staged = with_normalized_affected_files(record, new_files);

    // A write through this function is a create or an edit of live content —
    // never a tombstone, which is `apply_gotcha_tombstone`'s job alone. Force
    // `Active` unconditionally so this mirrors `mcp::handlers::
    // handle_gotcha_upsert`'s own unconditional reset. Without it, an edit
    // that reaches a tombstoned key over this direct (no-daemon) path
    // persists the record but leaves it `Tombstoned` — invisible to
    // `mem_get`, which filters that lifecycle on read — so the write lands
    // with no visible effect and no error.
    let was_tombstoned = !matches!(
        staged.as_ref().unwrap_or(record).lifecycle,
        RecordLifecycle::Active
    );
    if was_tombstoned {
        let mut owned = staged.take().unwrap_or_else(|| record.clone());
        owned.lifecycle = RecordLifecycle::Active;
        staged = Some(owned);
    }

    // A new record that already carries `confirmed: true` is a developer
    // vouching for the rule right now — the direct-store `mati gotcha add`
    // path — so it earns the same content stamp `apply_gotcha_confirm`
    // writes. Without it the most common way to create an *enforcing* gotcha
    // would never be able to report drift.
    //
    // Guarded on `is_new` deliberately. Re-stamping on an edit would read the
    // file as it is now and silently clear the drift of a rule whose text was
    // tweaked but whose code nobody re-read — and the rename migration in
    // `cli::init` edits confirmed gotchas, where a moved path is precisely not
    // a content change. Layer 0 stubs, `mem_set` upserts and review edits all
    // write `confirmed: false`, so this is inert on every bulk path.
    if is_new && payload_is_confirmed(staged.as_ref().unwrap_or(record)) {
        let stamp = confirm_content_stamp(repo_root, new_files);
        let mut owned = staged.take().unwrap_or_else(|| record.clone());
        set_confirm_stamp(&mut owned, &stamp);
        staged = Some(owned);
    }

    let record = staged.as_ref().unwrap_or(record);
    let key = &record.key;

    // 1. Collision guard — fail hard
    if is_new {
        ensure_gotcha_key_available(store, key).await?;
    }

    // 2. Persist the gotcha record — fail hard
    store.put(key, record).await?;

    // 2a. Pre-arm the dirty marker so cancellation between here and the end of
    //     the derived-index work is recoverable. Without this, a future drop
    //     mid-loop (e.g. socket-handler abort on shutdown drain timeout) would
    //     leave file_keys / graph edges partially synced with NO dirty marker,
    //     and `repair_fast` on next start would silently skip the orphaned key
    //     because `is_dirty()` returns false. Marking up-front guarantees
    //     `repair_fast` re-reconciles this key on the next boot. Released
    //     (cleared) only after every secondary write returns; on the all-success
    //     path this is a single extra fsync per gotcha write.
    crate::store::repair::mark_dirty(store, key, "gotcha_write: pre-arm cancellation guard").await;

    // 2b. Record enforcement event — best-effort (advisory mode logged, strict propagated)
    let change_kind = if is_new {
        ControlChangeKind::Created
    } else {
        ControlChangeKind::Updated
    };
    if let Err(e) = record_event(
        store,
        EnforcementEventType::ControlChanged { change_kind },
        SubjectKind::Control,
        key.to_string(),
        "developer".to_string(),
        None,
        if is_new {
            "control_created".to_string()
        } else {
            "control_updated".to_string()
        },
        None,
    )
    .await
    {
        tracing::warn!("gotcha_write: enforcement event recording failed for {key}: {e}");
    }

    // 2c. Extraction tracking — best-effort (D3 foundation).
    //
    // If the record's tags include "enriched" (set by `/mati-enrich`'s
    // Stage 4 prompt), this gotcha is an enrichment output. We write an
    // ExtractionRecord with outcome=Pending so `mati doctor` can later
    // surface per-tier accuracy stats. Records without "enriched"
    // (manual `mati gotcha add`, MCP `mem_set` from non-enrichment flows)
    // are NOT tracked — keeps the analytics scoped to the enrichment
    // pipeline. Only fires on new writes; updates don't re-create.
    if is_new {
        let _ = crate::store::extraction::write_on_extraction(store, key, &record.tags, new_files)
            .await;
    }

    let mut secondary_failed = false;

    // A key that was tombstoned had its links and edges torn down by
    // `apply_gotcha_tombstone` regardless of `affected_files`. Diffing
    // against the caller's `old_files` here would see `old == new` for an
    // unchanged file list and no-op, leaving the resurrected record
    // unlinked. Treat resurrection as relinking every current file, the same
    // way `handle_gotcha_upsert` does when it derives `is_new` from a
    // tombstoned `existing` and finds no prior links to diff against.
    let sync_old_files: &[String] = if was_tombstoned { &[] } else { old_files };

    // 3. Sync file-record gotcha_keys — best-effort
    if let Err(e) = sync_gotcha_file_links(store, key, sync_old_files, new_files).await {
        tracing::warn!("gotcha_write: file link sync failed for {key}: {e}");
        secondary_failed = true;
        crate::store::repair::mark_dirty(store, key, &format!("link sync failed: {e}")).await;
    }

    // 4 + 5. Graph edges — best-effort. Runs while the pre-armed guard from
    // 2a is still set, so the marker stays continuously armed from the
    // record commit through the last derived write.
    if !sync_has_gotcha_edges(store, key, sync_old_files, new_files).await {
        secondary_failed = true;
    }

    // Disarm the cancellation guard if every secondary write succeeded AND
    // no other key was concurrently flagged. See `clear_dirty_key_if_solo`
    // for the reasoning — we err on the side of leaving the marker set so
    // `repair_fast` on the next boot reconciles any drift; a no-op repair
    // is cheap, a missed repair is silent corruption.
    if !secondary_failed {
        crate::store::repair::clear_dirty_key_if_solo(store, key).await;
    }

    Ok(())
}

/// Tombstone a gotcha record and clean up all related state:
///
/// 1. Set lifecycle to `Tombstoned`, bump version.
/// 2. Remove `gotcha_keys` entries from all affected file records.
/// 3. Remove all `HasGotcha` graph edges.
///
/// Step 1 fails hard. Steps 2–3 are best-effort: failures are logged but
/// do not un-tombstone the record.
pub async fn apply_gotcha_tombstone(
    store: &Store,
    key: &str,
    affected_files: &[String],
) -> Result<()> {
    // 1. Tombstone the record — fail hard.
    //
    // Snapshot the rule/reason/severity from the payload BEFORE flipping
    // lifecycle to Tombstoned. The negative-exemplar archive write
    // (step 1c below) needs them.
    let mut exemplar_snapshot: Option<(String, String, crate::store::Priority)> = None;
    match store.get(key).await? {
        Some(record) => {
            if let Some(ref payload) = record.payload {
                if let Ok(gr) =
                    serde_json::from_value::<crate::store::GotchaRecord>(payload.clone())
                {
                    exemplar_snapshot = Some((gr.rule, gr.reason, gr.severity));
                }
            }
            let record = tombstoned_copy(&record, TombstoneReason::ManualDeletion, now_secs());
            store.put(key, &record).await?;
        }
        None => anyhow::bail!("record not found: {key}"),
    }

    // 1a. Pre-arm cancellation guard. Same reasoning as `apply_gotcha_write`:
    //     a future drop between the tombstone commit and the end of the
    //     derived-index loop would leave file_keys / graph edges referring
    //     to a tombstoned gotcha with no dirty marker, which `repair_fast`
    //     would silently skip on the next boot. Pre-arming forces
    //     reconciliation. Cleared at the end if every secondary write succeeded.
    crate::store::repair::mark_dirty(store, key, "gotcha_tombstone: pre-arm cancellation guard")
        .await;
    let mut secondary_failed = false;

    // 1b. Record enforcement event for deletion — best-effort
    if let Err(e) = record_event(
        store,
        EnforcementEventType::ControlChanged {
            change_kind: ControlChangeKind::Deleted,
        },
        SubjectKind::Control,
        key.to_string(),
        "developer".to_string(),
        None,
        "control_deleted".to_string(),
        None,
    )
    .await
    {
        tracing::warn!("gotcha_tombstone: enforcement event recording failed for {key}: {e}");
    }

    // 1c. Negative-exemplar archive write — best-effort (D3 foundation).
    //
    // Captures rule + reason + severity into
    // `analytics:negative_exemplar:<dirname>:<slug>` for each unique
    // dirname in `affected_files`. Future `/mati-enrich` runs on the
    // same directory read these via `mati ls tombstoned` (D2-β) and
    // feed them to the LLM as NEGATIVE exemplars in Stage 2 prompts.
    // This is the closed-loop quality mechanism that lets the extractor
    // get sharper at this codebase over time.
    //
    // Failure does NOT block the tombstone — the gotcha is already gone
    // from the canonical store; the exemplar archive is a learning
    // signal, not a correctness invariant.
    if let Some((rule, reason, severity)) = exemplar_snapshot.as_ref() {
        match crate::store::negative_exemplar::write_on_tombstone(
            store,
            key,
            rule,
            reason,
            severity,
            affected_files,
        )
        .await
        {
            Ok(n) => tracing::debug!(
                "gotcha_tombstone: negative_exemplar archived for {key} across {n} dirname(s)"
            ),
            Err(e) => {
                tracing::warn!("gotcha_tombstone: negative_exemplar write failed for {key}: {e}")
            }
        }
    } else {
        tracing::debug!(
            "gotcha_tombstone: no GotchaRecord payload on {key}; skipping negative_exemplar archive"
        );
    }

    // 1d. Mark matching ExtractionRecord as Tombstoned. No-op when this
    // gotcha wasn't from `/mati-enrich`. Best-effort — never blocks.
    let _ = crate::store::extraction::mark_outcome(
        store,
        key,
        crate::store::extraction::ExtractionOutcome::Tombstoned,
    )
    .await;

    // 2. Remove gotcha_keys from file records — best-effort
    if let Err(e) = sync_gotcha_file_links(store, key, affected_files, &[]).await {
        tracing::warn!("gotcha_tombstone: file link cleanup failed for {key}: {e}");
        secondary_failed = true;
        crate::store::repair::mark_dirty(
            store,
            key,
            &format!("tombstone link cleanup failed: {e}"),
        )
        .await;
    }

    // 3. Remove graph edges — best-effort. Runs while the pre-armed guard
    // from 1a is still set, so the marker stays continuously armed from the
    // tombstone commit through the last derived write.
    if !sync_has_gotcha_edges(store, key, affected_files, &[]).await {
        secondary_failed = true;
    }

    // Disarm the cancellation guard if every secondary write returned
    // cleanly. See `clear_dirty_key_if_solo` for the conditions under which
    // it is safe to clear; if another key is concurrently flagged we leave
    // the marker set.
    if !secondary_failed {
        crate::store::repair::clear_dirty_key_if_solo(store, key).await;
    }

    Ok(())
}

/// Persist a confirmed gotcha record and record a `ControlChanged::Confirmed`
/// enforcement event.
///
/// Mirrors the non-collision path of [`apply_gotcha_write`] (record write,
/// file-link sync, graph edges) but emits `Confirmed` instead of `Updated`
/// so the enforcement audit distinguishes user confirmation from edits.
/// Used by the CLI `mati gotcha confirm` direct-mode path and by the legacy
/// socket `gotcha_confirm` command.
///
/// Confirming a legacy record written before path normalization existed also
/// rewrites its `affected_files` into normalized form. The link sync below is
/// additive (`old` is empty), so a link left behind at the old spelling stays
/// until `mati repair` — which now reports it as a stale file link and clears
/// it, per the derived-index model in [`super::repair`].
///
/// Confirming also stamps each affected file's on-disk content digest onto the
/// record (see [`confirm_content_stamp`]), which is what makes re-confirming a
/// drifted gotcha clear its drift. `repo_root` is the root the store's slug was
/// keyed on ([`crate::store::slug_root`]) — what those files resolve against.
pub async fn apply_gotcha_confirm(
    store: &Store,
    repo_root: &Path,
    record: &Record,
    affected_files: &[String],
) -> Result<()> {
    let affected_files = &normalize_affected_files(affected_files, repo_root);
    let stamp = confirm_content_stamp(repo_root, affected_files);
    let mut stamped =
        with_normalized_affected_files(record, affected_files).unwrap_or_else(|| record.clone());
    set_confirm_stamp(&mut stamped, &stamp);
    let record = &stamped;
    let key = &record.key;

    // Persist the confirmed record — fail hard.
    store.put(key, record).await?;

    // Pre-arm cancellation guard. Same pattern as `apply_gotcha_write` —
    // protects against drift if the future is dropped mid-loop with no
    // dirty marker set. Cleared on the all-success path below.
    crate::store::repair::mark_dirty(store, key, "gotcha_confirm: pre-arm cancellation guard")
        .await;
    let mut secondary_failed = false;

    // Record Confirmed enforcement event — best-effort.
    if let Err(e) = record_event(
        store,
        EnforcementEventType::ControlChanged {
            change_kind: ControlChangeKind::Confirmed,
        },
        SubjectKind::Control,
        key.to_string(),
        "developer".to_string(),
        None,
        "control_confirmed".to_string(),
        None,
    )
    .await
    {
        tracing::warn!("gotcha_confirm: enforcement event recording failed for {key}: {e}");
    }

    // Mark the matching ExtractionRecord (if any) as Confirmed. No-op when
    // this gotcha wasn't from `/mati-enrich`. Best-effort — never blocks.
    let _ = crate::store::extraction::mark_outcome(
        store,
        key,
        crate::store::extraction::ExtractionOutcome::Confirmed,
    )
    .await;

    // Sync file-record gotcha_keys — best-effort. Confirm is purely additive:
    // all affected_files should have the link; none are removed.
    if let Err(e) = sync_gotcha_file_links(store, key, &[], affected_files).await {
        tracing::warn!("gotcha_confirm: file link sync failed for {key}: {e}");
        secondary_failed = true;
        crate::store::repair::mark_dirty(store, key, &format!("link sync failed: {e}")).await;
    }

    // Graph edges — best-effort. Runs while the pre-armed guard above is
    // still set, so the marker stays continuously armed from the record
    // commit through the last derived write.
    if !sync_has_gotcha_edges(store, key, &[], affected_files).await {
        secondary_failed = true;
    }

    if !secondary_failed {
        crate::store::repair::clear_dirty_key_if_solo(store, key).await;
    }

    // Drop stale consultation receipts so the next hook re-checks this rule
    // instead of trusting a receipt minted before it was confirmed. Mirrors
    // `mcp::handlers::handle_gotcha_confirm` — without this, the direct-store
    // confirm path is silently non-enforcing for any file already consulted
    // this session.
    invalidate_consultation_receipts(store, affected_files).await;

    Ok(())
}
