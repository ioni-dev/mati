//! Centralized gotcha mutation operations.
//!
//! Every path that creates, edits, or tombstones a gotcha record — CLI direct,
//! daemon socket, MCP server — must go through these functions. They enforce
//! the full invariant: key collision check, record write, file-record link sync,
//! and graph edge management.
//!
//! Keeping this in the library crate (`mati_core::store`) ensures the binary
//! crate (`cli/`) and the MCP server (`mcp/server.rs`) share the same logic.
//!
//! ## Partial-failure behaviour
//!
//! SurrealKV supports multi-key atomic transactions within a single tree.
//! However, gotcha mutations span both the knowledge tree (gotcha records,
//! file-record links) and the sessions tree (graph edges). No single
//! transaction can span both trees — this is mati's two-tree architecture
//! constraint, not a SurrealKV limitation.
//!
//! The v2 protocol handlers in `mcp::handlers` stage knowledge-tree writes
//! (gotcha record + file-link updates + audit) in a single atomic
//! `transact_knowledge` call. Graph edge writes remain best-effort.
//!
//! The functions below are retained for the CLI direct-store path and as
//! building blocks. Their ordering is chosen to minimize damage from a
//! mid-operation failure:
//!
//! 1. **Record write first** — the gotcha record is the source of truth. If
//!    later steps fail, the record exists and a future mutation or manual
//!    `mati review` can reconcile the stale links.
//! 2. **File-record links second** — these are the primary consumer-visible
//!    state. A missing link causes a false-negative (gotcha not shown for a
//!    file); a stale link causes a false-positive. Both are visible in `mati
//!    status` and correctable by re-running `mati gotcha edit`.
//! 3. **Graph edges last** — edges are rebuilt from KV on every `Graph::load`,
//!    so a missing edge is corrected at next graph load as long as the
//!    file-record link is correct.
//!
//! Link-sync and edge-write failures are logged and set a dirty marker via
//! [`super::repair::mark_dirty`]. This makes drift visible in `mati status`
//! and repairable via `mati repair`. The record write is never rolled back,
//! since a partially-linked gotcha is recoverable but a silently lost one
//! is not.
//!
//! ## Cancellation safety
//!
//! These functions run inside cancellable contexts (socket-handler tasks
//! aborted on shutdown drain timeout, `tokio::select!` losing branches in
//! parent code). A future dropped between the canonical record commit and
//! the end of the derived-index loop would leave the gotcha record persisted
//! but file-link / graph-edge state partially updated, with **no dirty
//! marker set** — cancellation is not an explicit failure branch, so the
//! `mark_dirty` calls inside `if let Err(...)` arms never run.
//!
//! Without protection, `repair_fast` on the next startup would skip these
//! orphaned gotchas (`is_dirty()` returns false), and silent drift would
//! persist until a manual `mati repair` ran. To close that hole, we use a
//! `DirtyOnDrop` guard installed *after* the canonical write succeeds and
//! disarmed only when the derived-index work returns normally. If the
//! containing future is dropped mid-loop, the guard's `Drop` impl marks the
//! gotcha key dirty via a synchronous SurrealKV write, ensuring
//! `repair_fast` picks it up on the next start.
//!
//! The guard uses synchronous KV writes (`Tree::insert`/equivalent) rather
//! than async ones because `Drop` can't `.await`. This is safe because
//! SurrealKV transactions are single-writer in their commit path, and the
//! drop-time write is best-effort — drift remains repairable even if the
//! marker write fails.
//!
//! See [`super::repair`] for the full consistency model.

use std::collections::{BTreeMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::graph::edges::{Edge, EdgeKind};
use crate::store::db::Store;
use crate::store::enforcement::{
    record_event, ControlChangeKind, EnforcementEventType, SubjectKind,
};
use crate::store::record::{FileRecord, Record, RecordLifecycle, TombstoneReason};

/// Wall-clock seconds since the UNIX epoch, used to stamp graph edges
/// written by the gotcha mutation pipeline.
///
/// **Storage-class:** the returned value is persisted into SurrealKV (see
/// `apply_gotcha_write` line ~181, where it becomes the edge value). A
/// silent zero would mint an edge timestamped 1970-01-01 that survives
/// forever in the versioned store and breaks any "edges newer than X"
/// query downstream.
///
/// We refuse to fabricate a value when the system clock is before the
/// UNIX epoch (clock-backward / unset RTC / VM resume to 1969). Panicking
/// is preferable to silently corrupting the store: the daemon panic hook
/// installed in `mcp::metadata` cleans up the socket + pid file and writes
/// a "panic" entry to the lifecycle log, so the operator sees the failure
/// and can fix the clock before retrying.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before UNIX epoch — refusing to write a corrupt timestamp into the gotcha store")
        .as_secs()
}

// ── affected_files normalization ─────────────────────────────────────────────

/// Normalize one `affected_files` entry to the repo-relative form the read
/// gate keys on.
///
/// `GotchaRecord.affected_files` is joined to `file:<rel_path>` records by
/// exact string equality. The read gate normalizes its side
/// ([`crate::hooks::decide::normalize_path`], called from `cli::hook_decide`);
/// the write paths used to store whatever the user or agent typed. A gotcha
/// added as `./src/foo.rs` or as an absolute path therefore never matched
/// `file:src/foo.rs` and was silently inert — no denial, no warning.
///
/// This is deliberately the *same* function the gate calls, with the repo root
/// resolved the *same* way (see `discover_repo_root`). Agreeing with the read
/// side is the whole point; a second, "smarter" normalizer here would
/// reintroduce the mismatch from the other direction.
///
/// Globs survive unchanged (`src/payments/**`, minted by the CODEOWNERS
/// candidates in `analysis::onboarding`): `normalize_path` only ever drops
/// empty, `.` and `..` components, and `*` is an ordinary component.
pub fn normalize_affected_file(path: &str, repo_root: Option<&str>) -> String {
    // Match the producers of `file:*` keys — `analysis::walker::make_rel_path`
    // and `analysis::git::normalize_git_path` both rewrite `\` to `/`
    // unconditionally, so a backslash can never appear in a `file:*` key and an
    // entry carrying one could not match regardless of platform.
    crate::hooks::decide::normalize_path(&path.replace('\\', "/"), repo_root)
}

/// Normalize a whole `affected_files` list against an explicit repo root.
///
/// Purely lexical — no filesystem access. Empty entries are dropped and
/// duplicates collapsed (two spellings of one path, `./src/a.rs` and
/// `src/a.rs`, normalize to the same string). First-seen order is preserved.
pub fn normalize_affected_files_with_root(
    files: &[String],
    repo_root: Option<&str>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(files.len());
    for raw in files {
        if raw.is_empty() {
            continue;
        }
        let normalized = normalize_affected_file(raw, repo_root);
        if normalized.is_empty() || out.contains(&normalized) {
            continue;
        }
        out.push(normalized);
    }
    out
}

/// [`normalize_affected_files_with_root`] with the repo root discovered from
/// the process cwd, and absolute entries resolved through symlinks first.
///
/// Both only happen when at least one entry is absolute, so the common
/// all-relative case does no filesystem work at all.
///
/// Symlink resolution is what makes the prefix strip inside `normalize_path`
/// actually match. The gate never needs it — the agent hands it a path already
/// resolved against its own cwd — but a human running
/// `mati gotcha add /tmp/repo/src/a.rs` on macOS supplies `/tmp/...` while the
/// git workdir is `/private/tmp/...`, and the entry would otherwise become the
/// nonsense relative key `tmp/repo/src/a.rs`. Resolving an already-canonical
/// path is a no-op, so this only ever removes a mismatch.
pub fn normalize_affected_files(files: &[String]) -> Vec<String> {
    if !files.iter().any(|f| looks_absolute(f)) {
        return normalize_affected_files_with_root(files, None);
    }

    let repo_root = discover_repo_root();
    let resolved: Vec<String> = files
        .iter()
        .map(|f| match looks_absolute(f) {
            true => resolve_lenient(f).unwrap_or_else(|| f.clone()),
            false => f.clone(),
        })
        .collect();
    normalize_affected_files_with_root(&resolved, repo_root.as_deref())
}

/// Resolve the repo root the way the read gate does.
///
/// Mirrors `cli::hook_decide::discover_repo_root`: `git2::Repository::discover`
/// on the process cwd, with git2's occasional trailing separator stripped so
/// the prefix match inside `normalize_path` lines up. Every process that writes
/// gotchas (CLI, `mati daemon`, `mati serve`) runs with its cwd inside the
/// repo, so cwd discovery gets the same answer the gate gets.
///
/// The result is then resolved through symlinks to match the entries, which
/// [`normalize_affected_files`] resolves for the same reason. On Unix this is
/// already a no-op — `current_dir()` returns a resolved path, so git2's workdir
/// is resolved too — but relying on that is not worth the silent failure mode.
///
/// `None` (bare repo, not a repo, non-UTF-8 root) leaves absolute entries to
/// `normalize_path`'s repo-root-less branch, which is exactly what the gate
/// falls back to as well.
fn discover_repo_root() -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    let repo = git2::Repository::discover(&cwd).ok()?;
    let root = repo.workdir()?.to_str()?.trim_end_matches('/');
    Some(resolve_lenient(root).unwrap_or_else(|| root.to_string()))
}

/// Whether an entry needs a repo root to normalize. Checked before paying for
/// git discovery or symlink resolution.
fn looks_absolute(path: &str) -> bool {
    path.starts_with('/') || std::path::Path::new(path).is_absolute()
}

/// Resolve `path` through symlinks, tolerating a leaf that does not exist yet.
///
/// Mirrors `cli::sandbox::canonicalize_lenient` (which the read gate's
/// symlink-bypass fallback uses): canonicalize; on failure, canonicalize the
/// nearest existing ancestor and re-append the tail. `None` when nothing on the
/// path resolves or the result is not UTF-8, in which case the caller falls
/// back to the entry as typed.
fn resolve_lenient(path: &str) -> Option<String> {
    let path = std::path::Path::new(path);
    if let Ok(c) = std::fs::canonicalize(path) {
        return c.to_str().map(str::to_string);
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = path;
    loop {
        let parent = cur.parent()?;
        tail.push(cur.file_name()?.to_os_string());
        if let Ok(cp) = std::fs::canonicalize(parent) {
            let mut out = cp;
            for comp in tail.iter().rev() {
                out.push(comp);
            }
            return out.to_str().map(str::to_string);
        }
        cur = parent;
    }
}

/// Return a copy of `record` with the `affected_files` field of its gotcha
/// payload replaced by `files`, or `None` when the payload already carries
/// exactly those paths.
///
/// Patches the JSON object in place rather than re-serializing a
/// [`crate::store::GotchaRecord`]: the MCP `mem_set` path merges caller-supplied
/// payloads, so a gotcha payload may legitimately carry fields beyond the
/// struct and re-serializing would drop them. Returning `None` keeps the
/// already-normalized path clone-free.
///
/// Crate-visible because the daemon's `confirm_commit_once` re-keys a legacy
/// record the same way and cannot reach this module's private items.
pub(crate) fn with_normalized_affected_files(record: &Record, files: &[String]) -> Option<Record> {
    let current = record.payload.as_ref()?.get("affected_files")?.as_array()?;
    let unchanged = current.len() == files.len()
        && current
            .iter()
            .zip(files)
            .all(|(v, f)| v.as_str() == Some(f.as_str()));
    if unchanged {
        return None;
    }

    let mut out = record.clone();
    let obj = out.payload.as_mut()?.as_object_mut()?;
    obj.insert(
        "affected_files".into(),
        serde_json::Value::Array(
            files
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    Some(out)
}

// ── Confirm-time content stamp ───────────────────────────────────────────────

/// Read the SHA-256 content digest a `file:*` record already carries.
///
/// Returns `None` for a record with no payload, no `content_hash` (a file
/// indexed before content hashing existed, or a language Layer 0 does not
/// parse), or a hash stored as something other than a string. Reads the JSON
/// key directly rather than deserializing a whole
/// [`crate::store::FileRecord`] — one field is wanted and the rest of that
/// struct is comparatively expensive to build.
pub fn content_hash_of(file_record: &Record) -> Option<String> {
    file_record
        .payload
        .as_ref()?
        .get("content_hash")?
        .as_str()
        .map(str::to_string)
}

/// Collect the confirm-time content stamp for `affected_files`.
///
/// Confirmation is the moment a human vouched for a rule against *specific*
/// code, so that is the moment worth stamping: a later mismatch means the
/// code moved out from under a rule someone signed off on, which is a
/// stronger claim than "this record is old". See
/// [`crate::store::GotchaRecord::confirmed_content`].
///
/// Reuses the digest `mati init` already computed and stored on the file
/// record — no file is opened and nothing is hashed a second time. Paths with
/// no file record or no stored digest (globs, unparsed files, a path added
/// before the next init) are simply omitted; the reader treats a missing
/// entry as "unknown", never as drift.
///
/// Store-read failures are swallowed for the same reason: an unstamped entry
/// under-reports drift, which is the safe direction. Confirmation must not
/// fail because a file record could not be read.
pub async fn confirm_content_stamp(
    store: &Store,
    affected_files: &[String],
) -> BTreeMap<String, String> {
    let mut stamp = BTreeMap::new();
    for path in affected_files {
        let file_key = format!("file:{path}");
        if let Ok(Some(file_record)) = store.get(&file_key).await {
            if let Some(hash) = content_hash_of(&file_record) {
                stamp.insert(path.clone(), hash);
            }
        }
    }
    stamp
}

/// Whether a gotcha record's payload says the rule is developer-confirmed.
///
/// Reads the raw JSON rather than deserializing a
/// [`crate::store::GotchaRecord`]: the caller may hold a payload merged by
/// `mem_set` that does not round-trip through the struct.
fn payload_is_confirmed(record: &Record) -> bool {
    record
        .payload
        .as_ref()
        .and_then(|p| p.get("confirmed"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// Replace the `confirmed_content` field of a gotcha payload with `stamp`.
///
/// Patches the JSON object in place for the same reason
/// `with_normalized_affected_files` does: `mem_set` merges caller-supplied
/// payloads, so re-serializing a [`crate::store::GotchaRecord`] would drop any
/// field the struct does not know about.
///
/// Replaces rather than merges. A confirmation asserts the rule is right
/// against the files it names *now*, so any earlier baseline — including one
/// for a path the gotcha no longer covers — is spent. Merging would let a
/// stale entry keep reporting drift after a human explicitly re-confirmed,
/// which would break the curation loop; dropping an entry we could not read
/// only under-reports, which is the safe direction.
pub fn set_confirm_stamp(record: &mut Record, stamp: &BTreeMap<String, String>) {
    let Some(obj) = record.payload.as_mut().and_then(|p| p.as_object_mut()) else {
        return;
    };
    let stamped: serde_json::Map<String, serde_json::Value> = stamp
        .iter()
        .map(|(path, hash)| (path.clone(), serde_json::Value::String(hash.clone())))
        .collect();
    obj.insert(
        "confirmed_content".into(),
        serde_json::Value::Object(stamped),
    );
}

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
pub async fn apply_gotcha_write(
    store: &Store,
    record: &Record,
    old_files: &[String],
    new_files: &[String],
    is_new: bool,
) -> Result<()> {
    let new_files = &normalize_affected_files(new_files);
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
        let stamp = confirm_content_stamp(store, new_files).await;
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

    // 4 + 5. Graph edges — best-effort
    let old_set: HashSet<&str> = sync_old_files.iter().map(String::as_str).collect();
    let new_set: HashSet<&str> = new_files.iter().map(String::as_str).collect();

    let ts = now_secs().to_le_bytes();
    for file_path in &new_set {
        if !old_set.contains(*file_path) {
            let file_key = format!("file:{file_path}");
            let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, key.as_str()).to_key();
            if let Err(e) = store.put_raw(&edge_key, &ts).await {
                tracing::warn!("gotcha_write: edge add failed for {file_key} → {key}: {e}");
                secondary_failed = true;
                crate::store::repair::mark_dirty(store, key, &format!("edge add failed: {e}"))
                    .await;
            }
        }
    }
    for file_path in &old_set {
        if !new_set.contains(*file_path) {
            let file_key = format!("file:{file_path}");
            let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, key.as_str()).to_key();
            if let Err(e) = store.delete(&edge_key).await {
                tracing::warn!("gotcha_write: edge remove failed for {file_key} → {key}: {e}");
                secondary_failed = true;
                crate::store::repair::mark_dirty(store, key, &format!("edge remove failed: {e}"))
                    .await;
            }
        }
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
        Some(mut record) => {
            if let Some(ref payload) = record.payload {
                if let Ok(gr) =
                    serde_json::from_value::<crate::store::GotchaRecord>(payload.clone())
                {
                    exemplar_snapshot = Some((gr.rule, gr.reason, gr.severity));
                }
            }
            let now = now_secs();
            record.lifecycle = RecordLifecycle::Tombstoned {
                reason: TombstoneReason::ManualDeletion,
                at: now,
            };
            record.updated_at = now;
            record.version.logical_clock += 1;
            record.version.wall_clock = now;
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

    // 3. Remove graph edges — best-effort
    for file_path in affected_files {
        let file_key = format!("file:{file_path}");
        let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, key).to_key();
        if let Err(e) = store.delete(&edge_key).await {
            tracing::warn!("gotcha_tombstone: edge remove failed for {file_key} → {key}: {e}");
            secondary_failed = true;
            crate::store::repair::mark_dirty(
                store,
                key,
                &format!("tombstone edge remove failed: {e}"),
            )
            .await;
        }
    }

    // Disarm the cancellation guard if every secondary write returned cleanly.
    // See `clear_dirty_key_if_solo` for the conditions under which it is safe
    // to clear; if another key is concurrently flagged we leave the marker set.
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
/// Confirming also stamps each affected file's current content digest onto the
/// record (see [`confirm_content_stamp`]), which is what makes re-confirming a
/// drifted gotcha clear its drift.
pub async fn apply_gotcha_confirm(
    store: &Store,
    record: &Record,
    affected_files: &[String],
) -> Result<()> {
    let affected_files = &normalize_affected_files(affected_files);
    let stamp = confirm_content_stamp(store, affected_files).await;
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

    // Graph edges — best-effort.
    let ts = now_secs().to_le_bytes();
    for file_path in affected_files {
        let file_key = format!("file:{file_path}");
        let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, key.as_str()).to_key();
        if let Err(e) = store.put_raw(&edge_key, &ts).await {
            tracing::warn!("gotcha_confirm: edge add failed for {file_key} → {key}: {e}");
            secondary_failed = true;
            crate::store::repair::mark_dirty(store, key, &format!("edge add failed: {e}")).await;
        }
    }

    if !secondary_failed {
        crate::store::repair::clear_dirty_key_if_solo(store, key).await;
    }

    Ok(())
}

// ── File-record link sync ────────────────────────────────────────────────────

/// Synchronize `gotcha_keys` in file records with the current affected-file set.
///
/// Adds the gotcha key to files in `new_files` that are not in `old_files`,
/// and removes it from files in `old_files` that are not in `new_files`.
pub async fn sync_gotcha_file_links(
    store: &Store,
    gotcha_key: &str,
    old_files: &[String],
    new_files: &[String],
) -> Result<()> {
    let old_set: HashSet<&str> = old_files.iter().map(String::as_str).collect();
    let new_set: HashSet<&str> = new_files.iter().map(String::as_str).collect();

    for file_path in new_set.difference(&old_set) {
        update_file_gotcha_key(store, file_path, gotcha_key, true).await?;
    }

    for file_path in old_set.difference(&new_set) {
        update_file_gotcha_key(store, file_path, gotcha_key, false).await?;
    }

    Ok(())
}

async fn update_file_gotcha_key(
    store: &Store,
    file_path: &str,
    gotcha_key: &str,
    add: bool,
) -> Result<()> {
    let file_key = format!("file:{file_path}");

    // Bounded retry on optimistic-concurrency write conflicts. Concurrent
    // gotcha writes touching the same file:<path> record (e.g. parallel
    // `mati gotcha add` to one file in direct mode) race on this
    // read-modify-write under SurrealKV MVCC. Re-read on each attempt so we
    // re-apply against the latest gotcha_keys rather than clobbering a
    // sibling's concurrent add. Without this, the conflict falls through to
    // the caller's best-effort dirty-marker path and needs `mati repair`.
    const MAX_RETRIES: usize = 4;
    for attempt in 0..MAX_RETRIES {
        let Some(mut record) = store.get(&file_key).await? else {
            // File record doesn't exist yet — a file `init` never indexed
            // (e.g. `mati gotcha add newfile.rs` / `mem_set` before re-init).
            // Create-on-write: persist a minimal layer-0 file stub carrying this
            // gotcha key so the read gate — which keys on
            // `file_record.payload.gotcha_keys` (hooks/decide.rs) — enforces
            // IMMEDIATELY. Without this the gotcha is silently inert until the
            // next `mati init` section 8c back-fill. init/reparse later merge
            // real analysis and preserve gotcha_keys (reparse.rs).
            if add {
                let now = now_secs();
                let mut stub = Record::layer0_file_stub(
                    file_key.clone(),
                    crate::store::stable_device_id(),
                    1,
                    now,
                );
                let mut fr = FileRecord::layer0_stub(
                    file_path,
                    vec![],
                    vec![],
                    vec![],
                    0,
                    0,
                    0,
                    None,
                    false,
                    0,
                    now,
                );
                fr.gotcha_keys = vec![gotcha_key.to_string()];
                stub.payload = serde_json::to_value(&fr).ok();
                store.put(&file_key, &stub).await?;
            }
            return Ok(());
        };

        let changed = if add {
            add_gotcha_key(&mut record, gotcha_key)
        } else {
            remove_gotcha_key(&mut record, gotcha_key)
        };

        if !changed {
            return Ok(());
        }

        let now = now_secs();
        record.updated_at = now;
        record.version.logical_clock += 1;
        record.version.wall_clock = now;

        match store.put(&file_key, &record).await {
            Ok(()) => return Ok(()),
            Err(e)
                if attempt + 1 < MAX_RETRIES
                    && e.to_string().to_lowercase().contains("write conflict") =>
            {
                // Another writer committed file:<path> between our get and put.
                // Back off briefly (5/10/20ms) and retry against a fresh read.
                tokio::time::sleep(std::time::Duration::from_millis(5u64 << attempt)).await;
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

fn add_gotcha_key(record: &mut Record, gotcha_key: &str) -> bool {
    let Some(payload) = record.payload.as_mut() else {
        record.payload = Some(serde_json::json!({ "gotcha_keys": [gotcha_key] }));
        return true;
    };

    if let Some(obj) = payload.as_object_mut() {
        match obj.get_mut("gotcha_keys") {
            Some(existing) => {
                if let Some(arr) = existing.as_array_mut() {
                    if arr.iter().any(|v| v.as_str() == Some(gotcha_key)) {
                        false
                    } else {
                        arr.push(serde_json::Value::String(gotcha_key.to_string()));
                        true
                    }
                } else {
                    *existing = serde_json::json!([gotcha_key]);
                    true
                }
            }
            None => {
                obj.insert("gotcha_keys".into(), serde_json::json!([gotcha_key]));
                true
            }
        }
    } else {
        record.payload = Some(serde_json::json!({ "gotcha_keys": [gotcha_key] }));
        true
    }
}

fn remove_gotcha_key(record: &mut Record, gotcha_key: &str) -> bool {
    let Some(payload) = record.payload.as_mut() else {
        return false;
    };
    let Some(obj) = payload.as_object_mut() else {
        return false;
    };
    let Some(existing) = obj.get_mut("gotcha_keys") else {
        return false;
    };
    let Some(arr) = existing.as_array_mut() else {
        return false;
    };

    let before = arr.len();
    arr.retain(|v| v.as_str() != Some(gotcha_key));
    arr.len() != before
}

// ── Confirmation propagation ─────────────────────────────────────────────────

/// Increment `confirmation_count` on all file records linked to a confirmed gotcha.
///
/// Best-effort: failures are logged but do not fail the confirmation.
/// This propagates the signal that a human verified knowledge about this file,
/// which feeds into the confidence formula via `log2(confirmation_count + 2)`.
pub async fn propagate_confirmation_to_files(store: &Store, affected_files: &[String]) {
    for file_path in affected_files {
        let file_key = format!("file:{file_path}");
        if let Ok(Some(mut file_record)) = store.get(&file_key).await {
            file_record.confidence.confirmation_count += 1;
            let now = now_secs();
            file_record.updated_at = now;
            file_record.version.logical_clock += 1;
            file_record.version.wall_clock = now;
            if let Err(e) = store.put(&file_key, &file_record).await {
                tracing::warn!("propagate_confirmation: failed to update {file_key}: {e}");
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::record::{
        Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, RecordSource,
        RecordVersion, StalenessScore,
    };

    fn make_gotcha_record(key: &str, files: &[&str]) -> Record {
        let gotcha = GotchaRecord {
            rule: "test rule".into(),
            reason: "test reason".into(),
            severity: Priority::High,
            affected_files: files.iter().map(|s| s.to_string()).collect(),
            ref_url: None,
            discovered_session: 1_000_000,
            confirmed: true,
            confirmed_content: Default::default(),
        };
        Record {
            key: key.to_string(),
            value: "test rule because test reason".into(),
            payload: serde_json::to_value(&gotcha).ok(),
            category: Category::Gotcha,
            priority: Priority::High,
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
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
            gap_analysis_score: 0.0,
        }
    }

    /// `make_file_record` with a content digest, as `mati init` writes it.
    fn make_file_record_hashed(path: &str, content_hash: &str) -> Record {
        let mut rec = make_file_record(path);
        if let Some(obj) = rec.payload.as_mut().and_then(|p| p.as_object_mut()) {
            obj.insert(
                "content_hash".into(),
                serde_json::Value::String(content_hash.to_string()),
            );
        }
        rec
    }

    fn stored_stamp(record: &Record) -> BTreeMap<String, String> {
        record
            .payload_as::<GotchaRecord>()
            .map(|g| g.confirmed_content)
            .unwrap_or_default()
    }

    fn make_file_record(path: &str) -> Record {
        Record {
            key: format!("file:{path}"),
            value: String::new(),
            payload: Some(serde_json::json!({
                "path": path,
                "purpose": "",
                "entry_points": [],
                "imports": [],
                "gotcha_keys": [],
                "decision_keys": [],
                "todos": [],
                "unsafe_count": 0,
                "unwrap_count": 0,
                "change_frequency": 0,
                "is_hotspot": false,
                "token_cost_estimate": 0,
                "last_modified_session": 0,
                "line_count": 0
            })),
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

    fn file_gotcha_keys(record: &Record) -> Vec<String> {
        record
            .payload
            .as_ref()
            .and_then(|p| p.get("gotcha_keys"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn ensure_key_available_rejects_existing() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let record = make_gotcha_record("gotcha:exists", &["src/a.rs"]);
        store.put("gotcha:exists", &record).await.unwrap();

        let err = ensure_gotcha_key_available(&store, "gotcha:exists")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));
        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn ensure_key_available_passes_for_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        ensure_gotcha_key_available(&store, "gotcha:new")
            .await
            .unwrap();
        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn apply_write_adds_file_links_and_edges() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Seed file records
        store
            .put("file:src/a.rs", &make_file_record("src/a.rs"))
            .await
            .unwrap();
        store
            .put("file:src/b.rs", &make_file_record("src/b.rs"))
            .await
            .unwrap();

        let record = make_gotcha_record("gotcha:test", &["src/a.rs", "src/b.rs"]);
        let files = vec!["src/a.rs".into(), "src/b.rs".into()];

        apply_gotcha_write(&store, &record, &[], &files, true)
            .await
            .unwrap();

        // Both files should have the gotcha key
        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        let b = store.get("file:src/b.rs").await.unwrap().unwrap();
        assert!(file_gotcha_keys(&a).contains(&"gotcha:test".to_string()));
        assert!(file_gotcha_keys(&b).contains(&"gotcha:test".to_string()));

        // Graph edges should exist
        let edge_keys = store.scan_keys("graph:edge:").await.unwrap();
        let edge_a = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:test").to_key();
        let edge_b = Edge::new("file:src/b.rs", EdgeKind::HasGotcha, "gotcha:test").to_key();
        assert!(edge_keys.contains(&edge_a));
        assert!(edge_keys.contains(&edge_b));

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn apply_write_rejects_collision_when_is_new() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let record = make_gotcha_record("gotcha:dup", &["src/a.rs"]);
        store.put("gotcha:dup", &record).await.unwrap();

        let record2 = make_gotcha_record("gotcha:dup", &["src/b.rs"]);
        let err = apply_gotcha_write(&store, &record2, &[], &["src/b.rs".into()], true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn apply_write_edit_moves_links_between_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put("file:src/a.rs", &make_file_record("src/a.rs"))
            .await
            .unwrap();
        store
            .put("file:src/b.rs", &make_file_record("src/b.rs"))
            .await
            .unwrap();

        // Initial write targeting src/a.rs
        let record = make_gotcha_record("gotcha:move", &["src/a.rs"]);
        apply_gotcha_write(&store, &record, &[], &["src/a.rs".into()], true)
            .await
            .unwrap();

        // Edit: move from src/a.rs to src/b.rs
        let record2 = make_gotcha_record("gotcha:move", &["src/b.rs"]);
        apply_gotcha_write(
            &store,
            &record2,
            &["src/a.rs".into()],
            &["src/b.rs".into()],
            false,
        )
        .await
        .unwrap();

        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        let b = store.get("file:src/b.rs").await.unwrap().unwrap();
        assert!(!file_gotcha_keys(&a).contains(&"gotcha:move".to_string()));
        assert!(file_gotcha_keys(&b).contains(&"gotcha:move".to_string()));

        // Edge should move too
        let edge_keys = store.scan_keys("graph:edge:").await.unwrap();
        let edge_a = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:move").to_key();
        let edge_b = Edge::new("file:src/b.rs", EdgeKind::HasGotcha, "gotcha:move").to_key();
        assert!(!edge_keys.contains(&edge_a));
        assert!(edge_keys.contains(&edge_b));

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn apply_tombstone_cleans_links_and_edges() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put("file:src/a.rs", &make_file_record("src/a.rs"))
            .await
            .unwrap();
        store
            .put("file:src/b.rs", &make_file_record("src/b.rs"))
            .await
            .unwrap();

        // Write gotcha first
        let record = make_gotcha_record("gotcha:del", &["src/a.rs", "src/b.rs"]);
        let files = vec!["src/a.rs".into(), "src/b.rs".into()];
        apply_gotcha_write(&store, &record, &[], &files, true)
            .await
            .unwrap();

        // Tombstone it
        apply_gotcha_tombstone(&store, "gotcha:del", &files)
            .await
            .unwrap();

        // Record should be tombstoned
        let rec = store.get("gotcha:del").await.unwrap().unwrap();
        assert!(matches!(rec.lifecycle, RecordLifecycle::Tombstoned { .. }));

        // File records should have empty gotcha_keys
        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        let b = store.get("file:src/b.rs").await.unwrap().unwrap();
        assert!(file_gotcha_keys(&a).is_empty());
        assert!(file_gotcha_keys(&b).is_empty());

        // Graph edges should be gone
        let edge_keys = store.scan_keys("graph:edge:").await.unwrap();
        let edge_a = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:del").to_key();
        let edge_b = Edge::new("file:src/b.rs", EdgeKind::HasGotcha, "gotcha:del").to_key();
        assert!(!edge_keys.contains(&edge_a));
        assert!(!edge_keys.contains(&edge_b));

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn apply_tombstone_errors_on_missing_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let err = apply_gotcha_tombstone(&store, "gotcha:ghost", &[])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"));

        store.close().await.unwrap();
    }

    /// Simulates the mem_set → sync_gotcha_file_links path: a gotcha is
    /// written directly (as mem_set does), then file links are synced
    /// separately. Verifies that the file record's gotcha_keys are updated.
    #[tokio::test]
    async fn sync_file_links_backfills_after_direct_write() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Seed file record with no gotcha_keys
        store
            .put("file:src/a.rs", &make_file_record("src/a.rs"))
            .await
            .unwrap();

        // Simulate mem_set: write gotcha record directly (no apply_gotcha_write)
        let record = make_gotcha_record("gotcha:mcp-created", &["src/a.rs"]);
        store.put("gotcha:mcp-created", &record).await.unwrap();

        // File should NOT have the link yet (this is the pre-fix state)
        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        assert!(!file_gotcha_keys(&a).contains(&"gotcha:mcp-created".to_string()));

        // Now call sync_gotcha_file_links (what mem_set now does after the fix)
        sync_gotcha_file_links(&store, "gotcha:mcp-created", &[], &["src/a.rs".into()])
            .await
            .unwrap();

        // File should now have the link
        let a2 = store.get("file:src/a.rs").await.unwrap().unwrap();
        assert!(file_gotcha_keys(&a2).contains(&"gotcha:mcp-created".to_string()));

        store.close().await.unwrap();
    }

    /// Regression: `now_secs()` is storage-class — its return value is
    /// persisted as a graph edge timestamp. A clock that has slipped before
    /// the UNIX epoch (e.g. unset RTC on first boot, VM resumed against a
    /// 1969-stamped image) must abort the write rather than silently
    /// fabricating a 0-second timestamp that lives forever in the
    /// versioned store. This test reproduces the same `duration_since(...).expect(...)`
    /// pattern against a known-pre-epoch `SystemTime` and asserts the panic
    /// message identifies UNIX epoch as the cause so operators can diagnose
    /// it from the lifecycle.log "panic" entry.
    #[test]
    fn now_secs_panics_on_pre_epoch_clock_with_unix_epoch_in_message() {
        use std::panic;
        use std::time::{Duration, UNIX_EPOCH};

        // SystemTime one second before the epoch — `duration_since(UNIX_EPOCH)`
        // returns Err for any t < UNIX_EPOCH, mirroring what `SystemTime::now()`
        // would return on a backwards-walked system clock.
        let pre_epoch = UNIX_EPOCH - Duration::from_secs(1);

        // The next four lines must mirror the production `now_secs()` body
        // verbatim (modulo the `SystemTime::now()` substitution); the whole
        // point is to exercise the same `expect` literal that ships in the
        // hot path.
        let result = panic::catch_unwind(|| {
            let _ = pre_epoch
                .duration_since(UNIX_EPOCH)
                .expect("system clock is before UNIX epoch — refusing to write a corrupt timestamp into the gotcha store")
                .as_secs();
        });

        let payload = result.expect_err("pre-epoch SystemTime must panic, not silently return 0");
        let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
            (*s).to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            panic!("panic payload was neither &str nor String");
        };

        assert!(
            msg.contains("UNIX epoch"),
            "panic message should mention 'UNIX epoch' so operators can diagnose clock-backward; got: {msg}"
        );
        assert!(
            msg.contains("refusing to write"),
            "panic message should indicate the write was refused (not silently zeroed); got: {msg}"
        );
    }

    /// Sanity check that `now_secs()` returns a sensible value under normal
    /// conditions (post-epoch wall clock). Guards against a future refactor
    /// accidentally turning the `expect` into something that returns 0.
    #[test]
    fn now_secs_returns_recent_post_epoch_seconds() {
        let s = now_secs();
        // 2024-01-01 UTC = 1_704_067_200; any sane CI box runs after this.
        assert!(
            s > 1_704_067_200,
            "now_secs() returned {s}; expected a post-2024 timestamp"
        );
    }

    /// D3 regression: enrichment-tagged gotchas must produce an
    /// ExtractionRecord on write (outcome=Pending). Confirming the
    /// gotcha must flip the outcome to Confirmed; tombstoning to
    /// Tombstoned. Untagged gotchas (manual `mati gotcha add`) must
    /// NOT produce an ExtractionRecord — keeps the analytics scoped
    /// to the enrichment pipeline.
    #[tokio::test]
    async fn enriched_gotcha_lifecycle_flips_extraction_outcome() {
        use crate::store::extraction::{key_for, ExtractionOutcome, ExtractionRecord};

        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Build an "enriched" gotcha record with depth:deep tag.
        let mut record = make_gotcha_record("gotcha:enriched-rule", &["src/cli/repair.rs"]);
        record.tags = vec!["enriched".into(), "depth:deep".into()];

        apply_gotcha_write(&store, &record, &[], &["src/cli/repair.rs".into()], true)
            .await
            .unwrap();

        // After write, ExtractionRecord must exist with outcome=Pending,
        // depth=Deep, file_path set.
        let rec = store
            .get(&key_for("gotcha:enriched-rule"))
            .await
            .unwrap()
            .expect("extraction record must exist for enriched gotcha");
        let extraction: ExtractionRecord =
            serde_json::from_value(rec.payload.expect("payload")).unwrap();
        assert_eq!(extraction.outcome, ExtractionOutcome::Pending);
        assert_eq!(
            extraction.depth,
            Some(crate::health::enrichment::EnrichmentDepth::Deep)
        );
        assert_eq!(extraction.file_path, "src/cli/repair.rs");
        assert!(extraction.outcome_at.is_none());

        // Confirm → outcome must flip to Confirmed.
        apply_gotcha_confirm(&store, &record, &["src/cli/repair.rs".into()])
            .await
            .unwrap();
        let rec = store
            .get(&key_for("gotcha:enriched-rule"))
            .await
            .unwrap()
            .unwrap();
        let extraction: ExtractionRecord = serde_json::from_value(rec.payload.unwrap()).unwrap();
        assert_eq!(extraction.outcome, ExtractionOutcome::Confirmed);
        assert!(extraction.outcome_at.is_some());

        // Now write + tombstone another enriched gotcha — outcome flips to Tombstoned.
        let mut t_record = make_gotcha_record("gotcha:tombstone-me", &["src/cli/init.rs"]);
        t_record.tags = vec!["enriched".into(), "depth:fast".into()];
        apply_gotcha_write(&store, &t_record, &[], &["src/cli/init.rs".into()], true)
            .await
            .unwrap();
        apply_gotcha_tombstone(&store, "gotcha:tombstone-me", &["src/cli/init.rs".into()])
            .await
            .unwrap();

        let rec = store
            .get(&key_for("gotcha:tombstone-me"))
            .await
            .unwrap()
            .unwrap();
        let extraction: ExtractionRecord = serde_json::from_value(rec.payload.unwrap()).unwrap();
        assert_eq!(extraction.outcome, ExtractionOutcome::Tombstoned);
        assert_eq!(
            extraction.depth,
            Some(crate::health::enrichment::EnrichmentDepth::Fast)
        );

        // Untagged gotcha must NOT produce an ExtractionRecord.
        let untagged = make_gotcha_record("gotcha:manual-add", &["src/foo.rs"]);
        // tags vec is empty by default in make_gotcha_record
        apply_gotcha_write(&store, &untagged, &[], &["src/foo.rs".into()], true)
            .await
            .unwrap();
        assert!(store
            .get(&key_for("gotcha:manual-add"))
            .await
            .unwrap()
            .is_none());

        store.close().await.unwrap();
    }

    // ── confirm-time content stamp ───────────────────────────────────────
    //
    // The stamp is the baseline `health::drift` compares against. It is
    // written only by the confirm paths, reuses the digest already on the
    // file record, and never touches a score.

    #[tokio::test]
    async fn confirm_stamps_the_current_file_digest() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        store
            .put(
                "file:src/a.rs",
                &make_file_record_hashed("src/a.rs", "hash-v1"),
            )
            .await
            .unwrap();

        let record = make_gotcha_record("gotcha:stamped", &["src/a.rs"]);
        apply_gotcha_confirm(&store, &record, &["src/a.rs".into()])
            .await
            .unwrap();

        let stored = store.get("gotcha:stamped").await.unwrap().unwrap();
        assert_eq!(
            stored_stamp(&stored).get("src/a.rs"),
            Some(&"hash-v1".to_string())
        );

        // Stamping must not disturb anything the read gate reads. Quality and
        // confidence are set by the callers of this function, so the check here
        // is that they came through untouched.
        let gotcha = stored.payload_as::<GotchaRecord>().unwrap();
        assert!(gotcha.confirmed);
        assert_eq!(stored.confidence.value, record.confidence.value);
        assert_eq!(stored.quality.value, record.quality.value);
        assert!(matches!(
            stored.staleness.tier,
            crate::store::record::StalenessTier::Fresh
        ));

        store.close().await.unwrap();
    }

    /// Multi-file gotchas get one entry per affected file. A file with no
    /// indexed digest (unparsed file, glob, path not yet walked) is simply
    /// absent — the reader treats that as unknown, never as drift.
    #[tokio::test]
    async fn confirm_stamps_each_affected_file_and_skips_unindexed_ones() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        store
            .put(
                "file:src/a.rs",
                &make_file_record_hashed("src/a.rs", "hash-a"),
            )
            .await
            .unwrap();
        store
            .put(
                "file:src/b.rs",
                &make_file_record_hashed("src/b.rs", "hash-b"),
            )
            .await
            .unwrap();
        // Indexed but never parsed — no content_hash on the payload.
        store
            .put("file:src/c.bin", &make_file_record("src/c.bin"))
            .await
            .unwrap();

        let files: Vec<String> = ["src/a.rs", "src/b.rs", "src/c.bin", "src/payments/**"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let record = make_gotcha_record(
            "gotcha:multi",
            &["src/a.rs", "src/b.rs", "src/c.bin", "src/payments/**"],
        );
        apply_gotcha_confirm(&store, &record, &files).await.unwrap();

        let stamp = stored_stamp(&store.get("gotcha:multi").await.unwrap().unwrap());
        assert_eq!(stamp.get("src/a.rs"), Some(&"hash-a".to_string()));
        assert_eq!(stamp.get("src/b.rs"), Some(&"hash-b".to_string()));
        assert_eq!(stamp.len(), 2, "unindexed paths must not be stamped");

        store.close().await.unwrap();
    }

    /// The curation loop: edit the file, re-confirm, drift clears. Exercised
    /// end-to-end through `health::drift` so the test fails if either side of
    /// the comparison moves.
    #[tokio::test]
    async fn reconfirm_restamps_and_clears_drift() {
        use crate::health::drift::{current_content_hashes, detect_drift};

        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        store
            .put(
                "file:src/a.rs",
                &make_file_record_hashed("src/a.rs", "hash-v1"),
            )
            .await
            .unwrap();

        let record = make_gotcha_record("gotcha:curated", &["src/a.rs"]);
        apply_gotcha_confirm(&store, &record, &["src/a.rs".into()])
            .await
            .unwrap();

        // `mati init` re-hashes the edited file.
        store
            .put(
                "file:src/a.rs",
                &make_file_record_hashed("src/a.rs", "hash-v2"),
            )
            .await
            .unwrap();

        let gotchas = store.scan_prefix("gotcha:").await.unwrap();
        let files = store.scan_prefix("file:").await.unwrap();
        let drifted = detect_drift(&gotchas, &current_content_hashes(&files));
        assert_eq!(drifted.len(), 1, "edited file must report drift");
        assert_eq!(drifted[0].drifted_files, vec!["src/a.rs".to_string()]);

        // Developer re-reads and re-confirms.
        let current = store.get("gotcha:curated").await.unwrap().unwrap();
        apply_gotcha_confirm(&store, &current, &["src/a.rs".into()])
            .await
            .unwrap();

        let gotchas = store.scan_prefix("gotcha:").await.unwrap();
        let files = store.scan_prefix("file:").await.unwrap();
        assert!(
            detect_drift(&gotchas, &current_content_hashes(&files)).is_empty(),
            "re-confirming must re-stamp the current digest and clear the drift"
        );

        store.close().await.unwrap();
    }

    /// `mati gotcha add` writes an already-confirmed record straight through
    /// `apply_gotcha_write`, so that path stamps too — otherwise the most
    /// common way to create an enforcing gotcha could never report drift.
    /// Unconfirmed writes (Layer 0 stubs, `mem_set`) must stay unstamped.
    #[tokio::test]
    async fn new_confirmed_write_stamps_and_unconfirmed_does_not() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        store
            .put(
                "file:src/a.rs",
                &make_file_record_hashed("src/a.rs", "hash-v1"),
            )
            .await
            .unwrap();

        let confirmed = make_gotcha_record("gotcha:added", &["src/a.rs"]);
        apply_gotcha_write(&store, &confirmed, &[], &["src/a.rs".into()], true)
            .await
            .unwrap();
        assert_eq!(
            stored_stamp(&store.get("gotcha:added").await.unwrap().unwrap()).get("src/a.rs"),
            Some(&"hash-v1".to_string())
        );

        let mut candidate = make_gotcha_record("gotcha:candidate", &["src/a.rs"]);
        if let Some(obj) = candidate.payload.as_mut().and_then(|p| p.as_object_mut()) {
            obj.insert("confirmed".into(), serde_json::Value::Bool(false));
        }
        apply_gotcha_write(&store, &candidate, &[], &["src/a.rs".into()], true)
            .await
            .unwrap();
        assert!(
            stored_stamp(&store.get("gotcha:candidate").await.unwrap().unwrap()).is_empty(),
            "an unconfirmed candidate has no human sign-off to stamp"
        );

        store.close().await.unwrap();
    }

    /// An edit is not a re-confirmation: `apply_gotcha_write` with
    /// `is_new = false` must leave the baseline alone, so a rule whose text
    /// was tweaked (or whose path the rename migration moved) stays drifted.
    #[tokio::test]
    async fn edit_does_not_restamp_a_confirmed_gotcha() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        store
            .put(
                "file:src/a.rs",
                &make_file_record_hashed("src/a.rs", "hash-v1"),
            )
            .await
            .unwrap();

        let record = make_gotcha_record("gotcha:edited", &["src/a.rs"]);
        apply_gotcha_confirm(&store, &record, &["src/a.rs".into()])
            .await
            .unwrap();
        store
            .put(
                "file:src/a.rs",
                &make_file_record_hashed("src/a.rs", "hash-v2"),
            )
            .await
            .unwrap();

        // Re-write the record the way `mati gotcha edit` does — payload carried
        // forward, `is_new = false`.
        let edited = store.get("gotcha:edited").await.unwrap().unwrap();
        apply_gotcha_write(
            &store,
            &edited,
            &["src/a.rs".into()],
            &["src/a.rs".into()],
            false,
        )
        .await
        .unwrap();

        assert_eq!(
            stored_stamp(&store.get("gotcha:edited").await.unwrap().unwrap()).get("src/a.rs"),
            Some(&"hash-v1".to_string()),
            "an edit must not silently re-baseline a drifted rule"
        );

        store.close().await.unwrap();
    }

    /// A record confirmed before the stamp existed deserializes with an empty
    /// map, which `detect_drift` treats as unknown. Written as raw JSON with
    /// no `confirmed_content` key so it exercises the actual serde default.
    #[tokio::test]
    async fn pre_upgrade_record_has_no_stamp_and_is_not_drifted() {
        use crate::health::drift::{current_content_hashes, detect_drift};

        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        store
            .put(
                "file:src/a.rs",
                &make_file_record_hashed("src/a.rs", "hash-v2"),
            )
            .await
            .unwrap();

        let mut legacy = make_gotcha_record("gotcha:legacy", &["src/a.rs"]);
        legacy.payload = Some(serde_json::json!({
            "rule": "test rule",
            "reason": "test reason",
            "severity": "high",
            "affected_files": ["src/a.rs"],
            "discovered_session": 1_000_000,
            "confirmed": true
        }));
        store.put("gotcha:legacy", &legacy).await.unwrap();

        let stored = store.get("gotcha:legacy").await.unwrap().unwrap();
        let gotcha = stored
            .payload_as::<GotchaRecord>()
            .expect("a payload without confirmed_content must still deserialize");
        assert!(gotcha.confirmed);
        assert!(gotcha.confirmed_content.is_empty());

        let files = store.scan_prefix("file:").await.unwrap();
        assert!(
            detect_drift(&[stored], &current_content_hashes(&files)).is_empty(),
            "no stamp must read as unknown, never as drifted"
        );

        store.close().await.unwrap();
    }

    // ── affected_files normalization ─────────────────────────────────────
    //
    // The write side has to produce exactly the string the read gate looks up
    // (`hooks::decide::normalize_path`, via `cli::hook_decide`). Anything else
    // and the `file:<rel_path>` join silently misses and the gotcha never
    // fires.

    fn norm(files: &[&str], root: Option<&str>) -> Vec<String> {
        let owned: Vec<String> = files.iter().map(|s| s.to_string()).collect();
        normalize_affected_files_with_root(&owned, root)
    }

    #[test]
    fn normalize_strips_dot_slash_prefix() {
        assert_eq!(norm(&["./src/foo.rs"], None), vec!["src/foo.rs"]);
        assert_eq!(norm(&["././src/foo.rs"], None), vec!["src/foo.rs"]);
        assert_eq!(norm(&["src/./foo.rs"], None), vec!["src/foo.rs"]);
        assert_eq!(norm(&["src/bar/../foo.rs"], None), vec!["src/foo.rs"]);
        assert_eq!(norm(&["src//foo.rs"], None), vec!["src/foo.rs"]);
    }

    #[test]
    fn normalize_strips_repo_root_from_absolute_path() {
        assert_eq!(
            norm(&["/home/dev/repo/src/foo.rs"], Some("/home/dev/repo")),
            vec!["src/foo.rs"]
        );
        // Trailing slash on the entry's root prefix, and a `.` mid-path.
        assert_eq!(
            norm(&["/home/dev/repo/./src/foo.rs"], Some("/home/dev/repo")),
            vec!["src/foo.rs"]
        );
    }

    /// `normalize_affected_files` (the filesystem-aware wrapper) has to resolve
    /// an absolute entry through symlinks before the repo-root strip, or the
    /// macOS `/tmp` → `/private/tmp` split turns a valid absolute path into the
    /// nonsense relative key `tmp/.../src/a.rs`. Exercised with a real symlink
    /// so it fails on any platform where the resolution is skipped.
    #[test]
    fn normalize_resolves_symlinked_absolute_entry() {
        let dir = tempfile::TempDir::new().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(real.join("src")).unwrap();
        std::fs::write(real.join("src/a.rs"), "fn main() {}\n").unwrap();
        let link = dir.path().join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Root canonicalizes to `.../real`; the entry comes in via `.../link`.
        let root = std::fs::canonicalize(&real).unwrap();
        let entry = link.join("src/a.rs").to_string_lossy().into_owned();
        let resolved = resolve_lenient(&entry).expect("symlink must resolve");
        assert_eq!(
            normalize_affected_files_with_root(&[resolved], Some(root.to_str().unwrap())),
            vec!["src/a.rs"]
        );
    }

    /// Resolution must not require the file to exist — `mati gotcha add` on a
    /// path that has not been created yet is a real flow (the create-on-write
    /// stub in `update_file_gotcha_key` exists for exactly that).
    #[test]
    fn resolve_lenient_tolerates_a_missing_leaf() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let missing = dir.path().join("does_not_exist.rs");
        let resolved = resolve_lenient(missing.to_str().unwrap()).expect("parent resolves");
        assert_eq!(
            normalize_affected_files_with_root(&[resolved], Some(root.to_str().unwrap())),
            vec!["does_not_exist.rs"]
        );
    }

    /// Without a repo root there is nothing to strip. The gate behaves the
    /// same way (`normalize_path(path, None)`), so both sides still agree —
    /// which is the property that matters, even though neither can produce a
    /// useful key here.
    #[test]
    fn normalize_absolute_path_without_root_matches_read_side() {
        let expected = crate::hooks::decide::normalize_path("/elsewhere/foo.rs", None);
        assert_eq!(norm(&["/elsewhere/foo.rs"], None), vec![expected]);
    }

    /// Globs (`analysis::onboarding`'s CODEOWNERS candidates) must survive
    /// untouched — `*` is an ordinary path component to `normalize_path`.
    #[test]
    fn normalize_preserves_globs() {
        assert_eq!(norm(&["src/payments/**"], None), vec!["src/payments/**"]);
        assert_eq!(norm(&["src/*.rs"], None), vec!["src/*.rs"]);
        assert_eq!(norm(&["**/*.rs"], None), vec!["**/*.rs"]);
        // A glob still gets the `./` treatment, and nothing else.
        assert_eq!(norm(&["./src/payments/**"], None), vec!["src/payments/**"]);
    }

    #[test]
    fn normalize_is_a_no_op_for_already_normalized_paths() {
        let files = &["src/a.rs", "src/nested/b.rs", "Cargo.toml"];
        assert_eq!(norm(files, Some("/home/dev/repo")), files.to_vec());
    }

    /// Two spellings of one path collapse to a single entry, so the gotcha
    /// does not end up double-linked to the same file record.
    #[test]
    fn normalize_dedupes_and_drops_empties() {
        assert_eq!(
            norm(&["./src/a.rs", "src/a.rs", "", "src/b.rs"], None),
            vec!["src/a.rs", "src/b.rs"]
        );
    }

    /// `analysis::walker` and `analysis::git` rewrite `\` to `/` before a
    /// `file:*` key is ever minted, so an entry carrying a backslash could
    /// never match. Match the producers.
    #[test]
    fn normalize_rewrites_backslashes_like_the_key_producers() {
        assert_eq!(norm(&["src\\foo.rs"], None), vec!["src/foo.rs"]);
        assert_eq!(norm(&[".\\src\\foo.rs"], None), vec!["src/foo.rs"]);
    }

    /// End-to-end: a gotcha written with `./src/a.rs` must link `file:src/a.rs`
    /// — the key the read gate looks up — and must store the corrected path in
    /// its own payload, since `mati repair` rebuilds the indexes from there.
    #[tokio::test]
    async fn apply_write_normalizes_affected_files_before_linking() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put("file:src/a.rs", &make_file_record("src/a.rs"))
            .await
            .unwrap();

        let record = make_gotcha_record("gotcha:dotslash", &["./src/a.rs"]);
        apply_gotcha_write(&store, &record, &[], &["./src/a.rs".into()], true)
            .await
            .unwrap();

        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        assert!(file_gotcha_keys(&a).contains(&"gotcha:dotslash".to_string()));
        assert!(
            store.get("file:./src/a.rs").await.unwrap().is_none(),
            "the raw spelling must not be linked or stubbed"
        );

        let stored = store.get("gotcha:dotslash").await.unwrap().unwrap();
        let gotcha = stored.payload_as::<GotchaRecord>().unwrap();
        assert_eq!(gotcha.affected_files, vec!["src/a.rs".to_string()]);

        let edge_keys = store.scan_keys("graph:edge:").await.unwrap();
        let edge = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:dotslash").to_key();
        assert!(edge_keys.contains(&edge));

        store.close().await.unwrap();
    }

    /// An already-correct path must round-trip byte-for-byte: the payload is
    /// not rewritten and no clone is taken.
    #[tokio::test]
    async fn apply_write_leaves_normalized_affected_files_untouched() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let record = make_gotcha_record("gotcha:clean", &["src/a.rs", "src/payments/**"]);
        let files = vec!["src/a.rs".to_string(), "src/payments/**".to_string()];
        apply_gotcha_write(&store, &record, &[], &files, true)
            .await
            .unwrap();

        let stored = store.get("gotcha:clean").await.unwrap().unwrap();
        let gotcha = stored.payload_as::<GotchaRecord>().unwrap();
        assert_eq!(gotcha.affected_files, files);

        store.close().await.unwrap();
    }

    /// D3 foundation regression: tombstone must write a negative-exemplar
    /// record for each unique dirname in `affected_files`, capturing the
    /// rule/reason/severity from the tombstoned gotcha. The exemplar is
    /// what feeds back into future `/mati-enrich` runs on the same
    /// directory so the extractor can avoid re-proposing similar
    /// rejected rules. See `src/store/negative_exemplar.rs`.
    #[tokio::test]
    async fn tombstone_writes_negative_exemplar_per_unique_dirname() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Seed a gotcha that affects two files in different directories
        // plus a second file in one of those dirnames (dedup target).
        let record = make_gotcha_record(
            "gotcha:vague-rule",
            &["src/cli/repair.rs", "src/cli/init.rs", "src/store/db.rs"],
        );
        store.put("gotcha:vague-rule", &record).await.unwrap();

        // Tombstone it.
        apply_gotcha_tombstone(
            &store,
            "gotcha:vague-rule",
            &[
                "src/cli/repair.rs".into(),
                "src/cli/init.rs".into(),
                "src/store/db.rs".into(),
            ],
        )
        .await
        .unwrap();

        // src/cli and src/store → 2 unique dirnames → 2 exemplars.
        let cli_exemplar = store
            .get("analytics:negative_exemplar:src/cli:vague-rule")
            .await
            .unwrap()
            .expect("src/cli exemplar must exist");
        let store_exemplar = store
            .get("analytics:negative_exemplar:src/store:vague-rule")
            .await
            .unwrap()
            .expect("src/store exemplar must exist");

        // Payload carries rule/reason/severity from the make_gotcha_record helper.
        for rec in [&cli_exemplar, &store_exemplar] {
            let payload = rec.payload.clone().expect("payload present");
            let exemplar: crate::store::negative_exemplar::NegativeExemplar =
                serde_json::from_value(payload).unwrap();
            assert_eq!(exemplar.gotcha_key, "gotcha:vague-rule");
            assert_eq!(exemplar.rule, "test rule");
            assert_eq!(exemplar.reason, "test reason");
            assert_eq!(exemplar.severity, Priority::High);
            assert!(exemplar.tombstoned_at > 0);
        }

        store.close().await.unwrap();
    }
}
