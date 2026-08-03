//! Behavioural equivalence between the two live gotcha write paths.
//!
//! One CLI command has two transports. `StoreProxy` picks between them at
//! runtime: when no daemon owns the store it calls
//! [`crate::store::gotcha_ops`] directly; when a daemon does, it sends a typed
//! v2 command and [`crate::mcp::handlers`] performs the write inside its own
//! `transact_knowledge`. `ARCHITECTURE.md` section 22 concedes the split and
//! says anything `gotcha_ops` enforces "has to be mirrored there".
//!
//! `invariants::gotcha_write_sites` counts the write *sites*. It cannot say
//! whether the two implementations still agree. This module drives both with
//! the same input and diffs everything the write touches: the canonical
//! `gotcha:*` record, the derived `file:*.gotcha_keys`, the `HasGotcha` edges,
//! the `analytics:extraction:*` row, confidence, quality, lifecycle, clocks,
//! enforcement events, negative exemplars, dirty markers and consultation
//! receipts.
//!
//! # How to read a failure
//!
//! The paths already disagree. The `*_DIVERGENCES` constants below pin every
//! known difference with the reason it exists. A test fails when the pinned
//! set no longer matches reality — either a divergence was fixed (drop the
//! entry) or a new one appeared (a mirror update was missed; that is the bug
//! this module exists to catch).
//!
//! The snapshot deliberately does not compare wall-clock values field by
//! field. Both paths stamp `SystemTime::now()`, so an exact diff would be
//! flaky across a second boundary; [`snapshot`] renders them as
//! "bumped past the baseline" instead, which is the property that matters.

use std::collections::{BTreeMap, BTreeSet};

use crate::mcp::dispatch_v2::RequestContext;
use crate::mcp::handlers;
use crate::mcp::metadata::PeerContext;
use crate::mcp::protocol;
use crate::store::gotcha_ops;
use crate::store::record::{
    Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore,
};
use crate::store::Store;

// ── Which transport ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Path {
    /// No daemon: `StoreProxy::Direct` → `store::gotcha_ops`.
    Direct,
    /// Daemon owns the store: typed v2 command → `mcp::handlers`.
    Daemon,
}

fn test_ctx() -> RequestContext {
    RequestContext {
        peer: PeerContext {
            uid: 501,
            pid: Some(4242),
        },
        daemon_session: uuid::Uuid::nil(),
        repo_root: std::path::PathBuf::new(),
        policy_matcher: std::sync::Arc::new(tokio::sync::RwLock::new(
            crate::hooks::policy_match::PolicyMatcherSet::empty(),
        )),
    }
}

// ── Drivers ──────────────────────────────────────────────────────────────────

/// Mirror of `StoreProxy::gotcha_write`. The Socket arm's `GotchaDraftInput`
/// projection is copied verbatim from `src/cli/proxy.rs` so both arms receive
/// the same caller intent, not merely similar inputs.
async fn drive_write(
    path: Path,
    store: &Store,
    record: &Record,
    old_files: &[String],
    new_files: &[String],
    is_new: bool,
) -> Result<(), String> {
    match path {
        Path::Direct => gotcha_ops::apply_gotcha_write(store, record, old_files, new_files, is_new)
            .await
            .map_err(|e| e.to_string()),
        Path::Daemon => {
            let gotcha = record
                .payload_as::<GotchaRecord>()
                .unwrap_or_else(|| GotchaRecord {
                    rule: record.value.clone(),
                    reason: String::new(),
                    severity: Priority::Normal,
                    affected_files: new_files.to_vec(),
                    ref_url: None,
                    discovered_session: 0,
                    confirmed: false,
                    confirmed_content: Default::default(),
                });
            let source = match &record.source {
                RecordSource::DeveloperManual => Some("developer_manual".to_string()),
                RecordSource::Import => Some("import".to_string()),
                _ => None,
            };
            let input = protocol::GotchaDraftInput {
                key: record.key.clone(),
                rule: gotcha.rule,
                reason: gotcha.reason,
                severity: gotcha.severity.into(),
                affected_files: new_files.to_vec(),
                ref_url: gotcha.ref_url,
                tags: record.tags.clone(),
                priority: record.priority.clone().into(),
                source,
            };
            handlers::handle_gotcha_upsert(store, &test_ctx(), uuid::Uuid::nil(), &input)
                .await
                .map(|_| ())
                .map_err(|(code, msg)| format!("{code:?}: {msg}"))
        }
    }
}

/// Mirror of `cli::gotcha::confirm_gotcha`, including the record mutation the
/// CLI performs before handing the Direct arm its record and the
/// `propagate_confirmation` call it makes afterwards.
async fn drive_confirm(path: Path, store: &Store, key: &str) -> Result<(), String> {
    let mut record = store
        .get(key)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no record found for '{key}'"))?;

    if record.category != Category::Gotcha {
        return Err(format!("'{key}' is not a Gotcha record"));
    }
    if !matches!(record.lifecycle, RecordLifecycle::Active) {
        return Err(format!("'{key}' is tombstoned — cannot confirm"));
    }

    if let Some(obj) = record.payload.as_mut().and_then(|p| p.as_object_mut()) {
        if let Some(sev) = obj
            .get("severity")
            .and_then(|v| v.as_str())
            .map(str::to_lowercase)
        {
            obj.insert("severity".to_string(), serde_json::Value::String(sev));
        }
        obj.insert("confirmed".to_string(), serde_json::Value::Bool(true));
    }

    let now = now_secs();
    record.source = RecordSource::DeveloperManual;
    record.confidence.value = ConfidenceScore::base_for_source(&RecordSource::DeveloperManual);
    record.confidence.confirmation_count += 1;
    record.quality = crate::health::quality::analyze(&record);
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;

    let affected_files: Vec<String> = record
        .payload_as::<GotchaRecord>()
        .map(|g| g.affected_files)
        .unwrap_or_default();

    match path {
        Path::Direct => {
            gotcha_ops::apply_gotcha_confirm(store, &record, &affected_files)
                .await
                .map_err(|e| e.to_string())?;
            // `StoreProxy::propagate_confirmation`: Direct arm only — the
            // daemon handler stages the same bump inside its transaction.
            gotcha_ops::propagate_confirmation_to_files(store, &affected_files).await;
        }
        Path::Daemon => {
            let input = protocol::GotchaConfirmInput {
                key: key.to_string(),
            };
            handlers::handle_gotcha_confirm(store, &test_ctx(), uuid::Uuid::nil(), &input)
                .await
                .map_err(|(code, msg)| format!("{code:?}: {msg}"))?;
        }
    }
    Ok(())
}

/// Mirror of `StoreProxy::gotcha_tombstone`, including the CLI's read of
/// `affected_files` off the record before the call.
async fn drive_tombstone(path: Path, store: &Store, key: &str) -> Result<(), String> {
    let affected: Vec<String> = store
        .get(key)
        .await
        .map_err(|e| e.to_string())?
        .and_then(|r| r.payload_as::<GotchaRecord>())
        .map(|g| g.affected_files)
        .unwrap_or_default();

    match path {
        Path::Direct => gotcha_ops::apply_gotcha_tombstone(store, key, &affected)
            .await
            .map_err(|e| e.to_string()),
        Path::Daemon => {
            let input = protocol::GotchaTombstoneInput {
                key: key.to_string(),
            };
            handlers::handle_gotcha_tombstone(store, &test_ctx(), uuid::Uuid::nil(), &input)
                .await
                .map(|_| ())
                .map_err(|(code, msg)| format!("{code:?}: {msg}"))
        }
    }
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

/// Everything a gotcha write is supposed to touch, rendered as
/// `field -> value` so a diff names the exact field that moved.
type Snapshot = BTreeMap<String, String>;

async fn snapshot(store: &Store, key: &str, watched_files: &[&str], baseline: u64) -> Snapshot {
    let mut s = Snapshot::new();
    let bumped = |ts: u64| -> String { format!("bumped={}", ts >= baseline) };

    // ── canonical gotcha record ──
    match store.get(key).await.ok().flatten() {
        None => {
            s.insert("record".into(), "ABSENT".into());
        }
        Some(r) => {
            s.insert("record".into(), "present".into());
            s.insert("record.value".into(), r.value.clone());
            s.insert("record.category".into(), format!("{:?}", r.category));
            s.insert("record.priority".into(), format!("{:?}", r.priority));
            s.insert("record.tags".into(), format!("{:?}", r.tags));
            s.insert("record.source".into(), format!("{:?}", r.source));
            s.insert("record.ref_url".into(), format!("{:?}", r.ref_url));
            // Discriminant only — a tombstone carries a wall-clock `at`.
            s.insert(
                "record.lifecycle".into(),
                match &r.lifecycle {
                    RecordLifecycle::Tombstoned { reason, .. } => {
                        format!("Tombstoned({reason:?})")
                    }
                    other => format!("{other:?}"),
                },
            );
            s.insert(
                "confidence.value".into(),
                format!("{:.4}", r.confidence.value),
            );
            s.insert(
                "confidence.confirmation_count".into(),
                r.confidence.confirmation_count.to_string(),
            );
            s.insert(
                "confidence.contributor_count".into(),
                r.confidence.contributor_count.to_string(),
            );
            s.insert("quality.value".into(), format!("{:.4}", r.quality.value));
            s.insert("quality.tier".into(), format!("{:?}", r.quality.tier));
            s.insert(
                "quality.signals".into(),
                format!("{}", r.quality.signals.len()),
            );
            s.insert(
                "version.logical_clock".into(),
                r.version.logical_clock.to_string(),
            );
            s.insert("version.wall_clock".into(), bumped(r.version.wall_clock));
            s.insert("record.updated_at".into(), bumped(r.updated_at));

            let payload = r.payload_as::<GotchaRecord>();
            match payload {
                None => {
                    s.insert("payload".into(), "UNPARSEABLE".into());
                }
                Some(g) => {
                    s.insert("payload.rule".into(), g.rule);
                    s.insert("payload.reason".into(), g.reason);
                    s.insert("payload.severity".into(), format!("{:?}", g.severity));
                    s.insert(
                        "payload.affected_files".into(),
                        format!("{:?}", g.affected_files),
                    );
                    s.insert("payload.ref_url".into(), format!("{:?}", g.ref_url));
                    s.insert("payload.confirmed".into(), g.confirmed.to_string());
                    s.insert(
                        "payload.confirmed_content".into(),
                        format!("{:?}", g.confirmed_content.keys().collect::<Vec<_>>()),
                    );
                }
            }
        }
    }

    // ── derived file links + confirmation propagation ──
    for path in watched_files {
        let file_key = format!("file:{path}");
        match store.get(&file_key).await.ok().flatten() {
            None => {
                s.insert(format!("file[{path}]"), "ABSENT".into());
            }
            Some(fr) => {
                let keys: Vec<String> = fr
                    .payload
                    .as_ref()
                    .and_then(|p| p.get("gotcha_keys"))
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                s.insert(format!("file[{path}].gotcha_keys"), format!("{keys:?}"));
                s.insert(
                    format!("file[{path}].confirmation_count"),
                    fr.confidence.confirmation_count.to_string(),
                );
                s.insert(
                    format!("file[{path}].logical_clock"),
                    fr.version.logical_clock.to_string(),
                );
            }
        }
    }

    // ── HasGotcha graph edges ──
    let edges: BTreeSet<String> = store
        .scan_keys("graph:edge:")
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|k| k.ends_with(key))
        .collect();
    s.insert("graph.has_gotcha_edges".into(), format!("{edges:?}"));

    // ── analytics:extraction:* ──
    let ex_key = crate::store::extraction::key_for(key);
    match store.get(&ex_key).await.ok().flatten() {
        None => {
            s.insert("extraction".into(), "ABSENT".into());
        }
        Some(r) => {
            let parsed = r.payload_as::<crate::store::extraction::ExtractionRecord>();
            s.insert(
                "extraction".into(),
                match parsed {
                    Some(e) => format!(
                        "outcome={:?} depth={:?} file={} config={:?}",
                        e.outcome, e.depth, e.file_path, e.config
                    ),
                    None => "UNPARSEABLE".into(),
                },
            );
        }
    }

    // ── analytics:negative_exemplar:* ──
    let negs: BTreeSet<String> = store
        .scan_keys(crate::store::negative_exemplar::NEG_EXEMPLAR_PREFIX)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    s.insert("negative_exemplars".into(), format!("{negs:?}"));

    // ── enforcement events ──
    let events = crate::store::enforcement::scan_enforcement_events(store, 0, u64::MAX)
        .await
        .unwrap_or_default();
    let rendered: Vec<String> = events
        .iter()
        .map(|e| {
            format!(
                "{:?}/{:?}/{}/{}",
                e.event_type, e.subject_kind, e.subject_key, e.decision_reason_code
            )
        })
        .collect();
    s.insert("enforcement_events".into(), format!("{rendered:?}"));

    // ── dirty marker ──
    s.insert(
        "dirty_marker".into(),
        match crate::store::repair::read_dirty_marker(store).await {
            None => "ABSENT".into(),
            Some(m) => format!("dirty={} keys={:?}", m.dirty, m.affected_keys),
        },
    );

    // ── consultation receipts ──
    let receipts: BTreeSet<String> = store
        .scan_keys("session:consulted:")
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    s.insert("consultation_receipts".into(), format!("{receipts:?}"));

    // ── v2 knowledge audit rows ──
    let audits = store
        .scan_keys("audit:knowledge:")
        .await
        .unwrap_or_default()
        .len();
    s.insert("audit_knowledge_rows".into(), audits.to_string());

    s
}

/// Field names whose rendered values differ, plus the two values.
fn diff(direct: &Snapshot, daemon: &Snapshot) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    let keys: BTreeSet<&String> = direct.keys().chain(daemon.keys()).collect();
    for k in keys {
        let a = direct.get(k).cloned().unwrap_or_else(|| "<missing>".into());
        let b = daemon.get(k).cloned().unwrap_or_else(|| "<missing>".into());
        if a != b {
            out.insert(k.clone(), (a, b));
        }
    }
    out
}

/// Assert the observed divergence set is exactly the pinned one, printing the
/// full field-level diff when it is not.
fn assert_divergences(scenario: &str, d: &BTreeMap<String, (String, String)>, expected: &[&str]) {
    let observed: BTreeSet<&str> = d.keys().map(String::as_str).collect();
    let pinned: BTreeSet<&str> = expected.iter().copied().collect();
    if observed == pinned {
        return;
    }
    let mut report = format!("\n{scenario}: gotcha write paths drifted\n\n");
    for (field, (a, b)) in d {
        let mark = if pinned.contains(field.as_str()) {
            "known"
        } else {
            "NEW  "
        };
        report.push_str(&format!(
            "  [{mark}] {field}\n    direct: {a}\n    daemon: {b}\n"
        ));
    }
    for missing in pinned.difference(&observed) {
        report.push_str(&format!(
            "  [GONE ] {missing}\n    the paths now agree here — drop it from EXPECTED_DIVERGENCES\n"
        ));
    }
    panic!("{report}");
}

// ── Pinned divergences ───────────────────────────────────────────────────────

/// Divergences on a **create** (`mati gotcha add`, `is_new = true`).
///
/// - `payload.confirmed` — `gotcha_ops` honours the caller's
///   `confirmed: true`; `upsert_commit_once` hard-codes `confirmed: false`.
///   Only `confirmed: true` can deny a read, so the daemon transport turns a
///   developer's enforcing rule into an advisory one.
/// - `payload.confirmed_content` — follows from the above:
///   `apply_gotcha_write` stamps the content digest of a new confirmed
///   record, so `mati stale` can report drift against it. The handler never
///   stamps, so drift on that gotcha is unreportable.
/// - `confidence.confirmation_count` — the CLI sets 1 (an explicit developer
///   assertion); the handler rebuilds the score with `for_new_record`, which
///   zeroes it. Feeds `log2(count + 2)` in the confidence formula.
/// - `dirty_marker` — `gotcha_ops` pre-arms and clears a cancellation guard,
///   leaving a clean marker behind; the handler has no dirty-marker path at
///   all, so its best-effort edge writes fail invisibly to
///   `mati repair --fast`. Only visible against a virgin store: once any
///   `gotcha_ops` write has run, the marker record exists on both sides.
/// - `audit_knowledge_rows` — only the handler writes `audit:knowledge:*`.
///
/// Quality does **not** split: `quality::analyze` reads rule, reason, value
/// and tags, none of which the handler rewrites, so its recomputation lands
/// on the same score the CLI already stored.
const CREATE_DIVERGENCES: &[&str] = &[
    "payload.confirmed",
    "payload.confirmed_content",
    "confidence.confirmation_count",
    "dirty_marker",
    "audit_knowledge_rows",
];

/// Divergences on an **edit** (`mati gotcha edit`, `is_new = false`).
///
/// Same causes as create. `payload.confirmed_content` splits for a different
/// reason here: the CLI carries the existing baseline forward untouched
/// (editing rule text is not re-reading the code), while the handler rebuilds
/// the payload with `confirmed_content: Default::default()` and discards it.
/// Editing a confirmed, stamped gotcha over the socket therefore both
/// un-confirms it and erases its drift baseline.
///
/// `dirty_marker` is absent from this list only because the fixture seeds via
/// `apply_gotcha_write`, which leaves a marker record in both stores.
const EDIT_DIVERGENCES: &[&str] = &[
    "payload.confirmed",
    "payload.confirmed_content",
    "confidence.confirmation_count",
    "audit_knowledge_rows",
];

/// Divergences on **confirm** (`mati gotcha confirm`).
///
/// `consultation_receipts` — the handler drops
/// `session:consulted:file:<path>` for every affected file so the next hook
/// re-blocks; `apply_gotcha_confirm` leaves the stale receipt in place,
/// letting an agent act on the file without ever seeing the newly-confirmed
/// rule.
const CONFIRM_DIVERGENCES: &[&str] = &["consultation_receipts", "audit_knowledge_rows"];

/// Divergences on **confirm of a legacy record** whose `affected_files` were
/// stored before path normalization existed.
///
/// `apply_gotcha_confirm` re-keys them through `normalize_affected_files`;
/// `confirm_commit_once` does not. The daemon transport leaves the record
/// pointing at `./src/a.rs`, which `file:src/a.rs` never matches, so the
/// derived index, the graph edge and the confirm-time content stamp all miss
/// too. This is the silent-non-enforcement case ARCHITECTURE.md section 22
/// calls out under "Path normalization".
///
/// No receipt is seeded here, so `consultation_receipts` does not appear —
/// that difference is covered by [`CONFIRM_DIVERGENCES`].
const CONFIRM_LEGACY_DIVERGENCES: &[&str] = &[
    "payload.affected_files",
    "payload.confirmed_content",
    "file[src/a.rs].gotcha_keys",
    "file[src/a.rs].logical_clock",
    "graph.has_gotcha_edges",
    "dirty_marker",
    "audit_knowledge_rows",
];

/// Divergences on **tombstone** (`mati gotcha delete`).
///
/// The two paths agree on everything the tombstone touches — record
/// lifecycle, clocks, file-link cleanup, edge removal, the negative-exemplar
/// archive, the extraction outcome and the `ControlChanged::Deleted` event.
/// Only the v2 audit row is one-sided.
const TOMBSTONE_DIVERGENCES: &[&str] = &["audit_knowledge_rows"];

// ── Fixtures ─────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

/// A gotcha record shaped exactly as `cli::gotcha::finish_gotcha_add` builds
/// it: developer-manual, `confirmed: true`, one confirmation, quality scored
/// by `quality::analyze`.
fn manual_add_record(key: &str, rule: &str, reason: &str, files: &[&str]) -> Record {
    let now = now_secs();
    let gotcha = GotchaRecord {
        rule: rule.into(),
        reason: reason.into(),
        severity: Priority::High,
        affected_files: files.iter().map(|s| s.to_string()).collect(),
        ref_url: None,
        discovered_session: now,
        confirmed: true,
        confirmed_content: Default::default(),
    };
    let mut record = Record {
        key: key.into(),
        value: format!("{rule} because {reason}"),
        payload: serde_json::to_value(&gotcha).ok(),
        category: Category::Gotcha,
        priority: Priority::High,
        tags: vec![],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: crate::store::stable_device_id(),
            logical_clock: 1,
            wall_clock: now,
        },
        quality: QualityScore::developer_entry_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::DeveloperManual,
        confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
        gap_analysis_score: 0.0,
    };
    record.confidence.confirmation_count = 1;
    record.quality = crate::health::quality::analyze(&record);
    record
}

/// A Layer 0 file record, as `mati init` writes it, carrying a content digest
/// so `confirm_content_stamp` has something to read.
fn file_record(path: &str) -> Record {
    let now = now_secs();
    let mut fr = crate::store::record::FileRecord::layer0_stub(
        path,
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
    fr.content_hash = Some(format!("hash-of-{path}"));
    let mut rec = Record::layer0_file_stub(
        format!("file:{path}"),
        crate::store::stable_device_id(),
        1,
        now,
    );
    rec.payload = serde_json::to_value(&fr).ok();
    rec
}

/// Seed a Layer 0 `file:*` record. The key is bound to a `format!` with a
/// literal prefix so `invariants::gotcha_write_sites` can prove this write can
/// never name a gotcha.
async fn seed_file(store: &Store, path: &str) {
    let file_key = format!("file:{path}");
    store
        .put(&file_key, &file_record(path))
        .await
        .expect("seed file record");
}

/// Seed a gotcha record byte-for-byte, bypassing `gotcha_ops`.
///
/// Needed by exactly one scenario: a record whose `affected_files` predate
/// path normalization. `apply_gotcha_write` would re-key it on the way in,
/// which is the behaviour under test. Listed in `invariants::INVENTORY`.
async fn seed_verbatim(store: &Store, record: &Record) {
    store.put(&record.key, record).await.expect("seed gotcha");
}

/// Run `body` against a pair of freshly-opened, identically-seeded temp
/// stores — one per transport — and return the field-level diff.
async fn compare<F, Fut>(
    watched: &[&str],
    gotcha_key: &str,
    body: F,
) -> BTreeMap<String, (String, String)>
where
    F: Fn(Path, Store) -> Fut,
    Fut: std::future::Future<Output = Store>,
{
    let baseline = now_secs();
    let mut snaps = Vec::new();
    for path in [Path::Direct, Path::Daemon] {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = Store::open(dir.path()).await.expect("open store");
        let store = body(path, store).await;
        snaps.push(snapshot(&store, gotcha_key, watched, baseline).await);
        store.close().await.expect("close store");
    }
    diff(&snaps[0], &snaps[1])
}

// ── Scenarios ────────────────────────────────────────────────────────────────

const KEY: &str = "gotcha:never-swallow-the-write-error";
const RULE: &str = "Never swallow the error returned by Store::put";
const REASON: &str =
    "the canonical record is the source of truth, so a dropped error loses the write silently";

#[tokio::test]
async fn create_paths_diverge_only_where_pinned() {
    let d = compare(&["src/a.rs"], KEY, |path, store| async move {
        seed_file(&store, "src/a.rs").await;
        let record = manual_add_record(KEY, RULE, REASON, &["src/a.rs"]);
        drive_write(path, &store, &record, &[], &["src/a.rs".into()], true)
            .await
            .expect("create");
        store
    })
    .await;
    assert_divergences("create", &d, CREATE_DIVERGENCES);
}

#[tokio::test]
async fn create_with_multiple_affected_files_diverges_only_where_pinned() {
    let files = ["src/a.rs", "src/b.rs", "src/c.rs"];
    let d = compare(&files, KEY, |path, store| async move {
        for f in files {
            seed_file(&store, f).await;
        }
        let record = manual_add_record(KEY, RULE, REASON, &files);
        let new: Vec<String> = files.iter().map(|s| s.to_string()).collect();
        drive_write(path, &store, &record, &[], &new, true)
            .await
            .expect("create");
        store
    })
    .await;
    assert_divergences("create multi-file", &d, CREATE_DIVERGENCES);
}

#[tokio::test]
async fn create_below_quality_gate_diverges_only_where_pinned() {
    // A rule with no concrete target and a reason with no causal clause —
    // `quality::analyze` scores it low. The CLI would refuse it at
    // `below_quality_gate`, but neither write path has a gate of its own, so
    // this asks what each one *stores* when handed a weak record.
    let d = compare(&["src/a.rs"], KEY, |path, store| async move {
        seed_file(&store, "src/a.rs").await;
        let record = manual_add_record(KEY, "be careful", "it breaks", &["src/a.rs"]);
        assert!(
            crate::health::quality::below_quality_gate(&record.quality),
            "fixture must sit below the quality gate for this test to mean anything"
        );
        drive_write(path, &store, &record, &[], &["src/a.rs".into()], true)
            .await
            .expect("create");
        store
    })
    .await;
    assert_divergences("create below quality gate", &d, CREATE_DIVERGENCES);
}

#[tokio::test]
async fn create_on_existing_slug_diverges_only_where_pinned() {
    // `is_new = true` against a key that already holds an active record.
    // `apply_gotcha_write` refuses (`ensure_gotcha_key_available`);
    // `handle_gotcha_upsert` overwrites. Both outcomes are captured in the
    // snapshot, so the diff shows the whole record, not just an error string.
    let d = compare(&["src/a.rs"], KEY, |path, store| async move {
        seed_file(&store, "src/a.rs").await;
        let first = manual_add_record(KEY, RULE, REASON, &["src/a.rs"]);
        gotcha_ops::apply_gotcha_write(&store, &first, &[], &["src/a.rs".into()], true)
            .await
            .expect("seed");

        let second = manual_add_record(KEY, "Always close the store handle", REASON, &["src/a.rs"]);
        // Deliberately ignored: Direct errors, Daemon succeeds. The
        // divergence we care about is what ends up in the store.
        let _ = drive_write(path, &store, &second, &[], &["src/a.rs".into()], true).await;
        store
    })
    .await;
    assert_divergences(
        "create on existing slug",
        &d,
        &[
            // Direct refused the write, so the first record survives intact;
            // Daemon replaced it. Everything the second write touches splits,
            // including the enforcement stream: Direct records nothing at all,
            // Daemon records a `ControlChanged::Updated` for what the caller
            // asked to be a create.
            "record.value",
            "payload.rule",
            "payload.confirmed",
            "payload.confirmed_content",
            "confidence.confirmation_count",
            "quality.value",
            "version.logical_clock",
            "enforcement_events",
            "audit_knowledge_rows",
        ],
    );
}

#[tokio::test]
async fn edit_paths_diverge_only_where_pinned() {
    let d = compare(&["src/a.rs", "src/b.rs"], KEY, |path, store| async move {
        for f in ["src/a.rs", "src/b.rs"] {
            seed_file(&store, f).await;
        }
        let original = manual_add_record(KEY, RULE, REASON, &["src/a.rs"]);
        gotcha_ops::apply_gotcha_write(&store, &original, &[], &["src/a.rs".into()], true)
            .await
            .expect("seed");

        // `mati gotcha edit`: same key, new rule text, file set moves a -> b.
        let mut edited = store.get(KEY).await.unwrap().unwrap();
        let mut g = edited.payload_as::<GotchaRecord>().unwrap();
        g.rule = "Always close the store handle".into();
        g.affected_files = vec!["src/b.rs".into()];
        edited.value = format!("{} because {}", g.rule, g.reason);
        edited.payload = serde_json::to_value(&g).ok();
        edited.version.logical_clock += 1;
        edited.quality = crate::health::quality::analyze(&edited);

        drive_write(
            path,
            &store,
            &edited,
            &["src/a.rs".into()],
            &["src/b.rs".into()],
            false,
        )
        .await
        .expect("edit");
        store
    })
    .await;
    assert_divergences("edit", &d, EDIT_DIVERGENCES);
}

#[tokio::test]
async fn confirm_paths_diverge_only_where_pinned() {
    let d = compare(&["src/a.rs"], KEY, |path, store| async move {
        seed_file(&store, "src/a.rs").await;
        // Seed an unconfirmed record, the state `mati review` confirms from.
        let mut record = manual_add_record(KEY, RULE, REASON, &["src/a.rs"]);
        let mut g = record.payload_as::<GotchaRecord>().unwrap();
        g.confirmed = false;
        record.payload = serde_json::to_value(&g).ok();
        record.source = RecordSource::ClaudeEnrich;
        record.confidence = ConfidenceScore::for_new_record(&RecordSource::ClaudeEnrich);
        gotcha_ops::apply_gotcha_write(&store, &record, &[], &["src/a.rs".into()], true)
            .await
            .expect("seed");
        // A receipt minted before confirmation — the bypass token the daemon
        // path invalidates and the direct path does not.
        crate::store::session::log_hit(&store, "file:src/a.rs")
            .await
            .expect("seed receipt");

        drive_confirm(path, &store, KEY).await.expect("confirm");
        store
    })
    .await;
    assert_divergences("confirm", &d, CONFIRM_DIVERGENCES);
}

#[tokio::test]
async fn confirm_of_legacy_unnormalized_paths_diverges_only_where_pinned() {
    let d = compare(&["src/a.rs"], KEY, |path, store| async move {
        seed_file(&store, "src/a.rs").await;
        // Written before path normalization existed: `./src/a.rs` never
        // matches `file:src/a.rs`, so the rule is inert until something
        // re-keys it.
        let mut record = manual_add_record(KEY, RULE, REASON, &["./src/a.rs"]);
        let mut g = record.payload_as::<GotchaRecord>().unwrap();
        g.confirmed = false;
        g.affected_files = vec!["./src/a.rs".into()];
        record.payload = serde_json::to_value(&g).ok();
        record.source = RecordSource::ClaudeEnrich;
        record.confidence = ConfidenceScore::for_new_record(&RecordSource::ClaudeEnrich);
        seed_verbatim(&store, &record).await;

        drive_confirm(path, &store, KEY).await.expect("confirm");
        store
    })
    .await;
    assert_divergences("confirm legacy paths", &d, CONFIRM_LEGACY_DIVERGENCES);
}

#[tokio::test]
async fn tombstone_paths_diverge_only_where_pinned() {
    let files = ["src/a.rs", "src/b.rs"];
    let d = compare(&files, KEY, |path, store| async move {
        for f in files {
            seed_file(&store, f).await;
        }
        let record = manual_add_record(KEY, RULE, REASON, &files);
        let new: Vec<String> = files.iter().map(|s| s.to_string()).collect();
        gotcha_ops::apply_gotcha_write(&store, &record, &[], &new, true)
            .await
            .expect("seed");

        drive_tombstone(path, &store, KEY).await.expect("tombstone");
        store
    })
    .await;
    assert_divergences("tombstone", &d, TOMBSTONE_DIVERGENCES);
}

#[tokio::test]
async fn enriched_tag_extraction_row_matches_on_both_paths() {
    // `/mati-enrich` writes gotchas tagged "enriched"; both paths carry their
    // own copy of the `write_on_extraction` hook. This pins that the two
    // copies still produce the same `analytics:extraction:*` row.
    let d = compare(&["src/a.rs"], KEY, |path, store| async move {
        seed_file(&store, "src/a.rs").await;
        let mut record = manual_add_record(KEY, RULE, REASON, &["src/a.rs"]);
        record.tags = vec![
            "enriched".into(),
            "depth:deep".into(),
            "signal-source:ast".into(),
        ];
        drive_write(path, &store, &record, &[], &["src/a.rs".into()], true)
            .await
            .expect("create");
        store
    })
    .await;
    assert!(
        !d.contains_key("extraction"),
        "extraction row drifted between write paths: {:?}",
        d.get("extraction")
    );
    assert_divergences("create with enriched tags", &d, CREATE_DIVERGENCES);
}
