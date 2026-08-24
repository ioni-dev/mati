use super::*;

// ─────────────────────────────────────────────
// Decision Basis Hash
// ─────────────────────────────────────────────

/// Compute a hash of the gotcha state used for an enforcement decision.
///
/// Each gotcha contributes its key, rule text, and confidence value to the
/// hash. This proves which exact rule state was in force at decision time.
///
/// Gotchas are sorted by key first: callers hold them in a `HashMap`, whose
/// iteration order varies per process, so an unsorted digest would differ
/// between two decisions made on identical state.
///
/// Only stored knowledge goes in — key, rule, confidence — never the command
/// line or tool input that triggered the decision, and the output is a digest,
/// so no secret can reach the append-only chain through this field.
pub fn compute_decision_basis_hash(gotchas: &[(&str, &serde_json::Value)]) -> String {
    let mut ordered: Vec<&(&str, &serde_json::Value)> = gotchas.iter().collect();
    ordered.sort_by(|a, b| a.0.cmp(b.0));

    let mut hasher = Sha256::new();
    for (key, record_json) in ordered {
        hasher.update(key.as_bytes());
        let rule = record_json
            .pointer("/value")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        hasher.update(rule.as_bytes());
        let conf = record_json
            .pointer("/confidence/value")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        hasher.update(format!("{conf}").as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

// ─────────────────────────────────────────────
// Standalone Event Recording
// ─────────────────────────────────────────────

/// Process-global registry of per-store serialized enforcement writers.
///
/// One long-lived [`EnforcementEventWriter`] per store (keyed by store root)
/// serializes the whole `prev_hash`-capture → seq-allocation → event-write
/// critical section. Without it, each `record_event` built a fresh writer that
/// independently captured `prev_hash`/seq, so concurrent writers collided on a
/// seq number (silently overwriting an already-recorded event) or shared a
/// `prev_hash` (breaking the chain). Caching the head in memory also drops the
/// O(N) `scan_keys` the per-call writer ran on every single event.
///
/// Cross-process correctness comes from SurrealKV's exclusive per-path lock:
/// only one process can open (and thus write to) a store at a time, and each
/// process loads the current head when it first writes.
static ENFORCEMENT_WRITERS: OnceLock<
    StdMutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<EnforcementEventWriter>>>>,
> = OnceLock::new();

/// Get (or lazily create) the single serialized writer for `store`.
pub(crate) async fn shared_writer(
    store: &Store,
) -> Result<Arc<tokio::sync::Mutex<EnforcementEventWriter>>> {
    let registry = ENFORCEMENT_WRITERS.get_or_init(|| StdMutex::new(HashMap::new()));

    // Fast path: a writer already exists for this store.
    if let Some(writer) = registry
        .lock()
        .expect("enforcement writer registry poisoned")
        .get(&store.root)
        .cloned()
    {
        return Ok(writer);
    }

    // Slow path: build the writer (async I/O) OUTSIDE the registry lock, then
    // insert. Double-checked — a concurrent caller may have inserted first, in
    // which case we keep theirs and drop ours (both loaded the same head).
    let writer = Arc::new(tokio::sync::Mutex::new(
        EnforcementEventWriter::new(store).await?,
    ));
    Ok(registry
        .lock()
        .expect("enforcement writer registry poisoned")
        .entry(store.root.clone())
        .or_insert(writer)
        .clone())
}

/// Record a single enforcement event through the store's serialized writer.
///
/// All event writes funnel through one [`EnforcementEventWriter`] per store
/// (via the internal `shared_writer` registry), so the hash chain stays intact
/// and seq numbers never collide under concurrency.
///
/// Respects the enforcement mode: in advisory mode, write failures are
/// logged but Ok(None) is returned. In strict mode, write failures propagate.
#[allow(clippy::too_many_arguments)]
pub async fn record_event(
    store: &Store,
    event_type: EnforcementEventType,
    subject_kind: SubjectKind,
    subject_key: String,
    agent_type: String,
    receipt_id: Option<String>,
    decision_reason_code: String,
    decision_basis_hash: Option<String>,
) -> Result<Option<EnforcementEvent>> {
    record_event_with_session(
        store,
        event_type,
        subject_kind,
        subject_key,
        agent_type,
        receipt_id,
        decision_reason_code,
        decision_basis_hash,
        None,
    )
    .await
}

/// Like [`record_event`], but attributes the event to an AI agent SESSION
/// (Claude Code `session_id`) for per-actor audit (schema_version 2). Used by the
/// hook-event path, which carries the `session_id` from the PreToolUse input.
#[allow(clippy::too_many_arguments)]
pub async fn record_event_with_session(
    store: &Store,
    event_type: EnforcementEventType,
    subject_kind: SubjectKind,
    subject_key: String,
    agent_type: String,
    receipt_id: Option<String>,
    decision_reason_code: String,
    decision_basis_hash: Option<String>,
    agent_session: Option<String>,
) -> Result<Option<EnforcementEvent>> {
    record_event_with_lineage(
        store,
        event_type,
        subject_kind,
        subject_key,
        agent_type,
        receipt_id,
        decision_reason_code,
        decision_basis_hash,
        agent_session,
        None,
    )
    .await
}

/// Like [`record_event_with_session`], but also records the subagent ACTOR
/// (Claude Code Task `agent_id`) that drove the event, for one-level agent
/// lineage (schema_version 3). `agent_session` is the spawning session, `agent_id`
/// the subagent that acted under it — `None` on the main thread. Only the
/// `ReceiptMinted` path that receives a `post-memget` hook payload carries both;
/// other emitters pass `None` for `agent_id`.
#[allow(clippy::too_many_arguments)]
pub async fn record_event_with_lineage(
    store: &Store,
    event_type: EnforcementEventType,
    subject_kind: SubjectKind,
    subject_key: String,
    agent_type: String,
    receipt_id: Option<String>,
    decision_reason_code: String,
    decision_basis_hash: Option<String>,
    agent_session: Option<String>,
    agent_id: Option<String>,
) -> Result<Option<EnforcementEvent>> {
    record_event_with_nested_lineage(
        store,
        event_type,
        subject_kind,
        subject_key,
        agent_type,
        receipt_id,
        decision_reason_code,
        decision_basis_hash,
        agent_session,
        agent_id,
        None,
    )
    .await
}

/// Like [`record_event_with_lineage`], plus `parent_agent_id` — the agent that
/// spawned `agent_id`, for nested agent→agent lineage (schema_version 4). Set
/// only by the `SubagentEdge` emitter fed by the `Agent`-tool `PostToolUse`
/// payload; hashed by the v4 canonical form (see `SCHEMA_VERSION`).
#[allow(clippy::too_many_arguments)]
pub async fn record_event_with_nested_lineage(
    store: &Store,
    event_type: EnforcementEventType,
    subject_kind: SubjectKind,
    subject_key: String,
    agent_type: String,
    receipt_id: Option<String>,
    decision_reason_code: String,
    decision_basis_hash: Option<String>,
    agent_session: Option<String>,
    agent_id: Option<String>,
    parent_agent_id: Option<String>,
) -> Result<Option<EnforcementEvent>> {
    let mode = get_enforcement_mode(store).await;

    let result = async {
        let writer = shared_writer(store).await?;
        let mut writer = writer.lock().await;
        writer.agent_session = agent_session;
        writer.agent_id = agent_id;
        writer.parent_agent_id = parent_agent_id;
        writer
            .write(
                store,
                event_type,
                subject_kind,
                subject_key,
                agent_type,
                receipt_id,
                decision_reason_code,
                decision_basis_hash,
            )
            .await
    }
    .await;

    match result {
        Ok(event) => Ok(Some(event)),
        Err(e) => match mode {
            EnforcementMode::Advisory => {
                tracing::warn!("enforcement event write failed (advisory mode): {e}");
                Ok(None)
            }
            EnforcementMode::Strict => Err(e),
        },
    }
}
