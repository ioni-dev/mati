use super::*;

// ─────────────────────────────────────────────
// Sequence Number Allocator
// ─────────────────────────────────────────────

/// Atomic sequence number allocator backed by the store.
///
/// Key: "enforcement:seq" — stores the current counter as a big-endian u64.
/// The counter is persisted before `next()` returns — if the store write
/// fails, the sequence number is not allocated.
pub struct SeqAllocator {
    current: u64,
}

impl SeqAllocator {
    /// Load the current sequence number from the store, or initialize to 0.
    pub async fn load(store: &Store) -> Self {
        let current = match store.get_raw_bytes(SEQ_KEY).await {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                u64::from_be_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
            }
            _ => 0,
        };
        Self { current }
    }

    /// Allocate the next sequence number and persist it durably.
    ///
    /// Returns the allocated seq_no. If the store write fails, the seq is
    /// NOT allocated and the caller gets an error.
    pub async fn next(&mut self, store: &Store) -> Result<u64> {
        self.current += 1;
        store.put_raw(SEQ_KEY, &self.current.to_be_bytes()).await?;
        Ok(self.current)
    }

    /// Return the current (last allocated) sequence number without incrementing.
    pub fn current(&self) -> u64 {
        self.current
    }
}

// ─────────────────────────────────────────────
// Installation ID
// ─────────────────────────────────────────────

/// Retrieve the installation_id from the store, or generate and persist one.
///
/// The installation_id is a UUIDv4 generated once at first init. It never
/// changes after that. NOT derived from hostname — stable across renames.
pub async fn get_or_create_installation_id(store: &Store) -> Result<String> {
    if let Ok(Some(bytes)) = store.get_raw_bytes(INSTALLATION_ID_KEY).await {
        if let Ok(id) = std::str::from_utf8(&bytes) {
            if !id.is_empty() {
                return Ok(id.to_string());
            }
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    store.put_raw(INSTALLATION_ID_KEY, id.as_bytes()).await?;
    Ok(id)
}

// ─────────────────────────────────────────────
// Actor Identity
// ─────────────────────────────────────────────

/// Get the local OS actor identity. Unverified — v1 trusts the local OS.
pub fn get_local_actor() -> Option<ActorLocal> {
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()?;

    #[cfg(unix)]
    let uid = Some(unsafe { libc::getuid() } as u32);
    #[cfg(not(unix))]
    let uid = None;

    Some(ActorLocal {
        username,
        uid,
        verified: false,
    })
}

// ─────────────────────────────────────────────
// Canonical File Identity
// ─────────────────────────────────────────────

/// Canonicalize a file path for use as a subject_key in enforcement events.
///
/// Rules (frozen for v1):
/// 1. Resolve relative paths against the repo root
/// 2. Normalize path separators to forward slash
/// 3. Remove `.` and `..` components
/// 4. Resolve symlinks where possible (fall back to normalized path if resolution fails)
/// 5. Strip the repo root prefix to produce a repo-relative path
/// 6. On case-insensitive filesystems (macOS default, Windows), lowercase the path
///
/// The output is a stable, canonical string that survives path aliasing.
///
/// # Known limitation (v1)
///
/// Case sensitivity is detected by platform default, not per-volume. Some
/// macOS volumes are case-sensitive and some Linux volumes (ecryptfs) are
/// case-insensitive. For v1, the platform default is acceptable.
pub fn canonicalize_file_key(path: &str, repo_root: &Path) -> String {
    // Step 1: Make absolute
    let abs_path = if Path::new(path).is_relative() {
        repo_root.join(path)
    } else {
        PathBuf::from(path)
    };

    // Step 2+3: Normalize components (remove `.` and `..`)
    let normalized = normalize_components(&abs_path);

    // Step 4: Try symlink resolution, fall back to normalized
    let resolved = std::fs::canonicalize(&normalized).unwrap_or(normalized);

    // Step 5: Strip repo root to get repo-relative path
    let repo_root_canonical =
        std::fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let relative = resolved
        .strip_prefix(&repo_root_canonical)
        .unwrap_or(&resolved);

    // Convert to forward-slash string
    let mut key = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/");

    // Step 6: Case-fold on case-insensitive platforms
    if is_case_insensitive() {
        key = key.to_lowercase();
    }

    key
}

/// Normalize path components without filesystem access.
/// Collapses `.` and `..` lexically.
pub(crate) fn normalize_components(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {} // skip "."
            Component::ParentDir => {
                // Pop last normal component; keep prefix/root
                if matches!(components.last(), Some(Component::Normal(_))) {
                    components.pop();
                } else {
                    components.push(component);
                }
            }
            _ => components.push(component),
        }
    }
    components.iter().collect()
}

/// Platform-default case sensitivity detection.
///
/// v1 simplification: macOS and Windows are case-insensitive,
/// Linux is case-sensitive. Per-volume detection deferred to v2.
pub(crate) fn is_case_insensitive() -> bool {
    cfg!(target_os = "macos") || cfg!(target_os = "windows")
}

/// Compute a SHA-256 hash of the canonical file key for cross-reference stability.
///
/// Allows correlating events even after file renames.
pub fn canonical_subject_hash(canonical_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_key.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ─────────────────────────────────────────────
// UUIDv7 generation
// ─────────────────────────────────────────────

/// Generate a UUIDv7 (time-ordered) string.
///
/// UUIDv7 encodes millisecond-precision Unix time in the high bits,
/// producing lexicographically sortable IDs that cluster temporally.
fn uuid7_string() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Current time as Unix milliseconds.
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ─────────────────────────────────────────────
// Event Writer
// ─────────────────────────────────────────────

/// The enforcement event writer. Ties together sequence allocation,
/// hash chaining, and store persistence into a single write path.
///
/// One writer per store lifetime. Not Clone — the seq counter and
/// prev_hash chain are stateful.
pub struct EnforcementEventWriter {
    seq: SeqAllocator,
    installation_id: String,
    prev_hash: String,
    /// Agent session (Claude Code `session_id`) to attribute written events to,
    /// for per-actor audit (schema_version 2). `None` unless set before `write`.
    pub(super) agent_session: Option<String>,
}

impl EnforcementEventWriter {
    /// Initialize the writer from store state.
    ///
    /// Loads the current seq counter, installation_id, and the hash of
    /// the last event in the stream (for chain continuity).
    pub async fn new(store: &Store) -> Result<Self> {
        let seq = SeqAllocator::load(store).await;
        let installation_id = get_or_create_installation_id(store).await?;
        let prev_hash = Self::load_last_hash(store).await;

        Ok(Self {
            seq,
            installation_id,
            prev_hash,
            agent_session: None,
        })
    }

    /// Load the hash of the most recent enforcement event.
    ///
    /// Scans for the highest seq_no enforcement event and returns its
    /// event_hash. Returns empty string if no events exist (first event).
    async fn load_last_hash(store: &Store) -> String {
        // The last event key is "enforcement:event:{seq_no}" with zero-padded seq.
        // Scan all event keys and find the highest.
        let keys = match store.scan_keys(EVENT_PREFIX).await {
            Ok(k) => k,
            Err(_) => return String::new(),
        };

        if keys.is_empty() {
            return String::new();
        }

        // Find the key with the highest seq_no
        let last_key = keys
            .iter()
            .max_by_key(|k| {
                k.strip_prefix(EVENT_PREFIX)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
            })
            .cloned();

        if let Some(key) = last_key {
            if let Ok(Some(bytes)) = store.get_raw_bytes(&key).await {
                if let Ok(event) = serde_json::from_slice::<EnforcementEvent>(&bytes) {
                    return event.event_hash;
                }
            }
        }

        String::new()
    }

    /// Write an enforcement event to the store.
    ///
    /// Allocates a seq_no (persisted before event write), computes the
    /// hash chain, and writes the event as JSON under `enforcement:event:{seq_no}`.
    ///
    /// Returns the written event (with computed hashes) or an error.
    #[allow(clippy::too_many_arguments)]
    pub async fn write(
        &mut self,
        store: &Store,
        event_type: EnforcementEventType,
        subject_kind: SubjectKind,
        subject_key: String,
        agent_type: String,
        receipt_id: Option<String>,
        decision_reason_code: String,
        decision_basis_hash: Option<String>,
    ) -> Result<EnforcementEvent> {
        let seq_no = self.seq.next(store).await?;

        let canonical_subject_hash_value = if subject_kind == SubjectKind::File {
            Some(canonical_subject_hash(&subject_key))
        } else {
            None
        };

        let mut event = EnforcementEvent {
            event_id: uuid7_string(),
            schema_version: SCHEMA_VERSION,
            seq_no,
            recorded_at_ms: now_ms(),
            event_type,
            event_hash: String::new(), // computed below
            prev_hash: self.prev_hash.clone(),
            installation_id: self.installation_id.clone(),
            actor_local: get_local_actor(),
            agent_type,
            subject_kind,
            subject_key,
            canonical_subject_hash: canonical_subject_hash_value,
            receipt_id,
            decision_reason_code,
            decision_basis_hash,
            agent_session: self.agent_session.clone(),
        };

        // Compute and set the event hash
        event.event_hash = event.compute_hash();

        // Write to store — zero-padded seq for lexicographic ordering
        let key = format!("{EVENT_PREFIX}{:020}", seq_no);
        let json = serde_json::to_vec(&event)?;
        store.put_raw(&key, &json).await?;

        // Update prev_hash for the next event in this writer's lifetime
        self.prev_hash = event.event_hash.clone();

        Ok(event)
    }

    /// Return the current installation ID.
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// Return the current sequence number (last allocated).
    pub fn current_seq(&self) -> u64 {
        self.seq.current()
    }

    /// Return the hash of the last written event.
    pub fn prev_hash(&self) -> &str {
        &self.prev_hash
    }

    /// Detect gaps in the event stream and emit a RecordingGap event.
    ///
    /// Called on writer initialization when the seq counter is ahead of
    /// the last stored event (indicating a crash between seq allocation
    /// and event write).
    pub async fn detect_and_record_gap(
        &mut self,
        store: &Store,
        gap_start_ms: u64,
        gap_end_ms: u64,
        cause: GapCause,
    ) -> Result<EnforcementEvent> {
        self.write(
            store,
            EnforcementEventType::RecordingGap {
                gap_start_ms,
                gap_end_ms,
                cause,
                enforcement_mode_during_gap: EnforcementMode::Advisory,
                missed_event_count: MissedEventCount::Unknown,
                certainty: GapCertainty::Inferred,
            },
            SubjectKind::System,
            "enforcement:stream".to_string(),
            "system".to_string(),
            None,
            "recording_gap_detected".to_string(),
            None,
        )
        .await
    }
}

// ─────────────────────────────────────────────
// Store scan helpers
// ─────────────────────────────────────────────

/// Read enforcement events within a seq_no range [since, until] inclusive.
///
/// Returns events in seq_no order. Events outside the range or with
/// corrupt JSON are skipped with a warning.
pub async fn scan_enforcement_events(
    store: &Store,
    since_seq: u64,
    until_seq: u64,
) -> Result<Vec<EnforcementEvent>> {
    let keys = store.scan_keys(EVENT_PREFIX).await?;
    let mut events = Vec::new();

    let start = keys.partition_point(|key| {
        key.strip_prefix(EVENT_PREFIX)
            .and_then(|s| s.parse::<u64>().ok())
            .map(|seq| seq < since_seq)
            .unwrap_or(true)
    });
    for key in keys.iter().skip(start) {
        let seq = match key
            .strip_prefix(EVENT_PREFIX)
            .and_then(|s| s.parse::<u64>().ok())
        {
            Some(s) => s,
            None => continue,
        };
        if seq > until_seq {
            break;
        }
        if seq < since_seq {
            continue;
        }
        if let Ok(Some(bytes)) = store.get_raw_bytes(key).await {
            match serde_json::from_slice::<EnforcementEvent>(&bytes) {
                Ok(event) => events.push(event),
                Err(e) => {
                    tracing::warn!(key, "skipping corrupt enforcement event: {e}");
                }
            }
        }
    }

    events.sort_by_key(|e| e.seq_no);
    Ok(events)
}

/// Result of a time-bounded enforcement scan. The oldest timestamp is kept
/// separate so callers can distinguish an empty retained window from history
/// that predates the retention floor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementEventScan {
    pub events: Vec<EnforcementEvent>,
    pub oldest_recorded_at_ms: Option<u64>,
    pub scanned_keys: usize,
}

/// Scan events from the first sequence whose recorded time reaches `since_ms`.
/// Event keys are zero-padded and sequence allocation is monotonic, so the
/// timestamp boundary is found with O(log n) raw reads and the matching suffix
/// is read forward. This keeps an activity report from loading a year's event
/// payloads just to discard them.
pub async fn scan_enforcement_events_since_ms(
    store: &Store,
    since_ms: u64,
    until_ms: u64,
) -> Result<EnforcementEventScan> {
    let keys = store.scan_keys(EVENT_PREFIX).await?;
    let valid_keys: Vec<&String> = keys
        .iter()
        .filter(|key| {
            key.strip_prefix(EVENT_PREFIX)
                .and_then(|s| s.parse::<u64>().ok())
                .is_some()
        })
        .collect();

    async fn read_event(store: &Store, key: &str) -> Option<EnforcementEvent> {
        let bytes = store.get_raw_bytes(key).await.ok()??;
        serde_json::from_slice(&bytes).ok()
    }

    let oldest_recorded_at_ms = match valid_keys.first() {
        Some(key) => read_event(store, key)
            .await
            .map(|event| event.recorded_at_ms),
        None => None,
    };

    let mut low = 0;
    let mut high = valid_keys.len();
    while low < high {
        let mid = low + (high - low) / 2;
        match read_event(store, valid_keys[mid]).await {
            Some(event) if event.recorded_at_ms < since_ms => low = mid + 1,
            Some(_) => high = mid,
            None => low = mid + 1,
        }
    }

    let mut events = Vec::new();
    let mut scanned_keys = 0;
    for key in valid_keys.into_iter().skip(low) {
        scanned_keys += 1;
        let Some(event) = read_event(store, key).await else {
            continue;
        };
        if event.recorded_at_ms > until_ms {
            break;
        }
        if event.recorded_at_ms >= since_ms {
            events.push(event);
        }
    }
    events.sort_by_key(|event| event.seq_no);
    Ok(EnforcementEventScan {
        events,
        oldest_recorded_at_ms,
        scanned_keys,
    })
}

// ─────────────────────────────────────────────
// Enforcement Mode
