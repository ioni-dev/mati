//! Core data types for the mati knowledge store.
//!
//! All types in this module are the canonical definitions used throughout
//! every layer of mati (storage, graph, search, MCP, CLI). Do not redefine
//! these elsewhere — import from `mati_core::store`.
//!
//! Key namespacing convention:
//! ```text
//! gotcha:<slug>          file:<path>          decision:<slug>
//! stage:current          dep:<ecosystem>:<name> dev_note:<slug>
//! session:<timestamp>    analytics:<type>_<date>  policy:<slug>
//! graph:edge:<from>:<kind>:<to>
//! ```
//!
//! # Float equality note
//!
//! Structs containing `f32` score fields (`QualityScore`, `StalenessScore`,
//! `ConfidenceScore`, and anything that embeds them) intentionally do **not**
//! derive `PartialEq`. Floating-point arithmetic produces values that are
//! semantically equal but bitwise distinct, making derived `==` a footgun for
//! computed scores. Use field-level epsilon comparison in tests and comparators.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

// ─────────────────────────────────────────────
// Primitive aliases
// ─────────────────────────────────────────────

/// UUID v7 generated once on first use, persisted at `~/.mati/device_id`
/// (`store::device::stable_device_id`). Stamps every record write for
/// Lamport-clock conflict resolution.
///
/// Requires the `uuid` crate with `features = ["v4", "v7"]`.
/// NOTE: records written by pre-device-id binaries carry per-record v4
/// placeholders — the v0.2 `MergeEngine` must treat those as
/// attribution-unknown, not as distinct devices.
pub type DeviceId = Uuid;

// ─────────────────────────────────────────────
// Enums — record metadata
// ─────────────────────────────────────────────

/// Which layer of mati produced this record.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecordSource {
    /// tree-sitter, git, dep parsing — Layer 0
    StaticAnalysis,
    /// `mati enrich` batch — Layer 1
    ClaudeEnrich,
    /// session-end harvest — Layer 2
    SessionHook,
    /// `mati gotcha add` / `mati note`
    DeveloperManual,
    /// `mati import` (CLAUDE.md or JSON)
    Import,
}

/// Which agent issued a daemon request, used for attribution in
/// `MutationEvent` and `Record.created_by` / `Record.last_modified_by`.
///
/// Client-declared, not server-verified — same-UID processes are trusted
/// (THREAT_MODEL.md section 3.C, section 3.I; ADR-018). The daemon stamps `pid` from
/// `SO_PEERCRED` separately; this enum is the human/tool side of attribution.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    /// MCP stdio client (Claude Code's rmcp transport).
    Claude,
    /// Codex hooks (`codex-*` variants).
    Codex,
    /// Direct CLI invocation by the developer.
    Cli,
    /// Daemon-internal operations (e.g. repair on startup, periodic
    /// reparse). Stamped server-side, never client-declared.
    Supervisor,
    /// Attribution unknown or pre-v2 record.
    Unknown,
}

/// Semantic category of a record. Determines key prefix and injection behaviour.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Gotcha,
    File,
    Decision,
    Stage,
    Dependency,
    DevNote,
    Session,
    Analytics,
    Policy,
}

/// Severity / importance ranking.
///
/// Derived `Ord`: `Low(0) < Normal(1) < High(2) < Critical(3)`.
///
/// **Do not reorder variants.** The derived ordering depends on declaration
/// position. Reordering silently inverts all priority comparisons.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Low,
    Normal,
    High,
    Critical,
}

// ─────────────────────────────────────────────
// Quality scoring
// ─────────────────────────────────────────────

/// Computed tier from `QualityScore::value` (half-open intervals):
///
/// ```text
/// Suppressed  [0.0, 0.2)   never injected — worse than nothing
/// Poor        [0.2, 0.4)   injected with "[mati] LOW QUALITY — verify"
/// Acceptable  [0.4, 0.7)   injected normally
/// Good        [0.7, 0.9)   prioritised in bootstrap
/// Excellent   [0.9, 1.0]   used as template in `mati garden`
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QualityTier {
    Suppressed,
    Poor,
    Acceptable,
    Good,
    Excellent,
}

/// Individual signals that raise or lower the computed quality score.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QualitySignal {
    // ── Positive ────────────────────────────
    HasImperativeVerb,
    HasCausality,
    HasSeveritySet,
    HasReference,
    RuleLengthAdequate,
    ReasonLengthAdequate,
    AffectedFilesSpecified,
    HasSpecificIdentifier,
    // ── Negative (penalties) ────────────────
    VaguePhrasing,
    NoActionableRule,
    NoReason,
    TooShort,
    DuplicatesFilePurpose,
}

/// Composite quality score for a [`Record`].
///
/// Formula (ARCHITECTURE.md section 5):
/// ```text
/// quality =
///   has_imperative_verb  × 0.20
///   + has_causality      × 0.25
///   + has_severity       × 0.10
///   + has_reference      × 0.15
///   + length_score       × 0.15
///   + specificity_score  × 0.15
///
/// penalties:
///   vague_phrase_detected → × 0.5
///   no_reason             → × 0.6
///   too_short             → × 0.4
/// ```
/// Layer 0 `StaticAnalysis` records default to `0.10` (Suppressed).
/// Recomputed by `RecordQualityAnalyzer` on every write and `mati enrich`.
///
/// Does **not** derive `PartialEq` — see module-level float equality note.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QualityScore {
    /// 0.0 (useless) → 1.0 (Claude-optimal)
    pub value: f32,
    pub tier: QualityTier,
    pub signals: Vec<QualitySignal>,
    /// Unix timestamp (seconds) when this score was last computed.
    /// `0` = not yet computed (sentinel).
    pub computed_at: u64,
}

impl QualityScore {
    /// Default for a Layer 0 `StaticAnalysis` stub — Suppressed, never injected.
    pub fn layer0_default() -> Self {
        Self {
            value: 0.10,
            tier: QualityTier::Suppressed,
            signals: vec![],
            computed_at: 0,
        }
    }

    /// Quality for a file record whose purpose was extracted from a language-
    /// canonical doc comment (Rust `//!`, Go `// Package`, Python docstring).
    ///
    /// `Acceptable` tier (0.40) passes the `quality >= 0.4` injection gate.
    /// Paired with `confidence = 0.45` in `init.rs`, these records surface as
    /// `additionalContext` (allow + attach) rather than deny + inject.
    pub fn doc_comment_default() -> Self {
        Self {
            value: 0.40,
            tier: QualityTier::Acceptable,
            signals: vec![],
            computed_at: 0,
        }
    }

    /// Quality for an auto-generated co-change gotcha (normal signal).
    ///
    /// `Acceptable` tier (0.40): passes quality gate.
    /// Paired with `confidence = 0.45` (0.3–0.6 band) → additionalContext injection.
    /// `confirmed: true` is set on the gotcha because co-change is objective git data,
    /// but the confidence band keeps it out of the deny+inject path.
    /// Quality for a developer-manually-added record (`mati gotcha add`, `mati note`).
    ///
    /// `Good` tier (0.65): developer is explicitly asserting the record is important.
    /// Paired with `DeveloperManual` confidence (0.80) + `confirmed=true` → deny+inject path.
    pub fn developer_entry_default() -> Self {
        Self {
            value: 0.65,
            tier: QualityTier::Good,
            signals: vec![],
            computed_at: 0,
        }
    }

    pub fn cochange_default() -> Self {
        Self {
            value: 0.40,
            tier: QualityTier::Acceptable,
            signals: vec![],
            computed_at: 0,
        }
    }

    /// Quality for a strong co-change gotcha (ratio >= 0.90 AND count >= 20).
    ///
    /// `Acceptable` tier (0.60): passes quality gate.
    /// Paired with `confidence = 0.65` → deny+inject path.
    /// A near-perfect co-change ratio over 20+ commits is strong enough evidence
    /// that Claude should be forced to see the coupling before editing either file.
    pub fn cochange_strong() -> Self {
        Self {
            value: 0.60,
            tier: QualityTier::Acceptable,
            signals: vec![],
            computed_at: 0,
        }
    }

    /// Derive `QualityTier` from a raw score value (half-open intervals).
    ///
    /// ```text
    /// [0.0, 0.2) → Suppressed
    /// [0.2, 0.4) → Poor
    /// [0.4, 0.7) → Acceptable
    /// [0.7, 0.9) → Good
    /// [0.9, 1.0] → Excellent
    /// ```
    pub fn tier_from_value(value: f32) -> QualityTier {
        // Non-finite values (NaN, ±∞) would pass all comparisons silently
        // and land in the else-Excellent branch — a hook-injection security bug.
        if !value.is_finite() || value < 0.2 {
            QualityTier::Suppressed
        } else if value < 0.4 {
            QualityTier::Poor
        } else if value < 0.7 {
            QualityTier::Acceptable
        } else if value < 0.9 {
            QualityTier::Good
        } else {
            QualityTier::Excellent
        }
    }
}

// ─────────────────────────────────────────────
// Staleness scoring
// ─────────────────────────────────────────────

/// Staleness tier — determines injection behaviour, not enforcement.
///
/// At `Liability` and `Tombstone`, the file record's own content is degraded
/// or excluded from injection entirely — trusting a wrong record silently is
/// a worse failure mode than a cache miss (ARCHITECTURE.md section 17). A
/// confirmed gotcha still denies at either tier: `hooks::decide::evaluate`
/// runs the gotcha loop before it ever checks the tier (section 10.1). The
/// one unconditional pass-through is the literal `FileDeleted` signal, not
/// the tier by itself.
///
/// Sync merge rule: `Tombstone > Liability > Stale > Aging > Fresh`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StalenessTier {
    Fresh,
    Aging,
    Stale,
    /// Injection degrades to a read-the-file warning. Enforcement unaffected.
    Liability,
    /// Injection fully excluded. Enforcement unaffected unless the record
    /// also carries a `FileDeleted` signal.
    Tombstone,
}

/// Individual signals that feed the staleness composite score.
///
/// Derives `PartialEq` (not `Eq`) because `LinesChangedPct(f32)` contains f32.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StalenessSignal {
    NotAccessedDays(u32),
    /// Percentage of lines changed since last confirmation (0.0–1.0).
    LinesChangedPct(f32),
    EntryPointsChanged(u32),
    ImportsChanged(u32),
    FileDeleted,
    FileRenamed {
        new_path: String,
    },
    DependencyBumped {
        dep: String,
        old_ver: String,
        new_ver: String,
    },
    LinkedFileChanged {
        path: String,
    },
    /// Another decision or gotcha this record depends on was modified.
    CascadeFromDecision(String),
    /// TODOs were added, removed, or changed.
    TodosChanged,
    /// Net change in `unsafe` block count (positive = added, negative = removed).
    UnsafeCountChanged(i32),
    /// Net change in `.unwrap()` call count (positive = added, negative = removed).
    UnwrapCountChanged(i32),
    /// Number of commits touching this file since last staleness confirmation.
    GitCommitsSince(u32),
}

impl std::fmt::Display for StalenessSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAccessedDays(d) => write!(f, "not accessed for {d} days"),
            Self::LinesChangedPct(pct) => write!(f, "{:.0}% of lines changed", pct * 100.0),
            Self::EntryPointsChanged(n) => write!(f, "{n} entry points changed"),
            Self::ImportsChanged(n) => write!(f, "{n} imports changed"),
            Self::FileDeleted => write!(f, "source file deleted"),
            Self::FileRenamed { new_path } => write!(f, "file renamed to {new_path}"),
            Self::DependencyBumped {
                dep,
                old_ver,
                new_ver,
            } => write!(f, "{dep} bumped {old_ver} \u{2192} {new_ver}"),
            Self::LinkedFileChanged { path } => write!(f, "linked file {path} changed"),
            Self::CascadeFromDecision(key) => write!(f, "cascaded from {key}"),
            Self::TodosChanged => write!(f, "TODOs changed"),
            Self::UnsafeCountChanged(delta) => write!(f, "unsafe count changed by {delta}"),
            Self::UnwrapCountChanged(delta) => write!(f, "unwrap count changed by {delta}"),
            Self::GitCommitsSince(n) => write!(f, "{n} commits since last confirmation"),
        }
    }
}

/// Replaces the flat `stale: bool` with a scored, tiered system.
///
/// Formula (ARCHITECTURE.md section 17):
/// ```text
/// staleness =
///   time_factor       × 0.20
///   + git_factor      × 0.35
///   + semantic_factor × 0.25
///   + dep_factor      × 0.10
///   + cascade_factor  × 0.10
/// ```
/// Hard overrides:
/// - `FileDeleted`  → `Tombstone` (1.0)
/// - `FileRenamed`  → `Liability` (0.85) until path is corrected
///
/// Does **not** derive `PartialEq` — see module-level float equality note.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StalenessScore {
    /// 0.0 (completely fresh) → 1.0 (tombstone)
    pub value: f32,
    pub tier: StalenessTier,
    pub signals: Vec<StalenessSignal>,
    /// Unix timestamp (seconds) when this score was last computed.
    /// `0` = not yet computed (sentinel).
    pub computed_at: u64,
    /// Git SHA of the source file at the time this record was last confirmed.
    /// Empty string = not yet established.
    pub last_record_sha: String,
}

impl StalenessScore {
    /// Fresh record with no signals — used when a record is first created.
    pub fn fresh() -> Self {
        Self {
            value: 0.0,
            tier: StalenessTier::Fresh,
            signals: vec![],
            computed_at: 0,
            last_record_sha: String::new(),
        }
    }

    /// Derive `StalenessTier` from a raw score value (half-open intervals).
    ///
    /// ```text
    /// [0.0, 0.2) → Fresh
    /// [0.2, 0.4) → Aging
    /// [0.4, 0.7) → Stale
    /// [0.7, 0.9) → Liability
    /// [0.9, 1.0] → Tombstone
    /// ```
    pub fn tier_from_value(value: f32) -> StalenessTier {
        if !value.is_finite() {
            return StalenessTier::Stale;
        }
        if value < 0.2 {
            StalenessTier::Fresh
        } else if value < 0.4 {
            StalenessTier::Aging
        } else if value < 0.7 {
            StalenessTier::Stale
        } else if value < 0.9 {
            StalenessTier::Liability
        } else {
            StalenessTier::Tombstone
        }
    }
}

// ─────────────────────────────────────────────
// Confidence scoring
// ─────────────────────────────────────────────

/// How much the system trusts this record's accuracy.
///
/// Formula (ARCHITECTURE.md section 13.1):
/// ```text
/// base_score:
///   DeveloperManual → 0.80
///   Import          → 0.70
///   ClaudeEnrich    → 0.60
///   SessionHook     → 0.50
///   StaticAnalysis  → 0.10
///
/// confidence = base_score
///   × log2(confirmation_count + 2)
///   × contributor_factor              1.0 solo, +0.1 per extra, capped at 3
///   × recency_weight(last_accessed)   90-day half-life
///   × ref_boost                       1.5× if ref_url set
/// ```
/// `health::confidence::recompute` implements this and currently has no
/// callers — every stored value comes from `for_new_record`. Wiring it into
/// `mem_get` is planned, not done.
///
/// Hook injection thresholds:
/// ```text
/// >= 0.6 + confirmed  → deny file read, inject record
/// 0.3 – 0.6           → allow read + attach as additionalContext
/// < 0.3               → allow read, no injection
/// ```
///
/// Does **not** derive `PartialEq` — see module-level float equality note.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfidenceScore {
    /// 0.0 → 1.0
    pub value: f32,
    /// How many times this record has been explicitly confirmed correct.
    pub confirmation_count: u32,
    /// How many distinct contributors have written or confirmed this record.
    pub contributor_count: u32,
    /// Unix timestamp of the last time this record was challenged or disputed.
    pub last_challenged: Option<u64>,
    pub challenge_count: u32,
}

impl ConfidenceScore {
    /// Initial confidence value for a freshly created record by source type.
    pub fn base_for_source(source: &RecordSource) -> f32 {
        match source {
            RecordSource::DeveloperManual => 0.80,
            RecordSource::Import => 0.70,
            RecordSource::ClaudeEnrich => 0.60,
            RecordSource::SessionHook => 0.50,
            RecordSource::StaticAnalysis => 0.10,
        }
    }

    /// Construct a [`ConfidenceScore`] for a newly created record.
    ///
    /// Sets `value` from `base_for_source` and zeros all counters. Use this
    /// instead of constructing manually to prevent `value` from diverging from
    /// the source-derived base.
    pub fn for_new_record(source: &RecordSource) -> Self {
        Self {
            value: Self::base_for_source(source),
            confirmation_count: 0,
            contributor_count: 1,
            last_challenged: None,
            challenge_count: 0,
        }
    }
}

// ─────────────────────────────────────────────
// Record lifecycle
// ─────────────────────────────────────────────

/// Why a record was tombstoned.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TombstoneReason {
    FileDeleted,
    FileRenamed {
        new_path: String,
    },
    ManualDeletion,
    Superseded,
    /// Retired by a schema migration, not by anyone's decision.
    MigrationRepair,
}

/// Current lifecycle state of a record.
///
/// Sync merge rule: `Tombstoned > Superseded > Active` (severity wins).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecordLifecycle {
    Active,
    Tombstoned { reason: TombstoneReason, at: u64 },
    Superseded { by_key: String },
}

// ─────────────────────────────────────────────
// Sync / versioning
// ─────────────────────────────────────────────

/// Lamport clock + wall clock per record write.
///
/// Wall clock is **never** used for conflict ordering — only for display.
/// All ordering uses `logical_clock` (see ARCHITECTURE.md section 20).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RecordVersion {
    /// UUID v7, generated once per device at `mati init`.
    pub device_id: DeviceId,
    /// Lamport clock — incremented on every local write.
    pub logical_clock: u64,
    /// Wall clock at time of write — display only, never for conflict ordering.
    pub wall_clock: u64,
}

// ─────────────────────────────────────────────
// Universal record
// ─────────────────────────────────────────────

/// The universal store entry. All categories (gotcha, file, decision, …)
/// share this struct. Category-specific detail is in `value` (human-readable)
/// and in the typed `FileRecord` / `GotchaRecord` for Layer 0/1 fast paths.
///
/// Does **not** derive `PartialEq` — see module-level float equality note.
///
/// Key namespacing:
/// ```text
/// gotcha:<slug>     file:<path>     decision:<slug>
/// stage:current     dep:<ecosystem>:<name> dev_note:<slug>
/// ```
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Record {
    /// Namespaced key — primary storage identifier and graph node key.
    pub key: String,
    /// Human-readable content: purpose (file), rule (gotcha), body (decision).
    /// Indexed by tantivy for full-text search.
    pub value: String,
    pub category: Category,
    pub priority: Priority,
    /// Free-form tags for search and filtering.
    pub tags: Vec<String>,
    /// Unix timestamp (seconds) when this record was first created.
    pub created_at: u64,
    /// Unix timestamp (seconds) of the last write.
    pub updated_at: u64,
    /// URL to a PR, issue, doc, or incident that explains this record.
    pub ref_url: Option<String>,
    pub staleness: StalenessScore,
    pub lifecycle: RecordLifecycle,
    /// Versioning for Lamport-clock conflict resolution (see [`RecordVersion`]).
    /// Use `record.version.device_id` to identify the authoring device.
    pub version: RecordVersion,
    pub quality: QualityScore,
    /// How many times this record has been read via `mem_get` or hooks.
    pub access_count: u32,
    /// Unix timestamp (seconds) of the last access.
    pub last_accessed: u64,
    pub source: RecordSource,
    pub confidence: ConfidenceScore,
    /// Pre-computed gap risk score: `change_frequency × (1 - coverage_score)`.
    pub gap_analysis_score: f32,
    /// Structured per-category payload — typed data in JSON form.
    ///
    /// - `file:*`     → `FileRecord`
    /// - `gotcha:*`   → `GotchaRecord`
    /// - `decision:*` → serialized decision body (TBD Layer 1)
    /// - `analytics:*`, `session:*` → arbitrary JSON blob (DailyAgg, StaleReviewPayload, …)
    ///
    /// `value` is always the human-readable text: rule, purpose, body.
    /// `payload` carries all structured fields so read sites never parse `value` as JSON.
    /// Stored as-is in MessagePack (serde_json::Value → msgpack map).
    #[serde(default)]
    pub payload: Option<JsonValue>,
}

impl Record {
    /// The device that last wrote this record.
    ///
    /// Convenience accessor — delegates to `self.version.device_id`.
    pub fn device_id(&self) -> DeviceId {
        self.version.device_id
    }

    /// Deserialize the structured payload into a typed value.
    ///
    /// Returns `None` when `payload` is absent or the JSON shape does not match `T`.
    /// Always prefer this over `serde_json::from_str(&self.value)`.
    pub fn payload_as<T: serde::de::DeserializeOwned>(&self) -> Option<T> {
        self.payload
            .as_ref()
            .and_then(|p| serde_json::from_value(p.clone()).ok())
    }

    /// Construct a layer-0 file stub for `file:<path>`.
    ///
    /// This is the persisted companion to [`FileRecord::layer0_stub`].
    /// Layer 0 file records start empty on purpose/value, but still get the
    /// suppressed quality default so they never surface in Claude-facing
    /// injection paths until enrichment raises them.
    pub fn layer0_file_stub(
        key: impl Into<String>,
        device_id: DeviceId,
        logical_clock: u64,
        wall_clock: u64,
    ) -> Self {
        Self {
            key: key.into(),
            value: String::new(),
            category: Category::File,
            priority: Priority::Normal,
            tags: vec![],
            created_at: wall_clock,
            updated_at: wall_clock,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id,
                logical_clock,
                wall_clock,
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
}

// ─────────────────────────────────────────────
// File record
// ─────────────────────────────────────────────

/// Kind of inline developer comment extracted by tree-sitter.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TodoKind {
    Todo,
    Fixme,
    Hack,
    Note,
    Deprecated,
}

/// A TODO/FIXME/HACK comment extracted from source code by tree-sitter.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TodoComment {
    pub text: String,
    pub line: u32,
    pub kind: TodoKind,
}

/// Per-file knowledge — stored under `file:<path>`, linked to `gotcha:*`
/// and `decision:*` via graph edges.
///
/// Does **not** derive `PartialEq` — contains `token_cost_estimate` which
/// may be computed and is not meaningful to compare directly.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileRecord {
    pub path: String,
    /// One-sentence purpose extracted by Layer 1 enrichment. Empty at Layer 0.
    pub purpose: String,
    /// Public functions / types / entry points visible from other modules.
    pub entry_points: Vec<String>,
    /// Import / use paths found by tree-sitter.
    pub imports: Vec<String>,
    /// Keys of associated `gotcha:*` records.
    pub gotcha_keys: Vec<String>,
    /// Keys of associated `decision:*` records.
    pub decision_keys: Vec<String>,
    pub todos: Vec<TodoComment>,
    pub unsafe_count: u32,
    pub unwrap_count: u32,
    /// Commit count touching this file (from git2, capped at 5 000 most recent non-merge commits).
    pub change_frequency: u32,
    pub last_author: Option<String>,
    /// True when `change_frequency` puts this file in the top 10% of the repo.
    pub is_hotspot: bool,
    /// Rough token count estimate for `mem_bootstrap` budget enforcement.
    pub token_cost_estimate: u32,
    /// Session timestamp of the last time this record was updated.
    pub last_modified_session: u64,
    /// SHA-256 hex digest of file content at the time of last Layer 0 scan.
    /// `None` for non-parseable files or the first scan (no stored baseline).
    #[serde(default)]
    pub content_hash: Option<String>,
    /// Newline count at last scan (≈ line count). 0 for non-parseable files.
    #[serde(default)]
    pub line_count: u32,
    /// Blast radius — how many files depend on this one (direct + transitive).
    /// Computed during `mati init` Phase 10a from Imports edges in the graph.
    /// `None` for stores created before blast radius was introduced.
    #[serde(default)]
    pub blast_radius: Option<crate::analysis::blast_radius::BlastRadius>,
    /// Staleness inherited from upstream stale sources via Imports edges.
    /// `None` for stores created before staleness propagation was introduced.
    #[serde(default)]
    pub propagated_staleness: Option<crate::analysis::propagation::PropagatedStaleness>,
}

impl FileRecord {
    /// Construct a layer-0 file stub from static-analysis signals.
    ///
    /// `purpose`, `gotcha_keys`, and `decision_keys` intentionally start empty.
    /// The Layer 0 pipeline only records structural facts; enrichment fills in
    /// the human-readable purpose later.
    #[allow(clippy::too_many_arguments)]
    pub fn layer0_stub(
        path: impl Into<String>,
        entry_points: Vec<String>,
        imports: Vec<String>,
        todos: Vec<TodoComment>,
        unsafe_count: u32,
        unwrap_count: u32,
        change_frequency: u32,
        last_author: Option<String>,
        is_hotspot: bool,
        token_cost_estimate: u32,
        last_modified_session: u64,
    ) -> Self {
        Self {
            path: path.into(),
            purpose: String::new(),
            entry_points,
            imports,
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos,
            unsafe_count,
            unwrap_count,
            change_frequency,
            last_author,
            is_hotspot,
            token_cost_estimate,
            last_modified_session,
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
        }
    }
}

// ─────────────────────────────────────────────
// Gotcha record
// ─────────────────────────────────────────────

/// A confirmed (or candidate) gotcha — a non-obvious rule that Claude must
/// know before reading or editing the associated file(s).
///
/// `confirmed: false` = Layer 0 candidate stub. Never injected.
/// `confirmed: true` + `confidence >= 0.6` + `quality >= 0.4`
///   → pre-read hook denies the file read and injects this record instead.
///
/// Does **not** derive `PartialEq` — embedded via `Record` which carries scores.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GotchaRecord {
    /// The actionable rule. Must start with an imperative verb for Good quality.
    pub rule: String,
    /// Why this rule exists. Causality sentence.
    pub reason: String,
    pub severity: Priority,
    #[serde(default)]
    pub affected_files: Vec<String>,
    #[serde(default)]
    pub ref_url: Option<String>,
    /// Timestamp of the session in which this gotcha was first discovered.
    #[serde(default)]
    pub discovered_session: u64,
    /// Whether a developer has explicitly confirmed this record is accurate.
    /// Layer 0 stubs are always `false` until confirmed via `mati gotcha add`.
    #[serde(default)]
    pub confirmed: bool,
    /// SHA-256 digest of each affected file's content at the moment a human
    /// last confirmed this rule — `<path> → hex`, the same digest
    /// [`FileRecord::content_hash`] already carries. Written by the confirm
    /// paths only; nothing else re-stamps it.
    ///
    /// This is the baseline that *content drift* compares against: when a
    /// file's current hash differs from the one stamped here, the code the
    /// rule describes changed after the last human sign-off, so the rule may
    /// now be **wrong** rather than merely dusty. Purely informational — see
    /// [`crate::health::drift`]. It feeds no score, no tier, and no hook
    /// decision, deliberately: the read gate must keep denying on a drifted
    /// gotcha (ARCHITECTURE.md section 10.1).
    ///
    /// Keyed per file rather than as one combined digest so the report can
    /// name *which* file moved, and so an entry with no indexed hash (a glob
    /// like `src/payments/**`, an unparsed file, a path indexed before
    /// content hashing existed) is simply absent. An absent entry means
    /// "unknown", never "drifted" — which is also what a record confirmed
    /// before this field existed deserializes to.
    #[serde(default)]
    pub confirmed_content: BTreeMap<String, String>,
}

/// Declarative action predicate stored on a local policy.
///
/// This is the persisted shape consumed by the pure policy matcher.
///
/// Unknown fields are rejected: every field is optional and an absent one is a
/// wildcard, so a misspelled key would otherwise deserialize into an all-`None`
/// trigger that matches every governed action.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyTrigger {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_glob: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_path_glob: Option<String>,
    /// Glob matched against the normalized command tokens joined by single
    /// spaces (`action.argv`, after wrapper stripping and `sh -c` unwrap). The
    /// only predicate that can gate a pathless verb (`dd`, `terraform destroy`,
    /// `git reset --hard`). Lexical and best-effort: quoting, variable
    /// expansion, and aliases bypass it, so a block on it is a tripwire, never
    /// a guarantee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_glob: Option<String>,
}

/// A content predicate evaluated on the action itself, independent of any
/// consult gate — the engine's first unconditional deny.
///
/// Lexical tripwire in this phase, on either channel:
/// - `CommandGlob` matches `action.argv` joined by single spaces, so quoting,
///   `-f file.sql`, heredocs, env, and aliases all bypass it.
/// - `PathGlob` matches any member of `target_path ∪ files` — the same path set
///   the consult-axis `target_path_glob` trigger uses. It sees only the
///   requested path, never file contents or a diff.
///
/// A deny on either is a tripwire, never a guarantee.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionPredicate {
    /// Deny when `action.argv.join(" ")` matches this glob.
    CommandGlob(String),
    /// Deny when any of `target_path ∪ files` matches this glob.
    PathGlob(String),
}

impl ActionPredicate {
    /// Whether this predicate denies the action. Pure; a glob that fails to
    /// compile is treated as no-match so the enforcement path fails open (P9).
    /// `CommandGlob` reads `argv`; `PathGlob` reads `paths` (`target_path ∪
    /// files`). Each variant ignores the channel it does not govern.
    pub fn denies(&self, argv: &[String], paths: &[String]) -> bool {
        match self {
            ActionPredicate::CommandGlob(pattern) => globset::Glob::new(pattern)
                .ok()
                .map(|glob| glob.compile_matcher())
                .is_some_and(|matcher| matcher.is_match(argv.join(" "))),
            ActionPredicate::PathGlob(pattern) => globset::Glob::new(pattern)
                .ok()
                .map(|glob| glob.compile_matcher())
                .is_some_and(|matcher| paths.iter().any(|path| matcher.is_match(path))),
        }
    }
}

/// Outcome of a policy's `deny_if` content predicate against one action,
/// precomputed by the daemon so the hook side carries it verbatim. Kept off the
/// consult (`satisfied`) axis and never lowered by the schema-introspection
/// exemption.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContentOutcome {
    /// No `deny_if` predicate on this policy.
    #[default]
    None,
    /// `deny_if` present, but the action content did not match it. Suppresses
    /// the policy's generic trigger-steer — a content policy speaks only through
    /// its predicate.
    Inert,
    /// `deny_if` matched and the author set `steer` — warn only.
    Warn,
    /// `deny_if` matched and the author set `block` — deny.
    Deny,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    Steer,
    Block,
}

impl ActionPredicate {
    /// Classify an action against this predicate for the given mode, as a
    /// `deny_if` (denylist) rule: match → deny/warn, no match → inert.
    pub fn outcome(&self, argv: &[String], paths: &[String], mode: PolicyMode) -> ContentOutcome {
        if self.denies(argv, paths) {
            match mode {
                PolicyMode::Block => ContentOutcome::Deny,
                PolicyMode::Steer => ContentOutcome::Warn,
            }
        } else {
            ContentOutcome::Inert
        }
    }

    /// Classify an action against this predicate as a `require` (allowlist)
    /// rule — the polarity mirror of `outcome`: the requirement is MET when the
    /// predicate matches (inert), and MISSED when it does not (deny/warn). A
    /// `require: PathGlob("src/**")` therefore denies any action outside `src/`.
    pub fn require_outcome(
        &self,
        argv: &[String],
        paths: &[String],
        mode: PolicyMode,
    ) -> ContentOutcome {
        if self.denies(argv, paths) {
            ContentOutcome::Inert
        } else {
            match mode {
                PolicyMode::Block => ContentOutcome::Deny,
                PolicyMode::Steer => ContentOutcome::Warn,
            }
        }
    }
}

/// Rollout stage for a local policy.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStage {
    Off,
    Shadow,
    Enforce,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptSource {
    DbIntrospection,
    HookContext,
    MemGet,
    /// A watched command was observed running (Bash PreToolUse). Attests the
    /// command was ATTEMPTED, not that it succeeded — the mint fires before the
    /// exit status is known. Portable across Claude and Codex for that reason.
    CommandObserved,
    /// A source string this binary does not recognize — a receipt or policy
    /// written by a newer mati. Never accepted by any `via` check and never in
    /// `CODEX_PRODUCIBLE_SOURCES`, so an unknown source reads as "no receipt":
    /// the consult gate denies, which fails safe for a block policy. Never
    /// constructed locally, so it is never serialized back out.
    #[serde(other)]
    Unknown,
}

/// Receipt sources a Codex session can actually produce.
///
/// `DbIntrospection` is absent on purpose and is a platform limit, not a gap to
/// close: Codex's `PostToolUse` payload carries no exit status — its published
/// schema types `tool_response` as unconstrained and defines no status field —
/// so mati cannot tell a successful introspection from one that exited 127, and
/// deliberately does not mint. A block policy accepting only sources outside
/// this list can never be satisfied in a Codex session.
///
/// Both the hook-time degrade and the authoring-time warning read this, so the
/// two can never disagree about what Codex can attest to. Keep it in step with
/// the mint sites: `HookContext` belongs here because `fire_events` runs on the
/// Codex pre-bash and apply-patch paths, and `CommandObserved` belongs here
/// because its mint fires on the same Codex pre-bash path, BEFORE the exit
/// status Codex omits — "attempted" needs no exit status.
pub const CODEX_PRODUCIBLE_SOURCES: &[ReceiptSource] = &[
    ReceiptSource::MemGet,
    ReceiptSource::HookContext,
    ReceiptSource::CommandObserved,
];

/// Default consultation freshness. Mirrors the `mati policy add --requires`
/// clap default (`src/cli/policy.rs`); a `policy_requires_default_matches_cli`
/// test locks the two together so the CLI and `mem_set` authoring paths agree.
const DEFAULT_POLICY_TTL_SECS: u64 = 900;

fn default_policy_ttl_secs() -> u64 {
    DEFAULT_POLICY_TTL_SECS
}

fn default_policy_freshness() -> PolicyFreshness {
    PolicyFreshness {
        ttl_secs: DEFAULT_POLICY_TTL_SECS,
        fingerprint: false,
    }
}

/// The default `requires` for a policy authored without one. Empty key/via means
/// "no consultation gate" — the same inert default `mati policy add` writes.
fn default_policy_requires() -> PolicyRequires {
    PolicyRequires {
        key: String::new(),
        via: Vec::new(),
        freshness: default_policy_freshness(),
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PolicyFreshness {
    #[serde(default = "default_policy_ttl_secs")]
    pub ttl_secs: u64,
    #[serde(default)]
    pub fingerprint: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequires {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub via: Vec<ReceiptSource>,
    #[serde(default = "default_policy_freshness")]
    pub freshness: PolicyFreshness,
}

/// Binds an observed command to a receipt it mints. When a Bash PreToolUse
/// action's joined argv matches `on_command_glob`, mati writes
/// `session:consulted:<key>` with source [`ReceiptSource::CommandObserved`], so
/// a separate policy whose `requires.key` is that key is satisfied. The bridge
/// for workflow ordering ("run tests before you commit").
///
/// Attests ATTEMPTED, not passed: the mint fires before the command's exit
/// status is known. Author `on_command_glob` for a FULL-suite run
/// (`cargo nextest run`, not `cargo test one::case`) — a subset-run glob mints
/// on a single-test invocation and is the dominant false-satisfy source.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReceiptEmitter {
    pub on_command_glob: String,
    pub key: String,
}

/// A developer-authored local policy stored under `policy:<slug>`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PolicyRecord {
    pub name: String,
    pub rule: String,
    pub reason: String,
    pub scope: String,
    pub mode: PolicyMode,
    pub trigger: PolicyTrigger,
    /// Content restriction on the matched action, orthogonal to `requires`
    /// (consult). `None` for every policy authored before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_if: Option<ActionPredicate>,
    /// Polarity mirror of `deny_if`: deny UNLESS the predicate matches
    /// (allowlist / required content). `None` for every policy that does not
    /// use it. Evaluated after `deny_if` — a `deny_if` match wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require: Option<ActionPredicate>,
    #[serde(default = "default_policy_requires")]
    pub requires: PolicyRequires,
    /// When set, an observed command matching `on_command_glob` mints the named
    /// [`ReceiptSource::CommandObserved`] receipt. `None` for every policy that
    /// does not emit one. Orthogonal to this policy's own `requires`/`trigger`:
    /// a policy typically EITHER mints (the test-runner) OR requires (the
    /// commit gate), rarely both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mints: Option<ReceiptEmitter>,
    pub stage: PolicyStage,
    pub severity: Priority,
    pub created_by: String,
}

// ─────────────────────────────────────────────
// Stale review (M-13-C)
// ─────────────────────────────────────────────

/// A single entry in a stale-review session payload.
///
/// Surfaced to Claude via `mem_bootstrap` stale warnings section.
/// Stored inside `StaleReviewPayload` in `session:<ts>` records.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StaleReviewEntry {
    pub key: String,
    pub staleness_value: f32,
    pub tier: StalenessTier,
    pub last_updated: u64,
    pub signals: Vec<String>,
}

/// Payload written to `session:<ts>` after a stale-review pass.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StaleReviewPayload {
    pub session_timestamp: u64,
    pub entries: Vec<StaleReviewEntry>,
}

// ─────────────────────────────────────────────
// Knowledge gaps
// ─────────────────────────────────────────────

/// Classification of why a knowledge gap exists.
///
/// Computed by `KnowledgeGapAnalyzer` — async, post-session, non-blocking.
/// Gap severity formula: `change_frequency × (1 - coverage_score)`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GapType {
    /// Hot file with no record at all.
    HotFileNoRecord,
    /// Hot file has a record but `purpose` is empty.
    HotFileNoPurpose,
    /// Hot file has no associated `gotcha:*` records.
    HotFileNoGotchas,
    /// File read frequently by Claude but never enriched past Layer 0.
    FrequentlyReadNoEnrich,
    /// A `decision:*` record with no `affected_files`.
    OrphanedDecision,
    /// A `dep:*` record with no confirmed gotchas.
    DependencyUnknown,
    /// Two files co-change in >70% of commits but have no explicit graph edge.
    CoChangePairUnmapped,
    /// Hot file's record hasn't been updated since a significant refactor.
    StaleHotspot,
    /// Hotspot file with no corresponding test file detected in the repo.
    HotFileNoTests,
    /// File imported by many others but has no gotchas or decisions documented.
    HighFanInNoContract,
}

/// A detected knowledge gap with risk score and suggested resolution action.
///
/// Does **not** derive `PartialEq` — `risk_score` is a computed f32.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KnowledgeGap {
    /// Namespaced key of the file, dep, or decision with the gap.
    pub key: String,
    pub gap_type: GapType,
    /// Computed risk score: `change_frequency × (1 - coverage_score)`.
    pub risk_score: f32,
    pub description: String,
    /// Suggested `mati` CLI command to resolve the gap.
    pub action_hint: String,
}

// ─────────────────────────────────────────────
// Context packet (mem_bootstrap output)
// ─────────────────────────────────────────────

/// What `mem_bootstrap()` returns to Claude. Token-budgeted to 2,000 tokens.
///
/// Assembly order (ARCHITECTURE.md section 6):
/// 1. Resolve `context_files` to graph nodes
/// 2. Traverse `HasGotcha` edges — direct gotchas for each file
/// 3. Traverse `Imports` one hop — gotchas for imported files
/// 4. Traverse `AffectedBy` edges — relevant architectural decisions
/// 5. Token-budget the result to 2,000 tokens
/// 6. Sort gotchas by `confidence × severity`
///
/// The MCP tool returns `injection_string` as the top-level tool result text.
/// The full struct is used internally for structured rendering and debugging.
///
/// Does **not** derive `PartialEq` — transitively contains f32 score fields.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContextPacket {
    /// Current `stage:current` record, if set.
    pub stage: Option<Record>,
    /// Gotchas sorted by `confidence × severity`. Only `confirmed: true` records.
    /// Type is [`Record`] (not `GotchaRecord`) — the base record is the storage
    /// unit. `mem_bootstrap` callers must look up the typed detail via
    /// `mati_core::store::GotchaRecord` when the rule/reason fields are needed.
    pub critical_gotchas: Vec<Record>,
    /// File records for the requested context files.
    pub file_records: Vec<FileRecord>,
    /// Decision records reached via `AffectedBy` graph traversal.
    pub related_decisions: Vec<Record>,
    /// Plain-text summary of the last session (from `session-harvest`).
    pub recent_session: Option<String>,
    /// Estimated token count of this packet.
    pub token_estimate: u32,
    /// Human-readable staleness warnings for records approaching Liability tier.
    pub stale_warnings: Vec<String>,
    /// Keys of `confirmed: false` Layer 0 stubs surfaced for developer review.
    pub unconfirmed_candidates: Vec<String>,
    /// Top knowledge gaps ranked by risk score.
    pub knowledge_gaps: Vec<KnowledgeGap>,
    /// Compliance rate for the last 7 days. Present only when < 0.85.
    pub compliance_rate: Option<f32>,
    /// Pre-formatted markdown string returned as the MCP tool result text.
    pub injection_string: String,
}

// ─────────────────────────────────────────────
// Health / onboarding
// ─────────────────────────────────────────────

/// Onboarding time estimate based on current knowledge coverage.
///
/// Formula (ARCHITECTURE.md section 13.3):
/// ```text
/// base_time = 22 minutes
///
/// reduction_factors:
///   hotspot_coverage  × 0.40
///   gotcha_coverage   × 0.25
///   decision_coverage × 0.15
///   confidence_weight × 0.20
///
/// estimated_minutes = base_time × (1 - weighted_reduction)
/// ```
/// Stored as `analytics:onboarding_score` with `Durability::Eventual`.
///
/// Does **not** derive `PartialEq` — all fields are computed f32 values.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OnboardingScore {
    pub estimated_minutes: f32,
    /// Fraction of hotspot files with a non-empty purpose (0.0–1.0).
    pub critical_files_covered: f32,
    /// Fraction of hotspot files with ≥1 confirmed gotcha (0.0–1.0).
    pub gotcha_coverage: f32,
    /// Fraction of architectural decisions documented (0.0–1.0).
    pub decision_coverage: f32,
    /// Average confidence across all confirmed records.
    pub avg_confidence: f32,
    pub computed_at: u64,
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn device_id() -> DeviceId {
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    fn sample_record() -> Record {
        Record {
            key: "gotcha:inference-async".to_string(),
            value: "Never call .await inside a rayon::spawn closure — it panics.".to_string(),
            category: Category::Gotcha,
            priority: Priority::Critical,
            tags: vec!["async".to_string(), "rayon".to_string()],
            created_at: 1_710_520_800,
            updated_at: 1_710_520_800,
            ref_url: Some("https://github.com/example/issue/42".to_string()),
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: device_id(),
                logical_clock: 1,
                wall_clock: 1_710_520_800,
            },
            quality: QualityScore {
                value: 0.85,
                tier: QualityTier::Good,
                signals: vec![
                    QualitySignal::HasImperativeVerb,
                    QualitySignal::HasCausality,
                ],
                computed_at: 1_710_520_800,
            },
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
            gap_analysis_score: 0.0,
            payload: None,
        }
    }

    fn sample_file_record() -> FileRecord {
        FileRecord {
            path: "src/store/db.rs".to_string(),
            purpose: "Initialises SurrealKV trees and exposes the Store handle.".to_string(),
            entry_points: vec!["Store::open".to_string()],
            imports: vec!["surrealkv".to_string()],
            gotcha_keys: vec!["gotcha:inference-async".to_string()],
            decision_keys: vec![],
            todos: vec![TodoComment {
                text: "add fsync benchmark".to_string(),
                line: 42,
                kind: TodoKind::Todo,
            }],
            unsafe_count: 0,
            unwrap_count: 1,
            change_frequency: 12,
            last_author: Some("ioni".to_string()),
            is_hotspot: false,
            token_cost_estimate: 180,
            last_modified_session: 1_710_520_800,
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
        }
    }

    fn sample_context_packet() -> ContextPacket {
        ContextPacket {
            stage: None,
            critical_gotchas: vec![sample_record()],
            file_records: vec![sample_file_record()],
            related_decisions: vec![],
            recent_session: Some(
                "Implemented storage layer. SurrealKV tree opened cleanly.".to_string(),
            ),
            token_estimate: 420,
            stale_warnings: vec![],
            unconfirmed_candidates: vec!["file:src/analysis/walker.rs".to_string()],
            knowledge_gaps: vec![KnowledgeGap {
                key: "file:src/analysis/parser.rs".to_string(),
                gap_type: GapType::HotFileNoGotchas,
                risk_score: 0.72,
                description: "Hot file with 23 commits in 60d and no gotchas".to_string(),
                action_hint: "mati gotcha add src/analysis/parser.rs".to_string(),
            }],
            compliance_rate: None,
            injection_string: String::new(),
        }
    }

    /// Round-trip helper: serialise, deserialise, re-serialise and compare
    /// JSON strings. This avoids relying on `PartialEq` for f32-containing
    /// types while still fully exercising the serde impls.
    fn assert_serde_roundtrip<T>(value: &T)
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let json1 = serde_json::to_string(value).expect("serialization failed");
        let restored: T = serde_json::from_str(&json1).expect("deserialization failed");
        let json2 = serde_json::to_string(&restored).expect("re-serialization failed");
        assert_eq!(json1, json2, "serde round-trip produced different JSON");
    }

    // ── Round-trip tests ─────────────────────────────────────────────────────

    #[test]
    fn record_serde_roundtrip() {
        assert_serde_roundtrip(&sample_record());
    }

    #[test]
    fn file_record_serde_roundtrip() {
        assert_serde_roundtrip(&sample_file_record());
    }

    /// Old stores serialized FileRecord without the `blast_radius` field.
    /// `#[serde(default)]` on the field must make deserialization succeed
    /// with `blast_radius == None`.
    #[test]
    fn file_record_backward_compat_no_blast_radius() {
        let json = r#"{
            "path": "src/main.rs",
            "purpose": "Entry point",
            "entry_points": ["main"],
            "imports": [],
            "gotcha_keys": [],
            "decision_keys": [],
            "todos": [],
            "unsafe_count": 0,
            "unwrap_count": 0,
            "change_frequency": 5,
            "last_author": "dev",
            "is_hotspot": false,
            "token_cost_estimate": 100,
            "last_modified_session": 1710520800
        }"#;
        let fr: FileRecord = serde_json::from_str(json).unwrap();
        assert!(fr.blast_radius.is_none());
        assert_eq!(fr.path, "src/main.rs");
        assert_eq!(fr.content_hash, None);
        assert_eq!(fr.line_count, 0);
    }

    #[test]
    fn gotcha_record_serde_roundtrip() {
        let gotcha = GotchaRecord {
            rule: "Never hold a write transaction across an await point.".to_string(),
            reason: "SurrealKV write txns are not Send; the future will not compile.".to_string(),
            severity: Priority::Critical,
            affected_files: vec!["src/store/db.rs".to_string()],
            ref_url: Some("https://github.com/example/issue/99".to_string()),
            discovered_session: 1_710_520_800,
            confirmed: true,
            confirmed_content: Default::default(),
        };
        assert_serde_roundtrip(&gotcha);
    }

    #[test]
    fn policy_record_roundtrips_through_record_messagepack() {
        let policy = PolicyRecord {
            deny_if: None,
            require: None,
            name: "Production query safety".into(),
            rule: "Consult the production schema before querying it.".into(),
            reason: "Queries can target incompatible production tables because schemas drift."
                .into(),
            scope: "repo".into(),
            mode: PolicyMode::Block,
            trigger: PolicyTrigger {
                tool: Some("db_client".into()),
                host_glob: Some("*prod*".into()),
                target_path_glob: None,
                command_glob: None,
            },
            requires: PolicyRequires {
                key: "schema:orders_db".into(),
                via: vec![ReceiptSource::DbIntrospection, ReceiptSource::MemGet],
                freshness: PolicyFreshness {
                    ttl_secs: 900,
                    fingerprint: false,
                },
            },
            mints: None,
            stage: PolicyStage::Enforce,
            severity: Priority::Critical,
            created_by: "developer".into(),
        };
        let record = Record {
            key: "policy:production-query-safety".into(),
            value: policy.rule.clone(),
            category: Category::Policy,
            priority: policy.severity.clone(),
            tags: vec![],
            created_at: 1_710_520_800,
            updated_at: 1_710_520_800,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: device_id(),
                logical_clock: 1,
                wall_clock: 1_710_520_800,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
            gap_analysis_score: 0.0,
            payload: Some(serde_json::to_value(&policy).unwrap()),
        };
        let bytes = rmp_serde::to_vec_named(&record).unwrap();
        let restored: Record = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(restored.category, Category::Policy);
        assert_eq!(restored.payload_as::<PolicyRecord>().unwrap(), policy);
    }

    #[test]
    fn policy_requires_defaults_when_payload_omits_it() {
        // A policy payload authored via `mem_set` may omit `requires`; it must
        // deserialize to the inert default instead of erroring. Regression for
        // the observed mem_set "missing field `requires`" retry.
        let full = PolicyRecord {
            deny_if: None,
            require: None,
            name: "n".into(),
            rule: "r".into(),
            reason: "why".into(),
            scope: "repo".into(),
            mode: PolicyMode::Steer,
            trigger: PolicyTrigger {
                tool: Some("path".into()),
                host_glob: None,
                target_path_glob: Some("src/secrets/**".into()),
                command_glob: None,
            },
            requires: default_policy_requires(),
            mints: None,
            stage: PolicyStage::Off,
            severity: Priority::High,
            created_by: "developer".into(),
        };
        let mut value = serde_json::to_value(&full).unwrap();
        value.as_object_mut().unwrap().remove("requires");
        let parsed: PolicyRecord = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.requires, default_policy_requires());
        assert_eq!(parsed.requires.freshness.ttl_secs, DEFAULT_POLICY_TTL_SECS);
        assert!(parsed.requires.key.is_empty());
    }

    #[test]
    fn unknown_receipt_source_deserializes_to_unknown() {
        // Forward-compat: a source string from a newer mati degrades to Unknown
        // instead of failing the whole record, and Unknown is never accepted.
        assert_eq!(
            serde_json::from_str::<ReceiptSource>("\"future_source\"").unwrap(),
            ReceiptSource::Unknown
        );
        assert_eq!(
            serde_json::from_str::<ReceiptSource>("\"command_observed\"").unwrap(),
            ReceiptSource::CommandObserved
        );
        assert!(!CODEX_PRODUCIBLE_SOURCES.contains(&ReceiptSource::Unknown));
        assert!(CODEX_PRODUCIBLE_SOURCES.contains(&ReceiptSource::CommandObserved));
    }

    #[test]
    fn policy_mints_roundtrips_and_defaults_none() {
        let json = r#"{"on_command_glob":"cargo nextest run*","key":"tests-ran"}"#;
        let emitter: ReceiptEmitter = serde_json::from_str(json).unwrap();
        assert_eq!(emitter.key, "tests-ran");
        assert_eq!(emitter.on_command_glob, "cargo nextest run*");
        assert_serde_roundtrip(&emitter);
    }

    #[test]
    fn policy_requires_default_matches_cli_literal() {
        // Lock the serde default to the `mati policy add --requires` clap default
        // so the CLI and mem_set authoring paths cannot drift apart.
        let cli = r#"{"key":"","via":[],"freshness":{"ttl_secs":900}}"#;
        let from_cli: PolicyRequires = serde_json::from_str(cli).unwrap();
        assert_eq!(from_cli, default_policy_requires());
    }

    #[test]
    fn context_packet_serde_roundtrip() {
        assert_serde_roundtrip(&sample_context_packet());
    }

    // ── Lifecycle & tombstone serde ──────────────────────────────────────────

    #[test]
    fn record_lifecycle_tombstoned_serde() {
        let lifecycle = RecordLifecycle::Tombstoned {
            reason: TombstoneReason::FileDeleted,
            at: 1_710_520_800,
        };
        assert_serde_roundtrip(&lifecycle);
    }

    #[test]
    fn record_lifecycle_superseded_serde() {
        let lifecycle = RecordLifecycle::Superseded {
            by_key: "gotcha:inference-async-v2".to_string(),
        };
        assert_serde_roundtrip(&lifecycle);
    }

    #[test]
    fn tombstone_reason_file_renamed_serde() {
        let reason = TombstoneReason::FileRenamed {
            new_path: "src/store/backend.rs".to_string(),
        };
        assert_serde_roundtrip(&reason);
    }

    // ── Staleness signal serde ───────────────────────────────────────────────

    #[test]
    fn staleness_signal_dependency_bumped_serde() {
        let signal = StalenessSignal::DependencyBumped {
            dep: "tokio".to_string(),
            old_ver: "1.40".to_string(),
            new_ver: "1.50".to_string(),
        };
        assert_serde_roundtrip(&signal);
    }

    #[test]
    fn staleness_signal_file_renamed_serde() {
        let signal = StalenessSignal::FileRenamed {
            new_path: "src/store/backend.rs".to_string(),
        };
        assert_serde_roundtrip(&signal);
    }

    #[test]
    fn staleness_signal_cascade_serde() {
        let signal = StalenessSignal::CascadeFromDecision("decision:storage-engine".to_string());
        assert_serde_roundtrip(&signal);
    }

    #[test]
    fn staleness_score_fresh_default() {
        let s = StalenessScore::fresh();
        assert_eq!(s.tier, StalenessTier::Fresh);
        assert_eq!(s.value, 0.0);
        assert!(s.signals.is_empty());
        assert_eq!(s.computed_at, 0, "0 = not yet computed sentinel");
        assert!(s.last_record_sha.is_empty());
    }

    // ── Quality tier thresholds ──────────────────────────────────────────────

    #[test]
    fn quality_tier_ranges() {
        assert_eq!(QualityScore::tier_from_value(0.00), QualityTier::Suppressed);
        assert_eq!(QualityScore::tier_from_value(0.10), QualityTier::Suppressed);
        assert_eq!(QualityScore::tier_from_value(0.19), QualityTier::Suppressed);
        assert_eq!(QualityScore::tier_from_value(0.20), QualityTier::Poor);
        assert_eq!(QualityScore::tier_from_value(0.30), QualityTier::Poor);
        assert_eq!(QualityScore::tier_from_value(0.39), QualityTier::Poor);
        assert_eq!(QualityScore::tier_from_value(0.40), QualityTier::Acceptable);
        assert_eq!(QualityScore::tier_from_value(0.55), QualityTier::Acceptable);
        assert_eq!(QualityScore::tier_from_value(0.69), QualityTier::Acceptable);
        assert_eq!(QualityScore::tier_from_value(0.70), QualityTier::Good);
        assert_eq!(QualityScore::tier_from_value(0.80), QualityTier::Good);
        assert_eq!(QualityScore::tier_from_value(0.89), QualityTier::Good);
        // 0.9 is the start of Excellent [0.9, 1.0]
        assert_eq!(QualityScore::tier_from_value(0.90), QualityTier::Excellent);
        assert_eq!(QualityScore::tier_from_value(0.95), QualityTier::Excellent);
        assert_eq!(QualityScore::tier_from_value(1.00), QualityTier::Excellent);
    }

    // ── Confidence score ─────────────────────────────────────────────────────

    #[test]
    fn confidence_base_scores_by_source() {
        assert_eq!(
            ConfidenceScore::base_for_source(&RecordSource::DeveloperManual),
            0.80
        );
        assert_eq!(
            ConfidenceScore::base_for_source(&RecordSource::Import),
            0.70
        );
        assert_eq!(
            ConfidenceScore::base_for_source(&RecordSource::ClaudeEnrich),
            0.60
        );
        assert_eq!(
            ConfidenceScore::base_for_source(&RecordSource::SessionHook),
            0.50
        );
        assert_eq!(
            ConfidenceScore::base_for_source(&RecordSource::StaticAnalysis),
            0.10
        );
    }

    #[test]
    fn confidence_for_new_record_value_matches_base() {
        let source = RecordSource::ClaudeEnrich;
        let score = ConfidenceScore::for_new_record(&source);
        assert_eq!(score.value, ConfidenceScore::base_for_source(&source));
        assert_eq!(score.confirmation_count, 0);
        assert_eq!(score.contributor_count, 1);
        assert!(score.last_challenged.is_none());
        assert_eq!(score.challenge_count, 0);
    }

    // ── Priority ordering ────────────────────────────────────────────────────

    #[test]
    fn priority_total_ordering() {
        assert!(Priority::Critical > Priority::High);
        assert!(Priority::High > Priority::Normal);
        assert!(Priority::Normal > Priority::Low);
        assert!(Priority::Critical > Priority::Low);
        assert_eq!(Priority::High, Priority::High);
    }

    // ── Device ID accessor ───────────────────────────────────────────────────

    #[test]
    fn record_device_id_accessor_matches_version() {
        let rec = sample_record();
        assert_eq!(rec.device_id(), rec.version.device_id);
    }

    // ── Quality tier: out-of-range & non-finite ──────────────────────────────

    #[test]
    fn quality_tier_non_finite_is_suppressed() {
        // NaN, +∞, and -∞ must never reach Excellent — they would satisfy the
        // hook injection gate (quality >= 0.4) and inject untrusted records.
        assert_eq!(
            QualityScore::tier_from_value(f32::NAN),
            QualityTier::Suppressed
        );
        assert_eq!(
            QualityScore::tier_from_value(f32::INFINITY),
            QualityTier::Suppressed
        );
        assert_eq!(
            QualityScore::tier_from_value(f32::NEG_INFINITY),
            QualityTier::Suppressed
        );
    }

    #[test]
    fn quality_tier_out_of_range_finite_saturates() {
        // Finite values outside [0, 1] saturate without panicking.
        assert_eq!(QualityScore::tier_from_value(-1.0), QualityTier::Suppressed);
        assert_eq!(
            QualityScore::tier_from_value(-0.001),
            QualityTier::Suppressed
        );
        assert_eq!(QualityScore::tier_from_value(1.001), QualityTier::Excellent);
        assert_eq!(QualityScore::tier_from_value(100.0), QualityTier::Excellent);
    }

    #[test]
    fn layer0_default_quality_is_suppressed_tier() {
        let q = QualityScore::layer0_default();
        assert_eq!(q.tier, QualityTier::Suppressed);
        assert_eq!(q.value, 0.10);
        assert!(q.signals.is_empty());
        assert_eq!(q.computed_at, 0, "0 = not yet computed sentinel");
    }

    // ── Confidence: all sources ───────────────────────────────────────────────

    #[test]
    fn confidence_for_new_record_all_sources_correct() {
        let cases: &[(RecordSource, f32)] = &[
            (RecordSource::DeveloperManual, 0.80),
            (RecordSource::Import, 0.70),
            (RecordSource::ClaudeEnrich, 0.60),
            (RecordSource::SessionHook, 0.50),
            (RecordSource::StaticAnalysis, 0.10),
        ];
        for (source, expected) in cases {
            let score = ConfidenceScore::for_new_record(source);
            assert!(
                (score.value - expected).abs() < f32::EPSILON,
                "{source:?}: expected {expected}, got {}",
                score.value
            );
            assert_eq!(score.confirmation_count, 0);
            assert_eq!(score.contributor_count, 1);
            assert!(score.last_challenged.is_none());
            assert_eq!(score.challenge_count, 0);
        }
    }

    #[test]
    fn confidence_base_scores_are_all_distinct() {
        let scores: Vec<f32> = [
            RecordSource::DeveloperManual,
            RecordSource::Import,
            RecordSource::ClaudeEnrich,
            RecordSource::SessionHook,
            RecordSource::StaticAnalysis,
        ]
        .iter()
        .map(ConfidenceScore::base_for_source)
        .collect();

        for i in 0..scores.len() {
            for j in (i + 1)..scores.len() {
                assert!(
                    (scores[i] - scores[j]).abs() > f32::EPSILON,
                    "sources {i} and {j} have identical base score {}",
                    scores[i]
                );
            }
        }
    }

    // ── Priority: exhaustive ordering ─────────────────────────────────────────

    #[test]
    fn priority_exhaustive_pairwise_ordering() {
        use std::cmp::Ordering::*;
        let pairs = [
            (Priority::Low, Priority::Normal, Less),
            (Priority::Low, Priority::High, Less),
            (Priority::Low, Priority::Critical, Less),
            (Priority::Normal, Priority::High, Less),
            (Priority::Normal, Priority::Critical, Less),
            (Priority::High, Priority::Critical, Less),
            (Priority::Low, Priority::Low, Equal),
            (Priority::Normal, Priority::Normal, Equal),
            (Priority::High, Priority::High, Equal),
            (Priority::Critical, Priority::Critical, Equal),
        ];
        for (a, b, expected) in pairs {
            assert_eq!(
                a.cmp(&b),
                expected,
                "{a:?}.cmp({b:?}) should be {expected:?}"
            );
            // Antisymmetry: if a < b then b > a
            if expected == Less {
                assert_eq!(b.cmp(&a), std::cmp::Ordering::Greater, "{b:?}.cmp({a:?})");
            }
        }
    }

    // ── StalenessSignal: all variants round-trip ──────────────────────────────

    #[test]
    fn staleness_all_signal_variants_serde() {
        let signals: Vec<StalenessSignal> = vec![
            StalenessSignal::NotAccessedDays(30),
            StalenessSignal::LinesChangedPct(0.75),
            StalenessSignal::EntryPointsChanged(2),
            StalenessSignal::ImportsChanged(5),
            StalenessSignal::FileDeleted,
            StalenessSignal::FileRenamed {
                new_path: "src/foo.rs".to_string(),
            },
            StalenessSignal::DependencyBumped {
                dep: "tokio".to_string(),
                old_ver: "1.40".to_string(),
                new_ver: "1.50".to_string(),
            },
            StalenessSignal::LinkedFileChanged {
                path: "src/bar.rs".to_string(),
            },
            StalenessSignal::CascadeFromDecision("decision:arch".to_string()),
            StalenessSignal::TodosChanged,
            StalenessSignal::UnsafeCountChanged(3),
            StalenessSignal::UnwrapCountChanged(-2),
            StalenessSignal::GitCommitsSince(7),
        ];
        for signal in &signals {
            let json = serde_json::to_string(signal).expect("serialize");
            let restored: StalenessSignal = serde_json::from_str(&json).expect("deserialize");
            let json2 = serde_json::to_string(&restored).expect("re-serialize");
            assert_eq!(json, json2, "roundtrip failed for: {json}");
        }
    }

    // ── TombstoneReason: all variants ────────────────────────────────────────

    #[test]
    fn tombstone_reason_all_variants_serde() {
        let reasons = vec![
            TombstoneReason::FileDeleted,
            TombstoneReason::FileRenamed {
                new_path: "src/new.rs".to_string(),
            },
            TombstoneReason::ManualDeletion,
            TombstoneReason::Superseded,
            TombstoneReason::MigrationRepair,
        ];
        for reason in &reasons {
            assert_serde_roundtrip(reason);
        }
    }

    // ── Serde snake_case contracts ────────────────────────────────────────────

    #[test]
    fn category_serializes_as_snake_case() {
        let cases = [
            (Category::Gotcha, "\"gotcha\""),
            (Category::File, "\"file\""),
            (Category::Decision, "\"decision\""),
            (Category::Stage, "\"stage\""),
            (Category::Dependency, "\"dependency\""),
            (Category::DevNote, "\"dev_note\""),
            (Category::Session, "\"session\""),
            (Category::Analytics, "\"analytics\""),
        ];
        for (cat, expected_json) in cases {
            let json = serde_json::to_string(&cat).unwrap();
            assert_eq!(json, expected_json, "Category::{cat:?}");
        }
    }

    #[test]
    fn record_source_serializes_as_snake_case() {
        let cases = [
            (RecordSource::StaticAnalysis, "\"static_analysis\""),
            (RecordSource::ClaudeEnrich, "\"claude_enrich\""),
            (RecordSource::SessionHook, "\"session_hook\""),
            (RecordSource::DeveloperManual, "\"developer_manual\""),
            (RecordSource::Import, "\"import\""),
        ];
        for (src, expected_json) in cases {
            let json = serde_json::to_string(&src).unwrap();
            assert_eq!(json, expected_json, "RecordSource::{src:?}");
        }
    }

    #[test]
    fn staleness_tier_serializes_as_snake_case() {
        // Sync merge rule depends on the wire format being stable.
        let cases = [
            (StalenessTier::Fresh, "\"fresh\""),
            (StalenessTier::Aging, "\"aging\""),
            (StalenessTier::Stale, "\"stale\""),
            (StalenessTier::Liability, "\"liability\""),
            (StalenessTier::Tombstone, "\"tombstone\""),
        ];
        for (tier, expected_json) in cases {
            let json = serde_json::to_string(&tier).unwrap();
            assert_eq!(json, expected_json, "StalenessTier::{tier:?}");
        }
    }

    // ── GotchaRecord: confirmed flag ─────────────────────────────────────────

    #[test]
    fn gotcha_record_layer0_stub_is_unconfirmed() {
        // Layer 0 stubs must start unconfirmed; the hook decision matrix never
        // injects confirmed:false records regardless of confidence or quality.
        let stub = GotchaRecord {
            rule: "Do not call .await inside rayon::spawn.".to_string(),
            reason: "rayon threads have no tokio runtime.".to_string(),
            severity: Priority::Critical,
            affected_files: vec!["src/analysis/walker.rs".to_string()],
            ref_url: None,
            discovered_session: 0,
            confirmed: false,
            confirmed_content: Default::default(),
        };
        assert!(
            !stub.confirmed,
            "Layer 0 stubs must be unconfirmed on construction"
        );

        // Serde roundtrip preserves the flag
        let json = serde_json::to_string(&stub).unwrap();
        let restored: GotchaRecord = serde_json::from_str(&json).unwrap();
        assert!(
            !restored.confirmed,
            "confirmed flag must survive serde roundtrip"
        );
        // The JSON wire format must contain "confirmed":false explicitly
        assert!(json.contains("\"confirmed\":false"), "wire format: {json}");
    }

    #[test]
    fn gotcha_record_confirmed_true_roundtrips() {
        let confirmed = GotchaRecord {
            rule: "Use SurrealKV::with_versioning(true, 0) for indefinite retention.".to_string(),
            reason: "0 means retain all versions forever, not disabled.".to_string(),
            severity: Priority::High,
            affected_files: vec!["src/store/db.rs".to_string()],
            ref_url: Some("https://github.com/example/issue/5".to_string()),
            discovered_session: 1_710_520_800,
            confirmed: true,
            confirmed_content: Default::default(),
        };
        assert_serde_roundtrip(&confirmed);
        let json = serde_json::to_string(&confirmed).unwrap();
        assert!(json.contains("\"confirmed\":true"));
    }

    // ─── Complex serde round-trips ────────────────────────────────────────────

    #[test]
    fn staleness_score_fully_populated_serde() {
        let s = StalenessScore {
            value: 0.87,
            tier: StalenessTier::Liability,
            signals: vec![
                StalenessSignal::NotAccessedDays(90),
                StalenessSignal::LinesChangedPct(0.6),
                StalenessSignal::EntryPointsChanged(3),
                StalenessSignal::FileRenamed {
                    new_path: "src/store/backend.rs".to_string(),
                },
            ],
            computed_at: 1_710_520_800,
            last_record_sha: "deadbeefcafe0123".to_string(),
        };
        assert_serde_roundtrip(&s);
        let json = serde_json::to_string(&s).unwrap();
        let restored: StalenessScore = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.tier, StalenessTier::Liability);
        assert_eq!(restored.signals.len(), 4);
        assert_eq!(restored.last_record_sha, "deadbeefcafe0123");
    }

    #[test]
    fn quality_score_with_all_positive_signals_serde() {
        let q = QualityScore {
            value: 0.92,
            tier: QualityTier::Excellent,
            signals: vec![
                QualitySignal::HasImperativeVerb,
                QualitySignal::HasCausality,
                QualitySignal::HasSeveritySet,
                QualitySignal::HasReference,
                QualitySignal::RuleLengthAdequate,
                QualitySignal::ReasonLengthAdequate,
                QualitySignal::AffectedFilesSpecified,
                QualitySignal::HasSpecificIdentifier,
            ],
            computed_at: 1_710_520_800,
        };
        assert_serde_roundtrip(&q);
        let json = serde_json::to_string(&q).unwrap();
        let restored: QualityScore = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.tier, QualityTier::Excellent);
        assert_eq!(restored.signals.len(), 8);
    }

    #[test]
    fn confidence_score_with_challenge_history_serde() {
        // last_challenged: Some(u64) — a real production state for a disputed record.
        let c = ConfidenceScore {
            value: 0.45,
            confirmation_count: 1,
            contributor_count: 3,
            last_challenged: Some(1_710_500_000),
            challenge_count: 2,
        };
        let json = serde_json::to_string(&c).unwrap();
        let restored: ConfidenceScore = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.last_challenged, Some(1_710_500_000));
        assert_eq!(restored.challenge_count, 2);
        assert_eq!(restored.contributor_count, 3);
        let json2 = serde_json::to_string(&restored).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn record_ref_url_none_does_not_become_some() {
        // ref_url: None must not silently become Some("") or Some("null").
        let mut r = sample_record();
        r.ref_url = None;
        let json = serde_json::to_string(&r).unwrap();
        let restored: Record = serde_json::from_str(&json).unwrap();
        assert!(
            restored.ref_url.is_none(),
            "ref_url: None must not become Some after roundtrip"
        );
        assert!(
            json.contains("\"ref_url\":null"),
            "wire format must encode None as null"
        );
    }

    #[test]
    fn context_packet_zero_knowledge_case_serde() {
        // The "blank slate" scenario: mati installed but nothing indexed yet.
        let empty = ContextPacket {
            stage: None,
            critical_gotchas: vec![],
            file_records: vec![],
            related_decisions: vec![],
            recent_session: None,
            token_estimate: 0,
            stale_warnings: vec![],
            unconfirmed_candidates: vec![],
            knowledge_gaps: vec![],
            compliance_rate: None,
            injection_string: String::new(),
        };
        assert_serde_roundtrip(&empty);
        let json = serde_json::to_string(&empty).unwrap();
        let restored: ContextPacket = serde_json::from_str(&json).unwrap();
        assert!(restored.critical_gotchas.is_empty());
        assert!(restored.file_records.is_empty());
        assert!(restored.stage.is_none());
        assert_eq!(restored.token_estimate, 0);
    }

    #[test]
    fn record_tags_empty_and_many_both_survive_serde() {
        let mut r = sample_record();

        r.tags = vec![];
        let json_empty = serde_json::to_string(&r).unwrap();
        let restored_empty: Record = serde_json::from_str(&json_empty).unwrap();
        assert!(
            restored_empty.tags.is_empty(),
            "empty tags must remain empty"
        );

        r.tags = (0..50).map(|i| format!("tag-{i:03}")).collect();
        let json_many = serde_json::to_string(&r).unwrap();
        let restored_many: Record = serde_json::from_str(&json_many).unwrap();
        assert_eq!(restored_many.tags.len(), 50);
        assert_eq!(restored_many.tags[0], "tag-000");
        assert_eq!(restored_many.tags[49], "tag-049");
    }

    #[test]
    fn file_record_layer0_stub_serde() {
        // Layer 0: file exists, but purpose and entry_points are empty.
        let stub = FileRecord::layer0_stub(
            "src/analysis/walker.rs",
            vec![],
            vec!["ignore".to_string(), "rayon".to_string()],
            vec![],
            0,
            3,
            17,
            None,
            true,
            0,
            0,
        );
        assert_serde_roundtrip(&stub);
        let json = serde_json::to_string(&stub).unwrap();
        let restored: FileRecord = serde_json::from_str(&json).unwrap();
        assert!(
            restored.purpose.is_empty(),
            "empty purpose must remain empty"
        );
        assert!(restored.entry_points.is_empty());
        assert!(restored.last_author.is_none());
        assert!(restored.is_hotspot);
        assert_eq!(restored.unwrap_count, 3);
    }

    #[test]
    fn layer0_file_record_builder_sets_suppressed_quality() {
        let record =
            Record::layer0_file_stub("file:src/analysis/walker.rs", device_id(), 7, 1_710_520_800);

        assert_eq!(record.key, "file:src/analysis/walker.rs");
        assert_eq!(record.category, Category::File);
        assert!(record.value.is_empty());
        assert_eq!(record.quality.value, 0.10);
        assert_eq!(record.quality.tier, QualityTier::Suppressed);
        assert_eq!(record.source, RecordSource::StaticAnalysis);
        assert_eq!(record.confidence.value, 0.10);
        assert_eq!(record.confidence.contributor_count, 1);
    }

    // ── StaleReviewEntry / StaleReviewPayload serde ──────────────────────────

    #[test]
    fn stale_review_entry_serde_roundtrip() {
        let entry = StaleReviewEntry {
            key: "file:src/store/db.rs".to_string(),
            staleness_value: 0.72,
            tier: StalenessTier::Stale,
            last_updated: 1_710_520_800,
            signals: vec![
                "not accessed for 45 days".to_string(),
                "3 entry points changed".to_string(),
            ],
        };
        assert_serde_roundtrip(&entry);
    }

    #[test]
    fn stale_review_payload_serde_roundtrip() {
        let payload = StaleReviewPayload {
            session_timestamp: 1_710_520_800,
            entries: vec![
                StaleReviewEntry {
                    key: "file:src/store/db.rs".to_string(),
                    staleness_value: 0.72,
                    tier: StalenessTier::Stale,
                    last_updated: 1_710_500_000,
                    signals: vec!["not accessed for 45 days".to_string()],
                },
                StaleReviewEntry {
                    key: "gotcha:inference-async".to_string(),
                    staleness_value: 0.85,
                    tier: StalenessTier::Liability,
                    last_updated: 1_710_400_000,
                    signals: vec![
                        "90 commits since last confirmation".to_string(),
                        "75% of lines changed".to_string(),
                    ],
                },
            ],
        };
        assert_serde_roundtrip(&payload);
        let json = serde_json::to_string(&payload).unwrap();
        let restored: StaleReviewPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.entries.len(), 2);
        assert_eq!(restored.session_timestamp, 1_710_520_800);
    }

    #[test]
    fn stale_review_payload_empty_entries_serde() {
        let payload = StaleReviewPayload {
            session_timestamp: 1_710_520_800,
            entries: vec![],
        };
        assert_serde_roundtrip(&payload);
        let json = serde_json::to_string(&payload).unwrap();
        let restored: StaleReviewPayload = serde_json::from_str(&json).unwrap();
        assert!(restored.entries.is_empty());
    }

    // ── GitCommitsSince signal ───────────────────────────────────────────────

    #[test]
    fn staleness_signal_git_commits_since_serde() {
        let signal = StalenessSignal::GitCommitsSince(42);
        assert_serde_roundtrip(&signal);
        let json = serde_json::to_string(&signal).unwrap();
        assert!(json.contains("git_commits_since"), "wire format: {json}");
    }

    #[test]
    fn staleness_signal_git_commits_since_display() {
        let signal = StalenessSignal::GitCommitsSince(7);
        assert_eq!(signal.to_string(), "7 commits since last confirmation");
    }

    #[test]
    fn staleness_signal_display_all_variants() {
        // Smoke test: every variant produces a non-empty string.
        let signals: Vec<StalenessSignal> = vec![
            StalenessSignal::NotAccessedDays(30),
            StalenessSignal::LinesChangedPct(0.75),
            StalenessSignal::EntryPointsChanged(2),
            StalenessSignal::ImportsChanged(5),
            StalenessSignal::FileDeleted,
            StalenessSignal::FileRenamed {
                new_path: "src/foo.rs".to_string(),
            },
            StalenessSignal::DependencyBumped {
                dep: "tokio".to_string(),
                old_ver: "1.40".to_string(),
                new_ver: "1.50".to_string(),
            },
            StalenessSignal::LinkedFileChanged {
                path: "src/bar.rs".to_string(),
            },
            StalenessSignal::CascadeFromDecision("decision:arch".to_string()),
            StalenessSignal::TodosChanged,
            StalenessSignal::UnsafeCountChanged(3),
            StalenessSignal::UnwrapCountChanged(-2),
            StalenessSignal::GitCommitsSince(7),
        ];
        for signal in &signals {
            let display = signal.to_string();
            assert!(
                !display.is_empty(),
                "Display for {signal:?} should not be empty"
            );
        }
    }
}
