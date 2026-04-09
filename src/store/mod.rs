//! Storage layer — SurrealKV (M-03)
//!
//! Two trees:
//! - `knowledge.db` — all user-visible records, versioning enabled
//! - `sessions.db`  — session analytics and hook events, 90-day retention
//!
//! Path: `~/.mati/<slug>/knowledge.db` and `sessions.db`

pub mod db;
pub mod durability;
pub mod gotcha_ops;
pub mod record;
pub mod repair;
pub mod session;

pub use db::{derive_slug, KnowledgeWriteOp, Store};
pub use durability::Durability;
pub use record::{
    Category, ConfidenceScore, ContextPacket, DeviceId, FileRecord, GapType, GotchaRecord,
    KnowledgeGap, OnboardingScore, Priority, QualityScore, QualitySignal, QualityTier, Record,
    RecordLifecycle, RecordSource, RecordVersion, StaleReviewEntry, StaleReviewPayload,
    StalenessScore, StalenessSignal, StalenessTier, TodoComment, TodoKind, TombstoneReason,
};
