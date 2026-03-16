//! Storage layer — SurrealKV (M-03)
//!
//! Two trees:
//! -  — all user-visible records, versioning enabled
//! -  — session analytics and hook events, 90-day retention
//!
//! Path:  and
//!
//! , , ,
//! implemented in M-03. Types are available now via  and .

pub mod durability;
pub mod record;

pub use durability::Durability;
pub use record::{
    Category, ConfidenceScore, ContextPacket, DeviceId, FileRecord, GapType, GotchaRecord,
    KnowledgeGap, OnboardingScore, Priority, QualityScore, QualitySignal, QualityTier, Record,
    RecordLifecycle, RecordSource, RecordVersion, StalenessScore, StalenessSignal, StalenessTier,
    TodoComment, TodoKind, TombstoneReason,
};
