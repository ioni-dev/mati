//! Storage layer — SurrealKV (M-03)
//!
//! Two trees:
//! - `knowledge.db` — all user-visible records, versioning enabled
//! - `sessions.db`  — session analytics and hook events, 90-day retention
//!
//! Path: `~/.mati/<slug>/knowledge.db` and `sessions.db`

pub mod db;
pub mod device;
pub mod durability;
pub mod enforcement;
pub mod extraction;
pub mod gotcha_ops;
pub mod migrations;
pub mod negative_exemplar;
pub mod observability;
pub mod policy_ops;
pub mod record;
pub mod repair;
pub mod session;

pub use db::{
    derive_slug, mati_home, mati_home_opt, slug_root, KnowledgeWriteOp, RepoIdent, Store,
};
pub use device::stable_device_id;
pub use durability::{Durability, Encoding};
pub use migrations::CURRENT_SCHEMA_VERSION;
pub use record::{
    ActionPredicate, AgentKind, Category, ConfidenceScore, ContentOutcome, ContextPacket, DeviceId,
    FileRecord, GapType, GotchaRecord, KnowledgeGap, OnboardingScore, PolicyFreshness, PolicyMode,
    PolicyRecord, PolicyRequires, PolicyStage, PolicyTrigger, Priority, QualityScore,
    QualitySignal, QualityTier, ReceiptEmitter, ReceiptSource, Record, RecordLifecycle,
    RecordSource, RecordVersion, StaleReviewEntry, StaleReviewPayload, StalenessScore,
    StalenessSignal, StalenessTier, TodoComment, TodoKind, TombstoneReason,
    CODEX_PRODUCIBLE_SOURCES,
};
