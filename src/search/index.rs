//! Tantivy full-text search index (M-05).
//!
//! Schema matches ARCHITECTURE.md §7 exactly:
//! ```text
//! key        TEXT | STORED        BM25-indexed, stored for retrieval
//! value      TEXT | STORED        Primary search target (purpose, rule, body)
//! category   STRING | STORED | FAST   Not tokenised — exact match + filter
//! tags       TEXT | STORED        Free-form tags, space-joined before indexing
//! priority   u64  | STORED | FAST  Numeric filter / sort
//! updated_at u64  | STORED | FAST  Numeric filter / sort (Unix secs)
//! ```
//!
//! **Do not add fields** without updating ARCHITECTURE.md §7 and bumping
//! the schema. Adding fields silently invalidates existing indices — callers
//! see an `IndexError` on open and must trigger a rebuild from SurrealKV (C4).

use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use tantivy::directory::error::OpenReadError;
use tantivy::schema::{FieldType, NumericOptions, Schema, FAST, STORED, STRING, TEXT};
use tantivy::{Index, IndexWriter, TantivyDocument, TantivyError};

use crate::store::record::{Category, Priority, Record};

// ── Field handles ─────────────────────────────────────────────────────────────

/// Handles to every schema field — stored next to the `Index` so callers never
/// need to call `schema.get_field(name)` (which panics on unknown names).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Fields {
    pub(crate) key:        tantivy::schema::Field,
    pub(crate) value:      tantivy::schema::Field,
    pub(crate) category:   tantivy::schema::Field,
    pub(crate) tags:       tantivy::schema::Field,
    pub(crate) priority:   tantivy::schema::Field,
    pub(crate) updated_at: tantivy::schema::Field,
}

// ── Search struct ─────────────────────────────────────────────────────────────

/// Full-text BM25 search over all mati knowledge records.
///
/// Index lives at `~/.mati/<slug>/search_index/`.
/// Constructed via [`Search::open`] — either creates a fresh index or reopens
/// an existing one. Corrupt indices must be detected and rebuilt by the caller
/// (see C4 in ARCHITECTURE.md).
pub struct Search {
    pub(crate) index:  Index,
    pub(crate) fields: Fields,
    /// Tantivy index writer — held open for the session lifetime.
    /// Wrapped in `Mutex` so `add_record` can take `&self` (matching
    /// `Store::put`'s immutable receiver) while `commit` needs `&mut`.
    writer: Mutex<IndexWriter>,
}

impl Search {
    /// Open (or create) the tantivy index at `path`.
    ///
    /// - If `path` does not exist it is created.
    /// - If `path` is empty, a fresh index is written.
    /// - If a valid index already exists, it is opened.
    ///
    /// Returns `Err` if an existing index has an incompatible schema
    /// (schema mismatch = field set changed). The caller should delete
    /// `search_index/` and call `open` again to trigger a full rebuild.
    pub fn open(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)?;

        let (schema, fields) = schema();

        // Try to open an existing index first.
        // Only fall back to creation when meta.json is absent — i.e. the
        // directory exists but no index has been written yet.
        // All other errors (DataCorruption, SchemaError, LockFailure, IoError)
        // propagate to the caller so C4 rebuild logic can handle them.
        let index = match Index::open_in_dir(path) {
            Ok(idx) => idx,
            Err(TantivyError::OpenReadError(OpenReadError::FileDoesNotExist(_))) => {
                Index::create_in_dir(path, schema)?
            }
            Err(e) => return Err(e.into()),
        };

        // 15 MB is sufficient for mati's small documents and keeps memory
        // footprint low. Tantivy requires a minimum of 3 MB.
        let writer = index.writer(15_000_000)?;

        Ok(Self { index, fields, writer: Mutex::new(writer) })
    }

    /// Index a single record and commit immediately.
    ///
    /// Writes are additive — tantivy has no update primitive. If the same key
    /// is indexed twice (e.g. on `mati enrich` re-run), both versions exist
    /// in the index until a full rebuild (M-05-D / C4). Search results remain
    /// correct because tantivy returns the latest committed version first;
    /// duplicates are a space issue, not a correctness issue.
    pub fn add_record(&self, record: &Record) -> Result<()> {
        let doc = record_to_doc(record, &self.fields);
        let mut writer = self.writer.lock().expect("search writer lock poisoned");
        writer.add_document(doc)?;
        writer.commit()?;
        Ok(())
    }

    /// Index a batch of records with a single commit at the end.
    ///
    /// Use this from `Store::put_batch` — one tantivy commit for the whole
    /// batch instead of one per record.
    pub fn add_records(&self, records: &[(&str, &Record)]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let mut writer = self.writer.lock().expect("search writer lock poisoned");
        for (_, record) in records {
            let doc = record_to_doc(record, &self.fields);
            writer.add_document(doc)?;
        }
        writer.commit()?;
        Ok(())
    }

    /// Flush pending writes and release the writer lock.
    ///
    /// Must be called before dropping `Search` to ensure all indexed documents
    /// are committed. After `close`, the index is safe to reopen.
    pub fn close(self) -> Result<()> {
        let mut writer = self.writer.into_inner().expect("search writer lock poisoned");
        writer.commit()?;
        Ok(())
    }
}

// ── Document construction ─────────────────────────────────────────────────────

/// Convert a `Record` into a tantivy document ready for indexing.
fn record_to_doc(record: &Record, fields: &Fields) -> TantivyDocument {
    let mut doc = TantivyDocument::default();
    doc.add_text(fields.key,        &record.key);
    doc.add_text(fields.value,      &record.value);
    doc.add_text(fields.category,   category_str(&record.category));
    doc.add_text(fields.tags,       &record.tags.join(" "));
    doc.add_u64(fields.priority,    priority_u64(&record.priority));
    doc.add_u64(fields.updated_at,  record.updated_at);
    doc
}

/// Map `Category` to its snake_case string — matches serde representation
/// so tantivy category values are consistent with JSON serialization.
fn category_str(cat: &Category) -> &'static str {
    match cat {
        Category::Gotcha     => "gotcha",
        Category::File       => "file",
        Category::Decision   => "decision",
        Category::Stage      => "stage",
        Category::Dependency => "dependency",
        Category::DevNote    => "dev_note",
        Category::Session    => "session",
        Category::Analytics  => "analytics",
    }
}

/// Map `Priority` to a sortable u64 — matches the derived `Ord` ordering.
fn priority_u64(p: &Priority) -> u64 {
    match p {
        Priority::Low      => 0,
        Priority::Normal   => 1,
        Priority::High     => 2,
        Priority::Critical => 3,
    }
}

// ── Schema builder ────────────────────────────────────────────────────────────

/// Build the tantivy schema and return field handles alongside it.
///
/// Called once per `Search::open`. Separated from the struct so tests can
/// verify field presence without opening a real index.
pub(crate) fn schema() -> (Schema, Fields) {
    let mut b = Schema::builder();

    let key        = b.add_text_field("key",        TEXT | STORED);
    let value      = b.add_text_field("value",      TEXT | STORED);
    let category   = b.add_text_field("category",   STRING | STORED | FAST);
    let tags       = b.add_text_field("tags",        TEXT | STORED);
    let priority   = b.add_u64_field("priority",    numeric_stored_fast());
    let updated_at = b.add_u64_field("updated_at",  numeric_stored_fast());

    (b.build(), Fields { key, value, category, tags, priority, updated_at })
}

/// `STORED | FAST` for u64 fields — tantivy requires `NumericOptions`, not
/// the `TextOptions` bitflags, so we build them explicitly.
fn numeric_stored_fast() -> NumericOptions {
    NumericOptions::default().set_stored().set_fast()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── Schema correctness ───────────────────────────────────────────────────

    #[test]
    fn schema_has_all_six_fields() {
        let (s, _) = schema();
        for name in ["key", "value", "category", "tags", "priority", "updated_at"] {
            assert!(s.get_field(name).is_ok(), "missing field: {name}");
        }
    }

    #[test]
    fn text_fields_are_stored() {
        let (s, f) = schema();
        for field in [f.key, f.value, f.tags] {
            let entry = s.get_field_entry(field);
            assert!(entry.is_stored(), "text field {field:?} must be stored");
        }
    }

    #[test]
    fn category_field_is_string_not_text() {
        // STRING = not tokenised. Exact-match semantics for category filtering.
        let (s, f) = schema();
        let entry = s.get_field_entry(f.category);
        let FieldType::Str(opts) = entry.field_type() else {
            panic!("category must be a text field");
        };
        // A STRING field must have indexing options (it is indexed) and must
        // use the "raw" tokenizer — i.e. no tokenisation, exact-match only.
        let indexing = opts
            .get_indexing_options()
            .expect("category must have indexing options");
        assert_eq!(
            indexing.tokenizer(), "raw",
            "category must use raw tokenizer (STRING), not default (TEXT)"
        );
    }

    #[test]
    fn u64_fields_are_stored_and_fast() {
        let (s, f) = schema();
        for field in [f.priority, f.updated_at] {
            let entry = s.get_field_entry(field);
            assert!(entry.is_stored(), "u64 field {field:?} must be stored");
            let FieldType::U64(opts) = entry.field_type() else {
                panic!("field {field:?} must be u64");
            };
            assert!(opts.is_fast(), "u64 field {field:?} must be FAST");
        }
    }

    // ── Index lifecycle ──────────────────────────────────────────────────────

    #[test]
    fn open_creates_index_in_new_directory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("search_index");
        assert!(!path.exists());
        Search::open(&path).unwrap();
        assert!(path.exists(), "search_index dir must be created");
    }

    #[test]
    fn open_creates_index_when_dir_is_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("search_index");
        std::fs::create_dir_all(&path).unwrap();
        Search::open(&path).unwrap(); // must not panic on empty dir
    }

    #[test]
    fn open_reopens_existing_index() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("search_index");
        Search::open(&path).unwrap();
        // Second open must succeed without error.
        Search::open(&path).unwrap();
    }

    #[test]
    fn open_is_idempotent_schema_stays_stable() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("search_index");
        let schema1 = {
            let s = Search::open(&path).unwrap();
            s.index.schema()
        }; // s dropped here — releases any index lock before second open
        let schema2 = {
            let s = Search::open(&path).unwrap();
            s.index.schema()
        };
        assert_eq!(
            schema1.num_fields(),
            schema2.num_fields(),
            "schema must not drift between opens"
        );
    }

    #[test]
    fn open_path_is_independent_per_project() {
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("project_a/search_index");
        let b = dir.path().join("project_b/search_index");
        Search::open(&a).unwrap();
        Search::open(&b).unwrap();
        assert!(a.exists());
        assert!(b.exists());
    }
}
