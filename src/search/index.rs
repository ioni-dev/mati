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

use anyhow::{Context, Result};
use tantivy::collector::TopDocs;
use tantivy::directory::error::OpenReadError;
use tantivy::query::{PhraseQuery, QueryParser};
use tantivy::schema::{NumericOptions, Schema, Value, FAST, STORED, STRING, TEXT};
use tantivy::{Index, IndexReader, IndexWriter, ReloadPolicy, TantivyDocument, TantivyError, Term};

use crate::store::record::{Category, Priority, Record};

// ── Writer tuning ─────────────────────────────────────────────────────────────

/// Writer heap budget in bytes.
///
/// Tantivy divides this equally among worker threads (up to 8). Each thread
/// needs at least 15 MB (`MEMORY_BUDGET_NUM_BYTES_MIN`). At 50 MB on a
/// multi-core machine this yields 3 threads × ~16.7 MB each — a sweet spot
/// between thread coordination overhead (which hurts small batches) and
/// parallelism (which helps large batches).
///
/// When a thread's share fills up, tantivy auto-flushes the in-memory segment
/// to disk (cheap — no meta update, no merge). Larger per-thread budgets mean
/// fewer auto-flushes and fewer intermediate segments to merge after commit.
///
/// Benchmarked: 50 MB + single commit gives 7.6× speedup at 10k records
/// (1.55s → 203ms) with only 2× overhead at 250 records (91ms → 193ms).
/// 120 MB (8 threads) was slower at both sizes due to coordination overhead.
const WRITER_HEAP_BYTES: usize = 50_000_000;

// ── Field handles ─────────────────────────────────────────────────────────────

/// Handles to every schema field — stored next to the `Index` so callers never
/// need to call `schema.get_field(name)` (which panics on unknown names).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Fields {
    pub(crate) key: tantivy::schema::Field,
    pub(crate) value: tantivy::schema::Field,
    pub(crate) category: tantivy::schema::Field,
    pub(crate) tags: tantivy::schema::Field,
    pub(crate) priority: tantivy::schema::Field,
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
    pub(crate) index: Index,
    pub(crate) fields: Fields,
    /// Tantivy index writer — held open for the session lifetime.
    /// Wrapped in `Mutex` so `add_record` can take `&self` (matching
    /// `Store::put`'s immutable receiver) while `commit` needs `&mut`.
    writer: Mutex<IndexWriter>,
    /// Reader held open for the session lifetime.
    /// `ReloadPolicy::Manual` — we call `reader.reload()` explicitly at the
    /// start of `query_keys`, guaranteeing read-after-write without a background
    /// watcher thread.
    reader: IndexReader,
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

        // Try to open an existing index first.
        // Only fall back to creation when meta.json is absent — i.e. the
        // directory exists but no index has been written yet.
        // All other errors (DataCorruption, SchemaError, LockFailure, IoError)
        // propagate to the caller so C4 rebuild logic can handle them.
        let index = match Index::open_in_dir(path) {
            Ok(idx) => idx,
            Err(TantivyError::OpenReadError(OpenReadError::FileDoesNotExist(_))) => {
                let (schema, _) = schema();
                Index::create_in_dir(path, schema)?
            }
            Err(e) => return Err(e.into()),
        };

        // Derive field handles from the stored schema by name, not by ordinal.
        // This is correct for both the create path (schema we just wrote) and
        // the reopen path (schema read from disk). If a field is missing
        // (schema changed between binary versions), get_field returns Err
        // and the caller must delete search_index/ and rebuild (C4).
        let fields = fields_from_schema(&index.schema())?;

        let writer = index.writer(WRITER_HEAP_BYTES)?;
        // Manual reload policy: we call reader.reload() explicitly at the
        // start of query_keys, guaranteeing read-after-write correctness
        // without relying on a background watcher thread.
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()?;

        Ok(Self {
            index,
            fields,
            writer: Mutex::new(writer),
            reader,
        })
    }

    /// Replace a single record in the search index and commit immediately.
    ///
    /// Search truth is keyed by `Record.key`. We first delete any existing
    /// document for that key, then re-add the current record when it is
    /// searchable. This keeps tantivy aligned with the latest KV state and
    /// avoids stale top-k slots from previous versions.
    ///
    /// **Performance:** commits on every call. For bulk writes use
    /// [`Search::add_records`] via [`crate::store::Store::put_batch`] — that
    /// path stages the entire batch and commits once.
    pub fn add_record(&self, record: &Record) -> Result<()> {
        let mut writer = self.writer.lock().expect("search writer lock poisoned");
        delete_by_key(&self.index, &writer, self.fields.key, &record.key)?;
        if is_searchable(record) {
            writer.add_document(record_to_doc(record, &self.fields))?;
        }
        writer.commit()?;
        Ok(())
    }

    /// Replace a batch of records with a single commit at the end.
    ///
    /// Returns the total number of searchable records successfully staged and
    /// committed.
    ///
    /// All documents are staged first, then a single `commit()` makes them
    /// searchable. Tantivy's worker threads auto-flush in-memory segments to
    /// disk when their heap share fills up — those flushes are cheap (no meta
    /// update) and transparent. The single explicit commit at the end is the
    /// only expensive operation (~140 ms for meta persistence + merge policy).
    ///
    /// All keys in the batch are deleted from tantivy first, then the latest
    /// searchable version for each key is re-added. This avoids stale duplicate
    /// docs after re-enrich / update flows and keeps delete-like replacements
    /// consistent.
    ///
    /// On staging error, the batch is rolled back — no partial state is
    /// committed. This is safe because the primary callers are idempotent.
    ///
    /// Use this from `Store::put_batch`. Single-record writes use [`Self::add_record`].
    pub fn add_records(&self, records: &[&Record]) -> Result<usize> {
        if records.is_empty() {
            return Ok(0);
        }

        let mut latest_by_key = std::collections::BTreeMap::<String, &Record>::new();
        for &record in records {
            latest_by_key.insert(record.key.clone(), record);
        }

        let mut writer = self.writer.lock().expect("search writer lock poisoned");

        for key in latest_by_key.keys() {
            delete_by_key(&self.index, &writer, self.fields.key, key)?;
        }

        let indexable: Vec<&Record> = latest_by_key
            .values()
            .copied()
            .filter(|r| is_searchable(r))
            .collect();
        if indexable.is_empty() {
            writer.commit()?;
            return Ok(0);
        }

        let total = indexable.len();

        // Stage all documents. Tantivy worker threads handle auto-flushing
        // when their heap share fills up — no explicit chunking needed.
        for (i, record) in indexable.iter().enumerate() {
            if let Err(e) = writer.add_document(record_to_doc(record, &self.fields)) {
                if let Err(rb) = writer.rollback() {
                    tracing::warn!(
                        staged = i,
                        total,
                        "tantivy rollback failed after staging error: {rb:#}"
                    );
                }
                return Err(anyhow::Error::from(e))
                    .with_context(|| format!("search index staging failed at record {i}/{total}"));
            }
        }

        // Single commit — makes all staged documents searchable.
        writer
            .commit()
            .with_context(|| format!("tantivy commit failed after staging {total} records"))?;

        Ok(total)
    }

    /// Flush pending writes and release the writer lock.
    ///
    /// Must be called before dropping `Search` to ensure all indexed documents
    /// are committed. After `close`, the index is safe to reopen.
    pub fn close(self) -> Result<()> {
        let mut writer = self
            .writer
            .into_inner()
            .expect("search writer lock poisoned");
        writer.commit()?;
        Ok(())
    }

    /// Remove a record from the search index by key and commit immediately.
    pub fn delete_key(&self, key: &str) -> Result<()> {
        let mut writer = self.writer.lock().expect("search writer lock poisoned");
        delete_by_key(&self.index, &writer, self.fields.key, key)?;
        writer.commit()?;
        Ok(())
    }

    /// BM25 text search over `key`, `value`, and `tags` fields.
    ///
    /// Returns record keys (not full records) sorted by descending relevance
    /// score. The caller (`Store::search`) is responsible for fetching full
    /// records from SurrealKV.
    ///
    /// Never returns `Err` for user-supplied query strings — malformed queries
    /// are parsed leniently (best-effort, soft errors logged as warnings).
    /// Returns `Err` only for infrastructure failures (reader reload, segment
    /// read). Returns an empty `Vec` when `text` is blank or `limit` is 0.
    ///
    /// Deduplicates results: if the same key appears in multiple tantivy
    /// segments (e.g. before a full index rebuild per M-05-D), it is returned
    /// only once — the highest-scoring occurrence wins.
    pub fn query_keys(&self, text: &str, limit: usize) -> Result<Vec<String>> {
        if text.trim().is_empty() || limit == 0 {
            return Ok(vec![]);
        }

        // Reload picks up any commits written since the last query.
        self.reader.reload()?;
        let searcher = self.reader.searcher();

        // Search key, value, and tags — category/priority/updated_at are
        // filter fields, not free-text search targets.
        let mut parser = QueryParser::for_index(
            &self.index,
            vec![self.fields.key, self.fields.value, self.fields.tags],
        );
        // Boost key matches 2×: a term in the key is a stronger signal than
        // the same term buried in the value body.
        parser.set_field_boost(self.fields.key, 2.0);

        // Lenient parsing: malformed user queries (unclosed parens, trailing
        // operators, unknown field refs) produce a best-effort query rather
        // than an error. Parse warnings are logged but do not fail the call.
        let (query, parse_warnings) = parser.parse_query_lenient(text);
        if !parse_warnings.is_empty() {
            tracing::warn!(
                query = text,
                warnings = ?parse_warnings,
                "query parse warnings — proceeding with best-effort query"
            );
        }

        let top_docs = searcher.search(&query, &TopDocs::with_limit(limit))?;

        let mut keys: Vec<String> = Vec::with_capacity(top_docs.len());
        let mut seen = std::collections::HashSet::new();
        for (_score, doc_address) in top_docs {
            // Corrupted or missing segments are skipped rather than aborting
            // the whole search — partial results are better than an error.
            let doc = match searcher.doc::<TantivyDocument>(doc_address) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to retrieve doc — skipping");
                    continue;
                }
            };
            if let Some(key) = doc.get_first(self.fields.key).and_then(|v| v.as_str()) {
                // Deduplicate: duplicate tantivy entries (pre M-05-D) must
                // not surface the same key twice in search results.
                let key = key.to_string();
                if seen.insert(key.clone()) {
                    keys.push(key);
                }
            } else {
                tracing::warn!(?doc_address, "indexed doc missing key field — skipping");
            }
        }
        Ok(keys)
    }
}

// ── Document construction ─────────────────────────────────────────────────────

/// Returns `false` for `file:*` records whose extension has no tree-sitter
/// grammar — config files, markdown, shell scripts, etc. These records carry
/// empty `entry_points` and imports at Layer 0 and add little BM25 signal on
/// the cold path. All non-file records (gotcha:*, decision:*, dep:*, etc.)
/// return `true`.
fn is_searchable(record: &Record) -> bool {
    let Some(path) = record.key.strip_prefix("file:") else {
        return true;
    };
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    matches!(
        ext,
        "rs" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "py" | "pyi" | "go" | "java"
    )
}

/// Convert a `Record` into a tantivy document ready for indexing.
fn record_to_doc(record: &Record, fields: &Fields) -> TantivyDocument {
    let mut doc = TantivyDocument::default();
    doc.add_text(fields.key, &record.key);
    doc.add_text(fields.value, &record.value);
    doc.add_text(fields.category, category_str(&record.category));
    doc.add_text(fields.tags, record.tags.join(" "));
    doc.add_u64(fields.priority, priority_u64(&record.priority));
    doc.add_u64(fields.updated_at, record.updated_at);
    doc
}

/// Map `Category` to its snake_case string — matches serde representation
/// so tantivy category values are consistent with JSON serialization.
fn category_str(cat: &Category) -> &'static str {
    match cat {
        Category::Gotcha => "gotcha",
        Category::File => "file",
        Category::Decision => "decision",
        Category::Stage => "stage",
        Category::Dependency => "dependency",
        Category::DevNote => "dev_note",
        Category::Session => "session",
        Category::Analytics => "analytics",
    }
}

/// Map `Priority` to a sortable u64 — matches the derived `Ord` ordering.
fn priority_u64(p: &Priority) -> u64 {
    match p {
        Priority::Low => 0,
        Priority::Normal => 1,
        Priority::High => 2,
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

    let key = b.add_text_field("key", TEXT | STORED);
    let value = b.add_text_field("value", TEXT | STORED);
    let category = b.add_text_field("category", STRING | STORED | FAST);
    let tags = b.add_text_field("tags", TEXT | STORED);
    let priority = b.add_u64_field("priority", numeric_stored_fast());
    let updated_at = b.add_u64_field("updated_at", numeric_stored_fast());

    (
        b.build(),
        Fields {
            key,
            value,
            category,
            tags,
            priority,
            updated_at,
        },
    )
}

/// `STORED | FAST` for u64 fields — tantivy requires `NumericOptions`, not
/// the `TextOptions` bitflags, so we build them explicitly.
fn numeric_stored_fast() -> NumericOptions {
    NumericOptions::default().set_stored().set_fast()
}

/// Derive `Fields` from a stored `Schema` by field name.
///
/// Used in [`Search::open`] after obtaining an `Index` — both on create
/// (schema we just wrote) and on reopen (schema read from disk). Resolving
/// by name rather than relying on builder ordinals makes field access
/// correct even if field insertion order ever changes across binary versions.
fn fields_from_schema(s: &Schema) -> Result<Fields> {
    Ok(Fields {
        key: s.get_field("key")?,
        value: s.get_field("value")?,
        category: s.get_field("category")?,
        tags: s.get_field("tags")?,
        priority: s.get_field("priority")?,
        updated_at: s.get_field("updated_at")?,
    })
}

fn delete_by_key(
    index: &Index,
    writer: &IndexWriter,
    key_field: tantivy::schema::Field,
    key: &str,
) -> Result<()> {
    let mut tokenizer = index.tokenizer_for_field(key_field)?;
    let mut stream = tokenizer.token_stream(key);
    let mut tokens = Vec::new();
    stream.process(&mut |token| tokens.push(token.text.clone()));

    if tokens.is_empty() {
        return Ok(());
    }

    if tokens.len() == 1 {
        writer.delete_term(Term::from_field_text(key_field, &tokens[0]));
    } else {
        let terms = tokens
            .into_iter()
            .map(|token| Term::from_field_text(key_field, &token))
            .collect();
        let query = PhraseQuery::new(terms);
        writer.delete_query(Box::new(query))?;
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tantivy::schema::FieldType;
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
            indexing.tokenizer(),
            "raw",
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
        }; // s dropped here — releases the index writer before second open
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

    // ── query_keys helpers ───────────────────────────────────────────────────

    fn make_record(key: &str, value: &str, tags: &[&str]) -> Record {
        use crate::store::record::{
            Category, ConfidenceScore, Priority, QualityScore, RecordLifecycle, RecordSource,
            RecordVersion, StalenessScore,
        };
        Record {
            key: key.to_string(),
            value: value.to_string(),
            category: Category::Gotcha,
            priority: Priority::Normal,
            tags: tags.iter().map(|s| s.to_string()).collect(),
            created_at: 0,
            updated_at: 0,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 0,
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

    fn open_search(dir: &TempDir) -> Search {
        Search::open(&dir.path().join("search_index")).unwrap()
    }

    // ── boundary / guard-rail tests ──────────────────────────────────────────

    #[test]
    fn query_keys_empty_and_whitespace_return_empty() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        let r = make_record("gotcha:foo", "async inference race", &[]);
        s.add_record(&r).unwrap();
        // None of these should match — they must short-circuit before touching
        // the index.
        for blank in ["", " ", "\t", "\n", "  \t  "] {
            let keys = s.query_keys(blank, 10).unwrap();
            assert!(keys.is_empty(), "expected empty for {blank:?}");
        }
    }

    #[test]
    fn query_keys_zero_limit_returns_empty_even_with_matching_docs() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        let r = make_record("gotcha:foo", "async inference race", &[]);
        s.add_record(&r).unwrap();
        assert!(s.query_keys("async", 0).unwrap().is_empty());
    }

    // ── field coverage ───────────────────────────────────────────────────────

    #[test]
    fn query_keys_matches_value_field() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        // "inference" only appears in value, not in key or tags
        let r = make_record(
            "gotcha:async-race",
            "never use inference in async context",
            &[],
        );
        s.add_record(&r).unwrap();
        let keys = s.query_keys("inference", 10).unwrap();
        assert_eq!(keys, vec!["gotcha:async-race"]);
    }

    #[test]
    fn query_keys_matches_tags_field() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        // "performance" only in tags
        let r = make_record(
            "file:engine/mod.rs",
            "engine entry point",
            &["performance", "critical"],
        );
        s.add_record(&r).unwrap();
        let keys = s.query_keys("performance", 10).unwrap();
        assert_eq!(keys, vec!["file:engine/mod.rs"]);
    }

    #[test]
    fn query_keys_matches_key_field() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        // "surrealkv" only in the key; value/tags have different terms
        let r = make_record(
            "gotcha:surrealkv-versioning",
            "retention is always enabled",
            &[],
        );
        s.add_record(&r).unwrap();
        let keys = s.query_keys("surrealkv", 10).unwrap();
        assert_eq!(keys, vec!["gotcha:surrealkv-versioning"]);
    }

    // ── key boost correctness ────────────────────────────────────────────────

    #[test]
    fn query_keys_key_match_ranks_above_value_only_match() {
        // "petgraph" appears in the *key* of record A and only in the *value*
        // of record B. The 2× key boost must push A to rank #1.
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        // Record A: "petgraph" in the key
        let a = make_record(
            "gotcha:petgraph-cycles",
            "watch for cycles in traversal",
            &[],
        );
        // Record B: "petgraph" only in value, noisier text
        let b = make_record(
            "gotcha:graph-general",
            "petgraph handles directed and undirected graphs for traversal and cycle detection",
            &[],
        );
        s.add_record(&a).unwrap();
        s.add_record(&b).unwrap();

        let keys = s.query_keys("petgraph", 10).unwrap();
        assert_eq!(keys.len(), 2, "both records must match");
        assert_eq!(
            keys[0], "gotcha:petgraph-cycles",
            "key match must rank first"
        );
    }

    // ── limit ────────────────────────────────────────────────────────────────

    #[test]
    fn query_keys_limit_caps_results() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        // Use add_records (batch path) — single commit, tests that path too
        let records: Vec<Record> = (0..20)
            .map(|i| {
                make_record(
                    &format!("gotcha:item-{i:02}"),
                    "tokio runtime executor gotcha",
                    &[],
                )
            })
            .collect();
        let refs: Vec<&Record> = records.iter().collect();
        s.add_records(&refs).unwrap();

        assert_eq!(s.query_keys("tokio", 1).unwrap().len(), 1);
        assert_eq!(s.query_keys("tokio", 7).unwrap().len(), 7);
        assert_eq!(s.query_keys("tokio", 20).unwrap().len(), 20);
        // limit > total docs — must return all docs, not error
        assert_eq!(s.query_keys("tokio", 999).unwrap().len(), 20);
    }

    /// Stress test: 500,000 noise docs + 20 sentinel targets (no SurrealKV).
    /// Proves BM25 returns zero false positives from 500k noise records and
    /// that limit enforcement works at that scale.
    ///
    /// `add_records` commits every `COMMIT_CHUNK` (1 000) docs — 500,020
    /// records ≈ 501 commits. Runtime is dominated by tantivy indexing, not
    /// commit overhead (~5–10 ms × 501 ≈ 5 s total commit overhead).
    #[test]
    fn query_keys_500k_noise_zero_false_positives_and_limit_correct() {
        // Use a fixed device_id across all records to avoid 500k RNG calls.
        let device_id = uuid::Uuid::nil();
        let make = |key: &str, value: &str| -> Record {
            use crate::store::record::{
                Category, ConfidenceScore, Priority, QualityScore, RecordLifecycle, RecordSource,
                RecordVersion, StalenessScore,
            };
            Record {
                key: key.to_string(),
                value: value.to_string(),
                category: Category::File,
                priority: Priority::Normal,
                tags: vec![],
                created_at: 0,
                updated_at: 0,
                ref_url: None,
                staleness: StalenessScore::fresh(),
                lifecycle: RecordLifecycle::Active,
                version: RecordVersion {
                    device_id,
                    logical_clock: 1,
                    wall_clock: 0,
                },
                quality: QualityScore::layer0_default(),
                access_count: 0,
                last_accessed: 0,
                source: RecordSource::StaticAnalysis,
                confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
                gap_analysis_score: 0.0,
                payload: None,
            }
        };

        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);

        // 500,000 noise records — realistic Layer 0 corpus at Linux-kernel scale.
        // Content varies per record to create a realistic term distribution.
        let noise: Vec<Record> = (0..500_000_usize)
            .map(|i| make(
                &format!("file:src/module_{i:06}.rs"),
                &format!("module {i} handles initialization routing configuration management dispatch"),
            ))
            .collect();
        s.add_records(&noise.iter().collect::<Vec<_>>()).unwrap();

        // 20 target records containing the unique sentinel term
        let targets: Vec<Record> = (0..20_usize)
            .map(|i| {
                make(
                    &format!("gotcha:target-{i:02}"),
                    &format!("zqx_sentinel_500k_proof unique term record {i} extra text filler"),
                )
            })
            .collect();
        s.add_records(&targets.iter().collect::<Vec<_>>()).unwrap();

        // All 20 targets returned, zero noise leaks through
        let keys = s.query_keys("zqx_sentinel_500k_proof", 20).unwrap();
        assert_eq!(
            keys.len(),
            20,
            "expected 20 hits from 500,020 records, got {}",
            keys.len()
        );

        let target_keys: Vec<String> = targets.iter().map(|r| r.key.clone()).collect();
        for k in &target_keys {
            assert!(keys.contains(k), "missing target key: {k}");
        }
        for k in &keys {
            assert!(
                k.starts_with("gotcha:target-"),
                "noise doc '{k}' leaked into results"
            );
        }

        // Limit enforcement at scale
        let limited = s.query_keys("zqx_sentinel_500k_proof", 5).unwrap();
        assert_eq!(
            limited.len(),
            5,
            "limit=5 must cap results even with 20 matching docs in 500k corpus"
        );

        // Over-limit returns exactly the matching set, not more
        let over = s.query_keys("zqx_sentinel_500k_proof", 999).unwrap();
        assert_eq!(
            over.len(),
            20,
            "limit > match count must return all matches, not panic"
        );
    }

    // ── adversarial / malformed queries ─────────────────────────────────────

    #[test]
    fn query_keys_malformed_trailing_operator_does_not_error() {
        // "inference AND" — trailing boolean operator is a parse error in strict
        // mode. Lenient mode must return results for "inference" without failing.
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        let r = make_record("gotcha:async-race", "inference in async context", &[]);
        s.add_record(&r).unwrap();
        let keys = s.query_keys("inference AND", 10).unwrap();
        assert!(
            keys.contains(&"gotcha:async-race".to_string()),
            "lenient parse must still match 'inference'"
        );
    }

    #[test]
    fn query_keys_unclosed_paren_does_not_error() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        let r = make_record("gotcha:foo", "tokio runtime issue", &[]);
        s.add_record(&r).unwrap();
        // Must not panic or return Err
        let _ = s.query_keys("(tokio", 10).unwrap();
    }

    #[test]
    fn query_keys_unknown_field_ref_does_not_error() {
        // "nonexistent_field:value" — strict parse would error on unknown field.
        // Lenient mode must not propagate the error.
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        let _ = s.query_keys("nonexistent_field:value", 10).unwrap();
    }

    #[test]
    fn query_keys_special_chars_do_not_error() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        for q in ["!@#$%^&*()", "+++---", "\"\"", "\\n\\t", ":::", "NULL\0"] {
            let result = s.query_keys(q, 10);
            assert!(result.is_ok(), "query {q:?} must not return Err");
        }
    }

    #[test]
    fn query_keys_unicode_content_is_searchable() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        // Value contains both ASCII and Unicode; the ASCII term must still match
        let r = make_record(
            "decision:i18n",
            "latency gotcha for データベース queries",
            &[],
        );
        s.add_record(&r).unwrap();
        let keys = s.query_keys("latency", 10).unwrap();
        assert_eq!(keys, vec!["decision:i18n"]);
    }

    // ── duplicate indexing (pre M-05-D) ─────────────────────────────────────

    #[test]
    fn query_keys_duplicate_indexing_returns_key_exactly_once() {
        // Re-indexing the same key should replace the old doc, not duplicate it.
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        let r = make_record("gotcha:dup", "duplicate indexing scenario", &[]);
        s.add_record(&r).unwrap();
        s.add_record(&r).unwrap(); // index same doc a second time
        let keys = s.query_keys("duplicate", 10).unwrap();
        assert_eq!(
            keys,
            vec!["gotcha:dup"],
            "same key should only exist once in the index"
        );
    }

    #[test]
    fn query_keys_updated_record_replaces_old_terms() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);

        let old = make_record("gotcha:update", "oldterm sentinel", &[]);
        let new = make_record("gotcha:update", "newterm sentinel", &[]);

        s.add_record(&old).unwrap();
        assert_eq!(s.query_keys("oldterm", 10).unwrap(), vec!["gotcha:update"]);

        s.add_record(&new).unwrap();
        assert!(s.query_keys("oldterm", 10).unwrap().is_empty());
        assert_eq!(s.query_keys("newterm", 10).unwrap(), vec!["gotcha:update"]);
    }

    #[test]
    fn delete_key_removes_record_from_results() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);

        let r = make_record("gotcha:delete", "delete_me sentinel", &[]);
        s.add_record(&r).unwrap();
        assert_eq!(
            s.query_keys("delete_me", 10).unwrap(),
            vec!["gotcha:delete"]
        );

        s.delete_key("gotcha:delete").unwrap();
        assert!(s.query_keys("delete_me", 10).unwrap().is_empty());
    }

    // ── read-after-write ─────────────────────────────────────────────────────

    #[test]
    fn query_keys_immediately_searchable_after_add_record() {
        // Verifies Manual reload policy + explicit reload() gives immediate
        // read-after-write without any sleep or external coordination.
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        let r = make_record("gotcha:immediate", "petgraph traversal depth limit", &[]);
        s.add_record(&r).unwrap();
        let keys = s.query_keys("petgraph", 10).unwrap();
        assert_eq!(keys, vec!["gotcha:immediate"]);
    }

    #[test]
    fn query_keys_sees_all_records_after_add_records_batch() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        let records: Vec<Record> = (0..10)
            .map(|i| {
                make_record(
                    &format!("gotcha:batch-{i}"),
                    "batchwrite rayon parallel",
                    &[],
                )
            })
            .collect();
        let refs: Vec<&Record> = records.iter().collect();
        s.add_records(&refs).unwrap();
        let keys = s.query_keys("rayon", 20).unwrap();
        assert_eq!(
            keys.len(),
            10,
            "all 10 batch records must be searchable immediately"
        );
    }

    // ── no match ─────────────────────────────────────────────────────────────

    #[test]
    fn query_keys_no_match_returns_empty() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        let r = make_record("gotcha:foo", "unrelated content about bananas", &[]);
        s.add_record(&r).unwrap();
        assert!(s
            .query_keys("surrealdb_not_in_any_record", 10)
            .unwrap()
            .is_empty());
    }

    // ── result correctness ───────────────────────────────────────────────────

    #[test]
    fn query_keys_returns_key_strings_not_values() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        let r = make_record(
            "decision:use-surrealkv",
            "SurrealKV chosen for durability guarantees",
            &[],
        );
        s.add_record(&r).unwrap();
        let keys = s.query_keys("durability", 10).unwrap();
        assert_eq!(
            keys,
            vec!["decision:use-surrealkv"],
            "must return the key string, not the value body"
        );
    }

    #[test]
    fn query_keys_multi_word_query_matches_records_with_all_terms() {
        let dir = TempDir::new().unwrap();
        let s = open_search(&dir);
        // Record with both terms
        let both = make_record("gotcha:both-terms", "tantivy petgraph integration", &[]);
        // Record with only one term
        let one = make_record("gotcha:one-term", "tantivy only record", &[]);
        s.add_record(&both).unwrap();
        s.add_record(&one).unwrap();
        // Both-term record must score highest
        let keys = s.query_keys("tantivy petgraph", 10).unwrap();
        assert!(!keys.is_empty());
        assert_eq!(
            keys[0], "gotcha:both-terms",
            "record containing both query terms must rank first"
        );
    }
}
