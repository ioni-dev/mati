//! Parallel file walker for Layer 0 static analysis.
//!
//! Uses `ignore::WalkParallel` (same engine as ripgrep) for parallel,
//! gitignore-aware directory traversal. Results stream to the caller via an
//! `mpsc` channel so downstream parsing can start before the walk completes.
//!
//! # Architecture
//!
//! ```text
//! Walker::walk_channel()
//!     │
//!     ├── spawns std::thread (WalkParallel::visit is blocking/sync)
//!     │       │
//!     │       ├── VisitorBuilder::build() — one FileVisitor per worker thread
//!     │       │
//!     │       └── FileVisitor::visit() — per-entry filtering + local buffering
//!     │               │
//!     │               └── flush every FLUSH_THRESHOLD entries → mpsc::Sender
//!     │                   Drop flush handles tail entries
//!     │
//!     └── returns mpsc::Receiver<WalkedFile>  (parser consumes while walk runs)
//!
//! Walker::walk() — thin wrapper: collect channel → sort → Vec<WalkedFile>
//! ```
//!
//! ## Why thread-local buffering?
//!
//! `mpsc::Sender::send()` acquires an internal lock on every call. With 8
//! threads and 80k files, 80k individual sends ≈ 16ms of contention overhead.
//! Flushing every [`FLUSH_THRESHOLD`] entries reduces sends to ~2 500,
//! cutting that overhead to ~500µs while still giving the receiver batches
//! early enough for meaningful parse pipelining.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};

use anyhow::Result;
use ignore::{DirEntry, ParallelVisitor, ParallelVisitorBuilder, WalkBuilder, WalkState};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default maximum file size accepted by the walker (bytes).
/// Files larger than this are silently skipped — they are almost always
/// generated artefacts (minified JS, compiled output) not worth parsing.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024; // 1 MiB

/// Number of [`WalkedFile`] entries a [`FileVisitor`] accumulates locally
/// before flushing to the shared channel. Balances streaming latency against
/// `mpsc` lock contention on large repos.
const FLUSH_THRESHOLD: usize = 32;

// ── Public types ──────────────────────────────────────────────────────────────

/// Programming language detected from file extension.
///
/// All variants with a corresponding tree-sitter grammar are explicitly named.
/// Everything else — config files, markdown, shell scripts, etc. — maps to
/// [`Language::Unknown`] and is still walked but not parsed by tree-sitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    Rust,
    TypeScript,
    JavaScript,
    Python,
    Go,
    Java,
    Unknown,
}

/// A single file discovered by the walker.
#[derive(Debug, Clone)]
pub struct WalkedFile {
    /// Absolute path — used for opening the file for parsing.
    pub abs_path: PathBuf,
    /// Repo-relative path with forward slashes — used as the mati store key
    /// suffix: `file:<rel_path>`.
    pub rel_path: String,
    pub language: Language,
    pub size_bytes: u64,
}

// ── Walker ────────────────────────────────────────────────────────────────────

/// Parallel, gitignore-aware file walker.
///
/// # Example
/// ```no_run
/// use mati_core::analysis::Walker;
///
/// let walker = Walker::new("/path/to/repo");
///
/// // Streaming — parser can consume while walk is still in progress.
/// for file in walker.walk_channel().unwrap() {
///     println!("{} ({:?})", file.rel_path, file.language);
/// }
///
/// // Batch — sorted Vec, useful when you need the full set before proceeding.
/// let files = walker.walk().unwrap();
/// ```
pub struct Walker {
    root: PathBuf,
    max_file_size: u64,
    follow_symlinks: bool,
}

impl Walker {
    /// Create a walker rooted at `root` with default settings.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            follow_symlinks: false,
        }
    }

    /// Override the maximum file size. Files larger than `bytes` are skipped.
    pub fn max_file_size(mut self, bytes: u64) -> Self {
        self.max_file_size = bytes;
        self
    }

    /// Whether to follow symbolic links. Default: `false` (avoids cycles).
    pub fn follow_symlinks(mut self, yes: bool) -> Self {
        self.follow_symlinks = yes;
        self
    }

    /// Primary interface: start the walk and return a channel receiver.
    ///
    /// The walk runs on a background thread; the caller can begin consuming
    /// [`WalkedFile`] items immediately while traversal is still in progress.
    /// The channel closes automatically when the walk finishes.
    ///
    /// Returns `Err` if `root` is not an accessible directory.
    pub fn walk_channel(&self) -> Result<mpsc::Receiver<WalkedFile>> {
        if !self.root.is_dir() {
            anyhow::bail!(
                "walk root is not a directory: {}",
                self.root.display()
            );
        }

        let (tx, rx) = mpsc::channel::<WalkedFile>();

        let walk_root = self.root.clone();
        let root_arc = Arc::new(self.root.clone());
        let max_file_size = self.max_file_size;
        let follow_symlinks = self.follow_symlinks;

        // Spawn a dedicated thread: WalkParallel::visit is blocking and spawns
        // its own worker threads internally. We must not block the async
        // runtime (tokio) — always call walk_channel from a spawn_blocking
        // context when used from async code.
        std::thread::spawn(move || {
            let walk = WalkBuilder::new(&walk_root)
                // Include hidden files — .gitignore is the authority on what
                // to skip; hiding .github/, .claude/ etc. would lose coverage.
                .hidden(false)
                .follow_links(follow_symlinks)
                // All git-related ignore rules enabled (default, stated for clarity).
                .git_ignore(true)
                .git_global(true)
                .git_exclude(true)
                .build_parallel();

            let mut builder = VisitorBuilder {
                // Arc<Mutex<Sender>> satisfies the Send + Sync bound required
                // by ParallelVisitorBuilder. Each FileVisitor clones the
                // Sender out of the Mutex exactly once in build().
                tx: Arc::new(Mutex::new(tx)),
                root: root_arc,
                max_file_size,
            };

            walk.visit(&mut builder);
            // builder drops here → Arc<Mutex<Sender>> drops → all Sender
            // clones held by FileVisitors have already been dropped when their
            // threads finished → channel closes → receiver exhausts cleanly.
        });

        Ok(rx)
    }

    /// Batch interface: collect the full walk into a sorted `Vec`.
    ///
    /// Useful for callers that need the complete file list before proceeding
    /// (tests, dep parsing, one-shot reporting). Prefer [`walk_channel`] when
    /// results will be piped into a parallel processing stage.
    ///
    /// [`walk_channel`]: Walker::walk_channel
    pub fn walk(&self) -> Result<Vec<WalkedFile>> {
        let mut files: Vec<WalkedFile> = self.walk_channel()?.into_iter().collect();
        // Deterministic order: sort by repo-relative path so downstream
        // consumers (store writes, tests) produce repeatable output.
        files.sort_unstable_by(|a, b| a.rel_path.cmp(&b.rel_path));
        Ok(files)
    }
}

// ── Internal visitor types ────────────────────────────────────────────────────

/// Builds a [`FileVisitor`] for each worker thread spawned by `WalkParallel`.
///
/// Must implement `Send + Sync`:
/// - `Arc<Mutex<mpsc::Sender<_>>>`: Send (Arc<T>: Send when T: Send+Sync) +
///   Sync (Mutex<T>: Sync when T: Send, mpsc::Sender<T>: Send) ✓
/// - `Arc<PathBuf>`: Send + Sync ✓
/// - `u64`: Send + Sync ✓
struct VisitorBuilder {
    tx: Arc<Mutex<mpsc::Sender<WalkedFile>>>,
    root: Arc<PathBuf>,
    max_file_size: u64,
}

impl<'s> ParallelVisitorBuilder<'s> for VisitorBuilder {
    fn build(&mut self) -> Box<dyn ParallelVisitor + 's> {
        // Clone the Sender once per thread. The Mutex is held only for the
        // duration of clone() — essentially free.
        let tx = self.tx.lock().expect("VisitorBuilder mutex poisoned").clone();
        Box::new(FileVisitor {
            local: Vec::with_capacity(FLUSH_THRESHOLD),
            tx,
            root: Arc::clone(&self.root),
            max_file_size: self.max_file_size,
        })
    }
}

/// Per-thread visitor. Accumulates entries locally and flushes in batches to
/// reduce `mpsc` lock contention on high-file-count repos.
struct FileVisitor {
    /// Thread-local accumulator — flushed every FLUSH_THRESHOLD entries and
    /// on Drop (tail flush for the final partial batch).
    local: Vec<WalkedFile>,
    tx: mpsc::Sender<WalkedFile>,
    root: Arc<PathBuf>,
    max_file_size: u64,
}

impl FileVisitor {
    /// Send all buffered entries to the channel.
    ///
    /// Returns `false` if the receiver was dropped — the caller should return
    /// [`WalkState::Quit`] to stop the walk early.
    fn flush(&mut self) -> bool {
        // mem::take swaps self.local with an empty Vec, giving us owned
        // iteration without holding a borrow on self.local. Any remaining
        // items are dropped when `batch` goes out of scope.
        for file in std::mem::take(&mut self.local) {
            if self.tx.send(file).is_err() {
                return false;
            }
        }
        true
    }
}

impl Drop for FileVisitor {
    fn drop(&mut self) {
        // Tail flush: send any entries accumulated since the last threshold flush.
        self.flush();
    }
}

impl ParallelVisitor for FileVisitor {
    fn visit(&mut self, entry: Result<DirEntry, ignore::Error>) -> WalkState {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("walker: entry error: {e}");
                return WalkState::Continue;
            }
        };

        // DirEntry::file_type() is free on Linux (returned by readdir).
        // On macOS it may require a stat; ignore handles the caching.
        let file_type = match entry.file_type() {
            Some(ft) => ft,
            None => return WalkState::Continue, // stdin / unknown — skip
        };

        // Directories are walk nodes, not files. The ignore crate handles
        // pruning gitignored directories via WalkState::Skip internally.
        if file_type.is_dir() {
            return WalkState::Continue;
        }

        let path = entry.path();

        // Extension-based binary filter: checked before metadata() to avoid
        // unnecessary syscalls on clearly unanalysable files.
        if is_binary_extension(path) {
            return WalkState::Continue;
        }

        // DirEntry::metadata() reuses cached data where available (inode
        // info from readdir on Linux). Unavoidable for size filtering.
        let size_bytes = match entry.metadata() {
            Ok(m) => m.len(),
            Err(e) => {
                tracing::warn!(
                    "walker: cannot read metadata for {}: {e}",
                    path.display()
                );
                return WalkState::Continue;
            }
        };

        if size_bytes > self.max_file_size {
            tracing::debug!(
                "walker: skipping large file {} ({size_bytes} bytes)",
                path.display()
            );
            return WalkState::Continue;
        }

        self.local.push(WalkedFile {
            abs_path: path.to_path_buf(),
            rel_path: make_rel_path(&self.root, path),
            language: detect_language(path),
            size_bytes,
        });

        if self.local.len() >= FLUSH_THRESHOLD {
            if !self.flush() {
                return WalkState::Quit;
            }
        }

        WalkState::Continue
    }
}

// ── Helper functions ──────────────────────────────────────────────────────────

/// Compute a forward-slash repo-relative path for use as the mati store key.
fn make_rel_path(root: &Path, abs: &Path) -> String {
    match abs.strip_prefix(root) {
        Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
        Err(_) => {
            // Should never happen — all entries come from walking root.
            tracing::debug!(
                "walker: {} is not under root {}; using absolute path",
                abs.display(),
                root.display()
            );
            abs.to_string_lossy().replace('\\', "/")
        }
    }
}

/// Detect programming language from file extension.
///
/// Only languages with a tree-sitter grammar in this project are explicitly
/// matched. Config files, markdown, shell scripts, etc. return
/// [`Language::Unknown`] — they are still walked and stored but not parsed.
pub fn detect_language(path: &Path) -> Language {
    match path.extension().and_then(|e| e.to_str()) {
        Some("rs") => Language::Rust,
        Some("ts" | "tsx") => Language::TypeScript,
        Some("js" | "jsx" | "mjs" | "cjs") => Language::JavaScript,
        Some("py" | "pyi") => Language::Python,
        Some("go") => Language::Go,
        Some("java") => Language::Java,
        _ => Language::Unknown,
    }
}

/// Return `true` for extensions that indicate binary or generated files that
/// are never useful for tree-sitter analysis or mati knowledge records.
///
/// `.svg` is intentionally excluded from this list — it is XML text and may
/// appear in documentation or assets that are relevant to know about.
/// `.json` is also excluded — `package.json`, `tsconfig.json` etc. are
/// valuable for dependency analysis (M-06-E).
fn is_binary_extension(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some(
            // Raster images
            "png" | "jpg" | "jpeg" | "gif" | "ico" | "webp" | "bmp" | "tiff"
            // Compiled / native artefacts
            | "o" | "a" | "so" | "dylib" | "dll" | "exe" | "wasm"
            | "class" | "jar"
            // Archives
            | "zip" | "tar" | "gz" | "bz2" | "xz" | "7z"
            // Media
            | "mp3" | "mp4" | "wav" | "avi" | "mkv" | "mov"
            // Fonts
            | "ttf" | "woff" | "woff2" | "otf" | "eot"
            // Generated lock / snapshot files — large, not useful for analysis
            | "lock" | "snap"
            // Databases
            | "db" | "sqlite" | "sqlite3"
            // Documents
            | "pdf"
        )
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Write `content` to `dir/path`, creating intermediate directories.
    fn write(dir: &Path, rel: &str, content: &str) {
        let full = dir.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, content).unwrap();
    }

    /// Collect rel_paths from a walk result, sorted.
    fn rel_paths(files: &[WalkedFile]) -> Vec<&str> {
        let mut paths: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
        paths.sort_unstable();
        paths
    }

    // ── Walker behaviour ──────────────────────────────────────────────────────

    #[test]
    fn walk_returns_all_source_files() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "src/main.rs", "fn main() {}");
        write(dir.path(), "src/lib.py", "def foo(): pass");
        write(dir.path(), "app/index.ts", "export {}");

        let files = Walker::new(dir.path()).walk().unwrap();
        let paths = rel_paths(&files);

        assert!(paths.contains(&"app/index.ts"));
        assert!(paths.contains(&"src/lib.py"));
        assert!(paths.contains(&"src/main.rs"));
        assert_eq!(files.len(), 3);
    }

    #[test]
    fn walk_output_is_sorted_by_rel_path() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "z.rs", "");
        write(dir.path(), "a.rs", "");
        write(dir.path(), "m.rs", "");

        let files = Walker::new(dir.path()).walk().unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();

        assert_eq!(paths, vec!["a.rs", "m.rs", "z.rs"]);
    }

    #[test]
    fn walk_empty_dir_returns_empty_vec() {
        let dir = TempDir::new().unwrap();
        let files = Walker::new(dir.path()).walk().unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn walk_nested_dirs_have_correct_rel_path() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "a/b/c/deep.rs", "");

        let files = Walker::new(dir.path()).walk().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].rel_path, "a/b/c/deep.rs");
    }

    #[test]
    fn walk_rel_path_does_not_start_with_slash() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "src/foo.rs", "");

        let files = Walker::new(dir.path()).walk().unwrap();
        assert_eq!(files.len(), 1);
        assert!(!files[0].rel_path.starts_with('/'));
    }

    #[test]
    fn walk_respects_gitignore() {
        let dir = TempDir::new().unwrap();
        // ignore crate only reads .gitignore when it detects a git root.
        // A .git directory (even empty) is sufficient for detection.
        fs::create_dir(dir.path().join(".git")).unwrap();
        write(dir.path(), ".gitignore", "ignored.rs\ntarget/\n");
        write(dir.path(), "kept.rs", "");
        write(dir.path(), "ignored.rs", "");
        write(dir.path(), "target/debug/binary", "");

        let files = Walker::new(dir.path()).walk().unwrap();
        let paths = rel_paths(&files);

        // .gitignore itself is included (it's a text file)
        assert!(paths.contains(&"kept.rs"));
        assert!(!paths.contains(&"ignored.rs"), "ignored.rs should be excluded by .gitignore");
        assert!(
            paths.iter().all(|p| !p.starts_with("target/")),
            "target/ should be excluded by .gitignore"
        );
    }

    #[test]
    fn walk_excludes_files_over_size_limit() {
        let dir = TempDir::new().unwrap();
        let big = dir.path().join("big.rs");
        // Write exactly max_file_size + 1 bytes
        fs::write(&big, vec![b'x'; 513]).unwrap();
        write(dir.path(), "small.rs", "fn main() {}");

        let files = Walker::new(dir.path())
            .max_file_size(512)
            .walk()
            .unwrap();

        let paths = rel_paths(&files);
        assert!(paths.contains(&"small.rs"));
        assert!(!paths.contains(&"big.rs"), "big.rs should be excluded by size limit");
    }

    #[test]
    fn walk_includes_file_exactly_at_size_limit() {
        let dir = TempDir::new().unwrap();
        let exact = dir.path().join("exact.rs");
        fs::write(&exact, vec![b'x'; 512]).unwrap();

        let files = Walker::new(dir.path())
            .max_file_size(512)
            .walk()
            .unwrap();

        assert_eq!(files.len(), 1, "file at exact size limit should be included");
    }

    #[test]
    fn walk_excludes_binary_extensions() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "image.png", "not really a png");
        write(dir.path(), "archive.zip", "not really a zip");
        write(dir.path(), "lib.so", "");
        write(dir.path(), "Cargo.lock", "generated");
        write(dir.path(), "source.rs", "fn main() {}");

        let files = Walker::new(dir.path()).walk().unwrap();
        let paths = rel_paths(&files);

        assert!(paths.contains(&"source.rs"));
        assert!(!paths.contains(&"image.png"));
        assert!(!paths.contains(&"archive.zip"));
        assert!(!paths.contains(&"lib.so"));
        assert!(!paths.contains(&"Cargo.lock"));
    }

    #[test]
    fn walk_does_not_yield_directories() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        write(dir.path(), "subdir/file.rs", "");

        let files = Walker::new(dir.path()).walk().unwrap();

        for f in &files {
            assert!(
                f.abs_path.is_file(),
                "walker yielded a directory: {}",
                f.rel_path
            );
        }
    }

    #[test]
    fn walk_channel_and_walk_return_same_files() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "a.rs", "");
        write(dir.path(), "b.py", "");
        write(dir.path(), "c.ts", "");

        let walker = Walker::new(dir.path());

        // Collect channel output (unordered)
        let mut channel_paths: Vec<String> = walker
            .walk_channel()
            .unwrap()
            .into_iter()
            .map(|f| f.rel_path)
            .collect();
        channel_paths.sort_unstable();

        // Batch walk (sorted)
        let batch_paths: Vec<String> =
            walker.walk().unwrap().into_iter().map(|f| f.rel_path).collect();

        assert_eq!(channel_paths, batch_paths);
    }

    #[test]
    fn walk_errors_on_nonexistent_root() {
        let result = Walker::new("/nonexistent/path/that/does/not/exist").walk();
        assert!(result.is_err());
    }

    #[test]
    fn walk_size_bytes_is_accurate() {
        let dir = TempDir::new().unwrap();
        let content = "fn main() { println!(\"hello\"); }";
        write(dir.path(), "main.rs", content);

        let files = Walker::new(dir.path()).walk().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].size_bytes, content.len() as u64);
    }

    // ── detect_language ───────────────────────────────────────────────────────

    #[test]
    fn detect_language_rust() {
        assert_eq!(detect_language(Path::new("foo.rs")), Language::Rust);
    }

    #[test]
    fn detect_language_typescript() {
        assert_eq!(detect_language(Path::new("app.ts")), Language::TypeScript);
        assert_eq!(detect_language(Path::new("comp.tsx")), Language::TypeScript);
    }

    #[test]
    fn detect_language_javascript() {
        assert_eq!(detect_language(Path::new("index.js")), Language::JavaScript);
        assert_eq!(detect_language(Path::new("mod.mjs")), Language::JavaScript);
        assert_eq!(detect_language(Path::new("cjs.cjs")), Language::JavaScript);
    }

    #[test]
    fn detect_language_python() {
        assert_eq!(detect_language(Path::new("main.py")), Language::Python);
        assert_eq!(detect_language(Path::new("types.pyi")), Language::Python);
    }

    #[test]
    fn detect_language_go() {
        assert_eq!(detect_language(Path::new("main.go")), Language::Go);
    }

    #[test]
    fn detect_language_java() {
        assert_eq!(detect_language(Path::new("Main.java")), Language::Java);
    }

    #[test]
    fn detect_language_unknown_for_config_and_text() {
        assert_eq!(detect_language(Path::new("Cargo.toml")), Language::Unknown);
        assert_eq!(detect_language(Path::new("README.md")), Language::Unknown);
        assert_eq!(detect_language(Path::new("script.sh")), Language::Unknown);
        assert_eq!(detect_language(Path::new(".env")), Language::Unknown);
        assert_eq!(detect_language(Path::new("no_extension")), Language::Unknown);
    }

    // ── is_binary_extension ───────────────────────────────────────────────────

    #[test]
    fn binary_extensions_are_excluded() {
        let binaries = [
            "image.png",
            "photo.jpg",
            "archive.zip",
            "lib.so",
            "binary.exe",
            "module.wasm",
            "Cargo.lock",
            "yarn.lock",
            "snapshot.snap",
            "data.db",
            "doc.pdf",
        ];
        for name in binaries {
            assert!(
                is_binary_extension(Path::new(name)),
                "{name} should be detected as binary"
            );
        }
    }

    #[test]
    fn source_extensions_are_not_binary() {
        let sources = [
            "main.rs",
            "app.py",
            "index.ts",
            "main.go",
            "package.json",
            "Cargo.toml",
            "README.md",
            "style.css",
            "image.svg",
        ];
        for name in sources {
            assert!(
                !is_binary_extension(Path::new(name)),
                "{name} should not be detected as binary"
            );
        }
    }
}
