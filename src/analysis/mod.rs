// Layer 0 — static analysis engine (M-06)
// Parallel file walker (ignore + rayon), tree-sitter parsing,
// git2 history mining, dependency parsing (Cargo.toml, package.json, go.mod)
// Target: <200ms on a 250-file Rust project

pub mod parser;
pub mod walker;

pub use parser::{parse_file, parse_files_parallel, StaticFileAnalysis};
pub use walker::{Language, WalkedFile, Walker};
