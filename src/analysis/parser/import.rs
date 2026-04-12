//! Structured import representation for cross-file resolution.
//!
//! Raw import strings (`Vec<String>`) lack the structural information needed
//! for production-grade import resolution across 12 languages. This module
//! provides `ImportStatement` — a typed representation that carries the import
//! path, its structural classification, and source location.
//!
//! Each language parser produces `Vec<ImportStatement>` during tree-sitter
//! extraction. The classification into `ImportKind` happens at parse time,
//! eliminating the need for a separate `is_external_import()` pass during
//! edge construction.

use serde::{Deserialize, Serialize};

/// A single import statement extracted from source code by tree-sitter.
///
/// Carries enough information for the resolver to decide whether to attempt
/// resolution, and for debugging/IDE integration via the line number.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImportStatement {
    /// The raw path/module string as extracted from source.
    ///
    /// - **Rust**: the `use` argument without the `as` alias (e.g. `crate::store::db`)
    /// - **Python**: the dotted module name (e.g. `django.conf` or `.helpers`)
    /// - **TypeScript/JavaScript**: the module specifier without quotes (e.g. `./utils` or `react`)
    /// - **Go**: the import path without quotes (e.g. `fmt` or `github.com/user/pkg`)
    /// - **Java**: the fully-qualified class/package name (e.g. `java.util.List`)
    /// - **C/C++**: the filename inside the include directive (e.g. `stdio.h` or `myheader.h`)
    /// - **Ruby**: the argument to `require`/`require_relative`
    /// - **Scala**: the import path without `import ` prefix
    /// - **Elixir**: the module name from `import`/`alias`/`use`/`require`
    /// - **Haskell**: the module name (e.g. `Data.List`)
    pub path: String,

    /// Structural classification that determines resolver behavior.
    pub kind: ImportKind,

    /// Line number in the source file where the import appears (1-indexed).
    /// Used for debugging and future IDE integration. 0 if unknown.
    pub line: u32,
}

/// Classification of an import statement that determines how the resolver
/// handles it.
///
/// An import can only have one kind. Priority when multiple could apply:
/// `External` > `Relative` > `Wildcard` > `Normal`. External imports are
/// never resolved; relative imports use the importing file's directory as
/// base; wildcards may match multiple targets in future phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImportKind {
    /// Standard import (e.g. `use foo::bar;`, `import X`, `#include "foo.h"`).
    /// The resolver will attempt to resolve this against the file index.
    Normal,

    /// Wildcard / glob import (e.g. `use foo::*;`, `from x import *`, `import com.acme.*`).
    /// The resolver will attempt resolution but may match multiple targets.
    Wildcard,

    /// Relative import that resolves from the importing file's directory.
    /// Used by Python (`.x`, `..x`), Ruby (`require_relative`), C (`#include "..."`),
    /// and TS/JS (`./foo`, `../bar`).
    Relative,

    /// External / third-party import that should be skipped by the resolver.
    /// (e.g. Rust non-crate imports, TS/JS bare specifiers, C angle-bracket system headers)
    External,
}

impl ImportStatement {
    /// Create a new import statement with all fields specified.
    pub fn new(path: impl Into<String>, kind: ImportKind, line: u32) -> Self {
        Self {
            path: path.into(),
            kind,
            line,
        }
    }

    /// Convenience: create a Normal import at the given line.
    #[cfg(test)]
    pub fn normal(path: impl Into<String>, line: u32) -> Self {
        Self::new(path, ImportKind::Normal, line)
    }

    /// Convenience: create an External import at the given line.
    #[cfg(test)]
    pub fn external(path: impl Into<String>, line: u32) -> Self {
        Self::new(path, ImportKind::External, line)
    }
}
