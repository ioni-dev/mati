//! Repo-wide invariants that prose alone kept getting wrong.
//!
//! Every module in this crate tests its own behaviour. The rules below are
//! different: they are properties of the *whole source tree*, so no single
//! module owns them, and each was stated in prose long before anything checked
//! it. All of them turned out to be false in prose and silently drifting in
//! code.
//!
//! - [`gotcha_write_sites`] — "all create/edit/tombstone paths go through
//!   `store::gotcha_ops`".
//! - [`zero_network`] — "the OSS binary never phones home. Period."
//! - [`documented_caller_claims`] — a doc comment that names a caller must
//!   actually have one.
//!
//! All are implemented as source scans over `src/**/*.rs`. That approach has
//! real limits and each module states its own; read them before trusting a
//! green run. The scans deliberately skip this file — it quotes every marker
//! string it searches for and would otherwise match itself.

use std::path::{Path, PathBuf};

/// This file. Excluded from every scan below: it contains the marker strings
/// verbatim, so including it would make every scan self-referential.
const THIS_FILE: &str = "src/invariants.rs";

/// Every `.rs` file under `src/`, as `(repo-relative path, contents)`, sorted,
/// EXCLUDING files that only ever compile under `cfg(test)`.
///
/// `src/` — not the whole repo — because that is what ships: the `mati` binary
/// (`src/main.rs` + `src/cli/`) and the `mati_core` library. `benches/`,
/// `tests/` and `scripts/` are developer-only and are not linked into the
/// released artifact. A file declared as `#[cfg(test)] mod <name>;` in its
/// parent — e.g. `src/store/db/tests.rs`, via `#[cfg(test)] mod tests;` in
/// `src/store/db/mod.rs` — doesn't ship either, for the same reason; see
/// [`test_only_files`].
fn rust_sources() -> Vec<(String, String)> {
    let mut out = raw_rust_sources();
    let hidden = test_only_files(&out);
    out.retain(|(path, _)| !hidden.contains(path));
    out
}

/// Every `.rs` file under `src/` (except this one), unfiltered — includes
/// files [`rust_sources`] hides as test-only. Exists so the self-checks on
/// [`test_only_files`]'s stated limits can inspect the files it hides, not
/// just the ones it doesn't.
fn raw_rust_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src/ subdirectory is readable") {
            let path = entry.expect("readable directory entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .expect("path is under CARGO_MANIFEST_DIR")
                .to_string_lossy()
                .replace('\\', "/");
            if rel == THIS_FILE {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source file is valid UTF-8");
            out.push((rel, text));
        }
    }
    out.sort();
    out
}

/// Files reachable ONLY through a `#[cfg(test)] mod <name>;` declaration —
/// the separate-file form, not the inline `#[cfg(test)] mod <name> { ... }`
/// block [`production_lines`] already skips within a single file.
///
/// Detected as a plain two-line text pattern: a line that is exactly
/// `#[cfg(test)]`, immediately followed by a line that is exactly
/// `mod <ident>;`. Resolved to a path with [`module_file_candidates`] and
/// kept only if that path is actually present in `all`.
///
/// # What this does not see
///
/// - **Split attributes or extra lines between `#[cfg(test)]` and `mod`**
///   (e.g. a doc comment, or `#[cfg(test)]` on its own line followed by
///   `#[allow(dead_code)]` then `mod x;`) are not recognized — the pattern is
///   exactly two adjacent lines. None of today's `#[cfg(test)] mod <name>;`
///   declarations are split this way (checked in
///   `every_cfg_test_mod_declaration_is_the_two_line_form` below); a future
///   one that is would silently fall back to being scanned as production
///   code, same as before this function existed.
/// - **Does not recurse.** A hidden file that itself declares a further
///   SEPARATE-FILE submodule (`mod x;`) would need that submodule to carry
///   its own `#[cfg(test)]` gate to be caught, since [`rust_sources`] only
///   calls this once over the top-level file list. None of today's hidden
///   files does (checked below). An INLINE `mod x { ... }` inside a hidden
///   file — grouping related tests, e.g. — needs nothing further: it isn't a
///   separate file, so it's already covered by hiding the one it's in.
/// - **A `#[cfg(test)]`-gated inline block still relies on [`production_lines`]**,
///   not this function — this only handles the separate-file form.
fn test_only_files(all: &[(String, String)]) -> std::collections::BTreeSet<String> {
    let mut hidden = std::collections::BTreeSet::new();
    for (file, src) in all {
        let lines: Vec<&str> = src.lines().collect();
        for i in 0..lines.len().saturating_sub(1) {
            if lines[i].trim() != "#[cfg(test)]" {
                continue;
            }
            let Some(name) = lines[i + 1]
                .trim()
                .strip_prefix("mod ")
                .and_then(|s| s.strip_suffix(';'))
            else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                continue;
            }
            for candidate in module_file_candidates(file, name) {
                if all.iter().any(|(p, _)| *p == candidate) {
                    hidden.insert(candidate);
                }
            }
        }
    }
    hidden
}

/// The path(s) Rust's module resolution would consider for `mod <name>;`
/// declared from `file`, per the standard 2018+ rule: `src/lib.rs` and
/// `src/main.rs` resolve siblings in `src/`; `.../mod.rs` resolves siblings
/// in its own directory; any other `.../foo.rs` resolves siblings under
/// `.../foo/`.
fn module_file_candidates(file: &str, name: &str) -> Vec<String> {
    let dir = if file == "src/lib.rs" || file == "src/main.rs" {
        "src".to_string()
    } else if let Some(d) = file.strip_suffix("/mod.rs") {
        d.to_string()
    } else {
        file.strip_suffix(".rs").unwrap_or(file).to_string()
    };
    vec![format!("{dir}/{name}.rs"), format!("{dir}/{name}/mod.rs")]
}

/// Pins the two stated limits of [`test_only_files`] against the actual tree,
/// so a future file that breaks either assumption fails loudly here instead
/// of silently falling back to being scanned as production code.
#[cfg(test)]
mod test_only_files_checks {
    use super::{module_file_candidates, raw_rust_sources, test_only_files};

    /// Limit 1: every `#[cfg(test)]` immediately followed (within 5 lines) by
    /// a separate-file `mod <ident>;` declaration is followed *immediately*
    /// (line i+1, no gap) — the exact shape [`test_only_files`] matches.
    ///
    /// The 5-line lookahead is generous on purpose: it exists only to catch a
    /// split form should one appear, not because 5 is significant.
    #[test]
    fn every_cfg_test_mod_declaration_is_the_two_line_form() {
        let mut split_forms = Vec::new();
        for (file, src) in raw_rust_sources() {
            let lines: Vec<&str> = src.lines().collect();
            for i in 0..lines.len() {
                if lines[i].trim() != "#[cfg(test)]" {
                    continue;
                }
                let is_mod_decl = |l: &str| {
                    let l = l.trim();
                    l.strip_prefix("mod ")
                        .and_then(|s| s.strip_suffix(';'))
                        .is_some()
                };
                let adjacent = lines.get(i + 1).is_some_and(|l| is_mod_decl(l));
                if adjacent {
                    continue;
                }
                for l in lines.iter().skip(i + 2).take(4) {
                    if is_mod_decl(l) {
                        split_forms.push(format!("{file}:{}", i + 1));
                        break;
                    }
                }
            }
        }
        assert!(
            split_forms.is_empty(),
            "SPLIT #[cfg(test)] mod DECLARATION(S) — test_only_files() only \
             matches the immediate two-line form and would silently miss \
             these, scanning the file they gate as production code:\n\
             {split_forms:#?}"
        );
    }

    /// Limit 2: no file [`test_only_files`] hides declares a SEPARATE-FILE
    /// submodule of its own (`mod <ident>;`) — the hiding is one level deep
    /// and does not recurse.
    ///
    /// An inline `mod <ident> { ... }` inside an already-hidden file is fine
    /// and common (e.g. a nested `mod some_scenario { ... }` grouping related
    /// `#[test]` fns within `tests.rs`) — it declares no new *file*, so there
    /// is nothing further for [`rust_sources`] to fail to hide.
    #[test]
    fn no_hidden_file_declares_a_further_submodule() {
        let all = raw_rust_sources();
        let hidden = test_only_files(&all);
        let mut nested = Vec::new();
        for (file, src) in &all {
            if !hidden.contains(file) {
                continue;
            }
            for (lineno, line) in src.lines().enumerate() {
                let l = line.trim();
                let Some(rest) = l.strip_prefix("mod ") else {
                    continue;
                };
                if rest.trim_end().ends_with(';') {
                    nested.push(format!("{file}:{}: {l}", lineno + 1));
                }
            }
        }
        assert!(
            nested.is_empty(),
            "HIDDEN FILE DECLARES A FURTHER FILE — test_only_files() does not \
             recurse, so a submodule of a hidden file is scanned as \
             production code unless it carries its own #[cfg(test)] gate:\n\
             {nested:#?}"
        );
    }

    /// Sanity check: the detector actually fires on the tree as it stands
    /// today, so the two tests above aren't vacuously true over an empty set.
    #[test]
    fn at_least_the_known_hidden_files_are_detected() {
        let all = raw_rust_sources();
        let hidden = test_only_files(&all);
        for expected in [
            "src/mcp/write_path_equivalence.rs",
            "src/hooks/compliance.rs",
            "src/store/db/tests.rs",
            "src/mcp/dispatch_v2/tests.rs",
        ] {
            assert!(
                hidden.contains(expected),
                "expected {expected} to be detected as test-only; \
                 test_only_files() returned {hidden:#?}"
            );
        }
    }

    /// [`module_file_candidates`] resolves both module-file shapes correctly.
    #[test]
    fn module_file_candidates_resolves_both_shapes() {
        assert_eq!(
            module_file_candidates("src/lib.rs", "invariants"),
            vec!["src/invariants.rs", "src/invariants/mod.rs"]
        );
        assert_eq!(
            module_file_candidates("src/store/db/mod.rs", "tests"),
            vec!["src/store/db/tests.rs", "src/store/db/tests/mod.rs"]
        );
        assert_eq!(
            module_file_candidates("src/mcp/dispatch_v2/mod.rs", "tests"),
            vec![
                "src/mcp/dispatch_v2/tests.rs",
                "src/mcp/dispatch_v2/tests/mod.rs"
            ]
        );
    }
}

/// Source lines that are compiled into the shipped binary, as
/// `(1-based line number, line)`.
///
/// Drops `#[cfg(test)]`-guarded items entirely (test fixtures build gotcha
/// records and name network crates freely; neither ships) and blanks
/// whole-line `//` comments (a doc comment that mentions `gotcha:` or
/// `reqwest` is prose, not behaviour). Block comments are not handled — this
/// crate does not use them.
///
/// Brace counting is literal: a `{` or `}` inside a string literal would skew
/// it. That is acceptable here because the callers use the result to *locate*
/// code, and the located set is pinned by an explicit allowlist, so any
/// mis-parse shows up as a failing test rather than a silent miss.
fn production_lines(src: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim_start();
        if trimmed.starts_with("#[cfg(test)]") {
            let mut depth: i32 = 0;
            let mut opened = false;
            while i < lines.len() {
                depth += lines[i].matches('{').count() as i32;
                depth -= lines[i].matches('}').count() as i32;
                if lines[i].contains('{') {
                    opened = true;
                }
                if opened && depth <= 0 {
                    break;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        out.push((
            i + 1,
            if trimmed.starts_with("//") {
                ""
            } else {
                lines[i]
            },
        ));
        i += 1;
    }
    out
}

/// The name of the function a line declares, if it declares one.
///
/// Handles `pub`, `pub(crate)`, `pub(in ...)`, `const`, `async` and `unsafe`
/// in any order before `fn`.
fn declared_fn_name(line: &str) -> Option<&str> {
    let mut rest = line.trim_start();
    if let Some(after_pub) = rest.strip_prefix("pub") {
        let after_pub = after_pub.trim_start();
        rest = match after_pub.strip_prefix('(') {
            Some(vis) => vis.split_once(')')?.1.trim_start(),
            None => after_pub,
        };
    }
    loop {
        let before = rest;
        for kw in ["const ", "async ", "unsafe "] {
            if let Some(r) = rest.strip_prefix(kw) {
                rest = r.trim_start();
            }
        }
        if rest.len() == before.len() {
            break;
        }
    }
    let rest = rest.strip_prefix("fn ")?;
    let name = rest.trim_start();
    let end = name.find(|c: char| !c.is_alphanumeric() && c != '_')?;
    if end == 0 {
        return None;
    }
    Some(&name[..end])
}

/// One function body: its name, its declaration line, and its lines.
struct FnBody<'a> {
    name: &'a str,
    line: usize,
    lines: Vec<(usize, &'a str)>,
}

/// Split production source into top-level function bodies.
///
/// A function nested inside another is attributed to the outer one — the
/// scanners below only need "which named entry point contains this write",
/// and the outer name is the reviewable unit.
fn fn_bodies(src: &str) -> Vec<FnBody<'_>> {
    let lines = production_lines(src);
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let Some(name) = declared_fn_name(lines[i].1) else {
            i += 1;
            continue;
        };
        let start = i;
        let mut depth: i32 = 0;
        let mut opened = false;
        let mut body = Vec::new();
        while i < lines.len() {
            let text = lines[i].1;
            if !opened {
                // A trait method or `extern` declaration ends at `;` with no
                // body — stop before running to the end of the enclosing item.
                let semi = text.find(';');
                let brace = text.find('{');
                if matches!((semi, brace), (Some(s), None) | (Some(s), Some(_)) if Some(s) < brace.or(Some(usize::MAX)))
                {
                    break;
                }
            }
            body.push(lines[i]);
            depth += text.matches('{').count() as i32;
            depth -= text.matches('}').count() as i32;
            if text.contains('{') {
                opened = true;
            }
            if opened && depth <= 0 {
                break;
            }
            i += 1;
        }
        out.push(FnBody {
            name,
            line: lines[start].0,
            lines: body,
        });
        i += 1;
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────

/// "All create/edit/tombstone paths go through `store::gotcha_ops`."
/// — `CLAUDE.md`, "Gotcha mutations are centralized"
///
/// That sentence is false, and was false for a long time before anything said
/// so. `mcp::handlers` (`upsert_commit_once`, `confirm_commit_once`,
/// `tombstone_commit_once`), the socket `put`/`confirm`
/// commands in `mcp::server`, `store::session::promote_gotcha_candidates`,
/// `health::staleness`, `store::repair`, `store::migrations` and several CLI
/// commands all write canonical `gotcha:*` records without touching
/// `gotcha_ops`. Most of those bypasses are deliberate — the v2 MCP handlers
/// need the gotcha record, the derived `file:*` links and the audit entry in a
/// single `transact_knowledge` transaction, which `gotcha_ops` does not offer —
/// but nothing recorded them, so each new one arrived silently.
///
/// # Can the module be sealed instead?
///
/// No, not without the typed-key refactor this test exists to avoid.
///
/// - Visibility does not help. `store`, `mcp` and `hooks` are all modules of
///   the same crate (`mati_core`), so `pub(crate)` is no barrier between them.
///   `pub(in crate::store::gotcha_ops)` would seal them out, but it would also
///   seal out `src/cli/`, which lives in the *binary* crate and can only reach
///   `Store` through the fully public API.
/// - The store is key-string addressed: `Store::put(&self, key: &str, ...)`.
///   "Is this a gotcha write?" is a property of a runtime `&str`, not of a
///   type, so the compiler has nothing to reject. Making it a compile error
///   means introducing a `GotchaKey` newtype and threading it through
///   `Store::put`, `put_batch`, `put_batch_kv_only` and `KnowledgeWriteOp` —
///   a change to every write path in the crate.
/// - A runtime seal (`Store::put` rejecting `gotcha:` keys unless handed a
///   token only `gotcha_ops` can mint) is possible, but it converts a class of
///   compile-time-absent bug into a runtime error on paths that today are
///   correct-but-uncentralized, and it would have to be threaded through the
///   same four APIs anyway.
///
/// So the rule stays a convention, and this module makes the convention
/// countable: the inventory below is pinned, and a write site that is not in it
/// fails the build.
///
/// # What the scan does and does not prove
///
/// It finds every **function** in `src/` that reaches a record-level knowledge
/// write (`Store::put`, `put_batch`, `put_batch_kv_only`, or a
/// `KnowledgeWriteOp::PutRecord` op) with a key it cannot *prove* is in a
/// non-gotcha namespace. A key is proven non-gotcha only when it is a string
/// literal, a `format!` with a literal prefix, or a local/const binding to one,
/// whose prefix is in [`PROVEN_NON_GOTCHA_PREFIXES`]. Everything else is
/// listed, because everything else could be a `gotcha:` key at runtime.
///
/// - **Sound for new sites.** A gotcha record cannot reach SurrealKV without
///   one of those four APIs, so a bypass added in a *new* function always
///   appears.
/// - **Not sound for existing sites.** A gotcha write added *inside* a function
///   already on the list is invisible to this test. The `class` column exists
///   to make that reviewable by hand.
/// - **Over-lists on purpose.** Roughly half the inventory writes only
///   `file:*`, `analytics:*` or `system:*` records; the scanner simply cannot
///   prove it. Each is marked `NonGotcha` with the evidence that settles it.
/// - Raw-byte writes (`put_raw`, `put_batch_raw`) are excluded: they carry
///   graph edges and session blobs, never a canonical `Record`.
#[cfg(test)]
mod gotcha_write_sites {
    use super::{fn_bodies, rust_sources};
    use std::collections::{BTreeMap, BTreeSet};

    /// Record-level knowledge writes. Disjoint substrings — `.put(` does not
    /// match `.put_batch(` or `.put_raw(`.
    const WRITE_MARKERS: [&str; 4] = [
        ".put(",
        ".put_batch(",
        ".put_batch_kv_only(",
        "KnowledgeWriteOp::PutRecord",
    ];

    /// Key namespaces that are structurally incapable of naming a gotcha.
    /// From `CLAUDE.md`, "Key namespacing convention", plus the internal
    /// `system:` and `cluster:` namespaces.
    const PROVEN_NON_GOTCHA_PREFIXES: [&str; 18] = [
        "file:",
        "decision:",
        "dev_note:",
        "policy:",
        "stage:",
        "dep:",
        "session:",
        "analytics:",
        "hook_event:",
        "compliance:",
        "graph:edge:",
        "health:",
        "parse:",
        "audit:",
        "enforcement:",
        "system:",
        "cluster:",
        "schema:",
    ];

    /// How a listed site relates to the centralization rule.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Class {
        /// Inside `store::gotcha_ops` — the sanctioned implementation.
        Sanctioned,
        /// Writes canonical `gotcha:*` records without going through
        /// `gotcha_ops`. Every one of these is a live exception to the rule in
        /// `CLAUDE.md`. Adding one is a design decision; it does not become a
        /// convention by being merged.
        Bypass,
        /// The scanner cannot prove the key, but inspection shows the site only
        /// ever writes a non-gotcha namespace. Listed so the scan stays sound;
        /// re-verify the reason if the function changes shape.
        NonGotcha,
    }

    /// The complete, hand-audited inventory of record-write sites in `src/`.
    ///
    /// `(file, function, class, why)`. Audited 2026-07-24 against the tip of
    /// `feat/gotcha-content-drift`. To add an entry you must state which class
    /// it is and why — that is the entire point of the test.
    const INVENTORY: &[(&str, &str, Class, &str)] = &[
        (
            "src/cli/init/run.rs",
            "run",
            Class::Bypass,
            "Layer 0 batch write: gotcha:cochange:*, gotcha:revert:*, \
             gotcha:ownership:*, gotcha:codeowners:* stubs plus CLAUDE.md \
             imports keyed gotcha:claude-md-<slug>",
        ),
        (
            "src/cli/proxy.rs",
            "put",
            Class::Bypass,
            "StoreProxy transport: the Direct arm forwards the caller's key \
             verbatim, and the sibling socket arm branches on \
             key.starts_with(\"gotcha:\")",
        ),
        (
            "src/cli/proxy.rs",
            "import_records",
            Class::Bypass,
            "direct-mode import allowlist starts with \"gotcha:\"",
        ),
        (
            "src/cli/repair.rs",
            "run",
            Class::NonGotcha,
            "blast-radius and propagation passes rewrite only \
             scan_prefix(\"file:\") results, keyed by record.key",
        ),
        (
            "src/cli/review.rs",
            "edit_candidate",
            Class::Bypass,
            "re-serializes a GotchaRecord into a key taken from the review \
             candidate list (scan_prefix(\"gotcha:\"))",
        ),
        (
            "src/cli/sandbox.rs",
            "run_protect",
            Class::Bypass,
            "re-puts scan_prefix(\"gotcha:\") matches with deny-read/deny-write \
             tags",
        ),
        (
            "src/cli/suggest.rs",
            "write_candidates",
            Class::Bypass,
            "onboarding::build_candidates emits gotcha:codeowners:* and \
             gotcha:marker:* keys with concrete affected file paths",
        ),
        (
            "src/health/staleness.rs",
            "cascade_staleness_to_gotchas",
            Class::Bypass,
            "writes gotcha_record under gotcha_key to cascade file staleness \
             onto the linked gotchas",
        ),
        (
            "src/health/staleness.rs",
            "analyze_until",
            Class::Bypass,
            "batch-rescores every namespace in STALENESS_PREFIXES, which \
             includes \"gotcha:\"",
        ),
        (
            "src/main.rs",
            "run_improve",
            Class::Bypass,
            "`mati improve <key>` rewrites whatever key the user passes, with \
             no prefix guard",
        ),
        (
            "src/mcp/dispatch_v2/session.rs",
            "dispatch_session_side",
            Class::Bypass,
            "ConsultationHit bumps access_count on input.key and re-puts the \
             record; gotchas are the primary consultation target",
        ),
        (
            "src/mcp/handlers/gotcha.rs",
            "upsert_commit_once",
            Class::Bypass,
            "v2 gotcha upsert — needs record + file links + audit in one \
             transact_knowledge, which gotcha_ops does not offer",
        ),
        (
            "src/mcp/handlers/gotcha.rs",
            "confirm_commit_once",
            Class::Bypass,
            "v2 gotcha confirm — same single-transaction requirement",
        ),
        (
            "src/mcp/handlers/gotcha.rs",
            "tombstone_commit_once",
            Class::Bypass,
            "v2 gotcha tombstone — same single-transaction requirement",
        ),
        (
            "src/mcp/handlers/file.rs",
            "handle_file_reparse",
            Class::NonGotcha,
            "writes the file_key returned by reparse_staged, built as \
             format!(\"file:{rel_path}\")",
        ),
        (
            "src/mcp/handlers/decision_devnote.rs",
            "handle_dev_note_upsert",
            Class::NonGotcha,
            "rejects any key that is not dev_note:-prefixed before writing",
        ),
        (
            "src/mcp/handlers/reads.rs",
            "handle_mem_get",
            Class::Bypass,
            "read path: the spawned task re-puts the fetched record with an \
             incremented access_count, and the fetched key is usually a gotcha",
        ),
        (
            "src/mcp/handlers/reads.rs",
            "handle_mem_bootstrap",
            Class::NonGotcha,
            "writes file:<path> records assembled for the bootstrap packet",
        ),
        (
            "src/mcp/handlers/record_import.rs",
            "handle_record_import",
            Class::Bypass,
            "import prefix allowlist includes \"gotcha:\"; accepted records are \
             emitted as PutRecord { key: r.key }",
        ),
        (
            "src/mcp/server.rs",
            "socket_dispatch",
            Class::Bypass,
            "the `put` command writes req.args[\"key\"] with no namespace \
             validation; the `confirm` command writes a confirmed GotchaRecord",
        ),
        (
            "src/store/db/crud.rs",
            "transact_knowledge",
            Class::NonGotcha,
            "the write primitive itself — it dispatches KnowledgeWriteOp, it \
             does not originate a key",
        ),
        (
            "src/store/extraction.rs",
            "write_on_extraction",
            Class::NonGotcha,
            "key_for() strips the gotcha: prefix and returns \
             analytics:extraction:<slug>",
        ),
        (
            "src/store/extraction.rs",
            "mark_outcome",
            Class::NonGotcha,
            "same key_for() -> analytics:extraction:<slug>",
        ),
        (
            "src/store/gotcha_ops.rs",
            "apply_gotcha_write",
            Class::Sanctioned,
            "the centralized create/edit path",
        ),
        (
            "src/store/gotcha_ops.rs",
            "apply_gotcha_tombstone",
            Class::Sanctioned,
            "the centralized tombstone path",
        ),
        (
            "src/store/gotcha_ops.rs",
            "apply_gotcha_confirm",
            Class::Sanctioned,
            "the centralized confirm path",
        ),
        (
            "src/store/migrations.rs",
            "commit_bootstrap",
            Class::NonGotcha,
            "writes only system:schema_version and \
             system:migration:applied:<n>",
        ),
        (
            "src/store/migrations.rs",
            "commit_migration",
            Class::NonGotcha,
            "the two literal ops are system:schema_version and the history \
             key; migration bodies arrive via extra_ops / as_write_op",
        ),
        // `write_sentinel` is deliberately absent: its key resolves to the
        // const `SENTINEL_KEY = "system:migration:in_progress"`, which the scan
        // proves is outside the gotcha namespace on its own.
        (
            "src/store/migrations.rs",
            "as_write_op",
            Class::Bypass,
            "its producers, apply_v2_unconfirm_auto_derived_gotchas and \
             apply_v3_repair_codeowners_gotchas, stage canonical gotcha writes \
             inside the migration transaction",
        ),
        (
            "src/store/negative_exemplar.rs",
            "write_on_tombstone",
            Class::NonGotcha,
            "make_key() returns analytics:negative_exemplar:<dir>:<slug>; the \
             gotcha key survives only as a payload field",
        ),
        (
            "src/store/policy_ops.rs",
            "create",
            Class::NonGotcha,
            "ensure_policy_key() rejects anything not policy:-prefixed",
        ),
        (
            "src/store/policy_ops.rs",
            "edit",
            Class::NonGotcha,
            "ensure_policy_key() rejects anything not policy:-prefixed",
        ),
        (
            "src/store/policy_ops.rs",
            "set_stage",
            Class::NonGotcha,
            "ensure_policy_key() rejects anything not policy:-prefixed",
        ),
        (
            "src/store/policy_ops.rs",
            "delete",
            Class::NonGotcha,
            "ensure_policy_key() rejects anything not policy:-prefixed",
        ),
        (
            "src/store/repair.rs",
            "repair_unnormalized_paths",
            Class::Bypass,
            "scans gotcha:*, rewrites affected_files in the payload and puts \
             back at record.key",
        ),
        (
            "src/store/repair.rs",
            "repair_fast",
            Class::NonGotcha,
            "both writes target file records; the gotcha key only moves in and \
             out of the gotcha_keys array",
        ),
        (
            "src/store/session.rs",
            "record_shadow_observation",
            Class::NonGotcha,
            "shadow_observation_key() -> analytics:policy_shadow_<date>",
        ),
        (
            "src/store/session.rs",
            "upsert_daily_agg",
            Class::NonGotcha,
            "agg_key is always an analytics:/compliance: daily key; the gotcha \
             key appears only as target_key inside the payload",
        ),
        (
            "src/store/session.rs",
            "log_hit",
            Class::Bypass,
            "the second write bumps access_count/last_accessed on the consulted \
             target record, which is routinely gotcha:<slug>",
        ),
        (
            "src/store/session.rs",
            "promote_gotcha_candidates",
            Class::Bypass,
            "scans gotcha:*, sets confirmed = true and increments \
             confirmation_count",
        ),
    ];

    /// True when `expr` provably names a key outside the gotcha namespace.
    ///
    /// Conservative by construction: anything it cannot resolve is treated as
    /// a possible gotcha write, so a mis-parse over-lists rather than hides.
    fn proven_non_gotcha(expr: &str, body: &str, consts: &[(String, String)]) -> bool {
        let expr = expr.trim_start().trim_start_matches('&').trim_start();

        if let Some(literal) = string_literal_at(expr) {
            return PROVEN_NON_GOTCHA_PREFIXES
                .iter()
                .any(|p| literal.starts_with(p));
        }

        let ident: String = expr
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if ident.is_empty() {
            return false;
        }
        // Terminator check: `key` yes, `key_owned` handled by take_while, but
        // `record.key` must not be read as the const `record`.
        let after = expr[ident.len()..].chars().next();
        if !matches!(after, None | Some(',') | Some(')') | Some(' ')) {
            return false;
        }

        if let Some((_, value)) = consts.iter().find(|(name, _)| *name == ident) {
            return PROVEN_NON_GOTCHA_PREFIXES
                .iter()
                .any(|p| value.starts_with(p));
        }

        // Local binding: `let <ident> = "lit"` / `= format!("lit...")`.
        for pattern in [format!("let {ident} ="), format!("let mut {ident} =")] {
            let Some(pos) = body.find(&pattern) else {
                continue;
            };
            let rhs = &body[pos + pattern.len()..];
            let rhs = rhs.trim_start().trim_start_matches('&').trim_start();
            let rhs = rhs.strip_prefix("format!(").unwrap_or(rhs).trim_start();
            if let Some(literal) = string_literal_at(rhs) {
                return PROVEN_NON_GOTCHA_PREFIXES
                    .iter()
                    .any(|p| literal.starts_with(p));
            }
        }
        false
    }

    /// The contents of a double-quoted literal starting at position 0, if any.
    fn string_literal_at(expr: &str) -> Option<&str> {
        let rest = expr.strip_prefix('"')?;
        let end = rest.find('"')?;
        Some(&rest[..end])
    }

    /// Module-level `const NAME: &str = "value";` bindings.
    fn str_consts(src: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for line in src.lines() {
            let line = line.trim_start();
            let line = line.strip_prefix("pub ").unwrap_or(line);
            let Some(rest) = line.strip_prefix("const ") else {
                continue;
            };
            let Some((name, tail)) = rest.split_once(':') else {
                continue;
            };
            let Some((_, value)) = tail.split_once('=') else {
                continue;
            };
            if let Some(literal) = string_literal_at(value.trim_start()) {
                out.push((name.trim().to_string(), literal.to_string()));
            }
        }
        out
    }

    /// Scan `src/` for `(file, function)` pairs that write a record under a key
    /// this analysis cannot prove is outside the gotcha namespace, mapped to
    /// the line the function is declared on.
    fn scan() -> BTreeMap<(String, String), usize> {
        let mut found = BTreeMap::new();
        for (file, src) in rust_sources() {
            let consts = str_consts(&src);
            for body in fn_bodies(&src) {
                let body_text: String = body
                    .lines
                    .iter()
                    .map(|(_, l)| *l)
                    .collect::<Vec<_>>()
                    .join("\n");
                for (idx, (_, line)) in body.lines.iter().enumerate() {
                    for marker in WRITE_MARKERS {
                        let Some(pos) = line.find(marker) else {
                            continue;
                        };
                        let tail = &line[pos + marker.len()..];
                        let key_expr = if marker == "KnowledgeWriteOp::PutRecord" {
                            // The `key:` field may be on this line or the next
                            // two (struct literal spread over lines).
                            let window: String = std::iter::once(tail)
                                .chain(body.lines[idx + 1..].iter().take(2).map(|(_, l)| *l))
                                .collect::<Vec<_>>()
                                .join("\n");
                            match window.split_once("key:") {
                                Some((_, after)) => after.trim_start().to_string(),
                                None => String::new(),
                            }
                        } else if tail.trim().is_empty() || tail.trim_start().starts_with("&[") {
                            // Argument on the following line, or a batch slice.
                            body.lines
                                .get(idx + 1)
                                .map(|(_, l)| l.to_string())
                                .unwrap_or_default()
                        } else {
                            tail.to_string()
                        };

                        if proven_non_gotcha(&key_expr, &body_text, &consts) {
                            continue;
                        }
                        found.insert((file.clone(), body.name.to_string()), body.line);
                    }
                }
            }
        }
        found
    }

    /// The load-bearing test: the set of possible gotcha-write sites is exactly
    /// the audited inventory. Anything else is a new, unreviewed way to mutate
    /// a control.
    #[test]
    fn every_possible_gotcha_write_site_is_in_the_audited_inventory() {
        let found = scan();
        let found_sites: BTreeSet<(String, String)> = found.keys().cloned().collect();
        let listed: BTreeSet<(String, String)> = INVENTORY
            .iter()
            .map(|(f, n, _, _)| (f.to_string(), n.to_string()))
            .collect();

        let unlisted: Vec<String> = found_sites
            .difference(&listed)
            .map(|site| format!("{}:{} fn {}", site.0, found[site], site.1))
            .collect();
        let stale: Vec<_> = listed.difference(&found_sites).collect();

        assert!(
            unlisted.is_empty(),
            "NEW GOTCHA WRITE SITE(S) — a record-level store write reachable \
             with a `gotcha:*` key appeared outside the audited inventory:\n\
             {unlisted:#?}\n\n\
             CLAUDE.md says every create/edit/tombstone path goes through \
             `store::gotcha_ops`. If this site really needs its own write, add \
             it to INVENTORY in src/invariants.rs with a Class and a reason. \
             Do not delete this assertion."
        );
        assert!(
            stale.is_empty(),
            "STALE INVENTORY ENTRIES — these are listed in \
             src/invariants.rs but no longer write records (renamed, deleted, \
             or now routed through gotcha_ops):\n{stale:#?}\n\n\
             Remove them so the inventory keeps describing the code."
        );
    }

    /// `gotcha_ops` must still own at least one write path. If the sanctioned
    /// module stops writing entirely, the rule it represents is gone and the
    /// inventory above is just a list.
    #[test]
    fn the_sanctioned_module_still_owns_the_centralized_paths() {
        let sanctioned: Vec<_> = INVENTORY
            .iter()
            .filter(|(_, _, class, _)| *class == Class::Sanctioned)
            .collect();
        assert_eq!(
            sanctioned.len(),
            3,
            "store::gotcha_ops must keep exactly its three centralized \
             mutations (write / tombstone / confirm); got {sanctioned:#?}"
        );
        assert!(
            sanctioned
                .iter()
                .all(|(file, _, _, _)| *file == "src/store/gotcha_ops.rs"),
            "only store::gotcha_ops may be classified Sanctioned"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// "The OSS binary never phones home. Period."
/// — `CLAUDE.md`, "What this repo must NEVER include"
///
/// Together with "Any network call in the enforcement path" being forbidden,
/// this is the single most load-bearing public claim mati makes. Until this
/// module existed it was backed by a manual reading of `Cargo.toml`.
///
/// # What these tests prove
///
/// 1. No source file under `src/` names an IP-socket or HTTP-client API.
/// 2. No direct dependency of the shipped build is a known HTTP client.
/// 3. The resolved dependency graph of the **default build** — which is the
///    build that ships, since `default = []` — links no known HTTP client,
///    transitively.
///
/// # What they do NOT prove
///
/// Be precise about this; an overclaiming check is worse than none.
///
/// - **Not a runtime proof.** They are a static, name-based analysis. They
///   cannot show that no packet leaves the machine. The airtight version of
///   that claim is a syscall-level audit (run the enforcement path under
///   `strace` and fail on `connect`/`sendto`/`sendmsg` to an `AF_INET` address)
///   and belongs in CI, not in a unit test.
/// - **The allowlist is finite.** Test 3 bans crates by name. A network client
///   nobody has heard of passes.
/// - **`std::net` is still reachable.** `tokio = ["full"]` links `mio` and
///   `socket2`, so TCP/UDP primitives are compiled in even though nothing in
///   `src/` calls them. Test 1 covers first-party code only — a *dependency*
///   opening a socket is invisible here.
/// - **Subprocesses are only spot-checked.** Test 1 bans `Command::new("curl")`
///   and friends by name; it cannot follow a command assembled at runtime.
/// - **The `semantic` feature is out of scope by design.** It is opt-in
///   (`--features semantic`) and downloads an embedding model through `hf-hub`,
///   which is why `reqwest`/`hyper`/`ureq` appear in `Cargo.lock` at all. They
///   are not in the default graph, which is what test 3 checks.
///
/// Unix domain sockets are the daemon's transport (`~/.mati/<slug>/mati.sock`)
/// and are explicitly fine: they are filesystem-scoped and cannot leave the
/// machine. Test 1 asserts they are the *only* `tokio::net` surface in use.
#[cfg(test)]
mod zero_network {
    use super::{production_lines, rust_sources};

    /// First-party API names that would mean mati itself opened a network
    /// socket or spoke HTTP. `tokio::net::Unix*` is deliberately absent.
    const BANNED_SOURCE_TOKENS: &[&str] = &[
        "std::net::",
        "TcpStream",
        "TcpListener",
        "UdpSocket",
        "to_socket_addrs",
        "tokio::net::TcpStream",
        "tokio::net::TcpListener",
        "tokio::net::UdpSocket",
        "reqwest::",
        "hyper::",
        "ureq::",
        "isahc::",
        "surf::",
        "attohttpc::",
        "curl::",
        "tokio_tungstenite::",
        "Command::new(\"curl\")",
        "Command::new(\"wget\")",
        "Command::new(\"nc\")",
        "Command::new(\"ping\")",
    ];

    /// Crates that exist to speak HTTP (or to carry a TLS/HTTP stack for one).
    /// Matched on the exact crate name in `cargo tree` output.
    const BANNED_CRATES: &[&str] = &[
        "reqwest",
        "hyper",
        "hyper-util",
        "hyper-rustls",
        "hyper-tls",
        "h2",
        "ureq",
        "ureq-proto",
        "isahc",
        "surf",
        "attohttpc",
        "curl",
        "curl-sys",
        "tokio-tungstenite",
        "tungstenite",
        "tonic",
        "hf-hub",
        "native-tls",
        "rustls",
        "tokio-rustls",
        "tokio-native-tls",
        "sentry",
        "opentelemetry",
        "posthog-rs",
        "segment",
    ];

    /// 1 — no first-party network code.
    #[test]
    fn no_source_file_opens_an_ip_socket_or_speaks_http() {
        let mut hits = Vec::new();
        for (file, src) in rust_sources() {
            for (lineno, line) in production_lines(&src) {
                for token in BANNED_SOURCE_TOKENS {
                    if line.contains(token) {
                        hits.push(format!("{file}:{lineno}  [{token}]  {}", line.trim()));
                    }
                }
            }
        }
        assert!(
            hits.is_empty(),
            "NETWORK API IN THE OSS BINARY — CLAUDE.md: \"The OSS binary never \
             phones home. Period.\" and \"Any network call in the enforcement \
             path\" is forbidden.\n{}\n\n\
             Unix domain sockets (tokio::net::UnixStream / UnixListener) are \
             the daemon transport and are allowed; nothing that can reach \
             another host is.",
            hits.join("\n")
        );
    }

    /// The daemon's IPC really is Unix-domain, not loopback TCP. Pins the
    /// premise the allowlist above rests on.
    #[test]
    fn the_daemon_transport_is_a_unix_domain_socket() {
        let uses_unix_sockets = rust_sources().iter().any(|(_, src)| {
            production_lines(src)
                .iter()
                .any(|(_, l)| l.contains("UnixListener") || l.contains("UnixStream"))
        });
        assert!(
            uses_unix_sockets,
            "expected the daemon to bind a Unix domain socket; if the IPC \
             transport changed, re-derive what BANNED_SOURCE_TOKENS must allow"
        );
    }

    /// 2 — no HTTP client is a direct dependency of the shipped build.
    ///
    /// A network-capable crate may appear in `[dependencies]` only as
    /// `optional = true`, i.e. reachable solely through an opt-in feature.
    /// `default = []` is asserted alongside, because "the default build" is
    /// only meaningful while it enables nothing.
    #[test]
    fn no_http_client_is_a_non_optional_direct_dependency() {
        let manifest = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
        )
        .expect("Cargo.toml is readable");
        let doc: toml_edit::DocumentMut = manifest.parse().expect("Cargo.toml parses");

        let default_features = doc["features"]["default"]
            .as_array()
            .expect("[features] default is an array");
        assert!(
            default_features.is_empty(),
            "`default` must stay empty — every zero-network claim below is \
             about the default build; got {default_features}"
        );

        let deps = doc["dependencies"]
            .as_table()
            .expect("[dependencies] is a table");
        let mut offenders = Vec::new();
        for (name, item) in deps.iter() {
            if !BANNED_CRATES.contains(&name) {
                continue;
            }
            let optional = item
                .get("optional")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !optional {
                offenders.push(name.to_string());
            }
        }
        assert!(
            offenders.is_empty(),
            "network-capable crate(s) are non-optional direct dependencies, so \
             they ship in the default binary: {offenders:?}"
        );
    }

    /// 3 — the strongest of the three: resolve the actual dependency graph of
    /// the default build and assert no banned crate is in it.
    ///
    /// `--edges normal` drops dev- and build-dependencies (neither is linked
    /// into the released binary). `--offline` keeps this test from doing the
    /// very thing it is checking for. A failure to run the command is a
    /// failure of the test: "could not verify" is not "verified".
    #[test]
    fn the_default_build_links_no_http_client_crate() {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let output = std::process::Command::new(&cargo)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args([
                "tree",
                "--locked",
                "--offline",
                "--no-default-features",
                "--edges",
                "normal",
                "--prefix",
                "none",
                "--format",
                "{p}",
            ])
            .output()
            .expect("`cargo tree` runs; the zero-network attestation cannot be skipped");
        assert!(
            output.status.success(),
            "`cargo tree` failed, so the zero-network attestation could not be \
             established:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let linked: Vec<&str> = stdout
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .collect();
        let offenders: Vec<&&str> = BANNED_CRATES
            .iter()
            .filter(|c| linked.contains(*c))
            .collect();

        assert!(
            offenders.is_empty(),
            "THE DEFAULT BUILD LINKS A NETWORK CLIENT — CLAUDE.md: \"The OSS \
             binary never phones home. Period.\"\nOffending crate(s): \
             {offenders:?}\n\n\
             The `semantic` feature is the one sanctioned exception and is \
             excluded here via --no-default-features. If a new dependency \
             pulled this in transitively, that dependency does not belong in \
             the default build."
        );
        assert!(
            linked.len() > 50,
            "sanity check: `cargo tree` returned only {} crates, so the scan \
             above proved nothing",
            linked.len()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// "Called during `mati init` and `mati repair --full`."
/// — the doc comment on `store::enforcement::enforce_retention`, which nothing
/// outside a test has ever called.
///
/// Five separate defects found weeks apart turned out to be one shape:
/// documentation asserting behaviour the code does not have. `ConfidenceScore`
/// said it was recomputed on every `mem_get`; `health::confidence::recompute`
/// has no callers. `enforce_retention` said `mati init` and `mati repair`
/// called it; only a test does, so the event log grows without bound. Each was
/// found by accident. Nothing was looking.
///
/// This module looks. It finds every `fn` whose doc comment makes a caller
/// claim, and asserts the function has at least one call site in production
/// source. A doc that says "called during X" while nothing anywhere calls it is
/// false no matter what X is.
///
/// # What the scan proves
///
/// Only the weak half of the claim, and deliberately so. It proves *a* caller
/// exists — not that the *named* caller is the one calling. Checking the named
/// caller means resolving prose like "the CLI path" or "`mati repair --full`"
/// to a function, which a text scan cannot do. The weak half is still worth
/// mechanizing: every known instance of this bug had **zero** callers, not the
/// wrong one.
///
/// # What it does not catch
///
/// - **Claims on anything that is not a `fn`.** `ConfidenceScore`'s false
///   "Recomputed on every `mem_get`" was on a *struct*; "has a caller" is not a
///   property a struct has. That case is out of reach here, and so is the
///   `enrichment_depth` rubric row that scored a `comment_density` input the
///   daemon always passes as `None` — a table cell, not a caller claim.
/// - **Module docs (`//!`).** The documented item is a module; same problem.
/// - **A caller that is itself dead.** Reachability from `main` is not checked,
///   only that some production line calls the name.
/// - **Name collisions.** Call sites are matched on the bare identifier, so
///   `foo()` in any file satisfies a claim on any `fn foo`. Two same-named
///   functions can cover for each other. This errs toward silence, which is the
///   right direction for a test that must not cry wolf.
/// - **Function values.** A call site is `name(`. Passing `name` as a function
///   pointer or storing it in a table does not count, so such a site reads as
///   "no caller". No current claim is affected; a future one would need an
///   allowlist entry.
/// - **`src/bin/bench_real` counts as a caller.** [`rust_sources`] walks all of
///   `src/`, and that dev binary is gated behind the `bench-bin` feature, so a
///   function called only from it would pass. Checked: none is today.
///
/// # The phrase list
///
/// Derived by grepping every `///` line in `src/` for verbs of invocation and
/// reading the hits, not by guessing. Two shapes survived: phrases whose object
/// is the **caller** ("used by `mati doctor`") and phrases whose object is the
/// **occasion** ("called on cold init") — both assert the function runs.
///
/// Four phrasings present in the tree were rejected as not caller claims at
/// all: "runs on" always names a thread (`walk_channel`: "the walk runs on a
/// background thread"; `install_panic_hook`: "the hook runs on the panicking
/// thread"), "runs from" names a side of a comparison, "used when" names a
/// situation ("used when git is unavailable"), and "used in" matches inside
/// "used instead of".
///
/// Phrase matching is word-bounded on both ends. Substring matching read
/// "Called once at daemon startup" as "called on" and "used instead of" as
/// "used in"; both are wrong.
///
/// One phrase is knowingly imprecise: "called on" also matches the precondition
/// form "must be called on a store whose index is empty". That costs nothing —
/// an over-matched doc only fails the test if the function *also* has no
/// caller, and a function in that state is worth a look regardless.
#[cfg(test)]
mod documented_caller_claims {
    use super::{declared_fn_name, fn_bodies, production_lines, rust_sources};
    use std::collections::BTreeSet;

    /// Doc phrasings that assert the documented function gets called.
    ///
    /// Matched case-insensitively and word-bounded against the joined text of
    /// the `///` block. First group names a caller, second names an occasion.
    const CLAIM_PHRASES: &[&str] = &[
        "called by",
        "called from",
        "invoked by",
        "invoked from",
        "used by",
        "used from",
        "consumed by",
        "triggered by",
        "driven by",
        "executed by",
        "fired by",
        "recomputed by",
        "called at",
        "called during",
        "called on",
        "called once",
        "called whenever",
        "invoked during",
        "invoked on",
        "recomputed on",
        "runs during",
        "runs whenever",
        "fires on",
        "fires when",
        "fires after",
        "fires during",
    ];

    /// Functions whose doc claims a caller that this scan cannot see.
    ///
    /// `(file, function, why)`. An entry is a claim that the scan is wrong, and
    /// it must say why it is wrong — trait objects, macro-generated call sites
    /// and FFI are the shapes that qualify. "It made the test red" is not a
    /// reason. Empty is the correct state; keep it that way.
    const ALLOWLIST: &[(&str, &str, &str)] = &[];

    /// A `fn` whose doc comment claims it gets called.
    struct Claim {
        file: String,
        line: usize,
        name: String,
        phrase: &'static str,
    }

    /// True when `needle` occurs in `hay` bounded by non-identifier characters.
    fn contains_word(hay: &str, needle: &str) -> bool {
        let bytes = hay.as_bytes();
        let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        let mut from = 0;
        while let Some(pos) = hay[from..].find(needle) {
            let start = from + pos;
            let end = start + needle.len();
            if (start == 0 || !ident(bytes[start - 1]))
                && (end == bytes.len() || !ident(bytes[end]))
            {
                return true;
            }
            from = end;
        }
        false
    }

    /// The first claim phrase the doc block uses, if any.
    fn claim_phrase(doc: &str) -> Option<&'static str> {
        let lower = doc.to_ascii_lowercase();
        CLAIM_PHRASES
            .iter()
            .copied()
            .find(|p| contains_word(&lower, p))
    }

    /// Every `fn` in `src` whose preceding `///` block makes a caller claim.
    ///
    /// A doc block is a run of `///` lines directly above the item, optionally
    /// separated from it by attributes. Any other line ends the block, so a
    /// `//` comment or a blank line between doc and item detaches them — the
    /// same rule rustdoc applies for blank lines, stricter for `//`.
    ///
    /// `#[cfg(test)]` items are skipped: [`production_lines`] omits their line
    /// numbers, which both drops test fixtures and ends any doc block that ran
    /// into one.
    fn claims(file: &str, src: &str) -> Vec<Claim> {
        let production: BTreeSet<usize> = production_lines(src).iter().map(|(n, _)| *n).collect();
        let mut out = Vec::new();
        let mut doc = String::new();
        for (idx, line) in src.lines().enumerate() {
            let lineno = idx + 1;
            if !production.contains(&lineno) {
                doc.clear();
                continue;
            }
            let trimmed = line.trim_start();
            if let Some(text) = trimmed.strip_prefix("///") {
                doc.push_str(text);
                doc.push('\n');
                continue;
            }
            if doc.is_empty() {
                continue;
            }
            if trimmed.starts_with("#[") {
                continue;
            }
            if let (Some(name), Some(phrase)) = (declared_fn_name(line), claim_phrase(&doc)) {
                out.push(Claim {
                    file: file.to_string(),
                    line: lineno,
                    name: name.to_string(),
                    phrase,
                });
            }
            doc.clear();
        }
        out
    }

    /// Line numbers belonging to the function's own declaration and body, so a
    /// recursive call cannot pass as an external caller.
    ///
    /// Falls back to the declaration line alone for a nested `fn`, which
    /// [`fn_bodies`] attributes to its enclosing function.
    fn own_lines(src: &str, name: &str, decl_line: usize) -> BTreeSet<usize> {
        fn_bodies(src)
            .into_iter()
            .find(|b| b.name == name && b.line == decl_line)
            .map(|b| b.lines.iter().map(|(n, _)| *n).collect())
            .unwrap_or_else(|| BTreeSet::from([decl_line]))
    }

    /// Production source as `(file, line number, line)`, computed once.
    fn production_corpus(sources: &[(String, String)]) -> Vec<(&str, usize, &str)> {
        sources
            .iter()
            .flat_map(|(file, src)| {
                production_lines(src)
                    .into_iter()
                    .map(move |(n, l)| (file.as_str(), n, l))
            })
            .collect()
    }

    /// True when some production line calls `name` from outside its own body.
    ///
    /// Declarations of the same name are skipped, so a trait method and its
    /// impls do not vouch for each other; only a `name(` call site counts.
    fn has_call_site(claim: &Claim, own: &BTreeSet<usize>, corpus: &[(&str, usize, &str)]) -> bool {
        corpus.iter().any(|(file, lineno, line)| {
            if *file == claim.file && own.contains(lineno) {
                return false;
            }
            if declared_fn_name(line) == Some(claim.name.as_str()) {
                return false;
            }
            call_site(line, &claim.name)
        })
    }

    /// True when `line` contains `name(` as a whole identifier.
    fn call_site(line: &str, name: &str) -> bool {
        let bytes = line.as_bytes();
        let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        let mut from = 0;
        while let Some(pos) = line[from..].find(name) {
            let start = from + pos;
            let end = start + name.len();
            let bounded = start == 0 || !ident(bytes[start - 1]);
            if bounded && line[end..].starts_with('(') {
                return true;
            }
            from = end;
        }
        false
    }

    /// The load-bearing test: every function documented as being called is.
    #[test]
    fn every_documented_caller_claim_has_a_caller() {
        let sources = rust_sources();
        let corpus = production_corpus(&sources);

        let mut claim_count = 0;
        let mut uncalled = Vec::new();
        for (file, src) in &sources {
            for claim in claims(file, src) {
                claim_count += 1;
                if ALLOWLIST
                    .iter()
                    .any(|(f, n, _)| *f == claim.file && *n == claim.name)
                {
                    continue;
                }
                let own = own_lines(src, &claim.name, claim.line);
                if !has_call_site(&claim, &own, &corpus) {
                    uncalled.push(format!(
                        "{}:{} fn {}  — doc says \"{}\", nothing calls it",
                        claim.file, claim.line, claim.name, claim.phrase
                    ));
                }
            }
        }

        assert!(
            uncalled.is_empty(),
            "DOC CLAIMS A CALLER THAT DOES NOT EXIST:\n{}\n\n\
             Each of these functions is documented as being called and has no \
             call site in src/. Fix the doc to say what is true — that is what \
             `enforce_retention` does now. Do not wire up a caller to silence \
             the test; that is a behaviour change and needs its own review. If \
             the call site is real but invisible to a text scan (trait object, \
             macro, FFI), add it to ALLOWLIST in src/invariants.rs with the \
             reason.",
            uncalled.join("\n")
        );

        assert!(
            claim_count > 30,
            "sanity check: only {claim_count} caller claims found in src/, so \
             the doc-block parser is broken and the assertion above proved \
             nothing"
        );
    }

    /// Every allowlist entry must name a function that still exists and still
    /// makes a caller claim. A stale suppression is a suppression nobody reads.
    #[test]
    fn the_allowlist_has_no_stale_entries() {
        let sources = rust_sources();
        let live: BTreeSet<(String, String)> = sources
            .iter()
            .flat_map(|(file, src)| claims(file, src))
            .map(|c| (c.file, c.name))
            .collect();

        let stale: Vec<_> = ALLOWLIST
            .iter()
            .filter(|(f, n, _)| !live.contains(&(f.to_string(), n.to_string())))
            .collect();
        assert!(
            stale.is_empty(),
            "STALE ALLOWLIST ENTRIES — renamed, deleted, or the doc no longer \
             claims a caller:\n{stale:#?}"
        );

        let unexplained: Vec<_> = ALLOWLIST
            .iter()
            .filter(|(_, _, why)| why.trim().is_empty())
            .collect();
        assert!(
            unexplained.is_empty(),
            "ALLOWLIST ENTRIES WITHOUT A REASON — an entry that does not say \
             why the scan is wrong is a suppression:\n{unexplained:#?}"
        );
    }
}
