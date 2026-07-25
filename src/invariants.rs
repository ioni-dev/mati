//! Repo-wide invariants that prose alone kept getting wrong.
//!
//! Every module in this crate tests its own behaviour. The two rules below are
//! different: they are properties of the *whole source tree*, so no single
//! module owns them, and both were stated in `CLAUDE.md` / `ARCHITECTURE.md`
//! long before anything checked them. Both turned out to be false in prose and
//! silently drifting in code.
//!
//! - [`gotcha_write_sites`] — "all create/edit/tombstone paths go through
//!   `store::gotcha_ops`".
//! - [`zero_network`] — "the OSS binary never phones home. Period."
//!
//! Both are implemented as source scans over `src/**/*.rs`. That approach has
//! real limits and each module states its own; read them before trusting a
//! green run. The scan deliberately skips this file — it quotes every marker
//! string it searches for and would otherwise match itself.

use std::path::{Path, PathBuf};

/// This file. Excluded from every scan below: it contains the marker strings
/// verbatim, so including it would make every scan self-referential.
const THIS_FILE: &str = "src/invariants.rs";

/// Every `.rs` file under `src/`, as `(repo-relative path, contents)`, sorted.
///
/// `src/` — not the whole repo — because that is what ships: the `mati` binary
/// (`src/main.rs` + `src/cli/`) and the `mati_core` library. `benches/`,
/// `tests/` and `scripts/` are developer-only and are not linked into the
/// released artifact.
fn rust_sources() -> Vec<(String, String)> {
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
/// `tombstone_commit_once`, `apply_mem_set_write`), the socket `put`/`confirm`
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
            "src/cli/init.rs",
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
             gotcha:marker:* keys",
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
            "analyze_all",
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
            "src/mcp/dispatch_v2.rs",
            "dispatch_session_side",
            Class::Bypass,
            "ConsultationHit bumps access_count on input.key and re-puts the \
             record; gotchas are the primary consultation target",
        ),
        (
            "src/mcp/handlers.rs",
            "upsert_commit_once",
            Class::Bypass,
            "v2 gotcha upsert — needs record + file links + audit in one \
             transact_knowledge, which gotcha_ops does not offer",
        ),
        (
            "src/mcp/handlers.rs",
            "confirm_commit_once",
            Class::Bypass,
            "v2 gotcha confirm — same single-transaction requirement",
        ),
        (
            "src/mcp/handlers.rs",
            "tombstone_commit_once",
            Class::Bypass,
            "v2 gotcha tombstone — same single-transaction requirement",
        ),
        (
            "src/mcp/handlers.rs",
            "handle_file_reparse",
            Class::NonGotcha,
            "writes the file_key returned by reparse_staged, built as \
             format!(\"file:{rel_path}\")",
        ),
        (
            "src/mcp/handlers.rs",
            "handle_dev_note_upsert",
            Class::NonGotcha,
            "rejects any key that is not dev_note:-prefixed before writing",
        ),
        (
            "src/mcp/handlers.rs",
            "handle_mem_get",
            Class::Bypass,
            "read path: the spawned task re-puts the fetched record with an \
             incremented access_count, and the fetched key is usually a gotcha",
        ),
        (
            "src/mcp/handlers.rs",
            "handle_mem_bootstrap",
            Class::NonGotcha,
            "writes file:<path> records assembled for the bootstrap packet",
        ),
        (
            "src/mcp/handlers.rs",
            "handle_record_import",
            Class::Bypass,
            "import prefix allowlist includes \"gotcha:\"; accepted records are \
             emitted as PutRecord { key: r.key }",
        ),
        (
            "src/mcp/handlers.rs",
            "apply_mem_set_write",
            Class::Bypass,
            "v1 mem_set bridge: writes any key whose prefix is in [gotcha:, \
             decision:, dev_note:, policy:]",
        ),
        (
            "src/mcp/handlers.rs",
            "try_confirm_once",
            Class::Bypass,
            "v1 confirm: rejects non-Gotcha categories, then flips \
             payload.confirmed and puts back at the same key",
        ),
        (
            "src/mcp/server.rs",
            "socket_dispatch",
            Class::Bypass,
            "the `put` command writes req.args[\"key\"] with no namespace \
             validation; the `confirm` command writes a confirmed GotchaRecord",
        ),
        (
            "src/store/db.rs",
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
            "its only producer, apply_v2_unconfirm_auto_derived_gotchas, \
             scans gotcha:cochange:/revert:/ownership: and rewrites those \
             records with confirmed = false",
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
