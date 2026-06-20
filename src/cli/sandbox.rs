//! `mati sandbox` — L3 sandbox floor (Plane 3).
//!
//! Compiles confirmed, explicitly-tagged "crown-jewel" gotchas into Claude Code
//! `sandbox.filesystem` deny rules — an OS-level (Seatbelt / bubblewrap) floor
//! that blocks the agent's shell and every subprocess it spawns from reading or
//! writing those files. This closes the shell / symlink bypass that the dynamic
//! hook gate (L1) cannot reach: for a crown-jewel file the shell path is denied
//! at the OS level, leaving the consultation-gated Read/Edit tools as the only
//! way the agent can touch it. See `MATI-SOTA-ARCHITECTURE.md` (L3).
//!
//! Design (validated through three review passes + a live Claude Code test):
//! - **Absolute canonical paths** — never `./`-relative (CC's `./` resolution and
//!   profile canonicalization are undocumented; an unresolved deny would silently
//!   fail to protect). Absolute canonical is exactly what Seatbelt matches.
//! - **Target `.claude/settings.local.json`** (per-user, gitignored): mati owns
//!   only the `denyRead`/`denyWrite` entries that are **under the repo root**;
//!   everything else (the user's `~/`, `./`, out-of-repo absolutes) is preserved.
//!   CC merges these arrays across scopes (deny wins), so they coexist with the
//!   user's own denies in `settings.json`. Ownership-by-location → no manifest.
//! - mati never writes `sandbox.enabled` (per-user / Enterprise-managed opt-in).
//!   Team-wide enforcement is the Enterprise managed-settings tier.
//!
//! Safety: highest-risk layer (mutates security config) → explicit-tag-only
//! (never severity-derived), preview-default (writes only on `--apply`),
//! reversible (`clear`), out-of-repo paths skipped, malformed settings refused.

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use mati_core::store::{GotchaRecord, Record, RecordLifecycle};

use super::proxy::StoreProxy;

/// Tag → shell-deny mapping. Explicit opt-in only; severity is never used.
/// - `crown-jewel`: shell / subprocess cannot WRITE the file (protect critical
///   logic from out-of-gate modification). Reads still work.
/// - `sandbox-deny-read`: additionally, the shell cannot READ the file (secrets).
const TAG_DENY_WRITE: &str = "crown-jewel";
const TAG_DENY_READ: &str = "sandbox-deny-read";

#[derive(Args, Debug)]
pub struct SandboxArgs {
    #[command(subcommand)]
    pub command: SandboxCommand,
}

#[derive(Subcommand, Debug)]
pub enum SandboxCommand {
    /// Compile crown-jewel gotchas into sandbox deny rules (preview, or --apply).
    Compile(CompileArgs),
    /// Mark a file's confirmed gotcha crown-jewel, then write the deny floor.
    Protect(ProtectArgs),
    /// Remove a file's crown-jewel protection and re-sync settings.local.json.
    Unprotect(ProtectArgs),
    /// Remove all mati-managed sandbox deny rules from settings.local.json.
    Clear,
}

#[derive(Args, Debug)]
pub struct CompileArgs {
    /// Write the rules into .claude/settings.local.json (default: preview only).
    #[arg(long)]
    pub apply: bool,
    /// With --apply, allow removing protections whose crown-jewel tag is gone.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct ProtectArgs {
    /// Repo-relative file path (must already have a confirmed gotcha).
    pub file: String,
    /// Also deny shell *reads* (for secrets), not just writes.
    #[arg(long)]
    pub read: bool,
    /// Confirm when the gotcha also covers other files (the tag is per-gotcha).
    #[arg(long)]
    pub yes: bool,
}

/// Sandbox filesystem deny rules. Paths are repo-relative after `compile_relative`
/// and absolute-canonical after `resolve_rules`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SandboxRules {
    pub deny_read: BTreeSet<String>,
    pub deny_write: BTreeSet<String>,
}

impl SandboxRules {
    pub fn is_empty(&self) -> bool {
        self.deny_read.is_empty() && self.deny_write.is_empty()
    }
}

/// One gotcha's sandbox-relevant fields. Both `active` and `confirmed` must hold
/// for it to gate — tombstoned/superseded/unconfirmed records never enforce.
pub struct GotchaSel<'a> {
    pub tags: &'a [String],
    pub active: bool,
    pub confirmed: bool,
    pub files: &'a [String],
}

/// Pure: select repo-relative paths and their deny kind. Explicit-tag-only,
/// never severity-derived; Active + confirmed only.
pub fn compile_relative<'a>(gotchas: impl Iterator<Item = GotchaSel<'a>>) -> SandboxRules {
    let mut rules = SandboxRules::default();
    for g in gotchas {
        if !g.active || !g.confirmed {
            continue;
        }
        let deny_write = g.tags.iter().any(|t| t == TAG_DENY_WRITE);
        let deny_read = g.tags.iter().any(|t| t == TAG_DENY_READ);
        if !deny_write && !deny_read {
            continue;
        }
        for f in g.files {
            let rel = normalize_rel(f);
            if rel.is_empty() {
                continue;
            }
            if deny_write {
                rules.deny_write.insert(rel.clone());
            }
            if deny_read {
                rules.deny_read.insert(rel);
            }
        }
    }
    rules
}

/// Clean repo-relative form: forward slashes, no leading `./` or `/`.
fn normalize_rel(p: &str) -> String {
    p.replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

/// Files a gotcha covers beyond `target` (normalized) — the blast radius of
/// (un)protecting through its per-gotcha crown-jewel tag. Empty for a
/// single-file gotcha; callers require `--yes` when it is non-empty.
fn blast_radius(target: &str, affected_files: &[String]) -> Vec<String> {
    affected_files
        .iter()
        .map(|f| normalize_rel(f))
        .filter(|f| f != target)
        .collect()
}

/// Resolve a repo-relative path to an absolute, canonical path UNDER `repo_root`.
/// Returns `None` if it resolves outside the repo (safety: a gotcha must never
/// deny `~` / `/etc` and brick the agent's shell).
fn resolve_under_repo(repo_root: &Path, rel: &str) -> Option<PathBuf> {
    let resolved = canonicalize_lenient(&repo_root.join(rel))?;
    resolved.starts_with(repo_root).then_some(resolved)
}

/// `std::fs::canonicalize` that tolerates a non-existent leaf: canonicalize the
/// longest existing ancestor (resolving symlinks), then re-append the missing
/// tail. So a file not yet created — or one under a symlinked parent — still
/// yields the canonical path Seatbelt will match.
fn canonicalize_lenient(path: &Path) -> Option<PathBuf> {
    if let Ok(c) = std::fs::canonicalize(path) {
        return Some(c);
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = path;
    loop {
        let parent = cur.parent()?;
        tail.push(cur.file_name()?.to_os_string());
        if let Ok(cp) = std::fs::canonicalize(parent) {
            let mut out = cp;
            for comp in tail.iter().rev() {
                out.push(comp);
            }
            return Some(out);
        }
        cur = parent;
    }
}

/// Resolve relative rules to absolute paths under `repo_root`; return the
/// absolute rules plus any paths skipped for resolving outside the repo.
fn resolve_rules(repo_root: &Path, rel: &SandboxRules) -> (SandboxRules, BTreeSet<String>) {
    let mut abs = SandboxRules::default();
    let mut skipped = BTreeSet::new();
    for r in &rel.deny_write {
        match resolve_under_repo(repo_root, r) {
            Some(p) => {
                abs.deny_write.insert(p.to_string_lossy().into_owned());
            }
            None => {
                skipped.insert(r.clone());
            }
        }
    }
    for r in &rel.deny_read {
        match resolve_under_repo(repo_root, r) {
            Some(p) => {
                abs.deny_read.insert(p.to_string_lossy().into_owned());
            }
            None => {
                skipped.insert(r.clone());
            }
        }
    }
    (abs, skipped)
}

// ── settings.local.json materialization (pure transforms + IO) ───────────────

/// An entry is mati-owned iff it is an absolute path under the canonical repo
/// root. The user's `~/`, `./`, and out-of-repo absolute denies are NOT owned.
fn is_mati_owned(entry: &str, repo_root: &Path) -> bool {
    Path::new(entry).starts_with(repo_root)
}

/// Merge mati's absolute deny rules into a settings object, owning only entries
/// under `repo_root` and preserving everything else. Pure.
fn apply_into_settings(mut root: Value, repo_root: &Path, abs: &SandboxRules) -> Value {
    {
        let sandbox = ensure_child(&mut root, "sandbox");
        let fs = ensure_child(sandbox, "filesystem");
        set_owned_array(fs, "denyWrite", repo_root, &abs.deny_write);
        set_owned_array(fs, "denyRead", repo_root, &abs.deny_read);
    }
    root
}

/// Remove mati-owned (under-repo) entries from the sandbox deny arrays. Pure.
fn clear_from_settings(mut root: Value, repo_root: &Path) -> Value {
    if let Some(fs) = nav_mut(&mut root, &["sandbox", "filesystem"]) {
        set_owned_array(fs, "denyWrite", repo_root, &BTreeSet::new());
        set_owned_array(fs, "denyRead", repo_root, &BTreeSet::new());
    }
    root
}

/// Rewrite `key`'s array to `(existing entries NOT mati-owned) ∪ mati`. Removes
/// the key entirely when the result is empty (no dangling `[]`).
fn set_owned_array(fs: &mut Value, key: &str, repo_root: &Path, mati: &BTreeSet<String>) {
    let Value::Object(map) = fs else {
        return;
    };
    let mut kept: Vec<Value> = Vec::new();
    if let Some(Value::Array(existing)) = map.get(key) {
        for v in existing {
            match v.as_str() {
                Some(s) if is_mati_owned(s, repo_root) => {} // drop: mati-managed, recomputed below
                _ => kept.push(v.clone()),                   // preserve user entries / non-strings
            }
        }
    }
    kept.extend(mati.iter().map(|m| Value::String(m.clone())));
    if kept.is_empty() {
        map.remove(key);
    } else {
        map.insert(key.to_string(), Value::Array(kept));
    }
}

fn ensure_child<'a>(v: &'a mut Value, key: &str) -> &'a mut Value {
    if !v.is_object() {
        *v = Value::Object(Map::new());
    }
    match v {
        Value::Object(map) => map
            .entry(key.to_string())
            .or_insert_with(|| Value::Object(Map::new())),
        _ => unreachable!("v was just coerced to an object"),
    }
}

fn nav_mut<'a>(root: &'a mut Value, keys: &[&str]) -> Option<&'a mut Value> {
    let mut cur = root;
    for k in keys {
        cur = cur.as_object_mut()?.get_mut(*k)?;
    }
    Some(cur)
}

fn read_settings(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(Value::Object(Map::new()));
    }
    let s = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    if s.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    let v: Value = serde_json::from_str(&s).with_context(|| {
        format!(
            "{} is not valid JSON — fix or remove it (refusing to overwrite)",
            path.display()
        )
    })?;
    if !v.is_object() {
        bail!("{} is not a JSON object", path.display());
    }
    validate_sandbox_shape(&v)?;
    Ok(v)
}

/// Refuse to proceed if the user's existing sandbox config has the wrong shape —
/// never silently coerce/discard their data.
fn validate_sandbox_shape(root: &Value) -> Result<()> {
    let Some(sb) = root.get("sandbox") else {
        return Ok(());
    };
    if !sb.is_object() {
        bail!("settings `sandbox` is not an object");
    }
    let Some(fs) = sb.get("filesystem") else {
        return Ok(());
    };
    if !fs.is_object() {
        bail!("settings `sandbox.filesystem` is not an object");
    }
    for k in ["denyRead", "denyWrite"] {
        if let Some(a) = fs.get(k) {
            if !a.is_array() {
                bail!("settings `sandbox.filesystem.{k}` is not an array");
            }
        }
    }
    Ok(())
}

/// Atomic write: serialize, write a sibling temp file, then rename over the
/// target (same directory → same filesystem → atomic).
fn write_settings_atomic(path: &Path, v: &Value) -> Result<()> {
    let dir = path.parent().context("settings path has no parent")?;
    std::fs::create_dir_all(dir)?;
    let body = serde_json::to_string_pretty(v)? + "\n";
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("settings.local.json");
    let tmp = path.with_file_name(format!(".{name}.mati-tmp"));
    std::fs::write(&tmp, body.as_bytes()).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
    Ok(())
}

// ── command entry points ─────────────────────────────────────────────────────

pub async fn run(args: SandboxArgs) -> Result<()> {
    match args.command {
        SandboxCommand::Compile(a) => run_compile(a).await,
        SandboxCommand::Protect(a) => run_protect(a, true).await,
        SandboxCommand::Unprotect(a) => run_protect(a, false).await,
        SandboxCommand::Clear => run_clear().await,
    }
}

/// The project root that `affected_files` are relative to and where `.claude`
/// lives — the nearest ancestor with a `.claude` or `.git` marker, NOT the
/// `~/.mati/<slug>` store dir. Falls back to the canonical cwd.
fn repo_root_for(cwd: &Path) -> Result<PathBuf> {
    let start = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let mut dir: &Path = &start;
    loop {
        if dir.join(".claude").is_dir() || dir.join(".git").exists() {
            return Ok(dir.to_path_buf());
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => break,
        }
    }
    Ok(start)
}

fn settings_local_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".claude").join("settings.local.json")
}

async fn run_compile(args: CompileArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo_root = repo_root_for(&cwd)?;
    let store = StoreProxy::open(&cwd).await?;
    let (abs, skipped, warnings) = compute_rules(&store, &repo_root).await?;
    for w in &warnings {
        eprintln!("warning: {w}");
    }
    for s in &skipped {
        eprintln!(
            "warning: {s} resolves outside the repo — skipped (denies are clamped to the repo)"
        );
    }

    let path = settings_local_path(&repo_root);
    if args.apply {
        materialize(&path, &repo_root, &abs, true, args.force)?;
        println!(
            "Applied {} denyWrite + {} denyRead entr{} to {}",
            abs.deny_write.len(),
            abs.deny_read.len(),
            if abs.deny_write.len() + abs.deny_read.len() == 1 {
                "y"
            } else {
                "ies"
            },
            path.display()
        );
        enablement_hint();
    } else {
        if let Ok(existing) = read_settings(&path) {
            for r in drifted_removals(&existing, &repo_root, &abs) {
                eprintln!("drift: {r} is in your sandbox config but no longer has a confirmed crown-jewel gotcha — `--apply` would remove it");
            }
        }
        print_preview(&abs, &path);
    }
    Ok(())
}

/// Scan the store → absolute deny rules, plus out-of-repo skips and warnings.
async fn compute_rules(
    store: &StoreProxy,
    repo_root: &Path,
) -> Result<(SandboxRules, BTreeSet<String>, Vec<String>)> {
    let records = store.scan_prefix("gotcha:").await?;
    let mut warnings = Vec::new();
    let mut items: Vec<(Vec<String>, bool, bool, Vec<String>)> = Vec::new();
    for r in &records {
        let active = matches!(r.lifecycle, RecordLifecycle::Active);
        let (confirmed, files) = match r.payload_as::<GotchaRecord>() {
            Some(g) => (g.confirmed, g.affected_files),
            None => (false, Vec::new()),
        };
        let tagged = r
            .tags
            .iter()
            .any(|t| t == TAG_DENY_WRITE || t == TAG_DENY_READ);
        if tagged && active && !confirmed {
            warnings.push(format!(
                "{} is tagged crown-jewel but not confirmed — not enforced (run `mati gotcha confirm`)",
                r.key
            ));
        } else if tagged && active && files.is_empty() {
            warnings.push(format!(
                "{} is tagged crown-jewel but has no affected_files",
                r.key
            ));
        }
        items.push((r.tags.clone(), active, confirmed, files));
    }
    let rel = compile_relative(items.iter().map(|(t, a, c, f)| GotchaSel {
        tags: t,
        active: *a,
        confirmed: *c,
        files: f,
    }));
    let (abs, skipped) = resolve_rules(repo_root, &rel);
    Ok((abs, skipped, warnings))
}

/// Write the rules into settings.local.json. When `guarded`, refuse to remove
/// mati-owned entries that drifted (their crown-jewel tag is gone) unless
/// `force` — a security floor is never silently removed.
fn materialize(
    path: &Path,
    repo_root: &Path,
    abs: &SandboxRules,
    guarded: bool,
    force: bool,
) -> Result<()> {
    let existing = read_settings(path)?;
    let removals = drifted_removals(&existing, repo_root, abs);
    if guarded && !removals.is_empty() && !force {
        eprintln!(
            "Refusing to remove {} sandbox protection(s) whose crown-jewel tag is gone:",
            removals.len()
        );
        for r in &removals {
            eprintln!("  {r}");
        }
        bail!("re-tag via `mati sandbox protect <file>`, or pass --force to remove them");
    }
    for r in &removals {
        eprintln!("note: removing sandbox protection for {r}");
    }
    let merged = apply_into_settings(existing, repo_root, abs);
    write_settings_atomic(path, &merged)
}

/// mati-owned (under-repo) entries currently in settings that `abs` would drop.
fn drifted_removals(existing: &Value, repo_root: &Path, abs: &SandboxRules) -> BTreeSet<String> {
    let mut removed = BTreeSet::new();
    for (key, new_set) in [("denyWrite", &abs.deny_write), ("denyRead", &abs.deny_read)] {
        let Some(arr) = settings_array(existing, key) else {
            continue;
        };
        for s in arr.iter().filter_map(|v| v.as_str()) {
            if is_mati_owned(s, repo_root) && !new_set.contains(s) {
                removed.insert(s.to_string());
            }
        }
    }
    removed
}

fn settings_array<'a>(root: &'a Value, key: &str) -> Option<&'a Vec<Value>> {
    root.get("sandbox")?.get("filesystem")?.get(key)?.as_array()
}

fn add_tags(tags: &mut Vec<String>, add: &[&str]) {
    for t in add {
        if !tags.iter().any(|x| x == t) {
            tags.push((*t).to_string());
        }
    }
}

fn remove_tags(tags: &mut Vec<String>, rm: &[&str]) {
    tags.retain(|t| !rm.iter().any(|r| r == t));
}

/// `protect`/`unprotect`: (un)tag a file's confirmed gotcha(s) crown-jewel, then
/// re-sync settings.local.json. Intentional, so the drift guard is off.
async fn run_protect(args: ProtectArgs, add: bool) -> Result<()> {
    let verb = if add { "protect" } else { "unprotect" };
    let cwd = std::env::current_dir()?;
    let repo_root = repo_root_for(&cwd)?;
    let store = StoreProxy::open(&cwd).await?;
    let file = normalize_rel(&args.file);

    let matched: Vec<Record> = store
        .scan_prefix("gotcha:")
        .await?
        .into_iter()
        .filter(|r| {
            matches!(r.lifecycle, RecordLifecycle::Active)
                && r.payload_as::<GotchaRecord>()
                    .map(|g| {
                        g.confirmed && g.affected_files.iter().any(|af| normalize_rel(af) == file)
                    })
                    .unwrap_or(false)
        })
        .collect();
    if matched.is_empty() {
        bail!(
            "no confirmed gotcha covers `{file}` — add one first:\n  \
             mati gotcha add {file} -r \"<rule>\"   then   mati gotcha confirm <key>"
        );
    }

    // Blast radius: the crown-jewel tag is per-gotcha, so a multi-file gotcha
    // would (un)protect ALL its files. Surface that and require --yes.
    for r in &matched {
        if let Some(g) = r.payload_as::<GotchaRecord>() {
            let others = blast_radius(&file, &g.affected_files);
            if !others.is_empty() && !args.yes {
                eprintln!("`{}` also covers: {}", r.key, others.join(", "));
                bail!("the crown-jewel tag is per-gotcha, so this would {verb} those too — re-run with --yes to confirm, or split the gotcha");
            }
        }
    }

    let to_add: Vec<&str> = if args.read {
        vec![TAG_DENY_WRITE, TAG_DENY_READ]
    } else {
        vec![TAG_DENY_WRITE]
    };
    let mut n = 0;
    for r in &matched {
        if let Some(mut rec) = store.get(&r.key).await? {
            if add {
                add_tags(&mut rec.tags, &to_add);
            } else {
                remove_tags(&mut rec.tags, &[TAG_DENY_WRITE, TAG_DENY_READ]);
            }
            store.put(&r.key, &rec).await?;
            n += 1;
        }
    }

    // Re-materialize — intentional change, so the drift guard is off.
    let (abs, _skipped, _warnings) = compute_rules(&store, &repo_root).await?;
    let path = settings_local_path(&repo_root);
    materialize(&path, &repo_root, &abs, false, true)?;

    println!(
        "{}ed `{file}` ({n} gotcha(s) updated); synced {}.",
        if add { "Protect" } else { "Unprotect" },
        path.display()
    );
    if add {
        enablement_hint();
    }
    Ok(())
}

async fn run_clear() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo_root = repo_root_for(&cwd)?;
    let path = settings_local_path(&repo_root);
    if !path.exists() {
        println!("Nothing to clear: {} does not exist.", path.display());
        return Ok(());
    }
    let existing = read_settings(&path)?;
    let cleared = clear_from_settings(existing, &repo_root);
    write_settings_atomic(&path, &cleared)?;
    println!(
        "Cleared mati-managed (in-repo) sandbox deny rules from {}",
        path.display()
    );
    Ok(())
}

fn enablement_hint() {
    println!(
        "\nThese OS-level denies cover the agent's shell and every subprocess it spawns;\n\
         the agent can still reach the files through the consultation-gated Read/Edit\n\
         tools (L1). They take effect only once the Claude Code sandbox is enabled\n\
         (`/sandbox`, or `sandbox.enabled` in settings) on macOS / Linux / WSL2.\n\
         Run `mati sandbox clear` to remove them."
    );
}

fn print_preview(abs: &SandboxRules, path: &Path) {
    if abs.is_empty() {
        println!("No crown-jewel gotchas resolve to in-repo files.");
        println!(
            "Tag a confirmed gotcha with `{TAG_DENY_WRITE}` (deny shell writes) or \
             `{TAG_DENY_READ}` (deny shell reads), then `mati sandbox compile --apply`."
        );
        return;
    }
    println!(
        "Sandbox floor preview — nothing written. `--apply` writes to {}.\n",
        path.display()
    );
    if !abs.deny_write.is_empty() {
        println!("  denyWrite (shell / subprocess cannot modify):");
        for p in &abs.deny_write {
            println!("    {p}");
        }
    }
    if !abs.deny_read.is_empty() {
        println!("  denyRead (shell / subprocess cannot read):");
        for p in &abs.deny_read {
            println!("    {p}");
        }
    }
    enablement_hint();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }
    fn sel<'a>(tags: &'a [String], confirmed: bool, files: &'a [String]) -> GotchaSel<'a> {
        GotchaSel {
            tags,
            active: true,
            confirmed,
            files,
        }
    }

    // ── compile_relative (pure selection) ────────────────────────────────────

    #[test]
    fn crown_jewel_maps_to_deny_write_relative() {
        let t = sv(&["crown-jewel"]);
        let f = sv(&["./src/payments/fraud.rs"]);
        let r = compile_relative([sel(&t, true, &f)].into_iter());
        assert!(r.deny_write.contains("src/payments/fraud.rs"));
        assert!(r.deny_read.is_empty());
    }

    #[test]
    fn deny_read_tag_and_compose() {
        let t = sv(&["crown-jewel", "sandbox-deny-read"]);
        let f = sv(&["secrets/key.pem"]);
        let r = compile_relative([sel(&t, true, &f)].into_iter());
        assert!(r.deny_write.contains("secrets/key.pem"));
        assert!(r.deny_read.contains("secrets/key.pem"));
    }

    #[test]
    fn unconfirmed_inactive_and_untagged_contribute_nothing() {
        let t = sv(&["crown-jewel"]);
        let f = sv(&["src/x.rs"]);
        // unconfirmed
        assert!(compile_relative([sel(&t, false, &f)].into_iter()).is_empty());
        // inactive (tombstoned/superseded)
        let inactive = GotchaSel {
            tags: &t,
            active: false,
            confirmed: true,
            files: &f,
        };
        assert!(compile_relative([inactive].into_iter()).is_empty());
        // untagged
        let untagged = sv(&["enriched", "depth:deep"]);
        assert!(compile_relative([sel(&untagged, true, &f)].into_iter()).is_empty());
    }

    // ── ownership / merge (pure transforms) ──────────────────────────────────

    #[test]
    fn is_mati_owned_only_under_repo() {
        let repo = Path::new("/work/repo");
        assert!(is_mati_owned("/work/repo/src/x.rs", repo));
        assert!(!is_mati_owned("/work/other/x.rs", repo));
        assert!(!is_mati_owned("~/.ssh/id_rsa", repo));
        assert!(!is_mati_owned("./src/x.rs", repo));
    }

    #[test]
    fn apply_preserves_user_entries_and_owns_in_repo() {
        let repo = Path::new("/work/repo");
        let existing = json!({
            "sandbox": { "filesystem": { "denyWrite": ["~/.ssh", "/work/repo/OLD.rs"] } },
            "env": { "X": "1" }
        });
        let mut abs = SandboxRules::default();
        abs.deny_write.insert("/work/repo/src/new.rs".to_string());
        let out = apply_into_settings(existing, repo, &abs);
        let dw = out["sandbox"]["filesystem"]["denyWrite"]
            .as_array()
            .unwrap();
        let set: BTreeSet<&str> = dw.iter().filter_map(|v| v.as_str()).collect();
        assert!(set.contains("~/.ssh"), "user entry preserved");
        assert!(
            set.contains("/work/repo/src/new.rs"),
            "new mati entry present"
        );
        assert!(
            !set.contains("/work/repo/OLD.rs"),
            "stale in-repo entry dropped"
        );
        assert_eq!(out["env"]["X"], "1", "unrelated settings untouched");
    }

    #[test]
    fn apply_is_idempotent() {
        let repo = Path::new("/work/repo");
        let mut abs = SandboxRules::default();
        abs.deny_read.insert("/work/repo/.env".to_string());
        let once = apply_into_settings(json!({}), repo, &abs);
        let twice = apply_into_settings(once.clone(), repo, &abs);
        assert_eq!(once, twice);
    }

    #[test]
    fn clear_removes_only_in_repo_entries() {
        let repo = Path::new("/work/repo");
        let existing = json!({
            "sandbox": { "filesystem": {
                "denyWrite": ["/work/repo/a.rs", "~/.aws"],
                "denyRead": ["/work/repo/.env"]
            } }
        });
        let out = clear_from_settings(existing, repo);
        let dw: Vec<&str> = out["sandbox"]["filesystem"]["denyWrite"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(dw, vec!["~/.aws"], "user entry kept, mati entry removed");
        // denyRead had only an in-repo entry → array removed entirely
        assert!(out["sandbox"]["filesystem"].get("denyRead").is_none());
    }

    #[test]
    fn validate_rejects_malformed_shape() {
        assert!(validate_sandbox_shape(&json!({"sandbox": "on"})).is_err());
        assert!(validate_sandbox_shape(&json!({"sandbox": {"filesystem": []}})).is_err());
        assert!(
            validate_sandbox_shape(&json!({"sandbox": {"filesystem": {"denyRead": "x"}}})).is_err()
        );
        assert!(
            validate_sandbox_shape(&json!({"sandbox": {"filesystem": {"denyRead": ["x"]}}}))
                .is_ok()
        );
        assert!(validate_sandbox_shape(&json!({})).is_ok());
    }

    // ── tag helpers + drift detection ────────────────────────────────────────

    #[test]
    fn add_and_remove_tags_dedupe() {
        let mut tags = sv(&["enriched"]);
        add_tags(&mut tags, &["crown-jewel", "sandbox-deny-read"]);
        add_tags(&mut tags, &["crown-jewel"]); // idempotent
        assert_eq!(tags.iter().filter(|t| *t == "crown-jewel").count(), 1);
        assert!(tags.contains(&"sandbox-deny-read".to_string()));
        remove_tags(&mut tags, &["crown-jewel", "sandbox-deny-read"]);
        assert_eq!(tags, sv(&["enriched"]), "only the sandbox tags are removed");
    }

    #[test]
    fn drifted_removals_flags_dropped_tag_only() {
        let repo = Path::new("/work/repo");
        let existing = json!({ "sandbox": { "filesystem": {
            "denyWrite": ["/work/repo/still.rs", "/work/repo/dropped.rs", "~/.ssh"]
        } } });
        let mut abs = SandboxRules::default();
        abs.deny_write.insert("/work/repo/still.rs".to_string());
        let drift = drifted_removals(&existing, repo, &abs);
        assert!(
            drift.contains("/work/repo/dropped.rs"),
            "tag-dropped entry flagged"
        );
        assert!(
            !drift.contains("/work/repo/still.rs"),
            "still-protected not flagged"
        );
        assert!(!drift.contains("~/.ssh"), "user entry never flagged");
    }

    // ── path resolution (filesystem) ─────────────────────────────────────────

    #[test]
    fn resolve_clamps_to_repo_and_handles_missing_leaf() {
        let dir = std::env::temp_dir().join(format!("mati-sbx-test-{}", std::process::id()));
        let repo = dir.join("repo");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(repo.join("src/exists.rs"), "x").unwrap();
        let repo = std::fs::canonicalize(&repo).unwrap();

        // existing file → resolved under repo
        assert!(resolve_under_repo(&repo, "src/exists.rs").is_some());
        // not-yet-existent leaf → still resolves (lenient ancestor canonicalize)
        let missing = resolve_under_repo(&repo, "src/not_yet.rs");
        assert!(missing.is_some());
        assert!(missing.unwrap().starts_with(&repo));
        // escapes the repo → skipped
        assert!(resolve_under_repo(&repo, "../escape.rs").is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    // ── command-path edges (blast radius, drift guard, subdir launch) ────────

    #[test]
    fn blast_radius_lists_only_extra_files() {
        assert!(blast_radius("src/a.rs", &sv(&["src/a.rs"])).is_empty());
        let extra = blast_radius("src/a.rs", &sv(&["src/a.rs", "./src/b.rs", "src/c.rs"]));
        assert_eq!(
            extra,
            sv(&["src/b.rs", "src/c.rs"]),
            "normalized, target excluded"
        );
    }

    #[test]
    fn materialize_guard_blocks_drift_unless_forced() {
        let dir = std::env::temp_dir().join(format!("mati-sbx-mat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Path::new("/work/repo");
        let path = dir.join("settings.local.json");
        std::fs::write(
            &path,
            r#"{"sandbox":{"filesystem":{"denyWrite":["/work/repo/x.rs"]}}}"#,
        )
        .unwrap();
        let empty = SandboxRules::default();
        // guarded + drift + not forced → refuse, and the file is left untouched
        assert!(materialize(&path, repo, &empty, true, false).is_err());
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("/work/repo/x.rs"));
        // forced → removes the drifted entry
        assert!(materialize(&path, repo, &empty, true, true).is_ok());
        assert!(!std::fs::read_to_string(&path)
            .unwrap()
            .contains("/work/repo/x.rs"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn repo_root_walks_up_to_project_marker() {
        let base = std::env::temp_dir().join(format!("mati-sbx-root-{}", std::process::id()));
        let repo = base.join("repo");
        let deep = repo.join("a/b/c");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        let repo_c = std::fs::canonicalize(&repo).unwrap();
        // launched from a deep subdir → resolves up to the .git/.claude root
        assert_eq!(repo_root_for(&deep).unwrap(), repo_c);
        assert_eq!(repo_root_for(&repo).unwrap(), repo_c);
        std::fs::remove_dir_all(&base).ok();
    }
}
