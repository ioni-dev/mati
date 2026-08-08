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

use mati_core::store::{
    GotchaRecord, PolicyMode, PolicyRecord, PolicyStage, Record, RecordLifecycle,
};

use super::proxy::StoreProxy;

/// Tag → shell-deny mapping. Explicit opt-in only; severity is never used.
/// - `crown-jewel`: shell / subprocess cannot WRITE the file (protect critical
///   logic from out-of-gate modification). Reads still work.
/// - `sandbox-deny-read`: additionally, the shell cannot READ the file (secrets).
/// - `secret-deny`: the file compiles into `sandbox.credentials.files` with
///   `mode: "deny"` — the shell/subprocess cannot read it at all.
/// - `secret-mask`: same target, `mode: "mask"` — Claude Code substitutes a
///   sentinel value for the real content (requires `sandbox.network.tlsTerminate`
///   for the proxy to actually inject; without it the file just fails to read).
///
/// Visible to `cli::init`, whose rename migration warns when it re-keys a
/// gotcha that compiles into the floor: the already-materialized
/// settings.local.json still names the pre-rename path.
pub(super) const TAG_DENY_WRITE: &str = "crown-jewel";
pub(super) const TAG_DENY_READ: &str = "sandbox-deny-read";
pub(super) const TAG_SECRET_DENY: &str = "secret-deny";
pub(super) const TAG_SECRET_MASK: &str = "secret-mask";

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
    /// Compile into `sandbox.credentials.files` instead: "deny" refuses reads
    /// outright, "mask" lets Claude Code substitute a sentinel value.
    #[arg(long, value_parser = ["deny", "mask"])]
    pub secret: Option<String>,
    /// Confirm when the gotcha also covers other files (the tag is per-gotcha).
    #[arg(long)]
    pub yes: bool,
}

/// Sandbox filesystem deny rules. Paths are repo-relative after `compile_relative`
/// and absolute-canonical after `resolve_rules`. `denied_domains` are never
/// path-resolved — they are host globs, not filesystem paths.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SandboxRules {
    pub deny_read: BTreeSet<String>,
    pub deny_write: BTreeSet<String>,
    pub credentials_deny: BTreeSet<String>,
    pub credentials_mask: BTreeSet<String>,
    pub denied_domains: BTreeSet<String>,
}

impl SandboxRules {
    pub fn is_empty(&self) -> bool {
        self.deny_read.is_empty()
            && self.deny_write.is_empty()
            && self.credentials_deny.is_empty()
            && self.credentials_mask.is_empty()
            && self.denied_domains.is_empty()
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
        let secret_deny = g.tags.iter().any(|t| t == TAG_SECRET_DENY);
        let secret_mask = g.tags.iter().any(|t| t == TAG_SECRET_MASK);
        if !deny_write && !deny_read && !secret_deny && !secret_mask {
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
                rules.deny_read.insert(rel.clone());
            }
            if secret_deny {
                rules.credentials_deny.insert(rel.clone());
            }
            if secret_mask {
                rules.credentials_mask.insert(rel);
            }
        }
    }
    rules
}

/// Owned scan-result tuple: (active, stage, mode, tool, host_glob).
type PolicyItem = (
    bool,
    PolicyStage,
    PolicyMode,
    Option<String>,
    Option<String>,
);

/// One policy's network-relevant fields, mirroring `GotchaSel`.
pub struct PolicyDomainSel<'a> {
    pub active: bool,
    pub stage: PolicyStage,
    pub mode: PolicyMode,
    pub tool: Option<&'a str>,
    pub host_glob: Option<&'a str>,
}

/// Pure: select `db_client` block-policy host globs that are currently
/// enforcing. Mirrors `compile_relative`'s gating — Active lifecycle, and here
/// `stage == Enforce` stands in for "confirmed": an authored-but-not-staged
/// policy gets no OS floor, same as an unconfirmed gotcha gets no deny.
pub fn compile_domains_relative<'a>(
    policies: impl Iterator<Item = PolicyDomainSel<'a>>,
) -> BTreeSet<String> {
    let mut domains = BTreeSet::new();
    for p in policies {
        if !p.active
            || !matches!(p.stage, PolicyStage::Enforce)
            || !matches!(p.mode, PolicyMode::Block)
        {
            continue;
        }
        if p.tool != Some("db_client") {
            continue;
        }
        if let Some(glob) = p.host_glob {
            let g = glob.trim();
            if !g.is_empty() {
                domains.insert(g.to_string());
            }
        }
    }
    domains
}

/// The full universe of `db_client` host globs any policy in the store has
/// ever named, active or tombstoned, enforcing or not. This is the ownership
/// boundary for `sandbox.network.deniedDomains`: a domain has no filesystem
/// path to test `starts_with(repo_root)` against, so ownership is instead "did
/// some policy in this store ever author this glob" — the policy corpus is the
/// manifest, mirroring how a gotcha's canonical record already outranks its
/// derived file-link index elsewhere in this codebase.
pub fn db_client_host_glob_universe<'a>(
    policies: impl Iterator<Item = (Option<&'a str>, Option<&'a str>)>,
) -> BTreeSet<String> {
    let mut universe = BTreeSet::new();
    for (tool, host_glob) in policies {
        if tool != Some("db_client") {
            continue;
        }
        if let Some(glob) = host_glob {
            let g = glob.trim();
            if !g.is_empty() {
                universe.insert(g.to_string());
            }
        }
    }
    universe
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
///
/// Shared with `cli::hook_decide`'s canonical-key enforcement fallback (WI-20):
/// the read/edit gate resolves a symlinked access path through this same helper
/// so a symlink to a gotcha'd file resolves to the real target's lexical key.
pub(super) fn canonicalize_lenient(path: &Path) -> Option<PathBuf> {
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
/// `denied_domains` pass through untouched — they are host globs, not paths.
fn resolve_rules(repo_root: &Path, rel: &SandboxRules) -> (SandboxRules, BTreeSet<String>) {
    let mut abs = SandboxRules::default();
    let mut skipped = BTreeSet::new();
    let mut resolve_into = |rels: &BTreeSet<String>, into: &mut BTreeSet<String>| {
        for r in rels {
            match resolve_under_repo(repo_root, r) {
                Some(p) => {
                    into.insert(p.to_string_lossy().into_owned());
                }
                None => {
                    skipped.insert(r.clone());
                }
            }
        }
    };
    resolve_into(&rel.deny_write, &mut abs.deny_write);
    resolve_into(&rel.deny_read, &mut abs.deny_read);
    resolve_into(&rel.credentials_deny, &mut abs.credentials_deny);
    resolve_into(&rel.credentials_mask, &mut abs.credentials_mask);
    abs.denied_domains = rel.denied_domains.clone();
    (abs, skipped)
}

// ── settings.local.json materialization (pure transforms + IO) ───────────────

/// An entry is mati-owned iff it is an absolute path under the canonical repo
/// root. The user's `~/`, `./`, and out-of-repo absolute denies are NOT owned.
fn is_mati_owned(entry: &str, repo_root: &Path) -> bool {
    Path::new(entry).starts_with(repo_root)
}

/// Merge mati's absolute deny rules into a settings object, owning only entries
/// under `repo_root` (or, for domains, in `domain_universe`) and preserving
/// everything else. Pure.
fn apply_into_settings(
    mut root: Value,
    repo_root: &Path,
    abs: &SandboxRules,
    domain_universe: &BTreeSet<String>,
) -> Value {
    {
        let sandbox = ensure_child(&mut root, "sandbox");
        let fs = ensure_child(sandbox, "filesystem");
        set_owned_array(fs, "denyWrite", repo_root, &abs.deny_write);
        set_owned_array(fs, "denyRead", repo_root, &abs.deny_read);
    }
    {
        let sandbox = ensure_child(&mut root, "sandbox");
        let creds = ensure_child(sandbox, "credentials");
        set_owned_credential_files(
            creds,
            repo_root,
            &abs.credentials_deny,
            &abs.credentials_mask,
        );
    }
    {
        let sandbox = ensure_child(&mut root, "sandbox");
        let net = ensure_child(sandbox, "network");
        set_owned_domains(net, domain_universe, &abs.denied_domains);
    }
    root
}

/// Remove mati-owned entries from the sandbox deny/credentials/network blocks.
/// Pure. `domain_universe` still must be passed — a domain has no path to test
/// `starts_with(repo_root)` against, so clearing needs the same ownership
/// lookup `apply` uses, computed from the current policy corpus.
fn clear_from_settings(
    mut root: Value,
    repo_root: &Path,
    domain_universe: &BTreeSet<String>,
) -> Value {
    if let Some(fs) = nav_mut(&mut root, &["sandbox", "filesystem"]) {
        set_owned_array(fs, "denyWrite", repo_root, &BTreeSet::new());
        set_owned_array(fs, "denyRead", repo_root, &BTreeSet::new());
    }
    if let Some(creds) = nav_mut(&mut root, &["sandbox", "credentials"]) {
        set_owned_credential_files(creds, repo_root, &BTreeSet::new(), &BTreeSet::new());
    }
    if let Some(net) = nav_mut(&mut root, &["sandbox", "network"]) {
        set_owned_domains(net, domain_universe, &BTreeSet::new());
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

/// Rewrite `credentials.files` to `(existing entries NOT mati-owned) ∪ mati`.
/// A mati-owned entry is `{"mode": ..., "path": <abs path under repo_root>}`;
/// a malformed or non-mati-owned entry is preserved verbatim.
fn set_owned_credential_files(
    creds: &mut Value,
    repo_root: &Path,
    deny: &BTreeSet<String>,
    mask: &BTreeSet<String>,
) {
    let Value::Object(map) = creds else {
        return;
    };
    let mut kept: Vec<Value> = Vec::new();
    if let Some(Value::Array(existing)) = map.get("files") {
        for v in existing {
            let owned = v
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(|p| is_mati_owned(p, repo_root));
            if !owned {
                kept.push(v.clone());
            }
        }
    }
    for (mode, paths) in [("deny", deny), ("mask", mask)] {
        for p in paths {
            kept.push(serde_json::json!({ "mode": mode, "path": p }));
        }
    }
    if kept.is_empty() {
        map.remove("files");
    } else {
        map.insert("files".to_string(), Value::Array(kept));
    }
    if map.is_empty() {
        *creds = Value::Object(Map::new());
    }
}

/// Rewrite `network.deniedDomains` to `(existing entries NOT in domain_universe)
/// ∪ mati`. `domain_universe` is every `db_client` host glob any policy in the
/// store has ever named — see `db_client_host_glob_universe` — since a domain
/// string carries no repo-root path to test ownership against.
fn set_owned_domains(net: &mut Value, domain_universe: &BTreeSet<String>, mati: &BTreeSet<String>) {
    let Value::Object(map) = net else {
        return;
    };
    let mut kept: Vec<Value> = Vec::new();
    if let Some(Value::Array(existing)) = map.get("deniedDomains") {
        for v in existing {
            match v.as_str() {
                Some(s) if domain_universe.contains(s) => {} // drop: mati-managed, recomputed below
                _ => kept.push(v.clone()),
            }
        }
    }
    kept.extend(mati.iter().map(|d| Value::String(d.clone())));
    if kept.is_empty() {
        map.remove("deniedDomains");
    } else {
        map.insert("deniedDomains".to_string(), Value::Array(kept));
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
    if let Some(creds) = sb.get("credentials") {
        if !creds.is_object() {
            bail!("settings `sandbox.credentials` is not an object");
        }
        if let Some(files) = creds.get("files") {
            if !files.is_array() {
                bail!("settings `sandbox.credentials.files` is not an array");
            }
        }
    }
    if let Some(net) = sb.get("network") {
        if !net.is_object() {
            bail!("settings `sandbox.network` is not an object");
        }
        if let Some(dd) = net.get("deniedDomains") {
            if !dd.is_array() {
                bail!("settings `sandbox.network.deniedDomains` is not an array");
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
pub(crate) fn repo_root_for(cwd: &Path) -> Result<PathBuf> {
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
    let (abs, skipped, domain_universe, warnings) = compute_rules(&store, &repo_root).await?;
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
        materialize(&path, &repo_root, &abs, &domain_universe, true, args.force)?;
        audit_sandbox(&store, "apply", &abs).await;
        println!(
            "Applied {} denyWrite + {} denyRead + {} credentials + {} deniedDomains entries to {}",
            abs.deny_write.len(),
            abs.deny_read.len(),
            abs.credentials_deny.len() + abs.credentials_mask.len(),
            abs.denied_domains.len(),
            path.display()
        );
        enablement_hint();
    } else {
        if let Ok(existing) = read_settings(&path) {
            for r in drifted_removals(&existing, &repo_root, &abs, &domain_universe) {
                eprintln!("drift: {r} is in your sandbox config but no longer has a confirmed crown-jewel gotcha, secret tag, or enforcing db_client policy — `--apply` would remove it");
            }
        }
        print_preview(&abs, &path);
    }
    Ok(())
}

/// Scan the store → absolute deny rules, plus out-of-repo skips, the
/// `db_client` host-glob ownership universe, and warnings.
pub(crate) async fn compute_rules(
    store: &StoreProxy,
    repo_root: &Path,
) -> Result<(
    SandboxRules,
    BTreeSet<String>,
    BTreeSet<String>,
    Vec<String>,
)> {
    let records = store.scan_prefix("gotcha:").await?;
    let mut warnings = Vec::new();
    let mut items: Vec<(Vec<String>, bool, bool, Vec<String>)> = Vec::new();
    for r in &records {
        let active = matches!(r.lifecycle, RecordLifecycle::Active);
        let (confirmed, files) = match r.payload_as::<GotchaRecord>() {
            Some(g) => (g.confirmed, g.affected_files),
            None => (false, Vec::new()),
        };
        let tagged = r.tags.iter().any(|t| {
            t == TAG_DENY_WRITE
                || t == TAG_DENY_READ
                || t == TAG_SECRET_DENY
                || t == TAG_SECRET_MASK
        });
        if tagged && active && !confirmed {
            warnings.push(format!(
                "{} is tagged for the sandbox floor but not confirmed — not enforced (run `mati gotcha confirm`)",
                r.key
            ));
        } else if tagged && active && files.is_empty() {
            warnings.push(format!(
                "{} is tagged for the sandbox floor but has no affected_files",
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
    let (mut abs, skipped) = resolve_rules(repo_root, &rel);

    let policies = store.scan_prefix("policy:").await?;
    let mut policy_items: Vec<PolicyItem> = Vec::new();
    for r in &policies {
        let active = matches!(r.lifecycle, RecordLifecycle::Active);
        if let Some(p) = r.payload_as::<PolicyRecord>() {
            let db_client = p.trigger.tool.as_deref() == Some("db_client");
            if db_client
                && matches!(p.stage, PolicyStage::Enforce)
                && matches!(p.mode, PolicyMode::Block)
                && p.trigger.host_glob.is_none()
            {
                warnings.push(format!(
                    "{} is an enforcing db_client block policy but has no host_glob — no domain compiled",
                    r.key
                ));
            }
            policy_items.push((active, p.stage, p.mode, p.trigger.tool, p.trigger.host_glob));
        }
    }
    abs.denied_domains = compile_domains_relative(policy_items.iter().map(
        |(active, stage, mode, tool, host_glob)| PolicyDomainSel {
            active: *active,
            stage: *stage,
            mode: *mode,
            tool: tool.as_deref(),
            host_glob: host_glob.as_deref(),
        },
    ));
    let domain_universe = db_client_host_glob_universe(
        policy_items
            .iter()
            .map(|(_, _, _, tool, host_glob)| (tool.as_deref(), host_glob.as_deref())),
    );

    Ok((abs, skipped, domain_universe, warnings))
}

/// The `db_client` host-glob ownership universe, scanned fresh — used where
/// only that (not the full rule set) is needed, e.g. `mati sandbox clear`.
async fn scan_domain_universe(store: &StoreProxy) -> BTreeSet<String> {
    let policies = store.scan_prefix("policy:").await.unwrap_or_default();
    let pairs: Vec<(Option<String>, Option<String>)> = policies
        .iter()
        .filter_map(|r| r.payload_as::<PolicyRecord>())
        .map(|p| (p.trigger.tool, p.trigger.host_glob))
        .collect();
    db_client_host_glob_universe(pairs.iter().map(|(t, h)| (t.as_deref(), h.as_deref())))
}

/// Write the rules into settings.local.json. When `guarded`, refuse to remove
/// mati-owned entries that drifted (their tag or enforcing policy is gone)
/// unless `force` — a security floor is never silently removed.
fn materialize(
    path: &Path,
    repo_root: &Path,
    abs: &SandboxRules,
    domain_universe: &BTreeSet<String>,
    guarded: bool,
    force: bool,
) -> Result<()> {
    let existing = read_settings(path)?;
    let removals = drifted_removals(&existing, repo_root, abs, domain_universe);
    if guarded && !removals.is_empty() && !force {
        eprintln!(
            "Refusing to remove {} sandbox protection(s) whose tag or enforcing policy is gone:",
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
    let merged = apply_into_settings(existing, repo_root, abs, domain_universe);
    write_settings_atomic(path, &merged)
}

/// mati-owned entries currently in settings that `abs` would drop: filesystem
/// denies (owned by repo-root path), credential files (same), and denied
/// domains (owned by membership in `domain_universe`).
fn drifted_removals(
    existing: &Value,
    repo_root: &Path,
    abs: &SandboxRules,
    domain_universe: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut removed = BTreeSet::new();
    for (key, new_set) in [("denyWrite", &abs.deny_write), ("denyRead", &abs.deny_read)] {
        let Some(arr) = settings_array(existing, &["sandbox", "filesystem"], key) else {
            continue;
        };
        for s in arr.iter().filter_map(|v| v.as_str()) {
            if is_mati_owned(s, repo_root) && !new_set.contains(s) {
                removed.insert(s.to_string());
            }
        }
    }
    if let Some(arr) = settings_array(existing, &["sandbox", "credentials"], "files") {
        let current: BTreeSet<&String> = abs
            .credentials_deny
            .iter()
            .chain(&abs.credentials_mask)
            .collect();
        for v in arr {
            if let Some(p) = v.get("path").and_then(Value::as_str) {
                if is_mati_owned(p, repo_root) && !current.contains(&p.to_string()) {
                    removed.insert(p.to_string());
                }
            }
        }
    }
    if let Some(arr) = settings_array(existing, &["sandbox", "network"], "deniedDomains") {
        for s in arr.iter().filter_map(|v| v.as_str()) {
            if domain_universe.contains(s) && !abs.denied_domains.contains(s) {
                removed.insert(s.to_string());
            }
        }
    }
    removed
}

fn settings_array<'a>(root: &'a Value, path: &[&str], key: &str) -> Option<&'a Vec<Value>> {
    let mut cur = root;
    for p in path {
        cur = cur.get(p)?;
    }
    cur.get(key)?.as_array()
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

    let to_add: Vec<&str> = match args.secret.as_deref() {
        Some("deny") => vec![TAG_SECRET_DENY],
        Some("mask") => vec![TAG_SECRET_MASK],
        _ if args.read => vec![TAG_DENY_WRITE, TAG_DENY_READ],
        _ => vec![TAG_DENY_WRITE],
    };
    let mut n = 0;
    for r in &matched {
        if let Some(mut rec) = store.get(&r.key).await? {
            if add {
                add_tags(&mut rec.tags, &to_add);
            } else {
                remove_tags(
                    &mut rec.tags,
                    &[
                        TAG_DENY_WRITE,
                        TAG_DENY_READ,
                        TAG_SECRET_DENY,
                        TAG_SECRET_MASK,
                    ],
                );
            }
            store.put(&r.key, &rec).await?;
            n += 1;
        }
    }

    // Re-materialize — intentional change, so the drift guard is off.
    let (abs, _skipped, domain_universe, _warnings) = compute_rules(&store, &repo_root).await?;
    let path = settings_local_path(&repo_root);
    materialize(&path, &repo_root, &abs, &domain_universe, false, true)?;
    audit_sandbox(&store, if add { "protect" } else { "unprotect" }, &abs).await;

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

/// Best-effort audit: record the sandbox-floor change as an
/// `EnforcementConfigChanged` event in the hash-chained log (L4 attribution).
/// Records in direct mode — the usual case for this admin command. When a daemon
/// holds the store (an active agent session), it is skipped; socket-mode
/// recording is a documented follow-up.
async fn audit_sandbox(store: &StoreProxy, action: &str, abs: &SandboxRules) {
    let new_value = format!(
        "{} denyWrite + {} denyRead + {} credentials + {} deniedDomains",
        abs.deny_write.len(),
        abs.deny_read.len(),
        abs.credentials_deny.len() + abs.credentials_mask.len(),
        abs.denied_domains.len()
    );
    store
        .record_sandbox_audit(&new_value, &format!("sandbox_{action}"))
        .await;
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
    // The domain-ownership universe needs the current policy corpus even
    // though clear writes nothing derived from it — see `set_owned_domains`.
    let store = StoreProxy::open(&cwd).await.ok();
    let domain_universe = match &store {
        Some(s) => scan_domain_universe(s).await,
        None => {
            // Without the corpus every domain looks like the user's, so clear
            // would drop the paths, keep the domains, and report a full clear.
            eprintln!("warning: store unavailable — sandbox.network.deniedDomains left in place");
            BTreeSet::new()
        }
    };
    let cleared = clear_from_settings(existing, &repo_root, &domain_universe);
    write_settings_atomic(&path, &cleared)?;
    if let Some(store) = &store {
        audit_sandbox(store, "clear", &SandboxRules::default()).await;
    }
    println!(
        "Cleared mati-managed (in-repo) sandbox deny/credentials/network rules from {}",
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
        println!("No crown-jewel/secret gotchas or enforcing db_client policies resolve to in-repo rules.");
        println!(
            "Tag a confirmed gotcha with `{TAG_DENY_WRITE}` (deny shell writes), `{TAG_DENY_READ}` \
             (deny shell reads), `{TAG_SECRET_DENY}`/`{TAG_SECRET_MASK}` (credentials), or enforce a \
             db_client block policy with a host_glob, then `mati sandbox compile --apply`."
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
    if !abs.credentials_deny.is_empty() {
        println!("  credentials.files mode=deny:");
        for p in &abs.credentials_deny {
            println!("    {p}");
        }
    }
    if !abs.credentials_mask.is_empty() {
        println!("  credentials.files mode=mask:");
        for p in &abs.credentials_mask {
            println!("    {p}");
        }
    }
    if !abs.denied_domains.is_empty() {
        println!("  network.deniedDomains (from enforcing db_client policies):");
        for d in &abs.denied_domains {
            println!("    {d}");
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

    #[test]
    fn secret_tags_map_to_credentials_deny_and_mask() {
        let t = sv(&["secret-deny"]);
        let f = sv(&["vault/prod.pem"]);
        let r = compile_relative([sel(&t, true, &f)].into_iter());
        assert!(r.credentials_deny.contains("vault/prod.pem"));
        assert!(r.credentials_mask.is_empty());

        let t = sv(&["secret-mask"]);
        let r = compile_relative([sel(&t, true, &f)].into_iter());
        assert!(r.credentials_mask.contains("vault/prod.pem"));
        assert!(r.credentials_deny.is_empty());
    }

    fn psel<'a>(
        active: bool,
        stage: PolicyStage,
        mode: PolicyMode,
        tool: Option<&'a str>,
        host_glob: Option<&'a str>,
    ) -> PolicyDomainSel<'a> {
        PolicyDomainSel {
            active,
            stage,
            mode,
            tool,
            host_glob,
        }
    }

    #[test]
    fn enforcing_db_client_block_with_host_glob_compiles_domain() {
        let d = compile_domains_relative(
            [psel(
                true,
                PolicyStage::Enforce,
                PolicyMode::Block,
                Some("db_client"),
                Some("*.prod.internal"),
            )]
            .into_iter(),
        );
        assert!(d.contains("*.prod.internal"));
    }

    #[test]
    fn shadow_steer_wrong_tool_or_missing_glob_compile_nothing() {
        assert!(compile_domains_relative(
            [psel(
                true,
                PolicyStage::Shadow,
                PolicyMode::Block,
                Some("db_client"),
                Some("*.prod")
            )]
            .into_iter()
        )
        .is_empty());
        assert!(compile_domains_relative(
            [psel(
                true,
                PolicyStage::Enforce,
                PolicyMode::Steer,
                Some("db_client"),
                Some("*.prod")
            )]
            .into_iter()
        )
        .is_empty());
        assert!(compile_domains_relative(
            [psel(
                true,
                PolicyStage::Enforce,
                PolicyMode::Block,
                Some("path"),
                Some("*.prod")
            )]
            .into_iter()
        )
        .is_empty());
        assert!(compile_domains_relative(
            [psel(
                true,
                PolicyStage::Enforce,
                PolicyMode::Block,
                Some("db_client"),
                None
            )]
            .into_iter()
        )
        .is_empty());
        assert!(compile_domains_relative(
            [psel(
                false,
                PolicyStage::Enforce,
                PolicyMode::Block,
                Some("db_client"),
                Some("*.prod")
            )]
            .into_iter()
        )
        .is_empty());
    }

    #[test]
    fn domain_universe_includes_non_enforcing_db_client_globs() {
        // The ownership universe is broader than the current compiled set: a
        // shadow-stage policy's glob still belongs to mati for drift purposes.
        let universe = db_client_host_glob_universe(
            [
                (Some("db_client"), Some("*.staging")),
                (Some("path"), Some("ignored")),
            ]
            .into_iter(),
        );
        assert!(universe.contains("*.staging"));
        assert!(!universe.contains("ignored"));
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
        let out = apply_into_settings(existing, repo, &abs, &BTreeSet::new());
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
        let once = apply_into_settings(json!({}), repo, &abs, &BTreeSet::new());
        let twice = apply_into_settings(once.clone(), repo, &abs, &BTreeSet::new());
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
        let out = clear_from_settings(existing, repo, &BTreeSet::new());
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
    fn credential_files_merge_owns_by_path_preserves_foreign_entries() {
        let repo = Path::new("/work/repo");
        let existing = json!({
            "sandbox": { "credentials": { "files": [
                { "mode": "deny", "path": "/work/repo/OLD.pem" },
                { "mode": "mask", "path": "~/.aws/credentials" }
            ] } }
        });
        let mut abs = SandboxRules::default();
        abs.credentials_deny
            .insert("/work/repo/new.pem".to_string());
        let out = apply_into_settings(existing, repo, &abs, &BTreeSet::new());
        let files = out["sandbox"]["credentials"]["files"].as_array().unwrap();
        let paths: BTreeSet<&str> = files.iter().map(|e| e["path"].as_str().unwrap()).collect();
        assert!(
            paths.contains("~/.aws/credentials"),
            "foreign entry preserved"
        );
        assert!(
            paths.contains("/work/repo/new.pem"),
            "new mati entry present"
        );
        assert!(
            !paths.contains("/work/repo/OLD.pem"),
            "stale in-repo entry dropped"
        );
        let new_entry = files
            .iter()
            .find(|e| e["path"] == "/work/repo/new.pem")
            .unwrap();
        assert_eq!(new_entry["mode"], "deny");
    }

    #[test]
    fn denied_domains_merge_owns_by_universe_membership() {
        let repo = Path::new("/work/repo");
        let existing = json!({
            "sandbox": { "network": { "deniedDomains": ["*.old-policy.internal", "user-added.example.com"] } }
        });
        let mut abs = SandboxRules::default();
        abs.denied_domains
            .insert("*.new-policy.internal".to_string());
        let universe: BTreeSet<String> = [
            "*.old-policy.internal".to_string(),
            "*.new-policy.internal".to_string(),
        ]
        .into_iter()
        .collect();
        let out = apply_into_settings(existing, repo, &abs, &universe);
        let domains: BTreeSet<&str> = out["sandbox"]["network"]["deniedDomains"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            domains.contains("user-added.example.com"),
            "non-mati domain preserved"
        );
        assert!(
            domains.contains("*.new-policy.internal"),
            "new mati domain present"
        );
        assert!(
            !domains.contains("*.old-policy.internal"),
            "policy no longer enforcing — dropped"
        );
    }

    #[test]
    fn drifted_removals_covers_credentials_and_domains() {
        let repo = Path::new("/work/repo");
        let existing = json!({ "sandbox": {
            "credentials": { "files": [{ "mode": "deny", "path": "/work/repo/dropped.pem" }] },
            "network": { "deniedDomains": ["*.dropped.internal"] }
        } });
        let abs = SandboxRules::default();
        let universe: BTreeSet<String> = ["*.dropped.internal".to_string()].into_iter().collect();
        let drift = drifted_removals(&existing, repo, &abs, &universe);
        assert!(drift.contains("/work/repo/dropped.pem"));
        assert!(drift.contains("*.dropped.internal"));
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
        let drift = drifted_removals(&existing, repo, &abs, &BTreeSet::new());
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
        assert!(materialize(&path, repo, &empty, &BTreeSet::new(), true, false).is_err());
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("/work/repo/x.rs"));
        // forced → removes the drifted entry
        assert!(materialize(&path, repo, &empty, &BTreeSet::new(), true, true).is_ok());
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
