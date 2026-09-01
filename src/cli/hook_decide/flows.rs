use super::*;

// ── Daemon readiness ────────────────────────────────────────────────────────

/// Ensure the daemon is reachable. Auto-starts if needed.
///
/// Pass-33: this is now a thin delegate to
/// [`mati_core::mcp::daemon_lifecycle::ensure_daemon`]. The library-side
/// implementation is the canonical one — sharing it lets MCP socket-backed
/// callers (`proxy_daemon_result` / `proxy_daemon_v2`) auto-spawn with the
/// exact same recovery semantics as the hook path. See the lib module
/// docs for the full Phase 1–4 strategy.
pub(crate) async fn ensure_daemon(mati_root: &Path) -> bool {
    mati_core::mcp::daemon_lifecycle::ensure_daemon(mati_root).await
}

// ── Tier 1 session lockdown ─────────────────────────────────────────────────

/// Is the Tier 1 session lockdown switched on for this invocation?
///
/// `MATI_LOCKDOWN` decides on its own when set, in either direction — it is
/// the per-process override the lab uses and the way out when the daemon holds
/// a value you cannot reach. Unset, the stored `enforcement.lockdown` key
/// decides, read per hook process so flipping it needs no restart. Default off
/// on every fault path: the lockdown denies unrelated reads and commands by
/// design, so it is the operator's call, not mati's.
///
/// Callers must have ensured the daemon first; the config read is a plain
/// daemon round trip.
async fn lockdown_enabled(mati_root: &Path) -> bool {
    match std::env::var("MATI_LOCKDOWN").as_deref() {
        Ok("1" | "on" | "true") => return true,
        Ok("0" | "off" | "false") => return false,
        _ => {}
    }
    let response = match super::daemon::daemon_v2(
        mati_root,
        mati_core::mcp::protocol::Command::ConfigGet(mati_core::mcp::protocol::ConfigGetInput {
            key: "enforcement.lockdown".to_string(),
        }),
    )
    .await
    {
        DaemonResult::Ok(response) => response,
        _ => return false,
    };
    daemon_data(&response).is_some_and(|value| value.as_str() == Some("on"))
}

/// The file this worktree was denied that `actor` still owes a receipt for.
///
/// `worktree` scopes the debt and `actor` settles it, so a subagent inherits
/// its parent's lockdown and lifts it only with its own `mem_get`.
///
/// `None` when the lockdown is off or the daemon says nothing is owed, and on
/// every daemon fault — an unreachable daemon must not deny (P9). No command or
/// read is exempt, `mati` included: the receipt that lifts the lockdown is
/// minted by `mem_get`, which is neither a shell command nor a read tool, so
/// exempting one would only open a route without opening the exit.
pub(crate) async fn lockdown_owed_key(
    mati_root: &Path,
    worktree: Option<&str>,
    actor: Option<&str>,
) -> Option<String> {
    if !lockdown_enabled(mati_root).await {
        return None;
    }
    let response = match super::daemon::daemon_v2(
        mati_root,
        mati_core::mcp::protocol::Command::SessionOwedReceipt(
            mati_core::mcp::protocol::SessionOwedReceiptInput {
                actor: actor.map(str::to_string),
                worktree: worktree.map(str::to_string),
            },
        ),
    )
    .await
    {
        DaemonResult::Ok(response) => response,
        _ => return None,
    };
    daemon_data(&response)?
        .get("owed")?
        .as_str()
        .map(str::to_string)
}

/// Emit the lockdown deny for an access that reached no file gate — a Bash
/// command naming no path, or a `Grep`/`Glob` with no `path`.
///
/// Self-contained like [`run_fileless_policy`]: it resolves its own repo
/// identity because the path-less branch returns before `run_inner` has done
/// so. Returns whether it denied.
pub(crate) async fn run_pathless_lockdown(
    input: &serde_json::Value,
    variant: HookVariant,
    agent_id: Option<&str>,
) -> bool {
    let Ok(cwd) = std::env::current_dir() else {
        return false;
    };
    let repo_ident = mati_core::store::RepoIdent::discover(&cwd);
    let Ok(mati_root) = mati_root_for_ident(&repo_ident, &cwd) else {
        return false;
    };
    if !ensure_daemon(&mati_root).await {
        return false;
    }
    let worktree = mati_core::store::session::worktree_scope_tag_for(&repo_ident);
    let actor_scope =
        mati_core::store::session::combined_actor_scope(worktree.as_deref(), agent_id);
    let Some(owed) =
        lockdown_owed_key(&mati_root, worktree.as_deref(), actor_scope.as_deref()).await
    else {
        // Nothing owed, so the access proceeds and no file gate ever saw it.
        // Record that. It is the one quantity a coverage claim cannot take
        // from the enforcement log, because by definition nothing was
        // enforced, and without it the unobserved rate stays a constant
        // quoted from ARCHITECTURE section 24 rather than a per-repo measurement.
        record_pathless_allow(&mati_root, input, variant, agent_id, actor_scope.as_deref()).await;
        return false;
    };

    let result = decide::lockdown_result(&owed);
    let events = platform_events(variant, &result.decision, result.events);
    let (stdout, stderr, exit_code) = format_decision(variant, &result.decision, &owed);
    if !stdout.is_empty() {
        println!("{stdout}");
    }
    if !stderr.is_empty() {
        eprintln!("{stderr}");
    }
    let session_id = input.get("session_id").and_then(|value| value.as_str());
    fire_events(
        &mati_root,
        &events,
        session_id,
        agent_id,
        actor_scope.as_deref(),
        None,
    )
    .await;
    if exit_code != 0 {
        let _ = std::io::Write::flush(&mut std::io::stderr());
        std::process::exit(exit_code);
    }
    true
}

/// Record that a path-less access was allowed without any file gate seeing it.
///
/// Reachable only with the daemon up — [`run_pathless_lockdown`] returns before
/// this when `ensure_daemon` fails — so the count is a lower bound on the
/// unobserved surface, never an upper one.
///
/// A command gate may still have run after this: `run_fileless_policy` handles
/// `db_client` and `unknown` tools further down. That does not double-count.
/// The claim is that no FILE gate saw the access, which stays true either way.
async fn record_pathless_allow(
    mati_root: &Path,
    input: &serde_json::Value,
    variant: HookVariant,
    agent_id: Option<&str>,
    actor_scope: Option<&str>,
) {
    let session_id = input.get("session_id").and_then(|value| value.as_str());
    fire_events(
        mati_root,
        &[decide::HookEvent::PathlessAllow {
            key: pathless_surface_key(variant),
        }],
        session_id,
        agent_id,
        actor_scope,
        None,
    )
    .await;
}

/// Which surface a path-less access arrived on.
///
/// Deliberately low-cardinality, and deliberately not a file key — there is no
/// path, which is the whole point. The daily aggregate caps its key list at
/// 100, and the useful question is which tool escapes the file gate, not which
/// command did it once.
pub(crate) fn pathless_surface_key(variant: HookVariant) -> String {
    let surface = match variant {
        HookVariant::ClaudePreBash => "claude-bash",
        HookVariant::CodexPreBash => "codex-bash",
        HookVariant::ClaudePreRead => "claude-read",
        // Unreachable: `entry.rs` calls the path-less gate for the three above
        // only. Named rather than panicking, so widening that list degrades to
        // a coarse count instead of killing the hook.
        _ => "other",
    };
    format!("pathless:{surface}")
}

// ── Tier 2 read floor ───────────────────────────────────────────────────────

/// Does `actor` hold a live consultation receipt for `key`?
///
/// `false` — deny — on a command fault, which inverts the usual fail-open on
/// purpose. The split is the one `FAILURE_MODES.md` section 1 draws: an
/// unreachable daemon fails open one level up, at `ensure_daemon`, because
/// mati being down must not block the agent (P9); a fault on a daemon that IS
/// up fails closed, because the file is standing at mode `000` either way and
/// treating the fault as consent would publish a one-line bypass. The exit
/// stays reachable without the daemon: `mati seal clear` never opens the
/// store.
async fn receipt_newer_than(
    mati_root: &Path,
    key: &str,
    actor: Option<&str>,
    ttl_secs: u64,
) -> Option<bool> {
    let response = match super::daemon::daemon_v2(
        mati_root,
        mati_core::mcp::protocol::Command::SessionCheckConsultedRecent(
            mati_core::mcp::protocol::SessionCheckConsultedRecentInput {
                key: key.to_string(),
                ttl_secs,
                actor: actor.map(str::to_string),
            },
        ),
    )
    .await
    {
        DaemonResult::Ok(response) => response,
        _ => return None,
    };
    daemon_data(&response).and_then(|v| v.as_bool())
}

/// Deny a command that would return a sealed file to a readable state while
/// its consultation receipt is outstanding. Returns whether it denied.
///
/// Self-contained like [`run_pathless_lockdown`], and for the same reason: a
/// floor-restoring command names no governed path, so it is decided before
/// `run_inner` has resolved repo identity.
///
/// Ordered cheapest first. The verb test is pure, so a command that could not
/// restore anything costs no I/O at all; the manifest is two syscalls and is
/// read only for a verb that could; the daemon is asked only in a repo that
/// has actually sealed something.
pub(crate) async fn run_seal_guard(
    input: &serde_json::Value,
    variant: HookVariant,
    agent_id: Option<&str>,
) -> bool {
    let Some(command) = input
        .pointer("/tool_input/command")
        .and_then(|value| value.as_str())
    else {
        return false;
    };
    if !decide::restores_read_floor(command) {
        return false;
    }

    let Ok(cwd) = std::env::current_dir() else {
        return false;
    };
    let repo_ident = mati_core::store::RepoIdent::discover(&cwd);
    let Some(repo_root) = discover_repo_root_for(&repo_ident) else {
        return false;
    };
    let Ok(manifest_path) = mati_core::seal::manifest_path(&repo_root) else {
        return false;
    };
    let manifest = mati_core::seal::read_manifest(&manifest_path);
    if manifest.files.is_empty() {
        return false;
    }
    let Ok(mati_root) = mati_root_for_ident(&repo_ident, &cwd) else {
        return false;
    };
    if !ensure_daemon(&mati_root).await {
        return false;
    }

    let worktree = mati_core::store::session::worktree_scope_tag_for(&repo_ident);
    let actor_scope =
        mati_core::store::session::combined_actor_scope(worktree.as_deref(), agent_id);
    let canonical_root = super::sandbox::canonicalize_lenient(&repo_root).unwrap_or(repo_root);

    // The first sealed file with no receipt decides. Every row has to be
    // checked because the verbs reach files they never name — `chmod -R` and
    // `git clone` restore the whole tree — so one unsettled row is enough.
    let mut owed = None;
    for file in &manifest.files {
        let Ok(rel) = Path::new(&file.path).strip_prefix(&canonical_root) else {
            continue;
        };
        let key = format!("file:{}", rel.display());
        if receipt_newer_than(
            &mati_root,
            &key,
            actor_scope.as_deref(),
            mati_core::store::session::CONSULTED_RECENT_TTL_SECS,
        )
        .await
            != Some(true)
        {
            owed = Some(key);
            break;
        }
    }
    let Some(owed) = owed else {
        return false;
    };

    let result = decide::seal_floor_result(&owed);
    let events = platform_events(variant, &result.decision, result.events);
    let (stdout, stderr, exit_code) = format_decision(variant, &result.decision, &owed);
    if !stdout.is_empty() {
        println!("{stdout}");
    }
    if !stderr.is_empty() {
        eprintln!("{stderr}");
    }
    let session_id = input.get("session_id").and_then(|value| value.as_str());
    fire_events(
        &mati_root,
        &events,
        session_id,
        agent_id,
        actor_scope.as_deref(),
        None,
    )
    .await;
    if exit_code != 0 {
        let _ = std::io::Write::flush(&mut std::io::stderr());
        std::process::exit(exit_code);
    }
    true
}

// ── Tier 2 post-Bash sweep ──────────────────────────────────────────────────

/// Stat every sealed file after a Bash command, restore any floor that came
/// down, and record the ones no receipt explains.
///
/// This is the layer that catches what the pre-Bash gate cannot classify: a
/// mode changed from inside `python3`, a rename over the file, a
/// chmod-write-chmod sequence in one command. The gate asks about a string;
/// this asks the filesystem, so a computed path has nothing to defeat.
///
/// It also owns the within-session re-arm. A receipt that lapses on its own
/// TTL leaves the file open until something puts it back, and until this ran,
/// nothing did before the next session boundary.
///
/// Fires on the async PostToolUse path, so it waits on nothing the agent is
/// waiting for. Fail-open at every step: a repo with an empty manifest costs
/// one `stat` of a file that is usually absent.
pub(crate) async fn run_seal_sweep(input: &serde_json::Value, agent_id: Option<&str>) {
    let Ok(cwd) = std::env::current_dir() else {
        return;
    };
    let repo_ident = mati_core::store::RepoIdent::discover(&cwd);
    let Some(repo_root) = discover_repo_root_for(&repo_ident) else {
        return;
    };
    let repo_root = super::sandbox::canonicalize_lenient(&repo_root).unwrap_or(repo_root);
    let Ok(store_root) = mati_root_for_ident(&repo_ident, &cwd) else {
        return;
    };

    let findings = mati_core::seal::scan(&store_root, &repo_root);
    if findings.is_empty() {
        return;
    }
    if !ensure_daemon(&store_root).await {
        return;
    }

    let worktree = mati_core::store::session::worktree_scope_tag_for(&repo_ident);
    let actor_scope =
        mati_core::store::session::combined_actor_scope(worktree.as_deref(), agent_id);
    let session_id = input.get("session_id").and_then(|value| value.as_str());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for finding in findings {
        let key = finding.key();
        // A live receipt means the agent consulted and `mem_get` lifted the
        // floor on purpose. Leave it open; the file is legitimately in hand.
        if let mati_core::seal::Finding::FloorDown { .. } = finding {
            if receipt_newer_than(
                &store_root,
                &key,
                actor_scope.as_deref(),
                mati_core::store::session::CONSULTED_RECENT_TTL_SECS,
            )
            .await
                == Some(true)
            {
                continue;
            }
        }

        // Nothing explains a lowered floor except a receipt minted after the
        // last re-arm, because `lift_on_receipt` runs only at mint time. A
        // receipt older than that is a lapsed lift; no receipt at all, or one
        // predating the re-arm, is a bypass. `ContentMoved` needs no dating —
        // the bytes moved under a mode the kernel was enforcing.
        let bypassed = match &finding {
            mati_core::seal::Finding::ContentMoved { .. } => true,
            mati_core::seal::Finding::FloorDown { rearmed_at, .. } => {
                receipt_newer_than(
                    &store_root,
                    &key,
                    actor_scope.as_deref(),
                    now.saturating_sub(*rearmed_at),
                )
                .await
                    == Some(false)
            }
        };

        mati_core::seal::reseal(&store_root, &repo_root, finding.rel());
        if bypassed {
            eprintln!("[mati] Tier 2 bypass: {} was opened without a receipt — the floor has been restored.", finding.rel());
            let _ = crate::cli::hooks::hook_fire_v2_at(
                &store_root,
                mati_core::mcp::protocol::Command::SessionLog(
                    mati_core::mcp::protocol::SessionLogInput {
                        event: mati_core::mcp::protocol::SessionEvent::SealBypassDetected,
                        key,
                        session_id: session_id.map(str::to_string),
                        actor: actor_scope.clone(),
                        decision_basis_hash: None,
                    },
                ),
            )
            .await;
        }
    }
}

// ── codex-post-bash flow ────────────────────────────────────────────────────

/// Compliance logging only — no `evaluate()`, no gotcha fetching.
pub(crate) async fn run_post_bash(
    mati_root: &Path,
    rel_path: &str,
    actor: Option<&str>,
) -> Result<()> {
    let file_key = format!("file:{rel_path}");

    // Reuse existing session_check_consulted_recent command. `actor` is the
    // same scope the gate evaluated at: querying without it asks about a
    // global receipt the gate never mints, and every consulted read then
    // records CodexShellMiss — a `bypass` event claiming the agent reached the
    // file off-gate when it had consulted first (measured 2026-08-29).
    let consulted = match daemon_result(
        mati_root,
        "session_check_consulted_recent",
        serde_json::json!({
            "key": &file_key,
            "ttl_secs": mati_core::store::session::CONSULTED_RECENT_TTL_SECS,
            "actor": actor,
        }),
    )
    .await
    {
        DaemonResult::Ok(resp) => match daemon_data(&resp) {
            Some(d) => d.as_bool().unwrap_or(false),
            // Daemon-side error: the consultation state is UNKNOWN. Recording
            // a CodexShellMiss here would be a false "bypass detected" audit
            // event (the daemon is reachable, so it WOULD be recorded).
            None => return Ok(()),
        },
        _ => false,
    };

    // Fire the appropriate compliance event via typed v2 command.
    let event = if consulted {
        mati_core::mcp::protocol::SessionEvent::ComplianceHit
    } else {
        mati_core::mcp::protocol::SessionEvent::CodexShellMiss
    };
    let cmd =
        mati_core::mcp::protocol::Command::SessionLog(mati_core::mcp::protocol::SessionLogInput {
            event,
            key: file_key.clone(),
            session_id: None,
            // Same scope the check ran at, so the daemon can find the receipt
            // that authorized the allow it is recording.
            actor: actor.map(str::to_string),
            decision_basis_hash: None,
        });
    let _ = super::daemon::daemon_v2(mati_root, cmd).await;

    // Post-hook: no output, always exit 0.
    Ok(())
}

// ── claude-post-memget flow ─────────────────────────────────────────────────

/// Record an actor-scoped consult receipt after a successful mem_get.
///
/// Fail-open at every step: if the key, session_id, or daemon is missing, exit 0.
/// No stdout output (PostToolUse hooks are fire-and-forget).
pub(crate) async fn run_post_memget(input: &serde_json::Value) -> Result<()> {
    // A failed mem_get delivered no context — minting a receipt for it would
    // wrongly downgrade a future deny (a receipt is proof the record was
    // READ). MCP tool errors surface as `tool_response.isError: true`; an
    // absent field means success, so this guard is a no-op on the happy path.
    if input
        .pointer("/tool_response/isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Ok(());
    }

    let key = match input
        .pointer("/tool_input/key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(k) => k,
        None => return Ok(()),
    };

    let agent_id = input
        .get("agent_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let session_id = input
        .get("session_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    let cwd = std::env::current_dir()?;
    // Resolve the daemon slug the way the gate does (repo root, not cwd) so the
    // receipt lands in the store the gate will read. The actor scope matches the
    // gate too: agent receipts are scoped, while the main thread (no agent_id)
    // uses the global receipt — both combined with the worktree scope so a
    // receipt minted here cannot satisfy a gate in a different worktree.
    let repo_root = discover_repo_root(&cwd);
    let root_for_slug = repo_root.as_deref().unwrap_or(&cwd);
    let mati_root = match mati_root_for(root_for_slug) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    if !ensure_daemon(&mati_root).await {
        return Ok(());
    }

    let worktree = mati_core::store::session::worktree_scope_tag(&cwd);
    let actor = receipt_actor(worktree.as_deref(), agent_id);

    let cmd = mati_core::mcp::protocol::Command::ConsultationHit(
        mati_core::mcp::protocol::ConsultationHitInput {
            key: key.to_string(),
            capture_fingerprint: true,
            actor,
            session_id: session_id.map(str::to_string),
            agent_id: agent_id.map(str::to_string),
            decision_basis_hash: None,
            source: Some(mati_core::store::ReceiptSource::MemGet),
        },
    );
    let _ = super::daemon::daemon_v2(&mati_root, cmd).await;
    Ok(())
}

// ── claude-post-task flow ───────────────────────────────────────────────────

/// A nested subagent spawn parsed from an `Agent`-tool PostToolUse payload:
/// (child_agent_id, parent_agent_id, session_id, agent_type).
type NestedSpawn = (String, String, Option<String>, Option<String>);

/// Extract a NESTED spawn edge from an `Agent`/`Task` PostToolUse payload.
///
/// Returns `None` for anything that is not a completed nested spawn: a failed or
/// in-progress tool call, a missing child id, or a root-session spawn (top-level
/// `agent_id` absent). A root spawn is already recorded by the SubagentStart
/// hook's `SubagentSpawned`, so recording it here too would double-count — hence
/// the parent (spawner) is required.
fn parse_nested_spawn(input: &serde_json::Value) -> Option<NestedSpawn> {
    // Only record a spawn that actually returned a subagent. A failed Task call
    // surfaces `tool_response.isError` or a non-"completed" status.
    if input
        .pointer("/tool_response/isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return None;
    }
    if input
        .pointer("/tool_response/status")
        .and_then(|v| v.as_str())
        != Some("completed")
    {
        return None;
    }

    let child = input
        .pointer("/tool_response/agentId")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())?
        .to_string();
    // The spawner. Absent ⇒ the root session spawned this child ⇒ not a nested
    // edge; SubagentSpawned already covers it.
    let parent = input
        .get("agent_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())?
        .to_string();

    let session_id = input
        .get("session_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let agent_type = input
        .pointer("/tool_response/agentType")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    Some((child, parent, session_id, agent_type))
}

/// Record a nested subagent→subagent spawn edge after an `Agent` tool call.
///
/// Fail-open at every step: a non-nested spawn, a missing daemon, or a bad
/// payload all exit 0 with no output (PostToolUse hooks are fire-and-forget).
pub(crate) async fn run_post_task(input: &serde_json::Value) -> Result<()> {
    let Some((child, parent, session_id, agent_type)) = parse_nested_spawn(input) else {
        return Ok(());
    };

    let cwd = std::env::current_dir()?;
    let repo_root = discover_repo_root(&cwd);
    let root_for_slug = repo_root.as_deref().unwrap_or(&cwd);
    let mati_root = match mati_root_for(root_for_slug) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    if !ensure_daemon(&mati_root).await {
        return Ok(());
    }

    let cmd = mati_core::mcp::protocol::Command::SubagentEdge(
        mati_core::mcp::protocol::SubagentEdgeInput {
            child_agent_id: Some(child),
            parent_agent_id: Some(parent),
            session_id,
            agent_type,
        },
    );
    let _ = super::daemon::daemon_v2(&mati_root, cmd).await;
    Ok(())
}

// ── claude-post-read-compliance flow ────────────────────────────────────────

/// Bash's `case "$REL_PATH" in *.*|*/*` guard: a name with a dot or a
/// separator is taken as a path, anything else only if it is really on disk.
/// Keeps `Dockerfile`, drops the tool-input junk that never named a file.
pub(super) fn names_a_file(path: &str, cwd: &Path, repo_root: Option<&Path>) -> bool {
    if path.contains('.') || path.contains('/') {
        return true;
    }
    resolve_access_path(path, cwd).exists()
        || repo_root.is_some_and(|root| root.join(path).exists())
}

/// Record a read that went unconsulted, exactly once.
///
/// PostToolUse: no stdout, always exit 0. The decision itself lives in
/// [`crate::cli::hooks::run_post_read_compliance`], which also canonicalizes
/// the key; this flow only extracts the path and guards the daemon.
pub(crate) async fn run_post_read_compliance(input: &serde_json::Value) -> Result<()> {
    let Some(path) = input
        .pointer("/tool_input/file_path")
        .or_else(|| input.pointer("/tool_input/path"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    else {
        return Ok(());
    };
    let Ok(cwd) = std::env::current_dir() else {
        return Ok(());
    };
    let repo_ident = mati_core::store::RepoIdent::discover(&cwd);
    let repo_root = discover_repo_root_for(&repo_ident);
    if !names_a_file(path, &cwd, repo_root.as_deref()) {
        return Ok(());
    }
    let mati_root = match mati_root_for_ident(&repo_ident, &cwd) {
        Ok(root) => root,
        Err(_) => {
            log_fail_open_named("post-read-compliance", path, "cannot determine mati root");
            return Ok(());
        }
    };
    if !ensure_daemon(&mati_root).await {
        log_fail_open_named("post-read-compliance", path, "daemon not running");
        return Ok(());
    }

    let agent_id = input
        .get("agent_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    crate::cli::hooks::run_post_read_compliance(&format!("file:{path}"), agent_id).await
}

/// Best-effort PostToolUse adapter for schema introspection. The policy
/// evaluation and receipt minting are deliberately fire-and-forget: a
/// PostToolUse hook must never disrupt the agent session.
pub(crate) async fn run_post_bash_introspection(input: &serde_json::Value) -> Result<()> {
    // Tier 2 first, and unconditional on what the command was: a bypass can
    // come from any of them, and the introspection path below returns early
    // for all but a database schema call.
    let agent_id = input
        .get("agent_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty());
    run_seal_sweep(input, agent_id).await;

    if !post_bash_succeeded(input) {
        return Ok(());
    }
    let Some(command) = input
        .pointer("/tool_input/command")
        .and_then(|value| value.as_str())
        .filter(|command| decide::is_schema_introspection(command))
    else {
        return Ok(());
    };
    let action = decide::normalize_action(Some(command), None);
    if action.tool != "db_client" {
        // `command` passed `is_schema_introspection` above but its leading
        // word didn't classify — an upstream PreToolUse hook rewrote it
        // (observed live: `rtk psql …`). The receipt this command should
        // mint never mints, so a `db_client` policy stays permanently
        // denied. Record the signature; do not attempt to mint or recover.
        record_wrapped_client_miss(input, &action).await;
        return Ok(());
    }

    let Ok(cwd) = std::env::current_dir() else {
        return Ok(());
    };
    let repo_root = discover_repo_root(&cwd);
    let root_for_slug = repo_root.as_deref().unwrap_or(&cwd);
    let mati_root = match mati_root_for(root_for_slug) {
        Ok(root) => root,
        Err(_) => return Ok(()),
    };
    if !ensure_daemon(&mati_root).await {
        return Ok(());
    }

    let agent_id = input
        .get("agent_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty());
    let session_id = input
        .get("session_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty());
    let worktree = mati_core::store::session::worktree_scope_tag(&cwd);
    let actor_scope = receipt_actor(worktree.as_deref(), agent_id);

    let Some(evaluation) = policy_verdicts_for_action(
        &mati_root,
        &action,
        actor_scope.as_deref(),
        "<post-bash>",
        Some(command),
    )
    .await
    else {
        return Ok(());
    };
    for verdict in evaluation.verdicts {
        if !accepts_db_introspection(&verdict.via) {
            continue;
        }
        let _ = daemon_v2(
            &mati_root,
            mati_core::mcp::protocol::Command::ConsultationHit(
                mati_core::mcp::protocol::ConsultationHitInput {
                    key: verdict.requires_key,
                    capture_fingerprint: false,
                    actor: actor_scope.clone(),
                    session_id: session_id.map(str::to_string),
                    agent_id: agent_id.map(str::to_string),
                    decision_basis_hash: None,
                    source: Some(mati_core::store::ReceiptSource::DbIntrospection),
                },
            ),
        )
        .await;
    }
    Ok(())
}

/// Record the wrapped-db-client deadlock signature: `is_schema_introspection`
/// was true but `normalize_action` did not classify the same command as
/// `db_client`. Diagnostic only — best-effort and fail-open like the rest of
/// this module, and never touches any allow/deny decision (this hook variant
/// emits no `permissionDecision` at all; see `allow_output`).
async fn record_wrapped_client_miss(input: &serde_json::Value, action: &decide::Action) {
    let Ok(cwd) = std::env::current_dir() else {
        return;
    };
    let repo_root = discover_repo_root(&cwd);
    let root_for_slug = repo_root.as_deref().unwrap_or(&cwd);
    let Ok(mati_root) = mati_root_for(root_for_slug) else {
        return;
    };
    if !ensure_daemon(&mati_root).await {
        return;
    }

    let session_id = input
        .get("session_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty());
    // The leading token survives env-assignment and PREFIX_WORDS stripping in
    // `normalize_action`, so it names the wrapper (e.g. "rtk") without ever
    // carrying the full command text (which may embed a DSN password).
    let wrapper = action.argv.first().map(String::as_str).unwrap_or("unknown");
    tracing::warn!(
        "post-bash: schema-introspection command led by '{wrapper}' did not \
         classify as db_client — likely rewritten by another PreToolUse hook; \
         its consultation receipt cannot mint (deadlock signature)"
    );

    let cmd =
        mati_core::mcp::protocol::Command::SessionLog(mati_core::mcp::protocol::SessionLogInput {
            event: mati_core::mcp::protocol::SessionEvent::WrappedDbClientMiss,
            key: format!("enforcement:wrapped_client:{wrapper}"),
            session_id: session_id.map(str::to_string),
            actor: None,
            decision_basis_hash: None,
        });
    let _ = daemon_v2(&mati_root, cmd).await;
}

/// Select the receipt scope shared by the gate and both post-tool mint paths:
/// the worktree tag combined with the subagent id, if any. Session IDs remain
/// consultation metadata, not receipt scope.
pub(crate) fn receipt_actor(worktree: Option<&str>, agent_id: Option<&str>) -> Option<String> {
    mati_core::store::session::combined_actor_scope(worktree, agent_id)
}

/// Claude's PostToolUse payloads have used both camelCase and snake_case
/// spellings. An unrecognized payload shape is not success: minting must stop
/// until the hook understands the new shape.
pub(crate) fn post_bash_succeeded(input: &serde_json::Value) -> bool {
    let Some(response) = input.pointer("/tool_response") else {
        tracing::warn!("Claude PostToolUse Bash payload is missing tool_response");
        return false;
    };
    // Claude Code omits `isError` entirely on a successful Bash command. A
    // captured payload carries exactly `{stdout, stderr, interrupted, isImage,
    // noOutputExpected}` and no exit status at all, so requiring the field made
    // every introspection look like a failure and `DbIntrospection` could never
    // mint. Absent means success, matching `run_post_memget`; only an explicit
    // `true` is a failure.
    //
    // Observed alongside that: a Bash call that exits non-zero fires no
    // PostToolUse event at all, so this function never runs for a failed
    // command and cannot mint for one. That is what makes the absent-means-
    // success default safe rather than merely convenient. Confirmed in both
    // `default` and `acceptEdits` permission modes; `bypassPermissions` is
    // untested. The checks below stay as defense in depth, because the absence
    // of an event is Claude Code's behavior to change, not a contract mati
    // controls: if a failing command ever did reach this function it would
    // carry no `isError` either, and the shape alone could not distinguish it
    // from a success.
    if response
        .get("isError")
        .or_else(|| response.get("is_error"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        return false;
    }
    // A cancelled command taught the agent nothing, so it must not mint.
    if response
        .get("interrupted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        return false;
    }
    for key in ["exit_code", "exitCode"] {
        let Some(value) = response.get(key) else {
            continue;
        };
        let Some(code) = value.as_i64() else {
            tracing::warn!("Claude PostToolUse Bash payload has non-numeric {key}");
            return false;
        };
        if code != 0 {
            return false;
        }
    }
    true
}

pub(crate) fn accepts_db_introspection(via: &[mati_core::store::ReceiptSource]) -> bool {
    via.contains(&mati_core::store::ReceiptSource::DbIntrospection)
}

// ── codex-pre-apply-patch flow ──────────────────────────────────────────────

/// Multi-file edit enforcement for Codex `apply_patch`.
///
/// Parses the patch envelope into target paths, evaluates each against the
/// gotcha store, and denies (exit 2 + stderr) if ANY touched file has a
/// confirmed gotcha the agent has not consulted. Fails OPEN at every step
/// (no command, no paths, unreachable daemon, per-file eval error, file count
/// over the cap) — wrongly blocking all edits is worse than missing a gotcha.
pub(crate) async fn run_apply_patch(input: &serde_json::Value) -> Result<()> {
    let variant = HookVariant::CodexPreApplyPatch;

    // 1. Patch text from tool_input.command.
    let Some(cmd) = input
        .pointer("/tool_input/command")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    else {
        emit_allow(variant);
        return Ok(());
    };

    // 2. Parse target paths from the envelope.
    let mut raw_paths = decide::extract_apply_patch_files(cmd);
    if raw_paths.is_empty() {
        emit_allow(variant);
        return Ok(());
    }
    if raw_paths.len() > decide::MAX_APPLY_PATCH_FILES {
        log_fail_open(
            "<apply_patch>",
            &format!(
                "patch touches {} files; gating only the first {}",
                raw_paths.len(),
                decide::MAX_APPLY_PATCH_FILES
            ),
        );
        raw_paths.truncate(decide::MAX_APPLY_PATCH_FILES);
    }

    // 3. Repo root + mati root + daemon (shared shape with the single-path flow).
    let cwd = std::env::current_dir()?;
    let repo_root = discover_repo_root(&cwd);
    let repo_root_str = repo_root.as_ref().and_then(|p| p.to_str());
    let root_for_slug = repo_root.as_deref().unwrap_or(&cwd);
    let mati_root = match mati_root_for(root_for_slug) {
        Ok(r) => r,
        Err(_) => {
            log_fail_open("<apply_patch>", "cannot determine mati root");
            emit_allow(variant);
            return Ok(());
        }
    };
    if !ensure_daemon(&mati_root).await {
        log_fail_open("<apply_patch>", "daemon not running after auto-start");
        emit_allow(variant);
        return Ok(());
    }

    // 4. Evaluate each touched path; collect the ones that must be consulted.
    // agent_id is present in subagent hook payloads; None on the Codex path.
    let agent_id = input
        .get("agent_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let worktree = mati_core::store::session::worktree_scope_tag(&cwd);
    let actor_scope =
        mati_core::store::session::combined_actor_scope(worktree.as_deref(), agent_id);
    // Enterprise consult-mandate globs — parity with the single-path flow.
    let consult_globs = consult_globset();
    // (deny key, deny reason, origin). The origin selects the message shape: a
    // policy deny's key is the policy, not something the agent can consult.
    let mut denied: Vec<(String, String, decide::DenyOrigin)> = Vec::new();
    let mut events: Vec<HookEvent> = Vec::new();
    for raw in &raw_paths {
        let rel_path = decide::normalize_path(raw, repo_root_str);
        let file_key = format!("file:{rel_path}");
        let eval_data = match daemon_result(
            &mati_root,
            "hook_evaluate",
            serde_json::json!({ "file_key": &file_key, "include_recent": true, "actor": actor_scope.clone() }),
        )
        .await
        {
            DaemonResult::Ok(resp) => match daemon_data(&resp) {
                Some(d) => d,
                None => {
                    // Per-file fail-open on a daemon-side error — recorded,
                    // not evaluated as a false "no record".
                    log_fail_open(&rel_path, "hook_evaluate returned error");
                    continue;
                }
            },
            _ => {
                // Per-file fail-open: don't block the whole edit on one bad lookup.
                log_fail_open(&rel_path, "hook_evaluate failed");
                continue;
            }
        };

        let file_exists = file_exists_for_deleted_signal(&eval_data, raw, &cwd);
        let mut adapter = process_eval_response(variant, &rel_path, &eval_data, file_exists);
        // Consult mandate on the patch target — parity with the read/edit
        // gates (this path uses include_recent semantics, hence `true`).
        apply_consult_mandate(
            &mut adapter,
            variant,
            &rel_path,
            consulted_flag(&eval_data, true),
            consult_globs.as_ref(),
        );
        // Resolve the symlink target ONCE, before any gate runs. Both the
        // gotcha gate and the policy gate need it: one gate knowing about
        // symlinks while its sibling does not was the actual defect, and a
        // path policy that misses a symlinked target is only the symptom.
        // `canonical_rel_path` returns None for a non-symlink, so the common
        // case costs nothing.
        let canon_rel = canonical_rel_path(raw, &cwd, repo_root.as_deref(), &rel_path);

        // Codex apply_patch has the exact target path, so apply the same
        // target_path_glob policy gate used by Claude edits, over the lexical
        // key and the canonical one. Escalate-only: the loop stops at the first
        // deny and a non-deny outcome never lowers an existing decision.
        for policy_path in std::iter::once(rel_path.as_str()).chain(canon_rel.as_deref()) {
            if matches!(adapter.decision, Decision::Deny { .. }) {
                break;
            }
            let action = decide::normalize_action(None, Some(policy_path));
            if let Some((policy_decision, policy_events)) = evaluate_governed_policy(
                Some(&mati_root),
                &action,
                "path",
                actor_scope.as_deref(),
                "<apply-patch-policy>",
                None,
                PolicyEvaluationOptions {
                    introspection_exemption: policy_block_exempt(variant, input),
                    codex_agent: true,
                },
            )
            .await
            {
                merge_policy_result(&mut adapter, variant, policy_decision, policy_events);
            }
        }
        // WI-20 parity: a patch targeting an in-repo symlink would otherwise
        // evaluate only the lexical key and write through to the real target
        // ungated. Escalate-only, like the read/edit path: a non-deny
        // canonical result never downgrades the lexical decision, and
        // `canonical_rel_path` returns None (zero cost) for non-symlinks.
        if !matches!(adapter.decision, Decision::Deny { .. }) {
            if let Some(canon_rel) = canon_rel.as_deref() {
                let canon_key = format!("file:{canon_rel}");
                if let Some(canon_eval) = match daemon_result(
                    &mati_root,
                    "hook_evaluate",
                    serde_json::json!({ "file_key": &canon_key, "include_recent": true, "actor": actor_scope.clone() }),
                )
                .await
                {
                    DaemonResult::Ok(resp) => {
                        let d = daemon_data(&resp);
                        if d.is_none() {
                            log_fail_open(
                                canon_rel,
                                "hook_evaluate returned error (canonical)",
                            );
                        }
                        d
                    }
                    _ => None,
                } {
                    let canon_file_exists =
                        file_exists_for_deleted_signal(&canon_eval, canon_rel, &cwd);
                    let mut canon_adapter =
                        process_eval_response(variant, canon_rel, &canon_eval, canon_file_exists);
                    apply_consult_mandate(
                        &mut canon_adapter,
                        variant,
                        canon_rel,
                        consulted_flag(&canon_eval, true),
                        consult_globs.as_ref(),
                    );
                    if matches!(canon_adapter.decision, Decision::Deny { .. }) {
                        adapter = canon_adapter;
                    }
                }
            }
        }
        // The Deny carries its own file_key — the lexical key, the canonical
        // (real-target) key, or the mandate key, whichever actually denied.
        if let Decision::Deny {
            file_key: denied_key,
            reason,
            origin,
        } = &adapter.decision
        {
            denied.push((denied_key.clone(), reason.clone(), *origin));
        }
        // Unconditionally: a non-denying policy still produces events. A shadow
        // observation and a satisfied block's receipt must both be recorded, or
        // `mati policy observations` reports zero matches for a policy that
        // matched every time, and this adapter's audit trail diverges from the
        // Claude edit gate's for the same action.
        events.extend(adapter.events);
    }

    // 5. Deny if any file needs consultation; otherwise allow. Output FIRST,
    // audit events second (missing beats false — see run_inner).
    if denied.is_empty() {
        // Output first, events second, matching the deny path below: a decision
        // delivered but unrecorded is an honest gap, the reverse is a lie.
        emit_allow(variant);
        // Firing here is what makes a non-denying policy observable at all. A
        // shadow-stage match and a satisfied block both land on this path, and
        // returning early dropped every one of them.
        fire_events(
            &mati_root,
            &events,
            None,
            agent_id,
            actor_scope.as_deref(),
            None,
        )
        .await;
        return Ok(());
    }
    // Policy denies carry their own actionable instruction; file denies keep the
    // established consult-the-file shape. A patch can trip both at once, so both
    // are reported rather than one shadowing the other.
    let (policy_denies, file_denies): (Vec<_>, Vec<_>) = denied
        .iter()
        .partition(|(_, _, origin)| matches!(origin, decide::DenyOrigin::Policy));
    let mut lines: Vec<String> = policy_denies
        .iter()
        .map(|(_, reason, _)| reason.clone())
        .collect();
    if file_denies.len() == 1 {
        lines.push(format!(
            "mati: call mem_get(\"{}\") before editing",
            file_denies[0].0
        ));
    } else if file_denies.len() > 1 {
        lines.push(format!(
            "mati: consult these files before editing — call mem_get for each: {}",
            file_denies
                .iter()
                .map(|(key, _, _)| key.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let msg = lines.join("\n");
    eprintln!("{msg}");
    let _ = std::io::Write::flush(&mut std::io::stderr());

    // 6. Fire compliance events for the blocked files (fire-and-forget).
    // Codex apply_patch: no Claude session_id in the input; agent_id is
    // present only in subagent payloads.
    fire_events(
        &mati_root,
        &events,
        None,
        agent_id,
        actor_scope.as_deref(),
        None,
    )
    .await;
    std::process::exit(2);
}

#[cfg(test)]
mod post_task_tests {
    use super::*;
    use serde_json::json;

    // Shaped like a real CC 2.1.241 `Agent` PostToolUse payload: top-level
    // `agent_id` is the spawner, `tool_response.agentId` the child.
    fn nested_payload() -> serde_json::Value {
        json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Agent",
            "agent_id": "a55cfb5149181a437",
            "session_id": "2e97c8b3-d0a5-4bdf-9570-095ef9631b74",
            "tool_response": {
                "status": "completed",
                "agentId": "a81912b553cdfcfac",
                "agentType": "general-purpose",
                "content": [{"type": "text", "text": "done"}]
            }
        })
    }

    #[test]
    fn nested_spawn_parses_both_ends() {
        let (child, parent, session, agent_type) = parse_nested_spawn(&nested_payload()).unwrap();
        assert_eq!(child, "a81912b553cdfcfac");
        assert_eq!(parent, "a55cfb5149181a437");
        assert_eq!(
            session.as_deref(),
            Some("2e97c8b3-d0a5-4bdf-9570-095ef9631b74")
        );
        assert_eq!(agent_type.as_deref(), Some("general-purpose"));
    }

    #[test]
    fn root_spawn_is_not_an_edge() {
        // Root session spawns a subagent: no top-level agent_id. SubagentSpawned
        // already records this, so parse_nested_spawn must skip it.
        let mut p = nested_payload();
        p.as_object_mut().unwrap().remove("agent_id");
        assert!(parse_nested_spawn(&p).is_none());
    }

    #[test]
    fn empty_spawner_is_not_an_edge() {
        // An interpolated-empty agent_id (main thread) is treated as absent.
        let mut p = nested_payload();
        p["agent_id"] = json!("");
        assert!(parse_nested_spawn(&p).is_none());
    }

    #[test]
    fn incomplete_spawn_is_skipped() {
        let mut p = nested_payload();
        p["tool_response"]["status"] = json!("in_progress");
        assert!(parse_nested_spawn(&p).is_none());
    }

    #[test]
    fn errored_spawn_is_skipped() {
        let mut p = nested_payload();
        p["tool_response"]["isError"] = json!(true);
        assert!(parse_nested_spawn(&p).is_none());
    }

    #[test]
    fn missing_child_id_is_skipped() {
        let mut p = nested_payload();
        p["tool_response"]
            .as_object_mut()
            .unwrap()
            .remove("agentId");
        assert!(parse_nested_spawn(&p).is_none());
    }

    #[test]
    fn absent_session_and_type_are_none_not_error() {
        let mut p = nested_payload();
        p.as_object_mut().unwrap().remove("session_id");
        p["tool_response"]
            .as_object_mut()
            .unwrap()
            .remove("agentType");
        let (child, parent, session, agent_type) = parse_nested_spawn(&p).unwrap();
        assert_eq!(child, "a81912b553cdfcfac");
        assert_eq!(parent, "a55cfb5149181a437");
        assert!(session.is_none());
        assert!(agent_type.is_none());
    }
}
