//! `mati doctor` — diagnostic health aggregator for support and CI.
//!
//! Fans out to: enforcement wiring (reused from `mati check`), daemon
//! reachability, dirty-marker presence, drift check, and recent lifecycle
//! events. Exits 0 if everything is healthy; non-zero if any check is in a
//! fail state. Intended as the "paste this output" command for support
//! requests and as a CI gate for repository health.
//!
//! Drift checks require direct store access. When the daemon holds the
//! exclusive lock, those checks report "skipped" rather than failing —
//! the daemon's own boot-time auto-drain (see `mcp::server::serve`) is
//! already running the same logic on its side.

use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use super::check::{self, CheckItem, CheckStatus};
use super::daemon::{daemon_result, mati_root_for, DaemonResult};

/// Doctor command arguments.
#[derive(Args)]
pub struct DoctorArgs {
    /// Output a structured JSON report on stdout (CI-friendly).
    #[arg(long)]
    pub json: bool,

    /// Show live daemon metrics (per-command counters and p50/p95/p99
    /// latencies) instead of the health-check report. Requires the daemon
    /// to be running — exits non-zero with a clear message otherwise.
    /// SLO-relevant view (ADR-010).
    #[arg(long)]
    pub internal: bool,
}

/// Run all doctor checks, render the report, exit 1 if any FAIL.
pub async fn run(args: DoctorArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = mati_root_for(&cwd)?;

    // `--internal` is a separate view — live daemon metrics, not the health
    // checklist. We intentionally don't run any of the health checks here:
    // those produce side effects (peer credentials, store locks) and would
    // muddy the metric numbers we're about to print.
    if args.internal {
        return run_internal(&root, args.json).await;
    }

    let report = collect(&cwd, &root).await;

    if args.json {
        // JSON goes to stdout — keep stderr quiet so consumers can pipe.
        let json = serde_json::to_string_pretty(&report)?;
        println!("{json}");
    } else {
        let use_color = io::stderr().is_terminal();
        render_human(&report, use_color);
    }

    if report.summary.fail > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Fetch the metrics snapshot from the live daemon and render it.
///
/// Returns Ok(()) on render success, even if the daemon is unreachable —
/// in that case a one-line "daemon not running" message is printed and the
/// process exits 1 (so CI wrappers don't silently succeed).
async fn run_internal(root: &Path, json: bool) -> Result<()> {
    let resp = daemon_result(root, "metrics", serde_json::json!({})).await;
    let data = match resp {
        DaemonResult::Ok(envelope) => envelope
            .get("data")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        DaemonResult::NotRunning | DaemonResult::StaleSocket => {
            eprintln!("daemon is not running — start it with `mati daemon start`");
            std::process::exit(1);
        }
        DaemonResult::Unresponsive | DaemonResult::PermissionDenied => {
            eprintln!("daemon socket exists but is unresponsive");
            eprintln!("  hint: mati daemon stop && mati daemon start");
            std::process::exit(1);
        }
    };

    if json {
        // JSON envelope passes through unchanged so callers see the same shape
        // the daemon emits.
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    render_internal_human(&data);
    Ok(())
}

/// Render a metrics snapshot as a human-readable table on stdout.
///
/// Resilient to schema drift: if the daemon returns a shape this binary
/// doesn't understand, fall back to pretty-printing the raw JSON so the
/// user still sees something useful.
fn render_internal_human(data: &serde_json::Value) {
    use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, ContentArrangement, Table};

    if data.is_null() {
        println!("(daemon has no metrics yet — none recorded since startup)");
        return;
    }

    let uptime = data
        .get("uptime_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let total = data
        .get("total_calls")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let errors = data
        .get("total_errors")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let err_pct = if total == 0 {
        0.0
    } else {
        (errors as f64 / total as f64) * 100.0
    };

    println!("daemon metrics");
    println!("  uptime         {}", format_duration(uptime));
    println!("  total calls    {total} (errors: {errors}, {err_pct:.2}%)");
    println!();

    let Some(commands) = data.get("commands").and_then(|v| v.as_array()) else {
        // Shape didn't match — dump raw so the user can still inspect.
        println!("(unknown metrics shape; raw payload:)");
        if let Ok(pretty) = serde_json::to_string_pretty(data) {
            println!("{pretty}");
        }
        return;
    };

    if commands.is_empty() {
        println!("(no commands recorded since startup)");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("command"),
            Cell::new("count"),
            Cell::new("err%"),
            Cell::new("mean"),
            Cell::new("p50"),
            Cell::new("p95"),
            Cell::new("p99"),
            Cell::new("max"),
        ]);

    for cmd in commands {
        let name = cmd.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let count = cmd.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let errs = cmd.get("error_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let cmd_err_pct = if count == 0 {
            0.0
        } else {
            (errs as f64 / count as f64) * 100.0
        };
        let mean = cmd.get("mean_us").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let p50 = cmd.get("p50_us").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let p95 = cmd.get("p95_us").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let p99 = cmd.get("p99_us").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let max = cmd.get("max_us").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        table.add_row(vec![
            Cell::new(name),
            Cell::new(count),
            Cell::new(format!("{cmd_err_pct:.1}%")),
            Cell::new(format_us(mean)),
            Cell::new(format_us(p50)),
            Cell::new(format_us(p95)),
            Cell::new(format_us(p99)),
            Cell::new(format_us(max)),
        ]);
    }

    println!("{table}");
}

/// Render a microsecond duration in the most readable unit.
fn format_us(us: u32) -> String {
    if us < 1_000 {
        format!("{us}µs")
    } else if us < 1_000_000 {
        format!("{:.1}ms", f64::from(us) / 1_000.0)
    } else {
        format!("{:.2}s", f64::from(us) / 1_000_000.0)
    }
}

/// Render a duration in seconds as a compact human-readable string.
fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

// ── Report types ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct Report {
    version: u32,
    root: String,
    checks: Vec<CheckResult>,
    lifecycle: Vec<LifecycleEntry>,
    summary: Summary,
    /// D3: per-tier accuracy of `/mati-enrich` extractions, computed from
    /// `analytics:extraction:*` records. `None` when the store wasn't
    /// reachable (e.g. uninitialized repo); empty stats when the store is
    /// reachable but no enrichment-tagged gotchas exist yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    extraction: Option<mati_core::store::extraction::ExtractionStats>,
}

#[derive(Serialize)]
struct CheckResult {
    section: &'static str,
    name: &'static str,
    status: Status,
    detail: String,
    /// One-line remediation hint when status is warn/fail.
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<&'static str>,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Status {
    Pass,
    Warn,
    Fail,
    Info,
}

#[derive(Serialize)]
struct LifecycleEntry {
    ts: u64,
    pid: u32,
    event: String,
    detail: String,
}

#[derive(Serialize, Default)]
struct Summary {
    pass: u32,
    warn: u32,
    fail: u32,
    info: u32,
}

// ── Collection ──────────────────────────────────────────────────────────────

async fn collect(cwd: &Path, root: &Path) -> Report {
    let mut checks: Vec<CheckResult> = Vec::new();

    // Enforcement wiring — fold in `mati check`'s pipeline probes so `mati
    // doctor` answers the #1 silent-failure question: "is enforcement actually
    // wired into the agent?" (hook scripts present + executable, settings.json
    // registers them + the mati MCP server, mati on PATH, awk float math).
    // These are side-effect-free and never touch the store, so they remain
    // available even when the daemon holds the store lock (unlike the integrity
    // checks below). `enforcement_results` drops check's own `store` and
    // `daemon` items — doctor already reports those in its own sections.
    checks.extend(enforcement_results(check::run_silent(cwd).await));

    // Daemon ping.
    let daemon_state = daemon_result(root, "ping", serde_json::json!({})).await;
    match &daemon_state {
        DaemonResult::Ok(_) => checks.push(CheckResult {
            section: "daemon",
            name: "ping",
            status: Status::Pass,
            detail: "ok".into(),
            fix: None,
        }),
        DaemonResult::Unresponsive | DaemonResult::PermissionDenied => checks.push(CheckResult {
            section: "daemon",
            name: "ping",
            status: Status::Fail,
            detail: "socket exists but daemon is not responding".into(),
            fix: Some("mati daemon stop && mati daemon start"),
        }),
        DaemonResult::StaleSocket => checks.push(CheckResult {
            section: "daemon",
            name: "ping",
            status: Status::Warn,
            detail: "stale socket detected and cleaned up".into(),
            fix: None,
        }),
        DaemonResult::NotRunning => match crate::cli::daemon::socket_path_problem(root) {
            Some(problem) => checks.push(CheckResult {
                section: "daemon",
                name: "ping",
                status: Status::Fail,
                detail: problem.lines().next().unwrap_or_default().to_string(),
                fix: Some("set MATI_HOME to a shorter directory"),
            }),
            None => checks.push(CheckResult {
                section: "daemon",
                name: "ping",
                status: Status::Info,
                detail: "not running (OK if no agent session is active)".into(),
                fix: None,
            }),
        },
    }

    // Integrity: dirty_marker + drift.
    //
    // Schema-stability invariant: always exactly two `integrity` checks —
    // `dirty_marker` then `drift`, in that order — in every scenario, so
    // `mati doctor --json` (version 2) stays index-stable.
    //
    // Routed through `StoreProxy` (read-only), so — unlike the old
    // `Store::open` path that went `skipped` — these now report even while the
    // daemon holds the store lock: the proxy routes the reads through the
    // daemon socket. On an uninitialised repo the proxy refuses to open (it
    // won't scaffold state) and we emit Info rows pointing at `mati init`.
    match crate::cli::proxy::StoreProxy::open(cwd).await {
        Ok(proxy) => {
            if mati_core::store::repair::is_dirty(&proxy).await {
                let detail = match mati_core::store::repair::read_dirty_marker(&proxy).await {
                    Some(m) => format!("{} key(s) flagged: {}", m.affected_keys.len(), m.cause),
                    None => "flagged but cause not readable".to_string(),
                };
                checks.push(CheckResult {
                    section: "integrity",
                    name: "dirty_marker",
                    status: Status::Warn,
                    detail,
                    fix: Some("mati repair --fast"),
                });
            } else {
                checks.push(CheckResult {
                    section: "integrity",
                    name: "dirty_marker",
                    status: Status::Pass,
                    detail: "not set".into(),
                    fix: None,
                });
            }

            match mati_core::store::repair::check_gotcha_indexes(&proxy, proxy.repo_root()).await {
                Ok(report) => {
                    if report.has_drift() {
                        let detail = format!(
                            "missing_file={}, stale_file={}, missing_edge={}, stale_edge={}, unnormalized_path={}",
                            report.missing_file_links.len(),
                            report.stale_file_links.len(),
                            report.missing_edges.len(),
                            report.stale_edges.len(),
                            report.unnormalized_paths.len(),
                        );
                        // `mati repair` re-keys gotchas whose affected_files
                        // were stored in a spelling the read gate never
                        // produces, and links the corrected path — creating a
                        // Layer 0 file stub if that path was never indexed.
                        // What it still cannot do is materialize a file:<path>
                        // record for an already-correct path that init never
                        // saw; that needs a re-index. So repair always comes
                        // first, and init only if links remain missing after.
                        let fix = if !report.unnormalized_paths.is_empty() {
                            "mati repair  (re-keys unnormalized gotcha paths)"
                        } else if !report.missing_file_links.is_empty() {
                            "mati repair, then mati init if links are still missing"
                        } else {
                            "mati repair"
                        };
                        checks.push(CheckResult {
                            section: "integrity",
                            name: "drift",
                            status: Status::Fail,
                            detail,
                            fix: Some(fix),
                        });
                    } else {
                        checks.push(CheckResult {
                            section: "integrity",
                            name: "drift",
                            status: Status::Pass,
                            detail: "no drift detected".into(),
                            fix: None,
                        });
                    }
                }
                Err(e) => checks.push(CheckResult {
                    section: "integrity",
                    name: "drift",
                    status: Status::Fail,
                    detail: format!("check error: {e}"),
                    fix: None,
                }),
            }

            let _ = proxy.close().await;
        }
        Err(_) => {
            // Proxy refuses to open when there's no store (and no daemon) — we
            // report state, never scaffold it. Same two rows, so the JSON
            // shape stays stable across scenarios.
            let no_store_detail =
                "skipped — no store initialized for this directory (run `mati init` to set up)";
            checks.push(CheckResult {
                section: "integrity",
                name: "dirty_marker",
                status: Status::Info,
                detail: no_store_detail.into(),
                fix: Some("mati init"),
            });
            checks.push(CheckResult {
                section: "integrity",
                name: "drift",
                status: Status::Info,
                detail: no_store_detail.into(),
                fix: Some("mati init"),
            });
        }
    }

    // Audit-chain integrity — routed through StoreProxy so it runs even while
    // the daemon holds the store lock (unlike dirty_marker/drift above). Reuses
    // the frozen-contract primitive `enforcement::verify_chain`.
    checks.push(collect_chain_check(cwd).await);
    checks.push(collect_freshness_check(cwd).await);

    // Network/telemetry posture — a compile-time attestation surfaced in-tool,
    // so an auditor sees mati's headline invariant by running `mati doctor`
    // rather than reading the CI workflow.
    checks.push(collect_network_attestation());

    // Appended after `network` on purpose: every check added from here on goes
    // at the end, so an index a consumer already relies on never moves. Adding
    // this one before `network` would have shifted it from 13 to 14.
    checks.push(collect_policy_check(cwd).await);
    checks.push(collect_binary_parity_check(cwd, root));
    checks.push(collect_gating_check(cwd).await);
    checks.push(collect_seal_check(cwd, root).await);

    // Lifecycle log tail.
    let lifecycle = read_lifecycle_tail(root, 5);

    // D3: extraction-quality stats. Routes through StoreProxy so it works
    // whether the daemon owns the lock (socket-routed scan_prefix) or the
    // store is direct-accessible. Default window: last 30 days — matches
    // `mati ls tombstoned --recent`'s default and the spec.
    let extraction = collect_extraction_stats(cwd).await;

    // Summary.
    let mut summary = Summary::default();
    for c in &checks {
        match c.status {
            Status::Pass => summary.pass += 1,
            Status::Warn => summary.warn += 1,
            Status::Fail => summary.fail += 1,
            Status::Info => summary.info += 1,
        }
    }

    Report {
        version: 2,
        root: root.display().to_string(),
        checks,
        lifecycle,
        summary,
        extraction,
    }
}

/// Surface the build's network/telemetry posture as a first-class doctor row.
///
/// This is the in-tool face of mati's headline invariant ("zero network calls,
/// never phones home"): an auditor running `mati doctor` sees the posture
/// directly instead of having to read the CI workflow. It is a *compile-time*
/// attestation, deliberately NOT a runtime probe — a probe would itself be a
/// network call, contradicting the very property being attested. The proof is
/// the `zero_network` module in `src/invariants.rs`, which scans the source for
/// IP-socket and HTTP APIs, asserts the daemon transport is a Unix socket, and
/// checks the default build's resolved dependency graph. That is static
/// analysis; a syscall-level audit would be the runtime proof and does not
/// exist. This row reports which build you are running.
///
/// Accurate via `cfg!(feature = "semantic")`: the default (enforcement) build
/// links no network/HTTP-client crate; the opt-in `semantic` feature is the one
/// documented exception — it fetches the embedding model via hf-hub on first
/// use — and is disclosed honestly rather than hidden.
fn collect_network_attestation() -> CheckResult {
    if cfg!(feature = "semantic") {
        CheckResult {
            section: "attestation",
            name: "network",
            status: Status::Info,
            detail: "semantic feature enabled — embedding-model fetch via hf-hub \
                     is linked (opt-in; downloads all-MiniLM-L6-v2 on first use). \
                     Enforcement decisions remain local and make no outbound \
                     connection."
                .into(),
            fix: None,
        }
    } else {
        CheckResult {
            section: "attestation",
            name: "network",
            status: Status::Pass,
            detail: "no network/HTTP-client dependency linked in this build; the \
                     enforcement path makes no outbound connection (checked by the \
                     zero_network tests: source scan, Unix-socket transport, and \
                     the default build's dependency graph — static analysis, not a \
                     runtime probe). mati never phones home."
                .into(),
            fix: None,
        }
    }
}

/// Map `mati check`'s enforcement-pipeline probes into doctor `CheckResult`s.
///
/// Drops the `store` and `daemon` items — doctor already reports those via its
/// own `integrity` and `daemon` sections, so folding them in would duplicate
/// rows. The remaining probes (git repo, mati-on-PATH, awk float math, hook
/// scripts, settings.json wiring) answer the question doctor couldn't before:
/// "is enforcement actually wired into the agent?" None of them open the store,
/// so they stay available even when the daemon holds the lock. Names are
/// normalized to snake_case to match doctor's existing convention (`ping`,
/// `dirty_marker`, `drift`).
fn enforcement_results(items: Vec<CheckItem>) -> Vec<CheckResult> {
    items
        .into_iter()
        .filter_map(|item| {
            let name: &'static str = match item.label {
                "git repo" => "git_repo",
                "mati in PATH" => "mati_on_path",
                "awk float math" => "awk_float_math",
                "agent host" => "agent_host",
                "claude hooks" => "claude_hooks",
                "claude config" => "claude_config",
                "codex hooks" => "codex_hooks",
                "codex config" => "codex_config",
                // `store` and `daemon` are already covered by doctor's own
                // integrity/daemon sections — skip to avoid duplicate rows.
                _ => return None,
            };
            let (status, detail) = match item.status {
                CheckStatus::Pass(extra) => {
                    (Status::Pass, extra.unwrap_or_else(|| "ok".to_string()))
                }
                CheckStatus::Warn(msg) => (Status::Warn, msg),
                CheckStatus::Fail(msg) => (Status::Fail, msg),
            };
            // `detail` already carries the specifics (e.g. "missing:
            // pre-read.sh"); `fix` is a static, name-keyed one-liner.
            let fix = if matches!(status, Status::Pass) {
                None
            } else {
                Some(match name {
                    "git_repo" => "run mati from inside a git repository",
                    "mati_on_path" => "ensure the mati binary is on PATH",
                    "awk_float_math" => "install awk/gawk and ensure it is on PATH",
                    "agent_host" => "mati hooks --claude  (or --codex)",
                    "codex_hooks" | "codex_config" => "mati hooks --codex",
                    // claude_hooks / claude_config
                    _ => "mati hooks --claude",
                })
            };
            Some(CheckResult {
                section: "enforcement",
                name,
                status,
                detail,
                fix,
            })
        })
        .collect()
}

/// Verify the enforcement audit chain. Routed through `StoreProxy`, so unlike
/// the `Store::open`-based dirty_marker/drift checks it runs even while the
/// daemon holds the store lock. Reuses `enforcement::verify_chain` — the single
/// source of truth for the frozen hash contract (same primitive as
/// `mati verify-chain`). Read-only, zero-network.
async fn collect_chain_check(cwd: &Path) -> CheckResult {
    let proxy = match crate::cli::proxy::StoreProxy::open(cwd).await {
        Ok(p) => p,
        Err(_) => {
            return CheckResult {
                section: "integrity",
                name: "chain",
                status: Status::Info,
                detail: "skipped — no store initialized for this directory".to_string(),
                fix: None,
            };
        }
    };
    let scan = proxy
        .scan_enforcement_events_with_skips(0, u64::MAX)
        .await
        .unwrap_or_default();
    let _ = proxy.close().await;

    let events = scan.events;
    let total = events.len();
    let result =
        mati_core::store::enforcement::verify_chain_with_skips(&events, &scan.skipped_seqs);
    if result.is_valid() {
        CheckResult {
            section: "integrity",
            name: "chain",
            status: Status::Pass,
            detail: format!("intact — {total} event(s), every hash verified"),
            fix: None,
        }
    } else {
        CheckResult {
            section: "integrity",
            name: "chain",
            status: Status::Fail,
            detail: format!(
                "BROKEN — {} tampered, {} linkage break(s), {} unknown-schema of {total} event(s)",
                result.tampered_events, result.linkage_breaks, result.unknown_schema
            ),
            fix: Some("mati verify-chain --verbose"),
        }
    }
}

/// Knowledge freshness — how many records have gone stale relative to the code.
/// Reads the write-seq-validated stale cache via StoreProxy (cheap; no full
/// scan). `Info` when the cache is cold (run `mati stale`); `Warn` when records
/// are stale — advisory, since stale knowledge degrades enforcement quality but
/// doesn't break it, so this never fails the CI gate.
/// Re-run the author-time checks against what is actually stored.
///
/// A policy can be authored before a check existed, or edited through a path
/// that skipped one, and a stored policy with a malformed glob is skipped by
/// `from_records_lenient` at daemon boot with only a log line. The operator sees
/// an `enforce` policy in `mati policy list` and reasonably assumes it enforces.
/// This is the surface that says otherwise.
async fn collect_policy_check(cwd: &Path) -> CheckResult {
    use mati_core::store::{PolicyRecord, PolicyStage, RecordLifecycle};

    let proxy = match crate::cli::proxy::StoreProxy::open(cwd).await {
        Ok(p) => p,
        Err(_) => {
            return CheckResult {
                section: "enforcement",
                name: "policy",
                status: Status::Info,
                detail: "skipped — no store initialized for this directory".to_string(),
                fix: None,
            };
        }
    };
    let records = match proxy.scan_prefix("policy:").await {
        Ok(r) => r,
        Err(e) => {
            let _ = proxy.close().await;
            return CheckResult {
                section: "enforcement",
                name: "policy",
                status: Status::Fail,
                detail: format!("could not read policies: {e}"),
                fix: Some("mati doctor"),
            };
        }
    };

    let (mut enforce, mut shadow, mut off) = (0usize, 0usize, 0usize);
    let mut broken: Vec<String> = Vec::new();
    let mut warned: Vec<String> = Vec::new();
    let mut enforcing_keys = std::collections::BTreeSet::new();
    let now = mati_core::store::session::now_secs();

    for record in &records {
        if !matches!(record.lifecycle, RecordLifecycle::Active) {
            continue;
        }
        let Some(policy) = record.payload_as::<PolicyRecord>() else {
            broken.push(format!("{} (unreadable payload)", record.key));
            continue;
        };
        match policy.stage {
            PolicyStage::Enforce => enforce += 1,
            PolicyStage::Shadow => shadow += 1,
            PolicyStage::Off => off += 1,
        }
        if matches!(policy.stage, PolicyStage::Off) {
            continue;
        }
        if matches!(policy.stage, PolicyStage::Enforce) {
            enforcing_keys.insert((record.key.clone(), record.created_at));
        }
        // A bad glob is a silent non-enforcement, not a style problem.
        if let Err(e) = mati_core::store::policy_ops::validate_trigger(&policy.trigger) {
            broken.push(format!("{} ({e})", record.key));
            continue;
        }
        let backed = matches!(proxy.get(&policy.requires.key).await, Ok(Some(_)));
        for w in mati_core::store::policy_ops::author_warnings(&policy, backed) {
            warned.push(format!(
                "{}: {}",
                record.key,
                w.trim_start_matches("warning: ")
            ));
        }
    }
    if let Ok(activity) = crate::cli::policy::collect_policy_activity(
        &proxy,
        crate::cli::policy::POLICY_ACTIVITY_DEFAULT_DAYS,
    )
    .await
    {
        for policy in activity.policies {
            if !matches!(policy.state, crate::cli::policy::ActivityState::NoActivity) {
                continue;
            }
            let Some((_, created_at)) =
                enforcing_keys.iter().find(|(key, _)| key == &policy.policy)
            else {
                continue;
            };
            if now.saturating_sub(*created_at)
                < crate::cli::policy::POLICY_ACTIVITY_GRACE_DAYS * 86_400
            {
                continue;
            }
            warned.push(format!(
                "{}: no activity in {} days; the rule may no longer be needed or its trigger may have stopped matching — use `mati policy test` to tell which",
                policy.policy, policy.window_days
            ));
        }
    }
    let _ = proxy.close().await;

    let counts = format!("{enforce} enforcing, {shadow} shadow, {off} off");
    if !broken.is_empty() {
        return CheckResult {
            section: "enforcement",
            name: "policy",
            status: Status::Fail,
            detail: format!(
                "{counts}; NOT enforcing despite their stage: {}",
                broken.join("; ")
            ),
            fix: Some("mati policy edit <slug>"),
        };
    }
    if !warned.is_empty() {
        return CheckResult {
            section: "enforcement",
            name: "policy",
            status: Status::Warn,
            detail: format!("{counts}; {}", warned.join("; ")),
            fix: Some("mati policy show <slug>"),
        };
    }
    if records.is_empty() {
        return CheckResult {
            section: "enforcement",
            name: "policy",
            status: Status::Info,
            detail: "no local policies authored".to_string(),
            fix: None,
        };
    }
    CheckResult {
        section: "enforcement",
        name: "policy",
        status: Status::Pass,
        detail: counts,
        fix: None,
    }
}

async fn collect_freshness_check(cwd: &Path) -> CheckResult {
    let proxy = match crate::cli::proxy::StoreProxy::open(cwd).await {
        Ok(p) => p,
        Err(_) => {
            return CheckResult {
                section: "knowledge",
                name: "freshness",
                status: Status::Info,
                detail: "skipped — no store initialized for this directory".to_string(),
                fix: None,
            };
        }
    };
    let summary = crate::cli::stale::stale_summary(&proxy).await;
    let _ = proxy.close().await;
    freshness_result(summary)
}

/// The `knowledge/freshness` verdict, split out so every branch is testable
/// without a store.
///
/// Drift gets its own arm. Folding it into the general Warn arm rendered
/// "0 stale record(s) (0 stale, 0 liability, 0 tombstone); 1 confirmed
/// gotcha(s) describe changed code" — a count of zero followed by a real
/// problem — and offered `mati reparse`, which cannot clear drift. Only
/// re-confirming can.
fn freshness_result(summary: Option<crate::cli::stale::StaleSummary>) -> CheckResult {
    match summary {
        None => CheckResult {
            section: "knowledge",
            name: "freshness",
            status: Status::Info,
            detail: "unknown — run `mati stale` for a current count".to_string(),
            fix: None,
        },
        Some(s) if s.total == 0 && s.drift == 0 => CheckResult {
            section: "knowledge",
            name: "freshness",
            status: Status::Pass,
            detail: "no stale records".to_string(),
            fix: None,
        },
        Some(s) if s.total == 0 => CheckResult {
            section: "knowledge",
            name: "freshness",
            status: Status::Warn,
            detail: format!(
                "no records stale by age; {} confirmed gotcha(s) describe changed code",
                s.drift
            ),
            fix: Some("mati gotcha confirm <key>  (after re-reading the file)"),
        },
        Some(s) => CheckResult {
            section: "knowledge",
            name: "freshness",
            status: Status::Warn,
            detail: format!(
                "{} stale record(s) ({} stale, {} liability, {} tombstone){}",
                s.total,
                s.stale,
                s.liability,
                s.tombstone,
                drift_detail(s.drift)
            ),
            fix: Some("mati stale  (then mati init / mati reparse to refresh)"),
        },
    }
}

/// Active confirmed gotchas, split by the two ways one can fail to gate a read.
///
/// Returns `(confirmed, ungated, inert)` — both residuals are `Info`, never
/// `Warn`/`Fail`, since each is a legitimate state, not a defect:
/// - `inert`: `quality < 0.4`. Confirm forces confidence to 0.80, so quality is
///   the only reachable blocker. Below 0.4 the record is excluded from bootstrap
///   injection (`is_injectable_gotcha`) AND cannot deny a read (`decide`
///   requires `quality >= 0.4`) — it does nothing, whether or not it names files.
/// - `ungated`: `quality >= 0.4` but empty `affected_files`. Injected by
///   `mem_bootstrap` as a project-wide advisory, yet the read gate can never
///   fire it — the gate keys on `file:<path>.gotcha_keys`, derived from
///   `affected_files`. Quality is checked first, so this bucket is genuinely
///   injected; the two are disjoint.
///
/// Auto-derived stubs (`gotcha:cochange/revert/ownership:*`) are
/// `confirmed=false` by design, so they fall out via `confirmed`.
fn gating_counts(records: &[mati_core::store::Record]) -> (usize, usize, usize) {
    use mati_core::store::{GotchaRecord, RecordLifecycle};
    let mut confirmed = 0usize;
    let mut ungated = 0usize;
    let mut inert = 0usize;
    for record in records {
        if !matches!(record.lifecycle, RecordLifecycle::Active) {
            continue;
        }
        let Some(g) = record.payload_as::<GotchaRecord>() else {
            continue;
        };
        if !g.confirmed {
            continue;
        }
        confirmed += 1;
        if record.quality.value < 0.4 {
            inert += 1;
        } else if g.affected_files.is_empty() {
            ungated += 1;
        }
    }
    (confirmed, ungated, inert)
}

async fn collect_gating_check(cwd: &Path) -> CheckResult {
    let proxy = match crate::cli::proxy::StoreProxy::open(cwd).await {
        Ok(p) => p,
        Err(_) => {
            return CheckResult {
                section: "knowledge",
                name: "gating",
                status: Status::Info,
                detail: "skipped — no store initialized for this directory".to_string(),
                fix: None,
            };
        }
    };
    let records = match proxy.scan_prefix("gotcha:").await {
        Ok(r) => r,
        Err(e) => {
            let _ = proxy.close().await;
            return CheckResult {
                section: "knowledge",
                name: "gating",
                status: Status::Fail,
                detail: format!("could not read gotchas: {e}"),
                fix: Some("mati doctor"),
            };
        }
    };
    let _ = proxy.close().await;

    let (confirmed, ungated, inert) = gating_counts(&records);

    if confirmed == 0 {
        return CheckResult {
            section: "knowledge",
            name: "gating",
            status: Status::Info,
            detail: "no confirmed gotchas yet".to_string(),
            fix: None,
        };
    }
    if ungated == 0 && inert == 0 {
        return CheckResult {
            section: "knowledge",
            name: "gating",
            status: Status::Pass,
            detail: format!("{confirmed} confirmed gotcha(s), all gate a file read"),
            fix: None,
        };
    }

    let mut parts: Vec<String> = Vec::new();
    if ungated > 0 {
        parts.push(format!(
            "{ungated} name no affected_files (injected as advisory, cannot gate a read)"
        ));
    }
    if inert > 0 {
        parts.push(format!(
            "{inert} name files but quality < 0.4 (not injected — inert)"
        ));
    }
    let fix = match (ungated > 0, inert > 0) {
        (true, true) => "mem_set affected_files, and raise quality >= 0.4 on the low-quality ones",
        (true, false) => "mem_set the gotcha with affected_files, or record it as a dev note",
        (false, true) => {
            "raise the gotcha's quality >= 0.4 (add causality, a specific identifier, more detail)"
        }
        (false, false) => unreachable!("guarded by the ungated == 0 && inert == 0 return above"),
    };
    CheckResult {
        section: "knowledge",
        name: "gating",
        status: Status::Info,
        detail: format!(
            "{} of {confirmed} confirmed gotcha(s) cannot gate a file read: {}",
            ungated + inert,
            parts.join("; ")
        ),
        fix: Some(fix),
    }
}

/// Tier 2 read floor: what `mati seal` is holding at mode `000` right now.
///
/// Inventory only. `seal::inventory` stats each manifest row and never hashes,
/// so running `mati doctor` cannot open a sealed file — the one privileged read
/// Tier 2 grants belongs to the post-Bash sweep, which has already seen the
/// bytes move before it takes it.
///
/// A lifted row is reported, never accused. Deciding whether a lowered floor
/// was a live receipt or a bypass needs a receipt question against the daemon,
/// and that is the sweep's job. Doctor reports the bypasses the sweep already
/// recorded instead of re-deriving them.
async fn collect_seal_check(cwd: &Path, root: &Path) -> CheckResult {
    let row = |status, detail: String, fix| CheckResult {
        section: "enforcement",
        name: "seal",
        status,
        detail,
        fix,
    };

    let inv = mati_core::seal::inventory(&mati_core::seal::manifest_in(root));
    if inv.total() == 0 {
        return row(Status::Info, "no files sealed".to_string(), None);
    }

    let bypasses = seal_bypasses_recorded(cwd).await;
    let mut notes: Vec<String> = Vec::new();
    if inv.lifted > 0 {
        notes.push(format!("{} currently readable", inv.lifted));
    }
    if inv.missing > 0 {
        notes.push(format!("{} gone from disk", inv.missing));
    }
    let detail = format!(
        "{} file(s) sealed, {} at mode 000{}",
        inv.total(),
        inv.at_floor,
        if notes.is_empty() {
            String::new()
        } else {
            format!(" ({})", notes.join(", "))
        }
    );

    if bypasses > 0 {
        return row(
            Status::Warn,
            format!("{detail}; {bypasses} bypass(es) recorded on sealed files"),
            Some("mati seal list, and mati verify-chain for the recorded events"),
        );
    }
    if inv.missing > 0 {
        return row(
            Status::Warn,
            detail,
            Some("mati seal remove <path>  (drops the row for a file that is gone)"),
        );
    }
    row(Status::Pass, detail, None)
}

/// Sum every retained `compliance:seal_bypass_*` daily aggregate.
///
/// A prefix scan rather than seven dated `get`s: the window that matters is
/// "has the floor ever been bypassed in this repo", and retention already
/// bounds how far back the rows go.
async fn seal_bypasses_recorded(cwd: &Path) -> u64 {
    let Ok(proxy) = crate::cli::proxy::StoreProxy::open(cwd).await else {
        return 0;
    };
    let total = match proxy.scan_prefix("compliance:seal_bypass_").await {
        Ok(records) => records
            .iter()
            .filter_map(|r| r.payload_as::<mati_core::store::session::DailyAgg>())
            .map(|a| a.count)
            .sum(),
        Err(_) => 0,
    };
    let _ = proxy.close().await;
    total
}

/// Do the hooks and the daemon run the same mati build?
///
/// They resolve independently. `mati init` pins `.claude/hooks/mati` (and the
/// Codex equivalent) to the absolute path of whatever executable ran it, while
/// `.mcp.json` registers a bare `mati` off PATH. On a normal install both are
/// `~/.cargo/bin/mati` and the wrapper's promise holds. Run `mati init` from a
/// dev build and the hooks are pinned to `target/debug/mati` instead — then
/// rebuilding one and not the other puts a stale client against a live daemon.
///
/// That failure is silent: hooks fail open on a protocol mismatch (P9), so the
/// symptom is under-enforcement, not an error. This check is the detection —
/// `Warn`, never `Fail`, because a version skew is a diagnosis, not a broken
/// pipeline, and doctor's exit code gates CI.
fn collect_binary_parity_check(cwd: &Path, root: &Path) -> CheckResult {
    let check = |name: &'static str, status, detail: String, fix| CheckResult {
        section: "enforcement",
        name,
        status,
        detail,
        fix,
    };

    let Some(wrapper) = hook_wrapper_path(cwd) else {
        return check(
            "binary parity",
            Status::Info,
            "no hook wrapper installed".into(),
            None,
        );
    };
    let Some(hook_version) = binary_version(&wrapper) else {
        return check(
            "binary parity",
            Status::Warn,
            format!(
                "hook wrapper {} did not report a version",
                wrapper.display()
            ),
            Some("mati hooks"),
        );
    };

    // The running daemon is authoritative — it is the process hooks talk to.
    // With none running, PATH is what the next `mati serve` will resolve.
    let (server_version, server_label) = match mati_core::mcp::metadata::read_metadata(root)
        .map(|m| m.version)
        .filter(|v| !v.is_empty())
    {
        Some(v) => (v, "daemon"),
        None => match binary_version(Path::new("mati")) {
            Some(v) => (v, "mati on PATH"),
            None => {
                return check(
                    "binary parity",
                    Status::Warn,
                    "no running daemon and no mati on PATH to compare against".into(),
                    Some("mati daemon start"),
                )
            }
        },
    };

    if hook_version == server_version {
        if let Some(detail) = build_skew(&wrapper, root) {
            return check(
                "binary parity",
                Status::Warn,
                detail,
                Some("mati daemon stop  (the next call restarts it from the current binary)"),
            );
        }
        check(
            "binary parity",
            Status::Pass,
            format!("hooks and {server_label} both {hook_version}"),
            None,
        )
    } else {
        check(
            "binary parity",
            Status::Warn,
            format!(
                "hooks run {hook_version} ({}), {server_label} runs {server_version} — \
                 hooks fail open on a protocol mismatch, so enforcement can silently degrade",
                wrapper.display()
            ),
            Some("mati init  (re-pins the hook wrapper to this binary)"),
        )
    }
}

/// Same version string, two different binaries — the skew `version` cannot
/// see. `cargo install` twice off one tree leaves a daemon serving the old
/// code while hooks exec the new, and both answer `--version` identically.
/// `None` when there is nothing to compare: no running daemon, metadata from a
/// binary that recorded no build, or an unreadable wrapper target.
fn build_skew(wrapper: &Path, root: &Path) -> Option<String> {
    let daemon_build = mati_core::mcp::metadata::read_metadata(root)
        .map(|m| m.build)
        .filter(|b| !b.is_empty())?;
    let target = wrapper_exec_target(wrapper)?;
    let hook_build = mati_core::mcp::metadata::build_id_of(&target)?;
    if hook_build == daemon_build {
        return None;
    }
    Some(format!(
        "hooks and the daemon both report {}, but are different builds \
         (hooks {}, daemon {}) — the daemon is still serving the code it \
         started with, so a rebuilt gate is not the one being enforced",
        env!("CARGO_PKG_VERSION"),
        &hook_build[..12],
        &daemon_build[..12],
    ))
}

/// The absolute binary a hook wrapper execs. The wrapper is a fixed four-line
/// bash script written by `scaffold::write_mati_wrapper`, so the target is the
/// quoted word on the `exec` line.
fn wrapper_exec_target(wrapper: &Path) -> Option<PathBuf> {
    let body = std::fs::read_to_string(wrapper).ok()?;
    let rest = body.lines().find_map(|l| l.strip_prefix("exec \""))?;
    let (bin, _) = rest.split_once('"')?;
    Some(PathBuf::from(bin))
}

/// The binary wrapper a host's hooks exec, if one is installed.
fn hook_wrapper_path(cwd: &Path) -> Option<PathBuf> {
    [".claude/hooks/mati", ".codex/hooks/mati"]
        .iter()
        .map(|p| cwd.join(p))
        .find(|p| p.exists())
}

/// `<bin> --version` → the version token, or `None` if it cannot be run.
fn binary_version(bin: &Path) -> Option<String> {
    let out = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .last()
        .map(str::to_owned)
}

/// Content-drift clause appended to the freshness detail.
///
/// Folded into the existing `knowledge/freshness` check rather than added as
/// its own entry: the `--json` check array is index-stable for consumers (see
/// `doctor_json_shape_is_stable_across_scenarios`), and `integrity/drift`
/// already means something else entirely — derived-index drift, not content
/// drift. Same freshness question, so same check.
fn drift_detail(drift: usize) -> String {
    if drift == 0 {
        return String::new();
    }
    format!("; {drift} confirmed gotcha(s) describe changed code")
}

/// Read all `analytics:extraction:*` records via StoreProxy and aggregate.
/// Returns `None` when the proxy can't be opened (uninitialized repo); an
/// empty `ExtractionStats` (total=0) is a valid Some(stats) — means "no
/// enrichment-tagged gotchas have been written yet."
///
/// Window: last 30 days, matching `mati ls tombstoned --recent`'s default
/// and ENRICH_QUALITY.md Section 8.
async fn collect_extraction_stats(
    cwd: &Path,
) -> Option<mati_core::store::extraction::ExtractionStats> {
    use mati_core::store::extraction::{aggregate_stats, ExtractionRecord, EXTRACTION_PREFIX};

    let proxy = match crate::cli::proxy::StoreProxy::open(cwd).await {
        Ok(p) => p,
        Err(_) => return None,
    };
    let records = proxy
        .scan_prefix(EXTRACTION_PREFIX)
        .await
        .unwrap_or_default();
    let _ = proxy.close().await;

    let extractions: Vec<ExtractionRecord> = records
        .into_iter()
        .filter_map(|r| r.payload.and_then(|p| serde_json::from_value(p).ok()))
        .collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let since = now.saturating_sub(30 * 86_400);
    Some(aggregate_stats(&extractions, since, now))
}

fn read_lifecycle_tail(root: &Path, n: usize) -> Vec<LifecycleEntry> {
    let path = root.join("lifecycle.log");
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..]
        .iter()
        .filter_map(|line| {
            let cols: Vec<&str> = line.splitn(4, '\t').collect();
            if cols.len() != 4 {
                return None;
            }
            Some(LifecycleEntry {
                ts: cols[0].parse().unwrap_or(0),
                pid: cols[1].parse().unwrap_or(0),
                event: cols[2].to_string(),
                detail: cols[3].to_string(),
            })
        })
        .collect()
}

// ── Human renderer ──────────────────────────────────────────────────────────

fn render_human(report: &Report, use_color: bool) {
    println!();
    println!("mati doctor — {}", report.root);
    println!();

    let mut current_section: &str = "";
    for c in &report.checks {
        if c.section != current_section {
            if !current_section.is_empty() {
                println!();
            }
            let title = match c.section {
                "enforcement" => "Enforcement",
                "daemon" => "Daemon",
                "integrity" => "Integrity",
                "knowledge" => "Knowledge",
                "attestation" => "Attestation",
                other => other,
            };
            println!("{title}");
            current_section = c.section;
        }
        let symbol = symbol_for(c.status, use_color);
        println!("  {:18} {}  {}", c.name, symbol, c.detail);
        if let Some(fix) = c.fix {
            println!("                       fix: {fix}");
        }
    }

    println!();
    println!("Lifecycle (last {} events)", report.lifecycle.len());
    if report.lifecycle.is_empty() {
        println!("  (no lifecycle.log yet — log fills as the daemon runs)");
    } else {
        for e in &report.lifecycle {
            println!(
                "  {:<14}  pid={:<6} {:<18} {}",
                relative_ts(e.ts),
                e.pid,
                e.event,
                e.detail
            );
        }
    }

    if let Some(extraction) = &report.extraction {
        render_extraction_section(extraction);
    }

    println!();
    let s = &report.summary;
    if s.fail > 0 {
        println!(
            "Result: {} fail, {} warn, {} pass — see fixes above",
            s.fail, s.warn, s.pass
        );
    } else if s.warn > 0 {
        println!("Result: clean with {} warn ({} pass)", s.warn, s.pass);
    } else {
        println!("Result: all checks passed ({} pass)", s.pass);
    }
}

/// Render the D3 extraction-quality section. Skipped entirely when no
/// extractions have been recorded (`total == 0`) — keeps the doctor
/// output clean on fresh installs.
fn render_extraction_section(s: &mati_core::store::extraction::ExtractionStats) {
    if s.total == 0 {
        return;
    }
    println!();
    println!("Extraction quality (last 30d, /mati-enrich pipeline)");
    println!("  total           {:>4}", s.total);
    println!(
        "  confirmed       {:>4}  ({})",
        s.confirmed,
        rate_label(s.confirmed, s.total)
    );
    println!(
        "  tombstoned      {:>4}  ({})",
        s.tombstoned,
        rate_label(s.tombstoned, s.total)
    );
    println!("  pending         {:>4}", s.pending);
    if s.expired > 0 {
        println!("  expired (>90d)  {:>4}", s.expired);
    }

    // Per-tier breakdown — only render tiers with non-zero data.
    let tiers = [
        ("fast    ", &s.per_tier.fast),
        ("standard", &s.per_tier.standard),
        ("deep    ", &s.per_tier.deep),
        ("unknown ", &s.per_tier.unknown),
    ];
    let any_tier_used = tiers.iter().any(|(_, t)| t.total > 0);
    if any_tier_used {
        println!();
        println!("  Per-tier:");
        for (label, tier) in &tiers {
            if tier.total == 0 {
                continue;
            }
            let rate = tier.confirmed_rate().map_or_else(
                || "—".to_string(),
                |r| format!("{:>3.0}% confirmed", r * 100.0),
            );
            println!("    {label}  {:>3} extractions, {rate}", tier.total);
        }
    }

    // SOTA-δ: per-config A/B breakdown. Hidden when only one config has
    // data (the comparison is meaningless until at least two configs
    // have extractions). Useful for proving the SOTA pipeline (`ast+*`)
    // outperforms the legacy LLM-driven scan (`llm+*`).
    let active_configs: Vec<_> = s.per_config.iter().filter(|(_, t)| t.total > 0).collect();
    if active_configs.len() >= 2 {
        println!();
        println!("  Per-config (A/B):");
        // Render in stable order: BTreeMap iteration is alphabetical
        // which is fine — `ast+*` sorts before `llm+*`.
        for (label, tier) in &active_configs {
            let rate = tier.confirmed_rate().map_or_else(
                || "—".to_string(),
                |r| format!("{:>3.0}% confirmed", r * 100.0),
            );
            println!("    {label:>11}  {:>3} extractions, {rate}", tier.total);
        }
    }
}

fn rate_label(n: u64, total: u64) -> String {
    (n * 100)
        .checked_div(total)
        .map(|pct| format!("{pct}%"))
        .unwrap_or_else(|| "0%".to_string())
}

fn symbol_for(status: Status, use_color: bool) -> String {
    let s = match status {
        Status::Pass => "ok",
        Status::Warn => "WARN",
        Status::Fail => "FAIL",
        Status::Info => "—",
    };
    if !use_color {
        return s.to_string();
    }
    match status {
        Status::Pass => format!("\x1b[32m{s}\x1b[0m"),
        Status::Warn => format!("\x1b[33m{s}\x1b[0m"),
        Status::Fail => format!("\x1b[31m{s}\x1b[0m"),
        Status::Info => format!("\x1b[90m{s}\x1b[0m"),
    }
}

fn relative_ts(ts: u64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ago = now.saturating_sub(ts);
    if ago == 0 {
        "just now".into()
    } else if ago < 60 {
        format!("{ago}s ago")
    } else if ago < 3600 {
        format!("{}m ago", ago / 60)
    } else if ago < 86400 {
        format!("{}h ago", ago / 3600)
    } else {
        format!("{}d ago", ago / 86400)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn gotcha_rec(
        key: &str,
        confirmed: bool,
        affected_files: Vec<String>,
        quality: f32,
        lifecycle: mati_core::store::RecordLifecycle,
    ) -> mati_core::store::Record {
        use mati_core::store::{
            Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, Record, RecordSource,
            RecordVersion, StalenessScore,
        };
        let gotcha = GotchaRecord {
            rule: "r".into(),
            reason: "because x".into(),
            severity: Priority::Normal,
            affected_files,
            ref_url: None,
            discovered_session: 0,
            confirmed,
            confirmed_content: Default::default(),
        };
        Record {
            key: key.into(),
            value: "r".into(),
            category: Category::Gotcha,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle,
            version: RecordVersion {
                device_id: uuid::Uuid::nil(),
                logical_clock: 1,
                wall_clock: 0,
            },
            quality: QualityScore {
                value: quality,
                tier: QualityScore::tier_from_value(quality),
                signals: vec![],
                computed_at: 0,
            },
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
            gap_analysis_score: 0.0,
            payload: serde_json::to_value(&gotcha).ok(),
        }
    }

    #[test]
    fn gating_counts_flags_confirmed_gotchas_with_no_files() {
        use mati_core::store::RecordLifecycle::Active;
        let tombstoned = mati_core::store::RecordLifecycle::Tombstoned {
            reason: mati_core::store::TombstoneReason::ManualDeletion,
            at: 0,
        };
        let records = vec![
            // confirmed + has file + quality >= 0.4 → counted, gates
            gotcha_rec("gotcha:a", true, vec!["src/a.rs".into()], 0.6, Active),
            // confirmed + no file → counted AND ungated (the residual)
            gotcha_rec("gotcha:b", true, vec![], 0.6, Active),
            // unconfirmed stub + no file → not counted at all
            gotcha_rec("gotcha:cochange:x|y", false, vec![], 0.6, Active),
            // tombstoned confirmed + no file → excluded by lifecycle
            gotcha_rec("gotcha:c", true, vec![], 0.6, tombstoned),
        ];
        let (confirmed, ungated, inert) = gating_counts(&records);
        assert_eq!(confirmed, 2, "only active confirmed gotchas count");
        assert_eq!(ungated, 1, "only the confirmed file-less one is ungated");
        assert_eq!(inert, 0, "no low-quality file-naming gotcha here");
    }

    #[test]
    fn gating_counts_flags_low_quality_file_naming_gotchas_as_inert() {
        use mati_core::store::RecordLifecycle::Active;
        let records = vec![
            // confirmed + files + quality < 0.4 → inert (not injected, cannot gate)
            gotcha_rec("gotcha:a", true, vec!["src/a.rs".into()], 0.30, Active),
            // confirmed + files + quality >= 0.4 → gates, not a residual
            gotcha_rec("gotcha:b", true, vec!["src/b.rs".into()], 0.60, Active),
            // confirmed + no files + quality >= 0.4 → ungated, not inert
            gotcha_rec("gotcha:c", true, vec![], 0.60, Active),
            // confirmed + no files + quality < 0.4 → inert (quality checked
            // first: not injected, so not an "advisory" ungated record)
            gotcha_rec("gotcha:d", true, vec![], 0.30, Active),
        ];
        let (confirmed, ungated, inert) = gating_counts(&records);
        assert_eq!(confirmed, 4);
        assert_eq!(ungated, 1, "only the q>=0.4 file-less one is ungated");
        assert_eq!(inert, 2, "both q<0.4 records are inert, files or not");
    }

    #[test]
    fn gating_counts_empty_store_is_zero() {
        assert_eq!(gating_counts(&[]), (0, 0, 0));
    }

    #[test]
    fn read_lifecycle_tail_parses_well_formed_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lifecycle.log"),
            "100\t111\tserve_start\tpid=111 owner=mcp\n\
             200\t111\tserve_shutdown\tclean\n",
        )
        .unwrap();
        let entries = read_lifecycle_tail(dir.path(), 5);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ts, 100);
        assert_eq!(entries[0].event, "serve_start");
        assert_eq!(entries[1].detail, "clean");
    }

    #[test]
    fn read_lifecycle_tail_returns_last_n_only() {
        let dir = tempfile::tempdir().unwrap();
        let body: String = (0..10)
            .map(|i| format!("{i}\t{i}\tevent{i}\tdetail{i}\n"))
            .collect();
        std::fs::write(dir.path().join("lifecycle.log"), body).unwrap();
        let entries = read_lifecycle_tail(dir.path(), 3);
        assert_eq!(entries.len(), 3);
        // Last three: 7, 8, 9
        assert_eq!(entries[0].ts, 7);
        assert_eq!(entries[2].ts, 9);
    }

    #[test]
    fn read_lifecycle_tail_skips_malformed_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lifecycle.log"),
            "100\t111\tserve_start\tok\n\
             not\ta\tvalid\n\
             200\t111\tserve_shutdown\tclean\n",
        )
        .unwrap();
        let entries = read_lifecycle_tail(dir.path(), 5);
        // Malformed line has only 3 tab-separated fields → skipped.
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn read_lifecycle_tail_returns_empty_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let entries = read_lifecycle_tail(dir.path(), 5);
        assert!(entries.is_empty());
    }

    /// End-to-end round trip: events written by the canonical writer
    /// (`mcp::metadata::record_lifecycle_event`) must parse back through the
    /// doctor reader without losing fields. The other reader-side tests use
    /// hand-rolled fixture strings — if the writer's column layout, separator,
    /// or escaping ever drifts, those tests would still pass while doctor's
    /// "Lifecycle (last N events)" panel silently goes blank in the field.
    /// Pass 24 caught this exact pattern in `fail_open.log`; this test guards
    /// the lifecycle.log surface against the same class of regression.
    #[test]
    fn lifecycle_log_round_trip_writer_reader() {
        use mati_core::mcp::metadata::record_lifecycle_event;
        let dir = tempfile::tempdir().unwrap();
        // Three events through the real writer — including a payload with
        // tabs/newlines so we cover the writer's escaping path.
        record_lifecycle_event(dir.path(), "serve_start", "owner=mcp");
        record_lifecycle_event(dir.path(), "panic", "boom\twith\ttabs\nand newline");
        record_lifecycle_event(dir.path(), "serve_shutdown", "reason=signal");

        let entries = read_lifecycle_tail(dir.path(), 5);
        assert_eq!(
            entries.len(),
            3,
            "doctor reader must parse all 3 writer-emitted lines, got {}",
            entries.len()
        );
        assert_eq!(entries[0].event, "serve_start");
        assert_eq!(entries[0].detail, "owner=mcp");
        assert_eq!(entries[1].event, "panic");
        // Writer replaces tabs/newlines with spaces so each event stays one line.
        assert!(
            !entries[1].detail.contains('\t') && !entries[1].detail.contains('\n'),
            "writer must scrub tabs/newlines; reader saw: {:?}",
            entries[1].detail
        );
        assert!(
            entries[1].detail.contains("boom") && entries[1].detail.contains("tabs"),
            "writer must preserve detail content (modulo separator scrubbing); got {:?}",
            entries[1].detail
        );
        assert_eq!(entries[2].event, "serve_shutdown");
        assert_eq!(entries[2].detail, "reason=signal");
        // Timestamps are real Unix seconds — must be non-zero, monotonic.
        assert!(entries[0].ts > 0, "writer must emit a real Unix timestamp");
        assert!(
            entries[0].ts <= entries[2].ts,
            "timestamps must be monotonic"
        );
        // PID must round-trip as the current process id.
        let pid = std::process::id();
        for e in &entries {
            assert_eq!(e.pid, pid, "writer→reader pid round-trip must be stable");
        }
    }

    // ── binary parity ───────────────────────────────────────────────────

    fn fake_wrapper(cwd: &Path, version: &str) {
        let dir = cwd.join(".claude/hooks");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mati");
        std::fs::write(&path, format!("#!/bin/sh\necho 'mati {version}'\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    /// A wrapper in the real `exec "<bin>" "$@"` shape, pointing at `target`.
    fn fake_wrapper_execing(cwd: &Path, target: &Path) {
        let dir = cwd.join(".claude/hooks");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mati");
        std::fs::write(
            &path,
            format!(
                "#!/usr/bin/env bash\nexec \"{}\" \"$@\"\n",
                target.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    /// Two builds of one version compare equal on the version string, so the
    /// daemon keeps serving the old code while hooks exec the new one. The
    /// recorded build hash is what separates them.
    #[test]
    fn binary_parity_names_a_same_version_build_skew() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("mati-bin");
        std::fs::write(&target, "#!/bin/sh\necho 'mati 0.1.4'\n").unwrap();
        fake_wrapper_execing(dir.path(), &target);
        fake_daemon(dir.path(), "0.1.4");
        // The daemon started from a different build of the same version.
        let mut meta = mati_core::mcp::metadata::read_metadata(dir.path()).unwrap();
        meta.build = "0".repeat(64);
        mati_core::mcp::metadata::publish_metadata(dir.path(), &meta).unwrap();

        let result = collect_binary_parity_check(dir.path(), dir.path());
        assert!(matches!(result.status, Status::Warn), "{}", result.detail);
        assert!(
            result.detail.contains("different builds"),
            "must name the skew, got: {}",
            result.detail
        );
    }

    /// Same version AND same build is the only clean state.
    #[test]
    fn binary_parity_passes_when_the_build_matches() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("mati-bin");
        std::fs::write(&target, "#!/bin/sh\necho 'mati 0.1.4'\n").unwrap();
        fake_wrapper_execing(dir.path(), &target);
        fake_daemon(dir.path(), "0.1.4");
        let mut meta = mati_core::mcp::metadata::read_metadata(dir.path()).unwrap();
        meta.build = mati_core::mcp::metadata::build_id_of(&target).unwrap();
        mati_core::mcp::metadata::publish_metadata(dir.path(), &meta).unwrap();

        let result = collect_binary_parity_check(dir.path(), dir.path());
        assert!(matches!(result.status, Status::Pass), "{}", result.detail);
    }

    fn fake_daemon(root: &Path, version: &str) {
        let mut meta = mati_core::mcp::metadata::DaemonMetadata::new(
            mati_core::mcp::metadata::DaemonOwner::Daemon,
        );
        meta.version = version.to_string();
        mati_core::mcp::metadata::publish_metadata(root, &meta).unwrap();
    }

    /// The hook binary and the daemon binary resolve independently, and a skew
    /// between them degrades enforcement *silently* — hooks fail open on a
    /// protocol mismatch. Nothing used to compare them.
    #[test]
    fn binary_parity_names_a_version_skew() {
        let dir = tempfile::tempdir().unwrap();
        fake_wrapper(dir.path(), "0.1.3");
        fake_daemon(dir.path(), "0.2.0");

        let result = collect_binary_parity_check(dir.path(), dir.path());
        assert!(matches!(result.status, Status::Warn));
        assert!(result.detail.contains("0.1.3"), "{}", result.detail);
        assert!(result.detail.contains("0.2.0"), "{}", result.detail);
    }

    #[test]
    fn binary_parity_passes_when_they_agree() {
        let dir = tempfile::tempdir().unwrap();
        fake_wrapper(dir.path(), "0.1.3");
        fake_daemon(dir.path(), "0.1.3");

        let result = collect_binary_parity_check(dir.path(), dir.path());
        assert!(matches!(result.status, Status::Pass), "{}", result.detail);
    }

    /// A project with no hooks installed is not a mismatch.
    #[test]
    fn binary_parity_is_informational_without_a_wrapper() {
        let dir = tempfile::tempdir().unwrap();
        let result = collect_binary_parity_check(dir.path(), dir.path());
        assert!(matches!(result.status, Status::Info));
    }

    /// A `mati.pid` from a binary predating the version field must still parse.
    #[test]
    fn metadata_without_a_version_still_reads() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("mati.pid"),
            r#"{"pid":42,"session":"00000000-0000-0000-0000-000000000000","owner":"daemon"}"#,
        )
        .unwrap();
        let meta = mati_core::mcp::metadata::read_metadata(dir.path()).expect("must parse");
        assert_eq!(meta.pid, 42);
        assert!(meta.version.is_empty());
    }

    /// Schema-stability invariant for `mati doctor --json`:
    /// every scenario (no-daemon-no-store, no-daemon-with-store,
    /// daemon-running, daemon-unresponsive, store-open-failed) must emit
    /// the five `enforcement/*` probes first, then exactly one `daemon/ping`
    /// check followed by `integrity/dirty_marker` then `integrity/drift`, in
    /// that order. CI consumers parse the report by name and by index, and a
    /// `version: 2` schema must keep both stable.
    ///
    /// `attestation/network` holds index 13, `enforcement/policy` index 14, and
    /// `enforcement/binary parity` index 15. `enforcement/seal` appends at 17.
    /// Policy was added later (75bec3a) and originally landed before `network`,
    /// which pushed a published index. New checks append at the end so an
    /// index a consumer already relies on never moves.
    ///
    /// This is a hermetic test: it drives `collect()` against a tempdir
    /// with no daemon and no `knowledge.db`, exercising the no-store
    /// branch. The other branches are exercised by the smoke tests in
    /// audit pass 18; their schema parity is guaranteed by code review of
    /// the single match arm in `collect()` that always pushes
    /// `dirty_marker` before `drift`.
    #[tokio::test]
    async fn doctor_json_shape_is_stable_across_scenarios() {
        let dir = tempfile::tempdir().unwrap();
        // No `knowledge.db` here — exercises the "no store" branch.
        let report = collect(dir.path(), dir.path()).await;
        let names: Vec<(&str, &str)> = report.checks.iter().map(|c| (c.section, c.name)).collect();
        assert_eq!(
            names,
            vec![
                ("enforcement", "git_repo"),
                ("enforcement", "mati_on_path"),
                ("enforcement", "awk_float_math"),
                ("enforcement", "agent_host"),
                ("enforcement", "claude_hooks"),
                ("enforcement", "claude_config"),
                ("enforcement", "codex_hooks"),
                ("enforcement", "codex_config"),
                ("daemon", "ping"),
                ("integrity", "dirty_marker"),
                ("integrity", "drift"),
                ("integrity", "chain"),
                ("knowledge", "freshness"),
                ("attestation", "network"),
                ("enforcement", "policy"),
                ("enforcement", "binary parity"),
                ("knowledge", "gating"),
                ("enforcement", "seal"),
            ],
            "doctor JSON check sequence must be the enforcement probes \
             (git_repo → mati_on_path → awk_float_math → agent_host → \
             claude_hooks → claude_config → codex_hooks → codex_config) then \
             ping → dirty_marker → drift → chain → freshness → network → policy \
             → binary parity → gating → seal (new checks append at the end so an \
             index a consumer already relies on never moves)"
        );
        assert_eq!(report.version, 2);
    }

    /// A manifest row whose file is gone strands the seal: the mode is lost
    /// with the inode, so the row can only be dropped, never restored.
    #[tokio::test]
    async fn seal_row_warns_when_a_sealed_file_is_gone() {
        let repo = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        // Written as JSON, not through `write_manifest`, so the test reads the
        // manifest the same way doctor does — off disk, in its on-disk form.
        std::fs::write(
            mati_core::seal::manifest_in(root.path()),
            serde_json::json!({
                "files": [{
                    "path": repo.path().join("gone.rs").to_string_lossy(),
                    "mode": "644",
                }]
            })
            .to_string(),
        )
        .unwrap();

        let r = collect_seal_check(repo.path(), root.path()).await;
        assert!(matches!(r.status, Status::Warn), "detail: {}", r.detail);
        assert!(r.detail.contains("gone from disk"), "detail: {}", r.detail);
        assert!(r.fix.unwrap().contains("mati seal remove"));
    }

    #[tokio::test]
    async fn seal_row_is_info_when_nothing_is_sealed() {
        let dir = tempfile::tempdir().unwrap();
        let r = collect_seal_check(dir.path(), dir.path()).await;
        assert!(matches!(r.status, Status::Info));
        assert_eq!(r.detail, "no files sealed");
    }

    fn summary(total: usize, drift: usize) -> crate::cli::stale::StaleSummary {
        crate::cli::stale::StaleSummary {
            total,
            stale: total,
            liability: 0,
            tombstone: 0,
            drift,
        }
    }

    /// Drift alone must not render as a zero count. The general Warn arm used
    /// to print "0 stale record(s) (0 stale, 0 liability, 0 tombstone)" above
    /// a real drift finding, and pointed at `mati reparse`, which cannot clear
    /// drift.
    #[test]
    fn freshness_reports_drift_without_claiming_a_zero_stale_count() {
        let r = freshness_result(Some(summary(0, 1)));
        assert!(matches!(r.status, Status::Warn));
        assert!(
            !r.detail.contains("0 stale record(s)"),
            "detail was: {}",
            r.detail
        );
        assert!(r
            .detail
            .contains("1 confirmed gotcha(s) describe changed code"));
        assert!(r.fix.unwrap().contains("gotcha confirm"));
    }

    /// The clean and the stale-records paths are unchanged by the new arm.
    #[test]
    fn freshness_keeps_its_other_verdicts() {
        let clean = freshness_result(Some(summary(0, 0)));
        assert!(matches!(clean.status, Status::Pass));
        assert_eq!(clean.detail, "no stale records");

        let stale = freshness_result(Some(summary(3, 0)));
        assert!(matches!(stale.status, Status::Warn));
        assert!(stale.detail.contains("3 stale record(s)"));

        assert!(matches!(freshness_result(None).status, Status::Info));
    }
    /// Content drift rides on the existing `knowledge/freshness` detail rather
    /// than adding a check, so the `--json` array stays index-stable and does
    /// not collide with `integrity/drift`, which means derived-index drift.
    #[test]
    fn drift_detail_is_appended_only_when_there_is_drift() {
        assert_eq!(drift_detail(0), "");
        assert_eq!(
            drift_detail(3),
            "; 3 confirmed gotcha(s) describe changed code"
        );
    }
}
