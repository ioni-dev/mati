use std::io::IsTerminal;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::Args;
use serde::{Deserialize, Serialize};

use mati_core::store::{
    Category, ConfidenceScore, FileRecord, GotchaRecord, Priority, QualityScore, QualityTier,
    Record, RecordLifecycle, RecordSource, RecordVersion, StalenessScore,
};

use super::colors;
use super::daemon::{daemon_result, mati_root_for, read_pid_file, DaemonResult};
use super::proxy::StoreProxy;

#[derive(Args)]
pub struct StatusArgs {}

/// Stable cache key for the status snapshot (write-seq invalidated).
const SNAPSHOT_KEY: &str = "analytics:status_cache";

/// Maximum age of a cached snapshot even if write-seq matches.
const SNAPSHOT_MAX_AGE_SECS: u64 = 86_400;

/// Snapshot payload written to `analytics:status_cache`.
#[derive(Serialize, Deserialize)]
struct StatusSnapshot {
    // Record counts
    files_count: usize,
    gotchas_count: usize,
    decisions_count: usize,
    notes_count: usize,
    deps_count: usize,

    // Confirmed gotchas
    confirmed_count: usize,

    // Quality distribution (gotchas + decisions + notes)
    excellent: u32,
    good: u32,
    acceptable: u32,
    poor: u32,
    suppressed: u32,
    quality_total: usize,

    // Confidence (files + gotchas + decisions + notes)
    avg_confidence: f32,
    median_confidence: f32,
    has_confidence: bool,

    // Hotspots
    hotspot_count: usize,

    // Cache metadata
    write_seq: u64,
    computed_at: u64,
}

/// Daemon health state for display purposes.
enum DaemonHealth {
    Running { pid: Option<u32> },
    Unresponsive { pid: Option<u32> },
    NotRunning,
}

/// Check daemon health without opening the store (reuses daemon socket logic).
async fn check_daemon_health(cwd: &std::path::Path) -> DaemonHealth {
    let root = match mati_root_for(cwd) {
        Ok(r) => r,
        Err(_) => return DaemonHealth::NotRunning,
    };

    match daemon_result(&root, "ping", serde_json::json!({})).await {
        DaemonResult::Ok(resp) if resp.get("ok") == Some(&serde_json::Value::Bool(true)) => {
            let pid = read_pid_file(&root).map(|(pid, _)| pid);
            DaemonHealth::Running { pid }
        }
        DaemonResult::Unresponsive => {
            let pid = read_pid_file(&root).map(|(pid, _)| pid);
            DaemonHealth::Unresponsive { pid }
        }
        _ => DaemonHealth::NotRunning,
    }
}

/// Print the Runtime section showing daemon health.
#[allow(clippy::too_many_arguments)]
fn print_runtime_section(
    health: &DaemonHealth,
    red: &str,
    green: &str,
    yellow: &str,
    gray: &str,
    _white: &str,
    blue: &str,
    reset: &str,
) {
    println!("  {blue}Runtime{reset}");
    match health {
        DaemonHealth::Running { pid } => {
            let pid_str = pid.map(|p| format!(" (pid {p})")).unwrap_or_default();
            println!("    Daemon               {green}running{reset}{pid_str}");
            println!("    Enforcement          {green}active{reset}");
        }
        DaemonHealth::Unresponsive { pid } => {
            let pid_str = pid.map(|p| format!(" (pid {p})")).unwrap_or_default();
            println!("    Daemon               {yellow}unresponsive{reset}{pid_str}");
            println!(
                "    Enforcement          {yellow}degraded{reset} {gray}— hooks fail open{reset}"
            );
        }
        DaemonHealth::NotRunning => {
            println!("    Daemon               {red}not running{reset}");
            println!(
                "    Enforcement          {red}degraded{reset} {gray}— hooks fail open without daemon{reset}"
            );
        }
    }
    println!();
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn daily_agg_count(record: Option<Record>) -> u64 {
    record
        .and_then(|r| r.payload_as::<mati_core::store::session::DailyAgg>())
        .map(|agg| agg.count)
        .unwrap_or(0)
}

#[derive(Default)]
struct CodexDailyMetrics {
    bootstrap_count: u64,
    shell_hit_count: u64,
    shell_miss_count: u64,
    prompt_nudge_count: u64,
}

impl CodexDailyMetrics {
    fn has_activity(&self) -> bool {
        self.bootstrap_count > 0
            || self.shell_hit_count > 0
            || self.shell_miss_count > 0
            || self.prompt_nudge_count > 0
    }
}

async fn load_codex_daily_metrics(store: &StoreProxy) -> Result<CodexDailyMetrics> {
    Ok(CodexDailyMetrics {
        bootstrap_count: daily_agg_count(
            store
                .get(&mati_core::store::session::today_key(
                    "analytics:bootstrap_",
                ))
                .await?,
        ),
        shell_hit_count: daily_agg_count(
            store
                .get(&mati_core::store::session::today_key(
                    "compliance:codex_shell_hit_",
                ))
                .await?,
        ),
        shell_miss_count: daily_agg_count(
            store
                .get(&mati_core::store::session::today_key(
                    "compliance:codex_shell_miss_",
                ))
                .await?,
        ),
        prompt_nudge_count: daily_agg_count(
            store
                .get(&mati_core::store::session::today_key(
                    "analytics:codex_prompt_nudge_",
                ))
                .await?,
        ),
    })
}

pub async fn run(_args: StatusArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = StoreProxy::open(&cwd).await?;
    let claude_mode = cwd.join(".claude/settings.json").exists();
    let codex_mode = cwd.join(".codex/config.toml").exists();
    let codex_metrics = if codex_mode {
        Some(load_codex_daily_metrics(&store).await?)
    } else {
        None
    };

    // ── Daemon health (real-time, never cached) ──────────────────────────
    let daemon_health = check_daemon_health(&cwd).await;

    // ── Cache check: reuse snapshot when write-seq unchanged ──────────────
    let now = now_secs();
    let current_seq = store.read_write_seq();
    if let Some(cached) = store.get(SNAPSHOT_KEY).await? {
        if let Some(snap) = cached.payload_as::<StatusSnapshot>() {
            let age = now.saturating_sub(snap.computed_at);
            if snap.write_seq == current_seq && age < SNAPSHOT_MAX_AGE_SECS {
                display_cached_status(
                    &snap,
                    age,
                    &cwd,
                    claude_mode,
                    codex_mode,
                    codex_metrics.as_ref(),
                    &daemon_health,
                );
                store.close().await?;
                return Ok(());
            }
        }
    }

    let use_color = std::io::stdout().is_terminal();

    let (red, blue, green, yellow, gray, white, bold, reset) = if use_color {
        (
            colors::RED,
            colors::BLUE,
            colors::GREEN,
            colors::YELLOW,
            colors::GRAY,
            colors::WHITE,
            colors::BOLD,
            colors::RESET,
        )
    } else {
        ("", "", "", "", "", "", "", "")
    };

    // ── Scan all namespaces in parallel ───────────────────────────────────
    let (files, gotchas, decisions, notes, deps) = tokio::try_join!(
        store.scan_prefix("file:"),
        store.scan_prefix("gotcha:"),
        store.scan_prefix("decision:"),
        store.scan_prefix("dev_note:"),
        store.scan_prefix("dep:"),
    )?;

    // ── Project name from cwd ─────────────────────────────────────────────
    let project = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    println!("\n{bold}{blue}◈ mati status{reset} — project: {bold}{white}{project}{reset}\n");

    // ── Runtime (daemon health) ──────────────────────────────────────────
    if claude_mode || codex_mode {
        print_runtime_section(&daemon_health, red, green, yellow, gray, white, blue, reset);
    }

    if claude_mode || codex_mode {
        println!("  {blue}Platform{reset}");
        if claude_mode {
            println!("    Claude  — hard read enforcement");
        }
        if codex_mode {
            println!("    Codex   — hard Bash enforcement, soft native-read enforcement");
        }
        println!();
    }

    // ── Integrity warning ────────────────────────────────────────────────
    if let Ok(Some(marker_record)) = store.get(mati_core::store::repair::DIRTY_MARKER_KEY).await {
        if let Some(marker) = marker_record.payload_as::<mati_core::store::repair::DirtyMarker>() {
            if marker.dirty {
                println!(
                    "  {yellow}⚠ Index drift detected{reset} — {gray}{}{reset}",
                    marker.cause
                );
                println!(
                    "    {gray}Affected keys: {}. Run `mati repair` to reconcile.{reset}\n",
                    marker.affected_keys.len()
                );
            }
        }
    }

    if let Some(metrics) = codex_metrics.as_ref().filter(|m| m.has_activity()) {
        println!(
                "  {blue}Codex Today{reset}  bootstraps {white}{}{reset}  shell ok {white}{}{reset}  shell misses {white}{}{reset}  prompt nudges {white}{}{reset}\n",
                metrics.bootstrap_count,
                metrics.shell_hit_count,
                metrics.shell_miss_count,
                metrics.prompt_nudge_count,
            );
    }

    // ── Record counts ─────────────────────────────────────────────────────
    println!(
        "  {blue}Records{reset}     {white}{}{reset} files  {white}{}{reset} gotchas  {white}{}{reset} decisions  {white}{}{reset} notes  {white}{}{reset} deps",
        files.len(),
        gotchas.len(),
        decisions.len(),
        notes.len(),
        deps.len(),
    );

    // ── Confirmed count ───────────────────────────────────────────────────
    let confirmed_count = gotchas
        .iter()
        .filter(|r| {
            r.payload_as::<GotchaRecord>()
                .map(|gr| gr.confirmed)
                .unwrap_or(false)
        })
        .count();

    let total_gotchas = gotchas.len();
    let pct = if total_gotchas > 0 {
        (confirmed_count as f32 / total_gotchas as f32 * 100.0) as u32
    } else {
        0
    };
    println!(
        "  {blue}Confirmed{reset}    {green}{confirmed_count}{reset} / {total_gotchas} gotchas ({pct}%)"
    );

    // ── Quality distribution ──────────────────────────────────────────────
    let quality_records: Vec<&Record> = gotchas
        .iter()
        .chain(decisions.iter())
        .chain(notes.iter())
        .collect();

    let (mut excellent, mut good, mut acceptable, mut poor, mut suppressed) =
        (0u32, 0u32, 0u32, 0u32, 0u32);

    if !quality_records.is_empty() {
        for r in &quality_records {
            match r.quality.tier {
                QualityTier::Excellent => excellent += 1,
                QualityTier::Good => good += 1,
                QualityTier::Acceptable => acceptable += 1,
                QualityTier::Poor => poor += 1,
                QualityTier::Suppressed => suppressed += 1,
            }
        }

        let total = quality_records.len() as f32;
        println!("\n  {blue}Quality Distribution{reset}");
        print_bar("Excellent", excellent, total, green, white, reset);
        print_bar("Good", good, total, green, white, reset);
        print_bar("Acceptable", acceptable, total, yellow, white, reset);
        print_bar("Poor", poor, total, yellow, white, reset);
        print_bar("Suppressed", suppressed, total, gray, white, reset);
    }

    // ── Confidence summary ────────────────────────────────────────────────
    let all_knowledge: Vec<&Record> = files
        .iter()
        .chain(gotchas.iter())
        .chain(decisions.iter())
        .chain(notes.iter())
        .collect();

    let (avg_confidence, median_confidence, has_confidence) = if !all_knowledge.is_empty() {
        let mut conf_values: Vec<f32> = all_knowledge.iter().map(|r| r.confidence.value).collect();
        conf_values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let avg = conf_values.iter().sum::<f32>() / conf_values.len() as f32;
        let n = conf_values.len();
        let median = if n % 2 == 0 {
            (conf_values[n / 2 - 1] + conf_values[n / 2]) / 2.0
        } else {
            conf_values[n / 2]
        };
        println!(
            "\n  {blue}Confidence{reset}   avg {white}{avg:.2}{reset}  median {white}{median:.2}{reset}"
        );
        (avg, median, true)
    } else {
        (0.0, 0.0, false)
    };

    // ── Hotspots ──────────────────────────────────────────────────────────
    let hotspot_count = files
        .iter()
        .filter(|r| {
            r.payload_as::<FileRecord>()
                .map(|fr| fr.is_hotspot)
                .unwrap_or(false)
        })
        .count();

    let total_files = files.len();
    let hot_pct = if total_files > 0 {
        (hotspot_count as f32 / total_files as f32 * 100.0) as u32
    } else {
        0
    };
    println!(
        "  {blue}Hotspots{reset}     {white}{hotspot_count}{reset} / {total_files} ({hot_pct}%)"
    );

    // ── Trust health ─────────────────────────────────────────────────────
    let stale_count = gotchas
        .iter()
        .chain(decisions.iter())
        .filter(|r| {
            matches!(
                r.staleness.tier,
                mati_core::store::StalenessTier::Stale
                    | mati_core::store::StalenessTier::Liability
                    | mati_core::store::StalenessTier::Tombstone
            )
        })
        .count();
    let low_confidence_count = gotchas
        .iter()
        .chain(decisions.iter())
        .filter(|r| r.confidence.value < 0.3)
        .count();

    let unconfirmed = total_gotchas - confirmed_count;

    // Compute oldest unconfirmed age for backlog visibility
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let oldest_unconfirmed_days = gotchas
        .iter()
        .filter(|r| {
            r.payload_as::<GotchaRecord>()
                .map(|g| !g.confirmed)
                .unwrap_or(false)
        })
        .map(|r| (now.saturating_sub(r.created_at)) / 86400)
        .max()
        .unwrap_or(0);

    // Count unconfirmed candidates on hotspot files
    let unconfirmed_on_hotspots = gotchas
        .iter()
        .filter(|r| {
            r.payload_as::<GotchaRecord>()
                .map(|g| !g.confirmed)
                .unwrap_or(false)
        })
        .filter(|r| {
            r.payload_as::<GotchaRecord>()
                .map(|g| {
                    g.affected_files.iter().any(|af| {
                        files.iter().any(|f| {
                            f.key == format!("file:{af}")
                                && f.payload_as::<FileRecord>()
                                    .map(|fr| fr.is_hotspot)
                                    .unwrap_or(false)
                        })
                    })
                })
                .unwrap_or(false)
        })
        .count();

    let has_trust_issues = stale_count > 0 || low_confidence_count > 0 || unconfirmed > 0;

    if has_trust_issues {
        println!("\n  {blue}Trust{reset}");
        if unconfirmed > 0 {
            let mut detail_parts = Vec::new();
            if unconfirmed_on_hotspots > 0 {
                detail_parts.push(format!("{unconfirmed_on_hotspots} on hotspots"));
            }
            if oldest_unconfirmed_days > 0 {
                detail_parts.push(format!("oldest {oldest_unconfirmed_days}d"));
            }
            let detail = if detail_parts.is_empty() {
                String::new()
            } else {
                format!(" {gray}({}){reset}", detail_parts.join(", "))
            };
            println!(
                "    {yellow}{unconfirmed} unconfirmed{reset}{detail} {gray}— run `mati review`{reset}"
            );
        }
        if stale_count > 0 {
            println!(
                "    {yellow}{stale_count} stale{reset} {gray}— run `mati stale` to see which records need attention{reset}"
            );
        }
        if low_confidence_count > 0 {
            println!(
                "    {yellow}{low_confidence_count} low-confidence{reset} {gray}(<0.3) — may need enrichment or manual review{reset}"
            );
        }
    }

    // ── Workflow guidance ────────────────────────────────────────────────
    if total_gotchas == 0 {
        println!();
        println!("  {gray}No gotchas yet. Run `mati init` to scan for candidates.{reset}");
    }

    println!();

    // ── Write snapshot (best-effort) ──────────────────────────────────────
    let snap = StatusSnapshot {
        files_count: files.len(),
        gotchas_count: gotchas.len(),
        decisions_count: decisions.len(),
        notes_count: notes.len(),
        deps_count: deps.len(),
        confirmed_count,
        excellent,
        good,
        acceptable,
        poor,
        suppressed,
        quality_total: quality_records.len(),
        avg_confidence,
        median_confidence,
        has_confidence,
        hotspot_count,
        write_seq: current_seq,
        computed_at: now,
    };
    let _ = write_snapshot_record(&store, &snap, now).await;

    store.close().await?;
    Ok(())
}

/// Write a `StatusSnapshot` to `SNAPSHOT_KEY` via proxy.
async fn write_snapshot_record(store: &StoreProxy, snap: &StatusSnapshot, now: u64) -> Result<()> {
    let record = Record {
        key: SNAPSHOT_KEY.to_string(),
        value: String::new(),
        payload: serde_json::to_value(snap).ok(),
        category: Category::Analytics,
        priority: Priority::Normal,
        tags: vec![],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: now,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
    };
    store.put(SNAPSHOT_KEY, &record).await
}

/// Render status output from a cached snapshot.
fn display_cached_status(
    s: &StatusSnapshot,
    age: u64,
    cwd: &std::path::Path,
    claude_mode: bool,
    codex_mode: bool,
    codex_metrics: Option<&CodexDailyMetrics>,
    daemon_health: &DaemonHealth,
) {
    let use_color = std::io::stdout().is_terminal();

    let (red, blue, green, yellow, gray, white, bold, reset) = if use_color {
        (
            colors::RED,
            colors::BLUE,
            colors::GREEN,
            colors::YELLOW,
            colors::GRAY,
            colors::WHITE,
            colors::BOLD,
            colors::RESET,
        )
    } else {
        ("", "", "", "", "", "", "", "")
    };

    let project = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    println!(
        "\n{bold}{blue}◈ mati status{reset} — project: {bold}{white}{project}{reset}  {gray}(cached {}s ago){reset}\n",
        age
    );

    // ── Runtime (daemon health — always real-time, never cached) ─────────
    if claude_mode || codex_mode {
        print_runtime_section(daemon_health, red, green, yellow, gray, white, blue, reset);
    }

    if claude_mode || codex_mode {
        println!("  {blue}Platform{reset}");
        if claude_mode {
            println!("    Claude  — hard read enforcement");
        }
        if codex_mode {
            println!("    Codex   — hard Bash enforcement, soft native-read enforcement");
        }
        println!();
    }

    if let Some(metrics) = codex_metrics.filter(|m| m.has_activity()) {
        println!(
            "  {blue}Codex Today{reset}  bootstraps {white}{}{reset}  shell ok {white}{}{reset}  shell misses {white}{}{reset}  prompt nudges {white}{}{reset}\n",
            metrics.bootstrap_count,
            metrics.shell_hit_count,
            metrics.shell_miss_count,
            metrics.prompt_nudge_count,
        );
    }

    println!(
        "  {blue}Records{reset}     {white}{}{reset} files  {white}{}{reset} gotchas  {white}{}{reset} decisions  {white}{}{reset} notes  {white}{}{reset} deps",
        s.files_count, s.gotchas_count, s.decisions_count, s.notes_count, s.deps_count,
    );

    let pct = if s.gotchas_count > 0 {
        (s.confirmed_count as f32 / s.gotchas_count as f32 * 100.0) as u32
    } else {
        0
    };
    println!(
        "  {blue}Confirmed{reset}    {green}{}{reset} / {} gotchas ({pct}%)",
        s.confirmed_count, s.gotchas_count,
    );

    if s.quality_total > 0 {
        let total = s.quality_total as f32;
        println!("\n  {blue}Quality Distribution{reset}");
        print_bar("Excellent", s.excellent, total, green, white, reset);
        print_bar("Good", s.good, total, green, white, reset);
        print_bar("Acceptable", s.acceptable, total, yellow, white, reset);
        print_bar("Poor", s.poor, total, yellow, white, reset);
        print_bar("Suppressed", s.suppressed, total, gray, white, reset);
    }

    if s.has_confidence {
        println!(
            "\n  {blue}Confidence{reset}   avg {white}{:.2}{reset}  median {white}{:.2}{reset}",
            s.avg_confidence, s.median_confidence,
        );
    }

    let hot_pct = if s.files_count > 0 {
        (s.hotspot_count as f32 / s.files_count as f32 * 100.0) as u32
    } else {
        0
    };
    println!(
        "  {blue}Hotspots{reset}     {white}{}{reset} / {} ({hot_pct}%)",
        s.hotspot_count, s.files_count,
    );

    println!();
}

fn print_bar(label: &str, count: u32, total: f32, color: &str, white: &str, reset: &str) {
    if count == 0 {
        return;
    }
    let pct = (count as f32 / total * 100.0) as u32;
    let bar_width = (count as f32 / total * 20.0).ceil() as usize;
    let bar: String = "█".repeat(bar_width);
    println!(
        "    {:<12} {white}{:>3}{reset}  {color}{bar}{reset}  {pct}%",
        label, count
    );
}
