use std::io::{self, IsTerminal};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::Args;
use serde::{Deserialize, Serialize};

use mati_core::health::{gaps, onboarding};
use mati_core::store::{
    Category, ConfidenceScore, FileRecord, Priority, QualityScore, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore, Store,
};

use super::colors;
use super::proxy::StoreProxy;

#[derive(Args)]
pub struct StatsArgs {}

/// Daily aggregation record value — mirrors `DailyAgg` in hooks.rs.
#[derive(Deserialize)]
struct DailyAgg {
    count: u64,
    #[allow(dead_code)]
    keys: Vec<String>,
}

/// Stable cache key for the health snapshot (write-seq invalidated, no date suffix).
const SNAPSHOT_KEY: &str = "analytics:knowledge_health";

/// Maximum age of a cached snapshot even if write-seq matches (catches stale
/// compliance data when no knowledge writes have happened for >24 h).
const SNAPSHOT_MAX_AGE_SECS: u64 = 86_400;

/// Snapshot payload written to `analytics:knowledge_health`.
#[derive(Serialize, Deserialize)]
struct HealthSnapshot {
    // Coverage
    files_with_purpose: u32,
    total_files: u32,
    purpose_coverage: f32,
    gotchas_per_hotspot: f32,
    decisions_documented: u32,
    avg_confidence: f32,
    knowledge_gaps: u32,

    // Velocity (30d)
    new_records_30d: u32,
    multi_contributor_records: u32,

    // Onboarding
    estimated_minutes: f32,
    critical_files_covered: f32,
    gotcha_coverage: f32,
    decision_coverage: f32,

    // Onboarding detail (added for cache display — backward compat via default)
    #[serde(default)]
    critical_uncovered: u32,
    #[serde(default)]
    orphaned_decisions: u32,
    #[serde(default)]
    low_confidence: u32,

    // Compliance (7d)
    hits_7d: u64,
    misses_7d: u64,
    hit_rate_7d: f32,
    bypasses_7d: u64,

    computed_at: u64,

    /// Knowledge write-sequence at time of computation. Cache is valid when
    /// this equals [`Store::read_write_seq()`]. `0` means no valid cache.
    #[serde(default)]
    write_seq: u64,
}

/// Current wall-clock time as Unix seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub async fn run(_args: StatsArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = StoreProxy::open(&cwd).await?;

    // ── Cache check: reuse snapshot when write-seq unchanged ──────────────
    let now = now_secs();
    let current_seq = store.read_write_seq();
    if let Ok(Some(cached)) = store.get(SNAPSHOT_KEY).await {
        if let Some(snapshot) = cached.payload_as::<HealthSnapshot>() {
            let age = now.saturating_sub(snapshot.computed_at);
            if snapshot.write_seq == current_seq && age < SNAPSHOT_MAX_AGE_SECS {
                display_cached_stats(&snapshot, age, &cwd);
                store.close().await?;
                return Ok(());
            }
        }
        // Stale or corrupt cache — fall through to recomputation
    }

    let use_color = io::stdout().is_terminal();

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

    // ── Scan all namespaces (once — results are reused by gaps + onboarding) ──

    let (mut files, mut gotchas, mut decisions, mut notes, deps) = tokio::try_join!(
        store.scan_prefix("file:"),
        store.scan_prefix("gotcha:"),
        store.scan_prefix("decision:"),
        store.scan_prefix("dev_note:"),
        store.scan_prefix("dep:"),
    )?;
    files.retain(|r| matches!(r.lifecycle, RecordLifecycle::Active));
    gotchas.retain(|r| matches!(r.lifecycle, RecordLifecycle::Active));
    decisions.retain(|r| matches!(r.lifecycle, RecordLifecycle::Active));
    notes.retain(|r| matches!(r.lifecycle, RecordLifecycle::Active));

    // ── Project name ───────────────────────────────────────────────────────────

    let project = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    println!("\n{bold}{blue}◈ mati stats{reset} — project: {bold}{white}{project}{reset}\n");

    // ════════════════════════════════════════════════════════════════════════════
    // 1. Coverage
    // ════════════════════════════════════════════════════════════════════════════

    println!("  {bold}{blue}Coverage{reset}");

    // Files with purpose
    let file_data: Vec<FileRecord> = files
        .iter()
        .filter_map(|r| r.payload_as::<FileRecord>())
        .collect();

    let files_with_purpose = file_data.iter().filter(|fr| !fr.purpose.is_empty()).count() as u32;
    let total_files = files.len() as u32;
    let purpose_pct = if total_files > 0 {
        files_with_purpose as f32 / total_files as f32 * 100.0
    } else {
        0.0
    };
    let purpose_color = if purpose_pct >= 60.0 { green } else { yellow };
    println!(
        "    Files with purpose     {purpose_color}{files_with_purpose}{reset} / {white}{total_files}{reset}  ({purpose_pct:.0}%)"
    );

    // Gotchas per hotspot file
    let hotspot_count = file_data.iter().filter(|fr| fr.is_hotspot).count();
    let gotchas_per_hotspot = if hotspot_count > 0 {
        gotchas.len() as f32 / hotspot_count as f32
    } else {
        0.0
    };
    let gph_color = if gotchas_per_hotspot >= 2.0 {
        green
    } else {
        yellow
    };
    println!(
        "    Gotchas per hotspot    {gph_color}{gotchas_per_hotspot:.1}{reset}  (target >= 2.0)"
    );

    // Decisions documented
    let decisions_count = decisions.len() as u32;
    let dec_color = if decisions_count > 0 { green } else { yellow };
    println!("    Decisions documented   {dec_color}{decisions_count}{reset}");

    // Avg confidence score across gotcha + decision records
    let knowledge_records: Vec<&Record> = gotchas.iter().chain(decisions.iter()).collect();
    let avg_confidence = if knowledge_records.is_empty() {
        0.0
    } else {
        let sum: f32 = knowledge_records.iter().map(|r| r.confidence.value).sum();
        sum / knowledge_records.len() as f32
    };
    let conf_color = if avg_confidence >= 0.6 { green } else { yellow };
    if knowledge_records.is_empty() {
        println!("    Avg confidence         {gray}—  (no gotchas or decisions yet){reset}");
    } else {
        println!(
            "    Avg confidence         {conf_color}{avg_confidence:.2}{reset}  {gray}(gotchas + decisions, n={}){reset}",
            knowledge_records.len()
        );
    }

    // Knowledge gaps — pass pre-loaded records, no redundant scans.
    // Empty fan_in: stats skips graph load for speed; HighFanInNoContract
    // gaps appear in `mati gaps` which loads the full graph.
    let gap_list = gaps::analyze(
        &files,
        &gotchas,
        &decisions,
        &deps,
        &std::collections::HashMap::new(),
    );
    let gap_count = gap_list.len() as u32;
    let gap_color = if gap_count == 0 { green } else { yellow };
    println!("    Knowledge gaps         {gap_color}{gap_count}{reset}");

    println!();

    // ════════════════════════════════════════════════════════════════════════════
    // 2. Knowledge velocity (30d)
    // ════════════════════════════════════════════════════════════════════════════

    println!("  {bold}{blue}Knowledge velocity (30d){reset}");

    let thirty_days_ago = now.saturating_sub(30 * 86400);

    // New records added in last 30 days (across all knowledge namespaces)
    let all_records: Vec<&Record> = files
        .iter()
        .chain(gotchas.iter())
        .chain(decisions.iter())
        .chain(notes.iter())
        .chain(deps.iter())
        .collect();

    let new_records_30d = all_records
        .iter()
        .filter(|r| r.created_at >= thirty_days_ago)
        .count() as u32;
    let vel_color = if new_records_30d > 0 { green } else { yellow };
    println!("    New records added      {vel_color}{new_records_30d}{reset}");

    // Records confirmed by 2+ devs
    let multi_contributor = all_records
        .iter()
        .filter(|r| r.confidence.contributor_count >= 2)
        .count() as u32;
    let mc_color = if multi_contributor > 0 { green } else { yellow };
    println!("    Confirmed by 2+ devs  {mc_color}{multi_contributor}{reset}");

    println!();

    // ════════════════════════════════════════════════════════════════════════════
    // 3. Onboarding readiness
    // ════════════════════════════════════════════════════════════════════════════

    println!("  {bold}{blue}Onboarding readiness{reset}");

    let onboarding_score = onboarding::compute_from_records(&files, &decisions, &gotchas);

    let min_color = if onboarding_score.estimated_minutes <= 10.0 {
        green
    } else {
        yellow
    };
    println!(
        "    Estimated onboarding   {min_color}{:.0} min{reset}",
        onboarding_score.estimated_minutes
    );

    // Critical files uncovered: hotspots with empty purpose
    let critical_uncovered = file_data
        .iter()
        .filter(|fr| fr.is_hotspot && fr.purpose.is_empty())
        .count();
    let cu_color = if critical_uncovered == 0 {
        green
    } else {
        yellow
    };
    println!("    Critical files uncov.  {cu_color}{critical_uncovered}{reset}");

    // Orphaned decisions (from gaps)
    let orphaned_decisions = gap_list
        .iter()
        .filter(|g| g.gap_type == mati_core::store::GapType::OrphanedDecision)
        .count();
    let od_color = if orphaned_decisions == 0 {
        green
    } else {
        yellow
    };
    println!("    Orphaned decisions     {od_color}{orphaned_decisions}{reset}");

    // Low-confidence records (confidence < 0.3)
    let low_confidence = all_records
        .iter()
        .filter(|r| r.confidence.value < 0.3)
        .count();
    let lc_color = if low_confidence == 0 { green } else { yellow };
    println!("    Low-confidence (<0.3)  {lc_color}{low_confidence}{reset}");

    println!();

    // ════════════════════════════════════════════════════════════════════════════
    // 4. Compliance (last 7 days)
    // ════════════════════════════════════════════════════════════════════════════

    println!("  {bold}{blue}Compliance (7d){reset}");

    let (hits_7d, misses_7d, bypasses_7d) = scan_compliance_7d(&store, now).await;

    let total_lookups = hits_7d + misses_7d;
    let hit_rate = if total_lookups > 0 {
        hits_7d as f32 / total_lookups as f32 * 100.0
    } else {
        0.0
    };

    if total_lookups > 0 {
        let hr_color = if hit_rate >= 80.0 { green } else { yellow };
        println!(
            "    Hit rate               {hr_color}{hit_rate:.0}%{reset}  ({white}{hits_7d}{reset} hits / {white}{total_lookups}{reset} lookups)"
        );
    } else {
        println!("    Hit rate               {gray}\u{2014}{reset}  (no hook data yet)");
    }

    let bp_color = if bypasses_7d == 0 { green } else { yellow };
    if bypasses_7d > 0 || total_lookups > 0 {
        println!("    Bypasses               {bp_color}{bypasses_7d}{reset}");
    } else {
        println!("    Bypasses               {gray}\u{2014}{reset}");
    }

    // Daemon-unreachable events from fail_open.log
    let fail_open = scan_fail_open_log(now);
    if fail_open.count_7d > 0 {
        let ago = format_ago(fail_open.last_ago_secs);
        println!(
            "    Daemon unreachable     {red}{}{reset}  {gray}(last: {ago} ago){reset}",
            fail_open.count_7d
        );
    }

    println!();

    // ════════════════════════════════════════════════════════════════════════════
    // 5. Write health snapshot (M-10-H)
    // ════════════════════════════════════════════════════════════════════════════

    let snapshot = HealthSnapshot {
        files_with_purpose,
        total_files,
        purpose_coverage: if total_files > 0 {
            files_with_purpose as f32 / total_files as f32
        } else {
            0.0
        },
        gotchas_per_hotspot,
        decisions_documented: decisions_count,
        avg_confidence,
        knowledge_gaps: gap_count,

        new_records_30d,
        multi_contributor_records: multi_contributor,

        estimated_minutes: onboarding_score.estimated_minutes,
        critical_files_covered: onboarding_score.critical_files_covered,
        gotcha_coverage: onboarding_score.gotcha_coverage,
        decision_coverage: onboarding_score.decision_coverage,

        critical_uncovered: critical_uncovered as u32,
        orphaned_decisions: orphaned_decisions as u32,
        low_confidence: low_confidence as u32,

        hits_7d,
        misses_7d,
        hit_rate_7d: if total_lookups > 0 {
            hits_7d as f32 / total_lookups as f32
        } else {
            0.0
        },
        bypasses_7d,

        computed_at: now,
        write_seq: current_seq,
    };

    write_snapshot_record(&store, &snapshot, now).await?;

    println!("  {gray}Snapshot written: {SNAPSHOT_KEY}{reset}");

    // ── Review backlog ────────────────────────────────────────────────
    let unconfirmed: Vec<&mati_core::store::Record> = gotchas
        .iter()
        .filter(|r| {
            r.payload
                .as_ref()
                .and_then(|p| p.get("confirmed"))
                .and_then(|v| v.as_bool())
                == Some(false)
        })
        .collect();

    if !unconfirmed.is_empty() {
        let oldest_created = unconfirmed
            .iter()
            .map(|r| r.created_at)
            .min()
            .unwrap_or(now);
        let oldest_days = (now.saturating_sub(oldest_created)) / 86400;
        let confirmed_total = gotchas.len() - unconfirmed.len();
        let confirmation_rate = if gotchas.is_empty() {
            0
        } else {
            (confirmed_total as f32 / gotchas.len() as f32 * 100.0) as u32
        };

        println!();
        println!("  {bold}{blue}Review backlog{reset}");

        let age_color = if oldest_days > 14 { yellow } else { white };
        println!(
            "    Pending            {yellow}{}{reset}",
            unconfirmed.len()
        );
        println!(
            "    Confirmation rate  {white}{confirmation_rate}%{reset}  {gray}({confirmed_total}/{} gotchas){reset}",
            gotchas.len()
        );
        println!("    Oldest pending     {age_color}{oldest_days}d{reset}");
    }

    println!();

    store.close().await?;
    Ok(())
}

// ── Snapshot persistence ──────────────────────────────────────────────────────

/// Write a `HealthSnapshot` to the stable `SNAPSHOT_KEY` via proxy.
async fn write_snapshot_record(
    store: &StoreProxy,
    snapshot: &HealthSnapshot,
    now: u64,
) -> Result<()> {
    let record = Record {
        key: SNAPSHOT_KEY.to_string(),
        value: String::new(),
        payload: serde_json::to_value(snapshot).ok(),
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

/// Compute and persist a `HealthSnapshot` from pre-loaded record slices.
///
/// Called by `mati init` after `put_batch` so that the very first `mati stats`
/// after initialization is served from cache (O(1)) rather than rescanning.
pub async fn seed_snapshot(
    store: &Store,
    files: &[Record],
    gotchas: &[Record],
    decisions: &[Record],
    deps: &[Record],
    now: u64,
) -> Result<()> {
    use mati_core::health::onboarding;
    use mati_core::store::FileRecord;

    let file_data: Vec<FileRecord> = files
        .iter()
        .filter_map(|r| r.payload_as::<FileRecord>())
        .collect();

    let files_with_purpose = file_data.iter().filter(|fr| !fr.purpose.is_empty()).count() as u32;
    let total_files = files.len() as u32;
    let hotspot_count = file_data.iter().filter(|fr| fr.is_hotspot).count();
    let gotchas_per_hotspot = if hotspot_count > 0 {
        gotchas.len() as f32 / hotspot_count as f32
    } else {
        0.0
    };
    let decisions_count = decisions.len() as u32;

    let all_knowledge: Vec<&Record> = gotchas.iter().chain(decisions.iter()).collect();
    let avg_confidence = if all_knowledge.is_empty() {
        0.0
    } else {
        let sum: f32 = all_knowledge.iter().map(|r| r.confidence.value).sum();
        sum / all_knowledge.len() as f32
    };

    // Skip gaps analysis during init — it adds ~1200ms to cold init.
    // The first `mati gaps` run computes and caches gaps independently.
    // Stats display treats 0 as "not yet computed" (no line shown).
    let gap_count = 0u32;

    let thirty_days_ago = now.saturating_sub(30 * 86400);
    let all_records: Vec<&Record> = files
        .iter()
        .chain(gotchas.iter())
        .chain(decisions.iter())
        .chain(deps.iter())
        .collect();
    let new_records_30d = all_records
        .iter()
        .filter(|r| r.created_at >= thirty_days_ago)
        .count() as u32;
    let multi_contributor = all_records
        .iter()
        .filter(|r| r.confidence.contributor_count >= 2)
        .count() as u32;

    let onboarding_score = onboarding::compute_from_records(files, decisions, gotchas);

    let critical_uncovered = file_data
        .iter()
        .filter(|fr| fr.is_hotspot && fr.purpose.is_empty())
        .count() as u32;
    let orphaned_decisions = 0u32; // computed by mati gaps, not seeded here
    let low_confidence = all_records
        .iter()
        .filter(|r| r.confidence.value < 0.3)
        .count() as u32;

    let write_seq = store.read_write_seq();
    let snapshot = HealthSnapshot {
        files_with_purpose,
        total_files,
        purpose_coverage: if total_files > 0 {
            files_with_purpose as f32 / total_files as f32
        } else {
            0.0
        },
        gotchas_per_hotspot,
        decisions_documented: decisions_count,
        avg_confidence,
        knowledge_gaps: gap_count,
        new_records_30d,
        multi_contributor_records: multi_contributor,
        estimated_minutes: onboarding_score.estimated_minutes,
        critical_files_covered: onboarding_score.critical_files_covered,
        gotcha_coverage: onboarding_score.gotcha_coverage,
        decision_coverage: onboarding_score.decision_coverage,
        critical_uncovered,
        orphaned_decisions,
        low_confidence,
        hits_7d: 0,
        misses_7d: 0,
        hit_rate_7d: 0.0,
        bypasses_7d: 0,
        computed_at: now,
        write_seq,
    };

    write_snapshot_record_direct(store, &snapshot, now).await
}

/// Write a `HealthSnapshot` to the stable `SNAPSHOT_KEY` via direct Store.
async fn write_snapshot_record_direct(
    store: &Store,
    snapshot: &HealthSnapshot,
    now: u64,
) -> Result<()> {
    let record = Record {
        key: SNAPSHOT_KEY.to_string(),
        value: String::new(),
        payload: serde_json::to_value(snapshot).ok(),
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

// ── Cached display ───────────────────────────────────────────────────────────

/// Render the stats dashboard from a cached `HealthSnapshot`.
///
/// Output is identical to the live computation path except for a small
/// "(cached Ns ago)" annotation after the header.
fn display_cached_stats(s: &HealthSnapshot, age: u64, cwd: &std::path::Path) {
    let use_color = io::stdout().is_terminal();

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
        "\n{bold}{blue}◈ mati stats{reset} — project: {bold}{white}{project}{reset}  {gray}(cached {age}s ago){reset}\n"
    );

    // ── Coverage ─────────────────────────────────────────────────────────

    println!("  {bold}{blue}Coverage{reset}");

    let purpose_pct = if s.total_files > 0 {
        s.files_with_purpose as f32 / s.total_files as f32 * 100.0
    } else {
        0.0
    };
    let purpose_color = if purpose_pct >= 60.0 { green } else { yellow };
    println!(
        "    Files with purpose     {purpose_color}{}{reset} / {white}{}{reset}  ({purpose_pct:.0}%)",
        s.files_with_purpose, s.total_files
    );

    let gph_color = if s.gotchas_per_hotspot >= 2.0 {
        green
    } else {
        yellow
    };
    println!(
        "    Gotchas per hotspot    {gph_color}{:.1}{reset}  (target >= 2.0)",
        s.gotchas_per_hotspot
    );

    let dec_color = if s.decisions_documented > 0 {
        green
    } else {
        yellow
    };
    println!(
        "    Decisions documented   {dec_color}{}{reset}",
        s.decisions_documented
    );

    let conf_color = if s.avg_confidence >= 0.6 {
        green
    } else {
        yellow
    };
    if s.avg_confidence == 0.0 && s.decisions_documented == 0 {
        println!("    Avg confidence         {gray}—  (no gotchas or decisions yet){reset}");
    } else {
        println!(
            "    Avg confidence         {conf_color}{:.2}{reset}  {gray}(gotchas + decisions){reset}",
            s.avg_confidence
        );
    }

    let gap_color = if s.knowledge_gaps == 0 { green } else { yellow };
    println!(
        "    Knowledge gaps         {gap_color}{}{reset}",
        s.knowledge_gaps
    );

    println!();

    // ── Knowledge velocity ───────────────────────────────────────────────

    println!("  {bold}{blue}Knowledge velocity (30d){reset}");

    let vel_color = if s.new_records_30d > 0 { green } else { yellow };
    println!(
        "    New records added      {vel_color}{}{reset}",
        s.new_records_30d
    );

    let mc_color = if s.multi_contributor_records > 0 {
        green
    } else {
        yellow
    };
    println!(
        "    Confirmed by 2+ devs  {mc_color}{}{reset}",
        s.multi_contributor_records
    );

    println!();

    // ── Onboarding readiness ─────────────────────────────────────────────

    println!("  {bold}{blue}Onboarding readiness{reset}");

    let min_color = if s.estimated_minutes <= 10.0 {
        green
    } else {
        yellow
    };
    println!(
        "    Estimated onboarding   {min_color}{:.0} min{reset}",
        s.estimated_minutes
    );

    let cu_color = if s.critical_uncovered == 0 {
        green
    } else {
        yellow
    };
    println!(
        "    Critical files uncov.  {cu_color}{}{reset}",
        s.critical_uncovered
    );

    let od_color = if s.orphaned_decisions == 0 {
        green
    } else {
        yellow
    };
    println!(
        "    Orphaned decisions     {od_color}{}{reset}",
        s.orphaned_decisions
    );

    let lc_color = if s.low_confidence == 0 { green } else { yellow };
    println!(
        "    Low-confidence (<0.3)  {lc_color}{}{reset}",
        s.low_confidence
    );

    println!();

    // ── Compliance ───────────────────────────────────────────────────────

    println!("  {bold}{blue}Compliance (7d){reset}");

    let total_lookups = s.hits_7d + s.misses_7d;
    let hit_rate = if total_lookups > 0 {
        s.hits_7d as f32 / total_lookups as f32 * 100.0
    } else {
        0.0
    };

    if total_lookups > 0 {
        let hr_color = if hit_rate >= 80.0 { green } else { yellow };
        println!(
            "    Hit rate               {hr_color}{hit_rate:.0}%{reset}  ({white}{}{reset} hits / {white}{total_lookups}{reset} lookups)",
            s.hits_7d
        );
    } else {
        println!("    Hit rate               {gray}\u{2014}{reset}  (no hook data yet)");
    }

    let bp_color = if s.bypasses_7d == 0 { green } else { yellow };
    if s.bypasses_7d > 0 || total_lookups > 0 {
        println!(
            "    Bypasses               {bp_color}{}{reset}",
            s.bypasses_7d
        );
    } else {
        println!("    Bypasses               {gray}\u{2014}{reset}");
    }

    // Daemon-unreachable events from fail_open.log (always live, not cached)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let fail_open = scan_fail_open_log(now);
    if fail_open.count_7d > 0 {
        let ago = format_ago(fail_open.last_ago_secs);
        println!(
            "    Daemon unreachable     {red}{}{reset}  {gray}(last: {ago} ago){reset}",
            fail_open.count_7d
        );
    }

    println!();
}

// ── Compliance scanning helpers ──────────────────────────────────────────────

/// Scan analytics:hit_*, analytics:miss_*, and compliance:miss_* for the last
/// 7 days and return (total_hits, total_misses, total_bypasses).
async fn scan_compliance_7d(store: &StoreProxy, now: u64) -> (u64, u64, u64) {
    let mut hits: u64 = 0;
    let mut misses: u64 = 0;
    let mut bypasses: u64 = 0;

    // Generate date keys for the last 7 days
    for day_offset in 0..7 {
        let day_ts = now.saturating_sub(day_offset * 86400);
        let date = format_snapshot_date(day_ts);

        let hit_key = format!("analytics:hit_{date}");
        let miss_key = format!("analytics:miss_{date}");
        let bypass_key = format!("compliance:miss_{date}");

        if let Ok(Some(record)) = store.get(&hit_key).await {
            if let Some(agg) = record.payload_as::<DailyAgg>() {
                hits += agg.count;
            }
        }

        if let Ok(Some(record)) = store.get(&miss_key).await {
            if let Some(agg) = record.payload_as::<DailyAgg>() {
                misses += agg.count;
            }
        }

        if let Ok(Some(record)) = store.get(&bypass_key).await {
            if let Some(agg) = record.payload_as::<DailyAgg>() {
                bypasses += agg.count;
            }
        }
    }

    (hits, misses, bypasses)
}

/// Format a Unix timestamp as `YYYY-MM-DD` for snapshot keys.
fn format_snapshot_date(ts: u64) -> String {
    let days = ts / 86400;
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Result of scanning `~/.mati/fail_open.log` for daemon-unreachable events.
struct FailOpenStats {
    /// Number of FAIL_OPEN events in the last 7 days.
    count_7d: u64,
    /// Seconds since the most recent event (0 = no events).
    last_ago_secs: u64,
}

/// Scan `~/.mati/fail_open.log` for FAIL_OPEN entries in the last 7 days.
fn scan_fail_open_log(now: u64) -> FailOpenStats {
    let log_path = match dirs::home_dir() {
        Some(h) => h.join(".mati").join("fail_open.log"),
        None => return FailOpenStats { count_7d: 0, last_ago_secs: 0 },
    };

    let content = match std::fs::read_to_string(&log_path) {
        Ok(c) => c,
        Err(_) => return FailOpenStats { count_7d: 0, last_ago_secs: 0 },
    };

    let cutoff = now.saturating_sub(7 * 86400);
    let mut count: u64 = 0;
    let mut latest_ts: u64 = 0;

    for line in content.lines() {
        if !line.contains("FAIL_OPEN") {
            continue;
        }
        // Parse ISO 8601 timestamp from the start of the line:
        // "2026-04-02T14:30:00Z FAIL_OPEN hook=..."
        let ts_str = match line.split_whitespace().next() {
            Some(s) => s,
            None => continue,
        };
        let ts = parse_iso_timestamp(ts_str);
        if ts == 0 {
            continue;
        }
        if ts >= cutoff {
            count += 1;
        }
        if ts > latest_ts {
            latest_ts = ts;
        }
    }

    let last_ago = if latest_ts > 0 {
        now.saturating_sub(latest_ts)
    } else {
        0
    };

    FailOpenStats { count_7d: count, last_ago_secs: last_ago }
}

/// Minimal ISO 8601 timestamp parser: `YYYY-MM-DDTHH:MM:SSZ` -> Unix seconds.
fn parse_iso_timestamp(s: &str) -> u64 {
    // Expected format: 2026-04-02T14:30:00Z (exactly 20 chars)
    if s.len() < 19 {
        return 0;
    }
    let b = s.as_bytes();
    let year = parse_u64(&s[0..4]);
    let month = parse_u64(&s[5..7]);
    let day = parse_u64(&s[8..10]);
    let hour = parse_u64(&s[11..13]);
    let min = parse_u64(&s[14..16]);
    let sec = parse_u64(&s[17..19]);
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return 0;
    }
    // Convert to Unix timestamp (simplified, assumes UTC)
    let days = civil_to_days(year, month, sec, day);
    days * 86400 + hour * 3600 + min * 60 + sec
}

fn parse_u64(s: &str) -> u64 {
    s.parse::<u64>().unwrap_or(0)
}

/// Convert civil date to days since epoch (same algorithm as format_snapshot_date inverse).
fn civil_to_days(y: u64, m: u64, _sec: u64, d: u64) -> u64 {
    let y = y as i64;
    let m = m as u64;
    let (y, m) = if m <= 2 {
        (y - 1, m + 9)
    } else {
        (y, m - 3)
    };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe as i64 - 719_468) as u64
}

/// Format seconds-ago as a human-readable delta: "3m", "2h", "1d".
fn format_ago(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_snapshot_date_epoch() {
        assert_eq!(format_snapshot_date(0), "1970-01-01");
    }

    #[test]
    fn format_snapshot_date_known() {
        // 2024-01-15
        assert_eq!(format_snapshot_date(19737 * 86400), "2024-01-15");
    }

    #[test]
    fn format_snapshot_date_leap_day() {
        // 2024-02-29
        assert_eq!(format_snapshot_date(19782 * 86400), "2024-02-29");
    }

    #[test]
    fn daily_agg_deserializes() {
        let json = r#"{"count": 5, "keys": ["file:a.rs", "file:b.rs"]}"#;
        let agg: DailyAgg = serde_json::from_str(json).unwrap();
        assert_eq!(agg.count, 5);
        assert_eq!(agg.keys.len(), 2);
    }

    /// Helper to build a fully-populated snapshot for tests.
    fn sample_snapshot() -> HealthSnapshot {
        HealthSnapshot {
            files_with_purpose: 10,
            total_files: 20,
            purpose_coverage: 0.5,
            gotchas_per_hotspot: 1.5,
            decisions_documented: 3,
            avg_confidence: 0.45,
            knowledge_gaps: 7,
            new_records_30d: 15,
            multi_contributor_records: 2,
            estimated_minutes: 16.5,
            critical_files_covered: 0.6,
            gotcha_coverage: 0.3,
            decision_coverage: 1.0,
            critical_uncovered: 4,
            orphaned_decisions: 1,
            low_confidence: 3,
            hits_7d: 42,
            misses_7d: 8,
            hit_rate_7d: 0.84,
            bypasses_7d: 1,
            computed_at: 1_710_520_800,
            write_seq: 42,
        }
    }

    #[test]
    fn health_snapshot_serializes() {
        let snapshot = sample_snapshot();
        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["files_with_purpose"], 10);
        assert_eq!(parsed["total_files"], 20);
        assert!((parsed["purpose_coverage"].as_f64().unwrap() - 0.5).abs() < 0.01);
        assert_eq!(parsed["knowledge_gaps"], 7);
        assert_eq!(parsed["hits_7d"], 42);
        assert_eq!(parsed["bypasses_7d"], 1);
        assert_eq!(parsed["critical_uncovered"], 4);
        assert_eq!(parsed["orphaned_decisions"], 1);
        assert_eq!(parsed["low_confidence"], 3);
    }

    #[test]
    fn health_snapshot_roundtrips() {
        let snapshot = sample_snapshot();
        let json = serde_json::to_string(&snapshot).unwrap();
        let deserialized: HealthSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.files_with_purpose, snapshot.files_with_purpose);
        assert_eq!(deserialized.total_files, snapshot.total_files);
        assert_eq!(
            deserialized.decisions_documented,
            snapshot.decisions_documented
        );
        assert_eq!(deserialized.knowledge_gaps, snapshot.knowledge_gaps);
        assert_eq!(deserialized.new_records_30d, snapshot.new_records_30d);
        assert_eq!(
            deserialized.multi_contributor_records,
            snapshot.multi_contributor_records
        );
        assert_eq!(deserialized.critical_uncovered, snapshot.critical_uncovered);
        assert_eq!(deserialized.orphaned_decisions, snapshot.orphaned_decisions);
        assert_eq!(deserialized.low_confidence, snapshot.low_confidence);
        assert_eq!(deserialized.hits_7d, snapshot.hits_7d);
        assert_eq!(deserialized.misses_7d, snapshot.misses_7d);
        assert_eq!(deserialized.bypasses_7d, snapshot.bypasses_7d);
        assert_eq!(deserialized.computed_at, snapshot.computed_at);
        assert!((deserialized.avg_confidence - snapshot.avg_confidence).abs() < 0.001);
        assert!((deserialized.estimated_minutes - snapshot.estimated_minutes).abs() < 0.01);
    }

    #[test]
    fn health_snapshot_backward_compat_missing_new_fields() {
        // Simulates an old snapshot that was written before
        // critical_uncovered / orphaned_decisions / low_confidence existed.
        let old_json = r#"{
            "files_with_purpose": 5,
            "total_files": 10,
            "purpose_coverage": 0.5,
            "gotchas_per_hotspot": 2.0,
            "decisions_documented": 1,
            "avg_confidence": 0.7,
            "knowledge_gaps": 2,
            "new_records_30d": 8,
            "multi_contributor_records": 0,
            "estimated_minutes": 12.0,
            "critical_files_covered": 0.8,
            "gotcha_coverage": 0.5,
            "decision_coverage": 1.0,
            "hits_7d": 20,
            "misses_7d": 5,
            "hit_rate_7d": 0.8,
            "bypasses_7d": 0,
            "computed_at": 1710000000
        }"#;
        let snapshot: HealthSnapshot = serde_json::from_str(old_json).unwrap();
        // New fields default to 0
        assert_eq!(snapshot.critical_uncovered, 0);
        assert_eq!(snapshot.orphaned_decisions, 0);
        assert_eq!(snapshot.low_confidence, 0);
        // Existing fields parse correctly
        assert_eq!(snapshot.files_with_purpose, 5);
        assert_eq!(snapshot.total_files, 10);
        assert_eq!(snapshot.hits_7d, 20);
    }
}
