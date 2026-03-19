use std::io::{self, IsTerminal};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::Args;
use serde::{Deserialize, Serialize};

use mati_core::health::{gaps, onboarding};
use mati_core::store::{
    Category, ConfidenceScore, FileRecord, Record, RecordLifecycle, RecordSource,
    RecordVersion, StalenessScore, Store, Priority, QualityScore,
};

use super::colors;

#[derive(Args)]
pub struct StatsArgs {}

/// Daily aggregation record value — mirrors `DailyAgg` in hooks.rs.
#[derive(Deserialize)]
struct DailyAgg {
    count: u64,
    #[allow(dead_code)]
    keys: Vec<String>,
}

/// Snapshot payload written to `analytics:knowledge_health_<date>`.
#[derive(Serialize)]
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

    // Compliance (7d)
    hits_7d: u64,
    misses_7d: u64,
    hit_rate_7d: f32,
    bypasses_7d: u64,

    computed_at: u64,
}

pub async fn run(_args: StatsArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    let use_color = io::stdout().is_terminal();

    let (blue, green, yellow, gray, white, bold, reset) = if use_color {
        (
            colors::BLUE,
            colors::GREEN,
            colors::YELLOW,
            colors::GRAY,
            colors::WHITE,
            colors::BOLD,
            colors::RESET,
        )
    } else {
        ("", "", "", "", "", "", "")
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // ── Scan all namespaces ────────────────────────────────────────────────────

    let files = store.scan_prefix("file:").await?;
    let gotchas = store.scan_prefix("gotcha:").await?;
    let decisions = store.scan_prefix("decision:").await?;
    let notes = store.scan_prefix("dev_note:").await?;
    let deps = store.scan_prefix("dep:").await?;

    // ── Project name ───────────────────────────────────────────────────────────

    let project = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    println!(
        "\n{bold}{blue}◈ mati stats{reset} — project: {bold}{white}{project}{reset}\n"
    );

    // ════════════════════════════════════════════════════════════════════════════
    // 1. Coverage
    // ════════════════════════════════════════════════════════════════════════════

    println!("  {bold}{blue}Coverage{reset}");

    // Files with purpose
    let file_data: Vec<FileRecord> = files
        .iter()
        .filter_map(|r| serde_json::from_str(&r.value).ok())
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
    let gph_color = if gotchas_per_hotspot >= 2.0 { green } else { yellow };
    println!(
        "    Gotchas per hotspot    {gph_color}{gotchas_per_hotspot:.1}{reset}  (target >= 2.0)"
    );

    // Decisions documented
    let decisions_count = decisions.len() as u32;
    let dec_color = if decisions_count > 0 { green } else { yellow };
    println!(
        "    Decisions documented   {dec_color}{decisions_count}{reset}"
    );

    // Avg confidence score across gotcha + decision records
    let knowledge_records: Vec<&Record> = gotchas.iter().chain(decisions.iter()).collect();
    let avg_confidence = if knowledge_records.is_empty() {
        0.0
    } else {
        let sum: f32 = knowledge_records.iter().map(|r| r.confidence.value).sum();
        sum / knowledge_records.len() as f32
    };
    let conf_color = if avg_confidence >= 0.6 { green } else { yellow };
    println!(
        "    Avg confidence         {conf_color}{avg_confidence:.2}{reset}"
    );

    // Knowledge gaps
    let gap_list = gaps::analyze(&store).await?;
    let gap_count = gap_list.len() as u32;
    let gap_color = if gap_count == 0 { green } else { yellow };
    println!(
        "    Knowledge gaps         {gap_color}{gap_count}{reset}"
    );

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
    println!(
        "    New records added      {vel_color}{new_records_30d}{reset}"
    );

    // Records confirmed by 2+ devs
    let multi_contributor = all_records
        .iter()
        .filter(|r| r.confidence.contributor_count >= 2)
        .count() as u32;
    let mc_color = if multi_contributor > 0 { green } else { yellow };
    println!(
        "    Confirmed by 2+ devs  {mc_color}{multi_contributor}{reset}"
    );

    println!();

    // ════════════════════════════════════════════════════════════════════════════
    // 3. Onboarding readiness
    // ════════════════════════════════════════════════════════════════════════════

    println!("  {bold}{blue}Onboarding readiness{reset}");

    let onboarding_score = onboarding::compute(&store).await?;

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
    let cu_color = if critical_uncovered == 0 { green } else { yellow };
    println!(
        "    Critical files uncov.  {cu_color}{critical_uncovered}{reset}"
    );

    // Orphaned decisions (from gaps)
    let orphaned_decisions = gap_list
        .iter()
        .filter(|g| g.gap_type == mati_core::store::GapType::OrphanedDecision)
        .count();
    let od_color = if orphaned_decisions == 0 { green } else { yellow };
    println!(
        "    Orphaned decisions     {od_color}{orphaned_decisions}{reset}"
    );

    // Low-confidence records (confidence < 0.3)
    let low_confidence = all_records
        .iter()
        .filter(|r| r.confidence.value < 0.3)
        .count();
    let lc_color = if low_confidence == 0 { green } else { yellow };
    println!(
        "    Low-confidence (<0.3)  {lc_color}{low_confidence}{reset}"
    );

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
        println!(
            "    Hit rate               {gray}\u{2014}{reset}  (no hook data yet)"
        );
    }

    let bp_color = if bypasses_7d == 0 { green } else { yellow };
    if bypasses_7d > 0 || total_lookups > 0 {
        println!(
            "    Bypasses               {bp_color}{bypasses_7d}{reset}"
        );
    } else {
        println!(
            "    Bypasses               {gray}\u{2014}{reset}"
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

        hits_7d,
        misses_7d,
        hit_rate_7d: if total_lookups > 0 {
            hits_7d as f32 / total_lookups as f32
        } else {
            0.0
        },
        bypasses_7d,

        computed_at: now,
    };

    let today = format_snapshot_date(now);
    let snapshot_key = format!("analytics:knowledge_health_{today}");
    let snapshot_value = serde_json::to_string(&snapshot)?;

    let device_id = uuid::Uuid::new_v4();
    let snapshot_record = Record {
        key: snapshot_key.clone(),
        value: snapshot_value,
        category: Category::Analytics,
        priority: Priority::Normal,
        tags: vec![],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id,
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

    store.put(&snapshot_key, &snapshot_record).await?;

    println!(
        "  {gray}Snapshot written: {snapshot_key}{reset}\n"
    );

    store.close().await?;
    Ok(())
}

// ── Compliance scanning helpers ──────────────────────────────────────────────

/// Scan analytics:hit_*, analytics:miss_*, and compliance:miss_* for the last
/// 7 days and return (total_hits, total_misses, total_bypasses).
async fn scan_compliance_7d(store: &Store, now: u64) -> (u64, u64, u64) {
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
            if let Ok(agg) = serde_json::from_str::<DailyAgg>(&record.value) {
                hits += agg.count;
            }
        }

        if let Ok(Some(record)) = store.get(&miss_key).await {
            if let Ok(agg) = serde_json::from_str::<DailyAgg>(&record.value) {
                misses += agg.count;
            }
        }

        if let Ok(Some(record)) = store.get(&bypass_key).await {
            if let Ok(agg) = serde_json::from_str::<DailyAgg>(&record.value) {
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

    #[test]
    fn health_snapshot_serializes() {
        let snapshot = HealthSnapshot {
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
            hits_7d: 42,
            misses_7d: 8,
            hit_rate_7d: 0.84,
            bypasses_7d: 1,
            computed_at: 1_710_520_800,
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["files_with_purpose"], 10);
        assert_eq!(parsed["total_files"], 20);
        assert!((parsed["purpose_coverage"].as_f64().unwrap() - 0.5).abs() < 0.01);
        assert_eq!(parsed["knowledge_gaps"], 7);
        assert_eq!(parsed["hits_7d"], 42);
        assert_eq!(parsed["bypasses_7d"], 1);
    }
}
