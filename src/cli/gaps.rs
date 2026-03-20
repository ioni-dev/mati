use std::io::IsTerminal;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::Args;
use serde::{Deserialize, Serialize};

use mati_core::health::gaps;
use mati_core::store::{
    Category, ConfidenceScore, KnowledgeGap, Priority, QualityScore, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore, Store,
};

use super::colors;

/// Wrapper around the cached gap list that includes write-seq for invalidation.
#[derive(Serialize, Deserialize)]
struct GapsCacheEntry {
    /// Knowledge write-sequence at cache time. `0` means no valid cache.
    write_seq: u64,
    gaps: Vec<KnowledgeGap>,
}

#[derive(Args)]
pub struct GapsArgs {
    /// Minimum risk score to include (0.0-1.0)
    #[arg(long, default_value = "0.3")]
    pub min_risk: f32,

    /// Maximum results to show
    #[arg(long, short = 'n', default_value = "20")]
    pub limit: usize,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cache_record(key: &str, value: String) -> Record {
    let now = now_secs();
    Record {
        key: key.to_string(),
        value,
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
        source: RecordSource::SessionHook,
        confidence: ConfidenceScore::for_new_record(&RecordSource::SessionHook),
        gap_analysis_score: 0.0,
    }
}

pub async fn run(args: GapsArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    let use_color = std::io::stdout().is_terminal();

    // ── Cache check: reuse when write-seq unchanged ───────────────────────
    let cache_key = "analytics:gaps_cache";
    let current_seq = store.read_write_seq();
    if let Ok(Some(cached)) = store.get(cache_key).await {
        if let Ok(entry) = serde_json::from_str::<GapsCacheEntry>(&cached.value) {
            let now = now_secs();
            let age = now.saturating_sub(cached.updated_at);
            if entry.write_seq == current_seq {
                let filtered: Vec<_> = entry.gaps
                    .into_iter()
                    .filter(|g| g.risk_score >= args.min_risk)
                    .take(args.limit)
                    .collect();
                display_gaps(&filtered, Some(age), use_color);
                store.close().await?;
                return Ok(());
            }
        }
    }

    // ── Compute gaps — scan once and pass pre-loaded records ─────────────
    let (files, gotchas, decisions, deps) = tokio::try_join!(
        store.scan_prefix("file:"),
        store.scan_prefix("gotcha:"),
        store.scan_prefix("decision:"),
        store.scan_prefix("dep:"),
    )?;
    let all_gaps = gaps::analyze(&files, &gotchas, &decisions, &deps);

    // ── Write cache (best-effort) ────────────────────────────────────────
    let cache_entry = GapsCacheEntry { write_seq: current_seq, gaps: all_gaps.clone() };
    if let Ok(cache_value) = serde_json::to_string(&cache_entry) {
        let record = cache_record(cache_key, cache_value);
        let _ = store.put(cache_key, &record).await;
    }

    let filtered: Vec<_> = all_gaps
        .into_iter()
        .filter(|g| g.risk_score >= args.min_risk)
        .take(args.limit)
        .collect();

    display_gaps(&filtered, None, use_color);
    store.close().await?;
    Ok(())
}

fn display_gaps(gaps: &[KnowledgeGap], cache_age: Option<u64>, use_color: bool) {
    let (red, yellow, blue, gray, bold, reset) = if use_color {
        (
            colors::RED,
            colors::YELLOW,
            colors::BLUE,
            colors::GRAY,
            colors::BOLD,
            colors::RESET,
        )
    } else {
        ("", "", "", "", "", "")
    };

    if gaps.is_empty() {
        println!("No knowledge gaps found.");
        return;
    }

    let cache_suffix = match cache_age {
        Some(n) => format!("  (cached {n}s ago)"),
        None => String::new(),
    };

    println!(
        "\n{bold}KNOWLEDGE GAPS{reset} -- {bold}{}{reset} found                 sorted by risk score{cache_suffix}\n",
        gaps.len()
    );

    for gap in gaps {
        let (tier_label, tier_color) = if gap.risk_score >= 0.7 {
            ("CRITICAL", red)
        } else if gap.risk_score >= 0.4 {
            ("HIGH", yellow)
        } else if gap.risk_score >= 0.2 {
            ("NORMAL", blue)
        } else {
            ("LOW", gray)
        };

        // Strip namespace prefix from the key for display (e.g. "file:src/main.rs" -> "src/main.rs")
        let display_key = gap.key.splitn(2, ':').nth(1).unwrap_or(&gap.key);

        println!(
            "{tier_color}{bold}\u{25cf} {tier_label:<9}{reset} {bold}{display_key}{reset}"
        );
        println!(
            "            {gray}{}{reset}",
            gap.description
        );
        println!(
            "            {gray}\u{2192} Action:{reset} {}\n",
            gap.action_hint
        );
    }
}
