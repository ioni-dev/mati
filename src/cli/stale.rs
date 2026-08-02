use std::io::IsTerminal;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::Args;
use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, Color, ContentArrangement, Table};
use serde::{Deserialize, Serialize};

use mati_core::health::drift::{current_content_hashes, detect_drift, DriftedGotcha};
use mati_core::store::{
    Category, ConfidenceScore, FileRecord, Priority, QualityScore, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore, StalenessSignal, StalenessTier, Store,
};

use super::proxy::StoreProxy;

use super::colors;
use super::show::{format_date, staleness_color, truncate};

/// Effective staleness: max of local and propagated. For file records,
/// this accounts for inherited staleness from upstream imports.
fn effective_staleness(record: &Record) -> f32 {
    let local = record.staleness.value;
    let propagated = record
        .payload_as::<FileRecord>()
        .and_then(|fr| fr.propagated_staleness)
        .map(|p| p.value)
        .unwrap_or(0.0);
    local.max(propagated)
}

// ── Cache ─────────────────────────────────────────────────────────────────────

const STALE_CACHE_KEY: &str = "analytics:stale_cache";

/// Write-seq–invalidated cache of the full stale record list.
/// Records are pre-sorted by staleness value descending; apply `--limit` at display time.
#[derive(Serialize, Deserialize)]
struct StaleCache {
    /// Knowledge write-seq at cache time. Cache is valid while this matches the store.
    write_seq: u64,
    records: Vec<Record>,
    /// Confirmed gotchas whose code changed since confirmation
    /// ([`mati_core::health::drift`]). Kept alongside `records` rather than
    /// inside it because a drifted gotcha is usually still `Fresh` — drift is
    /// about content moving, not about age — so it would never survive the
    /// tier filter above. `default` so a cache written by an older binary
    /// deserializes as "no drift known" instead of invalidating.
    #[serde(default)]
    drift: Vec<DriftedGotcha>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cache_record(value: String) -> Record {
    let now = now_secs();
    Record {
        key: STALE_CACHE_KEY.to_string(),
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
            device_id: mati_core::store::stable_device_id(),
            logical_clock: 1,
            wall_clock: now,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
        payload: None,
    }
}

/// Seed the stale cache from in-memory records immediately after `mati init`.
///
/// Called only on cold init (skipped_count == 0), where all records are freshly
/// written and their staleness tiers are accurate. On cold init the stale list
/// is always empty, so this writes a trivially small record that lets the very
/// first post-init `mati stale` hit the cache (O(1)).
pub async fn seed_stale_cache(store: &Store, records: &[Record]) -> Result<()> {
    let write_seq = store.read_write_seq();
    let mut stale: Vec<Record> = records
        .iter()
        .filter(|r| {
            matches!(
                r.staleness.tier,
                StalenessTier::Stale | StalenessTier::Liability | StalenessTier::Tombstone
            )
        })
        .cloned()
        .collect();
    stale.sort_by(|a, b| {
        effective_staleness(b)
            .partial_cmp(&effective_staleness(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    // Cold init rewrote every file record, so `records` carries the current
    // digest for every path. The gotchas do need a scan: a confirmed gotcha
    // written in an earlier session is not part of this run's output, and
    // seeding the cache without it would hide real drift behind a cache hit
    // until the next store write. One prefix scan on the cold path only.
    let gotchas = store.scan_prefix("gotcha:").await.unwrap_or_default();
    let drift = detect_drift(&gotchas, &current_content_hashes(records));
    let entry = StaleCache {
        write_seq,
        records: stale,
        drift,
    };
    let mut rec = cache_record(String::new());
    rec.payload = serde_json::to_value(&entry).ok();
    store.put(STALE_CACHE_KEY, &rec).await?;
    Ok(())
}

// ── Args ─────────────────────────────────────────────────────────────────────

// ── doctor freshness helper ───────────────────────────────────────────────────

/// Stale-record counts by tier — used by `mati doctor`'s freshness check.
pub(crate) struct StaleSummary {
    pub total: usize,
    pub stale: usize,
    pub liability: usize,
    pub tombstone: usize,
    /// Confirmed gotchas whose code changed since confirmation. Counted apart
    /// from `total` — drift is not a staleness tier and most drifted gotchas
    /// are not stale at all.
    pub drift: usize,
}

/// Read stale counts from the write-seq-validated cache. Returns `None` when no
/// valid cache exists (the caller treats that as "unknown — run `mati stale`").
/// Cheap: a single cache read, never a full scan.
pub(crate) async fn cached_stale_summary(proxy: &StoreProxy) -> Option<StaleSummary> {
    let current_seq = proxy.read_write_seq();
    let cached = proxy.get(STALE_CACHE_KEY).await.ok()??;
    let entry = cached.payload_as::<StaleCache>()?;
    if entry.write_seq != current_seq {
        return None;
    }
    let mut s = StaleSummary {
        total: entry.records.len(),
        stale: 0,
        liability: 0,
        tombstone: 0,
        drift: entry.drift.len(),
    };
    for r in &entry.records {
        match r.staleness.tier {
            StalenessTier::Stale => s.stale += 1,
            StalenessTier::Liability => s.liability += 1,
            StalenessTier::Tombstone => s.tombstone += 1,
            _ => {}
        }
    }
    Some(s)
}

// ── Args ─────────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct StaleArgs {
    /// Show full signal details and action hints per record
    #[arg(long, short = 'v')]
    pub verbose: bool,
    /// Maximum results to show
    #[arg(long, short = 'n', default_value = "50")]
    pub limit: usize,
}

// ── Main ─────────────────────────────────────────────────────────────────────

pub async fn run(args: StaleArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;

    // ── Cache check: reuse when write-seq unchanged ───────────────────────────
    let current_seq = proxy.read_write_seq();
    if let Some(cached) = proxy.get(STALE_CACHE_KEY).await? {
        if let Some(entry) = cached.payload_as::<StaleCache>() {
            if entry.write_seq == current_seq {
                let mut stale = entry.records;
                stale.truncate(args.limit);
                proxy.close().await?;
                display_stale(&stale, &entry.drift, args.verbose);
                return Ok(());
            }
        }
    }

    // ── Cache miss: scan all four prefixes concurrently ───────────────────────
    let (gotchas, decisions, files, notes) = tokio::try_join!(
        proxy.scan_prefix("gotcha:"),
        proxy.scan_prefix("decision:"),
        proxy.scan_prefix("file:"),
        proxy.scan_prefix("dev_note:"),
    )?;

    // Content drift, from the two scans already in hand — no extra store reads
    // and no hashing: `confirmed_content` was stamped at confirm time and
    // `content_hash` at the last `mati init`.
    let drift = detect_drift(&gotchas, &current_content_hashes(&files));

    let mut stale: Vec<Record> = gotchas
        .into_iter()
        .chain(decisions)
        .chain(files)
        .chain(notes)
        .filter(|r| {
            matches!(
                r.staleness.tier,
                StalenessTier::Stale | StalenessTier::Liability | StalenessTier::Tombstone
            )
        })
        .collect();

    // Sort by staleness descending
    stale.sort_by(|a, b| {
        effective_staleness(b)
            .partial_cmp(&effective_staleness(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Write cache (full sorted list, before limit)
    let cache_entry = StaleCache {
        write_seq: current_seq,
        records: stale.clone(),
        drift: drift.clone(),
    };
    let mut rec = cache_record(String::new());
    rec.payload = serde_json::to_value(&cache_entry).ok();
    let _ = proxy.put(STALE_CACHE_KEY, &rec).await;

    // Limit
    stale.truncate(args.limit);

    proxy.close().await?;
    display_stale(&stale, &drift, args.verbose);
    Ok(())
}

fn display_stale(stale: &[Record], drift: &[DriftedGotcha], verbose: bool) {
    if stale.is_empty() {
        if drift.is_empty() {
            println!("No stale records.");
            return;
        }
        // Drift is not a staleness tier, so it can be the only thing to report.
        println!("No stale records.\n");
        display_drift(drift, std::io::stdout().is_terminal());
        return;
    }

    let use_color = std::io::stdout().is_terminal();

    // ── Compact table ────────────────────────────────────────────────────────

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Key"),
            Cell::new("Score"),
            Cell::new("Tier"),
            Cell::new("Age"),
            Cell::new("Signals"),
            Cell::new("Impact"),
        ]);

    if !use_color {
        table.force_no_tty();
    }

    let now = now_secs();

    for r in stale {
        let age_days = if r.updated_at > 0 {
            (now.saturating_sub(r.updated_at)) / 86400
        } else {
            0
        };

        let tier_color = staleness_comfy_color(&r.staleness.tier);

        // Check for propagated staleness [P] marker
        let has_propagation = r
            .payload_as::<mati_core::store::FileRecord>()
            .and_then(|fr| fr.propagated_staleness)
            .is_some_and(|p| p.value > 0.0);
        let prop_marker = if has_propagation { " [P]" } else { "" };

        table.add_row(vec![
            Cell::new(format!("{}{prop_marker}", truncate(&r.key, 40))).fg(Color::White),
            Cell::new(format!("{:.2}", r.staleness.value)).fg(tier_color),
            Cell::new(tier_short_label(&r.staleness.tier)).fg(tier_color),
            Cell::new(format!("{age_days}d")).fg(Color::Grey),
            Cell::new(summarize_signals(&r.staleness.signals, 2)).fg(Color::Grey),
            Cell::new(impact_label(&r.staleness.tier)).fg(tier_color),
        ]);
    }

    println!("{table}");

    // ── Summary + action hints ───────────────────────────────────────────────

    let (red, yellow, gray, bold, reset) = if use_color {
        (
            colors::RED,
            colors::YELLOW,
            colors::GRAY,
            colors::BOLD,
            colors::RESET,
        )
    } else {
        ("", "", "", "", "")
    };

    let n_liability = stale
        .iter()
        .filter(|r| r.staleness.tier == StalenessTier::Liability)
        .count();
    let n_tombstone = stale
        .iter()
        .filter(|r| r.staleness.tier == StalenessTier::Tombstone)
        .count();
    let n_stale = stale
        .iter()
        .filter(|r| r.staleness.tier == StalenessTier::Stale)
        .count();

    let mut parts: Vec<String> = Vec::new();
    if n_tombstone > 0 {
        parts.push(format!("{red}{n_tombstone} tombstone{reset}"));
    }
    if n_liability > 0 {
        parts.push(format!("{red}{n_liability} liability{reset}"));
    }
    if n_stale > 0 {
        parts.push(format!("{yellow}{n_stale} stale{reset}"));
    }
    let breakdown = if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    };

    println!(
        "\n  {bold}{} stale records{reset}{breakdown}\n",
        stale.len()
    );

    let mut actions: Vec<String> = Vec::new();
    for r in stale {
        let hint = action_hint(r);
        if !actions.contains(&hint) {
            actions.push(hint);
        }
        if actions.len() >= 5 {
            break;
        }
    }

    if !actions.is_empty() {
        println!("  {gray}Suggested actions:{reset}");
        for a in &actions {
            println!("    {a}");
        }
        println!();
    }

    // ── Content drift ────────────────────────────────────────────────────────

    display_drift(drift, use_color);

    // ── Verbose per-record blocks ────────────────────────────────────────────

    if verbose {
        println!();
        for r in stale {
            let age_days = if r.updated_at > 0 {
                (now.saturating_sub(r.updated_at)) / 86400
            } else {
                0
            };
            let stc = if use_color {
                staleness_color(&r.staleness.tier)
            } else {
                ""
            };
            let tier_label = tier_short_label(&r.staleness.tier).to_uppercase();

            println!(
                "  {stc}{bold}\u{25cf} {tier_label:<11}{reset} {bold}{key}{reset}  {gray}age: {age_days}d{reset}",
                key = r.key
            );
            println!(
                "               {gray}Score: {:.2}  Updated: {}{reset}",
                r.staleness.value,
                format_date(r.updated_at),
            );

            if !r.staleness.signals.is_empty() {
                let full_sigs = summarize_signals(&r.staleness.signals, r.staleness.signals.len());
                println!("               {gray}Signals: {full_sigs}{reset}");
            }

            println!("               \u{2192} Action: {}\n", action_hint(r));
        }
    }
}

// ── Content drift ────────────────────────────────────────────────────────────

/// Render the confirmed gotchas whose code changed since confirmation.
///
/// A separate block rather than extra rows in the table above: these records
/// are usually `Fresh` — nothing about them is old — so they carry no tier,
/// no score, and no age worth printing. What they have is a specific claim,
/// which is why the third column is [`drift_impact_label`] rather than the
/// tier-derived [`impact_label`].
fn display_drift(drift: &[DriftedGotcha], use_color: bool) {
    if drift.is_empty() {
        return;
    }

    let (yellow, gray, bold, reset) = if use_color {
        (colors::YELLOW, colors::GRAY, colors::BOLD, colors::RESET)
    } else {
        ("", "", "", "")
    };

    let (noun, verb) = if drift.len() == 1 {
        ("gotcha", "describes")
    } else {
        ("gotchas", "describe")
    };
    println!(
        "  {yellow}{bold}\u{26a0} {n} confirmed {noun} {verb} code that has \
         changed since confirmation{reset}\n",
        n = drift.len(),
    );

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Key"),
            Cell::new("Changed since confirm"),
            Cell::new("Impact"),
        ]);
    if !use_color {
        table.force_no_tty();
    }

    for d in drift {
        table.add_row(vec![
            Cell::new(truncate(&d.key, 40)).fg(Color::White),
            Cell::new(summarize_drifted_files(&d.drifted_files, 2)).fg(Color::Yellow),
            Cell::new(drift_impact_label()).fg(Color::Yellow),
        ]);
    }

    println!("{table}");
    println!(
        "\n  {gray}Re-read the file, then re-confirm to clear: \
         mati gotcha confirm <key>{reset}\n"
    );
}

/// Join the drifted paths the same way [`summarize_signals`] joins signals.
fn summarize_drifted_files(files: &[String], max: usize) -> String {
    let mut result = files
        .iter()
        .take(max)
        .map(|f| truncate(f, 40))
        .collect::<Vec<_>>()
        .join(", ");
    if files.len() > max {
        result.push_str(&format!(" +{} more", files.len() - max));
    }
    result
}

/// Impact label for content drift — the sibling of [`impact_label`], which
/// only speaks tiers.
///
/// Deliberately says "may be wrong" and not "not enforced": a drifted gotcha
/// is still `confirmed`, still above the confidence and quality thresholds,
/// and still denies the read (ARCHITECTURE.md section 10.1). Drift is a
/// prompt to re-check the rule, never a reason to stop applying it.
fn drift_impact_label() -> &'static str {
    "rule may be wrong"
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Summarize staleness signals into a compact string.
/// Takes the first `max` signals and joins them with ", ".
/// Appends " +N more" if there are more signals than `max`.
fn summarize_signals(signals: &[StalenessSignal], max: usize) -> String {
    if signals.is_empty() {
        return String::new();
    }

    let labels: Vec<String> = signals.iter().take(max).map(signal_short_label).collect();
    let mut result = labels.join(", ");

    if signals.len() > max {
        result.push_str(&format!(" +{} more", signals.len() - max));
    }

    result
}

/// Map a single StalenessSignal to a short human-readable label.
fn signal_short_label(signal: &StalenessSignal) -> String {
    match signal {
        StalenessSignal::NotAccessedDays(n) => format!("unused {n}d"),
        StalenessSignal::EntryPointsChanged(n) => format!("{n} EP changed"),
        StalenessSignal::ImportsChanged(n) => format!("imports \u{00b1}{n}"),
        StalenessSignal::FileDeleted => "file deleted".to_string(),
        StalenessSignal::FileRenamed { .. } => "renamed".to_string(),
        StalenessSignal::LinkedFileChanged { .. } => "linked file changed".to_string(),
        StalenessSignal::TodosChanged => "TODOs changed".to_string(),
        StalenessSignal::UnsafeCountChanged(n) => format!("unsafe \u{00b1}{}", n.abs()),
        StalenessSignal::UnwrapCountChanged(n) => format!("unwrap \u{00b1}{}", n.abs()),
        StalenessSignal::DependencyBumped { dep, .. } => format!("dep:{dep} bumped"),
        StalenessSignal::LinesChangedPct(p) => format!("{:.0}% changed", p * 100.0),
        StalenessSignal::CascadeFromDecision(_) => "cascade".to_string(),
        StalenessSignal::GitCommitsSince(n) => format!("{n} commits"),
    }
}

/// Map a StalenessTier to a short impact label for the table.
fn impact_label(tier: &StalenessTier) -> &'static str {
    match tier {
        StalenessTier::Stale => "warn in bootstrap",
        StalenessTier::Liability => "blocks injection",
        StalenessTier::Tombstone => "excluded entirely",
        StalenessTier::Fresh | StalenessTier::Aging => "",
    }
}

/// Short tier label for the compact table (no extra description).
fn tier_short_label(tier: &StalenessTier) -> &'static str {
    match tier {
        StalenessTier::Fresh => "Fresh",
        StalenessTier::Aging => "Aging",
        StalenessTier::Stale => "Stale",
        StalenessTier::Liability => "Liability",
        StalenessTier::Tombstone => "Tombstone",
    }
}

/// Generate an action hint based on record category and staleness tier.
fn action_hint(record: &Record) -> String {
    match record.category {
        Category::Gotcha => format!("mati show {}", record.key),
        Category::File => {
            if record.staleness.tier == StalenessTier::Tombstone {
                let path = record.key.strip_prefix("file:").unwrap_or(&record.key);
                format!("file may be deleted \u{2014} verify: {path}")
            } else {
                let path = record.key.strip_prefix("file:").unwrap_or(&record.key);
                format!("mati reparse {path}")
            }
        }
        Category::Decision | Category::DevNote => format!("mati show {}", record.key),
        _ => format!("mati show {}", record.key),
    }
}

/// Map StalenessTier to comfy_table Color for table cells.
fn staleness_comfy_color(tier: &StalenessTier) -> Color {
    match tier {
        StalenessTier::Fresh | StalenessTier::Aging => Color::Green,
        StalenessTier::Stale => Color::Yellow,
        StalenessTier::Liability | StalenessTier::Tombstone => Color::Red,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mati_core::store::{
        ConfidenceScore, QualityScore, RecordLifecycle, RecordSource, RecordVersion, StalenessScore,
    };

    fn make_record(key: &str, category: Category, tier: StalenessTier) -> Record {
        Record {
            key: key.to_string(),
            value: String::new(),
            category,
            priority: mati_core::store::Priority::Normal,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
            ref_url: None,
            staleness: StalenessScore {
                value: 0.5,
                tier,
                signals: vec![],
                computed_at: 0,
                last_record_sha: String::new(),
            },
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::nil(),
                logical_clock: 1,
                wall_clock: 0,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: None,
        }
    }

    // ── summarize_signals ────────────────────────────────────────────────────

    #[test]
    fn summarize_signals_empty() {
        assert_eq!(summarize_signals(&[], 2), "");
    }

    #[test]
    fn summarize_signals_one_signal() {
        let signals = vec![StalenessSignal::FileDeleted];
        assert_eq!(summarize_signals(&signals, 2), "file deleted");
    }

    #[test]
    fn summarize_signals_truncated() {
        let signals = vec![
            StalenessSignal::EntryPointsChanged(2),
            StalenessSignal::ImportsChanged(1),
            StalenessSignal::FileDeleted,
            StalenessSignal::TodosChanged,
        ];
        let result = summarize_signals(&signals, 2);
        assert!(result.contains("2 EP changed"));
        assert!(result.contains("imports"));
        assert!(result.contains("+2 more"));
    }

    // ── impact_label ─────────────────────────────────────────────────────────

    #[test]
    fn impact_label_for_each_tier() {
        assert_eq!(impact_label(&StalenessTier::Fresh), "");
        assert_eq!(impact_label(&StalenessTier::Aging), "");
        assert_eq!(impact_label(&StalenessTier::Stale), "warn in bootstrap");
        assert_eq!(impact_label(&StalenessTier::Liability), "blocks injection");
        assert_eq!(impact_label(&StalenessTier::Tombstone), "excluded entirely");
    }

    // ── content drift ────────────────────────────────────────────────────────

    /// Drift is not a staleness tier, so it must not be described in tier
    /// language. It also must not claim enforcement stopped — a drifted gotcha
    /// still denies (`hooks::decide::eval_drifted_gotcha_still_denies`).
    #[test]
    fn drift_impact_label_does_not_claim_enforcement_stopped() {
        let label = drift_impact_label();
        assert_eq!(label, "rule may be wrong");
        for tier_label in ["warn in bootstrap", "blocks injection", "excluded entirely"] {
            assert_ne!(label, tier_label);
        }
    }

    #[test]
    fn summarize_drifted_files_truncates_like_signals() {
        let files: Vec<String> = ["src/a.rs", "src/b.rs", "src/c.rs"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(summarize_drifted_files(&files[..1], 2), "src/a.rs");
        let result = summarize_drifted_files(&files, 2);
        assert!(result.contains("src/a.rs"));
        assert!(result.contains("src/b.rs"));
        assert!(result.contains("+1 more"));
    }

    /// A drifted gotcha is usually `Fresh`, so it never lands in `records`.
    /// The cache has to carry it separately or `mati stale` would report it on
    /// the miss path and lose it on every subsequent hit.
    #[test]
    fn stale_cache_round_trips_drift_alongside_records() {
        let entry = StaleCache {
            write_seq: 42,
            records: vec![make_record(
                "file:src/x.rs",
                Category::File,
                StalenessTier::Stale,
            )],
            drift: vec![DriftedGotcha {
                key: "gotcha:lock".into(),
                rule: "hold the lock".into(),
                drifted_files: vec!["src/a.rs".into()],
            }],
        };
        let value = serde_json::to_value(&entry).unwrap();
        let back: StaleCache = serde_json::from_value(value).unwrap();
        assert_eq!(back.write_seq, 42);
        assert_eq!(back.records.len(), 1);
        assert_eq!(back.drift.len(), 1);
        assert_eq!(back.drift[0].key, "gotcha:lock");
    }

    /// A cache written before drift existed must still deserialize — it is
    /// keyed on `write_seq`, so invalidating it on a schema addition would
    /// force an unnecessary full scan on every upgrade.
    #[test]
    fn stale_cache_from_older_binary_deserializes_with_no_drift() {
        let legacy = serde_json::json!({ "write_seq": 7, "records": [] });
        let back: StaleCache = serde_json::from_value(legacy).unwrap();
        assert_eq!(back.write_seq, 7);
        assert!(back.drift.is_empty());
    }

    // ── action_hint ──────────────────────────────────────────────────────────

    #[test]
    fn action_hint_for_gotcha() {
        let r = make_record(
            "gotcha:inference-async",
            Category::Gotcha,
            StalenessTier::Stale,
        );
        assert_eq!(action_hint(&r), "mati show gotcha:inference-async");
    }

    #[test]
    fn action_hint_for_file() {
        let r = make_record("file:src/main.rs", Category::File, StalenessTier::Stale);
        assert_eq!(action_hint(&r), "mati reparse src/main.rs");
    }

    #[test]
    fn action_hint_for_file_tombstone() {
        let r = make_record("file:src/old.rs", Category::File, StalenessTier::Tombstone);
        let hint = action_hint(&r);
        assert!(hint.contains("file may be deleted"));
        assert!(hint.contains("src/old.rs"));
    }

    #[test]
    fn action_hint_for_decision() {
        let r = make_record(
            "decision:storage-engine",
            Category::Decision,
            StalenessTier::Liability,
        );
        assert_eq!(action_hint(&r), "mati show decision:storage-engine");
    }

    // ── M-15 Category 7 gap coverage ────────────────────────────────────────

    /// 7.02: Only Stale, Liability, Tombstone tiers appear in the stale list;
    /// Fresh and Aging are filtered out.
    #[test]
    fn stale_command_filters_only_stale_tiers() {
        // Simulate the filter logic from run(): only Stale|Liability|Tombstone pass.
        let records = [
            make_record("file:fresh.rs", Category::File, StalenessTier::Fresh),
            make_record("file:aging.rs", Category::File, StalenessTier::Aging),
            make_record("file:stale.rs", Category::File, StalenessTier::Stale),
            make_record(
                "file:liability.rs",
                Category::File,
                StalenessTier::Liability,
            ),
            make_record(
                "file:tombstone.rs",
                Category::File,
                StalenessTier::Tombstone,
            ),
        ];

        let stale: Vec<&Record> = records
            .iter()
            .filter(|r| {
                matches!(
                    r.staleness.tier,
                    StalenessTier::Stale | StalenessTier::Liability | StalenessTier::Tombstone
                )
            })
            .collect();

        assert_eq!(
            stale.len(),
            3,
            "only Stale, Liability, Tombstone should pass filter"
        );
        assert!(stale.iter().all(|r| !matches!(
            r.staleness.tier,
            StalenessTier::Fresh | StalenessTier::Aging
        )));
    }

    /// 7.03: Records are sorted by staleness descending.
    #[test]
    fn stale_command_sorts_descending() {
        let mut r1 = make_record("file:a.rs", Category::File, StalenessTier::Stale);
        r1.staleness.value = 0.50;
        let mut r2 = make_record("file:b.rs", Category::File, StalenessTier::Liability);
        r2.staleness.value = 0.70;
        let mut r3 = make_record("file:c.rs", Category::File, StalenessTier::Tombstone);
        r3.staleness.value = 0.95;

        let mut stale = [r1, r2, r3];
        stale.sort_by(|a, b| {
            b.staleness
                .value
                .partial_cmp(&a.staleness.value)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        assert_eq!(
            stale[0].key, "file:c.rs",
            "highest staleness should be first"
        );
        assert_eq!(stale[1].key, "file:b.rs", "second highest should be second");
        assert_eq!(stale[2].key, "file:a.rs", "lowest staleness should be last");
    }

    /// 7.04: truncate respects limit — seed 10, limit 3 → only 3 shown.
    #[test]
    fn stale_command_respects_limit() {
        let mut stale: Vec<Record> = (0..10)
            .map(|i| {
                let mut r = make_record(
                    &format!("file:mod_{i}.rs"),
                    Category::File,
                    StalenessTier::Stale,
                );
                r.staleness.value = 0.5 + (i as f32) * 0.04;
                r
            })
            .collect();

        let limit = 3;
        stale.truncate(limit);

        assert_eq!(stale.len(), limit, "truncate should cap results at {limit}");
    }

    /// 7.05: Every StalenessSignal variant produces a non-empty short label.
    #[test]
    fn signal_short_label_all_variants() {
        let variants: Vec<StalenessSignal> = vec![
            StalenessSignal::NotAccessedDays(30),
            StalenessSignal::EntryPointsChanged(2),
            StalenessSignal::ImportsChanged(5),
            StalenessSignal::FileDeleted,
            StalenessSignal::FileRenamed {
                new_path: "src/new.rs".to_string(),
            },
            StalenessSignal::LinkedFileChanged {
                path: "src/bar.rs".to_string(),
            },
            StalenessSignal::TodosChanged,
            StalenessSignal::UnsafeCountChanged(3),
            StalenessSignal::UnwrapCountChanged(-2),
            StalenessSignal::DependencyBumped {
                dep: "tokio".to_string(),
                old_ver: "1.0".to_string(),
                new_ver: "2.0".to_string(),
            },
            StalenessSignal::LinesChangedPct(0.75),
            StalenessSignal::CascadeFromDecision("decision:arch".to_string()),
        ];

        for variant in &variants {
            let label = signal_short_label(variant);
            assert!(
                !label.is_empty(),
                "signal_short_label for {:?} should produce non-empty string",
                variant
            );
        }
    }

    /// 7.06: impact_label returns a non-empty string for actionable tiers
    /// and empty string for non-actionable tiers.
    #[test]
    fn impact_label_all_tiers() {
        let all_tiers = [
            StalenessTier::Fresh,
            StalenessTier::Aging,
            StalenessTier::Stale,
            StalenessTier::Liability,
            StalenessTier::Tombstone,
        ];
        for tier in &all_tiers {
            let label = impact_label(tier);
            match tier {
                StalenessTier::Fresh | StalenessTier::Aging => {
                    assert_eq!(label, "", "Fresh/Aging should have empty impact label");
                }
                _ => {
                    assert!(
                        !label.is_empty(),
                        "{:?} should have a non-empty impact label",
                        tier
                    );
                }
            }
        }
    }

    /// 7.07: action_hint produces a meaningful hint for every category + tier combination.
    #[test]
    fn action_hint_for_each_category() {
        let categories_and_keys = vec![
            (Category::Gotcha, "gotcha:test"),
            (Category::File, "file:src/main.rs"),
            (Category::Decision, "decision:arch"),
            (Category::DevNote, "dev_note:tip"),
            (Category::Dependency, "dep:cargo:tokio"),
        ];

        for (cat, key) in &categories_and_keys {
            // Test with Stale tier
            let r = make_record(key, cat.clone(), StalenessTier::Stale);
            let hint = action_hint(&r);
            assert!(
                !hint.is_empty(),
                "action_hint for category {:?} should produce non-empty hint",
                cat
            );
        }

        // File + Tombstone specifically should mention "deleted"
        let r = make_record("file:src/gone.rs", Category::File, StalenessTier::Tombstone);
        let hint = action_hint(&r);
        assert!(
            hint.contains("deleted"),
            "File Tombstone action hint should mention deletion, got: {hint}"
        );
    }

    #[test]
    fn sort_by_effective_staleness_propagated_first() {
        use mati_core::analysis::propagation::PropagatedStaleness;

        // File A: local 0.3, propagated 0.55 → effective 0.55
        let fr_a = FileRecord {
            path: "src/a.rs".into(),
            purpose: String::new(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 0,
            last_modified_session: 0,
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: Some(PropagatedStaleness {
                value: 0.55,
                source_count: 1,
                primary_source: Some("src/upstream.rs".into()),
            }),
        };
        let rec_a = Record {
            key: "file:src/a.rs".into(),
            value: String::new(),
            category: Category::File,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
            ref_url: None,
            staleness: StalenessScore {
                value: 0.3,
                tier: StalenessTier::Aging,
                signals: vec![],
                computed_at: 0,
                last_record_sha: String::new(),
            },
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 0,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: serde_json::to_value(&fr_a).ok(),
        };

        // File B: local 0.45, no propagation → effective 0.45
        let fr_b = FileRecord {
            path: "src/b.rs".into(),
            purpose: String::new(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 0,
            last_modified_session: 0,
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
        };
        let mut rec_b = rec_a.clone();
        rec_b.key = "file:src/b.rs".into();
        rec_b.staleness.value = 0.45;
        rec_b.staleness.tier = StalenessTier::Stale;
        rec_b.payload = serde_json::to_value(&fr_b).ok();

        // Sort: A (effective 0.55) should come before B (effective 0.45)
        let mut records = [rec_b, rec_a]; // B first intentionally
        records.sort_by(|a, b| {
            effective_staleness(b)
                .partial_cmp(&effective_staleness(a))
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        assert_eq!(
            records[0].key, "file:src/a.rs",
            "A (effective 0.55) should sort before B (effective 0.45)"
        );
        assert_eq!(records[1].key, "file:src/b.rs");
    }
}
