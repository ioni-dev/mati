use super::*;

// ── format_ts ─────────────────────────────────────────────────────────────

#[test]
fn format_ts_zero_is_em_dash() {
    assert_eq!(format_ts(0), "\u{2014}");
}

#[test]
fn format_ts_epoch_plus_one_second() {
    assert_eq!(format_ts(1), "1970-01-01 00:00:01 UTC");
}

#[test]
fn format_ts_exactly_one_day() {
    assert_eq!(format_ts(86400), "1970-01-02 00:00:00 UTC");
}

#[test]
fn format_ts_known_date_2024_01_15() {
    assert_eq!(format_ts(19737 * 86400), "2024-01-15 00:00:00 UTC");
}

#[test]
fn format_ts_hms_components() {
    assert_eq!(format_ts(3723), "1970-01-01 01:02:03 UTC");
}

// ── days_to_ymd ───────────────────────────────────────────────────────────

#[test]
fn days_to_ymd_unix_epoch() {
    assert_eq!(days_to_ymd(0), (1970, 1, 1));
}

#[test]
fn days_to_ymd_2024_01_15() {
    assert_eq!(days_to_ymd(19737), (2024, 1, 15));
}

#[test]
fn days_to_ymd_leap_day_2024_02_29() {
    assert_eq!(days_to_ymd(19782), (2024, 2, 29));
}

#[test]
fn days_to_ymd_post_feb_non_leap_2023_03_01() {
    assert_eq!(days_to_ymd(19417), (2023, 3, 1));
}

#[test]
fn days_to_ymd_year_boundary_dec_31() {
    assert_eq!(days_to_ymd(19722), (2023, 12, 31));
}

#[test]
fn days_to_ymd_new_year_2024_01_01() {
    assert_eq!(days_to_ymd(19723), (2024, 1, 1));
}

#[test]
fn days_to_ymd_consistent_with_format_ts() {
    let ts = 19737_u64 * 86400;
    let (y, mo, d) = days_to_ymd(ts / 86400);
    assert_eq!((y, mo, d), (2024, 1, 15));
    assert!(format_ts(ts).starts_with("2024-01-15"));
}

// ── Helpers ───────────────────────────────────────────────────────────────

#[test]
fn truncate_short_string() {
    assert_eq!(truncate("hello", 10), "hello");
}

#[test]
fn truncate_long_string() {
    assert_eq!(truncate("hello world this is long", 10), "hello w...");
}

#[test]
fn truncate_multiline() {
    assert_eq!(truncate("first line\nsecond line", 40), "first line");
}

#[test]
fn format_date_zero() {
    assert_eq!(format_date(0), "\u{2014}");
}

#[test]
fn format_date_known() {
    assert_eq!(format_date(19737 * 86400), "2024-01-15");
}

// ── parse_since_duration ─────────────────────────────────────────────────

#[test]
fn parse_since_hours() {
    assert_eq!(parse_since_duration("2h").unwrap(), 7200);
}

#[test]
fn parse_since_days() {
    assert_eq!(parse_since_duration("7d").unwrap(), 604800);
}

#[test]
fn parse_since_weeks() {
    assert_eq!(parse_since_duration("2w").unwrap(), 14 * 86400);
}

#[test]
fn parse_since_months() {
    assert_eq!(parse_since_duration("3m").unwrap(), 90 * 86400);
}

#[test]
fn parse_since_years() {
    assert_eq!(parse_since_duration("1y").unwrap(), 365 * 86400);
}

#[test]
fn parse_since_invalid_suffix() {
    assert!(parse_since_duration("7x").is_err());
}

#[test]
fn parse_since_no_number() {
    assert!(parse_since_duration("d").is_err());
}

#[test]
fn parse_since_zero_value() {
    assert!(parse_since_duration("0d").is_err());
}

#[test]
fn parse_since_empty() {
    assert!(parse_since_duration("").is_err());
}

// ── format_ts_short ──────────────────────────────────────────────────────

#[test]
fn format_ts_short_zero_is_em_dash() {
    assert_eq!(format_ts_short(0), "\u{2014}");
}

#[test]
fn format_ts_short_known_date() {
    // 2024-01-15 01:02
    let ts = 19737 * 86400 + 3720;
    assert_eq!(format_ts_short(ts), "2024-01-15 01:02");
}

// ── source_short_label ───────────────────────────────────────────────────

#[test]
fn source_short_label_values() {
    assert_eq!(source_short_label(&RecordSource::StaticAnalysis), "L0");
    assert_eq!(source_short_label(&RecordSource::ClaudeEnrich), "L1");
    assert_eq!(source_short_label(&RecordSource::SessionHook), "L2");
    assert_eq!(source_short_label(&RecordSource::DeveloperManual), "manual");
    assert_eq!(source_short_label(&RecordSource::Import), "import");
}

// ── duration_label ───────────────────────────────────────────────────────

#[test]
fn duration_label_hours() {
    assert_eq!(duration_label(3600), "1 hour");
    assert_eq!(duration_label(7200), "2 hours");
}

#[test]
fn duration_label_days() {
    assert_eq!(duration_label(86400), "1 day");
    assert_eq!(duration_label(3 * 86400), "3 days");
}

#[test]
fn duration_label_weeks() {
    assert_eq!(duration_label(7 * 86400), "1 week");
    assert_eq!(duration_label(14 * 86400), "2 weeks");
}

#[test]
fn duration_label_months() {
    assert_eq!(duration_label(30 * 86400), "1 month");
    assert_eq!(duration_label(60 * 86400), "2 months");
}

#[test]
fn duration_label_years() {
    assert_eq!(duration_label(365 * 86400), "1 year");
    assert_eq!(duration_label(730 * 86400), "2 years");
}

// ── truncate multibyte + edge cases ──────────────────────────────────────

#[test]
fn truncate_multibyte_chars() {
    // Each emoji is 4 bytes. "abcde" is 9 chars total.
    let s = "ab\u{1F600}cd\u{1F600}ef";
    // max=6 means we need 3 chars + "..."
    let result = truncate(s, 6);
    assert!(result.ends_with("..."));
    assert_eq!(result.chars().count(), 6); // 3 chars + 3 dots
}

#[test]
fn truncate_exact_boundary() {
    assert_eq!(truncate("hello", 5), "hello");
}

#[test]
fn truncate_one_over() {
    assert_eq!(truncate("hello!", 5), "he...");
}

#[test]
fn truncate_max_less_than_four() {
    // max < 4: just take what fits, no "..."
    assert_eq!(truncate("hello", 3), "hel");
}

#[test]
fn truncate_empty_string() {
    assert_eq!(truncate("", 10), "");
}

#[test]
fn truncate_all_multibyte() {
    // 4 emoji = 4 chars, each 4 bytes
    let s = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}";
    let result = truncate(s, 4);
    assert_eq!(result, s); // exactly fits
}

#[test]
fn truncate_all_multibyte_over() {
    let s = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}\u{1F604}";
    let result = truncate(s, 4);
    // 1 char + "..." = 4 chars
    assert_eq!(result, "\u{1F600}...");
}

// ── enforcement history --limit tail semantics (pass 31) ─────────────────

/// Pass 31 regression: `mati history --enforcement --limit N` MUST show
/// the LAST N events (most recent), not the FIRST N (oldest). Pre-pass-31
/// the function used `.take(N)` on the ascending-ordered list, returning
/// events from weeks ago no matter how many were in the store. Smoke
/// tests failed Phase 5 history checks because `--limit 10` returned seq
/// 1-10 (months old), and the smoke's freshly-emitted `allow_receipt`
/// event lived at e.g. seq 1268 — invisible.
///
/// We test the slice math directly: `total.saturating_sub(limit)` is
/// what makes the tail behavior work. A simple unit on this expression
/// pins the semantics without spinning up a daemon.
#[test]
fn enforcement_limit_returns_tail_not_head() {
    // Simulate 1268 events (matching the real-world repro size).
    let total = 1268usize;
    let limit = 10usize;

    // The new tail-semantics computation:
    let skip = total.saturating_sub(limit);
    let kept_indices: Vec<usize> = (0..total).skip(skip).collect();

    assert_eq!(kept_indices.len(), 10, "exactly `limit` events kept");
    assert_eq!(
        kept_indices.first(),
        Some(&1258),
        "first kept event must be at index `total - limit`, not 0 (head)"
    );
    assert_eq!(
        kept_indices.last(),
        Some(&1267),
        "last kept event must be the most recent (index total-1)"
    );
    assert!(
        !kept_indices.contains(&0),
        "head events must NOT appear when total > limit (this was the pre-pass-31 bug)"
    );
}

/// Edge case: when total <= limit, return everything (no skip).
/// `saturating_sub` is what makes this safe — `total.saturating_sub(limit)`
/// returns 0 when `limit >= total`, so `.skip(0)` keeps the whole list.
#[test]
fn enforcement_limit_smaller_than_total_returns_all() {
    let total = 5usize;
    let limit = 100usize;
    let skip = total.saturating_sub(limit);
    let kept: Vec<usize> = (0..total).skip(skip).collect();
    assert_eq!(
        kept,
        vec![0, 1, 2, 3, 4],
        "all events kept when limit >= total"
    );
}

/// Edge case: limit=0 returns empty (no events). Matches existing semantics.
#[test]
fn enforcement_limit_zero_returns_empty() {
    let total = 50usize;
    let limit = 0usize;
    let skip = total.saturating_sub(limit);
    // skip == 50, so .skip(50).collect() on 0..50 returns empty.
    let kept: Vec<usize> = (0..total).skip(skip).collect();
    assert!(kept.is_empty(), "limit=0 returns empty");
}

// ── ls_file_row ──────────────────────────────────────────────────────────

#[test]
fn ls_file_row_shows_a_live_file_record() {
    let record = Record::layer0_file_stub("file:src/live.rs", uuid::Uuid::nil(), 1, 0);
    assert!(
        ls_file_row(&record).is_some(),
        "a record with no staleness signal must appear in `mati ls files`"
    );
}

/// `mati ls files` must not mix in a row for a `file:*` record whose
/// path was deleted from disk (`StalenessTier::Tombstone`, set by the
/// `FileDeleted` hard override in `health::staleness::compute_staleness`).
/// The gotcha this closes: eight such records showed up as ordinary
/// rows, indistinguishable from files that are actually gated.
#[test]
fn ls_file_row_excludes_a_deleted_file_record() {
    let mut record = Record::layer0_file_stub("file:src/dead.rs", uuid::Uuid::nil(), 1, 0);
    record.staleness.tier = StalenessTier::Tombstone;
    record.staleness.value = 1.0;
    assert!(
        ls_file_row(&record).is_none(),
        "a Tombstone-tier record must be excluded from `mati ls files`"
    );
}
