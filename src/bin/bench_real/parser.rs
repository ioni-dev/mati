/// Output parsers for every mati command.
///
/// All parsers accept raw stdout (may contain ANSI codes) and strip them
/// before extracting values. Parsing is best-effort — missing fields are
/// left at their zero/default values and surfaced in the accuracy report.

// ── ANSI stripper ─────────────────────────────────────────────────────────────

pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // ESC [ ... terminator  (CSI sequences only — covers all ANSI colour codes)
            if chars.peek() == Some(&'[') {
                chars.next();
                for c2 in chars.by_ref() {
                    // Terminates at any ASCII letter
                    if c2.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ── mati init ────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct InitMetrics {
    /// Wall-clock time per named stage (ms). Keys: "walk", "parse", "git",
    /// "deps", "records", "edges", "store", "scaffold", "close".
    pub stages:        std::collections::HashMap<String, u64>,
    /// Total init time reported at the bottom (ms).
    pub total_ms:      u64,
    /// File records written.
    pub file_count:    usize,
    /// Gotcha candidates found.
    pub gotcha_cands:  usize,
    /// Dependency records.
    pub dep_count:     usize,
    /// Graph edges built.
    pub edge_count:    usize,
    /// CLAUDE.md sections imported.
    pub imported_secs: usize,
    /// Hotspot files.
    pub hotspot_count: usize,
    /// True if "Total:" line was found (init completed).
    pub completed:     bool,
}

pub fn parse_init(stdout: &str) -> InitMetrics {
    let clean = strip_ansi(stdout);
    let mut m = InitMetrics::default();

    for line in clean.lines() {
        let trimmed = line.trim();

        // ── Progress lines ────────────────────────────────────────────────
        // "  Scanning with ignore...         387 files      9ms"
        if trimmed.starts_with("Scanning with ignore") {
            if let Some(ms) = last_ms(trimmed) {
                m.stages.insert("walk".into(), ms);
            }
        }
        // "  Parsing with tree-sitter...                    22ms"
        else if trimmed.starts_with("Parsing with tree-sitter") {
            if let Some(ms) = last_ms(trimmed) {
                m.stages.insert("parse".into(), ms);
            }
        }
        // "  Mining git history...                          12ms"
        else if trimmed.starts_with("Mining git history") {
            if let Some(ms) = last_ms(trimmed) {
                m.stages.insert("git".into(), ms);
            }
        }
        // "  Parsing dependencies...           34 deps      2ms"
        else if trimmed.starts_with("Parsing dependencies") {
            if let Some(ms) = last_ms(trimmed) {
                m.stages.insert("deps".into(), ms);
            }
        }
        // "  Importing CLAUDE.md..."
        else if trimmed.starts_with("Importing CLAUDE.md") {
            if let Some(ms) = last_ms(trimmed) {
                m.stages.insert("import".into(), ms);
            }
        }
        // "  Building graph edges...   2 edges   0ms"
        else if trimmed.starts_with("Building graph edges") {
            if let Some(ms) = last_ms(trimmed) {
                m.stages.insert("edges".into(), ms);
            }
            // Also capture edge count from this line
            if m.edge_count == 0 {
                m.edge_count = first_number(trimmed).unwrap_or(0);
            }
        }
        // "  Writing .claude/CLAUDE.md stub..."
        else if trimmed.starts_with("Writing .claude") {
            if let Some(ms) = last_ms(trimmed) {
                m.stages.insert("scaffold".into(), ms);
            }
        }
        // "  Installing hooks..."
        else if trimmed.starts_with("Installing hooks") {
            if let Some(ms) = last_ms(trimmed) {
                m.stages.insert("hooks".into(), ms);
            }
        }

        // ── Summary lines ─────────────────────────────────────────────────
        // "  file records:          448   (stubs + entry points)"
        else if trimmed.starts_with("file records:") {
            m.file_count = first_number(trimmed).unwrap_or(0);
        }
        // "  gotcha candidates:      12   (TODOs, unsafe, unwrap)"
        else if trimmed.starts_with("gotcha candidates:") {
            m.gotcha_cands = first_number(trimmed).unwrap_or(0);
        }
        // "  dep records:            34"
        else if trimmed.starts_with("dep records:") {
            m.dep_count = first_number(trimmed).unwrap_or(0);
        }
        // "  graph edges:           533   (import + co-change)"
        else if trimmed.starts_with("graph edges:") {
            m.edge_count = first_number(trimmed).unwrap_or(0);
        }
        // "  imported from CLAUDE.md:  2"
        else if trimmed.starts_with("imported from CLAUDE.md") {
            m.imported_secs = first_number(trimmed).unwrap_or(0);
        }
        // "  hotspot files:           4"
        else if trimmed.starts_with("hotspot files:") {
            m.hotspot_count = first_number(trimmed).unwrap_or(0);
        }

        // ── Total line ────────────────────────────────────────────────────
        // "  Total: 379ms · 0 tokens · 0 Claude calls"
        else if trimmed.starts_with("Total:") {
            if let Some(ms) = first_ms(trimmed) {
                m.total_ms  = ms;
                m.completed = true;
            }
        }
    }

    m
}

// ── mati status ──────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct StatusMetrics {
    pub file_count:      usize,
    pub gotcha_count:    usize,
    pub decision_count:  usize,
    pub note_count:      usize,
    pub dep_count:       usize,
    pub confirmed_count: usize,
    pub confirmed_pct:   f64,
    pub confidence_avg:  f64,
    pub confidence_med:  f64,
    pub hotspot_count:   usize,
    pub total_files:     usize,
}

pub fn parse_status(stdout: &str) -> StatusMetrics {
    let clean = strip_ansi(stdout);
    let mut m = StatusMetrics::default();

    for line in clean.lines() {
        let t = line.trim();

        // "  Records     387 files  0 gotchas  0 decisions  0 notes  34 deps"
        if t.contains("files") && t.contains("gotchas") {
            // Extract counts in order: files gotchas decisions notes deps
            let nums: Vec<usize> = numbers_in(t);
            if nums.len() >= 5 {
                m.file_count     = nums[0];
                m.gotcha_count   = nums[1];
                m.decision_count = nums[2];
                m.note_count     = nums[3];
                m.dep_count      = nums[4];
            }
        }

        // "  Confirmed    0 / 0 gotchas (0%)"
        if t.contains("Confirmed") || t.contains("confirmed") {
            let nums: Vec<usize> = numbers_in(t);
            if nums.len() >= 2 {
                m.confirmed_count = nums[0];
            }
            if let Some(pct) = percent_in(t) {
                m.confirmed_pct = pct;
            }
        }

        // "  Confidence   avg 0.72  median 0.68"
        if t.contains("Confidence") || t.contains("confidence") {
            let floats: Vec<f64> = floats_in(t);
            if floats.len() >= 1 {
                m.confidence_avg = floats[0];
            }
            if floats.len() >= 2 {
                m.confidence_med = floats[1];
            }
        }

        // "  Hotspots     4 / 387 (1%)"
        if t.contains("Hotspot") || t.contains("hotspot") {
            let nums: Vec<usize> = numbers_in(t);
            if nums.len() >= 1 {
                m.hotspot_count = nums[0];
            }
            if nums.len() >= 2 {
                m.total_files = nums[1];
            }
        }
    }

    m
}

// ── mati stats ───────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct StatsMetrics {
    pub files_with_purpose:   usize,
    pub total_files:          usize,
    pub purpose_pct:          f64,
    pub gotchas_per_hotspot:  f64,
    pub decision_count:       usize,
    pub avg_confidence:       f64,
    pub gap_count:            usize,
    pub new_records_30d:      usize,
    pub multi_contributor:    usize,
    pub onboarding_minutes:   f64,
    pub critical_uncovered:   usize,
    pub orphaned_decisions:   usize,
    pub low_confidence:       usize,
    pub hit_rate_pct:         f64,
    pub hits_7d:              usize,
    pub total_lookups:        usize,
    pub bypasses_7d:          usize,
    /// True if "(cached" appears in the header — this was a cache hit.
    pub was_cached:           bool,
}

pub fn parse_stats(stdout: &str) -> StatsMetrics {
    let clean = strip_ansi(stdout);
    let mut m = StatsMetrics::default();

    for line in clean.lines() {
        let t = line.trim();

        if t.contains("cached") {
            m.was_cached = true;
        }

        // "    Files with purpose     387 / 387  (100%)"
        if t.starts_with("Files with purpose") {
            let nums: Vec<usize> = numbers_in(t);
            if nums.len() >= 2 {
                m.files_with_purpose = nums[0];
                m.total_files        = nums[1];
            }
            if let Some(pct) = percent_in(t) {
                m.purpose_pct = pct;
            }
        }

        // "    Gotchas per hotspot    2.1  (target >= 2.0)"
        if t.starts_with("Gotchas per hotspot") {
            if let Some(f) = floats_in(t).into_iter().next() {
                m.gotchas_per_hotspot = f;
            }
        }

        // "    Decisions documented   5"
        if t.starts_with("Decisions documented") {
            m.decision_count = first_number(t).unwrap_or(0);
        }

        // "    Avg confidence         0.72"
        if t.starts_with("Avg confidence") {
            if let Some(f) = floats_in(t).into_iter().next() {
                m.avg_confidence = f;
            }
        }

        // "    Knowledge gaps         3"
        if t.starts_with("Knowledge gaps") {
            m.gap_count = first_number(t).unwrap_or(0);
        }

        // "    New records added      12"
        if t.starts_with("New records added") {
            m.new_records_30d = first_number(t).unwrap_or(0);
        }

        // "    Confirmed by 2+ devs  0"
        if t.contains("2+ dev") || t.contains("multi") {
            m.multi_contributor = first_number(t).unwrap_or(0);
        }

        // "    Estimated onboarding   45 min"
        if t.starts_with("Estimated onboarding") {
            if let Some(f) = floats_in(t).into_iter().next() {
                m.onboarding_minutes = f;
            }
        }

        // "    Critical files uncov.  2"
        if t.starts_with("Critical files") {
            m.critical_uncovered = first_number(t).unwrap_or(0);
        }

        // "    Orphaned decisions     1"
        if t.starts_with("Orphaned decisions") {
            m.orphaned_decisions = first_number(t).unwrap_or(0);
        }

        // "    Low-confidence (<0.3)  5"
        if t.starts_with("Low-confidence") {
            m.low_confidence = first_number(t).unwrap_or(0);
        }

        // "    Hit rate               78%  (156 hits / 200 lookups)"
        if t.starts_with("Hit rate") {
            if let Some(pct) = percent_in(t) {
                m.hit_rate_pct = pct;
            }
            let nums: Vec<usize> = numbers_in(t);
            if nums.len() >= 2 {
                m.hits_7d       = nums[0];
                m.total_lookups = nums[1];
            }
        }

        // "    Bypasses               3"
        if t.starts_with("Bypasses") {
            m.bypasses_7d = first_number(t).unwrap_or(0);
        }
    }

    m
}

// ── mati gaps ────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct GapsMetrics {
    pub critical: usize,
    pub high:     usize,
    pub normal:   usize,
    pub low:      usize,
}

impl GapsMetrics {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.normal + self.low
    }
}

pub fn parse_gaps(stdout: &str) -> GapsMetrics {
    let clean = strip_ansi(stdout);
    let mut m = GapsMetrics::default();

    for line in clean.lines() {
        let t = line.trim();
        // Each gap line starts with "● TIER" after stripping ANSI.
        if t.starts_with("● CRITICAL") || t.starts_with("●  CRITICAL") { m.critical += 1; }
        else if t.starts_with("● HIGH")     || t.starts_with("●  HIGH")     { m.high     += 1; }
        else if t.starts_with("● NORMAL")   || t.starts_with("●  NORMAL")   { m.normal   += 1; }
        else if t.starts_with("● LOW")      || t.starts_with("●  LOW")      { m.low      += 1; }
    }

    m
}

// ── mati stale ───────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct StaleMetrics {
    pub aging:     usize,
    pub stale:     usize,
    pub liability: usize,
    pub tombstone: usize,
}

impl StaleMetrics {
    pub fn total(&self) -> usize {
        self.aging + self.stale + self.liability + self.tombstone
    }
}

pub fn parse_stale(stdout: &str) -> StaleMetrics {
    let clean = strip_ansi(stdout);
    let mut m = StaleMetrics::default();

    for line in clean.lines() {
        let upper = line.to_uppercase();
        // Count rows that contain tier labels (table data rows).
        if upper.contains("AGING")     && upper.contains('│') { m.aging     += 1; }
        if upper.contains("LIABILITY") && upper.contains('│') { m.liability += 1; }
        if upper.contains("TOMBSTONE") && upper.contains('│') { m.tombstone += 1; }
        if upper.contains("│ STALE │") || (upper.contains("STALE") && upper.contains('│') && !upper.contains("AGING")) {
            m.stale += 1;
        }
    }

    m
}

// ── mati ping ────────────────────────────────────────────────────────────────

/// Extract the latency µs from "mati ok  116µs".
pub fn parse_ping_us(stdout: &str) -> Option<u64> {
    let clean = strip_ansi(stdout);
    for line in clean.lines() {
        if !line.contains("ok") { continue; }
        // Look for the number before "µs" or "us".
        let hay = line.replace("µs", "us");
        if let Some(pos) = hay.find("us") {
            let before = &hay[..pos];
            if let Some(n) = before.split_whitespace().last().and_then(|s| s.parse::<u64>().ok()) {
                return Some(n);
            }
        }
    }
    None
}

// ── mati ls ──────────────────────────────────────────────────────────────────

/// Count data rows in a comfy_table output (rows that contain '┆').
#[allow(dead_code)]
pub fn parse_ls_count(stdout: &str) -> usize {
    extract_file_keys(stdout).len()
}

/// Extract "file:<path>" keys from `mati ls files` output.
///
/// The table uses `┆` (U+2506) as the column separator and shows relative
/// paths in the first column — we prepend "file:" to form the store key.
pub fn extract_file_keys(stdout: &str) -> Vec<String> {
    let clean = strip_ansi(stdout);
    let mut keys = Vec::new();
    for line in clean.lines() {
        // Data rows contain ┆ as column separator.
        if !line.contains('┆') { continue; }
        // Skip header row (contains "Path" or "Purpose").
        let t = line.trim();
        if t.contains("Path") && t.contains("Purpose") { continue; }
        // First cell (between leading │/┆ and first ┆) is the path.
        let cell = line
            .splitn(3, '┆')
            .nth(0)
            .unwrap_or("")
            .trim_matches(|c: char| c == '│' || c == ' ' || c == '┆');
        let path = cell.trim();
        if !path.is_empty() && !path.starts_with('─') && !path.starts_with('═')
            && !path.starts_with('╞') && !path.starts_with('┌')
        {
            keys.push(format!("file:{}", path));
        }
    }
    keys
}

// ── Number extraction helpers ─────────────────────────────────────────────────

/// Extract the last "Nms" value in a line.
fn last_ms(line: &str) -> Option<u64> {
    let chars: Vec<char> = line.chars().collect();
    let mut i = chars.len();
    // Scan backwards looking for "ms" suffix.
    while i >= 2 {
        if chars[i - 1] == 's' && chars[i - 2] == 'm' {
            // Collect digits before "ms".
            let mut j = i - 2;
            while j > 0 && chars[j - 1].is_ascii_digit() {
                j -= 1;
            }
            if j < i - 2 {
                let num: String = chars[j..i - 2].iter().collect();
                return num.parse().ok();
            }
        }
        i -= 1;
    }
    None
}

/// Extract the first "Nms" value in a line.
fn first_ms(line: &str) -> Option<u64> {
    let mut buf = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            buf.push(c);
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    buf.push(d);
                    chars.next();
                } else {
                    break;
                }
            }
            // Is this followed by "ms"?
            let next2: String = chars.clone().take(2).collect();
            if next2 == "ms" {
                return buf.parse().ok();
            }
            buf.clear();
        }
    }
    None
}

/// Extract the first integer in a string.
pub fn first_number(s: &str) -> Option<usize> {
    numbers_in(s).into_iter().next()
}

/// All integers in a string (in order).
pub fn numbers_in(s: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut buf = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            buf.push(c);
        } else if !buf.is_empty() {
            if let Ok(n) = buf.parse::<usize>() {
                out.push(n);
            }
            buf.clear();
        }
    }
    if !buf.is_empty() {
        if let Ok(n) = buf.parse::<usize>() {
            out.push(n);
        }
    }
    out
}

/// All f64 values in a string (in order).  Skips percentage signs.
pub fn floats_in(s: &str) -> Vec<f64> {
    s.split_whitespace()
        .filter_map(|w| {
            let clean = w.trim_matches(|c: char| c == '%' || c == ',' || c == ')' || c == '(');
            clean.parse::<f64>().ok()
        })
        .collect()
}

/// First "XX%" value in a string.
pub fn percent_in(s: &str) -> Option<f64> {
    for word in s.split_whitespace() {
        if let Some(stripped) = word.strip_suffix('%') {
            let clean = stripped.trim_matches(|c: char| c == '(' || c == ')');
            if let Ok(f) = clean.parse::<f64>() {
                return Some(f);
            }
        }
    }
    None
}
