use crate::RepoReport;
use crate::runner::TimedResult;

pub fn generate(reports: &[RepoReport], date: &str) -> String {
    let mut out = String::new();

    out += &format!("# Real-Repo Validation — {}\n\n", date);
    out += "Measured on: macOS Darwin, Apple Silicon\n";
    out += "Build: `cargo build --release` (opt-level=3, thin LTO, strip=true)\n\n";
    out += "---\n\n";

    out += &section_repos_tested(reports);
    out += &section_init(reports);
    out += &section_latency(reports);
    out += &section_parallel_gets(reports);
    out += &section_cache(reports);
    out += &section_ping(reports);
    out += &section_accuracy(reports);
    out += &section_gaps(reports);
    out += &section_staleness(reports);
    out += &section_integrity(reports);
    out += &section_store_size(reports);

    out
}

// ── Repos tested ─────────────────────────────────────────────────────────────

fn section_repos_tested(reports: &[RepoReport]) -> String {
    let mut s = String::from("## Repos Tested\n\n");
    s += "| Repo | Files (git) | Source files | Languages | Store size |\n";
    s += "|------|-------------|--------------|-----------|------------|\n";
    for r in reports {
        let langs: String = r.lang_counts
            .iter()
            .take(3)
            .map(|(l, n)| format!("{} ({})", l, n))
            .collect::<Vec<_>>()
            .join(", ");
        s += &format!(
            "| **{}** | {} | {} | {} | {} |\n",
            r.repo_name,
            r.accuracy.file_count_git,
            r.accuracy.file_count_mati,
            langs,
            r.accuracy.store_size_mb.map(|n| format!("{:.1}MB", n)).unwrap_or_else(|| "—".into()),
        );
    }
    s + "\n---\n\n"
}

// ── Init performance ──────────────────────────────────────────────────────────

fn section_init(reports: &[RepoReport]) -> String {
    let mut s = String::from("## Init Performance (`mati init`)\n\n");
    s += "> Store writes are included in Total but not broken out separately — \
          no progress line is printed for that phase.\n\n";
    s += "| Repo | Files | Walk | Parse | Git | Deps | Edges | Gotcha cands | Total |\n";
    s += "|------|-------|------|-------|-----|------|-------|-------------|-------|\n";
    for r in reports {
        let i = &r.cold.init;
        s += &format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | **{}** |\n",
            r.repo_name,
            i.file_count,
            ms(&i.stages, "walk"),
            ms(&i.stages, "parse"),
            ms(&i.stages, "git"),
            ms(&i.stages, "deps"),
            i.edge_count,
            i.gotcha_cands,
            if i.total_ms > 0 { format!("{}ms", i.total_ms) } else { "—".into() },
        );
    }
    s + "\n---\n\n"
}

// ── Per-command latency: cold vs warm ────────────────────────────────────────

fn section_latency(reports: &[RepoReport]) -> String {
    let samples = reports.first().map(|r| r.cold.samples).unwrap_or(5);
    let mut s = String::from("## Command Latency — Cold vs Warm\n\n");
    s += &format!(
        "All times in ms (mean over {} samples). \
         Cold = first run after fresh init. Warm = repeat run (store warm).\n\n",
        samples
    );

    // Build header from repo names
    let repo_headers: Vec<String> = reports
        .iter()
        .map(|r| format!("{} cold | {} warm", r.repo_name, r.repo_name))
        .collect();
    s += &format!("| Command | {} |\n", repo_headers.join(" | "));

    let sep: Vec<&str> = std::iter::repeat_n("--- | ---", reports.len()).collect();
    s += &format!("| --- | {} |\n", sep.join(" | "));

    let rows: &[(&str, &str)] = &[
        ("status",          "mati status"),
        ("stats_first",     "mati stats (cache miss)"),
        ("stats_avg",       "mati stats (cache hit)"),
        ("gaps_first",      "mati gaps (cache miss)"),
        ("gaps_avg",        "mati gaps (cache hit)"),
        ("ls_files",        "mati ls files"),
        ("ls_gotchas",      "mati ls gotchas"),
        ("ls_decisions",    "mati ls decisions"),
        ("stale",           "mati stale"),
        ("quality_check",   "mati quality-check"),
        ("get_1",           "mati get ×1"),
        ("show",            "mati show"),
        ("export_json",     "mati export --format json"),
        ("history",         "mati history"),
        ("edit_hook",       "mati edit-hook"),
        ("session_harvest", "mati session-harvest"),
        ("log_miss",        "mati log-miss"),
        ("log_hit",         "mati log-hit"),
    ];

    for (key, label) in rows {
        let cells: Vec<String> = reports
            .iter()
            .map(|r| {
                let c = fmt_result(r.cold.commands.get(*key));
                let w = fmt_result(r.warm.commands.get(*key));
                format!("{} | {}", c, w)
            })
            .collect();
        s += &format!("| {} | {} |\n", label, cells.join(" | "));
    }

    s + "\n---\n\n"
}

// ── Parallel gets ─────────────────────────────────────────────────────────────

fn section_parallel_gets(reports: &[RepoReport]) -> String {
    let mut s = String::from("## Sequential Get Throughput\n\n");
    s += "Wall-clock for N sequential `mati get` calls (total / N = per-get avg shown).\n";
    s += "> **Note:** SurrealKV holds a process-level LOCK — concurrent CLI invocations\n";
    s += "> against the same store conflict. Parallel access requires the MCP daemon.\n\n";
    s += "| Repo | ×1 (avg) | ×10 (avg/get) | ×25 (avg/get) |\n";
    s += "| --- | --- | --- | --- |\n";
    for r in reports {
        s += &format!(
            "| {} | {} | {} | {} |\n",
            r.repo_name,
            fmt_result(r.cold.commands.get("get_1")),
            fmt_result(r.cold.commands.get("get_10")),
            fmt_result(r.cold.commands.get("get_25")),
        );
    }
    s + "\n---\n\n"
}

// ── Cache speedup ─────────────────────────────────────────────────────────────

fn section_cache(reports: &[RepoReport]) -> String {
    let mut s = String::from("## Cache Performance\n\n");
    s += "Cache TTL: 60 seconds.\n\n";
    s += "| Command | Repo | Cold | Cached | Speedup |\n";
    s += "| --- | --- | --- | --- | --- |\n";
    for r in reports {
        for (miss_key, hit_key, label) in &[
            ("stats_first", "stats_avg", "mati stats"),
            ("gaps_first",  "gaps_avg",  "mati gaps"),
        ] {
            let cold_ms = r.cold.commands.get(*miss_key).map(|t| t.mean_ms);
            let warm_ms = r.cold.commands.get(*hit_key).map(|t| t.mean_ms);
            if let (Some(c), Some(w)) = (cold_ms, warm_ms) {
                let speedup = if w > 0.1 { c / w } else { 0.0 };
                s += &format!(
                    "| {} | {} | {:.0}ms | **{:.0}ms** | {:.0}x |\n",
                    label, r.repo_name, c, w, speedup
                );
            }
        }
    }
    s + "\n---\n\n"
}

// ── Ping latency (in-process) ─────────────────────────────────────────────────

fn section_ping(reports: &[RepoReport]) -> String {
    let mut s = String::from("## Ping Latency\n\n");
    s += "In-process KV health check (no startup overhead).\n\n";
    s += "| Repo | Wall-clock (mati ping) | Reported latency |\n";
    s += "| --- | --- | --- |\n";
    for r in reports {
        let wall = fmt_result(r.cold.commands.get("ping"));
        let reported = r.accuracy.ping_us
            .map(|us| format!("{}µs", us))
            .unwrap_or_else(|| "—".into());
        s += &format!("| {} | {} | {} |\n", r.repo_name, wall, reported);
    }
    s + "\n---\n\n"
}

// ── Accuracy & health ─────────────────────────────────────────────────────────

fn section_accuracy(reports: &[RepoReport]) -> String {
    let mut s = String::from("## Accuracy & Health Metrics\n\n");
    s += "> Coverage >100%: mati walks untracked files (`.claude/` etc.) excluded from `git ls-files`.\n\n";
    s += "| Repo | Files (mati) | Files (git) | Coverage | Confidence avg | Cold=Warm stats | Get hit rate |\n";
    s += "| --- | --- | --- | --- | --- | --- | --- |\n";
    for r in reports {
        let a = &r.accuracy;
        let cov = if a.file_count_git > 0 {
            format!("{:.0}%", 100.0 * a.file_count_mati as f64 / a.file_count_git as f64)
        } else {
            "—".into()
        };
        s += &format!(
            "| {} | {} | {} | {} | {:.2} | {} | {}% |\n",
            r.repo_name,
            a.file_count_mati,
            a.file_count_git,
            cov,
            a.confidence_avg,
            ok(a.stats_cold_warm_consistent),
            a.get_hit_rate_pct,
        );
    }
    s + "\n---\n\n"
}

// ── Gaps ─────────────────────────────────────────────────────────────────────

fn section_gaps(reports: &[RepoReport]) -> String {
    let mut s = String::from("## Knowledge Gap Distribution\n\n");
    s += "| Repo | CRITICAL | HIGH | NORMAL | LOW | Total |\n";
    s += "| --- | --- | --- | --- | --- | --- |\n";
    for r in reports {
        let g = &r.accuracy.gaps;
        s += &format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            r.repo_name, g.critical, g.high, g.normal, g.low, g.total()
        );
    }
    s + "\n---\n\n"
}

// ── Staleness ─────────────────────────────────────────────────────────────────

fn section_staleness(reports: &[RepoReport]) -> String {
    let mut s = String::from("## Staleness Distribution (post-init)\n\n");
    s += "| Repo | Records | Aging | Stale | Liability | Tombstone |\n";
    s += "| --- | --- | --- | --- | --- | --- |\n";
    for r in reports {
        let st = &r.accuracy.stale;
        s += &format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            r.repo_name,
            r.accuracy.total_records,
            st.aging, st.stale, st.liability, st.tombstone,
        );
    }
    s + "\n---\n\n"
}

// ── Data integrity ────────────────────────────────────────────────────────────

fn section_integrity(reports: &[RepoReport]) -> String {
    let mut s = String::from("## Data Integrity\n\n");
    s += "| Repo | Init OK | Export OK | Stats consistent | Gets accurate | \
          Edit-hook OK | Harvest OK |\n";
    s += "| --- | --- | --- | --- | --- | --- | --- |\n";
    for r in reports {
        let a = &r.accuracy;
        s += &format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            r.repo_name,
            ok(a.init_success),
            ok(a.export_success),
            ok(a.stats_cold_warm_consistent),
            ok(a.get_hit_rate_pct >= 90),
            ok(a.edit_hook_success),
            ok(a.harvest_success),
        );
    }
    s + "\n---\n\n"
}

// ── Store size ────────────────────────────────────────────────────────────────

fn section_store_size(reports: &[RepoReport]) -> String {
    let mut s = String::from("## Store Size\n\n");
    s += "| Repo | Records | Store size |\n";
    s += "| --- | --- | --- |\n";
    for r in reports {
        let a = &r.accuracy;
        s += &format!(
            "| {} | {} | {} |\n",
            r.repo_name,
            a.total_records,
            a.store_size_mb.map(|n| format!("{:.1}MB", n)).unwrap_or_else(|| "—".into()),
        );
    }
    s + "\n"
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn ms(stages: &std::collections::HashMap<String, u64>, key: &str) -> String {
    stages
        .get(key)
        .map(|n| format!("{}ms", n))
        .unwrap_or_else(|| "—".into())
}

fn fmt_result(r: Option<&TimedResult>) -> String {
    match r {
        None => "—".into(),
        Some(t) if !t.success && t.samples == 0 => "—".into(),
        Some(t) if !t.success => format!("**FAIL** ({:.0}ms)", t.mean_ms),
        Some(t) => format!("{:.0}ms", t.mean_ms),
    }
}

fn ok(b: bool) -> &'static str {
    if b { "yes" } else { "**FAIL**" }
}
