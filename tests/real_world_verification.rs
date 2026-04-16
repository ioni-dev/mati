//! Real-world verification tests that run mati against external open-source
//! codebases to catch silent resolver and blast radius regressions on real code.
//!
//! These tests are marked `#[ignore]` because they require cloning external
//! repositories from GitHub, which is too expensive for normal `cargo test` runs.
//! Run them explicitly with:
//!
//!     cargo test --test real_world_verification -- --ignored
//!
//! Run before every release to catch silent correctness drift.
//!
//! Verification targets:
//! - Rust:       BurntSushi/ripgrep   (Cargo workspace — known resolver gap)
//! - Python:     encode/httpx          (single package + tests)
//! - TypeScript: vitest-dev/vitest     (pnpm monorepo)
//! - C++:        nlohmann/json         (angle-bracket internal includes)
//! - Haskell:    haskell/aeson         (Data.Aeson.* stdlib over-classification)
//! - Scala:      zio/zio-json          (sbt multi-project source roots)
//! - Ruby:       sinatra/sinatra       (Normal require lib/ fallback)
//!
//! ## Measurement baselines (2026-04-15, updated after Rails autoload support)
//!
//! | Codebase      | Edges | Resolution | Hub tier              | Notes                              |
//! |---------------|-------|------------|-----------------------|------------------------------------|
//! | ripgrep       |   342 | intra+cross| grep_matcher moderate | brace decomposition + cross-crate  |
//! | httpx         |   124 | ~100%      | __init__.py high      | healthy                            |
//! | vitest        |  2147 | ~97%       | core.ts critical      | healthy                            |
//! | nlohmann-json |   619 | ~84%       | json.hpp critical     | angle-bracket fix (Phase 2)        |
//! | aeson         |   223 | ~50%       | Aeson.hs critical     | stdlib allowlist fix (Phase 2)     |
//! | zio-json      |    21 | ~8%        | —                     | source root fix, wildcard limited  |
//! | sinatra       |   145 | ~60%       | base.rb high          | lib/ fallback fix (Phase 2)        |
//! | discourse     |  2622 | struct     | AppController critical| Rails autoload (Inherits/Includes) |
//! | solidus       |  1090 | struct     | core.rb moderate      | monorepo autoload + lib/ roots     |

use std::path::PathBuf;
use std::process::Command;

const VERIFICATION_DIR: &str = "/tmp/mati-verification";

// ── Helpers ─────────────────────────────────────────────────────────────────

fn mati_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_mati") {
        return PathBuf::from(p);
    }
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(manifest)
        .join("target")
        .join("debug")
        .join("mati")
}

fn clone_or_reuse(name: &str, url: &str) -> PathBuf {
    let dir = PathBuf::from(VERIFICATION_DIR).join(name);
    if !dir.join(".git").exists() {
        std::fs::create_dir_all(VERIFICATION_DIR).unwrap();
        let status = Command::new("git")
            .args(["clone", "--depth", "1", url, dir.to_str().unwrap()])
            .status()
            .expect("git clone failed — is git installed?");
        assert!(status.success(), "failed to clone {url}");
    }
    dir
}

/// Run `mati init` and return (init_stdout, slug).
/// Extracts the slug from the first output line: `◈  mati — project: X  (slug: YYYYYYYY)`
fn run_init(repo: &PathBuf) -> (String, String) {
    let output = Command::new(mati_bin())
        .arg("init")
        .current_dir(repo)
        .output()
        .expect("mati init failed to execute");
    assert!(
        output.status.success(),
        "mati init failed for {repo:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Parse slug from "◈  mati — project: X  (slug: YYYYYYYY)"
    let slug = stdout
        .lines()
        .find_map(|line| {
            let start = line.find("slug: ")?;
            let rest = &line[start + 6..];
            let end = rest.find(')')?;
            Some(rest[..end].to_string())
        })
        .unwrap_or_default();

    (stdout, slug)
}

/// Delete the mati store for a given slug so the next `mati init` is fresh.
fn clean_store(slug: &str) {
    if slug.is_empty() {
        return;
    }
    let store_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".mati")
        .join(slug);
    if store_dir.exists() {
        let _ = std::fs::remove_dir_all(&store_dir);
    }
}

/// Run `mati init` with a guaranteed fresh store. Returns (stdout, slug).
fn fresh_init(repo: &PathBuf) -> (String, String) {
    // First run to discover the slug (may be incremental).
    let (_, slug) = run_init(repo);
    // Clean the store so next init is fresh.
    clean_store(&slug);
    // Second run: full fresh scan.
    run_init(repo)
}

/// Parse the "graph edges:" line from `mati init` output.
fn parse_edge_count(init_output: &str) -> usize {
    for line in init_output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("graph edges:") {
            let after_colon = trimmed.strip_prefix("graph edges:").unwrap().trim();
            let num_str = after_colon.split_whitespace().next().unwrap_or("0");
            return num_str.parse::<usize>().unwrap_or(0);
        }
    }
    0
}

/// Parse the "file records:" line from `mati init` output.
fn parse_file_count(init_output: &str) -> usize {
    for line in init_output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("file records:") {
            let after_colon = trimmed.strip_prefix("file records:").unwrap().trim();
            let num_str = after_colon.split_whitespace().next().unwrap_or("0");
            return num_str.parse::<usize>().unwrap_or(0);
        }
    }
    0
}

/// Run `mati show <key>` and return stdout.
fn run_show(repo: &PathBuf, key: &str) -> Option<String> {
    let output = Command::new(mati_bin())
        .args(["show", key])
        .current_dir(repo)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Parse blast radius tier from `mati show` output.
fn parse_blast_tier(show_output: &str) -> String {
    let mut in_blast = false;
    for line in show_output.lines() {
        let trimmed = line.trim();
        if trimmed == "blast radius" {
            in_blast = true;
            continue;
        }
        if in_blast && trimmed.starts_with("tier") {
            return trimmed
                .strip_prefix("tier")
                .unwrap_or("")
                .trim()
                .to_string();
        }
        if in_blast
            && !trimmed.is_empty()
            && !trimmed.starts_with("direct")
            && !trimmed.starts_with("transitive")
            && !trimmed.starts_with("score")
            && !trimmed.starts_with("tier")
        {
            break;
        }
    }
    "unknown".to_string()
}

/// Parse blast radius direct count from `mati show` output.
fn parse_blast_direct(show_output: &str) -> usize {
    let mut in_blast = false;
    for line in show_output.lines() {
        let trimmed = line.trim();
        if trimmed == "blast radius" {
            in_blast = true;
            continue;
        }
        if in_blast && trimmed.starts_with("direct") {
            let num_str = trimmed.strip_prefix("direct").unwrap_or("0").trim();
            return num_str.parse::<usize>().unwrap_or(0);
        }
    }
    0
}

// ── ripgrep (Rust) ──────────────────────────────────────────────────────────
//
// Each codebase gets ONE test to avoid database lock contention — mati stores
// data in ~/.mati/<slug>/ and parallel inits on the same slug deadlock.

#[test]
#[ignore = "real_world: requires network and external repos"]
fn real_world_ripgrep() {
    let repo = clone_or_reuse("ripgrep", "https://github.com/BurntSushi/ripgrep");
    let (output, _slug) = fresh_init(&repo);

    // ── Resolution rate ─────────────────────────────────────────────────
    let edges = parse_edge_count(&output);
    let files = parse_file_count(&output);

    assert!(
        files >= 50,
        "ripgrep should index at least 50 files, got {files}"
    );

    // Baseline 2026-04-14: 342 edges, 214 files (brace decomposition + cross-crate).
    // Floor set ~5% below measured rate: 325 edges minimum.
    assert!(
        edges >= 325,
        "ripgrep resolution regressed: expected >= 325 edges (baseline 342), got {edges}"
    );

    eprintln!("[real_world_ripgrep] files={files} edges={edges}");

    // ── Hub file blast radius ───────────────────────────────────────────
    // grep_matcher is the most-imported crate in the workspace (used by
    // searcher, regex, printer, pcre2, and others).
    let key = "file:crates/matcher/src/lib.rs";
    let show_out = run_show(&repo, key)
        .unwrap_or_else(|| panic!("{key} not found — ripgrep may have restructured"));
    let tier = parse_blast_tier(&show_out);
    let direct = parse_blast_direct(&show_out);

    assert!(
        ["moderate", "high", "critical"].contains(&tier.as_str()),
        "ripgrep grep-matcher lib.rs should be moderate or higher, got tier={tier}"
    );
    assert!(
        direct >= 4,
        "ripgrep grep-matcher lib.rs should have >= 4 direct importers (baseline 6), got {direct}"
    );

    eprintln!("[real_world_ripgrep] {key} tier={tier} direct={direct}");

    // grep_regex crate — imported by printer and others.
    if let Some(show_out2) = run_show(&repo, "file:crates/regex/src/lib.rs") {
        let tier2 = parse_blast_tier(&show_out2);
        let direct2 = parse_blast_direct(&show_out2);
        eprintln!(
            "[real_world_ripgrep] file:crates/regex/src/lib.rs tier={tier2} direct={direct2}"
        );
    }
}

// ── httpx (Python) ──────────────────────────────────────────────────────────

#[test]
#[ignore = "real_world: requires network and external repos"]
fn real_world_httpx() {
    let repo = clone_or_reuse("httpx", "https://github.com/encode/httpx");
    let (output, _slug) = fresh_init(&repo);

    // ── Resolution rate ─────────────────────────────────────────────────
    let edges = parse_edge_count(&output);
    let files = parse_file_count(&output);

    // Baseline 2026-04-14: 124 edges, 115 files.
    // Floor set 5pp below measured rate (~100% → 95%): 100 edges minimum.
    assert!(
        files >= 50,
        "httpx should index at least 50 files, got {files}"
    );
    assert!(
        edges >= 100,
        "httpx resolution regressed: expected >= 100 edges (baseline 124), got {edges}"
    );

    eprintln!("[real_world_httpx] files={files} edges={edges}");

    // ── Hub file blast radius ───────────────────────────────────────────
    // httpx/__init__.py: baseline high tier, 32 direct importers.
    let key = "file:httpx/__init__.py";
    let show_out = run_show(&repo, key)
        .unwrap_or_else(|| panic!("{key} not found — httpx may have restructured"));
    let tier = parse_blast_tier(&show_out);
    let direct = parse_blast_direct(&show_out);

    assert!(
        ["moderate", "high", "critical"].contains(&tier.as_str()),
        "httpx/__init__.py should be moderate or higher, got tier={tier}"
    );
    assert!(
        direct >= 15,
        "httpx/__init__.py should have >= 15 direct importers (baseline 32), got {direct}"
    );

    eprintln!("[real_world_httpx] {key} tier={tier} direct={direct}");

    // httpx/_models.py: baseline moderate tier, 13 direct.
    if let Some(show_out2) = run_show(&repo, "file:httpx/_models.py") {
        let tier2 = parse_blast_tier(&show_out2);
        let direct2 = parse_blast_direct(&show_out2);
        assert!(
            ["low", "moderate", "high", "critical"].contains(&tier2.as_str()),
            "httpx/_models.py should be at least low tier, got tier={tier2}"
        );
        eprintln!("[real_world_httpx] file:httpx/_models.py tier={tier2} direct={direct2}");
    }

    // httpx/_client.py: baseline low tier, 3 direct.
    if let Some(show_out3) = run_show(&repo, "file:httpx/_client.py") {
        let tier3 = parse_blast_tier(&show_out3);
        let direct3 = parse_blast_direct(&show_out3);
        eprintln!("[real_world_httpx] file:httpx/_client.py tier={tier3} direct={direct3}");
    }
}

// ── vitest (TypeScript) ─────────────────────────────────────────────────────

#[test]
#[ignore = "real_world: requires network and external repos"]
fn real_world_vitest() {
    let repo = clone_or_reuse("vitest", "https://github.com/vitest-dev/vitest");
    let (output, _slug) = fresh_init(&repo);

    // ── Resolution rate ─────────────────────────────────────────────────
    let edges = parse_edge_count(&output);
    let files = parse_file_count(&output);

    // Baseline 2026-04-14: 2147 edges, 2808 files.
    // Floor set conservatively at 1500 (allows for repo restructuring).
    assert!(
        files >= 1000,
        "vitest should index at least 1000 files, got {files}"
    );
    assert!(
        edges >= 1500,
        "vitest resolution regressed: expected >= 1500 edges (baseline 2147), got {edges}"
    );

    eprintln!("[real_world_vitest] files={files} edges={edges}");

    // ── Hub file blast radius ───────────────────────────────────────────
    // packages/vitest/src/node/core.ts: baseline critical tier, 43 direct.
    let key = "file:packages/vitest/src/node/core.ts";
    let show_out = run_show(&repo, key)
        .unwrap_or_else(|| panic!("{key} not found — vitest may have restructured"));
    let tier = parse_blast_tier(&show_out);
    let direct = parse_blast_direct(&show_out);

    assert!(
        ["high", "critical"].contains(&tier.as_str()),
        "vitest node/core.ts should be high or critical, got tier={tier}"
    );
    assert!(
        direct >= 20,
        "vitest node/core.ts should have >= 20 direct importers (baseline 43), got {direct}"
    );

    eprintln!("[real_world_vitest] {key} tier={tier} direct={direct}");

    // packages/vitest/src/node/project.ts: baseline high tier, 33 direct.
    if let Some(show_out2) = run_show(&repo, "file:packages/vitest/src/node/project.ts") {
        let tier2 = parse_blast_tier(&show_out2);
        let direct2 = parse_blast_direct(&show_out2);
        assert!(
            ["moderate", "high", "critical"].contains(&tier2.as_str()),
            "vitest node/project.ts should be moderate or higher, got tier={tier2}"
        );
        eprintln!(
            "[real_world_vitest] file:packages/vitest/src/node/project.ts tier={tier2} direct={direct2}"
        );
    }

    // packages/vitest/src/node/types/config.ts: baseline high tier, 36 direct.
    if let Some(show_out3) = run_show(&repo, "file:packages/vitest/src/node/types/config.ts") {
        let tier3 = parse_blast_tier(&show_out3);
        let direct3 = parse_blast_direct(&show_out3);
        eprintln!(
            "[real_world_vitest] file:packages/vitest/src/node/types/config.ts tier={tier3} direct={direct3}"
        );
    }
}

// ── nlohmann-json (C++) ────────────────────────────────────────────────
//
// Phase 2 fix: angle-bracket includes resolved as internal when they match
// a repo file. Baseline before fix: 134 edges. After fix: 619 edges.

#[test]
#[ignore = "real_world: requires network and external repos"]
fn real_world_nlohmann_json_resolution() {
    let repo = clone_or_reuse("nlohmann-json", "https://github.com/nlohmann/json");
    let (output, _slug) = fresh_init(&repo);

    let edges = parse_edge_count(&output);
    let files = parse_file_count(&output);

    assert!(
        files >= 500,
        "nlohmann-json should index at least 500 files, got {files}"
    );

    // Baseline 2026-04-15: 619 edges (angle-bracket fix).
    // Floor set ~5% below: 588 edges minimum.
    assert!(
        edges >= 588,
        "nlohmann-json resolution regressed: expected >= 588 edges (baseline 619), got {edges}"
    );

    eprintln!("[real_world_nlohmann_json] files={files} edges={edges}");

    // json.hpp is the hub header — should be critical after the fix.
    let key = "file:include/nlohmann/json.hpp";
    let show_out = run_show(&repo, key)
        .unwrap_or_else(|| panic!("{key} not found — nlohmann-json may have restructured"));
    let tier = parse_blast_tier(&show_out);
    let direct = parse_blast_direct(&show_out);

    assert!(
        ["high", "critical"].contains(&tier.as_str()),
        "nlohmann json.hpp should be high or critical, got tier={tier}"
    );
    assert!(
        direct >= 100,
        "nlohmann json.hpp should have >= 100 direct importers (baseline 319), got {direct}"
    );

    eprintln!("[real_world_nlohmann_json] {key} tier={tier} direct={direct}");
}

// ── aeson (Haskell) ────────────────────────────────────────────────────
//
// Phase 2 fix: stdlib allowlist no longer kills Data.Aeson.* imports.
// Baseline before fix: 0 edges. After fix: 223 edges.

#[test]
#[ignore = "real_world: requires network and external repos"]
fn real_world_aeson_resolution() {
    let repo = clone_or_reuse("aeson", "https://github.com/haskell/aeson");
    let (output, _slug) = fresh_init(&repo);

    let edges = parse_edge_count(&output);
    let files = parse_file_count(&output);

    assert!(
        files >= 100,
        "aeson should index at least 100 files, got {files}"
    );

    // Baseline 2026-04-15: 223 edges (stdlib allowlist fix).
    // Floor set ~5% below: 211 edges minimum.
    assert!(
        edges >= 211,
        "aeson resolution regressed: expected >= 211 edges (baseline 223), got {edges}"
    );

    eprintln!("[real_world_aeson] files={files} edges={edges}");

    // Data/Aeson.hs is the hub module — should be critical after the fix.
    let key = "file:src/Data/Aeson.hs";
    let show_out = run_show(&repo, key)
        .unwrap_or_else(|| panic!("{key} not found — aeson may have restructured"));
    let tier = parse_blast_tier(&show_out);
    let direct = parse_blast_direct(&show_out);

    assert!(
        ["high", "critical"].contains(&tier.as_str()),
        "aeson Data/Aeson.hs should be high or critical, got tier={tier}"
    );
    assert!(
        direct >= 20,
        "aeson Data/Aeson.hs should have >= 20 direct importers (baseline 52), got {direct}"
    );

    eprintln!("[real_world_aeson] {key} tier={tier} direct={direct}");
}

// ── zio-json (Scala) ───────────────────────────────────────────────────
//
// Phase 2 fix: sbt multi-project source root detection.
// Baseline before fix: 0 edges. After fix: 21 edges.
// Most imports use wildcard `._` which resolves to the package prefix,
// not individual files — a known limitation.

#[test]
#[ignore = "real_world: requires network and external repos"]
fn real_world_zio_json_resolution() {
    let repo = clone_or_reuse("zio-json", "https://github.com/zio/zio-json");
    let (output, _slug) = fresh_init(&repo);

    let edges = parse_edge_count(&output);
    let files = parse_file_count(&output);

    assert!(
        files >= 100,
        "zio-json should index at least 100 files, got {files}"
    );

    // Baseline 2026-04-15: 21 edges (source root fix).
    // Floor set ~20% below because the number is small: 16 edges minimum.
    assert!(
        edges >= 16,
        "zio-json resolution regressed: expected >= 16 edges (baseline 21), got {edges}"
    );

    eprintln!("[real_world_zio_json] files={files} edges={edges}");
}

// ── sinatra (Ruby) ─────────────────────────────────────────────────────
//
// Phase 2 fix: Normal require now tries lib/ prefix.
// Baseline before fix: 63 edges. After fix: 93 edges.

#[test]
#[ignore = "real_world: requires network and external repos"]
fn real_world_sinatra_resolution() {
    let repo = clone_or_reuse("sinatra", "https://github.com/sinatra/sinatra");
    let (output, _slug) = fresh_init(&repo);

    let edges = parse_edge_count(&output);
    let files = parse_file_count(&output);

    assert!(
        files >= 100,
        "sinatra should index at least 100 files, got {files}"
    );

    // Baseline 2026-04-15: 145 edges (lib/ fallback + Inherits/Includes).
    // Floor set ~10% below: 130 edges minimum.
    assert!(
        edges >= 130,
        "sinatra resolution regressed: expected >= 130 edges (baseline 145), got {edges}"
    );

    eprintln!("[real_world_sinatra] files={files} edges={edges}");

    // lib/sinatra/base.rb is the hub — should be high or above after the fix.
    let key = "file:lib/sinatra/base.rb";
    let show_out = run_show(&repo, key)
        .unwrap_or_else(|| panic!("{key} not found — sinatra may have restructured"));
    let tier = parse_blast_tier(&show_out);
    let direct = parse_blast_direct(&show_out);

    assert!(
        ["moderate", "high", "critical"].contains(&tier.as_str()),
        "sinatra base.rb should be moderate or higher, got tier={tier}"
    );
    assert!(
        direct >= 10,
        "sinatra base.rb should have >= 10 direct importers (baseline 21), got {direct}"
    );

    eprintln!("[real_world_sinatra] {key} tier={tier} direct={direct}");
}

// ── discourse (Ruby/Rails) ────────────────────────────────────────────
//
// Rails autoload fix: Inherits + Includes + Zeitwerk path resolution.
// Baseline before fix: 1207 edges, ApplicationController isolated.
// After fix: 2622 edges, ApplicationController critical (102 direct).

#[test]
#[ignore = "real_world: requires network and external repos"]
fn real_world_discourse_application_controller_is_hub() {
    let repo = clone_or_reuse("discourse", "https://github.com/discourse/discourse");
    let (output, _slug) = fresh_init(&repo);

    let edges = parse_edge_count(&output);
    let files = parse_file_count(&output);

    assert!(
        files >= 10000,
        "discourse should index at least 10000 files, got {files}"
    );

    // Baseline 2026-04-15: 2622 edges (Inherits + Includes + Zeitwerk).
    // Floor set ~15% below: 2200 edges minimum.
    assert!(
        edges >= 2200,
        "discourse resolution regressed: expected >= 2200 edges (baseline 2622), got {edges}"
    );

    eprintln!("[real_world_discourse] files={files} edges={edges}");

    // ApplicationController is the most-inherited controller in any Rails app.
    // Baseline: 102 direct importers, critical tier.
    let key = "file:app/controllers/application_controller.rb";
    let show_out = run_show(&repo, key)
        .unwrap_or_else(|| panic!("{key} not found — discourse may have restructured"));
    let tier = parse_blast_tier(&show_out);
    let direct = parse_blast_direct(&show_out);

    assert!(
        ["moderate", "high", "critical"].contains(&tier.as_str()),
        "discourse ApplicationController should be moderate or higher, got tier={tier}"
    );
    assert!(
        direct >= 50,
        "discourse ApplicationController should have >= 50 direct importers (baseline 102), got {direct}"
    );

    eprintln!("[real_world_discourse] {key} tier={tier} direct={direct}");
}

// ── solidus (Ruby/Rails monorepo) ─────────────────────────────────────
//
// Rails autoload fix + monorepo lib/ root discovery.
// Baseline before fix: 30 edges, all hub files isolated.
// After fix: 1090 edges, core.rb moderate (7 direct).

#[test]
#[ignore = "real_world: requires network and external repos"]
fn real_world_solidus_core_is_hub() {
    let repo = clone_or_reuse("solidus", "https://github.com/solidusio/solidus");
    let (output, _slug) = fresh_init(&repo);

    let edges = parse_edge_count(&output);
    let files = parse_file_count(&output);

    assert!(
        files >= 2000,
        "solidus should index at least 2000 files, got {files}"
    );

    // Baseline 2026-04-15: 1090 edges (autoload roots + monorepo lib/).
    // Floor set ~15% below: 900 edges minimum.
    assert!(
        edges >= 900,
        "solidus resolution regressed: expected >= 900 edges (baseline 1090), got {edges}"
    );

    eprintln!("[real_world_solidus] files={files} edges={edges}");

    // Spree::Core is the central entry point for the core engine.
    // Baseline: 7 direct importers, moderate tier.
    let key = "file:core/lib/spree/core.rb";
    let show_out = run_show(&repo, key)
        .unwrap_or_else(|| panic!("{key} not found — solidus may have restructured"));
    let tier = parse_blast_tier(&show_out);
    let direct = parse_blast_direct(&show_out);

    assert!(
        ["low", "moderate", "high", "critical"].contains(&tier.as_str()),
        "solidus core.rb should be low or higher, got tier={tier}"
    );
    assert!(
        direct >= 3,
        "solidus core.rb should have >= 3 direct importers (baseline 7), got {direct}"
    );

    eprintln!("[real_world_solidus] {key} tier={tier} direct={direct}");
}
