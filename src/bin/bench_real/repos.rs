use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

// ── Repo catalogue ───────────────────────────────────────────────────────────

pub struct RepoSpec {
    pub name: &'static str,
    pub url:  &'static str,
    pub depth: u32,
}

pub const REPOS: &[RepoSpec] = &[
    RepoSpec { name: "ripgrep", url: "https://github.com/BurntSushi/ripgrep",  depth: 100 },
    RepoSpec { name: "deno",    url: "https://github.com/denoland/deno",       depth: 100 },
    RepoSpec { name: "nextjs",  url: "https://github.com/vercel/next.js",      depth:  50 },
    RepoSpec { name: "tokio",   url: "https://github.com/tokio-rs/tokio",      depth: 100 },
];

pub fn find_spec(name: &str) -> Option<&'static RepoSpec> {
    REPOS.iter().find(|r| r.name == name)
}

// ── Clone / update ───────────────────────────────────────────────────────────

pub fn ensure_cloned(spec: &RepoSpec, cache_dir: &Path) -> PathBuf {
    let dest = cache_dir.join(spec.name);
    if dest.join(".git").exists() {
        eprintln!("  [repos] {} already cloned — reusing", spec.name);
    } else {
        eprintln!("  [repos] Cloning {} (depth={})...", spec.name, spec.depth);
        let status = Command::new("git")
            .args([
                "clone",
                "--depth",
                &spec.depth.to_string(),
                spec.url,
                dest.to_str().unwrap(),
            ])
            .status()
            .expect("git not found");
        assert!(status.success(), "git clone failed for {}", spec.name);
    }
    dest
}

// ── Store slug ───────────────────────────────────────────────────────────────
// Mirrors mati's slug derivation:
//   SHA-256(git remote url OR canonical path) → first 8 hex chars

pub fn compute_slug(repo_root: &Path) -> String {
    let input = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(repo_root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| {
            repo_root
                .canonicalize()
                .unwrap_or_else(|_| repo_root.to_path_buf())
                .to_string_lossy()
                .to_string()
        });

    let hash = Sha256::digest(input.as_bytes());
    hex::encode(&hash[..4])
}

pub fn store_dir(slug: &str) -> PathBuf {
    dirs::home_dir()
        .expect("no home dir")
        .join(".mati")
        .join(slug)
}

/// Wipe the mati store for a repo so the next init is truly cold.
pub fn clean_store(slug: &str) {
    let dir = store_dir(slug);
    if dir.exists() {
        eprintln!("  [repos] cleaning store at {}", dir.display());
        std::fs::remove_dir_all(&dir).expect("failed to remove store dir");
    }
}

/// Snapshot all dir names currently under ~/.mati/ (used to detect new stores).
#[allow(dead_code)]
pub fn snapshot_mati_dirs() -> HashSet<String> {
    let home = dirs::home_dir().unwrap_or_default();
    let mati_home = home.join(".mati");
    if !mati_home.exists() {
        return HashSet::new();
    }
    std::fs::read_dir(&mati_home)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

/// Count files known to git in the repo (respects .gitignore).
pub fn git_file_count(repo_root: &Path) -> usize {
    Command::new("git")
        .args(["ls-files"])
        .current_dir(repo_root)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
        .unwrap_or(0)
}

/// Count source files by language using git ls-files.
pub fn git_lang_counts(repo_root: &Path) -> Vec<(String, usize)> {
    let out = Command::new("git")
        .args(["ls-files"])
        .current_dir(repo_root)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for line in out.lines() {
        let ext = std::path::Path::new(line)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("other");
        let lang = match ext {
            "rs"                         => "Rust",
            "ts" | "tsx"                 => "TypeScript",
            "js" | "jsx" | "mjs" | "cjs" => "JavaScript",
            "py"                         => "Python",
            "go"                         => "Go",
            "java"                       => "Java",
            "kt" | "kts"                 => "Kotlin",
            "rb"                         => "Ruby",
            "c" | "h"                    => "C",
            "cpp" | "cc" | "cxx" | "hpp" => "C++",
            _                            => "other",
        };
        *counts.entry(lang).or_insert(0) += 1;
    }

    let mut v: Vec<(String, usize)> = counts
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v
}
