//! `mati demo` — the enforcement loop, end to end, on a throwaway repo.
//!
//! Every step runs the real binary: the same `hook-decide claude-pre-read`
//! Claude Code invokes, against a store under the demo's own `MATI_HOME`.

use anyhow::{bail, Context, Result};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

const FILE: &str = "payments.py";
const CODE: &str = "\
def capture_payment(charge_id, db):
    # Looks redundant next to the DB unique constraint. It is not.
    if db.charge_exists(charge_id):
        return
    db.insert_charge(charge_id)
";
const RULE: &str = "Never remove the duplicate charge_id check in capture_payment()";
const REASON: &str =
    "the webhook retry path re-enters with an already-inserted row and double-charges the customer";

struct Demo {
    exe: PathBuf,
    dir: PathBuf,
}

impl Demo {
    fn repo(&self) -> PathBuf {
        self.dir.join("repo")
    }

    /// Run `mati` inside the demo repo. Inherited lockdown or a disabled
    /// daemon would change what the gate decides, so neither reaches it.
    fn mati(&self, args: &[&str], stdin: Option<&str>) -> Result<String> {
        let mut child = Command::new(&self.exe)
            .args(args)
            .current_dir(self.repo())
            .env("MATI_HOME", self.dir.join("h"))
            .env_remove("MATI_LOCKDOWN")
            .env_remove("MATI_DISABLE_AUTO_SPAWN")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to run mati {}", args.join(" ")))?;
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .expect("stdin is piped")
                .write_all(input.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!(
                "mati {} failed:\n{}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Send the PreToolUse payload Claude Code sends for a `Read`.
    fn agent_reads(&self) -> Result<(String, String)> {
        let payload = serde_json::json!({
            "session_id": "mati-demo",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": { "file_path": self.repo().join(FILE) },
            "cwd": self.repo(),
        });
        let out = self.mati(
            &["hook-decide", "claude-pre-read"],
            Some(&payload.to_string()),
        )?;
        let decision: serde_json::Value =
            serde_json::from_str(&out).with_context(|| format!("unexpected hook output: {out}"))?;
        let field = |k: &str| {
            decision["hookSpecificOutput"][k]
                .as_str()
                .unwrap_or_default()
                .to_string()
        };
        let message = match field("permissionDecisionReason") {
            reason if reason.is_empty() => field("additionalContext"),
            reason => reason,
        };
        Ok((field("permissionDecision"), message))
    }
}

impl Drop for Demo {
    fn drop(&mut self) {
        let _ = self.mati(&["daemon", "stop"], None);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn git(repo: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("git")
        .args([
            "-c",
            "user.name=mati-demo",
            "-c",
            "user.email=demo@mati.invalid",
        ])
        .args(args)
        .current_dir(repo)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("mati demo needs git on PATH")?;
    if !status.success() {
        bail!("git {} failed", args.join(" "));
    }
    Ok(())
}

fn step(n: u32, label: &str, started: Instant) {
    println!("  {n}. {label:<40} {:>5}ms", started.elapsed().as_millis());
}

pub fn run() -> Result<()> {
    // Short path: the daemon socket lives under it, and Unix caps socket paths.
    let dir = std::env::temp_dir().join(format!("mati-demo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let demo = Demo {
        exe: std::env::current_exe()?,
        dir,
    };
    std::fs::create_dir_all(demo.repo())?;
    std::fs::write(demo.repo().join(FILE), CODE)?;
    git(&demo.repo(), &["init", "-q"])?;
    git(&demo.repo(), &["add", "."])?;
    git(&demo.repo(), &["commit", "-q", "-m", "demo"])?;

    println!();
    println!("mati demo: the enforcement loop on a throwaway repo");
    println!(
        "  repo: {}  (deleted when the demo ends)",
        demo.repo().display()
    );
    println!();

    let t = Instant::now();
    demo.mati(&["init", "--no-hooks"], None)?;
    let created = demo.mati(
        &[
            "gotcha", "add", FILE, "-r", RULE, "-m", REASON, "-s", "critical",
        ],
        None,
    )?;
    let key = created
        .split_whitespace()
        .find(|w| w.starts_with("gotcha:"))
        .with_context(|| format!("no gotcha key in: {created}"))?
        .to_string();
    demo.mati(&["gotcha", "confirm", &key], None)?;
    demo.mati(&["ping"], None)?;
    step(1, "Record a confirmed gotcha", t);
    println!("     {FILE}: {RULE}");
    println!();

    let t = Instant::now();
    let (decision, message) = demo.agent_reads()?;
    if decision != "deny" {
        bail!("expected the first read to be denied, got {decision:?}: {message}");
    }
    step(2, &format!("Agent reads {FILE}  -> DENY"), t);
    println!("     {message}");
    println!();

    let t = Instant::now();
    demo.mati(&["explain", FILE], None)?;
    step(3, "Agent consults the record", t);
    println!("     An agent calls mem_get(\"file:{FILE}\"); here `mati explain` does the same.");
    println!();

    let t = Instant::now();
    let (decision, message) = demo.agent_reads()?;
    if decision != "allow" {
        bail!("expected the read after consulting to be allowed, got {decision:?}: {message}");
    }
    step(4, &format!("Agent reads {FILE}  -> ALLOW"), t);
    println!("     {message}");
    println!();
    println!("  In a real repo: mati init --claude, then mati gotcha add <file>.");
    println!();
    Ok(())
}
