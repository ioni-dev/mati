//! `mati supervisor` — generate per-project user-level service units that
//! keep `mati daemon start` alive across crashes.
//!
//! Per-project because mati's store is per-project (slug-derived). One service
//! unit per project under `~/Library/LaunchAgents/` (macOS) or
//! `~/.config/systemd/user/` (Linux). Restart semantics: respawn only on
//! abnormal exit — a clean shutdown via SIGTERM does not trigger a restart.
//!
//! By default `install` writes the unit file and prints the activation
//! command for the user to run. Activation is never executed automatically;
//! the user reviews the file first, then runs `launchctl bootstrap` /
//! `systemctl --user enable --now` themselves.
//!
//! Use `--print` to dry-run: emits the rendered template to stdout without
//! touching the filesystem.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use mati_core::store::derive_slug;

#[derive(Args)]
pub struct SupervisorArgs {
    #[command(subcommand)]
    pub command: SupervisorCommand,
}

#[derive(Subcommand)]
pub enum SupervisorCommand {
    /// Generate and install a user-level service unit for this project.
    Install {
        /// Print the rendered unit to stdout instead of writing to disk.
        #[arg(long)]
        print: bool,
    },
    /// Remove the service unit for this project.
    Uninstall,
    /// Show whether a service unit is installed for this project.
    Status,
}

pub async fn run(args: SupervisorArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let project =
        fs::canonicalize(&cwd).with_context(|| format!("cannot canonicalize {}", cwd.display()))?;
    let slug = derive_slug(&project);

    match args.command {
        SupervisorCommand::Install { print } => install(&project, &slug, print),
        SupervisorCommand::Uninstall => uninstall(&slug),
        SupervisorCommand::Status => status(&slug),
    }
}

fn install(project: &Path, slug: &str, print_only: bool) -> Result<()> {
    let bin = std::env::current_exe().context("cannot determine mati binary path")?;
    let unit = render_unit(&bin, project, slug)?;

    if print_only {
        println!("{}", unit.contents);
        return Ok(());
    }

    // Ensure `~/.mati/<slug>/` exists BEFORE asking launchd / systemd to
    // start the daemon. The unit's StandardOutPath / StandardErrorPath
    // point inside this directory; if it's missing, launchd silently fails
    // to launch the job. Also runs the symlink-attack hardening check —
    // refuse if a hostile symlink is pre-staged at the runtime path.
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let mati_root = home.join(".mati").join(slug);
    mati_core::mcp::metadata::ensure_runtime_dir(&mati_root)
        .context("preparing mati runtime dir for supervisor logs")?;

    // Detect a live daemon and warn the user. Activating the supervisor
    // while another `mati daemon` (or `mati serve`) holds the lock will
    // fail-loop on the launchd/systemd side with the configured restart
    // backoff — the new respawn refuses to start (`run_daemon_start`
    // bails on `LiveDaemon`). Better to surface this loudly at install
    // time than to leave the user debugging silent failed restarts.
    if let Some(meta) = mati_core::mcp::metadata::read_metadata(&mati_root) {
        if mati_core::mcp::metadata::is_pid_alive(meta.pid) {
            eprintln!();
            eprintln!(
                "WARNING: a mati instance is already running (owner={}, pid={}).",
                meta.owner, meta.pid
            );
            eprintln!(
                "Activating the supervisor before stopping it will respawn-loop \
                 until that instance exits."
            );
            eprintln!("Recommended: run `mati daemon stop` before activating.");
            eprintln!();
        }
    }

    let target = unit_target_path(slug)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    fs::write(&target, &unit.contents)
        .with_context(|| format!("cannot write {}", target.display()))?;

    println!("Installed {}", target.display());
    println!("Binary path baked into unit: {}", bin.display());
    println!("    (re-run `mati supervisor install` if you move the mati binary)");
    println!();
    println!("To activate:");
    println!("  {}", unit.activate_cmd);
    println!();
    println!("To deactivate later:");
    println!("  {}", unit.deactivate_cmd);
    Ok(())
}

fn uninstall(slug: &str) -> Result<()> {
    let target = unit_target_path(slug)?;
    if !target.exists() {
        println!("No supervisor unit installed for slug {slug}");
        return Ok(());
    }
    fs::remove_file(&target).with_context(|| format!("cannot remove {}", target.display()))?;
    println!("Removed {}", target.display());
    println!();
    println!("If you previously activated it, also run:");
    println!("  {}", deactivate_hint(slug));
    Ok(())
}

fn status(slug: &str) -> Result<()> {
    let target = unit_target_path(slug)?;
    if target.exists() {
        println!("installed: {}", target.display());
    } else {
        println!("not installed (slug={slug})");
    }
    Ok(())
}

// ── Per-OS rendering ────────────────────────────────────────────────────────

struct RenderedUnit {
    contents: String,
    activate_cmd: String,
    deactivate_cmd: String,
}

fn render_unit(bin: &Path, project: &Path, slug: &str) -> Result<RenderedUnit> {
    #[cfg(target_os = "macos")]
    {
        Ok(render_launchd(bin, project, slug))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(render_systemd(bin, project, slug))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (bin, project, slug);
        anyhow::bail!("supervisor install is only supported on macOS (launchd) and Linux (systemd)")
    }
}

fn unit_target_path(slug: &str) -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    #[cfg(target_os = "macos")]
    {
        Ok(home
            .join("Library/LaunchAgents")
            .join(format!("com.mati.{slug}.plist")))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(home
            .join(".config/systemd/user")
            .join(format!("mati-{slug}.service")))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (home, slug);
        anyhow::bail!("supervisor is only supported on macOS and Linux")
    }
}

fn deactivate_hint(slug: &str) -> String {
    #[cfg(target_os = "macos")]
    {
        format!("launchctl bootout gui/$(id -u)/com.mati.{slug} 2>/dev/null || true")
    }
    #[cfg(target_os = "linux")]
    {
        format!("systemctl --user disable --now mati-{slug}.service")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = slug;
        String::from("(unsupported OS)")
    }
}

#[cfg(target_os = "macos")]
fn render_launchd(bin: &Path, project: &Path, slug: &str) -> RenderedUnit {
    let label = format!("com.mati.{slug}");
    let log_dir = dirs::home_dir()
        .unwrap_or_default()
        .join(".mati")
        .join(slug);
    let stdout_log = log_dir.join("supervisor.stdout.log");
    let stderr_log = log_dir.join("supervisor.stderr.log");

    let contents = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>daemon</string>
        <string>start</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{project}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>StandardOutPath</key>
    <string>{stdout_log}</string>
    <key>StandardErrorPath</key>
    <string>{stderr_log}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin</string>
    </dict>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#,
        bin = xml_escape(&bin.display().to_string()),
        project = xml_escape(&project.display().to_string()),
        stdout_log = xml_escape(&stdout_log.display().to_string()),
        stderr_log = xml_escape(&stderr_log.display().to_string()),
    );

    let target = unit_target_path(slug).unwrap_or_default();
    let activate_cmd = format!("launchctl bootstrap gui/$(id -u) {}", target.display());
    let deactivate_cmd = deactivate_hint(slug);
    RenderedUnit {
        contents,
        activate_cmd,
        deactivate_cmd,
    }
}

#[cfg(target_os = "linux")]
fn render_systemd(bin: &Path, project: &Path, slug: &str) -> RenderedUnit {
    let contents = format!(
        r#"[Unit]
Description=mati daemon (project slug {slug})
After=default.target

[Service]
Type=simple
ExecStart={bin} daemon start
WorkingDirectory={project}
Restart=on-failure
RestartSec=5
# Don't churn on persistent failures.
StartLimitIntervalSec=300
StartLimitBurst=5
# Reasonable resource bounds for a single-user knowledge-store daemon.
MemoryHigh=512M
MemoryMax=1G

[Install]
WantedBy=default.target
"#,
        bin = bin.display(),
        project = project.display(),
        slug = slug,
    );
    let activate_cmd = format!(
        "systemctl --user daemon-reload && systemctl --user enable --now mati-{slug}.service"
    );
    let deactivate_cmd = deactivate_hint(slug);
    RenderedUnit {
        contents,
        activate_cmd,
        deactivate_cmd,
    }
}

/// Escape a string for embedding in a launchd plist. macOS-only because
/// the systemd unit format does not require XML escaping — keeping this
/// `#[cfg(target_os = "macos")]` avoids a `dead_code` warning on Linux CI
/// where `render_launchd` is not compiled.
#[cfg(target_os = "macos")]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_plist_contains_required_fields() {
        let bin = PathBuf::from("/usr/local/bin/mati");
        let project = PathBuf::from("/Users/example/repo");
        let unit = render_launchd(&bin, &project, "abcd1234");

        // Label is unique per slug.
        assert!(unit.contents.contains("<string>com.mati.abcd1234</string>"));
        // ProgramArguments invokes the headless daemon entry point.
        assert!(unit.contents.contains("<string>daemon</string>"));
        assert!(unit.contents.contains("<string>start</string>"));
        // WorkingDirectory is the project path.
        assert!(unit
            .contents
            .contains("<string>/Users/example/repo</string>"));
        // KeepAlive only on failure (SuccessfulExit=false).
        assert!(unit.contents.contains("<key>SuccessfulExit</key>"));
        assert!(unit.contents.contains("<false/>"));
        // ThrottleInterval prevents tight respawn loops.
        assert!(unit.contents.contains("<key>ThrottleInterval</key>"));
        // Activation command names the right plist.
        assert!(unit.activate_cmd.contains("com.mati.abcd1234.plist"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_plist_xml_escapes_paths() {
        // A path containing < or & must be escaped — otherwise the plist
        // is malformed and launchctl rejects it silently.
        let bin = PathBuf::from("/tmp/has<bad>&chars/mati");
        let project = PathBuf::from("/tmp/proj");
        let unit = render_launchd(&bin, &project, "x");
        assert!(unit.contents.contains("has&lt;bad&gt;&amp;chars"));
        assert!(!unit.contents.contains("has<bad>&chars"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_unit_contains_required_fields() {
        let bin = PathBuf::from("/usr/local/bin/mati");
        let project = PathBuf::from("/home/example/repo");
        let unit = render_systemd(&bin, &project, "abcd1234");

        assert!(unit
            .contents
            .contains("ExecStart=/usr/local/bin/mati daemon start"));
        assert!(unit
            .contents
            .contains("WorkingDirectory=/home/example/repo"));
        assert!(unit.contents.contains("Restart=on-failure"));
        assert!(unit.contents.contains("StartLimitBurst=5"));
        assert!(unit.activate_cmd.contains("mati-abcd1234.service"));
    }

    #[test]
    fn unit_target_path_uses_per_os_convention() {
        let target = unit_target_path("abcd1234").unwrap();
        let s = target.display().to_string();
        #[cfg(target_os = "macos")]
        assert!(s.contains("Library/LaunchAgents/com.mati.abcd1234.plist"));
        #[cfg(target_os = "linux")]
        assert!(s.contains(".config/systemd/user/mati-abcd1234.service"));
    }

    #[test]
    fn deactivate_hint_names_correct_unit() {
        let hint = deactivate_hint("abcd1234");
        #[cfg(target_os = "macos")]
        assert!(hint.contains("com.mati.abcd1234"));
        #[cfg(target_os = "linux")]
        assert!(hint.contains("mati-abcd1234.service"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn xml_escape_handles_special_chars() {
        assert_eq!(xml_escape("a&b"), "a&amp;b");
        assert_eq!(xml_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(xml_escape("plain"), "plain");
    }
}
