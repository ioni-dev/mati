use super::*;
use mati_core::scaffold::settings::install_hooks_with_options;

// ── Scaffold installation (no store access) ─────────────────────────────────

/// Install agent hooks and scaffold files. Returns (claude_installed, codex_installed).
///
/// This function only writes files to disk — it never opens the store or
/// contacts the daemon. Safe to call even when the daemon holds the lock.
pub fn install_scaffold(root: &std::path::Path, args: &InitArgs) -> Result<(bool, bool)> {
    let explicit_platform = args.claude || args.codex;
    let has_claude_dir = root.join(".claude").is_dir();
    let has_codex_dir = root.join(".codex").is_dir();

    // Platform selection:
    //   Flags present       → install exactly what was requested.
    //   No flags + dirs     → auto-detect from existing .claude/ and .codex/.
    //   No flags + no dirs  → scan only, guide user to pick a platform.
    let install_claude_integration = !args.no_hooks
        && if explicit_platform {
            args.claude
        } else {
            has_claude_dir
        };
    let install_codex_integration = !args.no_hooks
        && if explicit_platform {
            args.codex
        } else {
            has_codex_dir
        };

    if !args.no_hooks && !explicit_platform && !has_claude_dir && !has_codex_dir {
        println!("  No platform detected (.claude/ or .codex/ not found).");
        println!("  Skipping hook installation. To install, run:");
        println!();
        println!("    mati init --claude    # for Claude Code");
        println!("    mati init --codex     # for Codex");
        println!();
    }
    let mut claude_installed = false;
    let mut codex_installed = false;

    if install_claude_integration {
        let claude_dir = root.join(".claude");
        if !claude_dir.is_dir() {
            let _ = std::fs::create_dir_all(&claude_dir);
        }
        let t = Instant::now();
        match write_claude_md_stub(root) {
            Ok(_) => println!(
                "  Writing .claude/CLAUDE.md stub...                   {:>3}ms",
                t.elapsed().as_millis()
            ),
            Err(e) => {
                tracing::warn!("CLAUDE.md stub write failed: {e}");
                println!("  Writing .claude/CLAUDE.md stub...    skipped — {:#}", e);
            }
        }

        let t = Instant::now();
        match write_mati_enrich_command(root) {
            Ok(_) => println!(
                "  Writing .claude/commands/mati-enrich.md...          {:>3}ms",
                t.elapsed().as_millis()
            ),
            Err(e) => {
                tracing::warn!("mati-enrich command write failed: {e}");
                println!(
                    "  Writing .claude/commands/mati-enrich.md...    skipped — {:#}",
                    e
                );
            }
        }

        let t = Instant::now();
        match write_capture_skills(root) {
            Ok(_) => println!(
                "  Writing .claude/skills/ (capture)...                {:>3}ms",
                t.elapsed().as_millis()
            ),
            Err(e) => {
                tracing::warn!("capture skills write failed: {e}");
                println!(
                    "  Writing .claude/skills/ (capture)...    skipped — {:#}",
                    e
                );
            }
        }

        let t = Instant::now();
        match install_hooks_with_options(root, args.claude_mcp_tool) {
            Ok(InstallResult::Installed { .. }) => {
                claude_installed = true;
                println!(
                    "  Installing Claude integration...                    {:>3}ms",
                    t.elapsed().as_millis()
                );
                {
                    let g = if std::io::stderr().is_terminal() {
                        super::colors::GRAY
                    } else {
                        ""
                    };
                    let r = if std::io::stderr().is_terminal() {
                        super::colors::RESET
                    } else {
                        ""
                    };
                    println!("    {g}.claude/settings.json          hook registrations + MCP server config{r}");
                    // Derive count + names from HOOK_SCRIPTS so this line can
                    // never drift out of sync with what was actually installed.
                    let claude_hooks: Vec<&str> = mati_core::scaffold::settings::HOOK_SCRIPTS
                        .iter()
                        .map(|(n, _)| n.trim_end_matches(".sh"))
                        .collect();
                    println!(
                        "    {g}.claude/hooks/                 {} hooks ({}){r}",
                        claude_hooks.len(),
                        claude_hooks.join(", ")
                    );
                    println!(
                        "    {g}.claude/CLAUDE.md              read-gate + enrichment pointer{r}"
                    );
                    println!("    {g}.claude/skills/                capture skills (gotcha, policy) — load on demand{r}");
                    if args.claude_mcp_tool {
                        println!(
                            "    {g}experimental mcp_tool              additive prototype; shell pre-read remains the startup-independent path{r}"
                        );
                        eprintln!(
                            "  WARNING: mcp_tool hooks require the Claude MCP server to be connected; they fail open and are not used as the sole enforcement path."
                        );
                    }
                }
            }
            Ok(InstallResult::NoClaude) => println!(
                "  Installing Claude integration...                    {:>3}ms",
                t.elapsed().as_millis()
            ),
            Err(e) => {
                tracing::warn!("Claude integration installation failed: {e}");
                println!("  Installing Claude integration...       FAILED");
                eprintln!();
                eprintln!("  WARNING: Claude integration failed — {e:#}");
                eprintln!("  Claude read interception will not work until this is fixed.");
                eprintln!("  Fix the issue above, then re-run: mati init --claude");
                eprintln!();
            }
        }
    }

    if install_codex_integration {
        let t = Instant::now();
        match install_codex(root, args.codex) {
            Ok(CodexInstallResult::Installed { .. }) => {
                codex_installed = true;
                println!(
                    "  Installing Codex integration...                     {:>3}ms",
                    t.elapsed().as_millis()
                );
                {
                    let g = if std::io::stderr().is_terminal() {
                        super::colors::GRAY
                    } else {
                        ""
                    };
                    let r = if std::io::stderr().is_terminal() {
                        super::colors::RESET
                    } else {
                        ""
                    };
                    println!(
                        "    {g}.codex/config.toml             MCP server + hooks feature flag{r}"
                    );
                    // Derive count + names from CODEX_HOOK_SCRIPTS (single source
                    // of truth) so the summary always matches what was installed.
                    let codex_hooks: Vec<&str> = mati_core::scaffold::codex::CODEX_HOOK_SCRIPTS
                        .iter()
                        .map(|(n, _)| n.trim_end_matches(".sh"))
                        .collect();
                    println!(
                        "    {g}.codex/hooks/                  {} hooks ({}){r}",
                        codex_hooks.len(),
                        codex_hooks.join(", ")
                    );
                    println!("    {g}.codex/skills/mati/            skill instructions for agent guidance{r}");
                }
            }
            Ok(CodexInstallResult::NoCodex) => println!(
                "  Installing Codex integration...                     {:>3}ms",
                t.elapsed().as_millis()
            ),
            Err(e) => {
                tracing::warn!("Codex integration installation failed: {e}");
                println!("  Installing Codex integration...        FAILED");
                eprintln!();
                eprintln!("  WARNING: Codex integration failed — {e:#}");
                eprintln!(
                    "  Codex MCP/skill/hook support will not be available until this is fixed."
                );
                eprintln!("  Fix the issue above, then re-run: mati init --codex");
                eprintln!();
            }
        }
    }

    Ok((claude_installed, codex_installed))
}

// ── `mati hooks` subcommand ─────────────────────────────────────────────────

/// Arguments for `mati hooks` — install or update agent hooks without a full re-init.
#[derive(Args)]
pub struct HooksArgs {
    /// Path to repository root (defaults to current directory)
    #[arg(short, long)]
    pub path: Option<PathBuf>,

    /// Install or update Codex integration into .codex/
    #[arg(long)]
    pub codex: bool,

    /// Install or update Claude integration into .claude/
    #[arg(long)]
    pub claude: bool,

    /// Also scaffold the experimental Claude mcp_tool hook transport. The
    /// shell hook remains installed as the startup-independent path.
    #[arg(long)]
    pub claude_mcp_tool: bool,
}

/// Install or update agent hooks without touching the store.
///
/// Lightweight alternative to `mati init` — writes hook scripts, settings.json,
/// and SKILL.md from the current binary. Safe to run while the daemon is active.
pub fn run_hooks(args: HooksArgs) -> Result<()> {
    let root = match &args.path {
        Some(p) => p.clone(),
        None => std::env::current_dir()?,
    };
    let root = std::fs::canonicalize(&root)?;

    let init_args = InitArgs {
        path: Some(root.clone()),
        no_hooks: false,
        codex: args.codex,
        claude: args.claude,
        claude_mcp_tool: args.claude_mcp_tool,
    };

    let project_name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());

    println!();
    println!("◈  mati hooks — project: {}", project_name);
    println!();

    let (claude_installed, codex_installed) = install_scaffold(&root, &init_args)?;

    if !claude_installed && !codex_installed {
        println!("  No platform detected. Use --claude or --codex to force installation.");
    }

    println!();
    Ok(())
}
