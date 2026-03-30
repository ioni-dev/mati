// Scaffold files written by mati init (M-06-I/J)
// CLAUDE.md Vector C stub, .claude/settings.json, mati.json MCP config

use std::path::Path;

use anyhow::Result;

pub mod claude_md;
pub mod codex;
pub mod settings;

pub use claude_md::write_claude_md_stub;
pub use codex::install_codex;
pub use settings::install_hooks;

/// Resolve the absolute path to the running mati binary.
///
/// Used by scaffold installers to pin both MCP config and hook scripts to the
/// same binary. Falls back to `"mati"` if resolution fails (e.g. during tests).
pub fn mati_binary_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "mati".to_owned())
}

/// Write a `mati` wrapper script into `hooks_dir` that execs the resolved binary.
///
/// This ensures all hook scripts call the same mati binary used by the MCP server,
/// regardless of what `mati` is on PATH. Each hook prepends its own directory to
/// PATH so this wrapper is found first.
pub fn write_mati_wrapper(hooks_dir: &Path) -> Result<()> {
    let bin = mati_binary_path();
    let content = format!(
        "#!/usr/bin/env bash\n\
         # mati binary wrapper — written by mati init.\n\
         # Ensures hooks use the same binary as the MCP server.\n\
         # DO NOT EDIT — regenerated on each mati init.\n\
         exec \"{bin}\" \"$@\"\n"
    );
    let path = hooks_dir.join("mati");
    write_if_changed(&path, &content)?;
    make_executable(&path)?;
    Ok(())
}

pub(crate) fn write_if_changed(path: &Path, content: &str) -> Result<()> {
    if path.exists() {
        if let Ok(existing) = std::fs::read_to_string(path) {
            if existing == content {
                return Ok(());
            }
        }
    }
    std::fs::write(path, content)?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}
