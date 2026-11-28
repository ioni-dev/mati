pub mod check;
pub mod clusters;
pub mod colors;
pub mod config;
pub mod consult_gate;
pub mod daemon;
pub mod demo;
pub mod diff;
pub mod doctor;
pub mod enrich;
pub mod eval;
pub mod explain;
pub mod extract_signals;
pub mod gaps;
pub mod gotcha;
pub mod guard;
pub mod hook_decide;
pub mod hooks;
pub mod init;
pub mod policy;
pub mod protect;
pub mod proxy;
pub mod repair;
pub mod reparse;
pub mod review;
pub mod sandbox;
pub mod seal;
pub mod search;
pub mod show;
pub mod stale;
pub mod stats;
pub mod status;
pub mod subagent_context;
pub mod suggest;
pub mod supervisor;
pub mod verify_chain;
pub mod verify_evidence;
pub mod watch_paths;

/// Redirect all mati state to a per-process temp dir for bin-crate unit tests.
///
/// The lib's own `cfg(test)` redirect (`store::mati_home_opt`) covers lib unit
/// tests, but the bin crate's `cfg(test)` is separate: when a bin test calls
/// `Store::open`, the lib is compiled without `--test`, so its auto-redirect is
/// off. Bin tests that open a tempdir-backed store must call this first so
/// `$MATI_HOME` is set before any `mati_home()` resolution — keeping bin-test
/// state out of the developer's real `~/.mati`. Idempotent; safe to call from
/// every test. `set_var` propagates to any child `mati` process a test spawns.
///
/// An inherited `MATI_HOME` is ignored. Honoring one put every bin test in a
/// single shared store whenever a developer exported the variable, and the
/// suite stayed green throughout. `MATI_TEST_HOME` sets the parent dir instead
/// — macOS caps socket paths at 104 bytes — and the per-process leaf is
/// always appended.
#[cfg(test)]
pub(crate) fn ensure_test_home() {
    use std::sync::OnceLock;
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let root = std::env::var_os("MATI_TEST_HOME")
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = root.join(format!("mati-bin-test-{}", std::process::id()));
        // Pids are recycled and these dirs outlive the run that made them, so
        // wipe before use. Only the leaf is removed, never the root.
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        std::env::set_var("MATI_HOME", &dir);
    });
}

#[cfg(test)]
mod test_home_tests {
    /// The bug this guards: `ensure_test_home` used to keep an inherited
    /// `MATI_HOME`, so an exported one silently pointed every bin test at the
    /// same store.
    #[test]
    fn the_bin_test_home_is_process_unique() {
        super::ensure_test_home();
        let home = std::env::var("MATI_HOME").expect("ensure_test_home sets MATI_HOME");
        let pid = std::process::id().to_string();
        assert!(
            home.contains(&pid),
            "MATI_HOME must be per-process, got {home}"
        );
    }
}
