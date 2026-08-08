pub mod check;
pub mod clusters;
pub mod colors;
pub mod config;
pub mod daemon;
pub mod diff;
pub mod doctor;
pub mod enrich;
pub mod eval;
pub mod explain;
pub mod extract_signals;
pub mod gaps;
pub mod gotcha;
pub mod hook_decide;
pub mod hooks;
pub mod init;
pub mod policy;
pub mod proxy;
pub mod repair;
pub mod reparse;
pub mod review;
pub mod sandbox;
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
#[cfg(test)]
pub(crate) fn ensure_test_home() {
    use std::sync::OnceLock;
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        if std::env::var_os("MATI_HOME")
            .filter(|s| !s.is_empty())
            .is_none()
        {
            let dir = std::env::temp_dir().join(format!("mati-bin-test-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            std::env::set_var("MATI_HOME", &dir);
        }
    });
}
