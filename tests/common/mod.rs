//! Shared helpers for integration tests.
//!
//! Use via `mod common;` at the top of a test file. (`common/mod.rs`, not
//! `common.rs`, so cargo does not treat it as its own test binary.)
//!
//! Each test binary compiles this module independently and uses only a subset
//! of it, so unused-item warnings are expected and silenced.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::OnceLock;

/// Redirect all mati state — every project store, the daemon socket, logs, and
/// the device id — to a process-unique temp dir via `MATI_HOME`, and return it.
///
/// Integration tests spawn the real `mati` binary against tempdir repos; without
/// this, each spawn derives a slug and creates a permanent `~/.mati/<slug>/` in
/// the developer's real home. Setting `MATI_HOME` in the test process means:
///   - every child `mati` inherits it from the environment, and
///   - the test's own root computation (e.g. waiting on `<root>/mati.sock`)
///     resolves to the SAME place the child writes — call this instead of
///     `dirs::home_dir().join(".mati")`.
///
/// Idempotent: computed once per process (nextest runs each test in its own
/// process, so tests never share a home). The dir lives for the process
/// lifetime under `$TMPDIR`; the OS reclaims it.
pub fn mati_home() -> PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::var_os("MATI_HOME")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!("mati-it-{}", std::process::id()))
            });
        let _ = std::fs::create_dir_all(&dir);
        // Export so spawned `mati` children (and any daemon they spawn) inherit
        // the same root instead of computing a divergent one.
        std::env::set_var("MATI_HOME", &dir);
        dir
    })
    .clone()
}

/// Set `MATI_HOME` for this test process (and inherited by spawned children)
/// without needing the returned path. Convenience wrapper over [`mati_home`].
pub fn isolate_mati_home() {
    let _ = mati_home();
}

/// Stops the daemon for a scratch mati root on drop — including when the test
/// panics, since `Drop` still runs during unwinding.
///
/// A test that spawns `mati <cmd>` against a scratch home touches the store
/// through `StoreProxy::open`, which calls `ensure_daemon` and spawns a
/// *detached* `mati daemon start` process: it is not a child of the test's own
/// `Command`, so `kill_on_drop` on that `Command` (or killing a `mati serve`
/// wrapping it) never reaches it. Keep one of these alive for the scope that
/// owns the scratch home; it shells out to `mati daemon stop` against that
/// exact root on drop, so the daemon comes down no matter how the test exits.
///
/// Never point this at a developer's real `~/.mati` — it unconditionally
/// stops whatever daemon answers for the given root.
///
/// Needs the same `cwd` the original commands ran with, not just the home
/// override: the store root is `<home>/<slug>`, and the slug is derived from
/// cwd. Pointing `mati daemon stop` at the wrong cwd computes a different
/// slug and silently misses the daemon.
pub struct DaemonGuard {
    cwd: PathBuf,
    env_key: &'static str,
    env_val: PathBuf,
}

impl DaemonGuard {
    /// For tests isolating via `MATI_HOME` (i.e. [`mati_home`] / [`isolate_mati_home`]).
    pub fn for_mati_home(cwd: impl Into<PathBuf>, mati_home: impl Into<PathBuf>) -> Self {
        Self {
            cwd: cwd.into(),
            env_key: "MATI_HOME",
            env_val: mati_home.into(),
        }
    }

    /// For tests isolating via `HOME` (mati falls back to `$HOME/.mati` when
    /// `MATI_HOME` is unset) rather than setting `MATI_HOME` directly.
    pub fn for_home(cwd: impl Into<PathBuf>, home: impl Into<PathBuf>) -> Self {
        Self {
            cwd: cwd.into(),
            env_key: "HOME",
            env_val: home.into(),
        }
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new(env!("CARGO_BIN_EXE_mati"))
            .args(["daemon", "stop"])
            .current_dir(&self.cwd)
            .env(self.env_key, &self.env_val)
            .output();
    }
}

#[test]
fn integration_tests_never_use_real_mati_home() {
    let resolved = mati_home();
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let real_mati = home.join(".mati");
        assert_ne!(
            resolved,
            real_mati,
            "integration test resolved to the real ~/.mati ({})",
            real_mati.display()
        );
    }
    assert_eq!(
        std::env::var_os("MATI_HOME").map(PathBuf::from),
        Some(resolved),
        "integration tests must export MATI_HOME for spawned mati processes"
    );
}
