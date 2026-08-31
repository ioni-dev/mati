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

/// Longest `MATI_HOME` that still leaves room for a daemon socket.
///
/// The daemon binds `<home>/<slug>/mati.sock` and the slug is 8 hex chars.
/// macOS caps `sun_path` at 104 bytes including the NUL, leaving 103 for the
/// path, so the home may use `103 - len("/xxxxxxxx/mati.sock")` = 84. Past that
/// the bind fails silently and every hook measures the fail-open path instead
/// of a live daemon.
const MAX_HOME_LEN: usize = 84;

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
/// An inherited `MATI_HOME` is deliberately ignored. Honoring one put every
/// integration test in a single shared store whenever a developer exported the
/// variable, and the suite stayed green throughout. [`mati_home_root`] is the
/// lever that survives that: it sets the parent dir only.
///
/// Idempotent: computed once per process. Nextest runs each test in its own
/// process, so that is one home per test; vanilla `cargo test` shares one home
/// across a whole test binary.
pub fn mati_home() -> PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = mati_home_root().join(format!("mati-it-{}", std::process::id()));
        // Pids are recycled and these dirs outlive the run that made them, so
        // wipe before use: a fresh process must never open a store an older one
        // left behind. Only the leaf is removed, never the root.
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        // Export so spawned `mati` children (and any daemon they spawn) inherit
        // the same root instead of computing a divergent one.
        std::env::set_var("MATI_HOME", &dir);
        dir
    })
    .clone()
}

/// Parent of the per-process home, from `MATI_TEST_HOME` or `$TMPDIR`.
///
/// Overridable because `$TMPDIR` on macOS is 49 bytes and [`MAX_HOME_LEN`] is
/// 84. Only the parent: the per-process leaf is always appended, so pointing
/// two processes at one root still gives them separate stores.
fn mati_home_root() -> PathBuf {
    std::env::var_os("MATI_TEST_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
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

/// `mati_home` exports `MATI_HOME` as a side effect, so asserting it is set
/// after calling it proves nothing. What is worth pinning is where it points.
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
}

/// The bug this guards is narrower than the assertion above and is what let it
/// through: `mati_home` used to return an inherited `MATI_HOME` unchanged, so
/// an exported one pointed every integration test at a single store — not the
/// real `~/.mati`, so the check above stayed green.
#[test]
fn the_test_home_is_process_unique() {
    let resolved = mati_home();
    let pid = std::process::id().to_string();
    let leaf = resolved
        .file_name()
        .map(|leaf| leaf.to_string_lossy().into_owned())
        .unwrap_or_default();
    assert!(
        leaf.contains(&pid),
        "MATI_HOME must end in a per-process leaf containing pid {pid}, got {}",
        resolved.display()
    );
    // Tests run children with `current_dir` set to a tempdir repo. A relative
    // root would resolve differently in the child than in the test, splitting
    // them across two stores without either one erroring.
    assert!(
        resolved.is_absolute(),
        "MATI_TEST_HOME must be an absolute path, got {}",
        resolved.display()
    );
}

/// A home over the socket budget does not fail — it makes the daemon fail to
/// bind, silently, and every test then measures the fail-open path. Catch it
/// here with a message that names the fix.
#[test]
fn the_test_home_leaves_room_for_a_daemon_socket() {
    let resolved = mati_home();
    let len = resolved.as_os_str().len();
    assert!(
        len <= MAX_HOME_LEN,
        "MATI_HOME is {len} bytes, over the {MAX_HOME_LEN} that leaves room for \
         <slug>/mati.sock inside a 104-byte sun_path. Set MATI_TEST_HOME to a \
         short dir (e.g. /tmp/mati-it). Got {}",
        resolved.display()
    );
}
