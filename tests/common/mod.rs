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
