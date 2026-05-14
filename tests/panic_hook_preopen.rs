//! Integration test for Fix 3: pre-opened lifecycle log fd in the panic hook.
//!
//! Cargo runs each `tests/<name>.rs` as a separate integration binary, so the
//! `LIFECYCLE_LOG_FILE` / `PANIC_HOOK_ROOT` `OnceLock`s in `mati_core::mcp::metadata`
//! are fresh in this process. Tests within an integration binary run in
//! parallel by default, so all assertions live in a single `#[test]` to avoid
//! racing on the install / preopen state.
//!
//! What this verifies, beyond the in-module unit tests:
//!
//! - `install_panic_hook` actually populates `LIFECYCLE_LOG_FILE`
//!   (`is_lifecycle_log_preopened()` flips from false → true).
//! - When `record_lifecycle_event` is called with the *matching* root, the
//!   write lands in that root's `lifecycle.log` (preopened-fd path).
//! - When called with a *different* root, the write lands in the other
//!   root's log via the open(2) fallback — and **does not leak** into the
//!   preopened root's log. This is the strong assertion that the
//!   path-equality gate works.
//! - A real panic on a background thread routes through the panic hook,
//!   which uses the preopened fd to record a `panic` lifecycle event.

use mati_core::mcp::metadata::{
    install_panic_hook, is_lifecycle_log_preopened, record_lifecycle_event,
};

fn read_log(root: &std::path::Path) -> String {
    std::fs::read_to_string(root.join("lifecycle.log")).unwrap_or_default()
}

#[test]
fn panic_hook_preopens_lifecycle_fd_and_routes_correctly() {
    // Phase 1: pre-install — fd not yet pre-opened.
    assert!(
        !is_lifecycle_log_preopened(),
        "lifecycle fd must not be preopened before install_panic_hook"
    );

    // Phase 2: install for rootA. Use a tempdir with a `mati`-style layout.
    let dir_a = tempfile::tempdir().unwrap();
    let root_a = dir_a.path().to_path_buf();
    install_panic_hook(root_a.clone());

    // Phase 3: post-install — `LIFECYCLE_LOG_FILE` is populated.
    assert!(
        is_lifecycle_log_preopened(),
        "install_panic_hook must populate LIFECYCLE_LOG_FILE on success"
    );

    // Phase 4: matching root — event lands in rootA's log via preopened fd.
    record_lifecycle_event(&root_a, "evt_match", "matching root");
    let log_a = read_log(&root_a);
    assert!(
        log_a.contains("\tevt_match\tmatching root\n"),
        "matching-root event missing from rootA log; contents:\n{log_a}"
    );

    // Phase 5: mismatched root — event must land in rootB's log via the
    // open(2) fallback, NOT in rootA's log. This is the load-bearing
    // assertion that the path-equality gate (`pre.path == path`) actually
    // discriminates roots.
    let dir_b = tempfile::tempdir().unwrap();
    let root_b = dir_b.path().to_path_buf();
    record_lifecycle_event(&root_b, "evt_fallback", "other root");

    let log_b = read_log(&root_b);
    assert!(
        log_b.contains("\tevt_fallback\tother root\n"),
        "fallback-path event missing from rootB log; contents:\n{log_b}"
    );

    let log_a_after = read_log(&root_a);
    assert!(
        !log_a_after.contains("evt_fallback"),
        "fallback-path event leaked into rootA — path-equality check failed.\n\
         rootA log after mismatched write:\n{log_a_after}"
    );

    // Phase 6: real panic on a background thread. The panic hook fires
    // synchronously on the panicking thread (before `catch_unwind` catches
    // the unwind), calls `run_panic_cleanup`, which routes the lifecycle
    // event through the no-alloc panic writer and the preopened fd.
    let marker = "preopen-test-panic-marker-9b32f1";
    let payload = marker.to_string();
    let handle = std::thread::spawn(move || {
        // `catch_unwind` keeps the panic from propagating out of the test
        // process. The hook still fires before the catch.
        let _ = std::panic::catch_unwind(move || {
            panic!("{payload}");
        });
    });
    handle
        .join()
        .expect("panicking thread joined cleanly after catch_unwind");

    let log_panic = read_log(&root_a);
    assert!(
        log_panic.contains("\tpanic\t"),
        "no `panic` lifecycle event recorded in rootA log; contents:\n{log_panic}"
    );
    assert!(
        log_panic.contains(marker),
        "panic payload marker `{marker}` missing from rootA log; contents:\n{log_panic}"
    );
}
