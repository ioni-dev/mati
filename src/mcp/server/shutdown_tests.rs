use super::*;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn shutdown_signal_before_wait_returns_immediately() {
    // Pre-signal: subsequent wait must NOT block. Tests the flag-check
    // arm of `wait()` before the notified.await.
    let s = Shutdown::new();
    s.signal();
    // Should return well under timeout — generous bound to avoid CI flake.
    tokio::time::timeout(Duration::from_millis(100), s.wait())
        .await
        .expect("wait must return immediately when already signaled");
    assert!(s.is_set());
}

#[tokio::test]
async fn shutdown_wait_then_signal_wakes_waiter() {
    let s = Arc::new(Shutdown::new());
    let s_clone = Arc::clone(&s);
    let waiter = tokio::spawn(async move { s_clone.wait().await });

    // Give the waiter a moment to register on `notified()`.
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!s.is_set());

    s.signal();

    tokio::time::timeout(Duration::from_millis(200), waiter)
        .await
        .expect("waiter must wake within timeout")
        .expect("waiter task should not panic");
    assert!(s.is_set());
}

#[tokio::test]
async fn shutdown_multiple_concurrent_waiters_all_wake() {
    // The notify_waiters() in signal() must wake every active waiter.
    let s = Arc::new(Shutdown::new());
    let mut handles = Vec::new();
    for _ in 0..16 {
        let s = Arc::clone(&s);
        handles.push(tokio::spawn(async move { s.wait().await }));
    }
    // Let waiters register.
    tokio::time::sleep(Duration::from_millis(20)).await;

    s.signal();

    for h in handles {
        tokio::time::timeout(Duration::from_millis(200), h)
            .await
            .expect("each waiter must wake within timeout")
            .expect("waiter task should not panic");
    }
}

#[tokio::test]
async fn shutdown_signal_is_idempotent() {
    // Second signal must be a no-op. Subsequent waits still return.
    let s = Shutdown::new();
    s.signal();
    s.signal();
    s.signal();
    tokio::time::timeout(Duration::from_millis(100), s.wait())
        .await
        .expect("wait must still return on idempotent re-signal");
}

/// Contract test: the bounded-drain pattern in `serve_loop_graceful`
/// (and the caller-side hammer for `serve_daemon_socket`) relies on
/// `JoinSet::abort_all()` actually causing in-flight tasks to wake
/// with a cancellation error, so a subsequent `join_next` loop
/// completes. If tokio ever changes this — e.g., requires polling
/// each task explicitly — our drain-timeout fallback silently
/// regresses to "wait forever after abort_all".
#[tokio::test]
async fn joinset_abort_all_makes_drain_finite() {
    let mut set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    // Spawn a task that would otherwise run for a long time.
    set.spawn(async {
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    // First drain attempt: time out (task is mid-sleep).
    let primary = tokio::time::timeout(Duration::from_millis(100), async {
        while set.join_next().await.is_some() {}
    })
    .await;
    assert!(
        primary.is_err(),
        "primary drain should time out while task is still sleeping"
    );

    // Now abort and drain again — must complete promptly.
    set.abort_all();
    let secondary = tokio::time::timeout(Duration::from_millis(500), async {
        while set.join_next().await.is_some() {}
    })
    .await;
    assert!(
        secondary.is_ok(),
        "drain after abort_all must complete quickly"
    );
    assert!(set.is_empty(), "JoinSet should be empty after drain");
}

/// Contract test: the panic-detection logic in `serve_daemon_socket`
/// (and `cli::daemon::serve_loop_graceful`) relies on tokio's `JoinSet`
/// reporting panicked tasks via `try_join_next() -> Some(Err(e))` with
/// `e.is_panic() == true`. If tokio ever changes that, our handler-
/// panic-is-terminal property silently regresses. Lock it down here.
#[tokio::test]
async fn joinset_panics_are_observable_via_try_join_next() {
    let mut set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    set.spawn(async {
        panic!("simulated handler panic");
    });

    // Wait until the panicked task has been catch_unwind'd at the
    // tokio spawn boundary and parked on the JoinSet's completion queue.
    // Poll try_join_next briefly; assert we see the panic.
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    loop {
        if let Some(res) = set.try_join_next() {
            let err = res.expect_err("panicked task should yield Err");
            assert!(
                err.is_panic(),
                "JoinError must report is_panic for panicking task; got: {err:?}"
            );
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("try_join_next never reported the panic within 500ms");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Race contract — exercises the enable() pattern. A waiter that is
/// JUST being constructed (between the `notified()` call and the flag
/// check) must NOT miss a `signal()` that fires concurrently.
///
/// Probabilistic: runs many trials and asserts every one wakes.
#[tokio::test]
async fn shutdown_no_lost_signal_under_race() {
    for trial in 0..50 {
        let s = Arc::new(Shutdown::new());
        let s_waiter = Arc::clone(&s);
        let s_signaler = Arc::clone(&s);

        let waiter = tokio::spawn(async move { s_waiter.wait().await });

        // Yield briefly so the waiter has a chance to start `wait()`.
        tokio::task::yield_now().await;

        // Signal at the moment the waiter is racing to register.
        s_signaler.signal();

        tokio::time::timeout(Duration::from_millis(500), waiter)
            .await
            .unwrap_or_else(|_| panic!("trial {trial}: waiter stranded by lost signal"))
            .expect("waiter task should not panic");
    }
}
