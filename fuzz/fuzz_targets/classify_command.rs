#![no_main]

use libfuzzer_sys::fuzz_target;
use mati_core::hooks::decide::classify_command;

// Property: classify_command never panics, never hangs, on arbitrary
// shell-command-shaped input. It's the first thing the hook runs on every
// bash tool call, so it must be crashable-proof under a 3000ms kill.
fuzz_target!(|cmd: &str| {
    let _ = classify_command(cmd);
});
