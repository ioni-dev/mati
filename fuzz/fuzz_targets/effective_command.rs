#![no_main]

use libfuzzer_sys::fuzz_target;
use mati_core::hooks::decide::effective_command_for_fuzzing as effective_command;

// effective_command only strips prefixes and reduces the command word to its
// basename — it never adds bytes. out.len() <= cmd.len() follows directly
// from the function reconstructing its result from substrings of `cmd`.
fuzz_target!(|cmd: &str| {
    let out = effective_command(cmd);
    assert!(
        out.len() <= cmd.len(),
        "effective_command grew the input: {cmd:?} -> {out:?}"
    );
});
