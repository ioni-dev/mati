#![no_main]

use libfuzzer_sys::fuzz_target;
use mati_core::hooks::decide::extract_apply_patch_files;
use std::collections::HashSet;

// Contract from the doc comment on extract_apply_patch_files: paths are
// returned in first-seen order with duplicates removed, and an empty path
// after trim is never pushed. Assert both directly.
fuzz_target!(|patch: &str| {
    let files = extract_apply_patch_files(patch);

    let mut seen = HashSet::with_capacity(files.len());
    for f in &files {
        assert!(!f.is_empty(), "returned an empty path for input {patch:?}");
        assert!(seen.insert(f), "returned a duplicate path {f:?} for input {patch:?}");
    }
});
