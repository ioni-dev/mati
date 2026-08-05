use std::fs;
use std::path::Path;

#[test]
fn store_opening_tests_must_select_a_scratch_home() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let tests_dir = root.join("tests");

    for entry in fs::read_dir(&tests_dir).expect("read tests directory") {
        let path = entry.expect("read test entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some("store_home_guard.rs") {
            continue;
        }
        let source = fs::read_to_string(&path).expect("read integration test");
        if source.contains("Store::open(") {
            assert!(
                source.contains("common::isolate_mati_home()"),
                "{} opens a store without isolating MATI_HOME",
                path.display()
            );
        }
    }

    let cli_dir = root.join("src/cli");
    for entry in fs::read_dir(cli_dir).expect("read cli directory") {
        let path = entry.expect("read cli entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let source = fs::read_to_string(&path).expect("read cli source");
        let Some(test_source) = source.split_once("#[cfg(test)]\nmod tests {") else {
            continue;
        };
        if test_source.1.contains("Store::open(") {
            assert!(
                test_source.1.contains("ensure_test_home();"),
                "{} opens a store in bin tests without ensure_test_home()",
                path.display()
            );
        }
    }
}
