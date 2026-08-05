use super::*;
use crate::store::record::{Category, FileRecord, RecordLifecycle};
use crate::store::Store;

/// The MCP staged link-sync (`compute_file_link_updates`, used by the
/// typed mem_set/confirm handlers) must create a file stub carrying the
/// gotcha key when the file was never indexed — mirroring the
/// `gotcha_ops::update_file_gotcha_key` create-on-write fix — so an
/// agent-created gotcha on an un-indexed file enforces immediately.
#[tokio::test]
async fn compute_file_link_updates_creates_stub_for_unindexed_file() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = Store::open(dir.path()).await.expect("open store");

    // No file record exists for this path (init never indexed it).
    let updates =
        compute_file_link_updates(&store, "gotcha:x", &[], &["src/new.rs".to_string()]).await;

    assert_eq!(updates.len(), 1, "one file-record update staged");
    let (key, rec) = &updates[0];
    assert_eq!(key, "file:src/new.rs");
    let fr: FileRecord = rec.payload_as().expect("stub payload is a FileRecord");
    assert!(
        fr.gotcha_keys.contains(&"gotcha:x".to_string()),
        "staged stub must carry the gotcha key (got {:?})",
        fr.gotcha_keys
    );
    assert!(matches!(rec.category, Category::File));
    assert!(matches!(rec.lifecycle, RecordLifecycle::Active));

    store.close().await.expect("close");
}

/// Guard: when the file record already exists, no duplicate stub is created
/// and the existing record simply gains the key (regression on the match arm).
#[tokio::test]
async fn compute_file_link_updates_updates_existing_record() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = Store::open(dir.path()).await.expect("open store");

    let mut seed = Record::layer0_file_stub("file:src/exists.rs", uuid::Uuid::new_v4(), 1, 1);
    let fr0 = FileRecord::layer0_stub(
        "src/exists.rs",
        vec![],
        vec![],
        vec![],
        0,
        0,
        0,
        None,
        false,
        0,
        1,
    );
    seed.payload = serde_json::to_value(&fr0).ok();
    store.put("file:src/exists.rs", &seed).await.expect("seed");

    let updates =
        compute_file_link_updates(&store, "gotcha:y", &[], &["src/exists.rs".to_string()]).await;

    assert_eq!(updates.len(), 1);
    let fr: FileRecord = updates[0].1.payload_as().expect("payload");
    assert!(fr.gotcha_keys.contains(&"gotcha:y".to_string()));

    store.close().await.expect("close");
}
