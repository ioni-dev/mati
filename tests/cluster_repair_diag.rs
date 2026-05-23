//! Regression test for finding #5 — cluster count anomaly during direct-mode
//! `mati repair`.
//!
//! Bug history: `mati repair` reconstructed `(a, b, count)` co-change pairs
//! from CoChanges graph edges using a synthetic `count = MIN_COCHANGE_COUNT`
//! because edge values carry only a timestamp. This bypassed
//! `ClusterIndex::compute`'s count filter (clusters.rs:55-59) and collapsed
//! every persisted edge into a giant single component (e.g. 11 clusters →
//! 2 clusters where one contained 147 files).
//!
//! Fix (DECISIONS.md ADR-021): init now writes `analytics:co_change_pairs`
//! as a source-of-truth record alongside `cluster:index`. Repair reads from
//! that record so real counts drive the cluster filter.
//!
//! This test exercises the live store (gitignored `~/.mati/<slug>/`) — it
//! requires `mati init` to have run with the fix. The daemon must be
//! stopped for the test to acquire the store lock.
//!
//! Skipped (not failed) when:
//! - The store can't be opened (daemon holds the lock).
//! - `analytics:co_change_pairs` is missing (older repos pre-fix).
//!
//! Run with:
//!   `cargo nextest run --test cluster_repair_diag -- --nocapture`

use std::path::PathBuf;

use mati_core::analysis::clusters::ClusterIndex;
use mati_core::store::Store;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[tokio::test]
async fn repair_pairs_record_matches_persisted_cluster_index() {
    let store = match Store::open(&repo_root()).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "SKIP: cannot open store ({e}). \
                 Daemon must be stopped — run `mati daemon stop` first."
            );
            return;
        }
    };

    // 1. Read cluster:index (what init produced).
    let cluster_index_rec = match store
        .get("cluster:index")
        .await
        .expect("scan cluster:index")
    {
        Some(r) => r,
        None => {
            eprintln!("SKIP: cluster:index missing — run `mati init` first.");
            return;
        }
    };
    let persisted_total = cluster_index_rec
        .payload
        .as_ref()
        .and_then(|p| p.get("total"))
        .and_then(|v| v.as_u64())
        .expect("cluster:index payload.total present");
    let persisted_clustered = cluster_index_rec
        .payload
        .as_ref()
        .and_then(|p| p.get("clustered_files"))
        .and_then(|v| v.as_u64())
        .expect("cluster:index payload.clustered_files present");

    // 2. Read analytics:co_change_pairs (the source of truth the fix added).
    let pairs_rec = match store
        .get("analytics:co_change_pairs")
        .await
        .expect("scan analytics:co_change_pairs")
    {
        Some(r) => r,
        None => {
            eprintln!(
                "SKIP: analytics:co_change_pairs missing — run `mati init` \
                 with the post-ADR-021 binary first."
            );
            return;
        }
    };
    let pairs: Vec<(String, String, u32)> = pairs_rec
        .payload
        .as_ref()
        .and_then(|p| p.get("pairs"))
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .expect("analytics:co_change_pairs payload.pairs must deserialize");

    // 3. Recompute clusters from the source-of-truth record (the path
    //    `mati repair` now takes).
    let file_records = store
        .scan_prefix("file:")
        .await
        .expect("scan file: prefix");
    let total_files = file_records.len();
    let recomputed = ClusterIndex::compute(&pairs, total_files);

    eprintln!("--- diagnostic ---");
    eprintln!("  pairs in source-of-truth record: {}", pairs.len());
    eprintln!("  file_records: {total_files}");
    eprintln!("  persisted cluster:index total: {persisted_total}");
    eprintln!("  recomputed total: {}", recomputed.total);
    eprintln!("  persisted clustered_files: {persisted_clustered}");
    eprintln!("  recomputed clustered_files: {}", recomputed.clustered_files);

    // 4. Assert: the source-of-truth pairs MUST produce the same cluster
    //    shape as what init persisted. Any divergence indicates either:
    //    - init wrote a stale pairs record vs. its own cluster:index, OR
    //    - someone reverted ADR-021 and the synthetic-count bug is back.
    assert_eq!(
        recomputed.total as u64, persisted_total,
        "cluster total from analytics:co_change_pairs must match persisted \
         cluster:index — regression for ADR-021 (cluster count anomaly fix)"
    );
    assert_eq!(
        recomputed.clustered_files as u64, persisted_clustered,
        "clustered_files count must match — same regression check"
    );
}
