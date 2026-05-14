//! SurrealKV transaction-size spike.
//!
//! Question for ADR-012: does a single SurrealKV transaction over the
//! knowledge-tree options used by mati handle 10k / 50k / 100k record
//! writes, or do we need the chunked-migration approach?
//!
//! Methodology: open a fresh tree with mati's exact `open_knowledge_tree`
//! options (vlog enabled, versioning enabled with indefinite retention,
//! VLog checksum Full). Write N records of representative size in a single
//! WriteOnly transaction. Commit. Report success or first failure with
//! elapsed time + bytes written.
//!
//! Marked `#[ignore]` because the largest case writes ~512 MB to a temp
//! directory and takes minutes. Run explicitly:
//!
//!     cargo test --release --test surrealkv_tx_size_spike -- --ignored --nocapture
//!
//! What the result tells us:
//!
//! - All sizes succeed → ADR-012's chunked migration is *over-cautious*.
//!   A single transaction is safe up to the tested ceiling. We can simplify
//!   the migration to a single batch up to e.g. 100k records and chunk
//!   only above.
//! - 10k succeeds, 50k or 100k fails → chunked migration is *necessary*.
//!   The 1000-record batch size in ADR-012 is conservative; pick the
//!   largest size that succeeded and use it.
//! - 1k succeeds, 10k fails → SurrealKV has a tight per-tx limit. Lower
//!   the chunk size in ADR-012.

use std::time::Instant;

use surrealkv::{Durability, Mode, Options, TreeBuilder, VLogChecksumLevel};
use tempfile::TempDir;

/// Representative payload size. Real mati gotcha records serialize to a
/// few hundred bytes via MessagePack; 512 bytes is the same order of
/// magnitude with margin for the larger fields (`reason`, `affected_files`).
const VALUE_SIZE: usize = 512;

/// Sizes to test in order. The spike stops at the first failure.
const SIZES: &[usize] = &[1_000, 10_000, 50_000, 100_000, 500_000];

#[tokio::test]
#[ignore]
async fn surrealkv_single_transaction_size_ceiling() {
    println!();
    println!("SurrealKV transaction-size spike (knowledge-tree options)");
    println!("─────────────────────────────────────────────────────────");
    println!(
        "  payload size: {} per record",
        humansize(VALUE_SIZE as u64)
    );
    println!();

    for &n in SIZES {
        match try_single_transaction(n).await {
            Ok(elapsed_ms) => {
                let bytes = (n * VALUE_SIZE) as u64;
                println!(
                    "  {:>7} records  →  OK   in {:>7} ms  ({})",
                    n,
                    elapsed_ms,
                    humansize(bytes),
                );
            }
            Err(e) => {
                let bytes = (n * VALUE_SIZE) as u64;
                println!(
                    "  {:>7} records  →  FAIL ({})  attempted {}",
                    n,
                    e,
                    humansize(bytes),
                );
                println!();
                println!("→ Largest successful size determines the chunk ceiling.");
                println!("→ If 10k+ succeeded, ADR-012 may relax the 1000-record chunk size.");
                println!("→ If 1k succeeded but 10k failed, ADR-012's chunk size is correct or too large.");
                return;
            }
        }
    }

    println!();
    println!("→ All tested sizes succeeded in a single transaction.");
    println!("→ ADR-012's chunked-migration approach is over-cautious.");
    println!("→ Recommendation: relax migration to single-transaction up to ~100k records.");
}

async fn try_single_transaction(n: usize) -> Result<u128, String> {
    let dir = TempDir::new().map_err(|e| format!("tempdir: {e}"))?;

    // Identical options to `open_knowledge_tree` at src/store/db.rs:1107.
    let opts = Options::new()
        .with_path(dir.path().join("knowledge.db"))
        .with_versioning(true, 0)
        .with_enable_vlog(true)
        .with_vlog_value_threshold(0)
        .with_vlog_checksum_verification(VLogChecksumLevel::Full);

    let tree = TreeBuilder::with_options(opts)
        .build()
        .map_err(|e| format!("open: {e}"))?;

    let value = vec![0xABu8; VALUE_SIZE];

    let start = Instant::now();

    let mut txn = tree
        .begin_with_mode(Mode::WriteOnly)
        .map_err(|e| format!("begin: {e}"))?;
    txn.set_durability(Durability::Immediate);

    for i in 0..n {
        let key = format!("spike:record:{i:010}");
        txn.set(key.as_bytes(), &value).map_err(|e| {
            format!(
                "set @ {i} of {n}: {e} (txn buffered ~{} so far)",
                humansize((i as u64) * (VALUE_SIZE as u64))
            )
        })?;
    }

    txn.commit().await.map_err(|e| {
        format!(
            "commit: {e} (txn held {})",
            humansize((n as u64) * (VALUE_SIZE as u64))
        )
    })?;

    Ok(start.elapsed().as_millis())
}

fn humansize(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}
