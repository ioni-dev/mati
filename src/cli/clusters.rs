//! `mati clusters` — list co-change clusters discovered from git history.

use std::io::IsTerminal;

use anyhow::Result;
use clap::Args;

use mati_core::analysis::clusters::ClusterIndex;

use super::colors;
use super::proxy::StoreProxy;

#[derive(Args)]
#[command(
    long_about = "List co-change clusters — logical modules discovered from git history.\n\
                  Files that frequently change together form clusters, regardless of\n\
                  directory structure. Use this to understand implicit module boundaries."
)]
pub struct ClustersArgs {
    /// Show only the named cluster (by label)
    #[arg(long, value_name = "LABEL")]
    pub cluster: Option<String>,

    /// Emit the full ClusterIndex as JSON
    #[arg(long)]
    pub json: bool,

    /// Show only clusters with at least N members
    #[arg(long, value_name = "N", default_value = "2")]
    pub min_size: u32,
}

pub async fn run(args: ClustersArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;

    let cluster_index = match proxy.get("cluster:index").await? {
        Some(rec) => rec.payload_as::<ClusterIndex>().unwrap_or_default(),
        None => {
            println!("No cluster data found. Run `mati init` first.");
            proxy.close().await?;
            return Ok(());
        }
    };

    proxy.close().await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&cluster_index)?);
        return Ok(());
    }

    let use_color = std::io::stdout().is_terminal();
    let (blue, cyan, gray, _white, bold, reset) = if use_color {
        (
            colors::BLUE,
            colors::CYAN,
            colors::GRAY,
            colors::WHITE,
            colors::BOLD,
            colors::RESET,
        )
    } else {
        ("", "", "", "", "", "")
    };

    // Filter by --cluster label
    if let Some(ref label) = args.cluster {
        let matching: Vec<_> = cluster_index
            .clusters
            .iter()
            .filter(|c| c.label == *label)
            .collect();

        if matching.is_empty() {
            println!("No cluster with label '{label}' found.");
            return Ok(());
        }

        for c in &matching {
            println!(
                "\n{bold}{blue}● {}{reset} ({} files, cohesion {:.2}, centroid: {})",
                c.label,
                c.size,
                c.cohesion,
                stem(&c.centroid),
            );
            for member in &c.members {
                println!("  {cyan}{member}{reset}");
            }
        }
        println!();
        return Ok(());
    }

    // Apply --min-size filter
    let clusters: Vec<_> = cluster_index
        .clusters
        .iter()
        .filter(|c| c.size >= args.min_size)
        .collect();

    if clusters.is_empty() {
        println!("No clusters found with at least {} members.", args.min_size);
        return Ok(());
    }

    let total_files = cluster_index.clustered_files + cluster_index.isolated_files;
    println!(
        "\n{bold}{blue}CO-CHANGE CLUSTERS{reset} ({} total, {} of {} files)\n",
        cluster_index.total, cluster_index.clustered_files, total_files,
    );

    for c in &clusters {
        println!(
            "{bold}{blue}● {}{reset} ({} files, cohesion {:.2}, centroid: {})",
            c.label,
            c.size,
            c.cohesion,
            stem(&c.centroid),
        );

        let max_display = 10;
        for member in c.members.iter().take(max_display) {
            println!("  {cyan}{member}{reset}");
        }
        if c.members.len() > max_display {
            println!(
                "  {gray}(+{} more){reset}",
                c.members.len() - max_display
            );
        }
        println!();
    }

    Ok(())
}

fn stem(path: &str) -> String {
    std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string()
}
