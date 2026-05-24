//! `mati extract-signals` — deterministic enrichment-signal extraction
//! for `/mati-enrich`'s Stage 1 (SOTA pipeline replacement for
//! LLM-driven file scanning).
//!
//! Reads `--file <path>`, detects the language, runs the appropriate
//! tree-sitter signal extractor (in
//! `src/analysis/enrich_signals/`), and emits the SignalReport as
//! JSON on stdout. Designed to be called by `/mati-enrich`'s slash
//! flow via Bash; agents consume the JSON envelope deterministically
//! instead of relying on the LLM's own scanning judgment.
//!
//! Per ENRICH_QUALITY.md Section 4 (Proposal D SOTA expansion).
//! Hidden in `--help` output; intended for programmatic use.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use mati_core::analysis::enrich_signals;
use mati_core::analysis::walker::detect_language;

#[derive(Args, Debug)]
#[command(
    long_about = "Deterministic enrichment-signal extraction for /mati-enrich Stage 1.\n\
                  Returns a JSON SignalReport on stdout. Exit 0 always when the\n\
                  file is readable; signal_count=0 is a valid empty report.\n\
                  Use --limit N to cap the returned signals (after tier-sort)."
)]
pub struct ExtractSignalsArgs {
    /// Repo-relative or absolute path to the source file.
    #[arg(long)]
    pub file: PathBuf,

    /// Cap the returned signals to the top N (after sorting by tier
    /// descending). Default 0 = no cap.
    #[arg(long, default_value = "0")]
    pub limit: usize,

    /// Override language detection (rare). Accepts the same labels
    /// `mati doctor` uses: rust, typescript, python, go, javascript,
    /// java, c, cpp, ruby, scala, elixir, haskell.
    #[arg(long)]
    pub language: Option<String>,
}

pub async fn run(args: ExtractSignalsArgs) -> Result<()> {
    let language = match args.language.as_deref() {
        Some(label) => parse_language_label(label)?,
        None => detect_language(&args.file),
    };

    let mut report = enrich_signals::extract_signals(&args.file, language)?;
    if args.limit > 0 {
        report.truncate(args.limit);
    }

    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn parse_language_label(label: &str) -> Result<mati_core::analysis::walker::Language> {
    use mati_core::analysis::walker::Language;
    match label.to_ascii_lowercase().as_str() {
        "rust" => Ok(Language::Rust),
        "typescript" | "ts" => Ok(Language::TypeScript),
        "javascript" | "js" => Ok(Language::JavaScript),
        "python" | "py" => Ok(Language::Python),
        "go" => Ok(Language::Go),
        "java" => Ok(Language::Java),
        "c" => Ok(Language::C),
        "cpp" | "c++" => Ok(Language::Cpp),
        "ruby" | "rb" => Ok(Language::Ruby),
        "scala" => Ok(Language::Scala),
        "elixir" | "ex" => Ok(Language::Elixir),
        "haskell" | "hs" => Ok(Language::Haskell),
        "unknown" => Ok(Language::Unknown),
        other => anyhow::bail!(
            "unknown language label: {other:?}. \
             Valid: rust, typescript, python, go, javascript, java, c, cpp, \
             ruby, scala, elixir, haskell, unknown."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_language_handles_aliases() {
        use mati_core::analysis::walker::Language;
        assert_eq!(parse_language_label("rust").unwrap(), Language::Rust);
        assert_eq!(parse_language_label("ts").unwrap(), Language::TypeScript);
        assert_eq!(parse_language_label("py").unwrap(), Language::Python);
        assert_eq!(parse_language_label("c++").unwrap(), Language::Cpp);
        assert_eq!(parse_language_label("CPP").unwrap(), Language::Cpp);
        assert!(parse_language_label("klingon").is_err());
    }
}
