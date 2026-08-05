//! Command classification — is this a known action tool, a schema
//! introspection call, or something else. Pure, no I/O.

use super::*;

// ── Command Classification ──────────────────────────────────────────────────

const CAT_LIKE: &[&str] = &["cat", "less", "head", "tail", "bat"];
const GREP_LIKE: &[&str] = &["grep", "egrep", "fgrep", "rg", "sed", "awk"];
const DB_CLIENT_LIKE: &[&str] = &[
    "psql",
    "mysql",
    "mariadb",
    "redis-cli",
    "mongosh",
    "mongo",
    "sqlite3",
    "sqlcmd",
];

pub(super) const ACTION_TOOL_DB_CLIENT: &str = "db_client";
pub(super) const ACTION_TOOL_FILE_READ: &str = "file_read";
pub(super) const ACTION_TOOL_PATH: &str = "path";

/// The action categories emitted by the normalizer and accepted by policy
/// matching. Keep this as the single source for author-time recognition too.
pub const KNOWN_ACTION_TOOLS: &[&str] = &[
    ACTION_TOOL_DB_CLIENT,
    ACTION_TOOL_FILE_READ,
    ACTION_TOOL_PATH,
];

/// Return whether a policy trigger names an action category emitted by the
/// normalizer. Unknown values remain valid authoring data, but cannot match.
pub fn is_known_action_tool(tool: &str) -> bool {
    KNOWN_ACTION_TOOLS.contains(&tool)
}

/// Returns true if `trimmed` starts with `word` followed by whitespace
/// (or is exactly `word`). Prevents `"catch"` matching `"cat"`.
fn matches_command_word(trimmed: &str, word: &str) -> bool {
    if trimmed.len() < word.len() {
        return false;
    }
    if !trimmed.starts_with(word) {
        return false;
    }
    if trimmed.len() == word.len() {
        return true;
    }
    trimmed.as_bytes()[word.len()].is_ascii_whitespace()
}

/// Command prefixes that wrap the real command without changing what it reads:
/// `sudo cat …`, `env LOG=1 cat …`, `nice cat …`. Stripped before classifying
/// so the read gate sees `cat`, not the wrapper. Wrapper *flags* (e.g.
/// `sudo -u root`) are intentionally NOT parsed here — guessing which take a
/// value risks mis-stripping a real argument, so that narrow case is left as a
/// tracked gap rather than handled unsafely.
const PREFIX_WORDS: &[&str] = &[
    "sudo", "doas", "env", "nice", "ionice", "nohup", "setsid", "stdbuf", "command", "time",
];

/// Is `tok` a `NAME=VALUE` shell environment assignment?
fn is_env_assignment(tok: &str) -> bool {
    match tok.find('=') {
        Some(eq) if eq > 0 => {
            let name = &tok[..eq];
            name.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        _ => false,
    }
}

/// Normalize a command for detection: strip leading env assignments and wrapper
/// prefixes (`sudo`/`env`/`nice`/…), then reduce the command word to its
/// basename (`/bin/cat` → `cat`). Returns the effective command, left-trimmed.
/// Pure; closes the prefix and absolute-path bypass classes for the read gate.
pub(super) fn effective_command(cmd: &str) -> String {
    let mut rest = cmd.trim_start();
    loop {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let tok = &rest[..end];
        if tok.is_empty() {
            break;
        }
        if is_env_assignment(tok) || PREFIX_WORDS.contains(&tok) {
            rest = rest[end..].trim_start();
            continue;
        }
        break;
    }
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let (word, args) = rest.split_at(end);
    let base = word.rsplit('/').next().unwrap_or(word);
    let mut out = String::with_capacity(base.len() + args.len());
    out.push_str(base);
    out.push_str(args);
    out
}

/// Fuzz-only reexport of the private [`effective_command`]. `cargo fuzz`
/// sets `--cfg fuzzing` automatically, so this compiles only under
/// `cargo fuzz build`/`run` and never in a normal build.
#[cfg(fuzzing)]
pub fn effective_command_for_fuzzing(cmd: &str) -> String {
    effective_command(cmd)
}

/// Classify a bash command string. Returns `None` for non-file-read commands.
pub fn classify_command(cmd: &str) -> Option<CommandClass> {
    let eff = effective_command(cmd);
    let trimmed = eff.as_str();
    for &word in CAT_LIKE {
        if matches_command_word(trimmed, word) {
            return Some(CommandClass::CatLike);
        }
    }
    for &word in GREP_LIKE {
        if matches_command_word(trimmed, word) {
            return Some(CommandClass::GrepLike);
        }
    }
    for &word in DB_CLIENT_LIKE {
        if matches_command_word(trimmed, word) {
            return Some(CommandClass::DbClientLike);
        }
    }
    None
}

/// Return whether a command performs an allowlisted database schema
/// introspection. This is deliberately lexical: it recognizes only bounded
/// SQL/meta-command forms and never infers intent from natural language.
pub fn is_schema_introspection(command: &str) -> bool {
    let normalized = effective_command(split_at_shell_operator(command)).to_ascii_lowercase();
    let tokens = shell_tokens(&normalized);

    if tokens
        .iter()
        .any(|token| token.contains("information_schema"))
    {
        return true;
    }

    for token in &tokens {
        let token = token.trim_matches(|c: char| c.is_ascii_punctuation() && c != '\\');
        if ["describe", "desc"]
            .iter()
            .any(|word| token == *word || token.starts_with(&format!("{word} ")))
        {
            return true;
        }
        if ["\\d", "\\dt", "\\d+", "\\l"].iter().any(|meta| {
            token
                .strip_prefix(meta)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
        }) {
            return true;
        }
    }

    tokens.iter().any(|token| {
        let token = token.trim_matches(|c: char| c.is_ascii_punctuation());
        ["show tables", "show columns", "show schemas"]
            .iter()
            .any(|phrase| token == *phrase || token.starts_with(&format!("{phrase} ")))
    }) || tokens.windows(2).any(|pair| {
        pair[0] == "show"
            && matches!(
                pair[1].trim_matches(|c: char| c.is_ascii_punctuation()),
                "tables" | "columns" | "schemas"
            )
    })
}
