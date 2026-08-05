//! File path extraction from shell commands. Pure, no I/O.

use super::*;

// ── File Path Extraction ────────────────────────────────────────────────────

/// Extract the PRIMARY target file path from a classified command — the first
/// file for cat-like, the last positional for grep-like. The single-path
/// companion to [`extract_file_paths`]; see it for the tokenizer + grammar.
pub fn extract_file_path(cmd: &str, class: CommandClass) -> Option<String> {
    let paths = extract_file_paths(cmd, class);
    match class {
        CommandClass::CatLike => paths.into_iter().next(),
        CommandClass::GrepLike => paths.into_iter().next_back(),
        CommandClass::DbClientLike => paths.into_iter().next(),
    }
}

/// Extract ALL target file paths from a classified command, in order. The
/// multi-file companion to [`extract_file_path`] — lets the read gate catch a
/// gotcha on a non-first file (`cat a.rs b.rs`, `grep pat f1 f2`).
///
/// Tokenizes the command shell-style (honoring quotes) and reads files by each
/// command's real grammar:
/// - CatLike (`cat/less/head/tail/bat FILE...`): every positional is a file.
/// - GrepLike (`grep/rg/sed/awk [flags] PATTERN [FILE...]`): the first
///   positional is the search PATTERN; the rest are files (none after the
///   pattern ⇒ stdin, so no files).
///
/// Using real tokens + position — instead of a "the file is whatever's quoted"
/// heuristic — is what lets `grep -r "secret" src/db.rs` resolve to `src/db.rs`
/// (the path) not `secret` (the quoted pattern), while still handling quoted
/// paths that contain spaces. Stops at pipe (`|`), semicolon (`;`), `&&`, `||`.
pub fn extract_file_paths(cmd: &str, class: CommandClass) -> Vec<String> {
    // Same normalization as `classify_command` so prefixes/abs-paths don't
    // throw off extraction (`sudo cat foo` must extract `foo`, not `cat`).
    let eff = effective_command(cmd);
    let cmd_part = split_at_shell_operator(&eff);
    let tokens = shell_tokens(cmd_part);

    match class {
        CommandClass::CatLike => positional_args(&tokens),
        CommandClass::GrepLike => {
            let positionals = positional_args(&tokens);
            if positionals.len() >= 2 {
                positionals[1..].to_vec()
            } else {
                Vec::new()
            }
        }
        CommandClass::DbClientLike => extract_db_file_paths(&tokens),
    }
}

/// Extract DB-client file arguments from `-f/--file` and their `=value` forms.
fn extract_db_file_paths(tokens: &[String]) -> Vec<String> {
    let mut files = Vec::new();
    let mut expects_file = false;
    for token in tokens.iter().skip(1) {
        if expects_file {
            if !token.is_empty() {
                files.push(token.clone());
            }
            expects_file = false;
            continue;
        }
        if token == "-f" || token == "--file" {
            expects_file = true;
        } else if let Some(path) = token.strip_prefix("--file=") {
            if !path.is_empty() {
                files.push(path.to_string());
            }
        } else if let Some(path) = token.strip_prefix("-f=") {
            if !path.is_empty() {
                files.push(path.to_string());
            }
        }
    }
    files
}

/// Extract a DB host from `-h/--host` or a leading environment assignment.
fn extract_db_host(command: &str) -> Option<String> {
    let tokens = shell_tokens(split_at_shell_operator(command));
    let mut expects_host = false;
    let mut env_host = None;
    for token in &tokens {
        if expects_host {
            return (!token.is_empty()).then(|| token.clone());
        }
        if token == "-h" || token == "--host" {
            expects_host = true;
        } else if let Some(host) = token.strip_prefix("--host=") {
            return (!host.is_empty()).then(|| host.to_string());
        } else if let Some(host) = token.strip_prefix("-h=") {
            return (!host.is_empty()).then(|| host.to_string());
        } else if let Some(value) = token.strip_prefix("PGHOST=") {
            if !value.is_empty() {
                env_host = Some(value.to_string());
            }
        } else if let Some(value) = token.strip_prefix("DATABASE_URL=") {
            env_host = database_url_host(value);
        }
    }
    env_host
}

/// Pull the authority host from a DATABASE_URL without introducing a URL
/// parser into the pure command-normalization core.
fn database_url_host(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let authority = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(value)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let host = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let host = host
        .rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
        .map(|(host, _)| host)
        .unwrap_or(host);
    (!host.is_empty()).then(|| host.to_string())
}

/// Normalize a command and/or path into the pure policy-matching action shape.
pub fn normalize_action(command: Option<&str>, target_path: Option<&str>) -> Action {
    let mut action = Action {
        tool: "unknown".to_string(),
        target_path: target_path.map(str::to_string),
        host: None,
        argv: vec![],
        files: target_path.into_iter().map(str::to_string).collect(),
    };

    let Some(command) = command else {
        if action.target_path.is_some() {
            action.tool = "path".to_string();
        }
        return action;
    };

    let effective = effective_command(split_at_shell_operator(command));
    action.argv = shell_tokens(&effective);
    if let Some(class) = classify_command(command) {
        match class {
            CommandClass::DbClientLike => {
                action.tool = ACTION_TOOL_DB_CLIENT.to_string();
                action.host = extract_db_host(command).or_else(|| extract_db_host(&effective));
                action.files.extend(extract_file_paths(command, class));
            }
            CommandClass::CatLike | CommandClass::GrepLike => {
                action.tool = ACTION_TOOL_FILE_READ.to_string();
                action.files.extend(extract_file_paths(command, class));
            }
        }
    }
    if action.target_path.is_none() {
        action.target_path = action.files.first().cloned();
    }
    if action.tool == "unknown" && action.target_path.is_some() {
        action.tool = ACTION_TOOL_PATH.to_string();
    }
    action
}

/// Split at the first shell operator (`|`, `;`, `&&`, `||`), returning the
/// portion before the operator.
pub(super) fn split_at_shell_operator(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'|' => {
                // Could be `|` (pipe) or `||` — both mean stop.
                return &s[..i];
            }
            b';' => return &s[..i],
            b'&' if i + 1 < bytes.len() && bytes[i + 1] == b'&' => {
                return &s[..i];
            }
            b'"' => {
                // Skip quoted strings so we don't split on operators inside quotes.
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += 1;
                }
            }
            b'\'' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    s
}

/// Split a command into shell-style tokens, honoring single and double quotes
/// (the quotes are stripped from the returned tokens). Not a full shell parser
/// — enough for path extraction: a quoted path keeps its spaces as one token,
/// and a quoted pattern becomes just its inner text. Runs of whitespace are
/// collapsed; an unterminated quote consumes to end of input (best effort).
pub(super) fn shell_tokens(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' => {
                in_token = true;
                let quote = c;
                for q in chars.by_ref() {
                    if q == quote {
                        break;
                    }
                    cur.push(q);
                }
            }
            c if c.is_whitespace() => {
                if in_token {
                    tokens.push(std::mem::take(&mut cur));
                    in_token = false;
                }
            }
            c => {
                in_token = true;
                cur.push(c);
            }
        }
    }
    if in_token {
        tokens.push(cur);
    }
    tokens
}

/// Positional (non-flag) arguments after the command word, in order. Skips a
/// purely-numeric token that follows a flag — it is the flag's value, not a
/// file (`tail -n 100 file`, `head -c 5 file`).
fn positional_args(tokens: &[String]) -> Vec<String> {
    let mut args = Vec::new();
    let mut prev_was_flag = false;
    for t in tokens.iter().skip(1) {
        if t.starts_with('-') {
            prev_was_flag = true;
            continue;
        }
        if prev_was_flag && !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
            prev_was_flag = false;
            continue;
        }
        prev_was_flag = false;
        if !t.is_empty() {
            args.push(t.clone());
        }
    }
    args
}
