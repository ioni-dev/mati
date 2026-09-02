//! File path extraction from shell commands. Pure, no I/O.

use super::*;

// ── File Path Extraction ────────────────────────────────────────────────────

/// Extract the PRIMARY target file path from a classified command — the first
/// file for cat-like, the last positional for grep-like. The single-path
/// companion to [`extract_file_paths`]; see it for the tokenizer + grammar.
pub fn extract_file_path(cmd: &str, class: CommandClass) -> Option<String> {
    let paths = extract_file_paths(cmd, class);
    match class {
        CommandClass::CatLike | CommandClass::PathMutating => paths.into_iter().next(),
        CommandClass::GrepLike => paths.into_iter().next_back(),
        CommandClass::DbClientLike => paths.into_iter().next(),
        CommandClass::VcsRead | CommandClass::InterpreterSource | CommandClass::CopyLike => {
            paths.into_iter().next()
        }
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
    // Interpreter source is scanned whole: a literal can be assigned in an
    // earlier segment (`F="keys.py"; python3 -c "…$F…"`), so restricting the
    // scan to the interpreter's own segment would lose it.
    if class == CommandClass::InterpreterSource {
        return extract_interpreter_paths(cmd);
    }
    shell_segments(cmd)
        .into_iter()
        .filter(|seg| classify_command(seg) == Some(class))
        .flat_map(|seg| extract_segment_paths(seg, class))
        .collect()
}

/// Extract paths from ONE already-classified segment.
fn extract_segment_paths(cmd: &str, class: CommandClass) -> Vec<String> {
    // Same normalization as `classify_command` so prefixes/abs-paths don't
    // throw off extraction (`sudo cat foo` must extract `foo`, not `cat`).
    let eff = effective_command(cmd);
    let cmd_part = split_at_shell_operator(&eff);
    let tokens = shell_tokens(cmd_part);

    match class {
        CommandClass::CatLike | CommandClass::PathMutating => positional_args(&tokens),
        CommandClass::GrepLike => {
            let positionals = positional_args(&tokens);
            if positionals.len() >= 2 {
                positionals[1..].to_vec()
            } else {
                Vec::new()
            }
        }
        CommandClass::DbClientLike => extract_db_file_paths(&tokens),
        CommandClass::VcsRead => extract_vcs_file_paths(&tokens),
        CommandClass::CopyLike => extract_copy_source_paths(&tokens),
        // Scans the RAW command, not `cmd_part`: a heredoc body carries its own
        // `;` and `|`, which `split_at_shell_operator` would cut the source at.
        CommandClass::InterpreterSource => extract_interpreter_paths(cmd),
    }
}

/// Extract paths from a git invocation. Handles the `<rev>:<path>` form that
/// `git show`/`cat-file` use, everything after a `--` separator, and bare
/// positionals.
///
/// The first two forms are paths by git's own grammar, so they are taken as-is
/// — `git show HEAD:Makefile` resolves. A bare positional is ambiguous with a
/// rev (`git show HEAD`, `git grep -n TODO`), so it must look like a path to
/// count. That drops an extensionless filename passed bare to `git blame`;
/// the `--` and `rev:` forms cover it, and the cost of the alternative is a
/// store lookup on every rev the agent ever names.
fn extract_vcs_file_paths(tokens: &[String]) -> Vec<String> {
    let mut files = Vec::new();
    let mut seen_subcommand = false;
    let mut i = 1;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        if tok == "--" {
            files.extend(tokens[i + 1..].iter().cloned());
            break;
        }
        if GIT_VALUE_FLAGS.contains(&tok) {
            i += 2;
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        if !seen_subcommand {
            seen_subcommand = true;
            i += 1;
            continue;
        }
        match tok.split_once(':') {
            Some((_rev, path)) if !path.is_empty() => files.push(path.to_string()),
            Some(_) => {}
            None if looks_like_path_literal(tok) => files.push(tok.to_string()),
            None => {}
        }
        i += 1;
    }
    files
}

/// Extract the SOURCE paths of a copy-like command: every positional except
/// the destination, plus `dd`'s `if=`. The destination is deliberately left
/// out — a write onto a governed path is the `PathMutating` question, and
/// gating a copy's target would deny writing INTO an ungoverned temp file.
fn extract_copy_source_paths(tokens: &[String]) -> Vec<String> {
    if let Some(src) = tokens
        .iter()
        .find_map(|t| t.strip_prefix("if=").filter(|s| !s.is_empty()))
    {
        return vec![src.to_string()];
    }
    let mut positionals = positional_args(tokens);
    positionals.pop();
    positionals
}

/// Bound on paths pulled out of interpreter source. Each one costs a daemon
/// round-trip in the read gate, and the hook runs inside a 2500ms deadline.
pub(super) const MAX_INTERPRETER_PATHS: usize = 16;

/// Extract candidate file paths from interpreter source: any quoted literal
/// that is *entirely* a path, plus bare positional arguments (`python3
/// manage.py`).
///
/// Requiring the whole quoted region to be a path is what separates
/// `open('keys.py')` from `console.log(process.env.HOME)` — the first quotes
/// the path and nothing else, the second quotes an expression that merely
/// contains `stem.ext` fragments. Nested quotes are covered because the single-
/// and double-quote passes run independently over the raw command, so the inner
/// `'keys.py'` of a double-quoted `-c` argument is its own region.
///
/// Scanning literals rather than parsing is what makes `path = "keys.py"` …
/// `open(path)` resolve with no dataflow analysis. Two known misses, both
/// fail-open: a path the source computes rather than spells (`open("keys" +
/// ".py")`, `open(sys.argv[1])`), and a shifted quote parity from an odd count
/// of quote characters earlier in the command, such as a Python triple-quoted
/// block before the literal.
fn extract_interpreter_paths(cmd: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for quote in ['\'', '"'] {
        let mut parts = cmd.split(quote);
        parts.next();
        let mut inside = true;
        for part in parts {
            if inside && looks_like_path_literal(part.trim()) {
                push_unique(&mut out, part.trim().to_string());
            }
            inside = !inside;
        }
    }
    // Truncate at a heredoc operator: everything past `<<` is source, not
    // arguments, and tokenizing it turns `import os.path` into a file path.
    let args_only = cmd.split_once("<<").map_or(cmd, |(head, _)| head);
    let eff = effective_command(split_at_shell_operator(args_only));
    for arg in positional_args(&shell_tokens(&eff)) {
        if looks_like_path_literal(&arg) {
            push_unique(&mut out, arg);
        }
    }
    out
}

fn push_unique(out: &mut Vec<String>, cand: String) {
    if out.len() < MAX_INTERPRETER_PATHS && !out.contains(&cand) {
        out.push(cand);
    }
}

/// Is `run` a bare file path — path characters only, and either containing a
/// directory separator or shaped like `stem.ext` with an alphabetic stem and a
/// 1-8 character alphanumeric extension?
fn looks_like_path_literal(run: &str) -> bool {
    if run.is_empty() || run.len() > 512 {
        return false;
    }
    if !run
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '~'))
    {
        return false;
    }
    if run.contains('/') {
        return true;
    }
    let Some((stem, ext)) = run.rsplit_once('.') else {
        return false;
    };
    !stem.is_empty()
        && stem.chars().any(|c| c.is_ascii_alphabetic())
        && (1..=8).contains(&ext.len())
        && ext.chars().all(|c| c.is_ascii_alphanumeric())
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
            CommandClass::CatLike
            | CommandClass::GrepLike
            | CommandClass::VcsRead
            | CommandClass::InterpreterSource
            | CommandClass::CopyLike => {
                action.tool = ACTION_TOOL_FILE_READ.to_string();
                action.files.extend(extract_file_paths(command, class));
            }
            CommandClass::PathMutating => {
                action.tool = ACTION_TOOL_PATH.to_string();
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

/// Split a command into its shell segments at `;`, `&&`, `||` and `|`,
/// honoring quotes. Trimmed, empties dropped.
///
/// Exists because classifying only the first command let `echo hi && cat f`
/// through the gate: a two-character prefix hid every governed read behind an
/// operator (measured 2026-08-29, live). Each segment is classified on its own.
///
/// Splitting STOPS at a heredoc operator: everything from `<<` to the end is
/// one segment, because a heredoc body carries its own `;` and `|` that are
/// source text, not shell operators.
pub(super) fn shell_segments(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let (mut start, mut i) = (0usize, 0usize);
    while i < b.len() {
        match b[i] {
            b'\'' | b'"' => {
                let quote = b[i];
                i += 1;
                while i < b.len() && b[i] != quote {
                    i += 1;
                }
            }
            b'<' if i + 1 < b.len() && b[i + 1] == b'<' => break,
            b';' => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            b'&' if i + 1 < b.len() && b[i + 1] == b'&' => {
                out.push(&s[start..i]);
                i += 1;
                start = i + 1;
            }
            b'|' => {
                out.push(&s[start..i]);
                if i + 1 < b.len() && b[i + 1] == b'|' {
                    i += 1;
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(&s[start..]);
    out.into_iter()
        .map(str::trim)
        .filter(|seg| !seg.is_empty())
        .collect()
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
