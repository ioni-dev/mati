---
name: setup
description: Set up mati enforcement in the current project. Runs mati init --claude after checking the binary is installed.
disable-model-invocation: true
---

Set up mati in this project. Ask the user before installing anything.

1. Check the binary with `mati --version`. If it is missing, stop and show the
   user these options. Install only the one they pick:
   - `brew install ioni-dev/tap/mati`
   - `curl -fsSL https://github.com/ioni-dev/mati/releases/latest/download/install.sh | bash`
   - `cargo install mati`
2. Offer `mati demo`. It runs deny, consult and allow on a throwaway repo and
   touches nothing in this project.
3. From the repository root, run `mati init --claude`. It scans the repo and
   writes `.mcp.json`, the hooks in `.claude/settings.json`, and
   `.claude/CLAUDE.md`. Show the user its Next steps.
4. Tell the user that Claude Code reads hooks and MCP servers when a session
   starts. They must restart Claude Code in this repo and accept the
   folder-trust prompt. Until then nothing is enforced.
5. Nothing is denied until a gotcha is confirmed. Point the user to
   `/mati-enrich` to draft gotchas and `mati review` to confirm them, or to
   `mati gotcha add <file> -r "<rule>" -m "<reason>" -s high`.

This plugin installs no hooks of its own. `mati init` writes enforcement per
project, so repos that never ran it are untouched.
