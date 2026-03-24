# Marketplace Submission Checklist

## Claude Code MCP Marketplace

**What to submit:** `mati.json` from the repo root.

**Steps:**
1. Open a pull request or submission form at https://github.com/anthropics/claude-code-marketplace (or the current intake URL — check https://docs.anthropic.com/claude/claude-code/plugins for the latest).
2. Include `mati.json` in the PR / submission payload.
3. Verify the `server.command` resolves after `cargo install mati` (the binary must be on `$PATH`).
4. Confirm all three tool descriptions in the manifest match `src/mcp/tools.rs` exactly before submitting.

---

## Cursor MCP Marketplace

**What to submit:** `mati-mcp.json` from the repo root.

**Steps:**
1. Submit at https://cursor.sh/marketplace (or via the Cursor extension marketplace submission form — check https://docs.cursor.com/extensions for the current URL).
2. Attach or link `mati-mcp.json`.
3. The `mcpServers.mati.command` must be an installed binary — point reviewers to `cargo install mati` or the install script.
4. Note: `.cursor/mcp.json` is what Cursor reads from a project root automatically; `mati-mcp.json` is the registry submission artifact.

---

## Windsurf MCP Marketplace

**What to submit:** `mati-mcp.json` from the repo root (same format Windsurf uses).

**Steps:**
1. Submit at https://codeium.com/windsurf/mcp or the Windsurf plugin registry — check https://docs.codeium.com/windsurf/mcp for the current intake URL.
2. Provide the `mcpServers` block from `mati-mcp.json`.
3. Include the install command (`cargo install mati`) and the server command (`mati serve`) in the submission description.
