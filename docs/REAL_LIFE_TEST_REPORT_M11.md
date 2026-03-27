# M-11 Real-Life Test Report — MCP-Native Enrichment

**Date:** 2026-03-26
**Branch:** `main` (post-PR #12 merge)
**Test environment:** macOS Darwin 25.3.0, Claude Code session on Xok project (`mati serve` active)
**Binary:** mati v0.1.0 installed from source via `cargo install --path .`

---

## Test Matrix

| # | Prompt | Expected | Result | Notes |
|---|--------|----------|--------|-------|
| 1 | `mati init` (fresh repo) | Creates store, `.claude/CLAUDE.md` (~22 lines), settings.json, 6 hooks | **PASS** | Tested in `/tmp/mati-test-init`. Required fix: `mati init` was not creating `.claude/` directory — scaffold functions silently skipped. Fixed by adding `create_dir_all` before scaffold writes. |
| 2 | `/mati-enrich src/main.rs` | Claude reads file, calls `mem_set` for purpose + gotchas, reminds `mati review` | **PASS** | Claude followed CLAUDE.md workflow. Called `mem_get` first, read file, generated purpose + 2 gotchas, wrote via `mem_set`. All records: confidence=0.60, confirmed=false. Reminded to run `mati review`. |
| 3 | "add that as a gotcha for src/main.rs" | `mem_set` with category=Gotcha, confirmed=false, imperative verb | **PASS** | Claude called `mem_set` immediately without asking for confirmation. Key: `gotcha:main-silent-error-swallow`. Rule starts with "Never" (imperative). confirmed=false. Priority: High. |
| 4 | "Remember this: deploy script requires AWS_REGION" | `mem_set` with category=DevNote | **PASS** | Claude called `mem_set` with category=DevNote, key=`dev_note:deploy-aws-region-default`. No confirmation asked. |
| 5 | `mati ls gotchas` / `mati stats` | Records appear, unconfirmed warning shown | **PARTIAL FAIL** | CLI commands fail with lock error: "cannot open knowledge.db — another mati process holds the lock." StoreProxy not routing through daemon socket on Xok project. Workaround: used `mem_query` via MCP — all records confirmed present. |
| 6 | Read src/main.rs (pre-read hook) | Hook fires, `mem_get` called first, additionalContext if enriched | **PASS** | `mem_get` returned enriched record (confidence=0.60). Record not confirmed (confirmation_count=0), quality=0.07 (Suppressed). Claude correctly proceeded to file read since not confirmed. Hook allowed read. |
| 7 | `mati review` | Unconfirmed gotchas appear for confirmation | **FAIL** | "mati review requires an interactive terminal." Expected — Claude Code runs commands non-interactively. Also blocked by store lock (MCP server active). Must be run in external terminal after closing Claude Code session. |
| 8 | `/mati-enrich xok-cli/src/` (directory) | Enriches multiple files, batch report, review reminder | **PASS** | 19 files enriched + 4 gotchas discovered. All `mem_set` calls succeeded (confidence=0.60). Batch report shown with file table. Ended with "Run `mati review` to activate hook enforcement." |

---

## Bugs Found

### Bug 1: `mati init` does not create `.claude/` directory (FIXED)

**Severity:** Critical — scaffold is never written on fresh repos.

**Symptom:** `mati init` reports "Writing .claude/CLAUDE.md stub... 0ms" and "Installing hooks... 0ms" but no files are created. Exit code 0 (misleading success).

**Root cause:** Both `write_claude_md_stub()` and `install_hooks()` check `if !claude_dir.is_dir() { return Ok(NoClaude) }` — they skip silently when `.claude/` doesn't exist. Fresh repos (and repos not using Claude Code) never have this directory.

**Fix:** Added `std::fs::create_dir_all(&claude_dir)` in `src/cli/init.rs` before scaffold function calls.

**Status:** Fixed, committed on main.

### Bug 2: Binary PATH mismatch

**Severity:** High — user runs old binary without knowing.

**Symptom:** `cargo install --path .` installs to `~/.cargo/bin/mati` but `which mati` returns `~/.local/bin/mati` (older copy, 7 hours stale).

**Root cause:** User has both `~/.cargo/bin` and `~/.local/bin` in PATH, with `~/.local/bin` taking precedence. A previous manual copy exists at `~/.local/bin/mati`.

**Fix:** Manual: `cp ~/.cargo/bin/mati ~/.local/bin/mati`. Not a code bug — environment issue.

### Bug 3: CLI commands fail with lock error while MCP server running (REGRESSION?)

**Severity:** High — `mati ls`, `mati stats`, `mati review` all unusable during Claude Code sessions.

**Symptom:** `mati ls gotchas` → "cannot open knowledge.db — another mati process (MCP server or daemon) holds the lock."

**Expected:** StoreProxy should detect the daemon socket and route through it. This was working in the previous test session (PR #10 — 28 commands tested with zero lock errors).

**Possible causes:**
1. Xok project not re-initialized after StoreProxy changes (old settings.json, no daemon socket)
2. StoreProxy code regression in recent PRs
3. `mati serve` not binding the daemon socket on the Xok project

**Status:** Not yet investigated.

### Bug 4: `mati review` requires interactive terminal

**Severity:** Medium — expected behavior, but creates UX gap.

**Symptom:** `mati review` from Claude Code Bash tool → "requires an interactive terminal."

**Root cause:** `mati review` uses `dialoguer` (FuzzySelect, Input, Confirm) which requires a TTY. Claude Code's Bash tool runs non-interactively.

**Expected behavior:** Developer runs `mati review` in their own terminal after enrichment. The prompts and scaffold both direct them to do this.

**Status:** Known limitation. Documented in CLAUDE.md scaffold and test report.

---

## Schema Enforcement Results

The 4 scaffold restructure changes (PR #12) were validated:

| Change | Observed Effect |
|--------|-----------------|
| **schemars field descriptions** | `mem_set` calls used correct payload structures — gotchas had `rule`, `reason`, `severity`, `confirmed:false`. File records preserved Layer 0 fields (`entry_points`, `imports`, `change_frequency`). Schema descriptions guided Claude to correct format without prose instructions. |
| **Strengthened mem_set description** | "add that as a gotcha" trigger worked (Prompt 3). "remember this" trigger worked (Prompt 4). Claude called `mem_set` immediately without asking for confirmation — the tool description's "Do not ask for confirmation" instruction was followed. |
| **Shrunk CLAUDE.md (71→22 lines)** | `/mati-enrich` workflow was followed correctly from the 3-line trigger in CLAUDE.md. Claude read the mem_set tool description for payload format details. Token savings: ~50 lines of prose no longer loaded into every context window. |
| **Vector B capture triggers** | Not directly testable in this session (would need session restart to see `mem_bootstrap` output). The trigger text is compiled into the binary. |

---

## Quality Scores Observed

| Record | Quality | Tier | Notes |
|--------|---------|------|-------|
| `gotcha:intercept-silent-swallow` | 0.81 | Good | Strong imperative verb + causality reason |
| `gotcha:mcp-needs-shell` | 0.70 | Good | Security-focused, specific identifier |
| `gotcha:main-diff-read-rewrap` | 0.29 | Poor | Reason present but rule lacks specificity |
| `gotcha:daemon-unsafe-kill` | 0.29 | Poor | Short rule, weak causality signal |
| `gotcha:ipc-empty-inference-passthrough` | 0.27 | Poor | Rule adequate but reason lacks detail |
| `gotcha:main-pipe-fallback` | 0.21 | Poor | Generic phrasing detected |
| File records (all 20) | 0.07 | Suppressed | Expected — file purpose strings are short sentences, quality formula weights gotcha-specific signals (imperative verb, causality, severity) |

**Observation:** The quality analyzer is tuned for gotcha records. File records score Suppressed because they don't have rule/reason/severity structure. This is acceptable — file quality is informational, not gating. Gotcha quality gates (deny path requires quality >= 0.4) correctly filter: only `intercept-silent-swallow` (0.81) and `mcp-needs-shell` (0.70) would pass the injection gate after confirmation.

---

## Enrichment Statistics

```
Files enriched:     20 (19 new + 1 re-enriched)
Gotchas written:     7 (3 from prompt 2-3, 4 from prompt 8)
DevNotes written:    1
Total mem_set calls: 28
Failed mem_set:      0
Avg response time:   <200ms per mem_set call
```

---

## Recommendations

1. **Investigate StoreProxy lock regression** — CLI commands must work while MCP server runs. This was the core feature of PR #10.
2. **Consider `mati review --non-interactive`** — batch-confirm all pending gotchas without TUI. Would allow review from within Claude Code.
3. **File record quality scoring** — consider a separate quality formula for file records that weights purpose length and verb-starts instead of rule/reason structure.
4. **`mati init` success message** — print "Created .claude/ directory" when creating it, so users see it happened.
