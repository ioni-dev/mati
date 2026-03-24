# mati — Enrichment Strategy & Product Ideas

> Reference document for the passive enrichment approach (no Claude API required)
> and product features that make mati genuinely indispensable.
>
> Context: `mati enrich` (M-11) was deprioritised because it requires Claude API
> access, creates friction, and excludes users without API credentials.
> Everything in this document works without any LLM API calls unless explicitly noted.

---

## The Core Problem

After `mati init`, every record has `value: ""`, `confidence: 0.10`, `quality: Suppressed`.
The MCP hook decision matrix requires `confidence >= 0.6 AND confirmed=true AND quality >= 0.4`
to inject anything into Claude's context. So a cold init produces zero value for Claude Code.

Knowledge needs to come from somewhere. The options are:
1. **Batch LLM enrichment** (`mati enrich`) — rejected, requires API
2. **Static extraction** — extract what's already in the code
3. **Passive accumulation** — capture what Claude learns during normal use
4. **Git pattern mining** — derive gotchas from history patterns, not messages

All three non-LLM approaches are viable and complementary.

---

## Priority Stack

```
Done:
  1.1  Doc comment extraction          ✓
  1.2  Co-change pair gotchas          ✓ (gap detection only — confirmed=false stubs)
  1.3  Revert rate gotcha              ✓ (gap detection only)
  1.4  Ownership concentration gotcha  ✓ (gap detection only)
  2.3  PostToolUse doc capture         ✓
  P1   mati explain <file>             ✓
  P2   mati diff for PR review         ✓
  P3   Staleness tied to git diff      ✓
  mati review (candidate workflow)     ✓

Blocked — requires LLM API in hook path:
  2.1  Stop hook + last_assistant_msg  Regex signal rate too low (5–15%), needs LLM extraction
  2.2  PostCompact hook                Regex signal rate too low (20–40%), needs LLM extraction
                                       Prompt written — see section 2.1/2.2 below
```

### The missing piece: candidate confirmation workflow

Approaches 2.1, 2.2, and the auto-gotchas (1.2–1.4) all produce `confirmed: false` records.
Per the hook decision matrix, these are never injected — they exist only as gap signals.
The path from auto-detected candidate → confirmed record is currently `mati gotcha add`
(manual re-entry) or `mati improve <key>` (edit value only). Neither is a proper review flow.

Before implementing 2.1 or 2.2, build a `mati review` command: ✓ done
- Lists candidate records (confirmed=false, quality >= 0.4) sorted by access frequency
- For each: shows the auto-extracted text, prompts "Confirm? Edit? Skip? Delete?"
- Confirm → sets confirmed=true, bumps confidence to source-appropriate level
- Edit → opens the same pre-filled prompts as `mati gotcha edit`
- Skip → leaves as candidate
- Delete → tombstones

Without this, 2.1 and 2.2 produce records that sit at confirmed=false indefinitely.

---

## Part 1: Enrichment — Getting to Useful Coverage Without API Calls

### Tier 1 — Layer 0 Enhancements (zero friction, happens at `mati init`)

#### 1.1 Doc Comment Extraction ✓ done

**What:** Extract the canonical documentation comment per language and store it as `purpose`.

Be language-specific — each language has a strict convention:

| Language | Pattern | Node type | Example |
|---|---|---|---|
| Rust | `//!` at file top | `line_comment` containing `//!` | `//! Manages token lifecycle for auth sessions.` |
| Python | Module docstring | First `string_literal` as top-level statement | `"""Handles JWT token refresh and expiry."""` |
| Go | Package comment | `comment` immediately before `package` decl | `// Package auth implements JWT-based authentication.` |
| TypeScript/JS | `@fileoverview` JSDoc or first `/** */` block | `comment` at file top | `/** @fileoverview Entry point for the auth module. */` |

The parser already captures `line_comment` and `block_comment` nodes via tree-sitter but
currently discards them unless they contain TODO keywords. The change is minimal: capture
the first matching canonical node per language and store it as `file_record.purpose`.

**Confidence:** `0.65` (human-written by the file's own author, not inferred)
**Coverage estimate:** 60–80% of hotspot files in well-maintained codebases
**Honest caveat:** Codebases that need mati most tend to be poorly maintained and have
the fewest doc comments. Coverage will be inversely proportional to how badly you need it.
**Implementation:** 10–20 lines per parser in `src/analysis/parser/*.rs`
**ROI:** Highest of all enrichment approaches. Immediate, zero runtime cost.

---

#### 1.2 Co-Change Pair Gotchas ✓ done — gap detection only, not enrichment

**What:** `GitSignals.co_change_pairs` is already computed but only used for graph edges.
Promote every pair above the threshold as a gotcha candidate automatically.

**Gotcha text:** `"Changed together with X in 47/60 commits (78%) — modifying one
without the other is a known source of bugs."`

Include the ratio — it makes the gotcha credible and lets developers decide whether to care.

**Confidence:** `0.45` — never injected, surfaces in `mati gaps` only
**Classification note:** These are `confirmed: false` stubs. Value is in gap detection
and developer prompts, not in context injection. Do not treat as enrichment.
**Implementation:** In `src/cli/init.rs`, after edges are built, iterate `co_change_pairs`
and write gotcha stubs. All the data is already there.

---

#### 1.3 Revert Rate Gotcha ✓ done — gap detection only, not enrichment

**What:** Scan commit messages for the `"Revert"` prefix per file during the existing
revwalk. Files with >5% revert rate have unstable interfaces.

**Gotcha text:** `"High revert rate (8% of commits) — this interface has been broken
and undone repeatedly. Test carefully before touching."`

**Confidence:** `0.40` — never injected, surfaces in `mati gaps` only
**Classification note:** Same as 1.2 — gap signal, not injectable knowledge.
**Implementation:** One additional counter in `src/analysis/git.rs` during the existing
revwalk — no extra git operations needed.

---

#### 1.4 Ownership Concentration Gotcha ✓ done — gap detection only, not enrichment

**What:** Count commits per author per file. Single-author dominance on a hotspot = knowledge silo.
Currently only `last_author` is stored — extend to track per-author commit counts.

**Gotcha text:** `"78% of commits by one author — key person dependency. If they leave,
context for this file is lost."`

**Threshold:** >80% of commits by one author AND file is a hotspot.
**Confidence:** `0.40` — never injected, surfaces in `mati gaps` only
**Classification note:** Same as 1.2 — knowledge silo signal for developer awareness,
not a rule Claude should act on. Crosses into probabilistic territory if auto-confirmed.
**Implementation:** Extend per-file tracking in `src/analysis/git.rs` to accumulate
author → commit count map. Compute concentration ratio at the end of the revwalk.

---

### Note on Git Commit Messages for Purpose (Rejected)

Commit messages describe *changes*, not *current state*. "Fix null pointer in auth handler"
doesn't tell you what the file IS. For a file with 200 commits there's no reliable message
to pick. Noise is too high.

**Exception:** Creation commit (`--diff-filter=A`) sometimes describes why a file was
created. Worth implementing as a low-confidence fallback (`0.35`) when no doc comment
exists. Not a priority.

---

### Tier 2 — Hook-Based Passive Enrichment (zero API calls, accumulates over time)

#### 2.1 `Stop` Hook + `last_assistant_message` Parsing — blocked on LLM extraction

**What:** The `Stop` hook receives `last_assistant_message` — Claude's full final response
for the turn. Parse it for file path mentions and extract purpose/gotcha candidates.

**Why regex is insufficient:**
`last_assistant_message` is unstructured prose mixed with code, diffs, error output, and
explanations. Regex extraction against this produces a 5–15% signal rate — not useful
enough to justify the noise in `mati review`. Claude does not follow a consistent format,
and shaping instructions in CLAUDE.md do not apply to the Stop hook (only to compaction).

**What is needed — LLM extraction prompt:**
Pass `last_assistant_message` through a single cheap LLM call with the extraction prompt
(see below). The model returns structured JSON: `[{path, purpose?, gotcha?}]`. No free-text
parsing, no false positives. Records written at `confirmed=false`, `confidence=0.60`.

**Blocked on:** LLM API access in the hook path. The hook must complete in <3000ms and
mati has no Claude API client today. Options when unblocked:
- Use `claude-haiku` via API key configured in `.env` / env var
- Use a local model (ollama) if the user has it running

**Extraction prompt:** See end of this section.

---

#### 2.2 `PostCompact` Hook + `compact_summary` Mining — blocked on LLM extraction

**What:** After compaction, the `PostCompact` hook receives `compact_summary` — Claude's
distilled understanding of everything it read and did this session. This is the
highest-quality passive source because it covers the whole session in depth.

**Why regex is insufficient even with CLAUDE.md shaping:**
The compaction instruction (`"When compacting context, note each file's purpose..."`) nudges
Claude toward structure but does not guarantee it. Claude shapes its summary around the
conversation — a code-heavy session produces code-heavy summaries, not knowledge records.
Regex extraction still has ~20–40% signal rate with shaping, which produces a noisy review
queue over time.

**What is needed — LLM extraction prompt:**
Same as 2.1. Pass `compact_summary` through the extraction prompt. Higher confidence (0.65)
because the input is session-wide rather than turn-level.

**Blocked on:** Same as 2.1. PostCompact is higher priority than Stop once unblocked —
`compact_summary` fires rarely but is much denser signal per token.

**Extraction prompt (shared by 2.1 and 2.2):**

```
You are extracting engineering knowledge from an AI assistant's response.

INPUT: A message from an AI assistant that may mention source files and contain
knowledge about them — their purpose, gotchas, or important constraints.

TASK: For each source file mentioned, extract any of:
- purpose: one sentence describing what the file does (present tense, starts with a verb)
- gotcha: a non-obvious rule a developer must know before editing the file

OUTPUT: Return a JSON array. Each element has:
  {
    "path": "src/relative/path.ext",        // required — repo-relative path
    "purpose": "Manages JWT token lifecycle", // optional — omit if not found
    "gotcha": "Tokens expire 5min before stated TTL due to clock skew with middleware"
              // optional — omit if no clear rule found
  }

RULES:
- Only include files with at least one clear purpose or gotcha
- Purpose must describe what the file IS, not what was changed ("Manages X", not "Fixed X")
- Gotcha must be a concrete rule, not a vague observation ("tokens expire early", not "be careful")
- If unsure, omit rather than guess
- Return [] if nothing is extractable

INPUT:
{message}
```

---

#### 2.3 `PostToolUse` on `Write|Edit` — Capture Authored Doc Comments ✓ done

**What:** When Claude writes or edits a file and the new content contains a canonical
doc comment (`//!`, `///`, module docstring, package comment), that IS the purpose.
The `PostToolUse` hook fires with `tool_input.content` (Write) or `tool_input.new_string`
(Edit).

**Why this is different from 2.1/2.2:** The signal is unambiguous. Claude wrote a doc
comment at the top of the file — that text is the purpose by definition. No regex
fragility, no interpretation required.

**Confidence:** `0.65`
**Implementation:** Extend existing `post_edit.sh` hook. Already fires on Write|Edit.
Add doc comment pattern detection before the existing access counter logic. Only capture
if the doc comment is at the top of the file or is a module-level comment.

---

## Part 2: Product Features

### P1 — `mati explain <file>` — File Health Card ✓ done

A dedicated CLI command that aggregates everything mati knows about a file and displays
it as a structured health card. Uses only data already in the store — no Claude needed,
no API calls.

```
$ mati explain src/auth/session.rs

  session.rs — token lifecycle management
  confidence 0.72  quality Good  hotspot #3

  Gotchas (2)
  ● tokens expire 5min before stated TTL — clock skew with middleware
  ● refresh must happen atomically — concurrent requests cause double-issue

  Decisions linked
  ● decision:jwt-expiry-window — 5min buffer chosen after prod incident

  Co-changes with
  ● src/auth/middleware.rs  (78% of commits)
  ● src/auth/handler.rs     (61% of commits)

  Stability
  ● 3 reverts in last 6 months — unstable
  ● Last changed 2 days ago by alice

  TODOs (1)
  ● line 47: TODO(bob) handle concurrent refresh race
```

A developer runs this before touching a file and immediately knows every landmine.
Takes under 100ms.

**Also works for Claude Code agents:**
When a user tells Claude "explain src/auth/session.rs using mati", Claude calls
`mem_bootstrap(["src/auth/session.rs"])` — the MCP tool already returns purpose,
gotchas, confidence, quality, and co-change partners. Claude formats it as an explanation.
No new MCP tool needed, the 3-tool hard limit is preserved.

**Implementation:** New `mati explain <path>` command. Aggregates `file:`, `gotcha:`,
`decision:` records from store plus co-change signals from graph. All data already exists.

---

### P2 — `mati diff <branch>` — PR Review Safety Net ✓ done

Cross-references a git diff against the knowledge store and surfaces relevant gotchas
at the highest-risk moment: before merge.

```
$ mati diff main..feature-auth

  Files changed in this PR with existing knowledge records:

  ⚠  src/auth/session.rs  — 2 confirmed gotchas
     → tokens expire 5min early (confidence 0.82)
     → refresh must be atomic (confidence 0.76)

  ✓  src/auth/handler.rs  — documented, no gotchas flagged
  ○  src/auth/new_feature.rs — no records yet
```

Can also run as an async `PostToolUse` hook on `git merge` / `git push` Bash commands
so Claude Code users see the relevant gotchas automatically without having to remember
to check.

**Implementation:** `git diff --name-only <ref>` piped through the store to look up
records for each changed file. Pure CLI, no new store capabilities needed.

---

### P3 — Staleness Tied to Actual Git Changes ✓ implement

**The problem with current staleness:** It is purely time-based — records decay by age
and last-access. This produces noise: a record written yesterday about a file that was
completely rewritten last month is flagged "fresh." A record from two years ago about a
file that hasn't changed since is flagged "stale." The axis is wrong.

**The right axis: file divergence since the record was written.**

During `mati init`, the incremental pass already detects which files changed via mtime.
For those files, store a `content_hash` (SHA256 of file content) in `FileRecord.payload`.
On the next init, if the hash changed, compute how much using line count delta:

| Change magnitude | Lines changed | Staleness signal | Record treatment |
|---|---|---|---|
| Minor edit | < 10% | `MinorEdit` | Record still valid |
| Significant change | 10–50% | `SignificantEdit` | Flag for review |
| Rewrite | > 50% | `FileRewritten` | Likely wrong, warn loudly |

`mati stale` then shows something actionable instead of "this is old":

```
⚠  src/auth/session.rs
   File changed +47/-31 lines since this record was written
   Record last updated: 2025-11-15  |  File last changed: 2026-01-23
   → mati improve gotcha:session-token-expiry
```

**The second layer — implicit staleness from co-change coupling:**

If `session.rs` changed significantly but `middleware.rs` record was not updated,
and they co-change 78% of the time, then `middleware.rs` is also potentially stale
even though the file itself didn't change. The coupling tells you a change in one
likely invalidated knowledge about the other.

```
⚠  src/auth/middleware.rs  (implicit — co-changes with session.rs which was rewritten)
```

**Implementation:** During the incremental init pass in `src/cli/init.rs`, when a file's
mtime changes, recompute content hash and compare with stored hash in `FileRecord`. Compute
line count delta. Write the appropriate `StalenessSignal` variant to the record.
For implicit staleness: after processing all changed files, check their co-change partners
and flag those records too.

---

## What NOT to Build

- **Do not** try to extract `purpose` from general commit messages — noise is too high
- **Do not** run NLP or ML on commit messages without a proper pipeline
- **Do not** require Claude API for any feature in this document
- **Do not** make `mati diff` or `mati guard` blocking by default — opt-in first
- **Do not** auto-confirm passive enrichment records (2.1, 2.2) — always confirmed=false
  until a human reviews them via `mati review`

---

*Last updated: 2026-03-21. Restructured to separate enrichment (injectable) from gap
detection (confirmed=false stubs), and to block passive hook approaches on the missing
candidate confirmation workflow (`mati review`).*
