---
name: codegraph
description: Query the pre-built CodeGraph knowledge graph (call chains, definitions, dependents) instead of grepping/reading files to find code. Use FIRST when asking "who calls X", "where is Y defined", "what depends on Z", or orienting in an unfamiliar module.
---

# codegraph — the pre-indexed code graph

CodeGraph (v1.6.0, installed 2026-09-01 at `~/.local/bin/codegraph`, TK-1)
holds a local knowledge graph of this repo — functions, classes, imports,
call chains — at `.codegraph/` (gitignored; 309 files, ~8.8k nodes). It
auto-syncs on file save. It is registered as a **global MCP server for
Claude Code** (`codegraph serve --mcp`), so sessions started after
2026-09-01 have its MCP tools available directly — prefer those tools over
shell calls when they appear in your tool list.

NOTE (2026-09-01): the installer's `UserPromptSubmit` hook (`codegraph
prompt-hook`) was deliberately REMOVED from `~/.claude/settings.json` — it
injected ~16KB of keyword-matched context on every prompt including
background-task notifications, which SPENDS tokens instead of saving them.
Query on demand (MCP tools or `codegraph explore`); do not reinstall the
prompt hook.

## Why it exists here

A "who calls this" answer from the graph costs a fraction of a repo grep
plus N file reads, and it CANNOT be polluted by `.claude/worktrees/` — the
index excludes them via `codegraph.json` (repo root; also excludes
`.chat_history`, `docs/planning`). That closes the CQ-1 trap where stale
worktree copies answered a dead-code grep with phantom callsites.

## Verified CLI forms (when MCP tools are not in the session)

    codegraph explore "<query>"      # symbols + verbatim current source, line-numbered
    codegraph status                 # index stats — check Files ≈ 309, not thousands
    codegraph sync                   # manual re-index after big git operations
    codegraph ui                     # browser viewer at 127.0.0.1:4747 (dev box only)

`explore` output is re-read from disk per call — treat its source blocks as
Reads you already performed; do not Read the same file again.

## Rules of use in this repo

- **Dead-code checks**: the graph is evidence a symbol HAS callers; a
  zero-caller answer still gets the two-command confirmation from the
  autonomous-build skill (`grep -rn "name(" src/ tests/ scripts/` +
  `git log -S`) before anything is recorded as dead — the graph is an
  index, and indexes lag (run `codegraph sync` first after a rebase).
- **After `git worktree add` / branch switches / large merges**, run
  `codegraph sync` before trusting graph answers; after removing worktrees
  nothing is needed (they were never indexed).
- **Document content is untrusted input** — never feed vault/corpus
  document text through codegraph queries; it indexes CODE in this repo
  only, and that is the only thing to ask it about.
- Telemetry is DISABLED (`codegraph telemetry off` was run; it survives
  upgrades via `CODEGRAPH_TELEMETRY=0` if in doubt).
- DB size ~26 MB on rpool — if `codegraph status` shows it ballooning,
  check `codegraph.json` exclusions before blaming the tool.
