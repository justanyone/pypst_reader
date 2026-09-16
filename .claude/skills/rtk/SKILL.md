---
name: rtk
description: Use rtk (Rust Token Killer) to compress command output before it reaches context — grep/read/ls/git/pytest/psql proxies. Use whenever running shell commands whose output you will read, especially greps, file reads, git status/diff/log, and test lanes.
---

# rtk — token-compressed command output

`rtk` is a CLI proxy that filters/compresses command output 60–90% before it
enters model context. Nothing of rtk itself is committed to this repo: the
binary lives in `~/.local/bin`, and a full upstream checkout (docs, filter
examples, hook sources) sits at `.claude/skills/rtk/upstream/` — **gitignored**.

## How it is wired in this repo

- **`scripts/rtk-bootstrap.sh`** (committed, idempotent) — installs the binary
  if `rtk gain` does not work, clones/refreshes the upstream checkout, disables
  telemetry, trusts `.rtk/filters.toml`, runs `rtk verify`. Run it once per
  machine and after a pull that bumps the pinned version.
- **`.claude/settings.json`** (committed) — a `PreToolUse` Bash hook that
  rewrites common commands (`git status` → `rtk git status`) before they run.
  It is a no-op on a machine without rtk, and a no-op on a command that is
  already `rtk …`, so it coexists with a user-level `rtk init -g` hook.
- **`.rtk/filters.toml`** (committed) — project-local custom filters; empty
  template until a real noisy command earns one. Gated by `rtk trust`.
- **Upstream docs** (gitignored checkout): `README.md`, `INSTALL.md`,
  `docs/guide/getting-started/configuration.md` (config + filter fields,
  awareness levels), `docs/usage/FEATURES.md` (every built-in filter),
  `hooks/README.md` (hook contract). Read these before researching externally.

## When to reach for it explicitly

The built-in Read/Grep/Glob tools do not pass through the Bash hook. When a
sweep would dump large output into context, prefer a Bash call through rtk
over a raw dedicated-tool sweep — **but keep using dedicated tools for
precision work** (editing needs exact bytes; `rtk read` filters content and
is NOT safe as a pre-edit read).

## Verified command forms (this tree)

    rtk grep -r "pattern" src/ tests/         # grouped by file, stripped — same flags as grep
    rtk rg "pattern" src/                     # ripgrep proxy, same filter
    rtk read path/to/file.py                  # smart-filtered read — for ORIENTATION, not editing
    rtk ls src/skykeep/                       # compact listing
    rtk tree src/                             # compact tree
    rtk git status | diff | log -n 10         # compact git (hook usually does this for you)
    rtk pytest tests/gates -q                 # failures only (hook rewrites `pytest` on the ask path)
    rtk test -- <cmd>  /  rtk err -- <cmd>    # failures/errors only, any command
    rtk psql ...                              # strips table borders — good for vault counts
    rtk hook check "<cmd>"                    # dry-run: what would the hook rewrite this to?
    rtk gain                                  # measure what it saved this session
    rtk recall <id>                           # full unfiltered output of a failed run (id printed in the summary)

## Repo rules that still bind (rtk changes nothing)

- **Scope every grep**: `src/ tests/ scripts/ docs/` or
  `--exclude-dir=worktrees --exclude-dir=.git` — `.claude/worktrees/` holds
  stale `src/` copies and rtk inherits grep's blindness to that. The upstream
  checkout under `.claude/skills/rtk/upstream/` is another `src/` to exclude.
- **Lane counts come from pytest's own summary line.** rtk's test filter
  shows failures only; when a row needs the passed/failed/skipped counts,
  run the lane bare (`rtk run -- pytest …`) or read the lane log — never
  record a filtered view as evidence. Same rule as `| tail` in the
  autonomous-build skill: filtering at write time destroys evidence.
- **Mutation proofs, byte-identity asserts, and `git diff --cached` reads
  run UNFILTERED.** Any check whose point is "exactly what is there" must
  not pass through a compressor.
- `rtk run -- <cmd>` executes raw (no filtering) — the escape hatch when the
  hook rewrites something it shouldn't; permanent exclusions go in
  `[hooks] exclude_commands` in `~/.config/rtk/config.toml`.
- **The hook rewrites `cat`/`head` to `rtk read`.** Byte-identical on small
  files, filtered on large ones. For a pre-edit read that must be exact use
  `sed -n 'A,Bp' file` (not rewritten) or `rtk run -- cat file`.

## Housekeeping

- Telemetry is DISABLED (`rtk telemetry status` to confirm; bootstrap enforces it).
- `rtk verify` checks hook integrity if behavior looks wrong.
- Never pipe a command through rtk AND `tail`/`head` when the output is
  evidence for a MasterToDo row — one compressor already costs fidelity.
