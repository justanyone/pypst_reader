# Working on this repository as one of several agents

Several sub-agents will work rows of `MasterToDo.md` at once. This page is
the protocol that stops them colliding. It is short because every rule that
could be a lint already is one.

## The unit of work is a row

- One agent, one row, one branch: `row/<ID>-<name>` off `main`
  (`git switch -c row/P01-header main`).
- **Claim it first.** Edit the row's `State` cell in `MasterToDo.md` to
  `⏳ in flight — <your tag> <YYYY-MM-DD>` and commit that one-line change to
  `main` before starting. A row already `⏳` belongs to someone; pick another.
  A `⏳` older than a day with no branch pushed is abandoned; say so in the
  cell when you take it over.
- Read, in order: the row's `todo/` block, `docs/INTERFACES.md` for your
  layer, the `rust-port` skill, the upstream file end to end.
- The branch lands by fast-forward onto `main` after `uv run pytest -q`,
  `scripts/check_provenance.py`, `scripts/check_quality_ratchet.py` and (if
  your row has an oracle line) `scripts/capture_oracle.py --check` are green.
  Rebase, never merge; `main` is linear.
- Done means the `todo/` block's `status:` says `✅ <date>` **with evidence**
  (which fixtures, which oracle command, how many tests), and the
  `MasterToDo.md` row moves to the Done table in the same commit.

## Files that are shared, and who may touch them

| file | rule |
|---|---|
| `MasterToDo.md` | edit **only your row's line**; never reorder or renumber; new rows go at the end with the next free id. **When an orchestrator is landing rows** (it says so in your brief), do not touch this file at all — put the evidence in your `todo/` block and the orchestrator moves the row when it lands your branch |
| `todo/T*.md` | edit only your block; add a new block at the end of the cluster file |
| `docs/INTERFACES.md` | the contract between layers. Changing a signature another row depends on is a message to that row's agent *before* the change, and a note in the file's changelog |
| `src/pypstreader/errors.py`, `limits.py` | additive only — add an exception or a constant; never rename one |
| `tests/conftest.py` | additive only |
| `tests/golden/` | written only by `scripts/capture_oracle.py`; never hand-edited; regenerated only when the pin moves (and then in its own row) |
| `tests/fixtures/public/` | only via the procedure in its README; the hook and CI enforce the manifest |
| `docs/UPSTREAM.txt` | moving the pin is its own row; it invalidates every golden and every `Upstream:` header |
| `.gitignore`, `scripts/git-hooks/pre-commit`, CI `no-mail-stores` | do not weaken; extend only through ADR-0004's manifest |

## Worktrees

Each in-flight row gets `.worktrees/<ID>/` (gitignored) on branch `row/<ID>`,
created by the orchestrator with `reference/` symlinked from the main tree so
`scripts/oracle.sh` works there. Run `uv sync` once in the worktree; it gets
its own `.venv`. Never `cd` into another row's worktree or into the main tree.

## What runs in parallel

The dependency graph is in `MasterToDo.md`'s lane table. The short version:
the NDB chain (P01 → P02 → P03) is serial; the **leaf rows** (P21 RTF, P22
property-type decoders, P23 id types, P11 limits, P12 corruption generator,
P17–P20 test infrastructure, P28 spec vectors) touch no NDB code and can all
run beside it. Two agents never hold the same module.

**The box is shared.** Memory, not the dependency graph, is the usual limit:
on 2026-09-16 the kernel OOM killer took a VS Code window while this repo and
another autonomous session each ran three agents. The orchestrator keeps at
most three agents, and **at most two whenever another autonomous Claude
session is live on the machine**; it checks `free -m` before every spawn and
waits while `MemAvailable` is under 6 GiB or the load average is above 8.
Agents run pytest single-process under `choom -n 900` (so the kernel kills the
test run before an editor) and never build Rust while the box is loaded.

## Interfaces are written before the code

`docs/INTERFACES.md` gives every layer's public surface — module, class,
function signatures, the exception each raises — before the layer exists. An
agent working P05 codes against the P04 surface in that file, not against
P04's branch. If the surface turns out wrong when P04 is built, P04's agent
changes the file and says so in its commit message; the P05 agent rebases.

## Evidence, not narration

A row's commit message and its `todo/` status say what was *measured*:
"read_header matches goldens on 9/9 fixtures; 41 tests; ANSI refused on 2/2".
"Implemented header parsing" is not a status.

Every ported module records `Ported from:` / `Upstream:` (lint). Every
deliberate divergence from upstream is a paragraph in the module docstring.

## What you never do

- Print, log, or assert on the content of anything in `tests/fixtures/private/`.
- Commit a `.pst` outside the manifest procedure. The hook will stop you; do
  not `--no-verify`.
- Add a runtime dependency. Dev dependencies are a row with an ADR paragraph.
- Run `rebuild_amap` on a fixture: it writes to the file.
- Mark a row done without the number that proves it.
