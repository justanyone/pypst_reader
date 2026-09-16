# T05 — infrastructure and release

### P14-CI-ORACLE
status: 🔶 2026-09-15 — built and validated locally; CI-green awaits the first scheduled run. `.github/workflows/nightly-oracle.yml` (cron `17 3 * * *` + dispatch, one job, 45 min, concurrency-grouped, `contents: read`, no secrets, no push) installs uv + stable Rust, fetches upstream at the pin, restores a cache keyed on `hashFiles('docs/UPSTREAM.txt')` + OS, builds the oracle, then runs seven named steps, every one a call into `scripts/nightly_oracle_local.sh` (fetch, build, parity, goldens, dump-messages, fixture, tests) so the workflow and a laptop run cannot drift. **Measured locally** (no cargo run on this machine): `SKIP_RUST=1 scripts/nightly_oracle_local.sh` exits 0 — parity lint bites (15 upstream tests, 14 twinned, 1 pending), `make_fixture.py --check basics` regenerates 35,840 bytes byte-for-byte, Rust-free slow tests green; `bash -n` parses; unknown step exits 2. 7 tests in `tests/test_nightly_script.py` (6 unit, 1 slow self-run). **Unproven until the nightly first runs:** the cargo build on ubuntu-latest, the cache restore-after-clone ordering, `capture_oracle.py --check` on the runner, the drift-diff artifact path, and the wall-clock fit under 45 min. The `dump-messages` step is guarded on `oracle/Cargo.toml` and skips until P19 lands; P19 should add `oracle/target` to the cache path.
blocked on: nothing — the first scheduled run (or a `workflow_dispatch`) is the remaining evidence

Every-push CI already runs the differential tests, against the committed
goldens (ADR-0004 §5). What is left for a nightly job is the *re-derivation*:
build the Rust oracle, `scripts/capture_oracle.py --check`, and `-m oracle`.
not on every push: the cargo build is minutes and ~270 MB, and the unit suite is
the thing that must stay fast on every commit.

Cache `~/.cargo` and `reference/outlook-pst-rs/target` by the pin in
`docs/UPSTREAM.txt`, so a pin change invalidates the cache and nothing else does.

### P15-PERF
status: ✗ backlog — do not start before P10 works
blocked on: P10

Profile against a large store. The 140 MB and 179 MB stores stay **outside the
repository**; point the profile at an absolute path in `~/Downloads`.

Expected hot spots, in the order they will actually show up: BTree walking
(pure interpreter loop), property decoding (per-item), block reassembly
(memoryview slicing). The two encodings are already C-speed. Do not optimise
from this list — measure, then optimise what the profile says.

### P16-PUBLISH
status: ✅ 2026-09-16 — renamed, CLI landed, 0.1.0 built and verified from a
fresh venv; the wheels are on disk, unpublished (the upload is the user's,
with the user's token)

**Renamed, everywhere.** `git mv src/pypst src/pypstreader`, then every
reference: imports across `src/`, `tests/`, `scripts/`; `oracle/Cargo.toml`
and `Cargo.lock` (`pypst-oracle` → `pypstreader-oracle`; `cargo` was NOT
run); both `.github/workflows/*.yml`; all five `.claude/skills/*/SKILL.md`;
`CLAUDE.md`, `README.md`, `NOTICE`, `MasterToDo.md`, `todo/**`, and
`docs/**` including every `## pypst.<layer>` heading in INTERFACES.md and
ADR-0003's sibling `pypst_reader_nu` → `pypstreader_nu`. `pyproject.toml`:
`name = "pypstreader"`, `version = "0.1.0"`, new description, MIT by file,
`Development Status :: 3 - Alpha` + OS-Independent + Topic :: Communications
:: Email + Typing :: Typed (with a `py.typed` marker added), Homepage /
Repository / Issues, `[project.scripts]`, and an EXPLICIT
`[tool.hatch.build.targets.sdist] include` — without it `uv build` hangs
walking the 1.2 GB `reference/` symlink, because a git WORKTREE's `.git` is
a file and hatchling infers no VCS from it.

**Two renames reach shipped bytes**, done now so 0.1.0 is consistent from
the first release: `X-Pypst-*` → `X-Pypstreader-*` (Synthesized, Body,
Attachment-Skipped) and the synthetic Message-ID domain `pypst.invalid` →
`pypstreader.invalid`. **One literal was deliberately left alone**:
`make_fixture.py`'s `"pypst synthetic fixture: {name}"` seed is hashed into
`synth-basics.pst`'s record key and into every golden captured over it —
renaming it broke `make_fixture.py --check` and
`test_store_props_show_the_recipe`, which is exactly what those tests are
for. Comment added at the seed. Ruff's import sorter had to re-wrap eight
import blocks that the longer name pushed past the line length.

**The command** — `src/pypstreader/pypstreader.py`, `Ported from: not a
port`. `pypstreader IN.pst` → `./IN.mbox`, every folder in walk order, each
record stamped `X-Pypstreader-Folder: <display path>`; `-o/--output`,
`--per-folder` (via `export_mbox`, one `<nid>.mbox` + a merged
`folders.txt`), `--format {mbox,eml}` (via `export_folder`), `--folder PATH`
(subtree, repeatable), `--list`, `--strict`, `--max-depth` /
`--max-attachment-bytes` / `--max-embedded-depth` → `Limits`, `--codepage`,
`-q`/`-v`, `--version`. Exit 0 / 1 (PstError or OSError, one line, no
traceback) / 2 (usage); `main` catches `SystemExit` too, so in-process
callers get a status. `mbox._record` became public as
`mbox.mbox_record(message, *, limits, headers)` so the folder header has one
assembler rather than two.

**The alias** — `alias/pstreader/`: `uv_build` backend, `pypstreader==0.1.0`
pinned exactly, `src/pstreader/__init__.py` re-exporting the package (`open`
is the *same object*), console script `pstreader`, its own README and a copy
of the LICENSE. `scripts/check_quality_ratchet.py` now lints `alias` too.

**Tests** — `tests/test_cli.py`, 73 cases: the default mbox over every
Unicode store with the record count equal to T11's `OPENABLE` (tika 4,
pstsdk-test_unicode 2, synth-basics 1, Empty 0 and an empty file), the
summary cross-checked against `--list`, `--per-folder` + `folders.txt`,
`--format eml`, `--folder` single and repeated and unknown, `--list`,
skip-and-count vs `--strict` on `javalibpst-dist-list` (exit 1) and
`synth-basics`, every limit flag including the exit-2 cases, `--codepage`,
`-q`/`-v`, both ANSI stores → exit 1 naming `pypstreader_nu`, missing file /
directory / empty file → exit 1, unknown option / no arguments → exit 2,
`--version` = 0.1.0 through `-m` AND through the installed console script,
and the version pinned in all three places. Corruption: 494 mutations of
`pstd-inline-cid` and every 8th of `tika-variousBodyTypes` through `main()`
in-process (all of tika under `slow`) — 0 or 1, never a traceback.
`tests/corruption_harness.py` gained a `cli.main` entry point and
`tests/contract.py` adapters for `cli.main` and `mbox.mbox_record`, so the
standing sweeps cover them. `docs/TEST-PLAN.md` § T12 and
`docs/INTERFACES.md` § `pypstreader.pypstreader` record the contract.

**Evidence.** `uv run pytest -q -m "not slow"`: **2673 passed, 14 skipped,
23 deselected, 7 xfailed**. All four lints exit 0 (provenance 28 modules,
ratchet tier 1 clean / tier 2 0, parity 14 twinned + 1 P27-NU, ruff clean
over `src tests scripts alias`). `uv build` and `uv build alias/pstreader`;
`uvx twine check` PASSED on all four artefacts. From a fresh
`uv venv` + `uv pip install --no-index --find-links dist pypstreader`:
`pypstreader --version` → `pypstreader 0.1.0`, `--list` on
`tika-variousBodyTypes.pst` printed the seven folders, the default export
wrote an mbox that `mailbox.mbox` reads as **4** records. From a second
fresh venv, `pstreader` pulled `pypstreader==0.1.0` with it,
`pstreader.__version__` → `0.1.0` and `pstreader --version` → `pypstreader
0.1.0` (the command announces the real package's name on purpose).

**Not done, deliberately.** Nothing was uploaded and `~/.pypirc` was never
read — the coordinator publishes `dist/pypstreader-0.1.0{-py3-none-any.whl,
.tar.gz}` and `alias/pstreader/dist/pstreader-0.1.0{-py3-none-any.whl,
.tar.gz}` with the user's token. The slow lane was NOT run: loadavg was 8.04
with a local `llama-server` holding cores, which is the stated skip
condition. `cargo` was never run, so `oracle/Cargo.lock` carries the renamed
crate without a rebuild behind it; the nightly oracle job is what will
rebuild it.

### P27-NU
status: ✗ backlog — not before P10 works here
upstream: the ANSI arms of every `ndb/` and `ltp/` module (~480 sites)
oracle:   `pstsdk-test_ansi.pst`, `pstsdk-sample2.pst`; upstream's `read_header`/`read_store_props`/`read_named_props`/`read_root_folder`/`read_ipm_subtree` all read ANSI (`read_btrees` does not — it panics, exit 101 in the goldens)
blocked on: P10

`pypstreader_nu` — a **separate package** for ANSI (Outlook 97–2002, `wVer`
14/15) stores, per ADR-0003. Same method, same skills, same corpus policy;
copy this repository's scaffold, swap the struct-format table to 32-bit
indices, and port against the two ANSI fixtures. It gets its own repository
so that neither package carries the other's variant axis. Until it exists,
`pypstreader` names it in the `PstUnsupportedError` message so a user with an old
store knows where to look.
