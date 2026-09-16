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
status: ✗ backlog
blocked on: P10

PyPI: name availability, classifiers, `uv build`, and a README whose status
section states exactly what is implemented. The failure mode to avoid is a
package that reads as "a PST reader" when it reads headers and folders only.

### P27-NU
status: ✗ backlog — not before P10 works here
upstream: the ANSI arms of every `ndb/` and `ltp/` module (~480 sites)
oracle:   `pstsdk-test_ansi.pst`, `pstsdk-sample2.pst`; upstream's `read_header`/`read_store_props`/`read_named_props`/`read_root_folder`/`read_ipm_subtree` all read ANSI (`read_btrees` does not — it panics, exit 101 in the goldens)
blocked on: P10

`pypst_reader_nu` — a **separate package** for ANSI (Outlook 97–2002, `wVer`
14/15) stores, per ADR-0003. Same method, same skills, same corpus policy;
copy this repository's scaffold, swap the struct-format table to 32-bit
indices, and port against the two ANSI fixtures. It gets its own repository
so that neither package carries the other's variant axis. Until it exists,
`pypst` names it in the `PstUnsupportedError` message so a user with an old
store knows where to look.
