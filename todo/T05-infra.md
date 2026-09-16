# T05 — infrastructure and release

### P14-CI-ORACLE
status: ✗ not started
blocked on: P02 (nothing to differ against before then)

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
