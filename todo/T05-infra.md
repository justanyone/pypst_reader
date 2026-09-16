# T05 — infrastructure and release

### P14-CI-ORACLE
status: ✗ not started
blocked on: P02 (nothing to differ against before then)

Teach CI to build the Rust oracle and run `-m oracle` on a schedule (nightly),
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
