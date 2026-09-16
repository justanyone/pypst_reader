# T00 — foundation: the value types under every layer

Upstream keeps its packed identifiers in five small files (`ndb/node_id.rs`,
`ndb/block_id.rs`, `ndb/byte_index.rs`, `ndb/block_ref.rs`, `block_sig.rs`;
~1,000 lines, half of it the ANSI arms we are not porting — ADR-0003). They
are the first thing to port because every struct above them holds one, and
because four of upstream's fifteen tests live here.

### P23-IDS
status: ✅ 2026-09-15 — `src/pypstreader/ndb/ids.py` + `src/pypstreader/block_sig.py`. 103 tests in
        tests/test_ids.py, tests/test_block_sig.py, tests/parity/test_ids_parity.py
        (99 pass, 4 skip = the 2 ANSI stores × 2 differentials). Header ids unpacked
        from the fixtures' own bytes at the [MS-PST] 2.2.2.6/2.2.2.7 offsets reproduce
        the read_header golden text on 7/7 Unicode stores; every NodeId and BlockRef
        in the read_btrees goldens rebuilt from parts and printed back on 7/7 stores
        the oracle accepted (18 of 20 node types plus the `invalid` form seen); the
        4/4 upstream tests twinned and tagged. 19 deliberate breaks of the source:
        18 went red, 1 was an equivalent mutant (compute_sig's u32 input mask cannot
        change the result; documented in the module). Full suite 140 passed / 4
        skipped; check_provenance, check_quality_ratchet and ruff green.
upstream: `crates/pst/src/ndb/node_id.rs` (239), `ndb/block_id.rs` (304), `ndb/byte_index.rs` (115), `ndb/block_ref.rs` (135), `block_sig.rs` (32)
oracle:   none directly — but `read_header` and `read_btrees` goldens print every one of these types in Debug form, and P01/P02 diff against them
blocked on: none — **start here**

Port the Unicode arms only (ADR-0003):

- `NodeId` — a `u32`: low 5 bits `NodeIdType` (an enum of the [MS-PST]
  §2.2.2.1 values; unknown → `PstFormatError`), high 27 bits index. Upstream
  test: index overflow raises.
- `BlockId` — a `u64`: bit 1 "internal" (an XBLOCK/XXBLOCK/subnode block, not
  data), bit 0 reserved, remaining bits index. Upstream test: index overflow.
- `ByteIndex` — a `u64` file offset. Trivial, but typed: an offset is not a
  size and the code should not let you add one to the other silently.
- `PageId` — a `u64`-shaped block id used for page refs; upstream reuses
  `BlockId`'s layout.
- `BlockRef` / `PageRef` — `(BlockId, ByteIndex)` pairs, `struct` format `<QQ`.
- `compute_sig(index, block_id) -> u16` — [MS-PST] §5.5, `(ix ^ bid)` folded
  to 16 bits. Two upstream tests, including the overflow case; masks matter.

Frozen dataclasses with `slots=True`. Each has `from_bytes`/`unpack_from` and
a `__str__` that a golden parser can round-trip — pick the format now and
write it in `docs/INTERFACES.md`.

**Done means:** the 4 upstream tests ported under `tests/parity/` (tagged for
P18's lint), a denial test per type for the out-of-range and unknown-type
cases, a property test that pack/unpack round-trips (stdlib `random` if P25
has not landed), and `docs/INTERFACES.md` § NDB updated with the exact
signatures you built.

### P30-INTERFACES
status: ✅ 2026-09-15 — drafted from upstream's public surface; every row that builds a layer corrects its section
upstream: the `pub` items of every module, enumerated on 2026-09-15
oracle:   none
blocked on: none

`docs/INTERFACES.md` is a contract, not documentation of what exists. It lets
lane B and lane C rows code against a layer that lane A has not built yet.
Rows that build a layer own that section and must update it in the same
commit as the code.
