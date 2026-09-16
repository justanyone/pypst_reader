# T01 — the NDB layer (node database)

The bottom of the file format: the header, the two B-trees, and the blocks
they point at. Roughly 6,600 lines of upstream Rust, of which the read path is
maybe two thirds. This is the largest cluster and the most mechanical.

Read `.claude/skills/rust-port/SKILL.md` before starting any block here.

### P01-HEADER
status: ✗ not started
upstream: `crates/pst/src/ndb/header.rs` (640 lines), `ndb/root.rs` (292)
oracle:   `scripts/oracle.sh read_header tests/fixtures/Empty.pst`
blocked on: none — **this is the first row**

Parse the PST header: `!BDN` magic, CRCs (partial and full — `crc.py` is
already ported and tested), `wVer`, `bCryptMethod`, the root structure with its
`BREF`s to the node and block B-tree roots, and the AMap validity flag.

**Done means:** every field your parser produces matches `read_header`'s output
for `Empty.pst` AND for at least one private store, and a corrupted copy of
each (flip a byte in the CRC-covered region) is *refused* with `PstFormatError`
rather than parsed.

**The decision this row forces — do not defer it.** Upstream splits ANSI and
Unicode with a `PstFile` trait and two impls; ~480 references across the crate
turn on it. Python has no reason to copy that shape. Decide here between:

- **Unicode only** (recommended default): every store Outlook has written since
  2003. Drop the axis entirely, raise `PstUnsupportedError` on `wVer` 14/15.
- **Both**, via a per-variant struct-format table (`"<I"` vs `"<Q"` for byte
  indices) consulted by one parser, not two parsers.

Whichever you pick, record it as an ADR before writing the second module —
retrofitting the axis later means touching every file in `ndb/` and `ltp/`.

### P02-BTREE
status: ✗ not started
upstream: `crates/pst/src/ndb/page.rs` (2,381 lines — the biggest file in the crate)
oracle:   `scripts/oracle.sh read_btrees tests/fixtures/Empty.pst`
blocked on: P01

The node BTree (NBT) and block BTree (BBT): page headers, page trailers with
their CRCs, intermediate vs leaf pages, and the entry types each holds.

`page.rs` is large because it is generic over page kind and file variant. Once
the ANSI/Unicode decision from P01 is applied, the Python is far smaller — but
**split this row if it overruns a session**: pages/trailers first, then the two
BTree walks.

**Done means:** your NBT and BBT walks enumerate exactly the same entries, in
the same order, as `read_btrees` on every available fixture — and a store whose
BTree points at itself terminates with `PstLimitError` instead of hanging. That
second half is P11 work; land the guard with the walk, not after it.

### P03-BLOCK
status: ✗ not started
upstream: `crates/pst/src/ndb/block.rs` (1,501), `ndb/read_write.rs` (851, read half only)
oracle:   `scripts/oracle.sh read_density_list tests/fixtures/Empty.pst`, and P02's walk
blocked on: P02

Data blocks and their trailers; XBLOCK and XXBLOCK trees for data too large for
one block; subnode BTrees. This is where `encode.py` finally gets called in
anger: a block's bytes are decoded by the method the header declared.

**Done means:** you can pull the raw bytes of an arbitrary node out of a real
store and they are byte-identical to what the oracle produces. This is the
first row whose success feels like reading a PST.

**The trap:** block size accounting. The trailer is *inside* the 64-byte-aligned
allocation, the declared `cb` excludes it, and getting this wrong yields data
that decodes to plausible-looking garbage rather than an error. Test with a
block that is exactly at a size boundary.

### P13-ANSI
status: ✗ deferred — decided at P01, implemented here if the answer is "both"
upstream: the ANSI arms of every `ndb/` and `ltp/` module
oracle:   an ANSI store, which we do not currently have
blocked on: P01's decision, and on acquiring an ANSI fixture

Only start this if P01 chose "both" and an ANSI store actually exists to test
against. An untested ANSI path is worse than an honest `PstUnsupportedError`.
