# T01 — the NDB layer (node database)

The bottom of the file format: the header, the two B-trees, and the blocks
they point at. Roughly 6,600 lines of upstream Rust, of which the read path is
maybe two thirds. This is the largest cluster and the most mechanical.

Read `.claude/skills/rust-port/SKILL.md` before starting any block here.

### P01-HEADER
status: ✗ not started
upstream: `crates/pst/src/ndb/header.rs` (640 lines, Unicode arms only), `ndb/root.rs` (292)
oracle:   `tests/golden/*/read_header.txt` (captured), or live: `scripts/oracle.sh read_header tests/fixtures/public/pstsdk-test_unicode.pst`
blocked on: P23 (the `BlockRef`/`ByteIndex`/`BlockId` types it returns)

Parse the PST header: `!BDN` magic, CRCs (partial and full — `crc.py` is
already ported and tested), `wVer`, `bCryptMethod`, the root structure with its
`BREF`s to the node and block B-tree roots, and the AMap validity flag.

**The decision is made — ADR-0003: Unicode only.** `wVer` 14/15 raises
`PstUnsupportedError` naming the version and `pypst_reader_nu`; 23/36/37 are
parsed; anything else is `PstFormatError`. One struct format per structure,
no variant axis, no `PstFile` trait.

**Done means:**
- `python -m pypst.debug header <f>` parsed by P29's `parse_read_header`
  equals the golden's parsed values on **7/7 Unicode fixtures** (Empty and
  the six Unicode corpus stores), and on every private store present.
- `pstsdk-test_ansi.pst` and `pstsdk-sample2.pst` raise `PstUnsupportedError`
  — tested on the real bytes, not a synthetic header.
- A copy of each Unicode fixture with one byte flipped inside the CRC-covered
  region raises `PstFormatError`; a copy truncated at every 8-byte boundary
  of the header raises `PstFormatError` (this seeds P12's generator).
- The `test_magic_values` upstream test has its parity twin.
- `docs/INTERFACES.md` § header matches what you built.

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
status: ✅ 2026-09-15 decided — Unicode only (ADR-0003); ANSI support is the sibling package, row P27-NU in `T05-infra.md`
upstream: the ANSI arms of every `ndb/` and `ltp/` module — not ported here
oracle:   `pstsdk-test_ansi.pst`, `pstsdk-sample2.pst` (in the corpus for the refusal test and for P27)
blocked on: —

Closed. The two ANSI fixtures test that this package refuses cleanly; that is
the whole of the ANSI work here.
