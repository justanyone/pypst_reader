# T01 — the NDB layer (node database)

The bottom of the file format: the header, the two B-trees, and the blocks
they point at. Roughly 6,600 lines of upstream Rust, of which the read path is
maybe two thirds. This is the largest cluster and the most mechanical.

Read `.claude/skills/rust-port/SKILL.md` before starting any block here.

### P01-HEADER
status: ✅ 2026-09-15 — `python -m pypst.debug header` parsed by `parse_read_header` equals the golden on 7/7 Unicode stores (Empty + 6 corpus), twice: dumper text and `Header` attributes compared as values; ANSI refused 2/2 (`pstsdk-test_ansi`, `pstsdk-sample2`, real bytes, `PstUnsupportedError` naming pypst_reader_nu, `debug header` exit 1); private stores matched the live oracle 2/2 (`scripts/oracle.sh read_header`, structure only); corruption: 110 denial cases in `tests/test_header.py` (72 truncations = every 8-byte boundary + one byte short, CRC flips in the partial and the full-only region, bad magic, bad wMagicClient, 6 unknown wVer, 2 ANSI wVer, 2 4K wVer, crypt 0x10 / 3 unknown, 8 fixed-field checks, 3 unknown fAMapValid, zero-length file); 142 tests in test_header.py + 1 parity twin (`test_magic_values`); 30/30 deliberate mutations went red (`__pycache__` cleared each time); `tests/corrupt.py` seeded for P12
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
status: ✅ 2026-09-15 — `src/pypst/ndb/page.py` (PageType, PageTrailer, the three entry records, BTreePage, DensityListPage — DL ported; AMap/PMap/FMap/FPMap contents deliberately not) and `src/pypst/ndb/btree.py` (NodeBTree, BlockBTree, read_page, read_density_list) landed; `debug btrees` and `debug density_list` registered; `parse_read_btrees`/`parse_read_density_list` complete. Oracle: `read_btrees` block-B-tree section byte-identical on 7/7 Unicode corpus stores (Empty, javalibpst-dist-list, pstd-inline-cid, pstsdk-sample1, pstsdk-submessage, pstsdk-test_unicode, tika-variousBodyTypes) and parsed-equal on every page-level fact of the node B-tree (node, data block, `Size:` from the BBT entry, sub-node block, parent, every intermediate key, page skeleton) — the data-tree/sub-node-tree lines under those are blocks, P03; `read_density_list` identical on 5/5 stores that have the page, the 2 without it refused where upstream reports `InvalidPageType(0)`; the 2 ANSI stores refused at the header (`PstUnsupportedError`). Private: 2/2 stores match the live oracle on both examples (structure only, counts in the assertion). Tests: 65 in tests/test_page.py, 57 in tests/test_btree.py, 165 in tests/test_golden_parsers.py (933 suite-wide, 4 skipped, 1 xfailed). Denial (all `PstFormatError`): ptype≠ptypeRepeat, unknown ptype, map/DL ptype in a B-tree, bad page CRC, cEnt>cEntMax, cbEnt below the entry size for the level, cEntMax over what fits, cLevel 9/0x80/0xFF, dwPadding≠0, a leaf of the other tree, nid wider than 32 bits, an NBT intermediate key wider than 32 bits, a page ref past EOF / at 2**63 / at 2**64-1, a file truncated inside a page, an absent or broken DL page, DL count>119/padding/tail; (all `PstLimitError`, shown distinct from `PstFormatError`): root→root cycle (mutated Empty.pst), two-page cycle, a shared page (DAG), a chain of 10 pages (depth 9 > 8; 9 pages pass — inclusive ceiling), `Limits(max_btree_depth=3)`, `Limits(max_items=…)` on entries and on pages. Pinned as accepted, as upstream: a wrong wSig, a wrong trailer bid, an intermediate page of the other tree's ptype, cbEnt larger than the structure (the stride). 31 mutants with `PYTHONDONTWRITEBYTECODE=1` and `__pycache__` cleared: 29 red, 2 equivalent (the nid-width check is duplicated by `NodeId`'s constructor; the short-read check by `parse`'s length check). ruff, provenance, quality ratchet (0/0), parity green. Divergences (all in the module docstrings): the bounded walk (limits), refusing an over-wide NBT intermediate key where the upstream example skips the subtree, refusing a page ref beyond `max_file_size` before the read.
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
status: ✅ 2026-09-16 — `src/pypst/ndb/block.py` (block_size, BlockTrailer, DataBlock, XBlock, SubNodeLeafEntry/SubNodeIntermediateEntry, SubNodeLeafBlock/SubNodeIntermediateBlock, BlockReader with read_block / read_data_tree / read_subnode_block / read_data / read_subnode_tree / node_data / find) landed; `debug btrees` extended to the full `read_btrees` output and `debug node <file> <nid-hex>` registered (length, zlib CRC32, sub-node count — never the bytes). Oracle: `read_btrees` **byte-identical** (modulo the `Unicode` prefix) on 8/8 Unicode corpus stores (Empty, javalibpst-dist-list, pstd-inline-cid, pstsdk-sample1, pstsdk-submessage, pstsdk-test_unicode, synth-basics, tika-variousBodyTypes), data-tree and sub-node sections included, and parsed-equal; every node's `read_data` length, XBLOCK level/lcbTotal/entries and every sub-node entry (keys, data id, block ref, nested tree presence) equal to the parsed golden on 8/8; the 2 ANSI stores refused at the header. Private: 2/2 Unicode private stores match the live oracle per node (data length, XBLOCK header, sub-node entries) and `debug node` agrees with the walk on every node (counts only; a third private file is ANSI and skipped). Tests: 100 in tests/test_block.py (1219 suite-wide, 14 skipped, 2 xfailed). Denial (all `PstFormatError`): BBT cb 0 / 8177 / 0xFFFF refused before any read, trailer cb outside 1..=8176, trailer cb ≠ BBT cb, a flipped data byte (CRC), a data block with an internal trailer bid, a tree block with a leaf trailer bid, unknown btype 0x00/0x03/0xFF, an SLBLOCK where a data tree is expected and vice versa, subnode dwPadding ≠ 0, cEnt that does not fit cb (incl. u16 overflow values), tree cb below its header, slack in a tree block's cb (refused where upstream misreads the trailer — CRC sealed so only the location can refuse), a block ref past EOF, a ref beyond max_file_size before the seek, a file truncated inside the last block (5 cuts), Empty.pst with a flipped data byte / a changed trailer cb / a truncation; (`PstNotFoundError`) an XBLOCK entry, a zero bidData, an absent subnode root; (all `PstLimitError`, shown distinct from `PstFormatError`): XX→XX→X→data (3 internal, > 2) and 4 deep — both read under a raised `Limits`, an XBLOCK that lists itself, two XBLOCKs listing each other, lcbTotal 0xFFFFFFFF refused before any child read (read count proven), assembled length over `Limits(max_allocation)` even when lcbTotal lies (at the ceiling passes), SI→SI→SL (depth 3) and 4, an SIBLOCK naming itself, subnode entries over `Limits(max_items)` (at the ceiling passes). Pinned as accepted, as upstream: a wrong wSig (zero, as EMLtoPST writes), a trailer bid whose index differs from the B-tree's, lcbTotal ≠ assembled length, an SLENTRY nid truncated to 32 bits, a duplicate subnode NID (first wins), a flipped padding byte (outside the CRC). Decoding: NONE/PERMUTE/CYCLIC each round-trip through `read_block` and `read_data` (cyclic key from a 64-bit bid's low half), an unencoded block under PERMUTE/CYCLIC does NOT read as plaintext, internal blocks (XBLOCK, SLBLOCK) are never decoded. The size-boundary trap: cb 48 / 8112 (allocation exact) and 49 / 8113 (one over) plus 8176, with the store ending at the block and zero padding, so a wrong allocation reads short and a wrong trailer offset finds cb 0. Every-byte flip of a synthetic XBLOCK store: nothing but `PstError` escapes. 35 mutants with `PYTHONDONTWRITEBYTECODE=1` and `__pycache__` cleared: 33 red, 2 equivalent on the corpus (the dumper printing the entry bid instead of the trailer bid — no corpus store has them differ; the SIBLOCK indent quirk — no corpus store has an SIBLOCK or XXBLOCK, so those dumper branches are covered only by the reader's unit tests). ruff, provenance, quality ratchet (0/0), parity green. Divergences (all in the module docstring): the bounded iterative walks (limits, VisitedSet), refusing a block ref beyond `max_file_size` before the read, `read_subnode_tree` as a dict rather than upstream's partition descent. Not added, as upstream lacks them: wSig, trailer bid index, XBLOCK cLevel, lcbTotal vs assembled length.
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
