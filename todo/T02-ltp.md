# T02 — the LTP layer (lists, tables, properties)

The middle of the format: structures built *on top of* nodes that turn bytes
into MAPI properties. ~3,700 upstream lines. Less mechanical than NDB and more
fiddly; this is where a port most often produces something that runs and is
subtly wrong.

### P04-HEAP
status: ✅ 2026-09-16 — `src/pypstreader/ltp/heap.py` (HeapId, HeapNodeId, HeapNodeType,
HeapNodeHeader, HeapPageMap, HeapNode) and `src/pypstreader/ltp/tree.py`
(HeapTreeHeader, HeapTree); `BlockReader.read_data_blocks`/`node_data_blocks`
added (additive; `read_data` is their join); `debug heap` / `debug bth`.
Evidence — differential (indirect, through the committed goldens; no Rust
built): on 8/8 Unicode stores the store PC (NID 0x21), root-folder PC (0x122),
IPM-subtree PC and name-to-id map (0x61) open with `bClientSig` 0xBC and the
root/IPM hierarchy tables with 0x7C; the store PC's BTH has exactly the
records `read_store_props` prints — 7/7 stores with a property list (13, 16,
12, 11, 11, 8, 12 records; pstd-inline-cid's example exits 1 before the list,
its PC opens and `Display Name` decodes) — key for key, type for type, and
every heap-borne Unicode/String8/Binary/Integer64 value resolved by
`get_hnid` decodes (P22) to the golden's, inline Integer32/Boolean equal;
the root and IPM hierarchy tables' row-index BTHs hold exactly the goldens'
`Row:` ids (7/7 stores) and every `Record: Heap(HeapId(…))` in
`read_root_folder`/`read_ipm_subtree` resolves through `get` to the printed
value; NID 0x61's entry stream (property 0x0003, in a sub-node on 6 stores
→ the `get_hnid` sub-node arm) has 8 × the golden's `Named Property ID`
count on 8/8. Private (marker `private`+`oracle`, live oracle, structure
only): 2/2 Unicode private stores — 17/17 store-PC ids and printed types in
order, root hierarchy row ids equal; found that a zero HNID prints as
`Type: Null` (recorded in INTERFACES for P05). Denial: 260 tests in
tests/test_heap.py + tests/test_tree.py (denial first: bSig, bClientSig,
ibHnpm past the block, cAlloc over/under, rgibAlloc decreasing / one byte
past the block, cFree mismatch, HID type bits, null HID, index > cAlloc,
freed item, block index past the last, HNBITMAPHDR cadence at 8/136/264,
max_heap_items; BTH bType, cbKey, cbEnt, levels > limit, root type bits,
ragged leaf and index pages — the upstream `while let Ok` bug, refused —
index record naming an absent page, self-cycle, mutual cycle, a leaf reached
twice, max_items; every-byte flip and truncation leak nothing but PstError).
P12's two P04 stubs are live; `corrupt.py` gained the heap/BTH builders and
the `heap_lies` family (22 resealed lies over a real store's PC, pinned for
both bases), and the harness walks the store PC on every mutation (sweep
clean). Mutants (PYTHONDONTWRITEBYTECODE=1, __pycache__ cleared): 27, 26 red
at first pass; the survivor (an rgibAlloc offset exactly one byte past the
block) got its boundary test and is now red. Divergences (docstrings): an
offset past the block and a zero-length (freed) item refused where upstream
slices/returns empty; a page not a whole number of records is
PstFormatError; levels/cycles/counts bounded by `limits`. Not enforced, as
upstream: `ibHnpm` alignment (pstd-inline-cid has 121 and reads).
upstream: `crates/pst/src/ltp/heap.rs` (667), `ltp/tree.rs` (374)
oracle:   goldens `read_store_props` / `read_root_folder` / `read_ipm_subtree` / `read_named_props` (indirect — see status)
blocked on: P03

Heap-on-Node (HN): the heap header, page maps, allocation table, and the
fill-level map. Then BTree-on-Heap (BTH), which the property and table contexts
are both built on.

**Done means:** you can resolve an arbitrary HID to its bytes, and walk a BTH
producing the same key/value pairs as the oracle, on a real store.

**The trap:** HID vs HNID. They share a wire format and mean different things
(a heap item vs a subnode). Conflating them yields reads from the wrong place
that still return *some* bytes. Name the two types distinctly in Python even
though upstream can lean on its type system to keep them apart.

### P05-PC
status: ✅ 2026-09-16 — `src/pypstreader/ltp/prop_context.py` landed (`PropertyRecord`, `PropertyContext`, `from_node`); `tests/test_prop_context.py` 116 tests + 1 skip, 1811 suite-wide, all green. **Differential:** `python -m pypstreader.debug pc <store> 21` reproduces `read_store_props`'s property lines BYTE FOR BYTE on 7/7 Unicode corpus stores with a complete golden (Empty 26 lines, javalibpst-dist-list 32, pstsdk-sample1 24, pstsdk-submessage 22, pstsdk-test_unicode 22, synth-basics 16, tika-variousBodyTypes 24); the same goldens re-checked as DATA through `parse_read_store_props` — every property id, `Type:` variant and decoded value, 8–16 properties per store. pstd-inline-cid is the 8th: its golden is 2 lines and exit 1 (the ORACLE fails, before printing any property — no Deleted Items entry id), and the PC is only shown to open (12 properties). The name-to-id map's PC (NID 0x61) is checked value for value against `read_named_props` on 8/8 stores — the entry, GUID and string streams decoded from the PC and the named properties rebuilt from them equal the oracle's list exactly (Empty 35, pstsdk-sample1 172, pstsdk-submessage 172, pstsdk-test_unicode 164, javalibpst-dist-list 363, tika-variousBodyTypes 56, synth-basics 1, pstd-inline-cid 1 — 964 named properties in all); that path exercises the sub-node arm of `get_hnid` on the stores that keep a stream in a sub-node. The store, name-to-id-map, root-folder and IPM-subtree PCs all open with signature 0xBC and decode every value on 8/8 stores. **Private stores, STRUCTURE ONLY:** both open, property ids and `Type:` names match the live oracle in order (no value asserted, none printed); a survey of all 98 PCs across every node and sub-node of both found types 0x0003/0x000B/0x001F/0x0040/0x0048/0x0102/0x1102 and no non-`PstError` escape. **MV_GUID settled as far as evidence goes:** no private store and no corpus store carries a 0x1048 property, so upstream's count-prefixed reading and P22's pin stand; the survey is now a standing test that turns red on the first store that has one. **P22's other open item closed:** `ObjectRef.node` is a `NodeId`. **Denial:** 8 non-PC client signatures, 7 bad BTH width pairs, 7 unknown `wPropType`s, a repeated prop id, a count over `max_property_count`, a truncated record, an HNID past `cAlloc`, an HNID to a freed item, an HNID to an absent sub-node (`PstNotFoundError`), type bits on each of the 7 heap-only types, an MV count of 2^32-1 and a tight `max_mv_items` (both `PstLimitError`), an odd-length Unicode value, 3 non-boolean booleans; plus the new `pc_lies` mutation family (14 lies on Empty, 13 on pstd-inline-cid — the latter's store PC has no boolean) run through the corruption harness's new `pc.store_pc` entry point, every one drawing the pinned `PstError` subclass. **26 deliberate mutations, 24 confirmed red**; the 2 survivors are equivalent on the corpus and named in the commit message (little-endian truncation == masking; `dump_pc`'s code page, which no corpus or private store's store PC can distinguish — the constant itself is pinned). No upstream `#[test]` in `prop_context.rs`, so `check_upstream_parity.py` stays at 0 missing. Golden parsers completed for `read_store_props`, `read_named_props`, `read_root_folder`, `read_ipm_subtree` (+ `parse_value`, `parse_record`), 261 tests in `tests/test_golden_parsers.py`; a duplicate `_Cursor` class in the handover left `parse_read_btrees` broken and was renamed.
upstream: `crates/pst/src/ltp/prop_context.rs` (1,193), `ltp/prop_type.rs` (134)
oracle:   `scripts/oracle.sh read_store_props tests/fixtures/Empty.pst`
blocked on: P04, P22

Property contexts, over the P22 decoders (which are pure functions and land first):
PT_LONG, PT_BOOLEAN, PT_UNICODE, PT_STRING8 (which needs a codepage —
upstream's examples pull in `codepage-strings`; Python's `codecs` covers it),
PT_BINARY, PT_SYSTIME (a Windows FILETIME → `datetime`, UTC, and beware the
1601 epoch), PT_GUID, and the multi-valued PT_MV_* forms.

**Done means:** `read_store_props` output matches property for property,
including types you did not expect to see. Unknown property types must raise
`PstUnsupportedError` naming the type — never silently return raw bytes.

**Two things P22 left for this row.** (1) `ObjectRef.node` is a raw `int`
because P23's `NodeId` had not landed when P22 was built — wrap it (one-line
annotation change in `prop_type.py` plus the tests). (2) **MV_GUID:** upstream
reads a u32 count then GUIDs; [MS-PST] 2.3.3.4.1 names PtypGuid as a
fixed-size (packed, no count) example, and pstsdk packs. P22 followed upstream
and pinned it (`test_mv_guid_follows_upstream_count_prefix`). No corpus store
carries an MV_GUID property. If a private store does, settle it there and
record the answer in the module docstring; if not, leave upstream's reading
and the pin.

**Size note:** the type decoders are P22 and land before this row starts; if
the contexts alone overrun a session, split the PT_MV_* wiring off.

### P06-TC
status: ✅ 2026-09-16 — `src/pypstreader/ltp/table_context.py` landed
(`existence_bitmap_size`, `check_existence_bitmap`, `ColumnDescriptor`,
`TableContextInfo`, `CellKind`/`CellRecord`, `TableRow`, `TableContext`,
`from_node`); `HeapNode.get_hnid_blocks` added to P04 (additive — the row
matrix must be read block by block); `debug tc`, `debug.cell_lines`,
`debug.format_cell_record`. `tests/test_table_context.py` 151 tests, 1962
suite-wide, all green. **Differential:** `python -m pypstreader.debug tc <store>
<nid>` reproduces BOTH table goldens BYTE FOR BYTE on 8/8 Unicode corpus
stores — 16 tables, the root folder's hierarchy table (NID 0x12D) against
`read_root_folder` and the IPM subtree's against `read_ipm_subtree` (Empty
136/58 lines, javalibpst-dist-list 363/748, pstsdk-sample1 137/111,
pstsdk-submessage 102/111, pstsdk-test_unicode 104/111, synth-basics 34/51,
tika-variousBodyTypes 102/77). The 8th store, pstd-inline-cid, is
REFUSAL PARITY: both its goldens are empty with exit 1 because the ORACLE
refuses its only table context (its TCINFO declares rgib[TCI_bm] -
rgib[TCI_1b] = 5 existence-bitmap bytes for 5 columns, where [MS-PST]
2.3.4.1 allows ceil(5/8) = 1; its Boolean column is also 4 bytes wide at an
offset in an empty 1-byte region), and this port refuses it at the same
check with exit 1. The same goldens re-checked as DATA through
`parse_read_root_folder` / `parse_read_ipm_subtree` — every row id, version,
column id, `Type:` name, record kind (Small/Heap/Node) and decoded value,
14 tables, 7 stores. javalibpst-dist-list's IPM hierarchy table keeps its
row matrix in a SUB-NODE (12 rows, one block) and is pinned as the corpus
witness for that arm. **Private stores, STRUCTURE ONLY:** 100 table
contexts across the two (50 each), 56 rows, 398 cells decoded, column types
0x0003/0x000B/0x0014/0x001F/0x0040/0x0048/0x0102/0x1003/0x101F, no
non-`PstError` escape; every row has at least one sparse column. Against the
LIVE oracle (the prebuilt `read_ipm_subtree` binary, never `cargo`): 2/2
stores' IPM hierarchy tables — 23 columns × 10 rows each — agree on row ids,
versions, column ids, column types and exactly which cells are absent (no
value read, printed or asserted). **Denial:** a heap of each of the 8
non-TC client signatures, 4 bad `bType`s, a truncated TCINFO, a cCols whose
TCOLDESCs run past the item, cCols vs the bitmap width both ways, 4
unaligned/non-monotonic rgib sets, `rgib[TCI_4b]` of 0 and 4 (the
divergence), 5 unknown `wPropType`s, a PtypNull column, 8 columns whose cell
is outside its region, 5 whose `cbData` is not the type's width, an
existence bit past the schema and one exactly on the boundary (caught per
row, as upstream catches it), the two reserved columns moved, 6 wrong row
index BTH width pairs, a row index that is not a BTH, a null and an
out-of-range `hidRowIndex`, a duplicate row id, an index entry past the
matrix, a row id that is not indexed, an `hnidRows` past `cAlloc` and one
naming an absent sub-node (`PstNotFoundError`), a cell HNID past `cAlloc`
and one to an absent sub-node, an odd-length Unicode cell, 2 non-boolean
booleans, an MV count of 2^32-1, a row count over `max_items` and a matrix
over `max_allocation` (both `PstLimitError`), plus the new `tc_lies`
mutation family (25 lies on each base) through the harness's new
`tc.root_hierarchy` entry point; the sweep over both bases is clean.
**32 deliberate mutations, 29 confirmed red** (PYTHONDONTWRITEBYTECODE=1,
`__pycache__` cleared between runs); the 3 survivors are equivalent and
named in the commit message (the bitmap slice taken from the end of a row
that is always exactly `row_width`; `_check_offset`'s bounds, which
`TableContextInfo._validate` has already enforced — upstream keeps both
checks too; the TC's own row-index ceiling, which P04's `HeapTree` enforces
with the same `limits.max_items`). No upstream `#[test]` in
`table_context.rs`, so `check_upstream_parity.py` stays at 0 missing (15
upstream tests, 14 twinned, 1 pending P27-NU). Divergences (docstring):
`rgib[TCI_4b]` ≥ 8 (upstream underflows `end_4byte - 8`); a cell HNID of 0
is `None` (upstream refuses heap index 0 and fails the whole table);
`PtypObject` columns are readable; a duplicate row id and a row index entry
past the matrix are refused (upstream keeps the last / panics); rows and the
matrix size are bounded by `limits`. Followed, not fixed: a partial row at
the end of a matrix block is padding and is dropped ([MS-PST] 2.3.4.4).
upstream: `crates/pst/src/ltp/table_context.rs` (1,158 — largest LTP file)
oracle:   goldens `read_root_folder` / `read_ipm_subtree` over the corpus (16 tables), and the prebuilt `read_ipm_subtree` on the private stores
blocked on: P04

Table contexts: the column descriptor array, the row matrix, the row index, and
the cell-existence bitmap. Folder contents tables are TCs, so P08 cannot start
until this works.

**The trap:** the existence bitmap. A column can be *present in the schema* and
*absent from a row*, and reading the cell anyway returns stale heap bytes that
look like data. Test a row with a sparse column explicitly.

### P06b-EMPTY-TC
status: ✅ 2026-09-16 — `src/pypstreader/ltp/table_context.py`: `TableContextInfo._validate` no
longer refuses `rgib[TCI_4b] < ROW_HEADER_SIZE` (8) at TCINFO parse time; the check moved
to a new public method, `TableContextInfo.check_row_header_fits`, called from
`TableContext._read_matrix` only once the row count is known and only when it is `> 0`
(the module docstring's divergence paragraph rewritten to say exactly this). The eager
column-offset check (`_validate_column`) is untouched and still refuses a schema whose
reserved row-version column does not fit `end_4byte` regardless of row count — it is a
structural check, independent of this one.

**`debug folders` on `synth-basics.pst` is now byte-identical to the golden, 8/8 Unicode
corpus stores** (`tests/test_folder.py::test_debug_folders_is_byte_identical_to_the_golden`,
`BYTE_IDENTICAL` now = `UNICODE_STORES`, all eight). The six `Associated Table: None` lines
now print `Associated Count: 0`, matching `tests/golden/synth-basics/dump_messages.txt`
exactly — verified in-process (37/37 folder lines) and confirmed the underlying cause:
`opened.root_folder.associated_table` now returns a `TableContext` of `row_count == 0`
instead of raising. `test_synth_basics_associated_table_is_the_one_documented_divergence`
renamed to `test_synth_basics_associated_table_is_byte_identical` and rewritten to the 8/8
assertion.

`tests/test_table_context.py` gained two tests replacing the one that pinned the eager
refusal: `test_a_four_byte_region_that_cannot_hold_the_row_id_column_is_refused_at_parse_time`
(the structural check, `end_4byte = 0`, independent of row count) and
`test_a_four_byte_region_inside_the_row_header_is_refused_once_a_row_exists` (`end_4byte = 4`,
a single-column schema mirroring `synth-basics.pst`'s own shape, refused only once
`tc.row_count` is read) plus the new acceptance pin,
`test_a_four_byte_region_inside_the_row_header_is_accepted_while_the_matrix_is_empty`
(same shape, empty matrix, `row_count == 0`, `rows() == []`). `tests/corrupt.py`'s `tc_lies`
`rgib[TCI_4b]=4_inside_row_header` lie is unaffected: it targets NID 0x12D, the root
hierarchy table, which carries rows on every corpus base, so it still expects
`PstFormatError` — reverified via `tests/test_corrupt_generator.py` and
`tests/test_corruption.py` (80 passed, 5 skipped, no change needed). `tests/contract.py`
gained one adapter, `table_context.TableContextInfo.check_row_header_fits` (over every
real table's own TCINFO, via `s.tables`), 0 uncovered.

Whole suite `-m "not slow"`: **2355 passed** (2354 + 1 new test net of the 3-for-1
replacement), 22 skipped, 13 deselected, 2 xfailed, in ~23s. `check_provenance.py`,
`check_quality_ratchet.py` (tier 2 debt 0), `check_upstream_parity.py` and
`ruff check src tests scripts` all exit 0. **Mutant confirmed red**: re-added the eager
`check_row_header_fits()` call inside `TableContextInfo._validate` (with `__pycache__`
cleared, `PYTHONDONTWRITEBYTECODE=1`), and
`test_a_four_byte_region_inside_the_row_header_is_accepted_while_the_matrix_is_empty`
failed exactly as expected (`PstFormatError: TCINFO rgib[TCI_4b] 4 is inside the row
header's 8 bytes`); reverted and reconfirmed green.

upstream: `crates/pst/src/ltp/table_context.rs` (`TableContextInfo::read`, `rows_matrix`)
oracle:   `tests/golden/synth-basics/dump_messages.txt` (six `Associated Count: 0` lines)
blocked on: none (closed)

### P22-PROPTYPE
status: ✅ 2026-09-15 — `src/pypstreader/ltp/prop_type.py` landed; `tests/test_prop_type.py` 225 tests (266 suite-wide), all green; 30 `PropType` members (29 codes + CLSID alias) verified name-by-name against the [MS-OXCDATA] 2.11.1 table fetched from the spec; every `Value:`/`Type:` variant in the 9×3 property goldens (Integer32, Integer64, Boolean, Binary, Unicode, String8 on the corpus; all 28 upstream variants in the map) maps to a decoded PropType; 20 deliberate mutations of the decoder each confirmed red (GUID byte order, BOOLEAN leniency, signedness, over-long fixed values, FILETIME bounds ±1, limit-vs-format class, MV offset checks, lossy UTF-16, NUL alignment, MV_GUID length, NUL truncation, ObjectRef field order); FILETIME edges pinned: 0, 7, 10, 116444736000000000, 2650467743999999990, 2650467743999999999, 0x7FFFFFFFFFFFFFFF refused. No oracle line: this row has no example binary of its own — the layer rows diff its output through P05/P06.
upstream: `crates/pst/src/ltp/prop_type.rs` (134) and the per-type `read` arms in `ltp/prop_context.rs` (1,193 — the decoders only, not the context)
oracle:   the `Value:` lines of `read_store_props` / `read_root_folder` / `read_ipm_subtree` goldens show every type upstream produces on the corpus, in Debug form
blocked on: none

`ltp/prop_type.py`: `PropType` enum ([MS-OXCDATA] §2.11.1 values; unknown →
`PstUnsupportedError` naming the value) and one pure decoder per type:
`bytes → Python value`. PT_SHORT/LONG/LONGLONG/FLOAT/DOUBLE/BOOLEAN/ERROR;
PT_SYSTIME (FILETIME, 100 ns since 1601-01-01 → aware UTC `datetime`; values
before 1601 or past `datetime.max` are `PstFormatError`, not `OverflowError`);
PT_GUID; PT_UNICODE (UTF-16LE, no terminator); PT_STRING8 (needs a codepage —
`codecs`, default cp1252, unknown → `PstUnsupportedError`); PT_BINARY;
PT_CLSID; PT_OBJECT; and the PT_MV_* multi-valued forms with their
count+offsets prefix.

**Done means:** every decoder has a denial test (short buffer, bad count,
offsets out of range → `PstFormatError`), a round-trip property test where the
type is invertible, and the FILETIME edge cases (0, 1601 epoch, 9999-12-31,
`0x7FFFFFFFFFFFFFFF`) are pinned. Grep the goldens for every `Value:` variant
upstream printed and make sure each has a decoder.
