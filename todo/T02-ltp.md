# T02 — the LTP layer (lists, tables, properties)

The middle of the format: structures built *on top of* nodes that turn bytes
into MAPI properties. ~3,700 upstream lines. Less mechanical than NDB and more
fiddly; this is where a port most often produces something that runs and is
subtly wrong.

### P04-HEAP
status: ✅ 2026-09-16 — `src/pypst/ltp/heap.py` (HeapId, HeapNodeId, HeapNodeType,
HeapNodeHeader, HeapPageMap, HeapNode) and `src/pypst/ltp/tree.py`
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
status: ✗ not started
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
status: ✗ not started
upstream: `crates/pst/src/ltp/table_context.rs` (1,158 — largest LTP file)
oracle:   `scripts/oracle.sh read_named_props tests/fixtures/Empty.pst`, and P08's folder listing
blocked on: P04

Table contexts: the column descriptor array, the row matrix, the row index, and
the cell-existence bitmap. Folder contents tables are TCs, so P08 cannot start
until this works.

**The trap:** the existence bitmap. A column can be *present in the schema* and
*absent from a row*, and reading the cell anyway returns stale heap bytes that
look like data. Test a row with a sparse column explicitly.

### P22-PROPTYPE
status: ✅ 2026-09-15 — `src/pypst/ltp/prop_type.py` landed; `tests/test_prop_type.py` 225 tests (266 suite-wide), all green; 30 `PropType` members (29 codes + CLSID alias) verified name-by-name against the [MS-OXCDATA] 2.11.1 table fetched from the spec; every `Value:`/`Type:` variant in the 9×3 property goldens (Integer32, Integer64, Boolean, Binary, Unicode, String8 on the corpus; all 28 upstream variants in the map) maps to a decoded PropType; 20 deliberate mutations of the decoder each confirmed red (GUID byte order, BOOLEAN leniency, signedness, over-long fixed values, FILETIME bounds ±1, limit-vs-format class, MV offset checks, lossy UTF-16, NUL alignment, MV_GUID length, NUL truncation, ObjectRef field order); FILETIME edges pinned: 0, 7, 10, 116444736000000000, 2650467743999999990, 2650467743999999999, 0x7FFFFFFFFFFFFFFF refused. No oracle line: this row has no example binary of its own — the layer rows diff its output through P05/P06.
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
