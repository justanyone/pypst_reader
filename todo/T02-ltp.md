# T02 — the LTP layer (lists, tables, properties)

The middle of the format: structures built *on top of* nodes that turn bytes
into MAPI properties. ~3,700 upstream lines. Less mechanical than NDB and more
fiddly; this is where a port most often produces something that runs and is
subtly wrong.

### P04-HEAP
status: ✗ not started
upstream: `crates/pst/src/ltp/heap.rs` (667), `ltp/tree.rs` (374)
oracle:   `scripts/oracle.sh read_root_folder tests/fixtures/Empty.pst`
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
status: ✗ not started (leaf — runs beside lane A)
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
