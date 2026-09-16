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
blocked on: P04

Property contexts, and the MAPI property-type decoders underneath them:
PT_LONG, PT_BOOLEAN, PT_UNICODE, PT_STRING8 (which needs a codepage —
upstream's examples pull in `codepage-strings`; Python's `codecs` covers it),
PT_BINARY, PT_SYSTIME (a Windows FILETIME → `datetime`, UTC, and beware the
1601 epoch), PT_GUID, and the multi-valued PT_MV_* forms.

**Done means:** `read_store_props` output matches property for property,
including types you did not expect to see. Unknown property types must raise
`PstUnsupportedError` naming the type — never silently return raw bytes.

**Size note:** this row plus its type decoders may overrun one session. A clean
split is: contexts first, then the PT_MV_* family as its own block.

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
