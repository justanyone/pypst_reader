# T04 — hardening, because the input is hostile

A PST arrives from a laptop image, a discovery production, an adversary. Every
offset, length and count in it is attacker-controlled. Python removes memory
corruption from the risk list and removes nothing else.

**This cluster is where the port deliberately diverges from upstream.** Say so
in each module's docstring, with the reason — an unexplained divergence reads
as a porting bug.

### P11-LIMITS
status: ✅ 2026-09-15 — `src/pypst/limits.py` landed (not a port; divergence stated in the docstring); `tests/test_limits.py` 32 tests (493 suite-wide, 4 skipped), all green; 18 deliberate mutations each confirmed red with bytecode disabled and `__pycache__` cleared (Limit-subclasses-Format, each helper's off-by-one and exclusive-ceiling, helper never fires, message drift, non-positive constant, field default drift, attachments arithmetic, MAX_ITEMS ≠ nid space, prop_type default unlinked, unfrozen, zero/bool accepted, only-first-field checked, revisit missed, set bound exclusive, set default, `__contains__` lies); `PstLimitError`/`PstFormatError` distinguishability asserted both ways; every `Limits` field checked against its constant by `dataclasses.fields` introspection; `prop_type.DEFAULT_MAX_ITEMS` now IS `limits.MAX_MV_ITEMS` (value unchanged, 1 000 000). ruff, provenance, quality ratchet (0/0) and parity lints green. No oracle line: nothing to diff — the row is a Python-side guard with no upstream output. Ceilings are INCLUSIVE (the ceiling passes, one over raises); both sides tested for every helper.

| ceiling | default | why |
|---|---|---|
| `MAX_BTREE_DEPTH` | 8 | BTPAGE.cLevel is u8 ([MS-PST] 2.2.2.7.7.1); upstream `UnicodeBTreeEntryPage::new` (ndb/page.rs) refuses an intermediate level outside 1..=8; 20 entries/page → 8 levels index 2.6e10 |
| `MAX_XBLOCK_DEPTH` | 2 | [MS-PST] 2.2.2.8.3.2: XXBLOCK → XBLOCK → data |
| `MAX_SUBNODE_DEPTH` | 2 | [MS-PST] 2.2.2.8.3.3: SIBLOCK → SLBLOCK; nested subnode trees are the embedded-message axis |
| `MAX_HEAP_TREE_DEPTH` | 8 | BTHHEADER.bIdxLevels is u8 ([MS-PST] 2.3.2.1); allocation ≤ 3580 B (2.3.1.2), index record ≤ 20 B → fan-out ≥ 179 → 4 levels cover MAX_HEAP_ITEMS; 8 is double |
| `MAX_EMBEDDED_MESSAGE_DEPTH` | 16 | no format bound; practical (real forward chains are 3–4 deep) |
| `MAX_ALLOCATION` | 256 MiB | XBLOCK cbTotal is u32 (4 GiB formal); Outlook's largest documented attachment cap is 150 MB; one order of magnitude over |
| `MAX_FILE_SIZE` | 64 GiB | ROOT.ibFileEof is u64 ([MS-PST] 2.2.2.5), unbounded by the format; Outlook's MaxLargeFileSize default is 51 200 MB (50 GiB); next power of two |
| `MAX_ITEMS` | 2^27 | nidIndex is 27 bits ([MS-PST] 2.2.2.1; = `ids.MAX_NODE_INDEX + 1`); also = MAX_FILE_SIZE / 512-byte page. The draft's 1_000_000 would refuse a real 50 GiB store's BBT |
| `MAX_HEAP_ITEMS` | 65 536 × 2 047 | HID: 16-bit hidBlockIndex × 11-bit hidIndex, 0 reserved ([MS-PST] 2.3.1.1) |
| `MAX_PROPERTY_COUNT` | 2^16 | PC BTH is keyed by the u16 property id ([MS-PST] 2.3.3.3) |
| `MAX_RECIPIENTS` | 2^16 | no format bound tighter than the u32 TCROWID; 130× Exchange's default MaxRecipientEnvelopeLimit (500) — practical |
| `MAX_ATTACHMENTS` | 510 × 340 = 173 400 | one SIBLOCK of SLBLOCKs: block ≤ 8192 (upstream `MAX_BLOCK_SIZE`) − 8 header − 16 trailer = 8168 → 510 SIENTRYs (16 B) × 340 SLENTRYs (24 B) subnodes per message |
| `MAX_FOLDERS`, `MAX_MESSAGES` | 2^27 each | every folder/message is a node in the shared 27-bit nidIndex space |
| `MAX_MV_ITEMS` | 1 000 000 | P22's landed default kept; a counted MV carries a u32 ulCount (2.3.3.4.2), arithmetic bound is MAX_ALLOCATION // 4 offsets; 1 M = 4 MiB of offsets |

API: `check_depth/check_count/check_allocation(value, ceiling, what)` → `PstLimitError(f"{what}: {value} exceeds limit {ceiling}")`; `VisitedSet(what, ceiling=MAX_ITEMS).add(key)` → `PstLimitError(f"{what}: cycle at {key!r}")` on a revisit, and the size trip once `len == ceiling`. `Limits` refuses a non-positive field with `ValueError` and a non-int (incl. bool) with `TypeError` — caller configuration, never a `PstError`. The walks (P02 onward) call these; nothing in this row wires them in.
upstream: no direct equivalent (Rust's bounds checks make a panic survivable)
oracle:   none
blocked on: none, but meaningless before P02

A `limits.py` carrying the ceilings, and `PstLimitError` raised at each:

- **BTree depth** — a self-referential BTree must terminate, not hang.
- **Visited-node set** — cycle detection on every graph walk (NBT, BBT, BTH,
  subnode trees, embedded messages).
- **Total allocation** — a block claiming 4 GB inside a 265 KB file is refused
  before `bytearray(n)` is called, not after the machine swaps.
- **Item counts** — folders, messages, attachments, recipients.
- **Embedded-message depth** — an attachment containing a message containing an
  attachment, forever.

Every ceiling is a named constant with a default, overridable by the caller.
Refusal must be distinguishable from corruption: `PstLimitError`, never
`PstFormatError`, so a legitimately enormous store can be retried.

### P12-FUZZ
status: ✗ not started
upstream: none
oracle:   none — these files are not valid, so the oracle's behaviour on them
          is interesting but not authoritative
blocked on: P01 for the generator and the header mutations; each later layer adds its own mutations in its own row

The corruption suite. **Every input here is bytes we write ourselves**, which
is why this row needs no licensable PST and can be built the day P03 lands:

- `!BDN` magic and then nothing
- a valid header with a CRC that does not match
- a byte index pointing past EOF
- a block declaring a size larger than the file
- an NBT whose root page points at itself
- a BTH with a cycle
- an XXBLOCK tree 10,000 deep
- a `wVer` from the future

Each must raise a `PstError` subclass — named, specific, and *not* a
`struct.error`, `IndexError`, `MemoryError` or hang. Assert the exception type,
not just that something was raised.

Build these as a generator (`tests/corrupt.py`) that mutates a corpus store
(default `pstd-inline-cid.pst`, the smallest populated one; parametrise over
the Unicode corpus where cheap), so the suite grows by adding a mutation
rather than by checking in more binaries. P24 consumes the same generator.
