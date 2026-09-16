# Layer interfaces — the contract between rows

**This file is written before the code.** It exists so that an agent working
row P05 can code against row P04's surface while P04 is still a branch, and so
that two agents never have to guess each other's names. It is derived from
upstream's `pub` surface (Unicode arms only, read path only — ADR-0003), and
then made Pythonic where the `rust-port` skill says to.

Rules:

- The row that **builds** a layer owns its section and updates it in the same
  commit as the code. A section is a promise until then and a description
  after.
- Changing a name or signature another row depends on: tell that row's agent
  before the change (`docs/AGENTS.md`), and add a line to the changelog at the
  bottom.
- Every parsed structure is `@dataclass(frozen=True, slots=True)`. Every
  failure is a `PstError` subclass from `pypstreader.errors`. Every fixed-width
  integer is masked where it is computed.
- `__str__` on a value type must be stable: golden parsers (`tests/golden_parsers.py`)
  round-trip through it, and `pypstreader.debug` prints it.

Conventions for reading this file: `→ X` is the return type; `!E` after a
signature lists the exception types it may raise beyond the universal
`PstFormatError` for malformed bytes.

---

## `pypstreader.errors` — exists

```python
class PstError(Exception)                       # the family; nothing else escapes a public entry point
class PstFormatError(PstError)                  # the bytes are not a valid PST structure
class PstLimitError(PstError)                   # valid-looking but beyond a configured ceiling (limits.py)
class PstUnsupportedError(PstError)             # recognised, deliberately not handled: ANSI, unknown crypt/prop type
class PstNotFoundError(PstFormatError)          # a B-tree key the tree does not hold (upstream's BTreePageNotFound); added by P02
```

Additive only. P11 adds nothing here; it raises `PstLimitError`.

## `pypstreader.limits` — exists (P11)

Not a port: upstream has no equivalent (Rust's bounds checks make a panic
survivable; an unbounded Python loop is a hang). Every default cites the
[MS-PST] section, the upstream check, or the arithmetic that bounds it, in a
comment next to the constant. **Ceilings are inclusive**: the ceiling itself
passes, one over raises.

```python
MAX_BTREE_DEPTH: int = 8                # BTPAGE.cLevel u8; upstream page.rs refuses an intermediate level outside 1..=8
MAX_XBLOCK_DEPTH: int = 2               # [MS-PST] 2.2.2.8.3.2: XXBLOCK → XBLOCK → data
MAX_SUBNODE_DEPTH: int = 2              # [MS-PST] 2.2.2.8.3.3: SIBLOCK → SLBLOCK (nested subnode trees are the embedded-message axis)
MAX_HEAP_TREE_DEPTH: int = 8            # BTHHEADER.bIdxLevels u8; fan-out ≥ 179 per 3580-byte allocation → 4 levels cover MAX_HEAP_ITEMS
MAX_FOLDER_DEPTH: int = 64              # no format bound; practical (P08 added it; oracle/examples/dump_messages.rs uses the same 64)
MAX_EMBEDDED_MESSAGE_DEPTH: int = 16    # no format bound; practical
MAX_ALLOCATION: int = 256 * 2**20       # largest single bytes a walk assembles; XBLOCK cbTotal is u32 (4 GiB), Outlook writes ≤ 150 MB
MAX_FILE_SIZE: int = 64 * 2**30         # ROOT.ibFileEof is u64; Outlook's MaxLargeFileSize default is 50 GiB; next power of two
MAX_ITEMS: int = 1 << 27                # entries in one tree, rows in one table, keys in one VisitedSet: the 27-bit nidIndex space (= MAX_NODE_INDEX + 1 = MAX_FILE_SIZE / 512 pages)
MAX_HEAP_ITEMS: int = 65_536 * 2_047    # HID: 16-bit block index × 11-bit index with 0 reserved
MAX_PROPERTY_COUNT: int = 1 << 16       # PC is a BTH keyed by the u16 property id
MAX_RECIPIENTS: int = 1 << 16           # no format bound below the u32 row id; 130× Exchange's default envelope limit
MAX_ATTACHMENTS: int = 510 * 340        # one SIBLOCK of SLBLOCKs: (8192-8-16)//16 × (8192-8-16)//24 subnodes per message
MAX_FOLDERS: int = 1 << 27              # every folder is a node; 27-bit nidIndex
MAX_MESSAGES: int = 1 << 27             # every message is a node; 27-bit nidIndex
MAX_MV_ITEMS: int = 1_000_000           # prop_type.decode's max_items default (P22's landed value); bound is MAX_ALLOCATION // 4 offsets

@dataclass(frozen=True, slots=True)
class Limits:                           # one field per constant, lowercased: max_btree_depth … max_mv_items
    ...                                 # __post_init__: non-positive → ValueError, non-int (incl. bool) → TypeError.
                                        # Caller configuration, not file input — the one place those are right; never a PstError.
DEFAULT_LIMITS = Limits()

def check_depth(depth: int, ceiling: int, what: str) → None        # depth > ceiling → PstLimitError
def check_count(count: int, ceiling: int, what: str) → None        # count > ceiling → PstLimitError, before anything is allocated
def check_allocation(nbytes: int, ceiling: int, what: str) → None  # nbytes > ceiling → PstLimitError, before bytearray(nbytes)
# each raises PstLimitError(f"{what}: {value} exceeds limit {ceiling}")

class VisitedSet:                       # cycle guard, one per walk
    __init__(self, what: str, ceiling: int = MAX_ITEMS)
    add(self, key: Hashable) → None     # revisit → PstLimitError(f"{what}: cycle at {key!r}"); len == ceiling → PstLimitError (the set cannot be the DoS)
    __contains__, __len__
```

Every public opener accepts `limits: Limits = DEFAULT_LIMITS` and threads it
down. A limit trip is `PstLimitError(f"{what}: {value} exceeds limit {ceiling}")`,
and a revisited key in a walk is `PstLimitError(f"{what}: cycle at {key!r}")` —
a cycle is corruption by any reading, but every walk's contract above already
promises `PstLimitError` for it, and a caller that hits one has the same move
either way: stop.

## `pypstreader.encode`, `pypstreader.crc` — exist

```python
encode.decode_block(data: bytes | bytearray | memoryview, method: CryptMethod, key: int) → bytes
crc.compute_crc(data: bytes) → int     # u32
```

(Names as landed in P00; check the modules. `CryptMethod` moves to `ndb.header`
in P01 if it is not already an enum.)

## `pypstreader.ndb.ids` + `pypstreader.block_sig` — landed (P23)

```python
NODE_ID_FORMAT = "<I"; BLOCK_ID_FORMAT = "<Q"; BYTE_INDEX_FORMAT = "<Q"; BLOCK_REF_FORMAT = "<QQ"
MAX_NODE_INDEX = (1 << 27) - 1
MAX_BLOCK_INDEX = (1 << 62) - 1

class NodeIdType(IntEnum):          # [MS-PST] 2.2.2.1 — the 5-bit nidType, named as the spec names them
    HID = 0x00, INTERNAL = 0x01, NORMAL_FOLDER = 0x02, SEARCH_FOLDER = 0x03,
    NORMAL_MESSAGE = 0x04, ATTACHMENT = 0x05, SEARCH_UPDATE_QUEUE = 0x06,
    SEARCH_CRITERIA_OBJECT = 0x07, ASSOC_MESSAGE = 0x08, CONTENTS_TABLE_INDEX = 0x0A,
    RECEIVE_FOLDER_TABLE = 0x0B, OUTGOING_QUEUE_TABLE = 0x0C, HIERARCHY_TABLE = 0x0D,
    CONTENTS_TABLE = 0x0E, ASSOC_CONTENTS_TABLE = 0x0F, SEARCH_CONTENTS_TABLE = 0x10,
    ATTACHMENT_TABLE = 0x11, RECIPIENT_TABLE = 0x12, SEARCH_TABLE_INDEX = 0x13,
    LTP = 0x1F
    debug_name → str                # the name upstream prints and the goldens contain: HID → "HeapNode",
                                    # SEARCH_CRITERIA_OBJECT → "SearchCriteria", ASSOC_MESSAGE → "AssociatedMessage",
                                    # ASSOC_CONTENTS_TABLE → "AssociatedContentsTable", LTP → "ListsTablesProperties",
                                    # every other member → its CamelCase spelling
    @classmethod from_debug_name(cls, name: str) → NodeIdType   # !PstFormatError; the inverse, for golden parsers

# Every value type below: @dataclass(frozen=True, slots=True); a raw value outside its width (negative,
# too wide, bool, float) → PstFormatError in __post_init__; `SIZE: ClassVar[int]` is the on-disk size;
# unpack_from(buf: bytes | bytearray | memoryview, offset: int = 0) raises PstFormatError on a short
# buffer, an offset past the end, or a NEGATIVE offset (struct would count it from the end; we refuse);
# pack() → bytes is the inverse, for round-trip tests.

class NodeId:                       # u32
    raw: int                        # NodeId(raw) holds ANY u32, an unknown 5-bit type included — upstream's From<u32>;
                                    # the B-tree that contains such a node must stay walkable (goldens print them `invalid`)
    SIZE = 4
    @classmethod from_parts(cls, id_type: NodeIdType, index: int) → NodeId   # strict: unknown type or index > MAX_NODE_INDEX → PstFormatError
    @classmethod unpack_from(cls, buf, offset=0) → NodeId
    pack() → bytes
    id_type → NodeIdType            # !PstFormatError on an unknown 5-bit value — THIS is where an unknown type is refused
    index → int                     # 27 bits
    __str__ → "NodeId { <debug_name>: 0x<index, %X> }" | "NodeId { invalid: 0x<raw, %08X> }"

NID_MESSAGE_STORE = NodeId(0x21); NID_NAME_TO_ID_MAP = NodeId(0x61); NID_NORMAL_FOLDER_TEMPLATE = NodeId(0xA1)
NID_SEARCH_FOLDER_TEMPLATE = NodeId(0xC1); NID_ROOT_FOLDER = NodeId(0x122); NID_SEARCH_MANAGEMENT_QUEUE = NodeId(0x1E1)
NID_SEARCH_ACTIVITY_LIST = NodeId(0x201); NID_RESERVED1 = NodeId(0x241); NID_SEARCH_DOMAIN_OBJECT = NodeId(0x261)
NID_SEARCH_GATHERER_QUEUE = NodeId(0x281); NID_SEARCH_GATHERER_DESCRIPTOR = NodeId(0x2A1); NID_RESERVED2 = NodeId(0x2E1)
NID_RESERVED3 = NodeId(0x301); NID_SEARCH_GATHERER_FOLDER_QUEUE = NodeId(0x321)      # all of upstream's, [MS-PST] 2.4.1

class BlockId:                      # u64; bit 1 = internal, bit 0 reserved, rest index
    raw: int
    SIZE = 8
    @classmethod from_parts(cls, is_internal: bool, index: int) → BlockId     # index > MAX_BLOCK_INDEX → PstFormatError
    @classmethod unpack_from(cls, buf, offset=0) → BlockId
    pack() → bytes
    is_internal → bool
    index → int
    search_key → int                # what the BBT is keyed on: raw with the reserved bit cleared
    __str__ → "BlockId { leaf: 0x<index, %X> }" | "BlockId { internal: 0x<index, %X> }"

class PageId:                       # u64, the whole value is the index; distinct type on purpose
    raw: int
    SIZE = 8
    @classmethod unpack_from(cls, buf, offset=0) → PageId
    pack() → bytes
    is_internal → bool              # always False
    index → int; search_key → int   # both == raw
    __str__ → "PageId: 0x<raw, %X>"

class ByteIndex:                    # u64 file offset. Not an int: ByteIndex + ByteIndex is a TypeError.
    value: int
    SIZE = 8
    @classmethod unpack_from(cls, buf, offset=0) → ByteIndex
    pack() → bytes
    __str__ → "ByteIndex { 0x<value, %X> }"

class BlockRef:                     # BREF, [MS-PST] 2.2.2.4 — struct "<QQ"
    block: BlockId
    index: ByteIndex
    SIZE = 16
    @classmethod unpack_from(cls, buf, offset=0) → BlockRef
    pack() → bytes
    __str__ → "BlockRef { block: <BlockId>, index: <ByteIndex> }"

class PageRef:                      # same bytes, page-typed: the header's NBT/BBT roots, every B-tree child
    page: PageId
    index: ByteIndex
    SIZE = 16
    @classmethod unpack_from(cls, buf, offset=0) → PageRef
    pack() → bytes
    __str__ → "PageRef { page: <PageId>, index: <ByteIndex> }"

block_sig.compute_sig(index: int, block_id: int) → int     # u16; [MS-PST] 5.5; both inputs masked to u32 first (upstream's `as u32`)
```

Upstream's `Unicode*` prefix is dropped: there is only one variant here. Every
`__str__` is upstream's `Debug` text with that prefix removed, and
`tests/test_ids.py` checks it against every id in the read_header and
read_btrees goldens. Nothing here has `next()`: it has no read-path caller.

## `pypstreader.ndb.header` + `pypstreader.ndb.root` — landed (P01)

```python
# pypstreader.ndb.root
ROOT_FORMAT = "<IQQQQQQQQBBH"
class AmapStatus(IntEnum):  INVALID = 0x00, VALID1 = 0x01, VALID2 = 0x02
    debug_name → str                 # "Invalid" | "Valid1" | "Valid2" — upstream's spelling; __str__ is the same
    @classmethod from_byte(cls, value) → AmapStatus            # strict: unknown → PstFormatError
    @classmethod from_byte_lenient(cls, value) → AmapStatus    # upstream's read: unknown → INVALID

@dataclass(frozen=True, slots=True)
class Root:                          # [MS-PST] 2.2.2.5, Unicode layout, 72 bytes
    file_eof_index: ByteIndex
    amap_last_index: ByteIndex
    amap_free_size: ByteIndex
    pmap_free_size: ByteIndex
    node_btree: PageRef
    block_btree: PageRef
    amap_is_valid: AmapStatus        # via from_byte_lenient — an unknown byte reads as INVALID, as upstream
    SIZE = 72
    @classmethod unpack_from(cls, buf, offset=0) → Root        # short buffer / bad offset → PstFormatError
    # dwReserved, bReserved, wReserved are read and discarded (spec: readers SHOULD ignore)

# pypstreader.ndb.header
HEADER_MAGIC = 0x4E444221; HEADER_MAGIC_CLIENT = 0x4D53      # "!BDN" and "SM" read little-endian
CLIENT_VERSION = 19; PLATFORM_CREATE = PLATFORM_ACCESS = 0x01; SENTINEL = 0x80
CRYPT_METHOD_EDPCRYPTED = 0x10                                # the spec's name; refused by name
HEADER_SIZE = 564
from pypstreader.encode import CryptMethod                         # NONE/PERMUTE/CYCLIC live with the decoders; re-exported

class Version(IntEnum):  ANSI_14 = 14, ANSI_15 = 15, UNICODE = 23, UNICODE_4K_36 = 36, UNICODE_4K_37 = 37
    is_ansi → bool
    debug_name → str                 # "Ansi" | "Unicode" (upstream's NdbVersion Debug); __str__ is the same

@dataclass(frozen=True, slots=True)
class Header:                        # [MS-PST] 2.2.2.6, Unicode layout, 564 bytes
    version: Version                 # always Version.UNICODE once constructed
    client_version: int              # wVerClient, always 19 once constructed
    crypt_method: CryptMethod
    next_block: BlockId
    next_page: PageId
    unique_value: int                # dwUnique
    root: Root
    SIZE = 564
    @classmethod parse(cls, buf: bytes | bytearray | memoryview) → Header
        # !PstUnsupportedError  wVer 14/15 ("ANSI (pre-2003) store, wVer=14; … see pypstreader_nu"),
        #                       wVer 36/37 (4 KB-page store), bCryptMethod 0x10 (EDP/WIP)
        # !PstFormatError       short buffer, bad dwMagic, bad wMagicClient, unknown wVer, partial or full
        #                       CRC mismatch, wVerClient ≠ 19, platform bytes ≠ 1, dwAlign ≠ 0,
        #                       bSentinel ≠ 0x80, unknown bCryptMethod, rgbReserved ≠ 0
        # Check order: length, dwMagic, wMagicClient, wVer, dwCRCPartial, dwCRCFull, the fixed fields.
        # Read but NOT validated (as upstream): dwReserved1/2, bidUnused, qwUnused, rgbFM, rgbFP,
        # rgbReserved2, bReserved, rgbReserved3; rgnid is read and not kept.

read_header(f: BinaryIO) → Header    # seeks to 0, reads SIZE bytes; short read → PstFormatError; OSError is not caught
```

`python -m pypstreader.debug header <file>` prints the ten `read_header` lines in
upstream's format (`__str__` forms, no `Unicode` prefix) so `parse_read_header`
compares values directly; on an ANSI store it exits 1 with the
`PstUnsupportedError` message on stderr.

Changes from the draft, and why: `wVer` 36/37 are **refused**
(`PstUnsupportedError`), not parsed — they are the 4 KB-page layout, upstream
refuses them too, and reading them with 512-byte-page assumptions is the
plausible-garbage outcome. `CryptMethod` stays in `pypstreader.encode` (it was
already an enum there) and gains no `WINDOWS_EFS` member: 0x10 is the constant
`CRYPT_METHOD_EDPCRYPTED` and is refused before the enum is consulted, so
`decode_block` can never be handed it. `AmapStatus` has the two conversions
because upstream's read is lenient and the rest of this package is not.
`tests/corrupt.py` (mutation helpers; `reseal_header` recomputes both CRCs)
is the seed P12 extends.

## `pypstreader.ndb.page` + `pypstreader.ndb.btree` — landed (P02)

Unicode arms only. `page.py` parses one 512-byte page; `btree.py` reads
pages from the file and walks them. AMap/PMap/FMap/FPMap contents are not
ported (write-path only); `PageType` still names them.

```python
# pypstreader.ndb.page
PAGE_SIZE = 512; PAGE_DATA_SIZE = 496; BTREE_ENTRIES_SIZE = 488; MAX_BTREE_LEVEL = 8
DENSITY_LIST_OFFSET = 0x4200; DENSITY_LIST_INDEX = ByteIndex(0x4200); DENSITY_LIST_MAX_ENTRIES = 119
class PageType(IntEnum):  BBT = 0x80, NBT = 0x81, FMAP = 0x82, PMAP = 0x83, AMAP = 0x84, FPMAP = 0x85, DL = 0x86
    from_byte(value) → PageType                       # !PstFormatError unknown
    is_signed → bool; signature(index: int, page_id: int) → int   # compute_sig for BBT/NBT/DL, else 0
    debug_name → str; __str__ = debug_name            # "BlockBTree", "DensityList", … (goldens)

@dataclass(frozen=True, slots=True)
class PageTrailer:                   # [MS-PST] 2.2.2.7.1, the last 16 bytes of a page
    page_type: PageType; signature: int; crc: int; block_id: PageId
    SIZE = 16
    unpack_from(buf, offset=496) → PageTrailer        # !PstFormatError ptype != ptypeRepeat, unknown ptype, short
    verify(self, page_bytes, index: ByteIndex) → None # !PstFormatError CRC over the 496 data bytes; wrong length
    expected_signature(self, index) → int             # informational — NOT enforced (upstream ignores wSig on read)

@dataclass(frozen=True, slots=True)
class IntermediateEntry:             # BTENTRY 2.2.2.7.7.2, 24 bytes
    key: int; ref: PageRef;          unpack_from(buf, offset=0)
@dataclass(frozen=True, slots=True)
class BlockBTreeEntry:               # BBTENTRY 2.2.2.7.7.3, 24 bytes
    block: BlockRef; size: int; ref_count: int;  key → int (block.block.search_key);  unpack_from
@dataclass(frozen=True, slots=True)
class NodeBTreeEntry:                # NBTENTRY 2.2.2.7.7.4, 32 bytes
    node: NodeId; data: BlockId; sub_node: BlockId | None; parent: NodeId | None   # None when the field is 0
    key → int (node.raw);  unpack_from                # !PstFormatError nid wider than 32 bits (as upstream)

@dataclass(frozen=True, slots=True)
class BTreePage:                     # BTPAGE 2.2.2.7.7.1
    level: int; max_entries: int; entry_size: int
    entries: tuple[IntermediateEntry, ...] | tuple[BlockBTreeEntry, ...] | tuple[NodeBTreeEntry, ...]
    trailer: PageTrailer;  is_leaf → bool;  page_type → PageType
    parse(page_bytes, kind: PageType, index: ByteIndex) → BTreePage
        # upstream's checks in upstream's order: cEnt ≤ cEntMax; cbEnt ≥ entry size for the level (larger is
        # the stride, allowed); cEntMax ≤ 488 // cbEnt; cLevel ≤ 8; dwPadding == 0; ptype ∈ {BBT, NBT}; CRC;
        # a LEAF must be `kind` (an intermediate page may be either type, as upstream). All !PstFormatError.

@dataclass(frozen=True, slots=True)
class DensityListEntry:  raw: int;  page → int (20 bits);  free_slots → int (12 bits);  __str__ "DensityListPageEntry(raw)"
@dataclass(frozen=True, slots=True)
class DensityListPage:               # DLISTPAGE 2.2.2.7.2
    backfill_complete: bool; current_page: int; entries: tuple[DensityListEntry, ...]; trailer: PageTrailer
    parse(page_bytes, index=DENSITY_LIST_INDEX) → DensityListPage   # !PstFormatError count > 119, padding, ptype != DL, CRC

# pypstreader.ndb.btree
read_page(f, index: ByteIndex, limits=DEFAULT_LIMITS) → bytes     # one seek + one 512-byte read; !PstFormatError short read or index+512 > limits.max_file_size
read_density_list(f, limits=DEFAULT_LIMITS) → DensityListPage     # !PstFormatError when the slot is not a DL page (upstream: InvalidPageType(0))

class NodeBTree / BlockBTree:
    __init__(self, f: BinaryIO, root: PageRef, limits: Limits = DEFAULT_LIMITS)
    root → PageRef; limits → Limits
    find(self, key: NodeId | int) → NodeBTreeEntry            # NodeBTree: raw NID or int
    find(self, key: BlockId | int) → BlockBTreeEntry          # BlockBTree: search_key (reserved bit ignored) or int
        # !PstNotFoundError (a PstFormatError) when absent — including a key below the first key of the root
    __iter__ → Iterator[entry]       # leaf entries in tree order (key order for a well-formed store)
    pages() → Iterator[BTreePage]    # pre-order, root first, children in entry order — read_btrees' print order
    # Limits, on every walk: depth > limits.max_btree_depth → PstLimitError (root is depth 0; 8 is the deepest
    # cLevel ≤ 8 allows); a page visited twice (cycle OR shared page) → PstLimitError; entries yielded and
    # pages visited > limits.max_items → PstLimitError. Iterative: no RecursionError.
    # Divergence: an NBT intermediate key > 32 bits → PstFormatError (upstream's example skips the subtree).
```

`python -m pypstreader.debug btrees` prints upstream's `read_btrees` format; the block
section byte for byte, the node section down to each entry's data block id,
`Size:` (from the BBT entry) for a leaf data block, sub-node block id and parent —
the data-tree and sub-node-tree lines under those are blocks (P03), which
extends the dumper. `python -m pypstreader.debug density_list` prints
`read_density_list`'s seven lines; a store without the page is refused (exit 1)
where upstream prints an `Error:` line with exit 0.

## `pypstreader.ndb.block` — landed (P03)

Unicode arm only. One block at a time through the block B-tree, the
XBLOCK/XXBLOCK data trees and the SLBLOCK/SIBLOCK subnode trees over them.

```python
MAX_BLOCK_SIZE = 8192; BLOCK_TRAILER_SIZE = 16; MAX_BLOCK_DATA_SIZE = 8176; TREE_HEADER_SIZE = 8
BTYPE_DATA_TREE = 0x01; BTYPE_SUBNODE_TREE = 0x02
BLOCK_TRAILER_FORMAT = "<HHIQ"; DATA_TREE_HEADER_FORMAT = SUBNODE_HEADER_FORMAT = "<BBHI"
DATA_TREE_ENTRY_FORMAT = "<Q"; SUBNODE_LEAF_ENTRY_FORMAT = "<QQQ"; SUBNODE_INTERMEDIATE_ENTRY_FORMAT = "<QQ"

def block_size(size: int) → int      # DATA size (BBT cb) → 64-byte-aligned allocation INCLUDING the 16-byte trailer;
                                     # !PstFormatError outside 1..=8176 (upstream's block_size takes cb+16 and asserts)

@dataclass(frozen=True, slots=True)
class BlockTrailer:  size: int; signature: int; crc: int; block_id: BlockId;  SIZE = 16
    unpack_from(buf, offset=0) → BlockTrailer        # !PstFormatError cb outside 1..=8176, short buffer
    cyclic_key → int                                 # search_key & 0xFFFFFFFF (upstream's `as u32`)
    verify_block_id(self, is_internal: bool) → None  # !PstFormatError when the bid's internal bit disagrees
    verify_crc(self, data) → None                    # !PstFormatError; over the cb bytes only
    expected_signature(self, index: ByteIndex) → int # informational — NOT enforced (upstream ignores wSig)

@dataclass(frozen=True, slots=True)
class DataBlock:  data: bytes (decoded); trailer: BlockTrailer
@dataclass(frozen=True, slots=True)
class XBlock:     level: int (1 XBLOCK, 2 XXBLOCK — one class, as upstream's DataTreeBlock); total_size: int (lcbTotal);
                  entries: tuple[BlockId, ...]; trailer: BlockTrailer
@dataclass(frozen=True, slots=True)
class SubNodeLeafEntry:          node: NodeId; data: BlockId; sub_node: BlockId | None;  SIZE = 24;  unpack_from
                                 # nid is the 8-byte field truncated to 32 bits (upstream `as u32`); sub_node None when bidSub == 0
@dataclass(frozen=True, slots=True)
class SubNodeIntermediateEntry:  node: NodeId; next_level: BlockId;  SIZE = 16;  unpack_from
@dataclass(frozen=True, slots=True)
class SubNodeLeafBlock:          level: int (0); entries: tuple[SubNodeLeafEntry, ...]; trailer
@dataclass(frozen=True, slots=True)
class SubNodeIntermediateBlock:  level: int (> 0); entries: tuple[SubNodeIntermediateEntry, ...]; trailer

class BlockReader:
    __init__(self, f: BinaryIO, header: Header, bbt: BlockBTree, limits: Limits = DEFAULT_LIMITS)
    limits → Limits; crypt_method → CryptMethod
    find(self, block: BlockId) → BlockBTreeEntry                     # the BBT lookup; !PstNotFoundError
    read_block(self, ref: BlockRef, size: int, *, is_internal: bool) → bytes
        # the `size` (= cb) bytes, one seek + one read of block_size(size); data: trailer cb == size, bid not internal,
        # CRC, then DEcoded (cyclic key = trailer bid); internal: bid internal, CRC, trailer located from the header's
        # implied size as upstream, NEVER decoded. !PstFormatError short read, ref + allocation > limits.max_file_size
    read_data_tree(self, block: BlockId) → DataBlock | XBlock         # one block; the BBT bid's internal bit decides
    read_subnode_block(self, block: BlockId) → SubNodeLeafBlock | SubNodeIntermediateBlock   # cLevel > 0 → SIBLOCK
    read_data(self, block: BlockId) → bytes            # leaves of the tree in order; !PstLimitError lcbTotal > max_allocation
                                                       # (checked BEFORE any child read), assembled > max_allocation,
                                                       # internal depth > max_xblock_depth (root = 1), a revisited internal block
    read_subnode_tree(self, block: BlockId) → dict[NodeId, SubNodeLeafEntry]   # first entry per NID wins;
                                                       # !PstLimitError depth > max_subnode_depth, cycle, entries > max_items
    node_data(self, entry: NodeBTreeEntry) → bytes    # read_data(entry.data); a zero bidData is !PstNotFoundError (as upstream)
```

Verified on a block, exactly upstream's checks in upstream's order (module
docstring): trailer `cb` in 1..=8176; data block `cb` == BBT `cb`, bid not
internal, CRC; tree block type byte, `cEnt × entry ≤ cb − 8`, bid internal,
CRC, subnode `dwPadding == 0`. Not verified, as upstream: `wSig`, the
trailer bid's index, XBLOCK `cLevel`, `lcbTotal` against the assembled
length, slack in a tree block's `cb`. `PstNotFoundError` from the BBT
propagates unwrapped for every absent bid.

`python -m pypstreader.debug btrees` now prints upstream's `read_btrees` output in
full — data trees (`Data Tree Level:`/`Total Size:`/`Block:`, a data
block's TRAILER bid and decoded length) and sub-node trees (`Sub-Node Block
Entries:`, `PageRef:`, nested `Sub-Node Block:`), quirks included — byte-
identical on 8/8 Unicode corpus stores. `python -m pypstreader.debug node <file>
<nid-hex>` prints `Node:`, `Data Length:`, `Data CRC32:` (zlib), `Sub-Nodes:`
— the way to compare a node's bytes without printing them. `main` now passes
extra positional arguments to a dumper that declares them.

Changes from the draft, and why: `block_size` takes the data size and adds
the trailer itself (the draft said so; upstream's takes cb+16 — noted so a
reader of both is not misled). `SubNodeEntry` became `SubNodeLeafEntry`
(upstream's `LeafSubNodeTreeEntry`) beside `SubNodeIntermediateEntry`; the
per-block readers `read_data_tree` / `read_subnode_block`, `find`, the
four block dataclasses and the trailer's `verify_*` split were added because
the dumper and the tests need one block at a time. `limits` defaults to
`DEFAULT_LIMITS`. `tests/corrupt.py` gained the block builders (`data_block`,
`xblock`, `slblock`, `siblock`, `block_trailer`, `file_with_blocks`) for P12.

## `pypstreader.ltp.heap` + `pypstreader.ltp.tree` — landed (P04)

Unicode arm only. The Heap-on-Node over a node's data blocks and its
sub-node tree, and the BTree-on-Heap over that.

```python
# pypstreader.ltp.heap
HEAP_ID_FORMAT = "<I"; HEAP_HEADER_FORMAT = "<HBBII"; HEAP_HEADER_SIZE = 12; HEAP_SIGNATURE = 0xEC
PAGE_HEADER_FORMAT = "<H"; PAGE_HEADER_SIZE = 2; BITMAP_HEADER_FORMAT = "<H64s"; BITMAP_HEADER_SIZE = 66
FIRST_BITMAP_BLOCK = 8; BITMAP_PERIOD = 128          # HNBITMAPHDR at blocks 8, 136, 264, … (2.3.1.4)
PAGE_MAP_FORMAT = "<HH"; PAGE_MAP_SIZE = 4; MAX_HEAP_ITEM_INDEX = 2047

class HeapNodeType(IntEnum):        # bClientSig, [MS-PST] 2.3.1.2's nine values (upstream's HeapNodeType)
    RESERVED1=0x6C, TABLE=0x7C, RESERVED2=0x8C, RESERVED3=0x9C, RESERVED4=0xA5, RESERVED5=0xAC,
    TREE=0xB5, PROPERTIES=0xBC, RESERVED6=0xCC
    from_wire(value) → HeapNodeType                  # !PstFormatError for any other value (as upstream's TryFrom)

@dataclass(frozen=True, slots=True)
class HeapId:                        # HID 2.3.1.1 — an item in THIS heap
    raw: int;  SIZE = 4
    # !PstFormatError unless a u32 with zero type bits; HeapId(0) is the null HID
    from_parts(index: int, block_index: int = 0) → HeapId   # 1-based item index ≤ 2047, block ≤ 65535; 0 allowed (null)
    unpack_from(buf, offset=0) → HeapId; pack() → bytes
    is_null → bool; index → int (hidIndex, 1-based); block_index → int
    __str__ → "HeapId(NodeId { HeapNode: 0x5 })"        # upstream's Debug form, as the goldens print it

@dataclass(frozen=True, slots=True)
class HeapNodeId:                    # HNID 2.3.3.2 — the union; NOT a HeapId, NOT a NodeId
    raw: int;  SIZE = 4;  unpack_from; pack
    is_heap → bool                   # type bits == 0
    as_heap → HeapId | None          # the HID, or None
    as_node → NodeId | None          # the sub-node NID (ANY nonzero type, known or not — upstream's `_ =>` arm), or None
    __str__ → str(as_heap or NodeId)

@dataclass(frozen=True, slots=True)
class HeapNodeHeader:  page_map_offset: int; client_signature: HeapNodeType; user_root: HeapId; fill_levels: tuple[int, ...] (8 nibbles, low first)
    unpack_from(buf, offset=0)       # !PstFormatError bSig != 0xEC, unknown bClientSig, user root with type bits
@dataclass(frozen=True, slots=True)
class HeapPageMap:  offsets: tuple[int, ...] (rgibAlloc, cAlloc + 1); free_count: int; fill_levels: tuple[int, ...] | None (128 nibbles on a bitmap block)
    count → int (cAlloc); size(index) → int; sizes → tuple[int, ...]

class HeapNode:
    __init__(self, blocks: Sequence[bytes], *, subnodes: Mapping[NodeId, SubNodeLeafEntry] | None = None,
             reader: BlockReader | None = None, limits: Limits = DEFAULT_LIMITS)
        # `blocks` = the node's data blocks in order (BlockReader.read_data_blocks); block 0's HNHDR is read here.
        # !PstFormatError no blocks, bad HNHDR
    from_node(reader: BlockReader, entry: NodeBTreeEntry | SubNodeLeafEntry, limits=None) → HeapNode   # THE constructor:
        # read_data_blocks(entry.data) + read_subnode_tree(entry.sub_node); a SubNodeLeafEntry for an attachment's/embedded message's PC
    header → HeapNodeHeader; client_signature → HeapNodeType; user_root → HeapId; block_count → int; limits → Limits
    block(block_index) → bytes                       # !PstFormatError past the last block
    page_map(block_index) → HeapPageMap              # parsed on first use and kept (upstream re-parses per find_entry)
        # !PstFormatError header/page map outside the block, offsets decreasing or past the block, cFree != zero-length spans
        # !PstLimitError allocations so far > limits.max_heap_items
    get(self, hid: HeapId) → memoryview             # a VIEW into the block; !PstFormatError block index past the last,
                                                     # index 0 (null), index > cAlloc, zero-length (freed) item; TypeError for a non-HeapId
    get_hnid(self, hnid: HeapNodeId) → bytes        # heap item (copied), or the sub-node's whole data via reader.read_data;
                                                     # !PstNotFoundError sub-node absent (or no sub-node tree / no reader); TypeError for a non-HeapNodeId
    get_hnid_blocks(self, hnid: HeapNodeId) → list[bytes]   # the same bytes as the BLOCKS they are stored in (added by P06 for
                                                     # the row matrix, whose rows never straddle a block); a heap item is one block

# pypstreader.ltp.tree
BTH_HEADER_FORMAT = "<BBBBI"; BTH_HEADER_SIZE = 8; KEY_SIZES = (2, 4, 8, 16); MAX_ENTRY_SIZE = 32

@dataclass(frozen=True, slots=True)
class HeapTreeHeader:  key_size: int; entry_size: int; levels: int; root: HeapId (null = empty tree)
    unpack_from(buf, offset=0)       # !PstFormatError bType != 0xB5 (or unknown), cbKey ∉ KEY_SIZES, cbEnt ∉ 1..=32, root with type bits

class HeapTree:                      # BTH 2.3.2 over a HeapNode
    __init__(self, heap: HeapNode, root: HeapId | None = None)   # root = the BTHHEADER item; heap.user_root by default (a PC);
                                     # a TC passes TCINFO.hidRowIndex. Header read here; !PstLimitError levels > limits.max_heap_tree_depth
    heap → HeapNode; header → HeapTreeHeader; key_size, entry_size, levels → int; root → HeapId
    __iter__ → Iterator[tuple[bytes, bytes]]        # every leaf (key, value) — exactly key_size / entry_size bytes — in the
                                                     # tree's order, level by level as upstream's `entries`; an empty tree yields nothing
                                                     # !PstFormatError a page not a whole number of records, a record HID with type bits
                                                     # !PstLimitError a page visited twice (cycle), pages or records > limits.max_items
    entries() → list[tuple[bytes, bytes]]           # list(self)
    find(self, key: bytes) → bytes | None           # one descent; keys compared as little-endian unsigned ints of key_size bytes;
                                                     # !PstFormatError len(key) != key_size
```

What a PC record looks like to this layer, for P05: key = `<H` prop id, value
= `<H` wPropType + `<I` dwValueHnid; `HeapNodeId.unpack_from(value, 2)` then
`as_heap` / `as_node`; a fixed type ≤ 4 bytes is inline in those 4 bytes, an
HNID of 0 on any other type is upstream's `Null` (and `read_store_props`
prints `Type: Null` for it — `PropertyType::from(value)` names the value's
variant, not `wPropType`; the private stores have such a record). For P06:
the TC's user root is a TCINFO, `HeapTree(heap, HeapId(hidRowIndex))` is the
row index (key `<I` row id, value `<I` row index), `hnidRows` is a
`HeapNodeId` whose sub-node data is the row matrix.

Verified, exactly upstream's checks (module docstrings): `bSig`, `bClientSig`,
`hidUserRoot` type bits, page-map location, non-decreasing `rgibAlloc`,
`cFree` == zero-length spans, block/item index range; BTH `bType`, `cbKey`,
`cbEnt`, every page HID's type bits. Not verified, as upstream: `ibHnpm`
alignment (pstd-inline-cid has 121; read), item overlap, fill levels.
Divergences: an `rgibAlloc` offset past the block and a **zero-length item**
are refused (upstream slices/returns empty); a page **not a whole number of
records is `PstFormatError`** where upstream's `while let Ok` silently drops
the tail (P19's finding); levels, cycles and counts are bounded by `limits`.

`python -m pypstreader.debug heap <file> <nid-hex>` prints the HNHDR and every
block's page map as counts and item lengths; `bth <file> <nid-hex>` prints
the BTH at the user root and each leaf record as `key=<hex> value=<hex>`.
Neither has an upstream twin.

Changes from the draft, and why: `HeapNode` takes the node's **blocks**
(`Sequence[bytes]`), not one `bytes` — an HID's block index counts the data
tree's leaves, whose boundaries are their own `cb`; so `BlockReader` gained
`read_data_blocks(block) → list[bytes]` and `node_data_blocks(entry)`
(`read_data` is now their join — same bytes, same checks); `from_node` added
as the constructor every caller wants; `HeapNodeType`, `HeapNodeHeader`,
`HeapPageMap`, `HeapTreeHeader`, `block`/`page_map`/`block_count` and the
module constants added for the dumper and the tests; `HeapId` gained
`from_parts`/`is_null`/`unpack_from`/`pack`/`__str__`; `HeapNodeId` gained
`is_heap`; `HeapTree.root` defaults to the user root and `entries()` /
`header` were added; `key_size`/`value_size` became `key_size`/`entry_size`
(the spec's `cbEnt`). `tests/corrupt.py` gained the heap/BTH builders
(`hid`, `heap_header`, `page_header`, `bitmap_header`, `page_map`,
`heap_block`, `heap_node`, `bth_header`, `bth_leaf`, `bth_index`,
`bth_heap`, `pc_record`) and the `heap_lies` family (22 lies over the store
PC of a real store, resealed); the corruption harness now walks the store
PC's heap and BTH on every mutation.

## `pypstreader.ltp.prop_type` — P22 (leaf; land first)

**Built** (`src/pypstreader/ltp/prop_type.py`, 2026-09-15). Ported from `ltp/prop_type.rs`
and the value-decoder arms of `ltp/prop_context.rs`.

```python
class PropType(IntEnum):             # [MS-OXCDATA] 2.11.1
    UNSPECIFIED=0x0000, NULL=0x0001, SHORT=0x0002, LONG=0x0003, FLOAT=0x0004, DOUBLE=0x0005,
    CURRENCY=0x0006, APPTIME=0x0007, ERROR=0x000A, BOOLEAN=0x000B, OBJECT=0x000D, LONGLONG=0x0014,
    STRING8=0x001E, UNICODE=0x001F, SYSTIME=0x0040, GUID=0x0048, CLSID=GUID (alias), BINARY=0x0102,
    MV_SHORT=0x1002, MV_LONG=0x1003, MV_FLOAT=0x1004, MV_DOUBLE=0x1005, MV_CURRENCY=0x1006,
    MV_APPTIME=0x1007, MV_LONGLONG=0x1014, MV_STRING8=0x101E, MV_UNICODE=0x101F,
    MV_SYSTIME=0x1040, MV_GUID=0x1048, MV_BINARY=0x1102

    @classmethod
    def from_wire(cls, value: int) → PropType
    debug_name → str                     # upstream's Debug variant ("Integer32", "Time", …); UNSPECIFIED → PstUnsupportedError
    @classmethod
    def from_debug_name(cls, name: str) → PropType   # the inverse, for the golden parsers; unknown → PstFormatError
    # the way to construct from a wPropType field. Any code upstream's TryFrom<u16> rejects —
    # including UNSPECIFIED and the spec's ServerId/Restriction/RuleAction — is
    # PstUnsupportedError(f"property type 0x{v:04X}"); not a u16 at all → PstFormatError.
    # Do not rely on PropType(v): that raises ValueError.

def is_fixed_size(t: PropType) → bool  # NULL, SHORT, LONG, FLOAT, DOUBLE, CURRENCY, APPTIME, ERROR, BOOLEAN, LONGLONG, SYSTIME, GUID
def fixed_size(t: PropType) → int      # 0 (NULL) / 1 / 2 / 4 / 8 / 16; PstFormatError for a variable type. OBJECT is variable.

DEFAULT_MAX_ITEMS = MAX_MV_ITEMS               # from pypstreader.limits (P11); 1_000_000
def decode(t: PropType | int, data: bytes | memoryview, *, codepage: str = "cp1252",
           max_items: int = DEFAULT_MAX_ITEMS) → PropValue
# `data` is the WHOLE value (the inline bytes, or the complete heap/subnode allocation). An int `t` goes through from_wire.
# type PropValue = int | float | bool | bytes | str | datetime | uuid.UUID | ObjectRef | None | tuple[PropValue, ...]
# NULL → None (zero bytes). Fixed types must be EXACTLY their width (a 9-byte LONGLONG is PstFormatError).
# BOOLEAN: one byte, 0 or 1, else PstFormatError (the spec and upstream's table arm; upstream's PC arm is looser).
# CURRENCY → int in 1/10000 units, as upstream's i64. ERROR → signed i32, as upstream. APPTIME → float days.
# SYSTIME → aware UTC datetime (0 → 1601-01-01); negative or past 9999-12-31 → PstFormatError, never OverflowError.
# GUID → uuid.UUID (bytes_le: Data1/2/3 little-endian). OBJECT → ObjectRef.
# STRING8 → str via codecs, truncated at the first NUL; unknown codepage → PstUnsupportedError; undecodable → PstFormatError.
#   Upstream has no code page (bytes → U+00XX); pass codepage="latin-1" to reproduce its output exactly.
# UNICODE → str, UTF-16LE, truncated at the first aligned 0x0000; odd length or lone surrogate → PstFormatError.
# MV_SHORT/LONG/FLOAT/DOUBLE/CURRENCY/APPTIME/LONGLONG/SYSTIME: NO count field — a packed array whose count is
#   len(data) // width ([MS-PST] 2.3.3.4.1, as upstream reads them); a partial trailing element → PstFormatError.
# MV_STRING8/MV_UNICODE/MV_BINARY: u32 count, u32 offsets, items ([MS-PST] 2.3.3.4.2); first offset must follow the
#   table, offsets must be monotonic and in range → else PstFormatError; the last item runs to the end of data.
# MV_GUID: u32 count then 16-byte GUIDs — upstream's layout, which contradicts [MS-PST] 2.3.3.4.1; pinned by test.
# any multi-value count > max_items → PstLimitError (checked before allocation; distinct from PstFormatError).

@dataclass(frozen=True, slots=True)
class ObjectRef:  node: NodeId; size: int      # PT_OBJECT: the sub-node's NID (P05 wrapped it — see changelog) and byte size

def filetime_to_datetime(ft: int) → datetime   # 100 ns ticks since 1601-01-01 → aware UTC; sub-µs ticks dropped; out of range → PstFormatError
def datetime_to_filetime(dt: datetime) → int   # inverse; naive → TypeError, before 1601 → ValueError (caller errors, not file errors)
```

The goldens print upstream's variant names (`Integer32`, `Time`, ...); the
map from those to `PropType` is `UPSTREAM_VARIANT_TO_PROPTYPE` in
`tests/test_prop_type.py`, for the golden parsers to import.

## `pypstreader.ltp.prop_context` — P05

**Built** (`src/pypstreader/ltp/prop_context.py`, 2026-09-16). Ported from
`ltp/prop_context.rs` (the record types, `PropertyContextInner::properties`
and `read_property`; the value decoders are P22's).

```python
PC_KEY_FORMAT = "<H"; PC_KEY_SIZE = 2; PC_RECORD_FORMAT = "<HI"; PC_RECORD_SIZE = 6

@dataclass(frozen=True, slots=True)
class PropertyRecord:                # one PC BTH leaf: 2-byte prop id key, 6-byte value record
    prop_id: int; prop_type: PropType; raw: int   # raw = the 4-byte inline value OR an HNID
    SIZE = 8
    unpack(key: bytes, value: bytes) → PropertyRecord
        # !PstUnsupportedError naming BOTH the property and the wPropType; !PstFormatError short buffer
    is_inline → bool                 # upstream's `Small`: NULL and the ≤ 4-byte scalars
    hnid → HeapNodeId | None         # None for an inline record
    is_null → bool                   # a non-inline record whose HNID is 0 — upstream's PropertyValue::Null
    value_type → PropType            # prop_type, or NULL for a null HNID — the `Type:` the goldens print
    __str__ → "Small(0x0018B2B3)" | "HeapId(NodeId { HeapNode: 0x5 })" | "NodeId { … }"   # upstream's Debug

class PropertyContext:
    __init__(self, heap: HeapNode, limits: Limits | None = None, *, codepage: str = "cp1252")
        # !PstFormatError client sig != 0xBC, or a BTH whose cbKey/cbEnt are not 2 and 6
        # limits=None takes the heap's own. TypeError for a non-HeapNode.
    from_node(reader: BlockReader, entry: NodeBTreeEntry | SubNodeLeafEntry, limits=None, *, codepage="cp1252")
        # THE constructor: HeapNode.from_node + the checks above
    heap → HeapNode; tree → HeapTree; limits → Limits; codepage → str
    records → Mapping[int, PropertyRecord]   # read-only, ascending prop id, parsed once and kept
        # !PstLimitError count > limits.max_property_count; !PstFormatError a repeated prop id
    __len__; __contains__(prop_id)
    read(self, record: PropertyRecord) → PropValue      # upstream's read_property; TypeError for a non-record
    get(self, prop_id: int) → PropValue | None          # decodes on demand; None when ABSENT or when the HNID is 0
    __iter__ → Iterator[tuple[int, PropValue]]          # in prop-id order, as read_store_props prints
```

Values are decoded on demand and never cached; a caller that wants them all
iterates once. Fixed types of four bytes or fewer come from the 4-byte field,
masked to their width exactly as upstream masks (`& 0xFFFF`, `& 0xFF`);
everything else goes through `HeapNode.get_hnid` and `prop_type.decode`. A
sub-node an HNID names that the node's tree does not hold is
`PstNotFoundError` (upstream's `PropertySubNodeValueNotFound`).

Divergences from upstream, each in the module docstring with its reason: a
`PtypNull` record decodes to `None` (upstream's `small_value` has no Null
arm, so the whole store fails to open); `PtypObject` IS decoded (upstream's
`try_from` has no arm — P19's finding); an 8/16-byte scalar or Object whose
HNID carries type bits is `PstFormatError` (upstream reads the item at `raw
>> 5` anyway); a repeated property id is `PstFormatError` (upstream's
`BTreeMap` keeps the last); the BTH widths are checked before anything is
read; counts are bounded by `limits`. `PtypBoolean` is P22's strict form.

`python -m pypstreader.debug pc <file> <nid-hex>` prints the goldens' shape —
` Property ID: 0x%04X, Type: %s`, `  Record: %s`, `  Value: %s` — through
`debug.property_lines(prop_id, record, value)` and
`debug.format_property_value(prop_type, value)` (upstream's `Debug for
PropertyValue`, including Rust's float, string and `BinaryValue` spellings).
The dumper decodes String8 with `debug.DUMP_CODEPAGE` (`"latin-1"`), which
is upstream's code-page-less reading, so its output is byte-comparable with
`read_store_props`'s golden.

## `pypstreader.ltp.table_context` — landed (P06)

**Built** (`src/pypstreader/ltp/table_context.py`, 2026-09-16). Ported from
`ltp/table_context.rs` (the Unicode arm of `TableContextInfo`,
`TableColumnDescriptor`, `TableRowData` and `TableContextInner::read` /
`read_column`; the value decoders are P22's).

```python
LTP_ROW_ID_PROP_ID = 0x67F2; LTP_ROW_VERSION_PROP_ID = 0x67F3
TCINFO_FORMAT = "<BBHHHHIII"; TCINFO_SIZE = 22; TCOLDESC_FORMAT = "<HHHBB"; TCOLDESC_SIZE = 8
ROW_INDEX_KEY_SIZE = ROW_INDEX_ENTRY_SIZE = 4; ROW_HEADER_SIZE = 8; MAX_COLUMNS = 0xFF
TCI_4b, TCI_2b, TCI_1b, TCI_bm = 0, 1, 2, 3       # the rgib indices of [MS-PST] 2.3.4.1

def existence_bitmap_size(column_count: int) → int          # ceil(n / 8), upstream's
def check_existence_bitmap(column: int, bitmap: bytes | memoryview) → bool
    # MSB of a byte is column 0/8/16…; a bit past the bitmap is PstFormatError (upstream's InvalidTableContextColumnCount)

@dataclass(frozen=True, slots=True)
class ColumnDescriptor:              # TCOLDESC 2.3.4.2
    prop_type: PropType; prop_id: int; offset: int; size: int; existence_bit: int;  SIZE = 8
    unpack_from(buf, offset=0) → ColumnDescriptor    # !PstUnsupportedError naming the column and the wPropType

@dataclass(frozen=True, slots=True)
class TableContextInfo:              # TCINFO 2.3.4.1, validated exactly as upstream's `new` (plus one divergence)
    end_4byte: int; end_2byte: int; end_1byte: int; end_bitmap: int
    row_index: HeapId; rows: HeapNodeId | None; deprecated_index: int; columns: tuple[ColumnDescriptor, ...]
    unpack(data) → TableContextInfo  # !PstFormatError bType != 0x7C, rgib unaligned/not monotonic/inside the row
                                     # header/not leaving ceil(cCols/8) bitmap bytes, a column whose type is not a
                                     # column type (PtypNull), whose cell is outside its region, whose cbData is not
                                     # its type's width, whose existence bit is past the schema, or a reserved
                                     # column (0x67F2/0x67F3) away from offset 0/4
    row_width → int (rgib[TCI_bm]); bitmap_size → int

class CellKind(Enum):  SMALL, HEAP, NODE            # upstream's TableRowColumnValue variants
@dataclass(frozen=True, slots=True)
class CellRecord:  kind: CellKind; raw: int = 0; data: bytes = b""
    hnid → HeapNodeId | None; heap → HeapId | None; node → NodeId | None; is_null → bool (HNID 0)

@dataclass(frozen=True, slots=True)
class TableRow:
    id: int; unique: int
    cells: Mapping[int, PropValue]   # prop_id → value; a column whose existence bit is clear is ABSENT, not None
    records: tuple[CellRecord | None, ...]   # parallel to `columns`; None = absent (upstream's Vec<Option<…>>)
    get(prop_id, default=None); __contains__; __len__

class TableContext:
    __init__(self, heap: HeapNode, limits: Limits | None = None, *, codepage: str = "cp1252")   # client sig 0x7C
    from_node(reader, entry: NodeBTreeEntry | SubNodeLeafEntry, limits=None, *, codepage="cp1252") → TableContext
    heap → HeapNode; info → TableContextInfo; tree → HeapTree (the row index BTH); limits; codepage
    columns → tuple[ColumnDescriptor, ...]           # rgTCOLDESC order — the order the examples print
    row_index → Mapping[int, int]                    # row id → ordinal; !PstFormatError a repeated id
    row_count → int; __len__                         # sum of the PER-BLOCK floors; > limits.max_items → PstLimitError
    rows() → Iterator[TableRow]; __iter__            # MATRIX order (upstream's rows_matrix), not row-id order
    row(index: int) → TableRow                       # !PstFormatError past the last row
    find_row(self, row_id: int) → TableRow           # !PstNotFoundError (a PstFormatError) when the id is not indexed
    read_cell(self, record: CellRecord, prop_type: PropType) → PropValue    # upstream's read_column
```

The row matrix is `hnidRows`: a heap item, or a sub-node whose data BLOCKS
hold it — rows are packed per block and never straddle one ([MS-PST]
2.3.4.4), so `HeapNode.get_hnid_blocks(hnid) → list[bytes]` was added to
P04 (additive; `get_hnid` is still the joined form) and the row count is
the sum of the per-block floors. A partial row at the end of a block is
padding and is dropped, as upstream floors.

Divergences from upstream, each in the module docstring with its reason:
`rgib[TCI_4b]` must be ≥ 8 once the row matrix is non-empty (upstream
underflows `end_4byte - 8` as a `usize`, but only when it reads a row —
P06b narrowed the check from TCINFO parse time to `TableContext`'s first
matrix read, so a TCINFO that pairs `end_4byte < 8` with zero rows, as
`synth-basics.pst`'s associated-contents table does, is accepted); a cell
HNID of 0 is `None` rather than upstream's refusal of heap index 0;
`PtypObject` columns are readable (P22/P05 decode the type); a repeated row
id is refused; a row index entry past the matrix is `PstFormatError` where
upstream panics; rows and the matrix's size are bounded by `limits`.

`python -m pypstreader.debug tc <file> <nid-hex>` prints `read_root_folder` /
`read_ipm_subtree`'s shape through `debug.cell_lines(column, record, value)`
and `debug.format_cell_record(prop_type, record, value)` (upstream's `Debug`
for `TableRowColumnValue`: `Small(<the value>)`, `Heap(<HeapId>)`,
`Node(<NodeId>)`), reusing P05's `format_property_value` and
`DUMP_CODEPAGE`. `Type:` is the COLUMN's declared type, where
`read_store_props` prints the VALUE's variant.

`tests/corrupt.py` gained the TC builders (`tcinfo`, `tcoldesc`, `tcrowid`,
`tc_row`, `node_data_block`) and the `tc_lies` family (25 lies over the root
folder's hierarchy table, resealed); the corruption harness walks that table
on every mutation (`tc.root_hierarchy`).

## `pypstreader.messaging` — P07, P08, P09 (landed)

**`pypstreader.messaging.store` and `pypstreader.messaging.named_prop` are built**
(2026-09-16). Ported from `messaging/store.rs` and `messaging/named_prop.rs`
(the read halves; the ANSI arms are not ported — ADR-0003).

```python
# pypstreader.messaging.store
ENTRY_ID_FORMAT = "<I16sI"; ENTRY_ID_SIZE = 24; RECORD_KEY_SIZE = 16
PID_TAG_RECORD_KEY = 0x0FF9; PID_TAG_DISPLAY_NAME = 0x3001
PID_TAG_IPM_SUB_TREE_ENTRY_ID = 0x35E0; PID_TAG_IPM_WASTEBASKET_ENTRY_ID = 0x35E3
PID_TAG_FINDER_ENTRY_ID = 0x35E7

@dataclass(frozen=True, slots=True)
class EntryId:  record_key: bytes (16); node: NodeId;  SIZE = 24    # [MS-PST] 2.4.3.2
    unpack_from(buf, offset=0) → EntryId   # !PstFormatError short buffer, negative offset, rgbFlags != 0
    pack() → bytes                          # the inverse, for round-trip tests
    __str__ → "EntryId { record_key: AA-BB-…, node_id: NodeId { NormalFolder: 0x401 } }"

class Store:                          # P07 — the object `open()` returns
    __init__(self, f: BinaryIO, *, path=None, limits=DEFAULT_LIMITS, codepage="cp1252", owns_file=False)
        # reads the header, both B-trees, a BlockReader and the store PC's records — upstream's `StoreInner::read`
    @classmethod open(cls, path: str | os.PathLike[str], *, limits=DEFAULT_LIMITS, codepage="cp1252") → Store
        # context manager, owns the file. OSError from opening the PATH is NOT wrapped (see below).
    close()                           # idempotent; a borrowed file object is left alone
    path → Path | None; limits → Limits; codepage → str
    header → Header; reader → BlockReader; nbt → NodeBTree; bbt → BlockBTree
    properties → PropertyContext      # NID_MESSAGE_STORE's PC
    record_key → bytes (16); display_name → str
    ipm_subtree → EntryId             # required; !PstFormatError when absent
    wastebasket → EntryId | None; finder → EntryId | None   # P07 tolerates absence (below)
    entry_id(self, node: NodeId) → EntryId          # upstream's `make_entry_id`
    matches_record_key(self, entry: EntryId) → bool # upstream's; P08's `EntryIdWrongStore`
    get(self, prop_id: int) → PropValue | None      # one store property, decoded
    named_properties → NamedPropertyMap             # read on first use and kept
    root_folder → Folder; open_folder(entry) → Folder; open_message(entry, *, parent=None) → Message  # P08/P09

def open_store(path, *, limits=DEFAULT_LIMITS, codepage="cp1252") → Store   # exported as `pypstreader.open`

# pypstreader.messaging.named_prop
PS_MAPI = UUID("00020328-…"); PS_PUBLIC_STRINGS = UUID("00020329-…")     # [MS-OXPROPS] 1.3.2
NAME_ID_FORMAT = "<IHH"; NAME_ID_SIZE = 8; GUID_SIZE = 16
PID_TAG_NAMEID_BUCKET_COUNT = 0x0001; …_STREAM_GUID = 0x0002; …_STREAM_ENTRY = 0x0003
PID_TAG_NAMEID_STREAM_STRING = 0x0004; PID_TAG_NAMEID_BUCKET_BASE = 0x1000

@dataclass(frozen=True, slots=True)
class NamedPropertyGuid:  raw: int      # wGuid >> 1; 0 none, 1 Mapi, 2 PublicStrings, 3+ the stream
    from_wire(value) → NamedPropertyGuid    # !PstFormatError at 0x8000 and above (upstream's try_from)
    is_index → bool; index → int | None; well_known → uuid.UUID | None
    __str__ → "None" | "Mapi" | "PublicStrings" | "GuidIndex(n)"   # upstream's Debug, as the goldens print it

@dataclass(frozen=True, slots=True)
class NameIdEntry:  name_id: int; guid: NamedPropertyGuid; prop_index: int; is_string: bool;  SIZE = 8
    unpack_from(buf, offset=0)   # !PstFormatError short buffer, wPropIdx >= 0x8000
    prop_id → int (0x8000 + prop_index); hash_value → int   # upstream's hash_value

@dataclass(frozen=True, slots=True)
class NamedProperty:  guid: uuid.UUID; name: str | int;  is_string → bool

class NamedPropertyMap:               # P07 — NID_NAME_TO_ID_MAP
    __init__(self, properties: PropertyContext, limits: Limits | None = None)   # TypeError for a non-PC
    from_node(reader: BlockReader, entry: NodeBTreeEntry | SubNodeLeafEntry, limits=None, *, codepage="cp1252")
    properties → PropertyContext; limits → Limits; __len__
    bucket_count → int                # !PstFormatError absent, not Integer32, > 0xEFFF, 0 with entries,
                                      #   or smaller than the hash buckets the map holds
    guids → tuple[uuid.UUID, ...]     # !PstFormatError absent, not Binary, not a multiple of 16
    entries → tuple[NameIdEntry, ...] # !PstFormatError absent, not Binary, not a multiple of 8
    string_bytes(self, offset: int) → bytes      # the raw UTF-16LE name; !PstFormatError odd length, past the stream
    lookup_string(self, offset: int) → str       # the same, decoded lossily (upstream's from_utf16_lossy)
    guid_of(self, entry) → uuid.UUID  # !PstFormatError a wGuid index past the stream; UUID(int=0) for "none"
    name_of(self, entry) → str | int
    lookup(self, prop_id: int) → NamedProperty | None   # !PstFormatError a repeated prop id
    resolve(self, guid: uuid.UUID, name: str | int) → int | None   # the reverse; first entry wins
    hash_entry(self, entry) → NameIdEntry        # upstream's, with wGuid KEPT (divergence, below)
    hash_bucket(self, entry) → tuple[NameIdEntry, ...]   # !PstNotFoundError a bucket the map does not hold
```

Divergences, each a paragraph in its module's docstring: a **missing
`PidTagIpmWastebasketEntryId` or `PidTagFinderEntryId` is `None` and the
store still opens** (upstream's accessors fail — which is why
`read_store_props` exits 1 on `pstd-inline-cid.pst` — but upstream's
`open_store` succeeds on the same file, and `read_named_props` exits 0 on
it); an EntryID property must be **exactly** 24 bytes; store property values
are decoded on demand; `Store.open` lets `OSError` through, because opening
the path is the OS's business (everything about the *bytes* is a
`PstError`); a GUID or entry stream that is not a whole number of records is
refused where upstream's `while let Ok` drops the tail; a duplicate
`wPropIdx` is refused; a `PidTagNameidBucketCount` of 0 with entries, or one
smaller than the buckets present, is refused; `stream_string()` is not
ported (its walk skips every other entry); and **`hash_entry` keeps the
entry's `wGuid` where upstream clears it** — with `wGuid` cleared, every
string-named property lands in a bucket that does not hold it (9/35 on
`Empty.pst`, 34/56 on `tika-variousBodyTypes`); with it kept, all 964
entries of all 8 Unicode stores land in the right one.

`python -m pypstreader.debug store <file>` prints `read_store_props`'s output —
the four header lines and then the store PC without its `Record:` lines —
and refuses an absent wastebasket or finder exactly where the example does,
so its stdout AND its exit status match the golden on `pstd-inline-cid`
too. `python -m pypstreader.debug named_props <file>` prints `read_named_props`'s.

**`pypstreader.messaging.folder` is built** (2026-09-16). Ported from
`messaging/folder.rs` (`FolderProperties` and the read half of
`FolderInner`/`UnicodeFolder`; the write half and the ANSI arm are not
ported — ADR-0003). `Store` gained the two accessors its comment promised.

```python
# pypstreader.messaging.folder
PID_TAG_DISPLAY_NAME = 0x3001; PID_TAG_CONTENT_COUNT = 0x3602
PID_TAG_CONTENT_UNREAD_COUNT = 0x3603; PID_TAG_SUBFOLDERS = 0x360A
FOLDER_NODE_TYPES = (NodeIdType.NORMAL_FOLDER, NodeIdType.SEARCH_FOLDER)

class Folder:                         # P08 — one folder: its PC, and the three tables at its NID's index
    __init__(self, store: Store, node: NodeId)        # !TypeError non-Store/non-NodeId; !PstFormatError a NID
                                                      #   whose type is not a folder's; !PstNotFoundError absent
    @classmethod open(cls, store: Store, entry: EntryId | NodeId) → Folder   # !PstFormatError EntryID in wrong store
    store → Store; node → NodeId; properties → PropertyContext   # the FILE's PC — nothing injected (below)
    entry_id → EntryId                # upstream's injected PidTagEntryId (0x0FFF)
    folder_type → int                 # upstream's injected PidTagFolderType (0x3601): 0 root, 2 search, 1 other
    get(self, prop_id: int) → PropValue | None
    display_name → str                # !PstFormatError absent, or not a string (PtypNull included — see below)
    content_count → int; unread_count → int          # !PstFormatError absent or not Integer32
    has_subfolders → bool                            # !PstFormatError absent or not Boolean
    table(self, node_type: NodeIdType) → TableContext | None    # upstream's read_table; None ONLY when the NBT
                                                                #   has no such node (divergence, below)
    hierarchy_table / contents_table / associated_table → TableContext | None   # 0x0D / 0x0E / 0x0F, read once, kept
    subfolder_ids() → tuple[NodeId, ...]             # matrix order; () when there is no hierarchy table
    message_ids() → tuple[NodeId, ...]; associated_ids() → tuple[NodeId, ...]
    contents() → tuple[EntryId, ...]                 # message_ids() as this store's EntryIDs — Store.open_message input
    messages() → Iterator[Message]; associated() → Iterator[Message]    # added by P09, below
    subfolders() → Iterator[Folder]                  # each child opened, matrix order
    walk(self, *, max_depth: int | None = None) → Iterator[Folder]
        # pre-order, self first, children in matrix order — the oracle's dump_folder order. Iterative (no Python
        # recursion). max_depth defaults to limits.max_folder_depth (P08 added it). !PstLimitError depth past the
        # ceiling, a folder reached twice (a cycle), or more than limits.max_folders children in one table.
    __str__ → "Folder { NodeId { NormalFolder: 0x401 } }"

# pypstreader.messaging.store, added by P08
class Store:
    root_folder → Folder                              # NID_ROOT_FOLDER (0x122), NOT ipm_subtree
    open_folder(self, entry: EntryId | NodeId) → Folder
```

Divergences, each a paragraph in `folder.py`'s docstring: **a table node
that exists but will not parse is a refusal, not `None`** (upstream's
`read_table(..).ok()?` turns every error into "absent", which is how its
`dump_messages` prints `Hierarchy Table: None` for `pstd-inline-cid.pst` —
a caller cannot tell "no sub-folders" from "sub-folder list unreadable", and
the two lead to opposite actions); **the two properties upstream injects
into its property map (`PidTagEntryId`, `PidTagFolderType`) are attributes
here**, so `properties` is what the file holds; **`walk()` is iterative,
depth-bounded and cycle-guarded**, where upstream has no walk at all.

**The display-name decision: refuse, as upstream does.** Six of the eight
Unicode corpus stores have a root folder whose `PidTagDisplayName` record
has a zero HNID, and the oracle prints `Name: Error: …
InvalidFolderDisplayName(Null)` there. `display_name` raises
`PstFormatError` at the same point rather than returning `None`:
[MS-PST] 2.4.4.1 makes the property required, and a caller handed `None`
writes it into a path or a report as the empty string. The lenient reading
is still one call away (`folder.properties.get(0x3001)`).

`python -m pypstreader.debug folders <file>` prints exactly the folder blocks of
`dump_messages.txt` — a pre-order walk from `NID_ROOT_FOLDER`, no `Message:`
blocks, no `Errors:` trailer — through `debug.folder_lines(folder)`,
`debug.folder_accessor(folder, prop_id, render)` (the example's
`result_debug`: the accessor's value, or upstream's `Error: Custom { kind:
InvalidData, error: … }` text in its place) and `debug.folder_table(folder,
node_type)` (the example's `.ok()?`, so a corrupt table prints as absent
there and only there). `tests.golden_parsers.dump_messages_folder_lines(text)`
filters a golden down to exactly that, and `parse_dump_messages(text)` reads
the whole example into values (folder blocks in full; message blocks through
P09's `parse_message_block`, with their raw `lines` kept beside them).

`tests/corrupt.py` gained the `folder_lies` family (12 on both bases: the
root folder's four required properties absent and retyped, and the root
hierarchy table's first row id pointed at a node that is not there, at the
folder itself, at the message store and at an unassigned NID type); the
corruption harness gained `folder.walk` and `folder.tables`.

**`pypstreader.messaging.message` and `pypstreader.messaging.attachment` are built**
(2026-09-16). Ported from `messaging/message.rs` and `messaging/attachment.rs`
(the read halves; the write halves and the ANSI arms are not ported —
ADR-0003). `Store` gained `open_message` and `Folder` gained `messages()` /
`associated()`.

```python
# pypstreader.messaging.message
PID_TAG_MESSAGE_CLASS = 0x001A; PID_TAG_SUBJECT = 0x0037; PID_TAG_CLIENT_SUBMIT_TIME = 0x0039
PID_TAG_TRANSPORT_MESSAGE_HEADERS = 0x007D; PID_TAG_RECIPIENT_TYPE = 0x0C15; PID_TAG_SENDER_NAME = 0x0C1A
PID_TAG_SENDER_EMAIL_ADDRESS = 0x0C1F; PID_TAG_MESSAGE_DELIVERY_TIME = 0x0E06; PID_TAG_MESSAGE_FLAGS = 0x0E07
PID_TAG_MESSAGE_SIZE = 0x0E08; PID_TAG_MESSAGE_STATUS = 0x0E17; PID_TAG_NORMALIZED_SUBJECT = 0x0E1D
PID_TAG_BODY = 0x1000; PID_TAG_RTF_COMPRESSED = 0x1009; PID_TAG_HTML = 0x1013
PID_TAG_DISPLAY_NAME = 0x3001; PID_TAG_EMAIL_ADDRESS = 0x3003; PID_TAG_CREATION_TIME = 0x3007
PID_TAG_LAST_MODIFICATION_TIME = 0x3008; PID_TAG_SEARCH_KEY = 0x300B; PID_TAG_SMTP_ADDRESS = 0x39FE
PID_TAG_SENDER_SMTP_ADDRESS = 0x5D01
MESSAGE_NODE_TYPES = (NORMAL_MESSAGE, ASSOC_MESSAGE, ATTACHMENT)   # upstream accepts all three
SUBJECT_PREFIX_MARKER = "\x01"

class RecipientType(IntEnum):  ORIGINATOR=0, TO=1, CC=2, BCC=3     # [MS-OXCMSG] 2.2.3.1

def split_subject(raw: str) → tuple[str, str]      # (prefix, normalized), [MS-OXCMSG] 2.2.1.46
    # !PstFormatError a lone U+0001, a length byte of 0, or a prefix longer than the subject

@dataclass(frozen=True, slots=True)
class Recipient:  type: RecipientType | int; name: str | None; email: str | None; smtp: str | None
                  properties: Mapping[int, PropValue]              # the WHOLE row, by property id
    get(prop_id) → PropValue | None; __str__

class Message:                        # P09 — one message: its PC, its recipient table, its attachments
    __init__(self, store: Store, node: NodeId, *, entry: SubNodeLeafEntry | None = None,
             parent: Folder | None = None, depth: int = 0)
        # !TypeError non-Store/non-NodeId; !PstFormatError a NID whose type is not a message's, or a
        #   message node with NO SUB-NODE TREE (upstream's MessageSubNodeTreeNotFound); !PstNotFoundError absent
        # `entry`/`depth` are how an EMBEDDED message is built (its node is not in the store's NBT)
    @classmethod open(cls, store, entry: EntryId | NodeId, *, parent=None) → Message  # !PstFormatError wrong store
    store; node; parent → Folder | None; depth → int; entry_id → EntryId
    properties → PropertyContext      # the FILE's PC — nothing injected
    sub_nodes → Mapping[NodeId, SubNodeLeafEntry]
    get(prop_id) → PropValue | None
    message_class → str               # !PstFormatError absent or not a string
    subject → str | None              # the control prefix REMOVED, the prefix TEXT kept ("FW: original email")
    subject_raw → str | None          # exactly as stored ("\x01\x05FW: original email") — what the oracle prints
    subject_prefix → str | None       # "FW: ", or ""
    normalized_subject → str | None   # 0x0E1D when the store holds it, else the subject without its prefix
    sender_name / sender_email / sender_smtp / transport_headers / body_text → str | None
    delivery_time / client_submit_time / creation_time / last_modification_time → datetime | None
    delivery_filetime / client_submit_filetime → int | None    # the raw FILETIME ticks the goldens print
    message_flags / message_size / message_status → int; search_key → bytes   # upstream's other accessors
    body_html → bytes | None          # PtypBinary verbatim; a string value is UTF-8 encoded
    body_rtf → bytes | None           # PidTagRtfCompressed AS STORED (LZFu), not RTF yet
    body_rtf_decompressed() → bytes | None    # pypstreader.rtf over it, trimmed at the first NUL (as upstream)
    sub_node_table(node_type) → TableContext | None    # upstream's scan by NID TYPE; two of a type is a refusal
    recipient_table / attachment_table → TableContext | None      # None ONLY when there is no such sub-node
    recipients() → Iterator[Recipient]        # matrix order; !PstLimitError past limits.max_recipients
    attachment_ids() → tuple[NodeId, ...]     # the attachment table's row ids; !PstLimitError max_attachments
    attachments() → Iterator[Attachment]
    sub_node_entry(node) → SubNodeLeafEntry   # !PstNotFoundError (upstream's AttachmentSubNodeNotFound)
    check_embedded_depth() → None             # !PstLimitError past limits.max_embedded_message_depth
    __str__ → "Message { NodeId { NormalMessage: 0x10001 } }"

# pypstreader.messaging.attachment
PID_TAG_ATTACH_SIZE = 0x0E20; PID_TAG_ATTACH_DATA_BINARY = 0x3701; PID_TAG_ATTACH_FILENAME = 0x3704
PID_TAG_ATTACH_METHOD = 0x3705; PID_TAG_ATTACH_LONG_FILENAME = 0x3707; PID_TAG_RENDERING_POSITION = 0x370B
PID_TAG_ATTACH_MIME_TAG = 0x370E; PID_TAG_ATTACH_LONG_PATHNAME = 0x3710; PID_TAG_ATTACH_CONTENT_ID = 0x3712

class AttachMethod(IntEnum):          # [MS-OXCMSG] 2.2.2.9
    NONE=0, BY_VALUE=1, BY_REFERENCE=2, BY_REF_RESOLVE=3, BY_REF_ONLY=4, EMBEDDED_MESSAGE=5, OLE=6, BY_WEB_REFERENCE=7
    @classmethod from_wire(value: int) → AttachMethod    # !PstUnsupportedError naming any other value
    carries_bytes → bool                                  # BY_VALUE and OLE

class Attachment:                     # P09 — one sub-node of a message, with a PC of its own
    __init__(self, message: Message, node: NodeId)
        # !TypeError non-Message/non-NodeId; !PstFormatError a NID that is not an Attachment's;
        # !PstNotFoundError the message's sub-node tree does not hold it
    message → Message; node → NodeId; properties → PropertyContext; get(prop_id)
    sub_nodes → Mapping[NodeId, SubNodeLeafEntry]   # the ATTACHMENT's own tree (divergence, below)
    sub_node_entry(node) → SubNodeLeafEntry         # !PstNotFoundError
    method → AttachMethod; method_value → int       # the raw i32, as upstream's accessor
    size → int; rendering_position → int            # !PstFormatError absent or not Integer32
    filename / long_filename / pathname / mime_tag / content_id → str | None
    data() → bytes | None             # BY_VALUE and OLE; None for every other method.
                                      # !PstLimitError > limits.max_allocation (from BlockReader.read_data,
                                      #   which checks lcbTotal BEFORE any child read — no second check here)
    embedded_message() → Message | None   # EMBEDDED_MESSAGE; !PstLimitError past limits.max_embedded_message_depth
    __str__ → "Attachment { NodeId { Attachment: 0x401 } }"

# pypstreader.messaging.store / folder, added by P09
class Store:
    def open_message(self, entry: EntryId | NodeId, *, parent: Folder | None = None) → Message
class Folder:
    def messages(self) → Iterator[Message]; def associated(self) → Iterator[Message]
```

**The subject decision: `subject` is the readable form, `subject_raw` is the
file's.** `PidTagSubject` may begin with `U+0001` and a length byte
([MS-OXCMSG] 2.2.1.46); every Outlook-written corpus message carries it.
`subject` strips the two control characters and keeps the prefix text
(`"FW: original email"`), because that is what a caller writes into a
filename, a report or an `.eml`; `subject_raw` is the value verbatim, which
is what the oracle prints and what the differential compares;
`subject_prefix` and `normalized_subject` are the two halves. A prefix
length past the end of the string is `PstFormatError`, never a slice.

**The divergence that matters: this port opens embedded messages, and
upstream at pin cfb721da cannot.** `PropertyType::try_from` has no
`PtypObject` arm and upstream's BTH walk stops at the first record it cannot
decode, so an embedded-message attachment's property context is truncated
before `PidTagAttachMethod` and upstream refuses it with
`AttachmentMethodNotFound` — which the goldens carry, on
`pstsdk-submessage.pst` and twice on `javalibpst-dist-list.pst`. Arbitrated
by [MS-PST] 2.3.3.4 + 2.4.6.3 and by the bytes (the message that comes out
has a sensible class, subject, body and recipient, asserted in
`tests/test_message.py`). **A second upstream bug found the same way:**
`AttachmentInner::read` resolves the embedded message's NID in the owning
MESSAGE's sub-node tree, and the node is in the ATTACHMENT's own tree — so
`Attachment.sub_nodes` is the attachment's. `pypstreader.debug`'s `messages`
dumper re-creates upstream's truncation (`upstream_records`) so the golden
still matches byte for byte, and `test_the_golden_still_shows_upstreams_refusal`
fails if a moved pin fixes upstream.

Other divergences, each a paragraph in its module docstring: properties are
decoded on demand and the two tables are read on first use (upstream reads
everything at open, so one bad property fails the whole message — and
"absent", "empty" and "unreadable" stay three answers here); a table node
that exists but will not parse is a refusal, not `None` (as `folder.py`);
`recipients()` and `attachment_ids()` are bounded by `limits` (and
`data()` deliberately is NOT — the layer that assembles the bytes refuses
first, and a second ceiling here would be code no test could reach); the
embedded recursion is bounded by `limits.max_embedded_message_depth`, which
is what stops a message that embeds itself; `Message.parent` remembers the folder;
an unknown **recipient** type stays an `int` ([MS-OXCMSG] 2.2.3.1 reserves
flag bits and nothing is parsed from it) while an unknown **attachment
method** is `PstUnsupportedError`; `AttachMethod` names 3
(`afByReferenceResolve`), which the specification defines and upstream's
`TryFrom<i32>` rejects.

`python -m pypstreader.debug messages <file>` prints the whole of
`oracle/examples/dump_messages.rs` — the folder blocks `debug folders`
prints, plus every message block, its recipient and attachment rows, each
attachment's own property context, and the `Errors: <n>` trailer — and exits
1 when the trailer is not 0, as the example does. `tests/golden_parsers`
gained `parse_message_block` and `dump_messages_value`, and
`parse_dump_messages` now reads each message block into values (keeping its
raw `lines` beside them). `tests/corrupt.py` gained `message_lies` and
`attachment_lies` (and `retype_nbt_entry` / `subnode_data_block`); the
corruption harness gained `message.open` and `message.attachments`;
`tests/contract.py` gained `"Message"`/`"Attachment"` in `READER_TYPES`, a
`messages`/`message_nids`/`attachments`/`subjects` section on its fixture
object and 24 adapters.

## `pypstreader.rtf` — P21 (landed)

```python
class CompressionType(IntEnum):   COMPRESSED = 0x75465A4C ("LZFu"); UNCOMPRESSED = 0x414C454D ("MELA")

@dataclass(frozen=True, slots=True)
class CompressedRtfHeader:  comp_size: int; raw_size: int; comp_type: CompressionType; crc: int

def read_header(data: bytes) → CompressedRtfHeader
    # the 16-byte header, validated against the buffer: < 16 bytes, COMPSIZE + 4 != len(data),
    # or a COMPTYPE that is neither magic → PstFormatError
def decompress_rtf(data: bytes, *, max_output: int = 256 * 2**20) → bytes
    # [MS-OXRTFCP] 2.2. Returns the algorithm's output verbatim — NO NUL trimming (upstream cuts its
    # String at the first NUL; Outlook writes one NUL for an empty body). The messaging layer applies
    # `split(b"\0", 1)[0]` if it wants upstream's text, so its golden diffs match.
    # !PstFormatError: header as above; CRC mismatch (COMPRESSED only — 2.2.3.1 forbids checking it
    #   for MELA); payload ending before the terminator token, or inside a token; a reference into
    #   the unwritten part of the dictionary; MELA RAWSIZE past the buffer
    # !PstLimitError: RAWSIZE > max_output, and also the bytes actually produced > max_output
HEADER_SIZE = 16; DICTIONARY_SIZE = 4096
# tests/rtf_compress.py (tests only, not part of the package):
#   compress_rtf(raw: bytes, *, exhaustive: bool = False) → bytes   — upstream's compressor, byte-exact
#   encode_rtf_uncompressed(raw: bytes) → bytes                       — the MELA wrapper
```

Once `limits.py` lands (P11), `max_output` should default to `limits.MAX_ALLOCATION`;
the literal is the same value.

## `pypstreader.eml` — P10 (landed; not a port)

```python
POLICY = email.policy.SMTP.clone(cte_type="7bit")   # CRLF, RFC 2047 headers, 7-bit-clean output
SYNTHESIZED_HEADER = "X-Pypstreader-Synthesized"; BODY_HEADER = "X-Pypstreader-Body"
SKIPPED_HEADER = "X-Pypstreader-Attachment-Skipped"; SYNTHETIC_ID_DOMAIN = "pypstreader.invalid"
PID_TAG_INTERNET_MESSAGE_ID = 0x1035; PID_TAG_INTERNET_CODEPAGE = 0x3FDE

def to_eml(message: Message, *, synthesize_missing: bool = True, limits: Limits | None = None)
        → email.message.EmailMessage
    # !TypeError a non-Message / a non-Limits; !PstLimitError an attachment over limits.max_allocation,
    #   or embedding deeper than limits.max_embedded_message_depth COUNTED FROM `message.depth`;
    #   !PstFormatError for any property this layer cannot use — and for `email`'s own ValueError,
    #   which is a refusal about file content (module docstring)
def eml_bytes(message, *, synthesize_missing=True, limits=None) → bytes   # deterministic, pure ASCII, CRLF
def write_eml(message, path, *, synthesize_missing=True, limits=None) → Path     # binary write
def eml_name(message) → str                        # "<nid>.eml", 8 hex digits — never the subject
def folder_paths(folder, *, recurse=True, strict=False) → Iterator[(Folder, str)]
    # pre-order, `Folder.walk`'s ceiling and cycle guard, carrying the display path for an index;
    # strict=False treats a folder whose HIERARCHY table refuses as a leaf
def readable_messages(folder, *, strict=False) → Iterator[Message]
    # a CONTENTS table that will not parse refuses whatever `strict` says (it is a folder-level
    # answer); a single message that will not open is skipped unless strict
def export_folder(folder, dest_dir, *, recurse=True, strict=False, limits=None) → int   # count written
```

**The header policy, and the measurement it rests on** (P09 counted: 6 of the
12 openable corpus messages carry `PidTagTransportMessageHeaders`, 1 of 1
openable private message, and the split follows the message class):

1. `transport_headers` present → parsed with `email.parser` and **passed
   through** in source order, minus the headers that describe the ORIGINAL
   MIME body (`Content-*`, `MIME-Version`), which would mislabel the body
   this module re-assembles.
2. What is then missing is synthesised from MAPI: `From` (name + SMTP,
   falling back to the X.500 address in angle brackets), `To`/`Cc`/`Bcc` by
   `RecipientType`, `Subject`, `Date` (`client_submit_time` else
   `delivery_time`, RFC 5322, UTC), `Message-ID`.
3. **Every header added is named in `X-Pypstreader-Synthesized`** (absent when
   nothing was). A `Message-ID` comes from `PidTagInternetMessageId` when the
   store kept one — a real id under an added header — else it is invented
   deterministically from the store record key and the node id under
   `@pypstreader.invalid`, so an invented id is recognisable by inspection as well
   as by the marker. `synthesize_missing=False` writes only what the file
   holds.

**Bodies**: `multipart/alternative` in increasing fidelity — `text/plain`,
`application/rtf` (`body_rtf_decompressed()`), `text/html` — a single
representation as a single part. RTF alone is `application/rtf` plus
`X-Pypstreader-Body: rtf-only` and **no invented text body**; no body at all is an
empty `text/plain` plus `X-Pypstreader-Body: none`. HTML is decoded with
`PidTagInternetCodepage`, else the store's code page, else UTF-8, always
`errors="replace"`, and re-encoded as UTF-8 (a part's charset must match its
bytes, and re-encoding to the original can fail where decoding replaced).

**Attachments**: `BY_VALUE`/`OLE` → a part, `Content-Type` from a VALIDATED
`mime_tag` (two RFC 2045 tokens, parameters dropped) else
`application/octet-stream`, filename `long_filename` else `filename`,
`Content-ID` from `content_id`, `Content-Disposition: inline` inside a
`multipart/related` under the HTML part when the HTML has a matching `cid:`
URL, else `attachment`. `EMBEDDED_MESSAGE` → a `message/rfc822` part holding
the recursion (whose synthetic ids are prefixed with the carrier's, since
sub-node ids are unique only inside their tree). Every other method → an
`X-Pypstreader-Attachment-Skipped: <METHOD> <filename>` header, never an exception.

**Divergences from the rest of the package, all deliberate and all in the
module docstring**: every value that reaches a header is stripped of control
characters first (this is the layer where attacker-controlled text becomes
header text); `ValueError`/`LookupError` from the `email` package is re-raised
as `PstFormatError`; MIME boundaries are deterministic
(`----=_pypstreader.<nid>.<n>`) because `email` draws them from `random`; and file
names on disk are node ids, never `PidTagSubject` or
`PidTagAttachLongFilename`, both of which may say `../`.

## `pypstreader.mbox` — P10 (landed; not a port)

```python
MBOX_POLICY = POLICY.clone(linesep="\n")     # records are LF; an .eml on disk is CRLF
INDEX_NAME = "folders.txt"; MAILER_DAEMON = "MAILER-DAEMON"; EPOCH = 1970-01-01T00:00Z

def mbox_name(folder) → str        # "<nid>.mbox" — never the display name
def export_mbox(folder, dest_dir, *, recurse=True, strict=False, limits=None) → int
    # one <nid>.mbox per folder of the subtree plus `folders.txt`
    # ("<nid>.mbox\t<display path>\t<count>", or "# skipped: <PstError type>"); an existing
    # file is REPLACED, not appended to; returns the messages written
```

RFC 4155 records built from `to_eml`, written with the stdlib's
`mailbox.mbox`. The From_ line is `<sender SMTP, else PidTagSenderEmailAddress
when it is an addr-spec, else MAILER-DAEMON> <time.asctime of
client_submit_time, else delivery_time, else the epoch, in UTC>` — no clock,
because two exports of one store must be byte-identical. The stdlib quotes a
body line beginning `From ` to `>From ` and does not unquote on read, which is
**mboxo and not the mboxrd RFC 4155 prefers**: agreeing with the reader
everybody has is worth more than being reversible and read wrongly by default.
What is guaranteed is that no body line can be mistaken for a record
separator, so the message count survives.

## `pypstreader.debug` — P29 (built), then every layer registers

```python
python -m pypstreader.debug <layer> <file>      # exit 0; a PstError → "Error: …" on stderr, exit 1
python -m pypstreader.debug --list              # registered layer names, one per line
                                          # unknown/missing layer → argparse usage error, exit 2

DUMPERS: dict[str, Callable[[Path], None]]   # EMPTY today; a layer row adds one entry:
DUMPERS["header"] = dump_header              # prints upstream's read_header format for that file
```

Expected names, one per upstream example: `header`, `btrees`, `density_list`,
`store` (the draft said `store_props`; P07 registered it as `store`, beside
`pc`, `heap` and `bth`, which are named for the layer and not the example),
`named_props`, `root_folder`, `ipm_subtree`, `search_updates`,
and later `messages` (P19). P10 adds two that have no upstream example at
all: `eml <file> <nid-hex>` prints one message as RFC 5322 on stdout, and
`export <file> <dir>` writes the whole store — one `<nid>.mbox` per folder
by default, one `<nid>.eml` per message with `--eml` — and prints
`Format:`/`Folders:`/`Messages:`. `debug.dumper_arguments(dumper)` is what
`main` and `tests/contract.py` count a dumper's extra POSITIONAL arguments
with, so a keyword-only flag (`export`'s `as_eml`) is not mistaken for one.
A dumper prints upstream's example output for its
layer and raises only `PstError`; `tests/golden_parsers.py` parses both sides
with one parser and the test compares values.

The parser side (`tests/golden_parsers.py`, P29):

```python
PARSERS: dict[str, Callable[[str], Any]]   # every captured example → parser (read_header complete, the rest stubs)
parse_read_header(text) → {
    "version": "Unicode" | "Ansi",
    "next_block": {"internal": bool, "index": int},   # BlockId.is_internal / .index
    "next_page": int,                                  # PageId.raw
    "file_eof_index", "amap_last_index", "amap_free_size", "pmap_free_size": int,   # ByteIndex.value
    "node_btree", "block_btree": {"page": int, "index": int},                        # PageRef
    "amap_is_valid": "Invalid" | "Valid1" | "Valid2",                                # AmapStatus name, upstream spelling
}
parse_block_id(s) → {"internal": bool, "index": int}
parse_page_id(s) → int;  parse_byte_index(s) → int
parse_node_id(s) → {"type": str, "index": int}       # type is upstream's variant name, e.g. "NormalFolder"
parse_block_ref(s) → {"block": <block_id>, "index": int};  parse_page_ref(s) → {"page": int, "index": int}
# Every parser raises ValueError naming the offending line on truncated or garbled input — never a partial result.
# The `Unicode`/`Ansi` prefix on id types is OPTIONAL, so a dumper prints the `__str__` forms in § ids (no prefix).
```

`conftest.py` fixtures: `golden(store, example) → str` and
`golden_exit(store, example) → int` (0 when no `.exit` file); both skip when
the golden is missing. `tests/test_golden_drift.py` (`oracle`, `slow`) runs
`scripts/capture_oracle.py --check` and fails on drift.

## `pypstreader.pypstreader` — P16 (landed; not a port)

The command, and the only entry point in this package a person types.
`pypstreader.debug` stays what it is — one dumper per upstream example, for
reading the FORMAT; this is for getting the MAIL out.

```bash
pypstreader IN.pst                        # -> ./IN.mbox, every folder, every message; exit 0
pypstreader IN.pst -o mail.mbox           # the file to write (a DIRECTORY for the two modes below)
pypstreader --per-folder IN.pst -o out/   # one <nid>.mbox per folder + folders.txt (via export_mbox)
pypstreader --format eml IN.pst -o out/   # one <nid>.eml per message (via export_folder)
pypstreader --list IN.pst                 # "<count>  <display path>" per folder, on stdout; writes nothing
pypstreader --folder PATH IN.pst          # that folder and its subtree; repeatable
pypstreader --strict IN.pst               # stop at the first refusal instead of skipping it
pypstreader --max-depth N --max-attachment-bytes N --max-embedded-depth N
pypstreader --codepage NAME  -q | -v  --version
```

```python
from pypstreader import pypstreader          # `pypstreader.pypstreader`, importable under either name
pypstreader.main(argv: list[str] | None = None) -> int
pypstreader.FOLDER_HEADER == "X-Pypstreader-Folder"
```

**Exit codes are the contract**: `0` the run finished, `1` a `PstError` or an
`OSError` (one line on stderr, no traceback), `2` the command line was wrong.
`main` catches `SystemExit` as well, so calling it in-process returns a
status rather than raising one — `tests/corruption_harness.py`'s `cli.main`
entry point and `tests/contract.py`'s adapter both depend on that, and
`tests/test_cli.py` sweeps every mutation of a corpus store through it.

**What the flags mean.** `--max-depth` is `max_folder_depth`,
`--max-attachment-bytes` is `max_allocation`, `--max-embedded-depth` is
`max_embedded_message_depth`; a non-positive one is a usage error (exit 2),
not a `Limits` `ValueError`. `--folder` takes a display path exactly as
`--list` prints it and covers that folder AND its subtree; a path that names
nothing is a `PstNotFoundError`, exit 1. Skipping is the default and is
counted: the stderr summary is
`pypstreader: <n> folders, <n> messages written, <n> skipped -> <destination>`,
with `<n> folder(s) unreadable` appended when a contents table refused.

**The single-mbox mode stamps `X-Pypstreader-Folder`** on every record, the
same display path `--list` prints, because an mbox has no names in it and
flattening a store must not lose its tree. That header is added by
`pypstreader.mbox.mbox_record(message, *, limits=None, headers=())`, which
P16 made public for it (it was `mbox._record`); control characters are
stripped from every value, since a display name is attacker-chosen text.

## `pypstreader` — the top level

Today (P09), sorted and deliberately small — the exception family, the
limits, and the readers that exist:

```python
from pypstreader import (
    AttachMethod, Attachment, DEFAULT_LIMITS, EntryId, Folder, Header, Limits, Message,
    PstError, PstFormatError, PstLimitError, PstNotFoundError, PstUnsupportedError,
    Recipient, RecipientType, Store, __version__, eml_bytes, export_folder, export_mbox,
    open, read_header, to_eml, write_eml,
)
__all__ == sorted(__all__)           # tests/test_contract.py asserts it, and that every name resolves
```

`pypstreader.open` is `pypstreader.messaging.store.open_store` under another name; it
shadows the builtin inside `pypstreader` deliberately (`pypstreader.open(path)` reads
like `gzip.open`), and `tests/test_contract.py` pins that it is not the
builtin. `EntryId` is exported with it, because it is what `ipm_subtree`
and the other entry-id accessors return and a caller holds one.

P10 closed the last promise on the list and joined this surface: `to_eml`,
`eml_bytes` and `write_eml` from `pypstreader.eml`, `export_folder` from the same
module and `export_mbox` from `pypstreader.mbox`. They are exported here, and not
only from their modules, because they are what the reader is FOR — a caller
who has a store and wants the mail out of it should not have to know which
module assembles it.

P16 renamed the package from `pypst` (taken on PyPI) to `pypstreader`, which
is also the distribution name, the GitHub repository and the command. The
import surface above is unchanged apart from the prefix; the one rename that
reaches SHIPPED BYTES is the `X-Pypst-*` header family, now `X-Pypstreader-*`
(and the synthetic `Message-ID` domain, now `@pypstreader.invalid`), done in
the same commit as the first release so the name is consistent from 0.1.0
onward. `pstreader` is a second distribution, in `alias/pstreader/`, that
installs `pypstreader==<this version>` and re-exports it; it adds no names.

`__all__` is the enumerable contract, but not the whole of it: the T5
harness (`tests/contract.py`) discovers **every** public callable under the
package — each module's `__all__`, else its public top-level callables, plus
every public classmethod and method — and a new one must be given an adapter
or a reason there before the suite is green again (docs/TEST-PLAN.md § T5).

---

## Changelog

- 2026-09-16 — P16 renamed the package to `pypstreader` throughout (import
  package, distribution, docs, lints, workflows, the `X-Pypst-*` headers and
  the `pypst.invalid` Message-ID domain), added `pypstreader.pypstreader` —
  the `pypstreader` command, its section above — and the `pstreader` alias
  distribution under `alias/pstreader/`. `pypstreader.mbox._record` became
  public as `mbox_record`, with a `headers` argument, so the command can
  stamp `X-Pypstreader-Folder` onto a record without a second assembler.
  `__version__` is `0.1.0`; the PyPI 0.0.1 releases of both names are
  placeholders. One literal was deliberately NOT renamed:
  `scripts/make_fixture.py`'s `"pypst synthetic fixture: {name}"` seed is
  hashed into `synth-basics.pst` and every golden captured over it.

- 2026-09-16 — P10 landed `pypstreader.eml` and `pypstreader.mbox`, the first modules in
  this package with **no upstream counterpart at all** (upstream produces
  text dumps, never mail), and added `to_eml`, `eml_bytes`, `write_eml`,
  `export_folder` and `export_mbox` to `pypstreader.__all__` plus the `eml` and
  `export` dumpers to `pypstreader.debug.DUMPERS`. Changes from the draft above:
  `to_eml` gained a `limits` argument (the caller's ceilings, not only the
  store's); `write_eml` returns the `Path` it wrote; `export_folder` gained
  `recurse`/`strict`/`limits` and the two walk helpers `folder_paths` and
  `readable_messages` that it and `export_mbox` share; and the marker header
  is emitted only when something WAS synthesised rather than always, so its
  presence is the signal. `tests/contract.py` gained nine adapters and a
  `workdir` on its fixture object, `tests/corruption_harness.py` gained the
  `eml.export` entry point (bounded by `EML_BYTES_PER_SWEEP`), and
  `debug.main` learned `--eml` and `dumper_arguments`.
- 2026-09-16 — P09 landed `pypstreader.messaging.message` and
  `pypstreader.messaging.attachment`, and added `Store.open_message`,
  `Folder.messages()` / `Folder.associated()`; `Message`, `Recipient`,
  `RecipientType`, `Attachment` and `AttachMethod` join `pypstreader.__all__` and
  `pypstreader.messaging.__all__`. Changes from the draft: **`body_rtf` is the
  value AS STORED (compressed) and `body_rtf_decompressed()` is the
  expansion** — the draft said `body_rtf` was already decompressed, which
  hid the fact that the store holds LZFu and made the `Body RTF:` line of
  the goldens (a length and a CRC of the *stored* bytes) uncomparable; both
  forms are one call apart and `tests/test_rtf.py` asserts each.
  `Recipient` gained `smtp` (the oracle prints it) and `get`; `subject_raw`,
  `subject_prefix`, `delivery_filetime` / `client_submit_filetime` (the
  goldens print FILETIME ticks, and a `datetime` cannot round-trip the
  sub-microsecond digit), `sub_node_table`, `recipient_table` /
  `attachment_table`, `attachment_ids`, `sub_node_entry`,
  `check_embedded_depth`, `parent`, `depth`, `entry_id`, `get`, `__str__`
  and upstream's `message_flags` / `message_size` / `message_status` /
  `creation_time` / `last_modification_time` / `search_key` were added;
  `Attachment` gained `method_value`, `rendering_position`, `pathname`,
  `sub_nodes`, `sub_node_entry`, `get` and `__str__`, and its `data()`
  returns `None` (not bytes) for a method that carries none, as upstream's
  `Option<AttachmentData>` does. `split_subject` is public because the
  subject-prefix rule is the one piece of [MS-OXCMSG] this layer implements
  and a caller with a raw subject needs it. `pypstreader.debug` gained `messages`,
  `message_lines`, `message_accessor`, `attachment_accessor` and
  `upstream_records`. **Nothing in `pypstreader.limits` changed**: P11's
  `max_recipients`, `max_attachments`, `max_allocation` and
  `max_embedded_message_depth` were already the right four.

- 2026-09-16 — P08 landed `pypstreader.messaging.folder` and added
  `Store.root_folder` / `Store.open_folder`; `Folder` joins `pypstreader.__all__`
  and `pypstreader.messaging.__all__` (the package's `__init__` gained one).
  Changes from the draft: `messages()` and `associated()` are **not** here —
  they need P09's `Message`, so this row lands `message_ids()`,
  `associated_ids()` and `contents()` (the same rows as NIDs and as
  EntryIDs); `subfolders()` yields child `Folder`s and `subfolder_ids()` the
  raw NIDs; `walk` takes `max_depth`; `open`, `table`, the three table
  accessors, `entry_id`, `folder_type`, `get`, `store` and `__str__` were
  added. **`pypstreader.limits` gained `MAX_FOLDER_DEPTH` / `Limits.max_folder_depth`
  (64, additive)**, which is what bounds the walk. `pypstreader.debug` gained
  `folders`, `folder_lines`, `folder_accessor` and `folder_table`;
  `tests/golden_parsers.py` completed `parse_dump_messages` (folder blocks
  as values, message blocks as raw lines for P09) and added
  `dump_messages_folder_lines`; `tests/contract.py` gained `"Store"` and
  `"Folder"` in `READER_TYPES`, a `folders`/`folder_nids` section on its
  fixture object and 14 adapters; `tests/corrupt.py` gained `folder_lies`
  and the corruption harness `folder.walk` / `folder.tables`.
  **A P06 finding, closed by P06b:** `synth-basics.pst`'s root folder writes
  an empty associated-contents table with `rgib[TCI_4b] = 4`. P06 used to
  refuse it at TCINFO parse time, where upstream accepts it because it never
  reads a row of an empty table; P06b narrowed the check to a non-empty
  matrix (`pypstreader.ltp.table_context`'s module docstring), so this store's six
  `Associated Count: 0` lines now print as themselves and `debug folders` is
  byte-identical on 8/8 Unicode corpus stores, pinned by
  `tests/test_folder.py::test_synth_basics_associated_table_is_byte_identical`.

- 2026-09-16 — P06 landed `pypstreader.ltp.table_context`; its section now
  describes what was built. Changes from the draft: `limits` is optional and
  `codepage` was added (as P05's); `TableContextInfo`, `ColumnDescriptor`,
  `CellKind`/`CellRecord`, `from_node`, `read_cell`, `row(index)`,
  `row_index`, `info`/`tree`/`heap`/`limits`/`codepage`, `__len__` and
  `__iter__` added, along with `existence_bitmap_size` /
  `check_existence_bitmap` and the struct constants; `TableRow` gained
  `records` (parallel to `columns`, `None` where a cell is absent), which is
  what tells an ABSENT column from a null one and what the dumper needs;
  `rows()` is MATRIX order (the draft said "row-index order" — upstream's
  examples iterate `rows_matrix()`, and the row index's order is ascending
  row id, a different order); `find_row` raises `PstNotFoundError` (a
  `PstFormatError`, so the draft's contract holds). **`pypstreader.ltp.heap`
  gained `HeapNode.get_hnid_blocks`** (additive): the row matrix must be
  read block by block because rows never straddle a block boundary.
  `pypstreader.debug` gained `tc`, `cell_lines` and `format_cell_record`.
- 2026-09-16 — P07 landed `pypstreader.messaging.store` and
  `pypstreader.messaging.named_prop`; the messaging section now describes what was
  built and the top-level section gained `open`, `Store` and `EntryId`.
  Changes from the draft: `Store.__init__(f: BinaryIO, …)` is the borrowing
  constructor and `Store.open` the owning one, both taking `codepage` beside
  `limits`; `path`, `limits`, `codepage`, `reader`, `nbt`, `bbt`,
  `record_key`, `entry_id`, `matches_record_key` and `get` were added
  because P08 and P09 need them and the dumpers use them; `EntryId` gained
  `unpack_from`, `pack`, `SIZE` and upstream's `__str__`;
  `NamedPropertyMap` gained `from_node`, `properties`, `limits`,
  `bucket_count`, `guid_of`, `name_of`, `string_bytes`, `lookup_string`,
  `hash_entry`, `hash_bucket` and `__len__`, and `NamedPropertyGuid` /
  `NameIdEntry` / `NamedProperty` are named types rather than tuples.
  **`wastebasket` and `finder` are `None` when absent and the store still
  opens** (the row's decision, recorded in the module docstring and pinned
  from both sides in `tests/test_store.py`). **`hash_entry` keeps `wGuid`**
  where upstream clears it — an upstream bug found by checking all 964
  corpus entries against the hash table they actually sit in.
  `pypstreader.debug` gained `store` and `named_props`; `tests/contract.py` gained
  `"PropertyContext"` in `READER_TYPES` (so the map classifies as a reader
  class), a `Store`/`named_map`/`name_ids`/`named_streams`/`entry_id_buffers`
  section on its fixture object, and 20 adapters; `tests/corrupt.py` gained
  `node_pc_block` and the `store_lies` (9–11) and `named_prop_lies` (12–16)
  families; the corruption harness gained `store.open` and
  `store.named_properties`.

- 2026-09-16 — P05 landed `pypstreader.ltp.prop_context`; its section now describes
  what was built. Changes from the draft: `limits` is optional (the heap's
  own by default) and `codepage` was added; `PropertyContext.from_node`,
  `read(record)`, `tree`/`heap`/`limits`/`codepage`, `__len__` and
  `__contains__` added; `PropertyRecord` gained `unpack`, `is_inline`,
  `hnid`, `is_null`, `value_type`, `SIZE` and upstream's `__str__`; the PC
  BTH's 2/6 widths are checked in `__init__` and the module's struct
  constants are named. **`ObjectRef.node` is now a `NodeId`** (P22's open
  item, closed here — `pypstreader.ltp.prop_type` changed in one annotation), and
  `PropType` gained `debug_name` / `from_debug_name` for the dumper and the
  golden parsers. **MV_GUID keeps upstream's count-prefixed reading**: a
  structure-only survey of every PC in both private stores and the whole
  corpus found no `PtypMultipleGuid` property, and the survey is now a
  standing test. `pypstreader.debug` gained `pc`, `property_lines`,
  `format_property_value` and `DUMP_CODEPAGE`. `tests/golden_parsers.py`
  completed `parse_read_store_props`, `parse_read_named_props`,
  `parse_read_root_folder`, `parse_read_ipm_subtree`, `parse_value` and
  `parse_record` (only `read_search_updates` and `dump_messages` remain
  stubs). `tests/corrupt.py` gained the `pc_lies` family (13–14 lies: a
  signature the heap accepts and a PC does not, BTH widths the BTH accepts
  and a PC does not, unknown types, a repeated key, wrong-length fixed
  values, type bits on a fixed HNID, an MV count of 2^32-1, an odd-length
  Unicode value, a non-boolean boolean, and a zero HNID that must NOT
  raise), and the corruption harness a `pc.store_pc` entry point.

- 2026-09-16 — P24: `pypstreader.__all__` defined (the list above); `Header`
  and `read_header` exported at the top level. The T5 contract harness
  discovers every public callable rather than reading this file, so a
  surface change here is also an adapter change in `tests/contract.py`.
- 2026-09-15 — drafted from upstream's public surface (P30). Nothing above
  `errors`/`encode`/`crc` exists yet; every other section is a promise.
- 2026-09-15 — P29: `pypstreader.debug` built (empty `DUMPERS` registry, `--list`, exit codes); golden parser output shapes and the optional-prefix rule recorded above.
- 2026-09-15 — P23 landed `pypstreader.ndb.ids` and `pypstreader.block_sig`; its section
  now describes what was built. Changes from the draft: `NodeId(raw)` and
  `unpack_from` accept an unknown 5-bit type (the refusal is at `id_type`, as
  upstream; goldens print such nodes as `invalid`); `NodeIdType.debug_name` /
  `from_debug_name` added for golden parsers; `unpack_from`, `pack()` and
  `SIZE` on every type; `PageId` carries `index`/`search_key`/`is_internal`
  like upstream's trait; the struct-format constants are named; negative
  offsets are refused.
- 2026-09-15 — P22 landed `pypstreader.ltp.prop_type`. Changes from the draft:
  `PropType.from_wire(value)` is the constructor for wire codes (the enum's
  own `ValueError` is not part of the contract); `decode` gained
  `max_items` (→ `PstLimitError`) and accepts an `int` type; `PropValue`
  includes `None` (PtypNull); `CLSID` is an alias of `GUID`; `fixed_size(NULL)`
  is 0 and OBJECT is *not* fixed-size. **Fixed-base MV_\* values carry no
  count** (the [MS-PST] 2.3.3.4.1 packed form, as upstream reads them) — the
  draft's "count u32 then values" applies only to MV_STRING8/UNICODE/BINARY
  and, following upstream against the spec, MV_GUID. **`ObjectRef.node` is a
  raw `int`**, not `NodeId`, because P23 is being built in parallel; P05 wraps
  it (or P23 lands first and P05 changes the annotation here in one line).
- 2026-09-15 — P21: `pypstreader.rtf` built. Adds `read_header`, `CompressedRtfHeader`,
  `CompressionType`; `decompress_rtf` returns bytes with no NUL trimming (P09
  note above); `max_output` is a literal until P11's `limits.py` exists.
- 2026-09-15 — P01 landed `pypstreader.ndb.header` and `pypstreader.ndb.root`; its section
  now describes what was built. Changes from the draft: `wVer` 36/37 →
  `PstUnsupportedError` (not parsed); `CryptMethod` stays in `pypstreader.encode`
  with 0x10 refused as the constant `CRYPT_METHOD_EDPCRYPTED`; `AmapStatus`
  gains `from_byte` / `from_byte_lenient` and `debug_name`; `Version` gains
  `is_ansi` / `debug_name`; the module constants and the exact check order
  are recorded. `python -m pypstreader.debug header` registered.
- 2026-09-15 — P02 landed `pypstreader.ndb.page` and `pypstreader.ndb.btree`; its section
  now describes what was built. Changes from the draft: `NodeBTreeEntry.parent`
  is `NodeId | None` (upstream's `Option`, goldens print `None`); `verify` takes
  `(page_bytes, index)` and checks the CRC only — the signature is carried and
  exposed as `expected_signature`, never enforced, because upstream ignores it
  on read and `pstd-inline-cid.pst` has zero signatures; `BTreePage` is a
  frozen dataclass (not `Generic`) with `max_entries`/`entry_size` kept and a
  `parse(page_bytes, kind, index)` classmethod; `find` raises the new
  `PstNotFoundError` (a `PstFormatError`) and accepts a raw `int`; `limits`
  defaults to `DEFAULT_LIMITS`; `read_page`, `read_density_list`,
  `DensityListPage`/`DensityListEntry` and the module constants added; the
  density list IS ported. `python -m pypstreader.debug btrees` and `density_list`
  registered; `parse_read_btrees`/`parse_read_density_list` complete.
- 2026-09-15 — P11 landed `pypstreader.limits`; its section now describes what was
  built. Changes from the draft: `MAX_ITEMS` is `1 << 27` (the nidIndex
  space), not 1_000_000 — a 50 GiB store's BBT alone has millions of entries
  and the draft value would have refused a legitimate large file; `MAX_FILE_SIZE`,
  `MAX_HEAP_TREE_DEPTH`, `MAX_FOLDERS`, `MAX_MESSAGES` and `MAX_MV_ITEMS` added;
  the trip message is `f"{what}: {value} exceeds limit {ceiling}"` (the draft
  had no colon or "limit"); ceilings are inclusive; the helpers `check_depth`
  / `check_count` / `check_allocation` and the `VisitedSet` cycle guard are
  the API, so every walk raises the same message shape. `Limits` refuses a
  non-int with `TypeError` (ruff's default TRY004; the draft said ValueError
  for both). `prop_type.DEFAULT_MAX_ITEMS` is now `limits.MAX_MV_ITEMS`,
  value unchanged.
- 2026-09-16 — P03 landed `pypstreader.ndb.block`; its section now describes what
  was built. Changes from the draft: `SubNodeEntry` → `SubNodeLeafEntry` plus
  `SubNodeIntermediateEntry`; `DataBlock`/`XBlock`/`SubNodeLeafBlock`/
  `SubNodeIntermediateBlock` and the per-block `read_data_tree` /
  `read_subnode_block` / `find` added; `BlockTrailer.verify` is
  `verify_block_id` + `verify_crc` (upstream checks them at different points);
  `limits` defaults; the module constants named. `debug btrees` prints the
  full `read_btrees` output; `debug node` registered; `debug.main` passes
  extra positional arguments through.
- 2026-09-16 — P04 landed `pypstreader.ltp.heap` and `pypstreader.ltp.tree`; its section
  now describes what was built. Changes from the draft: `HeapNode` takes the
  node's blocks (not one `bytes`) plus `from_node`; **`BlockReader` gained
  `read_data_blocks` / `node_data_blocks`** (additive; `read_data` is their
  join); `HeapId.from_parts`/`is_null`/`__str__`, `HeapNodeId.is_heap`,
  `HeapNodeType`, `HeapNodeHeader`, `HeapPageMap`, `HeapTreeHeader`,
  `HeapTree.entries`; `value_size` → `entry_size`; a zero-length heap item
  and a ragged BTH page are refused (divergences, in the docstrings); the
  examples print `Type: Null` for a zero HNID (a fact for P05). `debug heap`
  and `debug bth` registered; `corrupt.py` gained the heap builders and the
  `heap_lies` family; the harness walks the store PC.
