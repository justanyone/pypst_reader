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
  failure is a `PstError` subclass from `pypst.errors`. Every fixed-width
  integer is masked where it is computed.
- `__str__` on a value type must be stable: golden parsers (`tests/golden_parsers.py`)
  round-trip through it, and `pypst.debug` prints it.

Conventions for reading this file: `→ X` is the return type; `!E` after a
signature lists the exception types it may raise beyond the universal
`PstFormatError` for malformed bytes.

---

## `pypst.errors` — exists

```python
class PstError(Exception)                       # the family; nothing else escapes a public entry point
class PstFormatError(PstError)                  # the bytes are not a valid PST structure
class PstLimitError(PstError)                   # valid-looking but beyond a configured ceiling (limits.py)
class PstUnsupportedError(PstError)             # recognised, deliberately not handled: ANSI, unknown crypt/prop type
```

Additive only. P11 adds nothing here; it raises `PstLimitError`.

## `pypst.limits` — exists (P11)

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

## `pypst.encode`, `pypst.crc` — exist

```python
encode.decode_block(data: bytes | bytearray | memoryview, method: CryptMethod, key: int) → bytes
crc.compute_crc(data: bytes) → int     # u32
```

(Names as landed in P00; check the modules. `CryptMethod` moves to `ndb.header`
in P01 if it is not already an enum.)

## `pypst.ndb.ids` + `pypst.block_sig` — landed (P23)

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

## `pypst.ndb.header` + `pypst.ndb.root` — landed (P01)

```python
# pypst.ndb.root
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

# pypst.ndb.header
HEADER_MAGIC = 0x4E444221; HEADER_MAGIC_CLIENT = 0x4D53      # "!BDN" and "SM" read little-endian
CLIENT_VERSION = 19; PLATFORM_CREATE = PLATFORM_ACCESS = 0x01; SENTINEL = 0x80
CRYPT_METHOD_EDPCRYPTED = 0x10                                # the spec's name; refused by name
HEADER_SIZE = 564
from pypst.encode import CryptMethod                         # NONE/PERMUTE/CYCLIC live with the decoders; re-exported

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
        # !PstUnsupportedError  wVer 14/15 ("ANSI (pre-2003) store, wVer=14; … see pypst_reader_nu"),
        #                       wVer 36/37 (4 KB-page store), bCryptMethod 0x10 (EDP/WIP)
        # !PstFormatError       short buffer, bad dwMagic, bad wMagicClient, unknown wVer, partial or full
        #                       CRC mismatch, wVerClient ≠ 19, platform bytes ≠ 1, dwAlign ≠ 0,
        #                       bSentinel ≠ 0x80, unknown bCryptMethod, rgbReserved ≠ 0
        # Check order: length, dwMagic, wMagicClient, wVer, dwCRCPartial, dwCRCFull, the fixed fields.
        # Read but NOT validated (as upstream): dwReserved1/2, bidUnused, qwUnused, rgbFM, rgbFP,
        # rgbReserved2, bReserved, rgbReserved3; rgnid is read and not kept.

read_header(f: BinaryIO) → Header    # seeks to 0, reads SIZE bytes; short read → PstFormatError; OSError is not caught
```

`python -m pypst.debug header <file>` prints the ten `read_header` lines in
upstream's format (`__str__` forms, no `Unicode` prefix) so `parse_read_header`
compares values directly; on an ANSI store it exits 1 with the
`PstUnsupportedError` message on stderr.

Changes from the draft, and why: `wVer` 36/37 are **refused**
(`PstUnsupportedError`), not parsed — they are the 4 KB-page layout, upstream
refuses them too, and reading them with 512-byte-page assumptions is the
plausible-garbage outcome. `CryptMethod` stays in `pypst.encode` (it was
already an enum there) and gains no `WINDOWS_EFS` member: 0x10 is the constant
`CRYPT_METHOD_EDPCRYPTED` and is refused before the enum is consulted, so
`decode_block` can never be handed it. `AmapStatus` has the two conversions
because upstream's read is lenient and the rest of this package is not.
`tests/corrupt.py` (mutation helpers; `reseal_header` recomputes both CRCs)
is the seed P12 extends.

## `pypst.ndb.page` + `pypst.ndb.btree` — P02

```python
PAGE_SIZE = 512
class PageType(IntEnum):  BBT = 0x80, NBT = 0x81, FMAP = 0x82, PMAP = 0x83, AMAP = 0x84, FPMAP = 0x85, DL = 0x86

@dataclass(frozen=True, slots=True)
class PageTrailer:                   # [MS-PST] 2.2.2.7.1, 16 bytes at the end of every page
    page_type: PageType; signature: int; crc: int; block_id: PageId
    verify(self, index: ByteIndex, page_bytes: memoryview) → None   # !PstFormatError sig/crc/type mismatch

@dataclass(frozen=True, slots=True)
class NodeBTreeEntry:                # NBTENTRY 2.2.2.7.7.4
    node: NodeId; data: BlockId; sub_node: BlockId | None; parent: NodeId
@dataclass(frozen=True, slots=True)
class BlockBTreeEntry:               # BBTENTRY 2.2.2.7.7.3
    block: BlockRef; size: int; ref_count: int
@dataclass(frozen=True, slots=True)
class IntermediateEntry:             # BTENTRY 2.2.2.7.7.2
    key: int; ref: PageRef

class BTreePage(Generic[E]):         # one page: level, entries, trailer
    level: int; entries: tuple[E, ...]; trailer: PageTrailer

class NodeBTree / BlockBTree:
    __init__(self, f: BinaryIO, root: PageRef, limits: Limits)
    find(self, key: NodeId | BlockId) → NodeBTreeEntry | BlockBTreeEntry     # !KeyError-shaped PstFormatError("node 0x.. not found")
    __iter__ → Iterator[entry]       # in key order; depth > limits.MAX_BTREE_DEPTH or a revisited page → PstLimitError
    pages() → Iterator[BTreePage]    # for the debug dumper; same order read_btrees prints
```

## `pypst.ndb.block` — P03

```python
MAX_BLOCK_SIZE = 8192
def block_size(size: int) → int      # data size → 64-byte-aligned allocation incl. 16-byte trailer

@dataclass(frozen=True, slots=True)
class BlockTrailer:  size: int; signature: int; crc: int; block_id: BlockId
    cyclic_key → int                 # low 32 bits of block_id, for CryptMethod.CYCLIC

class BlockReader:
    __init__(self, f: BinaryIO, header: Header, bbt: BlockBTree, limits: Limits)
    read_block(self, ref: BlockRef, size: int, *, is_internal: bool) → bytes   # raw, trailer-verified, DEcoded unless internal
    read_data(self, block: BlockId) → bytes        # follows XBLOCK/XXBLOCK; total > limits.MAX_ALLOCATION → PstLimitError
    read_subnode_tree(self, block: BlockId) → dict[NodeId, SubNodeEntry]      # SLBLOCK/SIBLOCK, depth-limited
    node_data(self, entry: NodeBTreeEntry) → bytes                             # the convenience every layer above uses

@dataclass(frozen=True, slots=True)
class SubNodeEntry:  node: NodeId; data: BlockId; sub_node: BlockId | None
```

## `pypst.ltp.heap` + `pypst.ltp.tree` — P04

```python
@dataclass(frozen=True, slots=True)
class HeapId:                        # HID 2.3.1.1: type (5 bits, must be HID=0), index (11 bits), block index (16 bits)
    raw: int
    index → int; block_index → int
@dataclass(frozen=True, slots=True)
class HeapNodeId:                    # HNID 2.3.3.2: the *union* — a HeapId if nidType == 0, else a NodeId (subnode)
    raw: int
    as_heap → HeapId | None
    as_node → NodeId | None
# The two are distinct classes on purpose (T02 § the trap).

class HeapNode:
    __init__(self, data: bytes, *, subnodes: dict[NodeId, SubNodeEntry] | None, reader: BlockReader, limits: Limits)
    client_signature → int           # bClientSig: 0xB5 = BTH, 0xBC = PC, 0x7C = TC, ...
    user_root → HeapId
    get(self, hid: HeapId) → memoryview             # !PstFormatError out-of-range index/block, zero-length freed item
    get_hnid(self, hnid: HeapNodeId) → bytes        # heap item or subnode data, transparently

class HeapTree:                      # BTH 2.3.2 over a HeapNode
    __init__(self, heap: HeapNode, root: HeapId)
    key_size, value_size → int
    __iter__ → Iterator[tuple[bytes, bytes]]        # leaf (key, value) pairs in key order; depth/cycle → PstLimitError
    find(self, key: bytes) → bytes | None
```

## `pypst.ltp.prop_type` — P22 (leaf; land first)

**Built** (`src/pypst/ltp/prop_type.py`, 2026-09-15). Ported from `ltp/prop_type.rs`
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
    # the way to construct from a wPropType field. Any code upstream's TryFrom<u16> rejects —
    # including UNSPECIFIED and the spec's ServerId/Restriction/RuleAction — is
    # PstUnsupportedError(f"property type 0x{v:04X}"); not a u16 at all → PstFormatError.
    # Do not rely on PropType(v): that raises ValueError.

def is_fixed_size(t: PropType) → bool  # NULL, SHORT, LONG, FLOAT, DOUBLE, CURRENCY, APPTIME, ERROR, BOOLEAN, LONGLONG, SYSTIME, GUID
def fixed_size(t: PropType) → int      # 0 (NULL) / 1 / 2 / 4 / 8 / 16; PstFormatError for a variable type. OBJECT is variable.

DEFAULT_MAX_ITEMS = MAX_MV_ITEMS               # from pypst.limits (P11); 1_000_000
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
class ObjectRef:  node: int; size: int         # PT_OBJECT: subnode id (raw u32 for now — see changelog) and byte size

def filetime_to_datetime(ft: int) → datetime   # 100 ns ticks since 1601-01-01 → aware UTC; sub-µs ticks dropped; out of range → PstFormatError
def datetime_to_filetime(dt: datetime) → int   # inverse; naive → TypeError, before 1601 → ValueError (caller errors, not file errors)
```

The goldens print upstream's variant names (`Integer32`, `Time`, ...); the
map from those to `PropType` is `UPSTREAM_VARIANT_TO_PROPTYPE` in
`tests/test_prop_type.py`, for the golden parsers to import.

## `pypst.ltp.prop_context` — P05

```python
@dataclass(frozen=True, slots=True)
class PropertyRecord:                # one PC BTH leaf: 2-byte prop id key, 6-byte value record
    prop_id: int; prop_type: PropType; raw: int   # raw = the 4-byte inline value OR an HNID

class PropertyContext:
    __init__(self, heap: HeapNode, limits: Limits)      # client sig must be 0xBC
    records → Mapping[int, PropertyRecord]              # count > limits.MAX_PROPERTY_COUNT → PstLimitError
    get(self, prop_id: int) → PropValue | None          # decodes on demand; fixed types inline, else via HNID
    __iter__ → Iterator[tuple[int, PropValue]]          # in prop-id order, as read_store_props prints
```

## `pypst.ltp.table_context` — P06

```python
LTP_ROW_ID_PROP_ID = 0x67F2; LTP_ROW_VERSION_PROP_ID = 0x67F3

@dataclass(frozen=True, slots=True)
class ColumnDescriptor:  prop_type: PropType; prop_id: int; offset: int; size: int; existence_bit: int
@dataclass(frozen=True, slots=True)
class TableRow:
    id: int; unique: int
    cells: Mapping[int, PropValue]   # prop_id → value; a column whose existence bit is clear is ABSENT, not None

class TableContext:
    __init__(self, heap: HeapNode, limits: Limits)      # client sig 0x7C
    columns → tuple[ColumnDescriptor, ...]
    row_count → int                                     # > limits.MAX_ITEMS → PstLimitError
    rows() → Iterator[TableRow]                         # row-index order, as read_ipm_subtree prints
    find_row(self, row_id: int) → TableRow              # !PstFormatError not found
```

## `pypst.messaging` — P07 / P08 / P09

```python
@dataclass(frozen=True, slots=True)
class EntryId:  record_key: bytes; node: NodeId        # 24 bytes; record_key is 16

class Store:                          # P07 — the object `open()` returns
    @classmethod open(cls, path: str | os.PathLike, *, limits: Limits = DEFAULT_LIMITS) → Store   # context manager
    header → Header
    properties → PropertyContext      # NID_MESSAGE_STORE's PC
    display_name → str
    ipm_subtree → EntryId; wastebasket → EntryId | None; finder → EntryId | None   # None where P07 decides to tolerate absence
    named_properties → NamedPropertyMap
    root_folder → Folder
    open_folder(self, entry: EntryId | NodeId) → Folder
    open_message(self, entry: EntryId | NodeId, *, parent: Folder | None = None) → Message
    close()

class NamedPropertyMap:               # P07 — NID_NAME_TO_ID_MAP
    guids → tuple[uuid.UUID, ...]
    entries → tuple[NameIdEntry, ...]
    lookup(self, prop_id: int) → NamedProperty | None            # 0x8000+ → (guid, name-or-id)
    resolve(self, guid: uuid.UUID, name: str | int) → int | None   # the reverse

class Folder:                         # P08
    node → NodeId; properties → PropertyContext
    display_name → str; content_count → int; unread_count → int; has_subfolders → bool
    subfolders() → Iterator[Folder]   # hierarchy table; depth > limits → PstLimitError
    messages() → Iterator[Message]    # contents table
    associated() → Iterator[Message]
    walk() → Iterator[Folder]         # pre-order, self first

class Message:                        # P09
    node → NodeId; properties → PropertyContext
    message_class → str; subject → str; normalized_subject → str   # prefix byte stripped (T03 trap)
    sender_name, sender_email, delivery_time, client_submit_time, ...  # thin property accessors
    body_text → str | None; body_html → bytes | None; body_rtf → bytes | None   # rtf DEcompressed via pypst.rtf
    transport_headers → str | None    # PR_TRANSPORT_MESSAGE_HEADERS, the P10 decision input
    recipients() → Iterator[Recipient]
    attachments() → Iterator[Attachment]

@dataclass(frozen=True, slots=True)
class Recipient:  type: RecipientType; name: str | None; email: str | None; properties: Mapping[int, PropValue]

class Attachment:                     # P09
    method → AttachMethod             # NONE/BY_VALUE/BY_REFERENCE/.../EMBEDDED_MESSAGE/OLE
    filename → str | None; long_filename → str | None; mime_tag → str | None; content_id → str | None
    size → int
    data() → bytes                    # BY_VALUE; > limits.MAX_ALLOCATION → PstLimitError
    embedded_message() → Message | None   # EMBEDDED_MESSAGE; depth > limits.MAX_EMBEDDED_MESSAGE_DEPTH → PstLimitError
```

## `pypst.rtf` — P21 (landed)

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

## `pypst.eml` — P10 (not a port)

```python
def to_eml(message: Message, *, synthesize_missing: bool = True) → email.message.EmailMessage
def write_eml(message: Message, path) → None
# Synthesised headers (Message-ID etc.) are marked with X-Pypst-Synthesized: <header names>
```

## `pypst.debug` — P29 (built), then every layer registers

```python
python -m pypst.debug <layer> <file>      # exit 0; a PstError → "Error: …" on stderr, exit 1
python -m pypst.debug --list              # registered layer names, one per line
                                          # unknown/missing layer → argparse usage error, exit 2

DUMPERS: dict[str, Callable[[Path], None]]   # EMPTY today; a layer row adds one entry:
DUMPERS["header"] = dump_header              # prints upstream's read_header format for that file
```

Expected names, one per upstream example: `header`, `btrees`, `density_list`,
`store_props`, `named_props`, `root_folder`, `ipm_subtree`, `search_updates`,
and later `messages` (P19). A dumper prints upstream's example output for its
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

## `pypst` — the top level

```python
from pypst import open, Store, Folder, Message, Attachment, PstError, PstFormatError, PstLimitError, PstUnsupportedError, Limits
__all__ = [...]                      # the P24 contract harness iterates this
```

---

## Changelog

- 2026-09-15 — drafted from upstream's public surface (P30). Nothing above
  `errors`/`encode`/`crc` exists yet; every other section is a promise.
- 2026-09-15 — P29: `pypst.debug` built (empty `DUMPERS` registry, `--list`, exit codes); golden parser output shapes and the optional-prefix rule recorded above.
- 2026-09-15 — P23 landed `pypst.ndb.ids` and `pypst.block_sig`; its section
  now describes what was built. Changes from the draft: `NodeId(raw)` and
  `unpack_from` accept an unknown 5-bit type (the refusal is at `id_type`, as
  upstream; goldens print such nodes as `invalid`); `NodeIdType.debug_name` /
  `from_debug_name` added for golden parsers; `unpack_from`, `pack()` and
  `SIZE` on every type; `PageId` carries `index`/`search_key`/`is_internal`
  like upstream's trait; the struct-format constants are named; negative
  offsets are refused.
- 2026-09-15 — P22 landed `pypst.ltp.prop_type`. Changes from the draft:
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
- 2026-09-15 — P21: `pypst.rtf` built. Adds `read_header`, `CompressedRtfHeader`,
  `CompressionType`; `decompress_rtf` returns bytes with no NUL trimming (P09
  note above); `max_output` is a literal until P11's `limits.py` exists.
- 2026-09-15 — P01 landed `pypst.ndb.header` and `pypst.ndb.root`; its section
  now describes what was built. Changes from the draft: `wVer` 36/37 →
  `PstUnsupportedError` (not parsed); `CryptMethod` stays in `pypst.encode`
  with 0x10 refused as the constant `CRYPT_METHOD_EDPCRYPTED`; `AmapStatus`
  gains `from_byte` / `from_byte_lenient` and `debug_name`; `Version` gains
  `is_ansi` / `debug_name`; the module constants and the exact check order
  are recorded. `python -m pypst.debug header` registered.
- 2026-09-15 — P11 landed `pypst.limits`; its section now describes what was
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
