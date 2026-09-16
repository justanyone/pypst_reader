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

## `pypst.limits` — P11

```python
MAX_BTREE_DEPTH: int = 8            # [MS-PST] says the trees are shallow; 8 is generous
MAX_XBLOCK_DEPTH: int = 2           # XXBLOCK → XBLOCK → data; anything deeper is not the format
MAX_SUBNODE_DEPTH: int = ...
MAX_EMBEDDED_MESSAGE_DEPTH: int = 16
MAX_ALLOCATION: int = 256 * 2**20   # the largest single bytes object a walk may build
MAX_ITEMS: int = 1_000_000          # rows in one table, entries in one tree
MAX_HEAP_ITEMS, MAX_PROPERTY_COUNT, MAX_RECIPIENTS, MAX_ATTACHMENTS: int

@dataclass(frozen=True, slots=True)
class Limits:                       # all of the above as fields, defaults from the constants
    ...
DEFAULT_LIMITS = Limits()
```

Every public opener accepts `limits: Limits = DEFAULT_LIMITS` and threads it
down. A limit trip is `PstLimitError(f"{what} {value} exceeds {ceiling}")`.

## `pypst.encode`, `pypst.crc` — exist

```python
encode.decode_block(data: bytes | bytearray | memoryview, method: CryptMethod, key: int) → bytes
crc.compute_crc(data: bytes) → int     # u32
```

(Names as landed in P00; check the modules. `CryptMethod` moves to `ndb.header`
in P01 if it is not already an enum.)

## `pypst.ndb.ids` + `pypst.block_sig` — P23

```python
class NodeIdType(IntEnum):          # [MS-PST] 2.2.2.1 — the 5-bit nidType; unknown value → PstFormatError
    HID = 0x00, INTERNAL = 0x01, NORMAL_FOLDER = 0x02, SEARCH_FOLDER = 0x03,
    NORMAL_MESSAGE = 0x04, ATTACHMENT = 0x05, SEARCH_UPDATE_QUEUE = 0x06,
    SEARCH_CRITERIA_OBJECT = 0x07, ASSOC_MESSAGE = 0x08, CONTENTS_TABLE_INDEX = 0x0A,
    RECEIVE_FOLDER_TABLE = 0x0B, OUTGOING_QUEUE_TABLE = 0x0C, HIERARCHY_TABLE = 0x0D,
    CONTENTS_TABLE = 0x0E, ASSOC_CONTENTS_TABLE = 0x0F, SEARCH_CONTENTS_TABLE = 0x10,
    ATTACHMENT_TABLE = 0x11, RECIPIENT_TABLE = 0x12, SEARCH_TABLE_INDEX = 0x13,
    LTP = 0x1F

@dataclass(frozen=True, slots=True)
class NodeId:                       # u32
    raw: int
    @classmethod from_parts(cls, id_type: NodeIdType, index: int) → NodeId   # index > MAX_NODE_INDEX → PstFormatError
    id_type → NodeIdType            # !PstFormatError on an unknown 5-bit value
    index → int                     # 27 bits
    __str__ → "NodeId { <Type>: 0x<index hex> }"   # upstream's Debug form, so goldens parse

MAX_NODE_INDEX = (1 << 27) - 1
NID_MESSAGE_STORE = NodeId(0x21); NID_NAME_TO_ID_MAP = NodeId(0x61); NID_ROOT_FOLDER = NodeId(0x122)
# ...and the rest of upstream's NID_* constants, verbatim values

@dataclass(frozen=True, slots=True)
class BlockId:                      # u64; bit 1 = internal, bit 0 reserved, rest index
    raw: int
    @classmethod from_parts(cls, is_internal: bool, index: int) → BlockId     # index > MAX_BLOCK_INDEX → PstFormatError
    is_internal → bool
    index → int
    search_key → int                # what the BBT is keyed on (raw with the reserved bit cleared)
    __str__ → "BlockId { leaf: 0x<hex> }" | "BlockId { internal: 0x<hex> }"

MAX_BLOCK_INDEX = (1 << 62) - 1

@dataclass(frozen=True, slots=True)
class PageId:                       # u64, same layout as BlockId; distinct type on purpose
    raw: int
    __str__ → "PageId: 0x<hex>"

@dataclass(frozen=True, slots=True)
class ByteIndex:                    # u64 file offset. Not an int: you may not add two of these.
    value: int
    __str__ → "ByteIndex { 0x<hex> }"

@dataclass(frozen=True, slots=True)
class BlockRef:                     # BREF, [MS-PST] 2.2.2.4 — struct "<QQ"
    block: BlockId
    index: ByteIndex
    SIZE = 16
    @classmethod unpack_from(cls, buf: bytes | memoryview, offset: int = 0) → BlockRef   # short buffer → PstFormatError

@dataclass(frozen=True, slots=True)
class PageRef:                      # same bytes, page-typed
    page: PageId
    index: ByteIndex

block_sig.compute_sig(index: int, block_id: int) → int     # u16; [MS-PST] 5.5; both inputs masked to u32 first
```

Upstream's `Unicode*` prefix is dropped: there is only one variant here.

## `pypst.ndb.header` + `pypst.ndb.root` — P01

```python
class Version(IntEnum):  ANSI_14 = 14, ANSI_15 = 15, UNICODE = 23, UNICODE_4K_36 = 36, UNICODE_4K_37 = 37
class CryptMethod(IntEnum):  NONE = 0x00, PERMUTE = 0x01, CYCLIC = 0x02, WINDOWS_EFS = 0x10   # 0x10 → PstUnsupportedError on read
class AmapStatus(IntEnum):  INVALID = 0x00, VALID1 = 0x01, VALID2 = 0x02

@dataclass(frozen=True, slots=True)
class Root:                          # [MS-PST] 2.2.2.5, Unicode layout, 72 bytes
    file_eof_index: ByteIndex
    amap_last_index: ByteIndex
    amap_free_size: ByteIndex
    pmap_free_size: ByteIndex
    node_btree: PageRef
    block_btree: PageRef
    amap_is_valid: AmapStatus
    SIZE = 72
    @classmethod unpack_from(cls, buf, offset=0) → Root

@dataclass(frozen=True, slots=True)
class Header:                        # [MS-PST] 2.2.2.6, Unicode layout, 564 bytes
    version: Version                 # always a UNICODE member once constructed
    client_version: int
    crypt_method: CryptMethod
    next_block: BlockId
    next_page: PageId
    unique_value: int
    root: Root
    SIZE = 564
    @classmethod parse(cls, buf: bytes | memoryview) → Header
        # !PstUnsupportedError  wVer 14/15 ("ANSI store; see pypst_reader_nu"), crypt 0x10
        # !PstFormatError       bad magic, bad CRC (partial or full), unknown wVer, unknown crypt

read_header(f: BinaryIO) → Header    # reads SIZE bytes from offset 0; short read → PstFormatError
```

`python -m pypst.debug header <file>` prints the ten `read_header` lines in
upstream's format so `parse_read_header` compares values directly.

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

```python
class PropType(IntEnum):             # [MS-OXCDATA] 2.11.1
    UNSPECIFIED=0x0000, NULL=0x0001, SHORT=0x0002, LONG=0x0003, FLOAT=0x0004, DOUBLE=0x0005,
    CURRENCY=0x0006, APPTIME=0x0007, ERROR=0x000A, BOOLEAN=0x000B, OBJECT=0x000D, LONGLONG=0x0014,
    STRING8=0x001E, UNICODE=0x001F, SYSTIME=0x0040, GUID=0x0048, BINARY=0x0102,
    MV_SHORT=0x1002, MV_LONG=0x1003, MV_FLOAT=0x1004, MV_DOUBLE=0x1005, MV_CURRENCY=0x1006,
    MV_APPTIME=0x1007, MV_LONGLONG=0x1014, MV_STRING8=0x101E, MV_UNICODE=0x101F,
    MV_SYSTIME=0x1040, MV_GUID=0x1048, MV_BINARY=0x1102
    # any other value → PstUnsupportedError(f"property type 0x{v:04X}")

def is_fixed_size(t: PropType) → bool
def fixed_size(t: PropType) → int    # 1/2/4/8/16 for the fixed types; !ValueError-shaped PstFormatError otherwise

def decode(t: PropType, data: bytes | memoryview, *, codepage: str = "cp1252") → PropValue
# PropValue = int | float | bool | bytes | str | datetime | uuid.UUID | tuple[PropValue, ...] | ObjectRef
# SYSTIME → aware UTC datetime; out of datetime range → PstFormatError, never OverflowError
# STRING8 → str via codecs; unknown codepage → PstUnsupportedError
# MV_* → tuple; bad count/offsets → PstFormatError

@dataclass(frozen=True, slots=True)
class ObjectRef:  node: NodeId; size: int      # PT_OBJECT: points at a subnode (attachment data, embedded message)

def filetime_to_datetime(ft: int) → datetime; def datetime_to_filetime(dt: datetime) → int   # the round-trip pair for property tests
```

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

## `pypst.rtf` — P21 (leaf)

```python
def decompress_rtf(data: bytes, *, max_output: int = limits.MAX_ALLOCATION) → bytes
    # [MS-OXRTFCP]; LZFu and MELA; !PstFormatError bad magic/CRC/token; !PstLimitError RAWSIZE > max_output
# tests/rtf_compress.py (tests only): compress_rtf(raw: bytes) → bytes — the round-trip partner
```

## `pypst.eml` — P10 (not a port)

```python
def to_eml(message: Message, *, synthesize_missing: bool = True) → email.message.EmailMessage
def write_eml(message: Message, path) → None
# Synthesised headers (Message-ID etc.) are marked with X-Pypst-Synthesized: <header names>
```

## `pypst.debug` — P29, then every layer

```python
python -m pypst.debug header|btrees|density_list|store_props|named_props|root_folder|ipm_subtree|search_updates|messages <file>
```

Each subcommand prints upstream's example output format for that layer,
so `tests/golden_parsers.py` parses both sides with one parser.

## `pypst` — the top level

```python
from pypst import open, Store, Folder, Message, Attachment, PstError, PstFormatError, PstLimitError, PstUnsupportedError, Limits
__all__ = [...]                      # the P24 contract harness iterates this
```

---

## Changelog

- 2026-09-15 — drafted from upstream's public surface (P30). Nothing above
  `errors`/`encode`/`crc` exists yet; every other section is a promise.
