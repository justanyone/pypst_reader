"""Identifiers — node ids, block ids, page ids, byte indices, and the BREF pairs.

Ported from: crates/pst/src/ndb/{node_id,block_id,byte_index,block_ref}.rs
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.2.2.1 NID, 2.2.2.2 BID, 2.2.2.3 IB, 2.2.2.4 BREF

These are the words the rest of the NDB is written in. A NID names a node in
the node B-tree, a BID names a block in the block B-tree, an IB is a byte
offset into the file, and a BREF pairs a BID with the IB where its bytes
live. Every one of them is a small integer with a bit layout, and every one
is worth a type of its own: an offset added to a size is a bug the file
format cannot express, and a frozen dataclass will not let it happen quietly.

**Unicode arms only (ADR-0003).** Upstream has a `Unicode*` and an `Ansi*`
form of each of these behind a trait; the ANSI forms are 32 bits wide. Only
the 64-bit forms are ported and the prefix is dropped: `BlockId` here is
upstream's `UnicodeBlockId`.

**Two reads, two strictnesses — and this mirrors upstream exactly.** A raw
value from the file is accepted as it is (`NodeId(raw)`, `unpack_from`),
because a store may legitimately carry a node whose 5-bit type this reader
does not know, and the B-tree that holds it must still be walkable; the
oracle goldens print such nodes as `NodeId { invalid: 0x... }`. Asking for
its `id_type` is where the refusal happens, as `PstFormatError`. Building a
value from parts (`from_parts`) is strict from the start: an index that does
not fit, or a type outside the enum, is refused at once, as upstream's
`new()` refuses it.

**Divergence: constructors check their width.** Upstream's `From<u32>` /
`From<u64>` cannot be handed a value that does not fit; Python's can. So
each type checks in `__post_init__` that its raw value is a non-negative
integer of the right width and raises `PstFormatError` otherwise. A u64
that is not a u64 is a lie about the file, and it is refused where it is
first seen rather than where it first misbehaves.

**Divergence: `__str__` reproduces upstream's `Debug` output.** The goldens
under tests/golden/ are the oracle's `Debug` text, and the differential
tests compare against it; so `str()` of every type here is that text with
the `Unicode` prefix removed. The forms are fixed in docs/INTERFACES.md and
must not drift.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar

from pypst.errors import PstFormatError

# Struct formats, one per structure, little-endian throughout ([MS-PST] 1.3.1).
NODE_ID_FORMAT = "<I"
BLOCK_ID_FORMAT = "<Q"
BYTE_INDEX_FORMAT = "<Q"
BLOCK_REF_FORMAT = "<QQ"

_U32 = 0xFFFFFFFF
_U64 = 0xFFFFFFFFFFFFFFFF

# A NID is 5 bits of type and 27 bits of index; a BID is 2 bits of flags and
# 62 bits of index. Both limits are the largest index that fits.
MAX_NODE_INDEX = (1 << 27) - 1
MAX_BLOCK_INDEX = (1 << 62) - 1

_NODE_TYPE_BITS = 5
_NODE_TYPE_MASK = (1 << _NODE_TYPE_BITS) - 1
_BLOCK_FLAG_BITS = 2
_BLOCK_INTERNAL_BIT = 0x2
_BLOCK_RESERVED_BIT = 0x1


def _check_width(name: str, value: object, mask: int) -> None:
    """Refuse anything that is not a non-negative int of the given width."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > mask:
        raise PstFormatError(f"{name} must be an unsigned {mask.bit_length()}-bit integer, got {value!r}")


def _unpack(fmt: str, buf: bytes | bytearray | memoryview, offset: int, what: str) -> tuple[int, ...]:
    """`struct.unpack_from` that fails closed: any misuse is a PstFormatError.

    A negative offset is refused explicitly. `struct` would count it from the
    end of the buffer, and an offset that went negative through file-driven
    arithmetic must not be allowed to read somewhere plausible.
    """
    if offset < 0:
        raise PstFormatError(f"{what}: negative offset {offset}")
    try:
        return struct.unpack_from(fmt, buf, offset)
    except struct.error as exc:
        raise PstFormatError(f"{what}: {exc} (offset {offset}, buffer of {len(buf)} bytes)") from exc


class NodeIdType(IntEnum):
    """The 5-bit `nidType` of a NID — [MS-PST] 2.2.2.1, table of NID_TYPE_* values.

    Members carry the specification's names; `debug_name` gives the name
    upstream prints, which is what the goldens contain.
    """

    HID = 0x00
    INTERNAL = 0x01
    NORMAL_FOLDER = 0x02
    SEARCH_FOLDER = 0x03
    NORMAL_MESSAGE = 0x04
    ATTACHMENT = 0x05
    SEARCH_UPDATE_QUEUE = 0x06
    SEARCH_CRITERIA_OBJECT = 0x07
    ASSOC_MESSAGE = 0x08
    CONTENTS_TABLE_INDEX = 0x0A
    RECEIVE_FOLDER_TABLE = 0x0B
    OUTGOING_QUEUE_TABLE = 0x0C
    HIERARCHY_TABLE = 0x0D
    CONTENTS_TABLE = 0x0E
    ASSOC_CONTENTS_TABLE = 0x0F
    SEARCH_CONTENTS_TABLE = 0x10
    ATTACHMENT_TABLE = 0x11
    RECIPIENT_TABLE = 0x12
    SEARCH_TABLE_INDEX = 0x13
    LTP = 0x1F

    @property
    def debug_name(self) -> str:
        """The variant name upstream's `Debug` prints for this type."""
        return _DEBUG_NAMES[self]

    @classmethod
    def from_debug_name(cls, name: str) -> NodeIdType:
        """The inverse of `debug_name`, for parsing the oracle's output."""
        try:
            return _TYPES_BY_DEBUG_NAME[name]
        except KeyError:
            raise PstFormatError(f"unknown node type name {name!r}") from None


# Upstream's enum variant names, keyed by our members. Both spellings are
# fixed: ours by the specification, theirs by the goldens.
_DEBUG_NAMES: dict[NodeIdType, str] = {
    NodeIdType.HID: "HeapNode",
    NodeIdType.INTERNAL: "Internal",
    NodeIdType.NORMAL_FOLDER: "NormalFolder",
    NodeIdType.SEARCH_FOLDER: "SearchFolder",
    NodeIdType.NORMAL_MESSAGE: "NormalMessage",
    NodeIdType.ATTACHMENT: "Attachment",
    NodeIdType.SEARCH_UPDATE_QUEUE: "SearchUpdateQueue",
    NodeIdType.SEARCH_CRITERIA_OBJECT: "SearchCriteria",
    NodeIdType.ASSOC_MESSAGE: "AssociatedMessage",
    NodeIdType.CONTENTS_TABLE_INDEX: "ContentsTableIndex",
    NodeIdType.RECEIVE_FOLDER_TABLE: "ReceiveFolderTable",
    NodeIdType.OUTGOING_QUEUE_TABLE: "OutgoingQueueTable",
    NodeIdType.HIERARCHY_TABLE: "HierarchyTable",
    NodeIdType.CONTENTS_TABLE: "ContentsTable",
    NodeIdType.ASSOC_CONTENTS_TABLE: "AssociatedContentsTable",
    NodeIdType.SEARCH_CONTENTS_TABLE: "SearchContentsTable",
    NodeIdType.ATTACHMENT_TABLE: "AttachmentTable",
    NodeIdType.RECIPIENT_TABLE: "RecipientTable",
    NodeIdType.SEARCH_TABLE_INDEX: "SearchTableIndex",
    NodeIdType.LTP: "ListsTablesProperties",
}
_TYPES_BY_DEBUG_NAME = {name: member for member, name in _DEBUG_NAMES.items()}


@dataclass(frozen=True, slots=True)
class NodeId:
    """A NID — [MS-PST] 2.2.2.1. 32 bits: low 5 the type, high 27 the index."""

    raw: int

    SIZE: ClassVar[int] = struct.calcsize(NODE_ID_FORMAT)

    def __post_init__(self) -> None:
        _check_width("NodeId", self.raw, _U32)

    @classmethod
    def from_parts(cls, id_type: NodeIdType, index: int) -> NodeId:
        """Build a NID from its type and index; either out of range is refused."""
        try:
            id_type = NodeIdType(id_type)
        except ValueError:
            raise PstFormatError(f"unknown node id type {id_type!r}") from None
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index <= MAX_NODE_INDEX:
            raise PstFormatError(f"node index {index!r} does not fit in {32 - _NODE_TYPE_BITS} bits")
        return cls((index << _NODE_TYPE_BITS) | int(id_type))

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> NodeId:
        """Read a NID from `buf` at `offset`. Short buffer → PstFormatError."""
        (raw,) = _unpack(NODE_ID_FORMAT, buf, offset, "NodeId")
        return cls(raw)

    def pack(self) -> bytes:
        """The on-disk bytes; exists so a round-trip can be tested."""
        return struct.pack(NODE_ID_FORMAT, self.raw)

    @property
    def id_type(self) -> NodeIdType:
        """The node's type; a value the enum does not know is refused here."""
        try:
            return NodeIdType(self.raw & _NODE_TYPE_MASK)
        except ValueError:
            # Spell out the raw value rather than format `self`: `__str__` asks for
            # `id_type`, and the two must not chase each other.
            raise PstFormatError(
                f"unknown node id type 0x{self.raw & _NODE_TYPE_MASK:02X} in NodeId 0x{self.raw:08X}"
            ) from None

    @property
    def index(self) -> int:
        return self.raw >> _NODE_TYPE_BITS

    def __str__(self) -> str:
        try:
            name = self.id_type.debug_name
        except PstFormatError:
            return f"NodeId {{ invalid: 0x{self.raw:08X} }}"
        return f"NodeId {{ {name}: 0x{self.index:X} }}"


# The fixed NIDs of [MS-PST] 2.4.1 — the nodes every store has by name.
NID_MESSAGE_STORE = NodeId(0x21)
NID_NAME_TO_ID_MAP = NodeId(0x61)
NID_NORMAL_FOLDER_TEMPLATE = NodeId(0xA1)
NID_SEARCH_FOLDER_TEMPLATE = NodeId(0xC1)
NID_ROOT_FOLDER = NodeId(0x122)
NID_SEARCH_MANAGEMENT_QUEUE = NodeId(0x1E1)
NID_SEARCH_ACTIVITY_LIST = NodeId(0x201)
NID_RESERVED1 = NodeId(0x241)
NID_SEARCH_DOMAIN_OBJECT = NodeId(0x261)
NID_SEARCH_GATHERER_QUEUE = NodeId(0x281)
NID_SEARCH_GATHERER_DESCRIPTOR = NodeId(0x2A1)
NID_RESERVED2 = NodeId(0x2E1)
NID_RESERVED3 = NodeId(0x301)
NID_SEARCH_GATHERER_FOLDER_QUEUE = NodeId(0x321)


@dataclass(frozen=True, slots=True)
class BlockId:
    """A BID — [MS-PST] 2.2.2.2. 64 bits: bit 1 "internal", bit 0 reserved, rest index.

    An internal block is an XBLOCK, XXBLOCK or subnode B-tree block — tree
    structure rather than data. The reserved bit is cleared for B-tree
    lookups (`search_key`), which is how a BID read from a record and a BID
    read from a B-tree entry compare equal.
    """

    raw: int

    SIZE: ClassVar[int] = struct.calcsize(BLOCK_ID_FORMAT)

    def __post_init__(self) -> None:
        _check_width("BlockId", self.raw, _U64)

    @classmethod
    def from_parts(cls, is_internal: bool, index: int) -> BlockId:
        """Build a BID from its flag and index; an index over 62 bits is refused."""
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index <= MAX_BLOCK_INDEX:
            raise PstFormatError(f"block index {index!r} does not fit in {64 - _BLOCK_FLAG_BITS} bits")
        flags = _BLOCK_INTERNAL_BIT if is_internal else 0
        return cls((index << _BLOCK_FLAG_BITS) | flags)

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> BlockId:
        """Read a BID from `buf` at `offset`. Short buffer → PstFormatError."""
        (raw,) = _unpack(BLOCK_ID_FORMAT, buf, offset, "BlockId")
        return cls(raw)

    def pack(self) -> bytes:
        return struct.pack(BLOCK_ID_FORMAT, self.raw)

    @property
    def is_internal(self) -> bool:
        return self.raw & _BLOCK_INTERNAL_BIT == _BLOCK_INTERNAL_BIT

    @property
    def index(self) -> int:
        return self.raw >> _BLOCK_FLAG_BITS

    @property
    def search_key(self) -> int:
        """What the block B-tree is keyed on: the raw id with the reserved bit cleared."""
        return self.raw & ~_BLOCK_RESERVED_BIT & _U64

    def __str__(self) -> str:
        kind = "internal" if self.is_internal else "leaf"
        return f"BlockId {{ {kind}: 0x{self.index:X} }}"


@dataclass(frozen=True, slots=True)
class PageId:
    """The id of a B-tree or map page. Same 64-bit slot as a BID, no bit layout.

    A page id has no internal flag and no reserved bit; the whole value is
    the index and the search key. It is a separate type so that a page ref
    cannot be handed to something that expects a data block.
    """

    raw: int

    SIZE: ClassVar[int] = struct.calcsize(BLOCK_ID_FORMAT)

    def __post_init__(self) -> None:
        _check_width("PageId", self.raw, _U64)

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> PageId:
        (raw,) = _unpack(BLOCK_ID_FORMAT, buf, offset, "PageId")
        return cls(raw)

    def pack(self) -> bytes:
        return struct.pack(BLOCK_ID_FORMAT, self.raw)

    @property
    def is_internal(self) -> bool:
        return False

    @property
    def index(self) -> int:
        return self.raw

    @property
    def search_key(self) -> int:
        return self.raw

    def __str__(self) -> str:
        return f"PageId: 0x{self.raw:X}"


@dataclass(frozen=True, slots=True)
class ByteIndex:
    """An IB — [MS-PST] 2.2.2.3: a 64-bit byte offset from the start of the file.

    Deliberately not an int. An offset plus an offset is meaningless, and a
    frozen dataclass has no `__add__`, so the mistake is a `TypeError` at
    the line that makes it rather than a wrong read three layers down.
    """

    value: int

    SIZE: ClassVar[int] = struct.calcsize(BYTE_INDEX_FORMAT)

    def __post_init__(self) -> None:
        _check_width("ByteIndex", self.value, _U64)

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> ByteIndex:
        (value,) = _unpack(BYTE_INDEX_FORMAT, buf, offset, "ByteIndex")
        return cls(value)

    def pack(self) -> bytes:
        return struct.pack(BYTE_INDEX_FORMAT, self.value)

    def __str__(self) -> str:
        return f"ByteIndex {{ 0x{self.value:X} }}"


@dataclass(frozen=True, slots=True)
class BlockRef:
    """A BREF — [MS-PST] 2.2.2.4: a block id and the byte offset of its bytes."""

    block: BlockId
    index: ByteIndex

    SIZE: ClassVar[int] = struct.calcsize(BLOCK_REF_FORMAT)

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> BlockRef:
        """Read a BREF from `buf` at `offset`. Short buffer → PstFormatError."""
        block, index = _unpack(BLOCK_REF_FORMAT, buf, offset, "BlockRef")
        return cls(BlockId(block), ByteIndex(index))

    def pack(self) -> bytes:
        return struct.pack(BLOCK_REF_FORMAT, self.block.raw, self.index.value)

    def __str__(self) -> str:
        return f"BlockRef {{ block: {self.block}, index: {self.index} }}"


@dataclass(frozen=True, slots=True)
class PageRef:
    """A BREF whose block is a page — the header's NBT/BBT roots, and every B-tree child."""

    page: PageId
    index: ByteIndex

    SIZE: ClassVar[int] = struct.calcsize(BLOCK_REF_FORMAT)

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> PageRef:
        page, index = _unpack(BLOCK_REF_FORMAT, buf, offset, "PageRef")
        return cls(PageId(page), ByteIndex(index))

    def pack(self) -> bytes:
        return struct.pack(BLOCK_REF_FORMAT, self.page.raw, self.index.value)

    def __str__(self) -> str:
        return f"PageRef {{ page: {self.page}, index: {self.index} }}"
