"""Heap-on-Node (HN) — the allocator a node's bytes are carved up by, and the two ids into it.

Ported from: crates/pst/src/ltp/heap.rs, crates/pst/src/ltp/read_write.rs (the HeapId
             and HeapNode read traits), and the HNID arm of ltp/prop_context.rs
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.3.1 HN, 2.3.1.1 HID, 2.3.1.2 HNHDR, 2.3.1.3 HNPAGEHDR,
             2.3.1.4 HNBITMAPHDR, 2.3.1.5 HNPAGEMAP, 2.3.3.2 HNID

Everything above the NDB — a property context, a table context, the B-tree
they are both built on (`pypst.ltp.tree`) — lives in a heap laid over one
node's data. The node's bytes come from `pypst.ndb.block` one data block
at a time, and each of those blocks is a **heap block**: a short header, the
items, and at `ibHnpm` a page map ([MS-PST] 2.3.1.5) of `cAlloc + 1` offsets
whose consecutive differences are the item sizes. Block 0 starts with the
HNHDR ([MS-PST] 2.3.1.2: `bSig` 0xEC, `bClientSig` naming the structure on
top, `hidUserRoot`, eight fill-level nibbles); block 8 and every 128th
block after it start with an HNBITMAPHDR ([MS-PST] 2.3.1.4: the offset and
a 64-byte fill-level map); every other block starts with the two-byte
HNPAGEHDR ([MS-PST] 2.3.1.3). The fill levels are read and carried, never
used: they are an allocator's hint, and this reader allocates nothing.

**Two ids that share one wire format.** An **HID** ([MS-PST] 2.3.1.1) is
32 bits: five type bits that MUST be zero, an 11-bit 1-based item index (0
is the null HID) and a 16-bit block index. An **HNID** ([MS-PST] 2.3.3.2) is
the same 32 bits read differently: with zero type bits it is an HID into
this heap, with any other type it is the NID of a sub-node of the same node
whose data IS the value. Upstream keeps them apart with `HeapId` and `NodeId`
plus a match in the property reader; here they are two frozen classes,
`HeapId` and `HeapNodeId`, and the second converts to the first only through
`as_heap`. Conflating them reads *some* bytes from the wrong place — which is
why the todo names it as the trap.

**The heap's blocks are the node's blocks.** An HID's block index counts the
data tree's leaf blocks in order, each with its own header and page map, and
the block boundaries are those blocks' own `cb` — never fixed 8 KB slices of
the joined bytes (`BlockReader.read_data_blocks` keeps them apart; upstream
collects `DataTree::blocks` the same way).

**What is verified, and where — exactly upstream's checks.** Building a
`HeapNode` reads block 0's HNHDR (`HeapNodeHeader::read`): `bSig` == 0xEC,
`bClientSig` one of the nine values of [MS-PST] 2.3.1.2 (`HeapNodeType`),
`hidUserRoot` with zero type bits. A page map is read on first use of its
block (`HeapNodeInner::find_entry`): the block-kind header must be present
(12, 2 or 66 bytes), then at its offset `cAlloc`, `cFree` and `cAlloc + 1`
offsets, all inside the block; the offsets must be non-decreasing
(`InvalidHeapPageAllocOffset`), and the number of zero-length items must
equal `cFree` (`InvalidHeapPageFreeCount`). `get` refuses an HID whose block
index is past the last block (`HeapBlockIndexNotFound`), whose item index is
0 (`InvalidHeapIndex`) or past `cAlloc` (`HeapAllocIndexNotFound`). Not
checked, as upstream: that `ibHnpm` is 2-byte aligned ([MS-PST] 2.3.1.5
says it is; `pstd-inline-cid.pst`'s root-folder heap has it at 121 and
upstream reads it), that items do not overlap the header or the page map,
that the fill levels agree with anything.

**Divergence: an item outside its block is refused, not sliced.** Upstream
indexes `&block[start..end]` and would panic on an offset past `cb`; every
`rgibAlloc` entry here must be ≤ the block's length or the page map is
`PstFormatError`.

**Divergence: a zero-length item is refused.** A zero difference in
`rgibAlloc` is how a freed item is recorded ([MS-PST] 2.3.1.5 `cFree`);
upstream's `find_entry` returns the empty slice and lets the caller decode
nothing. A live reference to a freed item is a dangling pointer, so `get`
raises `PstFormatError`. No golden in the corpus resolves an HID to an empty
value, so the oracle is not contradicted on any store this port is tested
against; if a real store does it, this is the paragraph to revisit.

**Divergence: counts are bounded.** The allocations parsed across a heap's
blocks are checked against `limits.max_heap_items` — the format's own bound
(65 536 blocks × 2 047 items) by default — so a page map claiming a `cAlloc`
of 65 535 in every block cannot buy a proportionate allocation.

Nothing but `PstError` subclasses escapes for any input bytes: a sub-node
absent from the tree is `PstNotFoundError` (a `PstFormatError`), everything
else about the bytes is `PstFormatError`, and only a limit is `PstLimitError`.
"""

from __future__ import annotations

import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar

from pypst.errors import PstFormatError, PstNotFoundError
from pypst.limits import DEFAULT_LIMITS, Limits, check_count
from pypst.ndb.block import BlockReader, SubNodeLeafEntry
from pypst.ndb.ids import NodeId, NodeIdType, _unpack
from pypst.ndb.page import NodeBTreeEntry

__all__ = [
    "BITMAP_HEADER_FORMAT",
    "BITMAP_HEADER_SIZE",
    "BITMAP_PERIOD",
    "FIRST_BITMAP_BLOCK",
    "HEAP_HEADER_FORMAT",
    "HEAP_HEADER_SIZE",
    "HEAP_ID_FORMAT",
    "HEAP_SIGNATURE",
    "MAX_HEAP_ITEM_INDEX",
    "PAGE_HEADER_FORMAT",
    "PAGE_HEADER_SIZE",
    "PAGE_MAP_FORMAT",
    "PAGE_MAP_SIZE",
    "HeapId",
    "HeapNode",
    "HeapNodeHeader",
    "HeapNodeId",
    "HeapNodeType",
    "HeapPageMap",
]

_U32 = 0xFFFFFFFF

# [MS-PST] 2.3.1.1 HID: 5 type bits (0), 11 index bits (1-based), 16 block bits.
HEAP_ID_FORMAT = "<I"
_HID_TYPE_BITS = 5
_HID_TYPE_MASK = (1 << _HID_TYPE_BITS) - 1
_HID_INDEX_BITS = 11
_HID_INDEX_MASK = (1 << _HID_INDEX_BITS) - 1
_HID_BLOCK_SHIFT = _HID_TYPE_BITS + _HID_INDEX_BITS
MAX_HEAP_ITEM_INDEX = _HID_INDEX_MASK  # 2047, the largest 1-based index an HID can carry
_MAX_BLOCK_INDEX = 0xFFFF

# [MS-PST] 2.3.1.2 HNHDR: ibHnpm, bSig, bClientSig, hidUserRoot, rgbFillLevel.
HEAP_HEADER_FORMAT = "<HBBII"
HEAP_HEADER_SIZE = struct.calcsize(HEAP_HEADER_FORMAT)
HEAP_SIGNATURE = 0xEC
# [MS-PST] 2.3.1.3 HNPAGEHDR: ibHnpm. 2.3.1.4 HNBITMAPHDR: ibHnpm, 64 bytes of fill levels.
PAGE_HEADER_FORMAT = "<H"
PAGE_HEADER_SIZE = struct.calcsize(PAGE_HEADER_FORMAT)
BITMAP_HEADER_FORMAT = "<H64s"
BITMAP_HEADER_SIZE = struct.calcsize(BITMAP_HEADER_FORMAT)
# [MS-PST] 2.3.1.4: a bitmap header at block 8, then every 128 blocks (8, 136, 264, …).
FIRST_BITMAP_BLOCK = 8
BITMAP_PERIOD = 128
# [MS-PST] 2.3.1.5 HNPAGEMAP: cAlloc, cFree, then cAlloc + 1 u16 offsets.
PAGE_MAP_FORMAT = "<HH"
PAGE_MAP_SIZE = struct.calcsize(PAGE_MAP_FORMAT)
_OFFSET_SIZE = 2


class HeapNodeType(IntEnum):
    """`bClientSig` — [MS-PST] 2.3.1.2's table: what is built on top of the heap.

    Upstream's `HeapNodeType`; a value outside the table is refused when the
    header is read, as its `TryFrom<u8>` refuses it (the spec reserves them).
    """

    RESERVED1 = 0x6C
    TABLE = 0x7C
    RESERVED2 = 0x8C
    RESERVED3 = 0x9C
    RESERVED4 = 0xA5
    RESERVED5 = 0xAC
    TREE = 0xB5
    PROPERTIES = 0xBC
    RESERVED6 = 0xCC

    @classmethod
    def from_wire(cls, value: int) -> HeapNodeType:
        try:
            return cls(value)
        except ValueError:
            raise PstFormatError(f"unknown heap client signature 0x{value:02X}") from None


def _check_u32(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > _U32:
        raise PstFormatError(f"{name} must be an unsigned 32-bit integer, got {value!r}")


@dataclass(frozen=True, slots=True)
class HeapId:
    """An HID — [MS-PST] 2.3.1.1: an item in THIS heap, by block index and 1-based item index.

    The type bits must be zero: `HeapId(raw)` refuses anything else, as
    upstream's `HeapId::read` refuses a node type other than `HeapNode`.
    `HeapId(0)` is the null HID (an empty BTH's root, a null property).
    """

    raw: int

    SIZE: ClassVar[int] = struct.calcsize(HEAP_ID_FORMAT)

    def __post_init__(self) -> None:
        _check_u32("HeapId", self.raw)
        if self.raw & _HID_TYPE_MASK:
            raise PstFormatError(f"HeapId 0x{self.raw:08X} has type bits 0x{self.raw & _HID_TYPE_MASK:02X}, not HID")

    @classmethod
    def from_parts(cls, index: int, block_index: int = 0) -> HeapId:
        """Build an HID from its 1-based item index and block index (upstream's `HeapId::new`).

        An index over 11 bits or a block index over 16 is refused; 0 is
        allowed, because that is how the null HID is spelled.
        """
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index <= MAX_HEAP_ITEM_INDEX:
            raise PstFormatError(f"heap item index {index!r} does not fit in {_HID_INDEX_BITS} bits")
        if isinstance(block_index, bool) or not isinstance(block_index, int) or not 0 <= block_index <= _MAX_BLOCK_INDEX:
            raise PstFormatError(f"heap block index {block_index!r} does not fit in 16 bits")
        return cls((block_index << _HID_BLOCK_SHIFT) | (index << _HID_TYPE_BITS))

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> HeapId:
        """Read an HID from `buf` at `offset`; short buffer or nonzero type bits → PstFormatError."""
        (raw,) = _unpack(HEAP_ID_FORMAT, buf, offset, "HeapId")
        return cls(raw)

    def pack(self) -> bytes:
        return struct.pack(HEAP_ID_FORMAT, self.raw)

    @property
    def is_null(self) -> bool:
        """The all-zero HID — upstream's `u32::from(heap_id) == 0`."""
        return self.raw == 0

    @property
    def index(self) -> int:
        """`hidIndex`, 1-based; 0 only in the null HID (and in a corrupt one, which `get` refuses)."""
        return (self.raw >> _HID_TYPE_BITS) & _HID_INDEX_MASK

    @property
    def block_index(self) -> int:
        """`hidBlockIndex`, 0-based into the node's data blocks."""
        return self.raw >> _HID_BLOCK_SHIFT

    def __str__(self) -> str:
        # Upstream's `Debug`: the HID printed as the NodeId it wraps.
        return f"HeapId(NodeId {{ HeapNode: 0x{self.raw >> _HID_TYPE_BITS:X} }})"


@dataclass(frozen=True, slots=True)
class HeapNodeId:
    """An HNID — [MS-PST] 2.3.3.2: an HID into the heap, or the NID of a sub-node, by its type bits.

    Deliberately not a `HeapId` and not a `NodeId`: a caller must ask which
    it is (`as_heap` / `as_node`) before reading anything. The split is
    upstream's `match NodeId::from(value).id_type()` in the property and
    table readers, where `HeapNode` is an HID and every other type — known
    or not — is a sub-node id.
    """

    raw: int

    SIZE: ClassVar[int] = struct.calcsize(HEAP_ID_FORMAT)

    def __post_init__(self) -> None:
        _check_u32("HeapNodeId", self.raw)

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> HeapNodeId:
        (raw,) = _unpack(HEAP_ID_FORMAT, buf, offset, "HeapNodeId")
        return cls(raw)

    def pack(self) -> bytes:
        return struct.pack(HEAP_ID_FORMAT, self.raw)

    @property
    def is_heap(self) -> bool:
        return (self.raw & _HID_TYPE_MASK) == NodeIdType.HID

    @property
    def as_heap(self) -> HeapId | None:
        """The HID this names, or None when the type bits say sub-node."""
        return HeapId(self.raw) if self.is_heap else None

    @property
    def as_node(self) -> NodeId | None:
        """The sub-node NID this names, or None when the type bits say heap."""
        return None if self.is_heap else NodeId(self.raw)

    def __str__(self) -> str:
        heap = self.as_heap
        return str(heap) if heap is not None else str(NodeId(self.raw))


@dataclass(frozen=True, slots=True)
class HeapNodeHeader:
    """HNHDR — [MS-PST] 2.3.1.2, the first 12 bytes of block 0.

    `fill_levels` are the eight 4-bit values of `rgbFillLevel`, low nibble
    first, as upstream's `unpack_fill_levels` orders them.
    """

    page_map_offset: int
    client_signature: HeapNodeType
    user_root: HeapId
    fill_levels: tuple[int, ...]

    SIZE: ClassVar[int] = HEAP_HEADER_SIZE

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> HeapNodeHeader:
        """Upstream's `HeapNodeHeader::read`: signature, client signature, user root, in that order."""
        page_map_offset, signature, client, user_root, fill = _unpack(HEAP_HEADER_FORMAT, buf, offset, "HNHDR")
        if signature != HEAP_SIGNATURE:
            raise PstFormatError(f"heap signature 0x{signature:02X} != 0x{HEAP_SIGNATURE:02X}")
        return cls(page_map_offset, HeapNodeType.from_wire(client), HeapId(user_root), _unpack_fill_levels(fill, 8))


def _unpack_fill_levels(packed: int | bytes, count: int) -> tuple[int, ...]:
    """`count` 4-bit fill levels, low nibble of the first byte first."""
    value = packed if isinstance(packed, int) else int.from_bytes(packed, "little")
    return tuple((value >> (4 * i)) & 0xF for i in range(count))


@dataclass(frozen=True, slots=True)
class HeapPageMap:
    """One heap block's HNPAGEMAP — [MS-PST] 2.3.1.5 — as item spans.

    `offsets` is `rgibAlloc` (cAlloc + 1 entries); item `i` (0-based) is
    `offsets[i]:offsets[i + 1]`. `free_count` is `cFree`, already checked
    against the zero-length spans. `fill_levels` is the block's
    HNBITMAPHDR map (128 nibbles) when it has one, else None.
    """

    offsets: tuple[int, ...]
    free_count: int
    fill_levels: tuple[int, ...] | None

    @property
    def count(self) -> int:
        """`cAlloc`."""
        return len(self.offsets) - 1

    def size(self, index: int) -> int:
        """The length of item `index` (0-based); the caller has checked the range."""
        return self.offsets[index + 1] - self.offsets[index]

    @property
    def sizes(self) -> tuple[int, ...]:
        return tuple(self.offsets[i + 1] - self.offsets[i] for i in range(self.count))


def _is_bitmap_block(block_index: int) -> bool:
    """[MS-PST] 2.3.1.4: block 8 and every 128th after it — upstream's `bitmap % 128 == 8`."""
    return block_index % BITMAP_PERIOD == FIRST_BITMAP_BLOCK


class HeapNode:
    """A heap over one node's data blocks — upstream's `HeapNode` + `HeapNodeInner`.

    `blocks` are the node's data blocks in order (`BlockReader.read_data_blocks`);
    `subnodes` is the node's sub-node tree (`BlockReader.read_subnode_tree`),
    where an HNID that is a NID is resolved, and `reader` reads those
    sub-nodes' data. Without a reader every sub-node HNID is
    `PstNotFoundError`, which is what a heap with no sub-node tree answers
    too. `from_node` does all of that from one B-tree entry.

    Block 0's HNHDR is read at construction; each block's page map on its
    first use, and kept.
    """

    __slots__ = ("_blocks", "_header", "_items_seen", "_limits", "_page_maps", "_reader", "_subnodes")

    def __init__(
        self,
        blocks: Sequence[bytes],
        *,
        subnodes: Mapping[NodeId, SubNodeLeafEntry] | None = None,
        reader: BlockReader | None = None,
        limits: Limits = DEFAULT_LIMITS,
    ) -> None:
        if not blocks:
            # Upstream: `data.first().ok_or(UnexpectedEof)`.
            raise PstFormatError("heap node has no data blocks")
        self._blocks: tuple[bytes, ...] = tuple(blocks)
        self._subnodes: Mapping[NodeId, SubNodeLeafEntry] = subnodes if subnodes is not None else {}
        self._reader = reader
        self._limits = limits
        self._header = HeapNodeHeader.unpack_from(self._blocks[0], 0)
        self._page_maps: dict[int, HeapPageMap] = {}
        self._items_seen = 0

    @classmethod
    def from_node(cls, reader: BlockReader, entry: NodeBTreeEntry | SubNodeLeafEntry, limits: Limits | None = None) -> HeapNode:
        """The heap over the node `entry` names — its data blocks and its sub-node tree, read through `reader`.

        A `SubNodeLeafEntry` works too: an attachment's or an embedded
        message's property context is a heap over a sub-node, with that
        sub-node's own sub-node tree (`bidSub`) for its HNIDs.
        """
        limits = reader.limits if limits is None else limits
        blocks = reader.read_data_blocks(entry.data)
        subnodes = reader.read_subnode_tree(entry.sub_node) if entry.sub_node is not None else {}
        return cls(blocks, subnodes=subnodes, reader=reader, limits=limits)

    # --- header ---------------------------------------------------------------

    @property
    def header(self) -> HeapNodeHeader:
        return self._header

    @property
    def client_signature(self) -> HeapNodeType:
        """`bClientSig`: 0xBC for a PC, 0x7C for a TC, 0xB5 for a bare BTH."""
        return self._header.client_signature

    @property
    def user_root(self) -> HeapId:
        """`hidUserRoot`: the BTHHEADER of a PC, the TCINFO of a TC."""
        return self._header.user_root

    @property
    def block_count(self) -> int:
        return len(self._blocks)

    @property
    def limits(self) -> Limits:
        return self._limits

    def block(self, block_index: int) -> bytes:
        """The raw bytes of heap block `block_index` (`PstFormatError` past the last)."""
        if not 0 <= block_index < len(self._blocks):
            raise PstFormatError(f"heap block index {block_index} not found: the heap has {len(self._blocks)} block(s)")
        return self._blocks[block_index]

    # --- page maps ------------------------------------------------------------

    def page_map(self, block_index: int) -> HeapPageMap:
        """Block `block_index`'s page map, parsed on first use (upstream parses it on every `find_entry`)."""
        cached = self._page_maps.get(block_index)
        if cached is not None:
            return cached
        page_map = self._parse_page_map(block_index, self.block(block_index))
        self._items_seen += page_map.count
        check_count(self._items_seen, self._limits.max_heap_items, "heap allocations")
        self._page_maps[block_index] = page_map
        return page_map

    @staticmethod
    def _parse_page_map(block_index: int, block: bytes) -> HeapPageMap:
        what = f"heap block {block_index}"
        fill_levels: tuple[int, ...] | None = None
        if block_index == 0:
            page_map_offset = HeapNodeHeader.unpack_from(block, 0).page_map_offset
        elif _is_bitmap_block(block_index):
            page_map_offset, packed = _unpack(BITMAP_HEADER_FORMAT, block, 0, f"{what} HNBITMAPHDR")
            fill_levels = _unpack_fill_levels(packed, 128)
        else:
            (page_map_offset,) = _unpack(PAGE_HEADER_FORMAT, block, 0, f"{what} HNPAGEHDR")
        count, free_count = _unpack(PAGE_MAP_FORMAT, block, page_map_offset, f"{what} HNPAGEMAP")
        offsets = _unpack(f"<{count + 1}H", block, page_map_offset + PAGE_MAP_SIZE, f"{what} rgibAlloc")
        # Upstream's `HeapNodePageMap::try_from`: each offset at least the last;
        # a zero step is a freed item, counted against cFree. The bound on
        # the block's length is this port's (module docstring).
        last = offsets[0]
        freed = 0
        for offset in offsets[1:]:
            if offset < last:
                raise PstFormatError(f"{what}: rgibAlloc offset {offset} is before the previous {last}")
            if offset == last:
                freed += 1
            last = offset
        if last > len(block):
            raise PstFormatError(f"{what}: rgibAlloc offset {last} is past the block's {len(block)} bytes")
        if freed != free_count:
            raise PstFormatError(f"{what}: cFree {free_count} != {freed} zero-length allocation(s)")
        return HeapPageMap(tuple(offsets), free_count, fill_levels)

    # --- items ----------------------------------------------------------------

    def get(self, hid: HeapId) -> memoryview:
        """The bytes of the item `hid` names — upstream's `find_entry`, with the divergences in the module docstring.

        A view into the block, not a copy: slice it, decode it, but do not
        hold it past the heap. `PstFormatError` for a block index past the
        last block, an item index of 0 or past `cAlloc`, or a zero-length
        (freed) item.
        """
        if not isinstance(hid, HeapId):
            # The T02 trap, refused by name: an HNID must be asked `as_heap` first.
            raise TypeError(f"HeapNode.get takes a HeapId, not {type(hid).__name__}")
        block_index = hid.block_index
        block = self.block(block_index)
        page_map = self.page_map(block_index)
        index = hid.index
        if index == 0:
            raise PstFormatError(f"{hid} has item index 0 (the null HID)")
        if index > page_map.count:
            raise PstFormatError(f"{hid}: item index {index} is past the block's {page_map.count} allocation(s)")
        start, end = page_map.offsets[index - 1], page_map.offsets[index]
        if start == end:
            raise PstFormatError(f"{hid} names a freed (zero-length) allocation")
        return memoryview(block)[start:end]

    def get_hnid(self, hnid: HeapNodeId) -> bytes:
        """The bytes an HNID names: a heap item, or a sub-node's whole data.

        The sub-node path is upstream's `PropertyValueRecord::Node` arm:
        the node's sub-node tree must hold the NID (`PstNotFoundError`
        otherwise, as for a heap with no sub-node tree at all), and its
        data tree is read whole through the `BlockReader`.
        """
        if not isinstance(hnid, HeapNodeId):
            raise TypeError(f"HeapNode.get_hnid takes a HeapNodeId, not {type(hnid).__name__}")
        heap = hnid.as_heap
        if heap is not None:
            return bytes(self.get(heap))
        node = NodeId(hnid.raw)
        entry = self._subnodes.get(node)
        if entry is None or self._reader is None:
            raise PstNotFoundError(f"sub-node {node} is not in the node's sub-node tree")
        return self._reader.read_data(entry.data)

    def get_hnid_blocks(self, hnid: HeapNodeId) -> list[bytes]:
        """The same bytes as `get_hnid`, but as the BLOCKS they are stored in, in order.

        `get_hnid` joins a sub-node's data tree into one `bytes`; a table
        context's row matrix must not be joined, because its rows are
        packed per block and never straddle a block boundary ([MS-PST]
        2.3.4.4 — upstream reads `data_tree.blocks(...)` and counts rows
        block by block). A heap item is one block by construction.
        """
        if not isinstance(hnid, HeapNodeId):
            raise TypeError(f"HeapNode.get_hnid_blocks takes a HeapNodeId, not {type(hnid).__name__}")
        heap = hnid.as_heap
        if heap is not None:
            return [bytes(self.get(heap))]
        node = NodeId(hnid.raw)
        entry = self._subnodes.get(node)
        if entry is None or self._reader is None:
            raise PstNotFoundError(f"sub-node {node} is not in the node's sub-node tree")
        return self._reader.read_data_blocks(entry.data)
