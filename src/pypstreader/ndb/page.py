"""Pages — the 512-byte units the NDB's B-trees and the density list live in.

Ported from: crates/pst/src/ndb/page.rs (the Unicode read arms) and the
             `UnicodeBTreePageReadWrite::read` / `DensityListPageReadWrite`
             defaults in crates/pst/src/ndb/read_write.rs
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.2.2.7 Pages, 2.2.2.7.1 PAGETRAILER, 2.2.2.7.2 DLISTPAGE,
             2.2.2.7.7 BTrees (BTPAGE, BTENTRY, BBTENTRY, NBTENTRY), 5.5 signature

A page is 512 bytes: 496 of data and a 16-byte trailer that names the page's
type, carries a CRC of the data and a signature derived from where the page
sits, and repeats the page's id. This module parses the trailer, the two
kinds of B-tree page (intermediate pages of BTENTRYs and leaf pages of
BBTENTRYs or NBTENTRYs), and the density list page. It never reads the
file: a page arrives as 512 bytes that `pypstreader.ndb.btree` fetched, and it is
refused or turned into frozen values here. The walks that follow page
references are in `pypstreader.ndb.btree`.

**Unicode arm only (ADR-0003).** Upstream's ANSI pages (12-byte trailer,
496-byte entry area, 32-bit ids) are not ported.

**What is not ported, and why.** The four allocation-map page types (AMap,
PMap, FMap, FPMap — [MS-PST] 2.2.2.7.3–2.2.2.7.6) exist so that a WRITER
can find free space. Nothing on the read path consults them: a reader
reaches every block through the block B-tree. `PageType` still names them,
because a trailer carrying one of their values is a valid page that is
merely the wrong kind, and that must be reported as such rather than as an
unknown type. Their contents are never parsed. Upstream's `find_free_bits`
and the whole `MapPage` family are write-path code and stay behind.

**What is validated — exactly what upstream validates, in the same order.**
For a B-tree page (`UnicodeBTreePageReadWrite::read`): `cEnt ≤ cEntMax`;
`cbEnt ≥` the entry size for the page's level (larger is allowed — the
specification says `cbEnt` may exceed the structure for alignment and
MUST be used as the stride); `cEntMax ≤ 488 // cbEnt`; `cLevel ≤ 8`;
`dwPadding == 0`; `ptype` is BBT or NBT; the trailer CRC over the 496 data
bytes; and then, from the page constructors, `cLevel` in 1..=8 for an
intermediate page and 0 for a leaf. An NBTENTRY whose 8-byte `nid` does
not fit in 32 bits is refused (`InvalidNodeBTreeEntryNodeId`). For the
density list (`DensityListPageReadWrite::read`): `cEntDList ≤ 119`,
`wPadding == 0`, `rgPadding` all zero, `ptype == DL`, the CRC.

**Read but not validated — as upstream, and deliberately.** The trailer's
`wSig` is carried, never enforced. Upstream computes a page signature only
when it writes one; its read path never compares it, and the corpus proves
why that matters: `pstd-inline-cid.pst` (written by EMLtoPST, not Outlook)
has `wSig == 0` on every B-tree page and upstream's `read_btrees` reads it
cleanly. A check upstream lacks would refuse a store upstream reads, which
CLAUDE.md forbids. `PageTrailer.expected_signature(index)` says what the
value should be ([MS-PST] 2.2.2.7.1 and 5.5, upstream's
`PageType::signature`) so that a caller or a test can ask; nothing here
acts on it. The same holds for the trailer's `bid`: upstream never compares
it with the id the parent's BREF named, so neither does this module. And an
intermediate page's `ptype` may be BBT or NBT regardless of which tree it
is in, exactly as upstream's `UnicodeBTreeEntryPage::new` allows; only a
LEAF page must be the tree's own type.

**Divergence: `sub_node` and `parent` are `None` when zero.** This is not
a divergence from upstream, which does the same (`Option`), but it is one
from the draft in docs/INTERFACES.md, which had `parent: NodeId`. Upstream's
`Debug` — and so the goldens — print `Parent Node: None`.

**Not checked, as upstream.** Keys are not required to be sorted within a
page or bounded by the parent's key; a child's level is not required to be
one less than its parent's; `cRef`, `cb`, `bidData` and `nidParent` are
taken as read. Upstream reads real stores without those checks and this
port adds no refusal upstream lacks unless the module says so above.

Nothing but `PstError` subclasses escapes any parser here for any input.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar

from pypstreader.block_sig import compute_sig
from pypstreader.crc import compute_crc
from pypstreader.errors import PstFormatError
from pypstreader.ndb.ids import (
    BlockId,
    BlockRef,
    ByteIndex,
    NodeId,
    PageId,
    PageRef,
    _unpack,
)

__all__ = [
    "BTREE_ENTRIES_SIZE",
    "DENSITY_LIST_INDEX",
    "DENSITY_LIST_MAX_ENTRIES",
    "DENSITY_LIST_OFFSET",
    "MAX_BTREE_LEVEL",
    "PAGE_DATA_SIZE",
    "PAGE_SIZE",
    "BTreePage",
    "BlockBTreeEntry",
    "DensityListEntry",
    "DensityListPage",
    "IntermediateEntry",
    "NodeBTreeEntry",
    "PageTrailer",
    "PageType",
]

# [MS-PST] 2.2.2.7: every page is 512 bytes, the last 16 of which are the
# PAGETRAILER; the CRC covers the 496 before it.
PAGE_SIZE = 512
PAGE_TRAILER_SIZE = 16
PAGE_DATA_SIZE = PAGE_SIZE - PAGE_TRAILER_SIZE
PAGE_TRAILER_OFFSET = PAGE_DATA_SIZE

# [MS-PST] 2.2.2.7.1 PAGETRAILER, Unicode layout: ptype, ptypeRepeat, wSig,
# dwCRC, bid.
PAGE_TRAILER_FORMAT = "<BBHIQ"

# [MS-PST] 2.2.2.7.7.1 BTPAGE, Unicode layout: rgentries (488 bytes), then
# cEnt, cEntMax, cbEnt, cLevel, dwPadding. The trailer follows.
BTREE_ENTRIES_SIZE = 488
_BTREE_HEADER_FORMAT = "<BBBBI"
_BTREE_HEADER_OFFSET = BTREE_ENTRIES_SIZE

# `cLevel` is one byte and upstream refuses anything above 8
# (`InvalidBTreePageLevel`); `pypstreader.limits.MAX_BTREE_DEPTH` is chosen to
# match, so a tree upstream can open is never refused by the depth guard.
MAX_BTREE_LEVEL = 8

# [MS-PST] 2.2.2.7.7.2 BTENTRY: btkey (u64), BREF (bid, ib).
INTERMEDIATE_ENTRY_FORMAT = "<QQQ"
# [MS-PST] 2.2.2.7.7.3 BBTENTRY: BREF (bid, ib), cb, cRef, dwPadding.
BLOCK_ENTRY_FORMAT = "<QQHHI"
# [MS-PST] 2.2.2.7.7.4 NBTENTRY: nid (u64: a NID zero-extended), bidData,
# bidSub, nidParent, dwPadding.
NODE_ENTRY_FORMAT = "<QQQII"

# [MS-PST] 2.2.2.7.2 DLISTPAGE: at a fixed file offset; bFlags, cEntDList,
# wPadding, ulCurrentPage, then 476 bytes of u32 DLISTPAGEENTs (119 of
# them), 12 bytes of padding, the trailer.
DENSITY_LIST_OFFSET = 0x4200
DENSITY_LIST_INDEX = ByteIndex(DENSITY_LIST_OFFSET)
_DENSITY_LIST_HEADER_FORMAT = "<BBHI"
_DENSITY_LIST_ENTRIES_OFFSET = struct.calcsize(_DENSITY_LIST_HEADER_FORMAT)
_DENSITY_LIST_ENTRIES_SIZE = 476
DENSITY_LIST_MAX_ENTRIES = _DENSITY_LIST_ENTRIES_SIZE // 4
_DENSITY_LIST_PADDING_OFFSET = _DENSITY_LIST_ENTRIES_OFFSET + _DENSITY_LIST_ENTRIES_SIZE
_DENSITY_LIST_PADDING_SIZE = 12
_DENSITY_LIST_BACKFILL_COMPLETE = 0x01
# DLISTPAGEENT ([MS-PST] 2.2.2.7.2.1): 20 bits of AMap page number, 12 of free slots.
_DENSITY_LIST_PAGE_BITS = 20
_DENSITY_LIST_PAGE_MASK = (1 << _DENSITY_LIST_PAGE_BITS) - 1

_U32 = 0xFFFFFFFF


class PageType(IntEnum):
    """`ptype` — [MS-PST] 2.2.2.7.1. Members carry the spec's short names."""

    BBT = 0x80  # ptypeBBT: block B-tree page
    NBT = 0x81  # ptypeNBT: node B-tree page
    FMAP = 0x82  # ptypeFMap: free map page (not read)
    PMAP = 0x83  # ptypePMap: allocation page map page (not read)
    AMAP = 0x84  # ptypeAMap: allocation map page (not read)
    FPMAP = 0x85  # ptypeFPMap: free page map page (not read)
    DL = 0x86  # ptypeDL: density list page

    @classmethod
    def from_byte(cls, value: int) -> PageType:
        """The strict conversion: a value outside the table is refused, as upstream's `TryFrom`."""
        try:
            return cls(value)
        except ValueError:
            raise PstFormatError(f"unknown page type 0x{value:02X}") from None

    @property
    def is_signed(self) -> bool:
        """Whether the trailer carries a computed signature (BBT, NBT, DL) or zero (the maps)."""
        return self in (PageType.BBT, PageType.NBT, PageType.DL)

    def signature(self, index: int, page_id: int) -> int:
        """The `wSig` this page type must carry at byte offset `index` with id `page_id`.

        Upstream's `PageType::signature`: `compute_sig` of the two values
        truncated to 32 bits for the signed types, and 0 for the rest.
        """
        if self.is_signed:
            return compute_sig(index & _U32, page_id & _U32)
        return 0

    @property
    def debug_name(self) -> str:
        """The variant name upstream's `Debug` prints, which the goldens contain."""
        return _DEBUG_NAMES[self]

    def __str__(self) -> str:
        return self.debug_name


_DEBUG_NAMES: dict[PageType, str] = {
    PageType.BBT: "BlockBTree",
    PageType.NBT: "NodeBTree",
    PageType.FMAP: "FreeMap",
    PageType.PMAP: "AllocationPageMap",
    PageType.AMAP: "AllocationMap",
    PageType.FPMAP: "FreePageMap",
    PageType.DL: "DensityList",
}


@dataclass(frozen=True, slots=True)
class PageTrailer:
    """PAGETRAILER — [MS-PST] 2.2.2.7.1, Unicode layout, the last 16 bytes of a page."""

    page_type: PageType
    signature: int
    crc: int
    block_id: PageId

    SIZE: ClassVar[int] = PAGE_TRAILER_SIZE

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = PAGE_TRAILER_OFFSET) -> PageTrailer:
        """Read a trailer from `buf` at `offset` (default: where it sits in a page).

        Refuses `ptype != ptypeRepeat` and an unknown type, in that order,
        as upstream's `UnicodePageTrailer::read` does. Nothing else is
        checked here: the CRC and signature need the page's bytes and
        offset, which is `verify`.
        """
        ptype, ptype_repeat, signature, crc, block_id = _unpack(PAGE_TRAILER_FORMAT, buf, offset, "PageTrailer")
        if ptype != ptype_repeat:
            raise PstFormatError(f"page trailer ptype 0x{ptype:02X} != ptypeRepeat 0x{ptype_repeat:02X}")
        return cls(PageType.from_byte(ptype), signature, crc, PageId(block_id))

    def verify(self, page_bytes: bytes | bytearray | memoryview, index: ByteIndex) -> None:
        """Check the CRC over the page's 496 data bytes — upstream's one trailer check.

        `page_bytes` is the whole 512-byte page this trailer ends; `index`
        is the byte offset it was read from, used only to name the page in
        the refusal. The signature is NOT checked (module docstring).
        """
        if len(page_bytes) != PAGE_SIZE:
            raise PstFormatError(f"page at {index} is {len(page_bytes)} bytes; a page is {PAGE_SIZE}")
        crc = compute_crc(0, bytes(page_bytes[:PAGE_DATA_SIZE]))
        if crc != self.crc:
            raise PstFormatError(f"page CRC mismatch at {index}: computed 0x{crc:08X}, trailer 0x{self.crc:08X}")

    def expected_signature(self, index: ByteIndex) -> int:
        """The `wSig` a page of this type at `index` should carry — informational, never enforced."""
        return self.page_type.signature(index.value, self.block_id.raw)


# --- B-tree entries ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IntermediateEntry:
    """BTENTRY — [MS-PST] 2.2.2.7.7.2: a key and the child page holding keys ≥ it."""

    key: int
    ref: PageRef

    SIZE: ClassVar[int] = struct.calcsize(INTERMEDIATE_ENTRY_FORMAT)

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> IntermediateEntry:
        key, page, index = _unpack(INTERMEDIATE_ENTRY_FORMAT, buf, offset, "BTENTRY")
        return cls(key, PageRef(PageId(page), ByteIndex(index)))


@dataclass(frozen=True, slots=True)
class BlockBTreeEntry:
    """BBTENTRY — [MS-PST] 2.2.2.7.7.3: where a block is, how big, how shared.

    `size` is `cb`, the block's data length without trailer or padding —
    the number a data-block read uses. `ref_count` is `cRef`.
    """

    block: BlockRef
    size: int
    ref_count: int

    SIZE: ClassVar[int] = struct.calcsize(BLOCK_ENTRY_FORMAT)

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> BlockBTreeEntry:
        block, index, size, ref_count, _padding = _unpack(BLOCK_ENTRY_FORMAT, buf, offset, "BBTENTRY")
        return cls(BlockRef(BlockId(block), ByteIndex(index)), size, ref_count)

    @property
    def key(self) -> int:
        """What the block B-tree is ordered by: the BID with its reserved bit cleared."""
        return self.block.block.search_key


@dataclass(frozen=True, slots=True)
class NodeBTreeEntry:
    """NBTENTRY — [MS-PST] 2.2.2.7.7.4: a node, its data block, its subnode tree, its parent.

    `sub_node` is `None` when `bidSub` is zero (no subnode tree) and
    `parent` is `None` when `nidParent` is zero, as upstream's `Option`s.
    """

    node: NodeId
    data: BlockId
    sub_node: BlockId | None
    parent: NodeId | None

    SIZE: ClassVar[int] = struct.calcsize(NODE_ENTRY_FORMAT)

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> NodeBTreeEntry:
        nid, data, sub_node, parent, _padding = _unpack(NODE_ENTRY_FORMAT, buf, offset, "NBTENTRY")
        # The Unicode `nid` is 8 bytes holding a 32-bit NID zero-extended
        # ([MS-PST] 2.2.2.7.7.4); upstream refuses one that does not fit.
        if nid > _U32:
            raise PstFormatError(f"NBTENTRY nid 0x{nid:016X} does not fit in 32 bits")
        sub = BlockId(sub_node)
        return cls(
            node=NodeId(nid),
            data=BlockId(data),
            sub_node=None if sub.search_key == 0 else sub,
            parent=None if parent == 0 else NodeId(parent),
        )

    @property
    def key(self) -> int:
        """What the node B-tree is ordered by: the raw NID."""
        return self.node.raw


# The leaf entry type and its size for each kind of tree; an intermediate
# page holds BTENTRYs in either.
_LEAF_ENTRY_TYPES: dict[PageType, type[BlockBTreeEntry | NodeBTreeEntry]] = {
    PageType.BBT: BlockBTreeEntry,
    PageType.NBT: NodeBTreeEntry,
}


@dataclass(frozen=True, slots=True)
class BTreePage:
    """BTPAGE — [MS-PST] 2.2.2.7.7.1: one page of a node or block B-tree.

    `entries` are `IntermediateEntry`s when `level > 0`, else the leaf
    entries of the tree's kind (`trailer.page_type`). `max_entries` and
    `entry_size` are `cEntMax` and `cbEnt`, kept because a reader that
    checks them against the spec's table needs them.
    """

    level: int
    max_entries: int
    entry_size: int
    entries: tuple[IntermediateEntry, ...] | tuple[BlockBTreeEntry, ...] | tuple[NodeBTreeEntry, ...]
    trailer: PageTrailer

    SIZE: ClassVar[int] = PAGE_SIZE

    @property
    def is_leaf(self) -> bool:
        return self.level == 0

    @property
    def page_type(self) -> PageType:
        return self.trailer.page_type

    @classmethod
    def parse(cls, page_bytes: bytes | bytearray | memoryview, kind: PageType, index: ByteIndex) -> BTreePage:
        """Parse one 512-byte page of a tree of `kind` (BBT or NBT) read from `index`.

        The checks and their order are upstream's, listed in the module
        docstring; `index` is needed for the trailer's signature.
        """
        if kind not in _LEAF_ENTRY_TYPES:
            raise PstFormatError(f"{kind} is not a B-tree page type")
        if len(page_bytes) != PAGE_SIZE:
            raise PstFormatError(f"page at {index} is {len(page_bytes)} bytes; a page is {PAGE_SIZE}")

        count, max_entries, entry_size, level, padding = struct.unpack_from(
            _BTREE_HEADER_FORMAT, page_bytes, _BTREE_HEADER_OFFSET
        )
        if count > max_entries:
            raise PstFormatError(f"BTPAGE at {index}: cEnt {count} > cEntMax {max_entries}")
        # Larger than the structure is allowed ([MS-PST] 2.2.2.7.7.1: cbEnt
        # is the stride); smaller cannot hold an entry.
        if level == 0:
            entry_type: type[IntermediateEntry | BlockBTreeEntry | NodeBTreeEntry]
            entry_type = _LEAF_ENTRY_TYPES[kind]
        else:
            entry_type = IntermediateEntry
        if entry_size < entry_type.SIZE:
            raise PstFormatError(
                f"BTPAGE at {index}: cbEnt {entry_size} < {entry_type.SIZE} ({entry_type.__name__} at level {level})"
            )
        if max_entries > BTREE_ENTRIES_SIZE // entry_size:
            raise PstFormatError(f"BTPAGE at {index}: cEntMax {max_entries} exceeds {BTREE_ENTRIES_SIZE // entry_size}")
        if level > MAX_BTREE_LEVEL:
            raise PstFormatError(f"BTPAGE at {index}: cLevel {level} > {MAX_BTREE_LEVEL}")
        if padding != 0:
            raise PstFormatError(f"BTPAGE at {index}: dwPadding 0x{padding:08X} != 0")

        trailer = PageTrailer.unpack_from(page_bytes)
        if trailer.page_type not in _LEAF_ENTRY_TYPES:
            raise PstFormatError(f"BTPAGE at {index}: page type {trailer.page_type} is not a B-tree page")
        trailer.verify(page_bytes, index)
        # Upstream's leaf constructors require the tree's own type; its
        # intermediate constructor accepts either B-tree type.
        if level == 0 and trailer.page_type is not kind:
            raise PstFormatError(f"leaf page at {index} is a {trailer.page_type} page in a {kind} tree")

        entries = tuple(entry_type.unpack_from(page_bytes, i * entry_size) for i in range(count))
        return cls(level=level, max_entries=max_entries, entry_size=entry_size, entries=entries, trailer=trailer)


# --- the density list --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DensityListEntry:
    """DLISTPAGEENT — [MS-PST] 2.2.2.7.2.1: an AMap page number and its free slots, packed in 32 bits."""

    raw: int

    @property
    def page(self) -> int:
        """`dwPageNum`, the low 20 bits: the zero-based AMap page index."""
        return self.raw & _DENSITY_LIST_PAGE_MASK

    @property
    def free_slots(self) -> int:
        """`dwFreeSlots`, the high 12 bits: free 64-byte slots in that AMap."""
        return (self.raw >> _DENSITY_LIST_PAGE_BITS) & 0xFFF

    def __str__(self) -> str:
        # Upstream's `Debug` form (a tuple struct around the u32), which the
        # goldens would contain for a non-empty list.
        return f"DensityListPageEntry({self.raw})"


@dataclass(frozen=True, slots=True)
class DensityListPage:
    """DLISTPAGE — [MS-PST] 2.2.2.7.2: the allocator's list of AMaps with free space.

    Read-path irrelevant (a reader never allocates) and ported because it
    is one page type with its own trailer rules and an oracle example
    (`read_density_list`) to diff against. `entries` holds only the
    `cEntDList` valid records.
    """

    backfill_complete: bool
    current_page: int
    entries: tuple[DensityListEntry, ...]
    trailer: PageTrailer

    SIZE: ClassVar[int] = PAGE_SIZE

    @classmethod
    def parse(cls, page_bytes: bytes | bytearray | memoryview, index: ByteIndex = DENSITY_LIST_INDEX) -> DensityListPage:
        """Parse the 512 bytes at the density list's fixed offset. Checks are upstream's."""
        if len(page_bytes) != PAGE_SIZE:
            raise PstFormatError(f"density list page is {len(page_bytes)} bytes; a page is {PAGE_SIZE}")
        flags, count, padding, current_page = struct.unpack_from(_DENSITY_LIST_HEADER_FORMAT, page_bytes, 0)
        if count > DENSITY_LIST_MAX_ENTRIES:
            raise PstFormatError(f"DLISTPAGE cEntDList {count} > {DENSITY_LIST_MAX_ENTRIES}")
        if padding != 0:
            raise PstFormatError(f"DLISTPAGE wPadding 0x{padding:04X} != 0")
        entries = tuple(
            DensityListEntry(raw)
            for raw in struct.unpack_from(f"<{count}I", page_bytes, _DENSITY_LIST_ENTRIES_OFFSET)
        )
        tail = bytes(page_bytes[_DENSITY_LIST_PADDING_OFFSET : _DENSITY_LIST_PADDING_OFFSET + _DENSITY_LIST_PADDING_SIZE])
        if tail != bytes(_DENSITY_LIST_PADDING_SIZE):
            raise PstFormatError("DLISTPAGE rgPadding is not zero")
        trailer = PageTrailer.unpack_from(page_bytes)
        if trailer.page_type is not PageType.DL:
            raise PstFormatError(f"page at {index} is a {trailer.page_type} page, not the density list")
        trailer.verify(page_bytes, index)
        return cls(
            backfill_complete=bool(flags & _DENSITY_LIST_BACKFILL_COMPLETE),
            current_page=current_page,
            entries=entries,
            trailer=trailer,
        )
