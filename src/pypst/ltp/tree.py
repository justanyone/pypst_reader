"""BTree-on-Heap (BTH) — the sorted key/value index a property or table context is read through.

Ported from: crates/pst/src/ltp/tree.rs, crates/pst/src/ltp/read_write.rs (the HeapTree read trait)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.3.2 BTH, 2.3.2.1 BTHHEADER, 2.3.2.2 Intermediate BTH (Index) Records,
             2.3.2.3 Leaf BTH (Data) Records

A BTH is a B-tree whose pages are heap items (`pypst.ltp.heap`). Its
BTHHEADER ([MS-PST] 2.3.2.1: `bType` 0xB5, `cbKey` in {2, 4, 8, 16},
`cbEnt` in 1..=32, `bIdxLevels`, `hidRoot`) is itself a heap item — the
heap's user root for a PC, the TCINFO's `hidRowIndex` for a TC. `hidRoot`
names the root page, or is the null HID for an empty tree. With
`bIdxLevels` == 0 the root page is a leaf: tightly packed `cbKey + cbEnt`
records ([MS-PST] 2.3.2.3), as many as the item holds. Otherwise the root
and the next `bIdxLevels - 1` levels are index pages of `cbKey + 4` records
([MS-PST] 2.3.2.2), each the first key of the page its HID names.

Keys and values are returned as `bytes` of exactly `cbKey` and `cbEnt`:
what they mean is the layer above's business (a PC key is a u16 property
id and its value a 6-byte type + HNID record; a TC row index key is a u32
row id). `find` compares keys as little-endian unsigned integers of
`cbKey` bytes, which is the order the two upstream instantiations (`u16`,
`u32`) sort by; nothing upstream instantiates the 8- and 16-byte widths.

**What is verified, exactly upstream's checks.** `HeapTreeHeader::read`:
`bType` is a known client signature AND is `bTypeBTH`; `cbKey` and `cbEnt`
in range; `hidRoot` with zero type bits. Every page HID read from an index
record has zero type bits (`HeapId::read`). `entries` walks the levels as
upstream's `HeapTreeInner::entries` does — breadth-first, a level at a
time, children in record order — so the leaf pairs come out in the tree's
own order.

**Divergence: an undecodable record is an error, not the end of the page.**
Upstream reads a page with `while let Ok(row) = read(cursor)`, so a page
whose length is not a multiple of the record size silently drops its tail,
and an index record whose HID has the wrong type bits silently ends the
level — the bug P19 recorded in `todo/T03-messaging.md` § P09. Here a page
length that is not a whole number of records is `PstFormatError`, and a
bad HID inside a record is the `PstFormatError` `HeapId` raises.

**Divergence: the walk is bounded — `pypst.limits`.** `bIdxLevels` is a
byte upstream walks as far as it says; here it is checked against
`limits.max_heap_tree_depth` when the header is read (`PstLimitError`).
Every page visited is added to a `VisitedSet` — an index record naming its
own page, or an ancestor, is a cycle and `PstLimitError` — and the
records collected are counted against `limits.max_items`.

`find` is this port's addition (upstream reads every entry into a
`BTreeMap`): one descent from the root choosing, at each index page, the
last record whose key is not greater than the target, then a scan of the
leaf for the exact key. A tree whose keys are out of order can answer
`find` with None for a key `entries` would list; that is the file's
disorder, not the reader's, and `entries` is the walk a caller who wants
everything should use.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import ClassVar

from pypst.errors import PstFormatError
from pypst.limits import VisitedSet, check_count, check_depth
from pypst.ltp.heap import HeapId, HeapNode, HeapNodeType
from pypst.ndb.ids import _unpack

__all__ = [
    "BTH_HEADER_FORMAT",
    "BTH_HEADER_SIZE",
    "KEY_SIZES",
    "MAX_ENTRY_SIZE",
    "HeapTree",
    "HeapTreeHeader",
]

# [MS-PST] 2.3.2.1 BTHHEADER: bType, cbKey, cbEnt, bIdxLevels, hidRoot.
BTH_HEADER_FORMAT = "<BBBBI"
BTH_HEADER_SIZE = struct.calcsize(BTH_HEADER_FORMAT)
KEY_SIZES = (2, 4, 8, 16)
MAX_ENTRY_SIZE = 32


@dataclass(frozen=True, slots=True)
class HeapTreeHeader:
    """BTHHEADER — [MS-PST] 2.3.2.1 — upstream's `HeapTreeHeader`."""

    key_size: int
    entry_size: int
    levels: int
    root: HeapId

    SIZE: ClassVar[int] = BTH_HEADER_SIZE

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> HeapTreeHeader:
        """Upstream's `HeapTreeHeader::read` then `::new`: type, then the sizes, then the root."""
        btype, key_size, entry_size, levels, root = _unpack(BTH_HEADER_FORMAT, buf, offset, "BTHHEADER")
        if HeapNodeType.from_wire(btype) is not HeapNodeType.TREE:
            raise PstFormatError(f"BTH header type 0x{btype:02X} != bTypeBTH 0x{HeapNodeType.TREE:02X}")
        if key_size not in KEY_SIZES:
            raise PstFormatError(f"BTH key size {key_size} is not one of {KEY_SIZES}")
        if not 1 <= entry_size <= MAX_ENTRY_SIZE:
            raise PstFormatError(f"BTH entry size {entry_size} is not in 1..={MAX_ENTRY_SIZE}")
        return cls(key_size, entry_size, levels, HeapId(root))


class HeapTree:
    """A BTH over `heap`, rooted at the BTHHEADER item `root` (the heap's user root by default).

    Upstream's `HeapTree` for one `(heap, user_root)`. The header is read
    at construction; the pages are read by `__iter__` / `entries` (every
    leaf pair, in order) and `find` (one descent).
    """

    __slots__ = ("_header", "_heap", "_root")

    def __init__(self, heap: HeapNode, root: HeapId | None = None) -> None:
        self._heap = heap
        self._root = heap.user_root if root is None else root
        self._header = HeapTreeHeader.unpack_from(heap.get(self._root), 0)
        check_depth(self._header.levels, heap.limits.max_heap_tree_depth, "BTH index levels")

    @property
    def heap(self) -> HeapNode:
        return self._heap

    @property
    def header(self) -> HeapTreeHeader:
        return self._header

    @property
    def key_size(self) -> int:
        return self._header.key_size

    @property
    def entry_size(self) -> int:
        return self._header.entry_size

    @property
    def levels(self) -> int:
        return self._header.levels

    @property
    def root(self) -> HeapId:
        """`hidRoot` — null for an empty tree."""
        return self._header.root

    # --- pages ------------------------------------------------------------------

    def _page(self, hid: HeapId, record_size: int, visited: VisitedSet) -> memoryview:
        """The item `hid` names, as a whole number of `record_size` records (module docstring)."""
        visited.add(hid.raw)
        page = self._heap.get(hid)
        if len(page) % record_size:
            raise PstFormatError(f"BTH page {hid}: {len(page)} bytes is not a whole number of {record_size}-byte records")
        return page

    def _index_records(self, page: memoryview) -> list[tuple[bytes, HeapId]]:
        key_size = self._header.key_size
        stride = key_size + HeapId.SIZE
        return [
            (bytes(page[i : i + key_size]), HeapId.unpack_from(page, i + key_size))
            for i in range(0, len(page), stride)
        ]

    def _leaf_records(self, page: memoryview) -> list[tuple[bytes, bytes]]:
        key_size, entry_size = self._header.key_size, self._header.entry_size
        stride = key_size + entry_size
        return [(bytes(page[i : i + key_size]), bytes(page[i + key_size : i + stride])) for i in range(0, len(page), stride)]

    # --- the walks --------------------------------------------------------------

    def __iter__(self) -> Iterator[tuple[bytes, bytes]]:
        """Every leaf `(key, value)` in the tree's order — upstream's `entries`, bounded."""
        header = self._header
        if header.root.is_null:
            return
        limits = self._heap.limits
        visited = VisitedSet("BTH pages", limits.max_items)
        index_stride = header.key_size + HeapId.SIZE
        leaf_stride = header.key_size + header.entry_size
        # Level by level from the root, as upstream: the pages of one level
        # are read in order and their children become the next level.
        pages = [header.root]
        for _level in range(header.levels):
            next_pages: list[HeapId] = []
            for hid in pages:
                next_pages.extend(child for _key, child in self._index_records(self._page(hid, index_stride, visited)))
            check_count(len(next_pages), limits.max_items, "BTH pages")
            pages = next_pages
        count = 0
        for hid in pages:
            records = self._leaf_records(self._page(hid, leaf_stride, visited))
            count += len(records)
            check_count(count, limits.max_items, "BTH records")
            yield from records

    def entries(self) -> list[tuple[bytes, bytes]]:
        """`list(self)`."""
        return list(self)

    def find(self, key: bytes) -> bytes | None:
        """The value stored under `key` (exactly `key_size` bytes), or None — one descent (module docstring)."""
        header = self._header
        if len(key) != header.key_size:
            raise PstFormatError(f"BTH key must be {header.key_size} bytes, got {len(key)}")
        if header.root.is_null:
            return None
        target = int.from_bytes(key, "little")
        visited = VisitedSet("BTH pages", self._heap.limits.max_items)
        index_stride = header.key_size + HeapId.SIZE
        hid = header.root
        for _level in range(header.levels):
            chosen: HeapId | None = None
            for first_key, child in self._index_records(self._page(hid, index_stride, visited)):
                if int.from_bytes(first_key, "little") > target:
                    break
                chosen = child
            if chosen is None:
                return None
            hid = chosen
        for record_key, value in self._leaf_records(self._page(hid, header.key_size + header.entry_size, visited)):
            if record_key == key:
                return value
        return None
