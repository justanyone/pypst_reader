"""The node B-tree and the block B-tree — the two indexes every read starts from.

Ported from: the `RootBTreeReadWrite` default impl in crates/pst/src/ndb/page.rs
             (`read`, `find_entry`) and the page walk in
             crates/pst/examples/read_btrees.rs; the density list read is
             `UnicodeDensityListPage::read` in the same page.rs
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.2.2.7.7 BTrees, 2.2.2.7.7.2 BTENTRY (btkey rule)

The header's ROOT names two pages. One is the root of the node B-tree
(NBT), keyed by NID, whose leaves say which block holds each node's data;
the other is the root of the block B-tree (BBT), keyed by BID, whose leaves
say where each block is in the file. Every higher layer resolves a node
through the first and a block through the second, so these two walks are
the whole of what "opening a PST" means at this level.

**Unicode arm only (ADR-0003).** `NodeBTree` is upstream's
`UnicodeNodeBTree`, `BlockBTree` its `UnicodeBlockBTree`.

**What is upstream's.** A page is read with one 512-byte read at the BREF's
byte index and parsed by `pypst.ndb.page` (whose checks are upstream's).
`find` descends as upstream's `find_entry` does: on an intermediate page
the child is the last entry whose key is ≤ the search key (`partition_point`,
here `bisect_right`), and "no such entry" — the first key is already above
the search key — is a refusal; on a leaf the key must match exactly. Upstream
keeps a per-tree cache of the pages a lookup has touched; here intermediate
pages are cached (leaves are the bulk of a tree and are re-read).

**Divergence: the walk is bounded — `pypst.limits`, wired here.** Rust's
bounds checks make a runaway walk a survivable panic; in Python an
unbounded loop is a hang, and a B-tree page that names itself or an
ancestor is a loop. So every walk here carries a `VisitedSet` of the page
byte offsets it has entered and refuses a second visit as `PstLimitError`,
and every descent checks its depth against `limits.max_btree_depth`. The
depth is the number of page references followed from the root: the root is
depth 0, and `MAX_BTREE_DEPTH` (8) is the deepest a legitimate tree can be
because `cLevel ≤ 8` (page.py, upstream's `InvalidBTreePageLevel`). The
count of entries yielded by an iteration is checked against
`limits.max_items`, and the VisitedSet is capped by the same number. The
VisitedSet also refuses a page reachable by two paths (a DAG rather than a
tree): upstream would read it twice without complaint, but a shared page is
not a B-tree and its keys cannot be in order. The walks are iterative
(explicit stacks), so no `RecursionError` is reachable.

**Divergence: a node B-tree intermediate key that does not fit 32 bits is
refused.** [MS-PST] 2.2.2.7.7.2 says an NBT `btkey` is a NID zero-extended
to 8 bytes. Upstream's library carries the u64 without looking at it; its
`read_btrees` example prints `Invalid Key` and silently skips that child's
whole subtree. Skipping hides nodes, so the walk here refuses the page as
`PstFormatError` instead. Leaf `nid`s are already refused the same way by
upstream (page.py). No corpus or private store carries such a key.

**Divergence: a page reference the file cannot contain is refused before
the read.** A BREF whose byte index plus 512 exceeds `limits.max_file_size`
is a `PstFormatError` (a lie about the file, not a budget); a read that
comes back short — the page is past EOF or the file is truncated — is the
same error, where upstream reports the OS's `UnexpectedEof`.

Nothing but `PstError` subclasses escapes for any input bytes. An `OSError`
from the file object is the environment's, not the file's, and is not
caught.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterator
from typing import BinaryIO, ClassVar

from pypst.errors import PstFormatError, PstNotFoundError
from pypst.limits import DEFAULT_LIMITS, Limits, VisitedSet, check_count, check_depth
from pypst.ndb.ids import BlockId, ByteIndex, NodeId, PageRef
from pypst.ndb.page import (
    DENSITY_LIST_INDEX,
    PAGE_SIZE,
    BlockBTreeEntry,
    BTreePage,
    DensityListPage,
    IntermediateEntry,
    NodeBTreeEntry,
    PageType,
)

__all__ = ["BlockBTree", "NodeBTree", "read_density_list", "read_page"]

_U32 = 0xFFFFFFFF


def read_page(f: BinaryIO, index: ByteIndex, limits: Limits = DEFAULT_LIMITS) -> bytes:
    """The 512 bytes at `index`, or `PstFormatError` if the file does not hold them.

    One seek, one read. The bound against `limits.max_file_size` is checked
    before the seek so that an absurd offset never reaches the OS.
    """
    if index.value + PAGE_SIZE > limits.max_file_size:
        raise PstFormatError(f"page reference {index} is beyond the largest supported file ({limits.max_file_size} bytes)")
    f.seek(index.value)
    data = f.read(PAGE_SIZE)
    if len(data) != PAGE_SIZE:
        raise PstFormatError(f"short read at {index}: got {len(data)} of {PAGE_SIZE} page bytes (past EOF?)")
    return data


class _BTree:
    """The walk, generic over the leaf entry type; `KIND` picks it (page.py)."""

    KIND: ClassVar[PageType]
    WHAT: ClassVar[str]

    __slots__ = ("_cache", "_f", "_limits", "_root")

    def __init__(self, f: BinaryIO, root: PageRef, limits: Limits = DEFAULT_LIMITS) -> None:
        self._f = f
        self._root = root
        self._limits = limits
        # Intermediate pages a `find` has parsed, keyed by byte offset. Never
        # leaves: they are 95 % of a tree and a lookup touches one of them.
        self._cache: dict[int, BTreePage] = {}

    @property
    def root(self) -> PageRef:
        return self._root

    @property
    def limits(self) -> Limits:
        return self._limits

    # --- reading one page ------------------------------------------------

    def _read(self, ref: PageRef) -> BTreePage:
        page = BTreePage.parse(read_page(self._f, ref.index, self._limits), self.KIND, ref.index)
        if not page.is_leaf:
            self._check_intermediate(page, ref)
        return page

    def _check_intermediate(self, page: BTreePage, ref: PageRef) -> None:
        """The NBT's zero-extended-NID rule (module docstring); the BBT has no such rule."""
        if self.KIND is PageType.NBT:
            for entry in page.entries:
                assert isinstance(entry, IntermediateEntry)
                if entry.key > _U32:
                    raise PstFormatError(f"NBT page at {ref.index}: key 0x{entry.key:X} is not a 32-bit NID")

    def _child(self, ref: PageRef, depth: int, visited: VisitedSet) -> BTreePage:
        """Follow one reference: bound the depth, refuse a revisit, read, cache if intermediate."""
        check_depth(depth, self._limits.max_btree_depth, f"{self.WHAT} depth")
        visited.add(ref.index.value)
        page = self._cache.get(ref.index.value)
        if page is None:
            page = self._read(ref)
            if not page.is_leaf:
                self._cache[ref.index.value] = page
        return page

    # --- the walks --------------------------------------------------------

    def pages(self) -> Iterator[BTreePage]:
        """Every page, pre-order: a page, then each child's subtree in entry order.

        This is the order upstream's `read_btrees` prints, so a dumper can
        consume the iterator recursively. The root comes first.
        """
        visited = VisitedSet(f"{self.WHAT} pages", self._limits.max_items)
        stack: list[tuple[PageRef, int]] = [(self._root, 0)]
        while stack:
            ref, depth = stack.pop()
            page = self._child(ref, depth, visited)
            yield page
            if not page.is_leaf:
                # Reversed so that the first entry's subtree is walked first.
                for entry in reversed(page.entries):
                    assert isinstance(entry, IntermediateEntry)
                    stack.append((entry.ref, depth + 1))

    def _leaf_entries(self) -> Iterator[BlockBTreeEntry | NodeBTreeEntry]:
        count = 0
        for page in self.pages():
            if page.is_leaf:
                count += len(page.entries)
                check_count(count, self._limits.max_items, f"{self.WHAT} entries")
                for entry in page.entries:
                    assert not isinstance(entry, IntermediateEntry)
                    yield entry

    # --- lookup -----------------------------------------------------------

    def _find(self, key: int) -> BlockBTreeEntry | NodeBTreeEntry:
        visited = VisitedSet(f"{self.WHAT} lookup", self._limits.max_items)
        ref, depth = self._root, 0
        while True:
            page = self._child(ref, depth, visited)
            if page.is_leaf:
                for entry in page.entries:
                    assert not isinstance(entry, IntermediateEntry)
                    if entry.key == key:
                        return entry
                raise PstNotFoundError(f"{self.WHAT}: key 0x{key:X} not found")
            # The child holding `key` is the last entry whose key is ≤ it
            # ([MS-PST] 2.2.2.7.7.2); none means the key is below the tree.
            keys = [entry.key for entry in page.entries]
            position = bisect_right(keys, key)
            if position == 0:
                raise PstNotFoundError(f"{self.WHAT}: key 0x{key:X} not found (below the first key)")
            child = page.entries[position - 1]
            assert isinstance(child, IntermediateEntry)
            ref, depth = child.ref, depth + 1


class NodeBTree(_BTree):
    """The NBT: NID → `NodeBTreeEntry`. Constructed from the header's `root.node_btree`."""

    KIND = PageType.NBT
    WHAT = "node B-tree"

    __slots__ = ()

    def find(self, key: NodeId | int) -> NodeBTreeEntry:
        """The entry for `key` (a `NodeId`, or its raw value); `PstNotFoundError` if absent."""
        raw = key.raw if isinstance(key, NodeId) else key
        entry = self._find(raw)
        assert isinstance(entry, NodeBTreeEntry)
        return entry

    def __iter__(self) -> Iterator[NodeBTreeEntry]:
        """Every leaf entry in tree order, which is NID order for a well-formed store."""
        for entry in self._leaf_entries():
            assert isinstance(entry, NodeBTreeEntry)
            yield entry


class BlockBTree(_BTree):
    """The BBT: BID → `BlockBTreeEntry`. Constructed from the header's `root.block_btree`."""

    KIND = PageType.BBT
    WHAT = "block B-tree"

    __slots__ = ()

    def find(self, key: BlockId | int) -> BlockBTreeEntry:
        """The entry for `key` (a `BlockId`, whose reserved bit is ignored, or a raw search key)."""
        raw = key.search_key if isinstance(key, BlockId) else key
        entry = self._find(raw)
        assert isinstance(entry, BlockBTreeEntry)
        return entry

    def __iter__(self) -> Iterator[BlockBTreeEntry]:
        """Every leaf entry in tree order, which is BID order for a well-formed store."""
        for entry in self._leaf_entries():
            assert isinstance(entry, BlockBTreeEntry)
            yield entry


def read_density_list(f: BinaryIO, limits: Limits = DEFAULT_LIMITS) -> DensityListPage:
    """The DLISTPAGE at its fixed offset ([MS-PST] 2.2.2.7.2).

    A store need not have one — the page slot may be zero, which upstream
    reports as `InvalidPageType(0)` — and that is a `PstFormatError` here
    too: the caller asked for a page that is not there.
    """
    return DensityListPage.parse(read_page(f, DENSITY_LIST_INDEX, limits), DENSITY_LIST_INDEX)
