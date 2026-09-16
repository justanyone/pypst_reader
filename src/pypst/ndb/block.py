"""Blocks — the 64-byte-aligned units a node's bytes are stored in, and the trees over them.

Ported from: crates/pst/src/ndb/block.rs, crates/pst/src/ndb/read_write.rs (read half)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.2.2.8 Blocks, 2.2.2.8.1 BLOCKTRAILER, 2.2.2.8.3 Block Types,
             2.2.2.8.3.1 Data Blocks, 2.2.2.8.3.2 XBLOCK / XXBLOCK,
             2.2.2.8.3.3 SLBLOCK / SIBLOCK (SLENTRY, SIENTRY), 5.5 signature,
             2.2.2.6 bCryptMethod

A node's bytes live in blocks. The block B-tree (`pypst.ndb.btree`) says
where a block is and how many data bytes (`cb`) it holds; this module reads
it. A block is allocated in multiples of 64 bytes with a 16-byte trailer at
the very end, and `cb` counts only the data — the trap named in the todo:
the trailer is *inside* the aligned allocation and the padding between the
data and the trailer is neither counted nor CRC'd. `block_size` is the one
place that arithmetic lives.

Three shapes of block ([MS-PST] 2.2.2.8.3). A **data block** is `cb` bytes
of node data, obfuscated by the header's `bCryptMethod`. When a node's data
exceeds one block, an **XBLOCK** (`btype` 0x01, `cLevel` 1) lists the data
blocks in order and an **XXBLOCK** (`cLevel` 2) lists XBLOCKs; both are
`XBlock` here, distinguished by `level`. A node's sub-nodes are a **subnode
B-tree** of **SLBLOCK**s (`btype` 0x02, `cLevel` 0, `SubNodeLeafEntry`s) under
an optional **SIBLOCK** (`cLevel` 1, `SubNodeIntermediateEntry`s). Tree
blocks are "internal" — bit 1 of their BID is set — and are never obfuscated.

**Unicode arm only (ADR-0003).** `BlockTrailer` is upstream's
`UnicodeBlockTrailer`; the ANSI trailer (12 bytes, different field order)
is not ported.

**What is verified on a block — exactly what upstream verifies, in its
order.** Reading the trailer (`UnicodeBlockTrailer::read`): `cb` must be in
1..=8176. For a data block (`BlockReadWrite::read`): the trailer's `cb` must
equal the block B-tree entry's `cb`; the trailer's BID must NOT have the
internal bit; the CRC over the `cb` data bytes must match; then the data is
decoded. For a tree block (`IntermediateTreeBlockReadWrite::read`): the
type byte must be the one the caller expects (0x01 data tree, 0x02 subnode
tree); `cEnt × entry size` must fit in `cb - 8`; the trailer's BID MUST have
the internal bit; the CRC over the `cb` bytes must match; a subnode block's
`dwPadding` must be zero. Upstream locates a tree block's trailer from the
size its header *implies* (8 + cEnt × entry size), not from `cb`, and so
does this module (`BlockReader._verify_tree_block`): a block whose `cb` has slack
past its entries is read, or refused, exactly where upstream reads or
refuses it.

**Read but not verified — as upstream, and deliberately.** The trailer's
`wSig` is carried and never compared: `pstd-inline-cid.pst` and
`synth-basics.pst` (both written by EMLtoPST) have `wSig == 0` on every
block and upstream reads them; `BlockTrailer.expected_signature(index)`
says what it should be so a test can ask. The trailer's BID is compared
with the B-tree's BID only on its internal bit, not its index. An XBLOCK's
`cLevel` is not checked against 1 or 2 (upstream reads the level and only
prints it), and its `lcbTotal` is not compared with the bytes actually
assembled — upstream's `DataTreeReader` concatenates the leaves and no
upstream layer reads `total_size` — but it IS the number checked against
`limits.max_allocation` before any child is read, because it is the file's
own claim about how much it wants allocated. A tree block's `cb` may exceed
8 + cEnt × entry size (slack). An SIENTRY/SLENTRY `nid` is an 8-byte field
holding a 32-bit NID; upstream truncates it (`as u32`) where the NBTENTRY
reader refuses one that does not fit, and this module does the same in each
place. A `bidData` of zero in a subnode leaf entry is kept as it is read.

**Divergence: every walk is bounded — `pypst.limits`, wired here.**
Upstream follows XBLOCK entries and SIBLOCK entries recursively with no
depth check and no memory of where it has been; a block that lists itself
is a stack overflow there and would be a hang here. So `read_data` and
`read_subnode_tree` are iterative, carry a `VisitedSet` of the internal
blocks they have entered (a revisit is `PstLimitError`), and check the
number of internal blocks on the path against `limits.max_xblock_depth` /
`limits.max_subnode_depth` (the root tree block is depth 1, so XXBLOCK →
XBLOCK → data is 2, the format's own maximum). `read_data` checks the
XBLOCK's `lcbTotal` against `limits.max_allocation` before reading any
child and the running assembled length as it goes (a lying `lcbTotal`
cannot buy more than the limit), and `read_subnode_tree` checks the entry
count against `limits.max_items`.

**Divergence: a block reference the file cannot contain is refused before
the read.** As `read_page`: a BREF whose index plus allocation exceeds
`limits.max_file_size` is `PstFormatError`, and a short read (past EOF, or
a file truncated inside the block) is the same error where upstream reports
the OS's `UnexpectedEof`.

**Divergence: `read_subnode_tree` is a dict, not a descent.** Upstream's
`SubNodeTree::find_entry` descends an SIBLOCK by `partition_point` on the
entry keys; here the whole tree is flattened once into `dict[NodeId, …]`
(the first entry for a NID wins, as upstream's leaf `find` returns the
first match), so a key that is present is always found even when an
SIBLOCK's keys are out of order.

A BID the block B-tree does not hold — a node's data block, an XBLOCK
entry, an SIENTRY's next level — raises `PstNotFoundError` from `btree`,
which propagates unwrapped everywhere in this module: it is a
`PstFormatError` and it names the key.

Nothing but `PstError` subclasses escapes for any input bytes. An `OSError`
from the file object is the environment's, not the file's, and is not
caught.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, ClassVar

from pypst.block_sig import compute_sig
from pypst.crc import compute_crc
from pypst.encode import CryptMethod, decode_block
from pypst.errors import PstFormatError
from pypst.limits import (
    DEFAULT_LIMITS,
    Limits,
    VisitedSet,
    check_allocation,
    check_count,
    check_depth,
)
from pypst.ndb.btree import BlockBTree
from pypst.ndb.header import Header
from pypst.ndb.ids import BlockId, BlockRef, ByteIndex, NodeId, _unpack
from pypst.ndb.page import BlockBTreeEntry, NodeBTreeEntry

__all__ = [
    "BLOCK_TRAILER_SIZE",
    "BTYPE_DATA_TREE",
    "BTYPE_SUBNODE_TREE",
    "MAX_BLOCK_DATA_SIZE",
    "MAX_BLOCK_SIZE",
    "TREE_HEADER_SIZE",
    "BlockReader",
    "BlockTrailer",
    "DataBlock",
    "SubNodeIntermediateBlock",
    "SubNodeIntermediateEntry",
    "SubNodeLeafBlock",
    "SubNodeLeafEntry",
    "XBlock",
    "block_size",
]

_U32 = 0xFFFFFFFF

# [MS-PST] 2.2.2.8: a block is a multiple of 64 bytes, at most 8192, with the
# BLOCKTRAILER as its last 16 bytes; so a data block holds at most 8176.
MAX_BLOCK_SIZE = 8192
BLOCK_ALIGNMENT = 64
BLOCK_TRAILER_SIZE = 16
MAX_BLOCK_DATA_SIZE = MAX_BLOCK_SIZE - BLOCK_TRAILER_SIZE

# [MS-PST] 2.2.2.8.1 BLOCKTRAILER, Unicode layout: cb, wSig, dwCRC, bid.
BLOCK_TRAILER_FORMAT = "<HHIQ"

# [MS-PST] 2.2.2.8.3.2 XBLOCK/XXBLOCK header: btype, cLevel, cEnt, lcbTotal;
# then cEnt 8-byte BIDs. 2.2.2.8.3.3 SLBLOCK/SIBLOCK header: btype, cLevel,
# cEnt, dwPadding; then cEnt SLENTRYs (nid u64, bidData, bidSub) or SIENTRYs
# (nid u64, bidNextLevel). Both headers are 8 bytes.
DATA_TREE_HEADER_FORMAT = "<BBHI"
SUBNODE_HEADER_FORMAT = "<BBHI"
TREE_HEADER_SIZE = struct.calcsize(DATA_TREE_HEADER_FORMAT)
DATA_TREE_ENTRY_FORMAT = "<Q"
SUBNODE_LEAF_ENTRY_FORMAT = "<QQQ"
SUBNODE_INTERMEDIATE_ENTRY_FORMAT = "<QQ"
BTYPE_DATA_TREE = 0x01
BTYPE_SUBNODE_TREE = 0x02


def block_size(size: int) -> int:
    """The allocation, trailer included, of a block holding `size` data bytes.

    [MS-PST] 2.2.2.8: the smallest multiple of 64 that holds `size + 16`.
    Upstream's `block_size` takes the trailer-inclusive size and asserts
    its range; here the 16 is added inside, so a caller never does the
    arithmetic the todo warns about, and the range is a refusal rather
    than a panic: `size` must be in 1..=8176 (`UnicodeBlockTrailer::read`'s
    bound on `cb`).
    """
    if not 1 <= size <= MAX_BLOCK_DATA_SIZE:
        raise PstFormatError(f"block data size {size} is not in 1..={MAX_BLOCK_DATA_SIZE}")
    total = size + BLOCK_TRAILER_SIZE
    return -(-total // BLOCK_ALIGNMENT) * BLOCK_ALIGNMENT


@dataclass(frozen=True, slots=True)
class BlockTrailer:
    """BLOCKTRAILER — [MS-PST] 2.2.2.8.1, Unicode layout, the last 16 bytes of a block."""

    size: int
    signature: int
    crc: int
    block_id: BlockId

    SIZE: ClassVar[int] = BLOCK_TRAILER_SIZE

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> BlockTrailer:
        """Read a trailer from `buf` at `offset`; `cb` outside 1..=8176 is refused, as upstream."""
        size, signature, crc, block_id = _unpack(BLOCK_TRAILER_FORMAT, buf, offset, "BlockTrailer")
        if not 1 <= size <= MAX_BLOCK_DATA_SIZE:
            raise PstFormatError(f"block trailer cb {size} is not in 1..={MAX_BLOCK_DATA_SIZE}")
        return cls(size, signature, crc, BlockId(block_id))

    @property
    def cyclic_key(self) -> int:
        """The key for `CryptMethod.CYCLIC`: the low 32 bits of the BID's search key (upstream's `as u32`)."""
        return self.block_id.search_key & _U32

    def verify_block_id(self, is_internal: bool) -> None:
        """The trailer's BID must carry the internal bit iff the block is a tree block — upstream's one BID check."""
        if self.block_id.is_internal != is_internal:
            kind = "an internal" if is_internal else "a data"
            raise PstFormatError(f"block trailer bid {self.block_id} in {kind} block")

    def verify_crc(self, data: bytes | bytearray | memoryview) -> None:
        """The CRC over the `cb` data bytes ([MS-PST] 2.2.2.8.1: never the padding or the trailer)."""
        crc = compute_crc(0, bytes(data))
        if crc != self.crc:
            raise PstFormatError(f"block CRC mismatch for {self.block_id}: computed 0x{crc:08X}, trailer 0x{self.crc:08X}")

    def expected_signature(self, index: ByteIndex) -> int:
        """The `wSig` a block at `index` should carry ([MS-PST] 5.5) — informational, never enforced."""
        return compute_sig(index.value, self.block_id.raw)


# --- the three block shapes ----------------------------------------------------


@dataclass(frozen=True, slots=True)
class DataBlock:
    """A data block ([MS-PST] 2.2.2.8.3.1): `cb` bytes, already decoded, and its trailer."""

    data: bytes
    trailer: BlockTrailer


@dataclass(frozen=True, slots=True)
class XBlock:
    """XBLOCK (`level` 1) or XXBLOCK (`level` 2) — [MS-PST] 2.2.2.8.3.2.

    `entries` are the BIDs in order; `total_size` is `lcbTotal`, the file's
    claim of how many data bytes the tree holds (see the module docstring
    for what is done with it).
    """

    level: int
    total_size: int
    entries: tuple[BlockId, ...]
    trailer: BlockTrailer


@dataclass(frozen=True, slots=True)
class SubNodeLeafEntry:
    """SLENTRY — [MS-PST] 2.2.2.8.3.3.1: a sub-node, its data block, its own subnode tree (or None)."""

    node: NodeId
    data: BlockId
    sub_node: BlockId | None

    SIZE: ClassVar[int] = struct.calcsize(SUBNODE_LEAF_ENTRY_FORMAT)

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> SubNodeLeafEntry:
        nid, data, sub_node = _unpack(SUBNODE_LEAF_ENTRY_FORMAT, buf, offset, "SLENTRY")
        sub = BlockId(sub_node)
        # The 8-byte nid holds a 32-bit NID; upstream truncates (module docstring).
        return cls(NodeId(nid & _U32), BlockId(data), None if sub.search_key == 0 else sub)


@dataclass(frozen=True, slots=True)
class SubNodeIntermediateEntry:
    """SIENTRY — [MS-PST] 2.2.2.8.3.3.3: the first NID of the SLBLOCK at `next_level`."""

    node: NodeId
    next_level: BlockId

    SIZE: ClassVar[int] = struct.calcsize(SUBNODE_INTERMEDIATE_ENTRY_FORMAT)

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> SubNodeIntermediateEntry:
        nid, next_level = _unpack(SUBNODE_INTERMEDIATE_ENTRY_FORMAT, buf, offset, "SIENTRY")
        return cls(NodeId(nid & _U32), BlockId(next_level))


@dataclass(frozen=True, slots=True)
class SubNodeLeafBlock:
    """SLBLOCK — [MS-PST] 2.2.2.8.3.3.2: `level` 0 and the leaf entries."""

    level: int
    entries: tuple[SubNodeLeafEntry, ...]
    trailer: BlockTrailer


@dataclass(frozen=True, slots=True)
class SubNodeIntermediateBlock:
    """SIBLOCK — [MS-PST] 2.2.2.8.3.3.4: `level` > 0 (1 in a well-formed store) and the intermediate entries."""

    level: int
    entries: tuple[SubNodeIntermediateEntry, ...]
    trailer: BlockTrailer


# The entry stride of a tree block, by type byte and level ([MS-PST]
# 2.2.2.8.3.2 and 2.2.2.8.3.3): what upstream's `ENTRY_SIZE` constants say.
def _tree_entry_size(btype: int, level: int) -> int:
    if btype == BTYPE_DATA_TREE:
        return struct.calcsize(DATA_TREE_ENTRY_FORMAT)
    if btype == BTYPE_SUBNODE_TREE:
        return SubNodeLeafEntry.SIZE if level == 0 else SubNodeIntermediateEntry.SIZE
    raise PstFormatError(f"unknown internal block type 0x{btype:02X}")


class BlockReader:
    """Reads blocks through the block B-tree and decodes them by the header's method.

    One per open store: `f` is the store's file object, `header` supplies
    `crypt_method`, `bbt` resolves BIDs, `limits` bounds every walk.
    """

    __slots__ = ("_bbt", "_crypt", "_f", "_limits")

    def __init__(self, f: BinaryIO, header: Header, bbt: BlockBTree, limits: Limits = DEFAULT_LIMITS) -> None:
        self._f = f
        self._crypt: CryptMethod = header.crypt_method
        self._bbt = bbt
        self._limits = limits

    @property
    def limits(self) -> Limits:
        return self._limits

    @property
    def crypt_method(self) -> CryptMethod:
        return self._crypt

    # --- one block ----------------------------------------------------------

    def _read_allocation(self, ref: BlockRef, size: int) -> memoryview:
        """The whole `block_size(size)` allocation at `ref.index`: one seek, one read."""
        total = block_size(size)
        if ref.index.value + total > self._limits.max_file_size:
            raise PstFormatError(
                f"block reference {ref} is beyond the largest supported file ({self._limits.max_file_size} bytes)"
            )
        self._f.seek(ref.index.value)
        data = self._f.read(total)
        if len(data) != total:
            raise PstFormatError(f"short read at {ref}: got {len(data)} of {total} block bytes (past EOF?)")
        return memoryview(data)

    def read_block(self, ref: BlockRef, size: int, *, is_internal: bool) -> bytes:
        """The `size` (= BBT `cb`) bytes of the block at `ref`, trailer-verified; decoded unless internal.

        A data block (`is_internal=False`) is checked and decoded exactly as
        upstream's `BlockReadWrite::read`; the cyclic key is the trailer's
        BID. A tree block (`is_internal=True`) is checked as upstream's
        `IntermediateTreeBlockReadWrite::read` — its type byte may be either
        tree type here; `read_data_tree` / `read_subnode_block` insist on
        theirs — and is NEVER decoded: internal blocks are stored in the
        clear ([MS-PST] 2.2.2.8.3.2, 2.2.2.8.3.3; upstream decodes only in
        the data-block path).
        """
        buf = self._read_allocation(ref, size)
        if is_internal:
            return bytes(self._verify_tree_block(buf, size, ref)[0])
        return self._verify_data_block(buf, size, ref).data

    def _verify_data_block(self, buf: memoryview, size: int, ref: BlockRef) -> DataBlock:
        data = buf[:size]
        trailer = BlockTrailer.unpack_from(buf, len(buf) - BLOCK_TRAILER_SIZE)
        if trailer.size != size:
            raise PstFormatError(f"block at {ref}: trailer cb {trailer.size} != block B-tree cb {size}")
        trailer.verify_block_id(False)
        trailer.verify_crc(data)
        return DataBlock(decode_block(bytes(data), self._crypt, trailer.cyclic_key), trailer)

    def _verify_tree_block(
        self, buf: memoryview, size: int, ref: BlockRef, expected_btype: int | None = None
    ) -> tuple[memoryview, BlockTrailer, int, int, int, int]:
        """Header checks, trailer location and verification for a tree block.

        Returns (cb bytes, trailer, btype, level, count, fourth), where
        `fourth` is the header's last u32: `lcbTotal` for a data tree
        block, `dwPadding` for a subnode block.
        """
        btype, level, count, fourth = _unpack(DATA_TREE_HEADER_FORMAT, buf, 0, "internal block header")
        if expected_btype is not None and btype != expected_btype:
            raise PstFormatError(f"block at {ref}: internal block type 0x{btype:02X}, expected 0x{expected_btype:02X}")
        entry_size = _tree_entry_size(btype, level)
        if size < TREE_HEADER_SIZE or count * entry_size > size - TREE_HEADER_SIZE:
            raise PstFormatError(f"block at {ref}: {count} entries of {entry_size} bytes do not fit in cb {size}")
        implied = TREE_HEADER_SIZE + count * entry_size
        # Upstream seeks from the end of the cb bytes by the padding the
        # IMPLIED size needs, and reads the trailer there (module docstring).
        offset = size + (block_size(implied) - implied - BLOCK_TRAILER_SIZE)
        if offset + BLOCK_TRAILER_SIZE > len(buf):
            raise PstFormatError(f"block at {ref}: trailer at {offset} is outside the {len(buf)}-byte allocation")
        trailer = BlockTrailer.unpack_from(buf, offset)
        trailer.verify_block_id(True)
        data = buf[:size]
        trailer.verify_crc(data)
        return data, trailer, btype, level, count, fourth

    # --- the tree blocks ----------------------------------------------------

    def find(self, block: BlockId) -> BlockBTreeEntry:
        """The block B-tree entry for `block` (`PstNotFoundError` if absent) — where it is and its `cb`."""
        return self._bbt.find(block)

    def read_data_tree(self, block: BlockId) -> DataBlock | XBlock:
        """One block of a node's data tree, by BID: a data block, or an XBLOCK/XXBLOCK (upstream's `DataTree::read`).

        The block B-tree entry's BID decides which — its internal bit — as upstream.
        """
        entry = self.find(block)
        ref, size = entry.block, entry.size
        buf = self._read_allocation(ref, size)
        if not ref.block.is_internal:
            return self._verify_data_block(buf, size, ref)
        data, trailer, _btype, level, count, total_size = self._verify_tree_block(buf, size, ref, BTYPE_DATA_TREE)
        entries = tuple(BlockId(raw) for raw in struct.unpack_from(f"<{count}Q", data, TREE_HEADER_SIZE))
        return XBlock(level, total_size, entries, trailer)

    def read_subnode_block(self, block: BlockId) -> SubNodeLeafBlock | SubNodeIntermediateBlock:
        """One block of a subnode B-tree, by BID (upstream's `SubNodeTree::read`): `cLevel` > 0 is an SIBLOCK."""
        entry = self.find(block)
        ref, size = entry.block, entry.size
        buf = self._read_allocation(ref, size)
        data, trailer, _btype, level, count, padding = self._verify_tree_block(buf, size, ref, BTYPE_SUBNODE_TREE)
        if padding != 0:
            raise PstFormatError(f"block at {ref}: subnode block dwPadding 0x{padding:08X} != 0")
        if level > 0:
            stride = SubNodeIntermediateEntry.SIZE
            return SubNodeIntermediateBlock(
                level,
                tuple(SubNodeIntermediateEntry.unpack_from(data, TREE_HEADER_SIZE + i * stride) for i in range(count)),
                trailer,
            )
        stride = SubNodeLeafEntry.SIZE
        return SubNodeLeafBlock(
            level,
            tuple(SubNodeLeafEntry.unpack_from(data, TREE_HEADER_SIZE + i * stride) for i in range(count)),
            trailer,
        )

    # --- the walks ----------------------------------------------------------

    def read_data(self, block: BlockId) -> bytes:
        """All of a node's data bytes: the data block, or the leaves of its XBLOCK/XXBLOCK tree in order.

        Bounded (module docstring): depth, cycles, the claimed and the
        assembled size. Not checked, as upstream: `lcbTotal` against the
        assembled length, `cLevel` against the depth.
        """
        root = self.read_data_tree(block)
        if isinstance(root, DataBlock):
            return root.data
        limits = self._limits
        what = "data tree"
        check_allocation(root.total_size, limits.max_allocation, f"{what} lcbTotal")
        visited = VisitedSet(f"{what} blocks", limits.max_items)
        visited.add(block.search_key)
        # Pre-order over the tree, children in entry order: a stack of
        # (block id, depth) with the entries pushed reversed. A data block's
        # bytes go straight to `parts`; an internal block is expanded.
        parts: list[bytes] = []
        assembled = 0
        stack: list[tuple[BlockId, int]] = [(child, 2) for child in reversed(root.entries)]
        while stack:
            child, depth = stack.pop()
            if child.is_internal:
                # Bounded before the read: the depth is known from the path
                # and the id from the entry. (The B-tree keys on the same
                # bit, so an internal id never resolves to a data block.)
                check_depth(depth, limits.max_xblock_depth, f"{what} depth")
                visited.add(child.search_key)
            node = self.read_data_tree(child)
            if isinstance(node, XBlock):
                stack.extend((grandchild, depth + 1) for grandchild in reversed(node.entries))
                continue
            parts.append(node.data)
            assembled += len(node.data)
            check_allocation(assembled, limits.max_allocation, f"{what} assembled size")
        return b"".join(parts)

    def read_subnode_tree(self, block: BlockId) -> dict[NodeId, SubNodeLeafEntry]:
        """Every leaf entry of the subnode B-tree rooted at `block`, keyed by NID (first entry per NID wins).

        Bounded (module docstring): depth, cycles, the entry count.
        """
        limits = self._limits
        what = "subnode tree"
        visited = VisitedSet(f"{what} blocks", limits.max_items)
        entries: dict[NodeId, SubNodeLeafEntry] = {}
        count = 0
        stack: list[tuple[BlockId, int]] = [(block, 1)]
        while stack:
            child, depth = stack.pop()
            check_depth(depth, limits.max_subnode_depth, f"{what} depth")
            visited.add(child.search_key)
            node = self.read_subnode_block(child)
            if isinstance(node, SubNodeIntermediateBlock):
                stack.extend((entry.next_level, depth + 1) for entry in reversed(node.entries))
                continue
            count += len(node.entries)
            check_count(count, limits.max_items, f"{what} entries")
            for entry in node.entries:
                entries.setdefault(entry.node, entry)
        return entries

    def node_data(self, entry: NodeBTreeEntry) -> bytes:
        """The bytes of the node `entry` names — the convenience every layer above uses.

        A `bidData` of zero is looked up like any other and is
        `PstNotFoundError`, as upstream's `find_entry` reports it.
        """
        return self.read_data(entry.data)
