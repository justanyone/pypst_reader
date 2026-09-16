"""Blocks: refused when the trailer or the tree lies, exact against the oracle when they do not.

Denial first. Synthetic stores built block by block (`tests/corrupt.py`'s
`data_block` / `xblock` / `slblock` / `siblock` under a one-page block
B-tree): a trailer whose `cb` disagrees with the B-tree, a flipped data
byte, a bid with the wrong internal bit, an unknown block type, an XBLOCK
that lists itself, a chain deeper than the format allows, an `lcbTotal`
that claims 4 GiB in a 300-byte file — each shown to raise the right
`PstError` subclass, with `PstLimitError` distinguishable from
`PstFormatError`, and the allocation check shown to fire BEFORE any child
is read. The size-boundary trap from the todo: a block whose `cb` lands
its allocation exactly on a 64-byte multiple, and one byte over, with the
trailer read from where the specification puts it.

Then the differential claim. `python -m pypstreader.debug btrees` byte-identical
to the committed `read_btrees` golden on every Unicode store — the data-tree
and sub-node sections included now — and `read_data` / `read_subnode_tree`
equal to the parsed golden's sizes and entries, so a lucky `__str__` cannot
hide a wrong value. The private stores against the live oracle, by count
and length only.
"""

from __future__ import annotations

import dataclasses
import io
import struct
import zlib
from pathlib import Path
from typing import Any

import pytest

from pypstreader import debug
from pypstreader.crc import compute_crc
from pypstreader.encode import CryptMethod, encode_decode_cyclic, encode_permute
from pypstreader.errors import (
    PstError,
    PstFormatError,
    PstLimitError,
    PstNotFoundError,
    PstUnsupportedError,
)
from pypstreader.limits import (
    DEFAULT_LIMITS,
    MAX_SUBNODE_DEPTH,
    MAX_XBLOCK_DEPTH,
    Limits,
)
from pypstreader.ndb.block import (
    BLOCK_TRAILER_SIZE,
    MAX_BLOCK_DATA_SIZE,
    MAX_BLOCK_SIZE,
    BlockReader,
    BlockTrailer,
    DataBlock,
    SubNodeIntermediateBlock,
    SubNodeLeafBlock,
    SubNodeLeafEntry,
    XBlock,
    block_size,
)
from pypstreader.ndb.btree import BlockBTree, NodeBTree
from pypstreader.ndb.header import Header, read_header
from pypstreader.ndb.ids import BlockId, BlockRef, ByteIndex, NodeId, PageId, PageRef
from tests import corrupt
from tests.conftest import FIXTURES, REFERENCE, public_fixture_paths, run_oracle
from tests.golden_parsers import parse_node_id, parse_read_btrees

EMPTY_PATH = FIXTURES / "Empty.pst"
EMPTY = EMPTY_PATH.read_bytes()
EMPTY_HEADER = Header.parse(EMPTY[: corrupt.HEADER_SIZE])
ANSI_STEMS = {"pstsdk-test_ansi", "pstsdk-sample2"}

ALL_STORES = [EMPTY_PATH, *public_fixture_paths()]
UNICODE_STORES = [p for p in ALL_STORES if p.stem not in ANSI_STEMS]
UNICODE_IDS = [p.stem for p in UNICODE_STORES]
ANSI_STORES = [p for p in ALL_STORES if p.stem in ANSI_STEMS]
ANSI_IDS = [p.stem for p in ANSI_STORES]

INTERNAL = corrupt.BID_INTERNAL

# The synthetic store: one BBT leaf page at 0x200 and blocks from 0x400 up.
BBT_OFFSET = 0x200
BBT_PAGE_ID = 0x77
FIRST_BLOCK = 0x400


class _CountingFile(io.BytesIO):
    """A file that counts its reads, so a test can prove a check fired before a read."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.reads = 0

    def read(self, size: int | None = -1, /) -> bytes:
        self.reads += 1
        return super().read(size)


def _store(
    blocks: dict[int, bytes],
    entries: list[tuple[int, int, int]],
    *,
    crypt: CryptMethod = CryptMethod.NONE,
    limits: Limits = DEFAULT_LIMITS,
    size: int | None = None,
) -> tuple[BlockReader, _CountingFile]:
    """A reader over an in-memory store: `blocks` at their offsets, `entries` as (bid, index, cb) in the BBT."""
    page = corrupt.btree_page(
        corrupt.PTYPE_BBT, 0, [corrupt.bbt_entry(bid, index, cb) for bid, index, cb in entries], BBT_PAGE_ID, BBT_OFFSET
    )
    data = corrupt.file_with_blocks({BBT_OFFSET: page, **blocks}, size)
    f = _CountingFile(data)
    bbt = BlockBTree(f, PageRef(PageId(BBT_PAGE_ID), ByteIndex(BBT_OFFSET)), limits)
    header = dataclasses.replace(EMPTY_HEADER, crypt_method=crypt)
    return BlockReader(f, header, bbt, limits), f


def _one_data_block(payload: bytes, **kwargs: Any) -> tuple[BlockReader, _CountingFile, BlockId]:
    """A store with one data block (bid 0x10 at FIRST_BLOCK); `kwargs` go to `corrupt.data_block`."""
    bid = 0x10
    block = corrupt.data_block(payload, bid, FIRST_BLOCK, **kwargs)
    reader, f = _store({FIRST_BLOCK: block}, [(bid, FIRST_BLOCK, len(payload))])
    return reader, f, BlockId(bid)


# --- block_size: the trap ------------------------------------------------------------


@pytest.mark.parametrize(
    ("cb", "expected"),
    [(1, 64), (47, 64), (48, 64), (49, 128), (112, 128), (113, 192), (8112, 8128), (8113, 8192), (8176, 8192)],
)
def test_block_size_is_the_aligned_allocation_with_the_trailer(cb: int, expected: int) -> None:
    """[MS-PST] 2.2.2.8: the smallest multiple of 64 holding cb + 16 — cb 48 fills 64 exactly, 49 spills."""
    assert block_size(cb) == expected
    assert block_size(cb) == corrupt.block_alloc_size(cb)
    assert block_size(cb) % 64 == 0 and block_size(cb) - BLOCK_TRAILER_SIZE >= cb


@pytest.mark.parametrize("cb", [0, -1, MAX_BLOCK_DATA_SIZE + 1, MAX_BLOCK_SIZE, 0xFFFF])
def test_block_size_refuses_what_upstream_asserts(cb: int) -> None:
    with pytest.raises(PstFormatError):
        block_size(cb)


@pytest.mark.parametrize("cb", [48, 49, 8112, 8113, 8176])
def test_trailer_is_read_from_the_end_of_the_allocation(cb: int) -> None:
    """The size-boundary trap: at 48 (and 8112) the allocation is exact; one over adds 64 bytes of padding.

    The store ends exactly where the block does, so a reader that
    allocates a size too large reads short; the padding is zero, so a
    reader that looks for the trailer too early finds cb = 0 and refuses.
    """
    payload = bytes(range(256)) * (cb // 256 + 1)
    payload = payload[:cb]
    reader, f, bid = _one_data_block(payload)
    assert len(f.getvalue()) == FIRST_BLOCK + block_size(cb)
    entry = reader.find(bid)
    assert entry.size == cb
    assert reader.read_block(entry.block, cb, is_internal=False) == payload
    node = reader.read_data_tree(bid)
    assert isinstance(node, DataBlock)
    assert node.data == payload and node.trailer.size == cb and node.trailer.block_id == bid
    assert reader.read_data(bid) == payload


# --- denial: the trailer --------------------------------------------------------------


@pytest.mark.parametrize("cb", [0, MAX_BLOCK_DATA_SIZE + 1, 0xFFFF])
def test_trailer_cb_outside_the_range_is_refused(cb: int) -> None:
    raw = struct.pack("<HHIQ", cb, 0, 0, 0x10)
    with pytest.raises(PstFormatError):
        BlockTrailer.unpack_from(raw)


def test_trailer_short_buffer_is_refused() -> None:
    with pytest.raises(PstFormatError):
        BlockTrailer.unpack_from(bytes(15))
    with pytest.raises(PstFormatError):
        BlockTrailer.unpack_from(bytes(32), -1)


def test_trailer_fields_and_cyclic_key() -> None:
    raw = corrupt.block_trailer(0x1FF0, 0x1_0000_0002 | 0x3, 0x4000, 0xDEADBEEF)
    t = BlockTrailer.unpack_from(raw)
    assert (t.size, t.crc) == (0x1FF0, 0xDEADBEEF)
    assert t.block_id.raw == 0x1_0000_0002 | 0x3
    # Upstream: `search_key() as u32` — the reserved bit cleared, the high half dropped.
    assert t.cyclic_key == 0x2
    assert t.signature == corrupt.block_sig(0x4000, 0x1_0000_0002 | 0x3) == t.expected_signature(ByteIndex(0x4000))


def test_bbt_cb_over_the_maximum_is_refused_before_any_read() -> None:
    """A B-tree entry claiming 8177 bytes: upstream's `block_size` panics; here it is a refusal, and no block is read."""
    reader, f, bid = _one_data_block(b"x" * 64)
    reader.find(bid)  # the page is now cached; nothing else should be read
    reads = f.reads
    for cb in (MAX_BLOCK_DATA_SIZE + 1, 0xFFFF, 0):
        with pytest.raises(PstFormatError):
            reader.read_block(BlockRef(bid, ByteIndex(FIRST_BLOCK)), cb, is_internal=False)
    assert f.reads == reads


def test_trailer_cb_that_disagrees_with_the_bbt_is_refused() -> None:
    reader, _, bid = _one_data_block(b"y" * 100, cb=99)
    with pytest.raises(PstFormatError):
        reader.read_data(bid)
    reader, _, bid = _one_data_block(b"y" * 100, cb=101)
    with pytest.raises(PstFormatError):
        reader.read_block(BlockRef(bid, ByteIndex(FIRST_BLOCK)), 100, is_internal=False)


@pytest.mark.parametrize("offset", [0, 1, 50, 99])
def test_flipped_data_byte_fails_the_crc(offset: int) -> None:
    reader, f, bid = _one_data_block(b"z" * 100)
    f.getbuffer()[FIRST_BLOCK + offset] ^= 0x01
    with pytest.raises(PstFormatError, match="CRC"):
        reader.read_data(bid)


def test_flipped_padding_byte_is_not_in_the_crc() -> None:
    """[MS-PST] 2.2.2.8.1: the CRC covers the cb bytes only; the padding before the trailer is not checked."""
    reader, f, bid = _one_data_block(b"z" * 100)  # allocation 128: padding at 100..112
    f.getbuffer()[FIRST_BLOCK + 105] ^= 0xFF
    assert reader.read_data(bid) == b"z" * 100


def test_data_block_with_an_internal_trailer_bid_is_refused() -> None:
    reader, _, bid = _one_data_block(b"d" * 20, trailer_bid=0x10 | INTERNAL)
    with pytest.raises(PstFormatError, match="bid"):
        reader.read_data(bid)


def test_tree_block_with_a_leaf_trailer_bid_is_refused() -> None:
    xb = corrupt.xblock([0x10], 0x20 | INTERNAL, FIRST_BLOCK, trailer_bid=0x20)
    reader, _ = _store({FIRST_BLOCK: xb}, [(0x20 | INTERNAL, FIRST_BLOCK, 16)])
    with pytest.raises(PstFormatError, match="bid"):
        reader.read_data_tree(BlockId(0x20 | INTERNAL))


def test_trailer_bid_index_mismatch_is_accepted_as_upstream() -> None:
    """Upstream compares only the internal bit of the trailer's bid; the goldens print the trailer's id."""
    reader, _, bid = _one_data_block(b"d" * 20, trailer_bid=0x14)
    node = reader.read_data_tree(bid)
    assert isinstance(node, DataBlock) and node.trailer.block_id == BlockId(0x14)
    assert reader.read_data(bid) == b"d" * 20


def test_signature_is_carried_not_enforced() -> None:
    """As upstream, and as pstd-inline-cid.pst / synth-basics.pst require (wSig == 0 on every block)."""
    reader, _, bid = _one_data_block(b"s" * 20, signature=0)
    node = reader.read_data_tree(bid)
    assert isinstance(node, DataBlock)
    assert node.trailer.signature == 0
    assert node.trailer.expected_signature(ByteIndex(FIRST_BLOCK)) == corrupt.block_sig(FIRST_BLOCK, 0x10)


# --- denial: tree blocks --------------------------------------------------------------


def _xtree(
    *,
    root_level: int = 1,
    root_entries: list[int] | None = None,
    total_size: int | None = None,
    limits: Limits = DEFAULT_LIMITS,
    crypt: CryptMethod = CryptMethod.NONE,
) -> tuple[BlockReader, _CountingFile, bytes]:
    """An XBLOCK (bid 0x20|I at 0x400) over two data blocks (0x10 at 0x500, 0x14 at 0x600). Returns the expected bytes."""
    a, b = b"A" * 100, b"B" * 200
    entries = root_entries if root_entries is not None else [0x10, 0x14]
    root_bid = 0x20 | INTERNAL
    body_len = 8 + 8 * len(entries)
    blocks = {
        FIRST_BLOCK: corrupt.xblock(entries, root_bid, FIRST_BLOCK, level=root_level, total_size=300 if total_size is None else total_size),
        0x500: corrupt.data_block(_encode(a, crypt, 0x10), 0x10, 0x500),
        0x600: corrupt.data_block(_encode(b, crypt, 0x14), 0x14, 0x600),
    }
    reader, f = _store(
        blocks, [(root_bid, FIRST_BLOCK, body_len), (0x10, 0x500, 100), (0x14, 0x600, 200)], limits=limits, crypt=crypt
    )
    return reader, f, a + b


def _encode(payload: bytes, crypt: CryptMethod, bid: int) -> bytes:
    if crypt == CryptMethod.PERMUTE:
        return encode_permute(payload)
    if crypt == CryptMethod.CYCLIC:
        return encode_decode_cyclic(payload, bid & 0xFFFFFFFF)
    return payload


def test_xblock_assembles_its_data_blocks_in_order() -> None:
    reader, _, expected = _xtree()
    root = reader.read_data_tree(BlockId(0x20 | INTERNAL))
    assert isinstance(root, XBlock)
    assert (root.level, root.total_size, root.entries) == (1, 300, (BlockId(0x10), BlockId(0x14)))
    assert reader.read_data(BlockId(0x20 | INTERNAL)) == expected
    assert reader.read_block(BlockRef(BlockId(0x20 | INTERNAL), ByteIndex(FIRST_BLOCK)), 24, is_internal=True) == (
        struct.pack("<BBHI", 1, 1, 2, 300) + struct.pack("<QQ", 0x10, 0x14)
    )


@pytest.mark.parametrize("btype", [0x00, 0x03, 0xFF])
def test_unknown_block_type_is_refused(btype: int) -> None:
    xb = corrupt.xblock([0x10], 0x20 | INTERNAL, FIRST_BLOCK, btype=btype)
    reader, _ = _store({FIRST_BLOCK: xb}, [(0x20 | INTERNAL, FIRST_BLOCK, 16)])
    with pytest.raises(PstFormatError):
        reader.read_data_tree(BlockId(0x20 | INTERNAL))
    with pytest.raises(PstFormatError):
        reader.read_subnode_block(BlockId(0x20 | INTERNAL))
    with pytest.raises(PstFormatError):
        reader.read_block(BlockRef(BlockId(0x20 | INTERNAL), ByteIndex(FIRST_BLOCK)), 16, is_internal=True)


def test_a_subnode_block_where_a_data_tree_is_expected_is_refused_and_vice_versa() -> None:
    sl = corrupt.slblock([(0x21, 0x10, 0)], 0x30 | INTERNAL, FIRST_BLOCK)
    xb = corrupt.xblock([0x10], 0x20 | INTERNAL, 0x500)
    reader, _ = _store({FIRST_BLOCK: sl, 0x500: xb}, [(0x30 | INTERNAL, FIRST_BLOCK, 32), (0x20 | INTERNAL, 0x500, 16)])
    with pytest.raises(PstFormatError, match="type"):
        reader.read_data_tree(BlockId(0x30 | INTERNAL))
    with pytest.raises(PstFormatError, match="type"):
        reader.read_subnode_block(BlockId(0x20 | INTERNAL))
    # Either reads as the tree block it is through the type-agnostic entry point.
    assert reader.read_block(BlockRef(BlockId(0x30 | INTERNAL), ByteIndex(FIRST_BLOCK)), 32, is_internal=True)[0] == 2
    assert reader.read_block(BlockRef(BlockId(0x20 | INTERNAL), ByteIndex(0x500)), 16, is_internal=True)[0] == 1


def test_subnode_block_padding_must_be_zero() -> None:
    sl = corrupt.slblock([(0x21, 0x10, 0)], 0x30 | INTERNAL, FIRST_BLOCK, padding=1)
    reader, _ = _store({FIRST_BLOCK: sl}, [(0x30 | INTERNAL, FIRST_BLOCK, 32)])
    with pytest.raises(PstFormatError, match="dwPadding"):
        reader.read_subnode_block(BlockId(0x30 | INTERNAL))


@pytest.mark.parametrize(("kind", "count"), [("x", 2), ("x", 1021), ("x", 0xFFFF), ("sl", 2), ("si", 0xFFFF)])
def test_entry_count_that_does_not_fit_the_block_is_refused(kind: str, count: int) -> None:
    """Upstream's `InvalidInternalBlockEntryCount`: cEnt × entry size > cb - 8 (and a u16 that would overflow it)."""
    if kind == "x":
        block = corrupt.xblock([0x10], 0x20 | INTERNAL, FIRST_BLOCK, count=count)
        cb = 16
    elif kind == "sl":
        block = corrupt.slblock([(0x21, 0x10, 0)], 0x20 | INTERNAL, FIRST_BLOCK, count=count)
        cb = 32
    else:
        block = corrupt.siblock([(0x21, 0x10)], 0x20 | INTERNAL, FIRST_BLOCK, count=count)
        cb = 24
    reader, _ = _store({FIRST_BLOCK: block}, [(0x20 | INTERNAL, FIRST_BLOCK, cb)])
    with pytest.raises(PstFormatError, match="entries"):
        reader.read_block(BlockRef(BlockId(0x20 | INTERNAL), ByteIndex(FIRST_BLOCK)), cb, is_internal=True)


def test_tree_block_cb_below_its_header_is_refused() -> None:
    xb = corrupt.xblock([], 0x20 | INTERNAL, FIRST_BLOCK, cb=4)
    reader, _ = _store({FIRST_BLOCK: xb}, [(0x20 | INTERNAL, FIRST_BLOCK, 4)])
    with pytest.raises(PstFormatError):
        reader.read_data_tree(BlockId(0x20 | INTERNAL))


def test_tree_block_with_slack_past_its_entries_is_read_where_upstream_reads_it() -> None:
    """Upstream seeks to the trailer from the size the header IMPLIES; with slack in cb it lands on padding and refuses."""
    # cb 24 over a header + one entry (16 bytes): upstream seeks 24 + (64 - 32) = 56, past the trailer at 48.
    # The CRC is sealed over all 24 cb bytes so that ONLY the trailer's location can refuse the block.
    body = struct.pack("<BBHI", 1, 1, 1, 0) + struct.pack("<Q", 0x10) + bytes(8)
    xb = corrupt.xblock([0x10], 0x20 | INTERNAL, FIRST_BLOCK, cb=24, crc=compute_crc(0, body))
    reader, _ = _store({FIRST_BLOCK: xb}, [(0x20 | INTERNAL, FIRST_BLOCK, 24)])
    with pytest.raises(PstFormatError, match="trailer"):
        reader.read_data_tree(BlockId(0x20 | INTERNAL))
    # Whereas cb equal to the implied size, with a trailer at the allocation's end, is the well-formed case.
    xb = corrupt.xblock([0x10], 0x20 | INTERNAL, FIRST_BLOCK)
    reader, _ = _store({FIRST_BLOCK: xb}, [(0x20 | INTERNAL, FIRST_BLOCK, 16)])
    assert isinstance(reader.read_data_tree(BlockId(0x20 | INTERNAL)), XBlock)


def test_xblock_entry_absent_from_the_bbt_is_not_found() -> None:
    reader, _, _ = _xtree(root_entries=[0x10, 0x18])
    with pytest.raises(PstNotFoundError):
        reader.read_data(BlockId(0x20 | INTERNAL))
    with pytest.raises(PstNotFoundError):
        reader.read_data(BlockId(0))
    with pytest.raises(PstNotFoundError):
        reader.read_subnode_tree(BlockId(0x99 | INTERNAL))


# --- limits: depth, cycles, allocation ------------------------------------------------


def _chain(depth: int, limits: Limits = DEFAULT_LIMITS) -> tuple[BlockReader, BlockId]:
    """`depth` internal blocks in a line — XX → … → X → one data block. depth 2 is the format's maximum."""
    leaf_bid, leaf_at = 0x10, 0x1000
    blocks = {leaf_at: corrupt.data_block(b"L" * 64, leaf_bid, leaf_at)}
    entries = [(leaf_bid, leaf_at, 64)]
    child = leaf_bid
    for level in range(1, depth + 1):
        bid, at = (0x20 + 4 * level) | INTERNAL, 0x400 + 0x40 * level
        blocks[at] = corrupt.xblock([child], bid, at, level=min(level, 2), total_size=64)
        entries.append((bid, at, 16))
        child = bid
    reader, _ = _store(blocks, entries, limits=limits)
    return reader, BlockId(child)


@pytest.mark.parametrize("depth", [1, 2])
def test_data_tree_up_to_the_format_depth_reads(depth: int) -> None:
    reader, root = _chain(depth)
    assert reader.read_data(root) == b"L" * 64


@pytest.mark.parametrize("depth", [3, 4])
def test_data_tree_deeper_than_the_format_is_a_limit_error(depth: int) -> None:
    reader, root = _chain(depth)
    with pytest.raises(PstLimitError) as info:
        reader.read_data(root)
    assert "depth" in str(info.value) and not isinstance(info.value, PstFormatError)
    assert MAX_XBLOCK_DEPTH == 2
    # A raised ceiling reads it, and shows the trip was the limit, not the bytes.
    reader, root = _chain(depth, Limits(max_xblock_depth=depth))
    assert reader.read_data(root) == b"L" * 64


def test_xblock_that_lists_itself_is_a_cycle() -> None:
    root = 0x20 | INTERNAL
    xb = corrupt.xblock([root], root, FIRST_BLOCK, total_size=64)
    reader, _ = _store({FIRST_BLOCK: xb}, [(root, FIRST_BLOCK, 16)], limits=Limits(max_xblock_depth=64))
    with pytest.raises(PstLimitError, match="cycle"):
        reader.read_data(BlockId(root))


def test_two_xblocks_that_list_each_other_are_a_cycle() -> None:
    a, b = 0x20 | INTERNAL, 0x24 | INTERNAL
    blocks = {0x400: corrupt.xblock([b], a, 0x400, level=2), 0x440: corrupt.xblock([a], b, 0x440)}
    reader, _ = _store(blocks, [(a, 0x400, 16), (b, 0x440, 16)], limits=Limits(max_xblock_depth=64))
    with pytest.raises(PstLimitError, match="cycle"):
        reader.read_data(BlockId(a))


def test_lcb_total_of_four_gib_is_refused_before_any_child_is_read() -> None:
    """The claim is checked first: the children are not in the B-tree, so reading one would be a different error."""
    reader, f, _ = _xtree(root_entries=[0x18, 0x1C], total_size=0xFFFFFFFF)
    reader.find(BlockId(0x20 | INTERNAL))
    reads = f.reads
    with pytest.raises(PstLimitError) as info:
        reader.read_data(BlockId(0x20 | INTERNAL))
    assert "lcbTotal" in str(info.value)
    # One BBT leaf page (leaves are not cached) and the XBLOCK itself; a
    # child lookup would have raised PstNotFoundError before any block read.
    assert f.reads == reads + 2, "only the B-tree page and the XBLOCK were read"
    assert len(f.getvalue()) < 0x1000


def test_assembled_size_is_bounded_even_when_lcb_total_lies() -> None:
    reader, _, expected = _xtree(total_size=10, limits=Limits(max_allocation=299))
    with pytest.raises(PstLimitError, match="assembled"):
        reader.read_data(BlockId(0x20 | INTERNAL))
    reader, _, expected = _xtree(total_size=10, limits=Limits(max_allocation=300))
    assert reader.read_data(BlockId(0x20 | INTERNAL)) == expected


def test_lcb_total_is_not_compared_with_the_assembled_length() -> None:
    """As upstream: `lcbTotal` is printed and never checked; the bytes are the leaves, in order."""
    reader, _, expected = _xtree(total_size=1)
    assert reader.read_data(BlockId(0x20 | INTERNAL)) == expected


def _subtree(
    levels: int, *, leaf_entries: int = 2, limits: Limits = DEFAULT_LIMITS, cycle: bool = False
) -> tuple[BlockReader, BlockId]:
    """`levels` SIBLOCKs in a line over one SLBLOCK of `leaf_entries` entries; `cycle` makes the top SI name itself."""
    sl_bid, sl_at = 0x30 | INTERNAL, 0x1000
    leaf = [(0x21 + 0x20 * i, 0x10 + 4 * i, 0) for i in range(leaf_entries)]
    blocks = {sl_at: corrupt.slblock(leaf, sl_bid, sl_at)}
    entries = [(sl_bid, sl_at, 8 + 24 * leaf_entries)]
    child = sl_bid
    for level in range(1, levels + 1):
        bid, at = (0x40 + 4 * level) | INTERNAL, 0x400 + 0x40 * level
        blocks[at] = corrupt.siblock([(0x21, bid if cycle and level == levels else child)], bid, at, level=level)
        entries.append((bid, at, 24))
        child = bid
    reader, _ = _store(blocks, entries, limits=limits)
    return reader, BlockId(child)


def test_subnode_tree_reads_leaf_and_one_intermediate_level() -> None:
    for levels in (0, 1):
        reader, root = _subtree(levels)
        tree = reader.read_subnode_tree(root)
        assert list(tree) == [NodeId(0x21), NodeId(0x41)]
        assert tree[NodeId(0x41)] == SubNodeLeafEntry(NodeId(0x41), BlockId(0x14), None)
    node = reader.read_subnode_block(root)
    assert isinstance(node, SubNodeIntermediateBlock) and node.level == 1
    assert node.entries[0].node == NodeId(0x21) and node.entries[0].next_level == BlockId(0x30 | INTERNAL)
    leaf = reader.read_subnode_block(node.entries[0].next_level)
    assert isinstance(leaf, SubNodeLeafBlock) and leaf.level == 0 and len(leaf.entries) == 2


@pytest.mark.parametrize("levels", [2, 3])
def test_subnode_tree_deeper_than_the_format_is_a_limit_error(levels: int) -> None:
    reader, root = _subtree(levels)
    with pytest.raises(PstLimitError, match="depth"):
        reader.read_subnode_tree(root)
    assert MAX_SUBNODE_DEPTH == 2
    reader, root = _subtree(levels, limits=Limits(max_subnode_depth=levels + 1))
    assert len(reader.read_subnode_tree(root)) == 2


def test_siblock_that_names_itself_is_a_cycle() -> None:
    reader, root = _subtree(1, cycle=True, limits=Limits(max_subnode_depth=64))
    with pytest.raises(PstLimitError, match="cycle"):
        reader.read_subnode_tree(root)


def test_subnode_entry_count_over_the_limit_is_refused_and_at_it_passes() -> None:
    reader, root = _subtree(0, leaf_entries=4, limits=Limits(max_items=3))
    with pytest.raises(PstLimitError, match="entries"):
        reader.read_subnode_tree(root)
    reader, root = _subtree(0, leaf_entries=4, limits=Limits(max_items=4))
    assert len(reader.read_subnode_tree(root)) == 4


def test_duplicate_subnode_nid_keeps_the_first_as_upstream() -> None:
    sl = corrupt.slblock([(0x21, 0x10, 0), (0x21, 0x14, 0)], 0x30 | INTERNAL, FIRST_BLOCK)
    reader, _ = _store({FIRST_BLOCK: sl}, [(0x30 | INTERNAL, FIRST_BLOCK, 56)])
    tree = reader.read_subnode_tree(BlockId(0x30 | INTERNAL))
    assert tree == {NodeId(0x21): SubNodeLeafEntry(NodeId(0x21), BlockId(0x10), None)}


def test_subnode_entry_nid_is_truncated_to_32_bits_as_upstream() -> None:
    """Upstream reads the 8-byte nid `as u32` (block.rs); the NBTENTRY reader refuses instead (page.py)."""
    sl = corrupt.slblock([(0x1_0000_0021, 0x10, 0x34 | INTERNAL)], 0x30 | INTERNAL, FIRST_BLOCK)
    reader, _ = _store({FIRST_BLOCK: sl}, [(0x30 | INTERNAL, FIRST_BLOCK, 32)])
    (entry,) = reader.read_subnode_block(BlockId(0x30 | INTERNAL)).entries
    assert entry == SubNodeLeafEntry(NodeId(0x21), BlockId(0x10), BlockId(0x34 | INTERNAL))


# --- denial: the file -----------------------------------------------------------------


def test_block_reference_past_eof_is_refused() -> None:
    reader, _, _ = _one_data_block(b"e" * 64)
    with pytest.raises(PstFormatError, match="short read"):
        reader.read_block(BlockRef(BlockId(0x10), ByteIndex(0x10000)), 64, is_internal=False)


@pytest.mark.parametrize("index", [2**63, 2**64 - 1, 64 * 2**30 - 1])
def test_block_reference_beyond_the_largest_file_is_refused_before_the_seek(index: int) -> None:
    reader, f, _ = _one_data_block(b"e" * 64)
    reads = f.reads
    with pytest.raises(PstFormatError, match="largest supported file"):
        reader.read_block(BlockRef(BlockId(0x10), ByteIndex(index)), 64, is_internal=False)
    assert f.reads == reads


def test_file_truncated_inside_the_final_block_is_refused() -> None:
    payload = b"t" * 100  # allocation 128
    block = corrupt.data_block(payload, 0x10, FIRST_BLOCK)
    for cut in (1, 16, 17, 28, 127):
        reader, _ = _store({FIRST_BLOCK: block[: 128 - cut]}, [(0x10, FIRST_BLOCK, 100)], size=FIRST_BLOCK + 128 - cut)
        with pytest.raises(PstFormatError, match="short read"):
            reader.read_data(BlockId(0x10))


def test_mutated_empty_pst_block_is_refused_and_the_walk_stays_pst_error() -> None:
    """Empty.pst with one data byte flipped, and with a trailer cb changed: both refused via node_data."""
    with EMPTY_PATH.open("rb") as f:
        header = read_header(f)
        bbt = BlockBTree(f, header.root.block_btree)
        entry = next(e for e in bbt if not e.block.block.is_internal)
    at = entry.block.index.value
    for mutant in (
        corrupt.flip_byte(EMPTY, at),
        corrupt.set_u16(EMPTY, at + block_size(entry.size) - BLOCK_TRAILER_SIZE, entry.size + 1),
        corrupt.truncate(EMPTY, at + 8),
    ):
        f = io.BytesIO(mutant)
        header = read_header(f)
        bbt = BlockBTree(f, header.root.block_btree)
        reader = BlockReader(f, header, bbt)
        with pytest.raises(PstFormatError):
            reader.read_data(entry.block.block)
    with io.BytesIO(EMPTY) as f:
        header = read_header(f)
        reader = BlockReader(f, header, BlockBTree(f, header.root.block_btree))
        assert len(reader.read_data(entry.block.block)) == entry.size


# --- decoding ---------------------------------------------------------------------------


@pytest.mark.parametrize("crypt", list(CryptMethod))
def test_data_blocks_are_decoded_by_the_header_method(crypt: CryptMethod) -> None:
    payload = bytes(range(256)) * 2
    bid = 0x1_0000_0010  # a high half, so the cyclic key's truncation is exercised
    block = corrupt.data_block(_encode(payload, crypt, bid), bid, FIRST_BLOCK)
    reader, _ = _store({FIRST_BLOCK: block}, [(bid, FIRST_BLOCK, len(payload))], crypt=crypt)
    assert reader.crypt_method == crypt
    assert reader.read_block(BlockRef(BlockId(bid), ByteIndex(FIRST_BLOCK)), len(payload), is_internal=False) == payload
    assert reader.read_data(BlockId(bid)) == payload
    if crypt != CryptMethod.NONE:
        raw = corrupt.data_block(payload, bid, FIRST_BLOCK)
        reader, _ = _store({FIRST_BLOCK: raw}, [(bid, FIRST_BLOCK, len(payload))], crypt=crypt)
        assert reader.read_data(BlockId(bid)) != payload, "an unencoded block must not read as its plaintext"


@pytest.mark.parametrize("crypt", [CryptMethod.PERMUTE, CryptMethod.CYCLIC])
def test_internal_blocks_are_never_decoded(crypt: CryptMethod) -> None:
    reader, _, expected = _xtree(crypt=crypt)
    root = reader.read_data_tree(BlockId(0x20 | INTERNAL))
    assert isinstance(root, XBlock) and root.entries == (BlockId(0x10), BlockId(0x14))
    assert reader.read_data(BlockId(0x20 | INTERNAL)) == expected
    sl = corrupt.slblock([(0x21, 0x10, 0)], 0x30 | INTERNAL, 0x700)
    reader, _ = _store({0x700: sl}, [(0x30 | INTERNAL, 0x700, 32)], crypt=crypt)
    assert list(reader.read_subnode_tree(BlockId(0x30 | INTERNAL))) == [NodeId(0x21)]


# --- property: every block the corpus B-trees name reads -----------------------------------


@pytest.mark.parametrize("store", [EMPTY_PATH, FIXTURES / "public" / "synth-basics.pst"], ids=["Empty", "synth-basics"])
def test_every_bbt_leaf_block_reads_and_its_trailer_matches_the_entry(store: Path) -> None:
    """The trailer walk in tests/spec/test_ms_pst_trailers.py proves the offsets; this proves the reader agrees."""
    if not store.exists():
        pytest.skip(f"{store.name} not in the corpus")
    with store.open("rb") as f:
        header = read_header(f)
        bbt = BlockBTree(f, header.root.block_btree)
        reader = BlockReader(f, header, bbt)
        count = 0
        for entry in bbt:
            internal = entry.block.block.is_internal
            data = reader.read_block(entry.block, entry.size, is_internal=internal)
            assert len(data) == entry.size
            f.seek(entry.block.index.value)
            raw = f.read(block_size(entry.size))
            trailer = BlockTrailer.unpack_from(raw, len(raw) - BLOCK_TRAILER_SIZE)
            assert trailer.size == entry.size and trailer.block_id.is_internal == internal
            count += 1
    assert count > 0


# --- differential: goldens ---------------------------------------------------------------


def _strip_prefix(text: str) -> str:
    return text.replace("Unicode", "")


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_debug_btrees_is_byte_identical_to_the_golden(store: Path, golden, golden_exit, capsys: pytest.CaptureFixture[str]) -> None:
    assert golden_exit(store, "read_btrees") == 0
    golden_text = golden(store, "read_btrees")
    assert debug.main(["btrees", str(store)]) == 0
    out = capsys.readouterr().out
    assert out == _strip_prefix(golden_text), f"{store.stem}: read_btrees text differs from the oracle"
    assert parse_read_btrees(out) == parse_read_btrees(golden_text)


def _golden_data_size(data: dict[str, Any]) -> int:
    if "blocks" in data:
        return sum(_golden_data_size(child["tree"]) for child in data["blocks"])
    return data.get("size", 0)


def _check_data(reader: BlockReader, block: dict[str, Any], data: dict[str, Any], problems: list[str], where: str) -> None:
    bid = BlockId.from_parts(block["internal"], block["index"])
    if "size" not in data and "blocks" not in data:
        return  # a zero data block: the oracle prints only the id
    if len(reader.read_data(bid)) != _golden_data_size(data):
        problems.append(f"{where}: data length")
    if "blocks" in data:
        root = reader.read_data_tree(bid)
        if not isinstance(root, XBlock) or root.level != data["level"] or root.total_size != data["total_size"]:
            problems.append(f"{where}: XBLOCK header")
        elif [e.index for e in root.entries] != [b["block"]["index"] for b in data["blocks"]]:
            problems.append(f"{where}: XBLOCK entries")


def _check_subnodes(reader: BlockReader, sub_node: dict[str, Any] | None, problems: list[str], where: str) -> int:
    """Compare a node's subnode tree with the golden's; returns the number of subnode entries seen."""
    if sub_node is None or sub_node["tree"] is None:
        return 0
    bid = BlockId.from_parts(sub_node["block"]["internal"], sub_node["block"]["index"])
    tree = reader.read_subnode_tree(bid)
    golden_entries = _golden_leaf_entries(sub_node["tree"])
    if [_nid(n) for n in tree] != [e["node"] for e in golden_entries]:
        problems.append(f"{where}: subnode keys")
        return len(golden_entries)
    seen = 0
    for entry, g in zip(tree.values(), golden_entries, strict=True):
        data = g["data"]
        expected_data = data.get("block")
        if expected_data is not None and (entry.data.index, entry.data.is_internal) != (expected_data["index"], expected_data["internal"]):
            problems.append(f"{where}: subnode {entry.node} data id")
        if reader.find(entry.data).block.index.value != g["ref"]["index"]:
            problems.append(f"{where}: subnode {entry.node} block ref")
        _check_data(reader, {"internal": entry.data.is_internal, "index": entry.data.index}, data, problems, f"{where}/{entry.node}")
        if (entry.sub_node is None) != (g["sub_node"] is None):
            problems.append(f"{where}: subnode {entry.node} sub_node presence")
        seen += 1 + _check_subnodes(reader, g["sub_node"], problems, f"{where}/{entry.node}")
    return seen


def _golden_leaf_entries(tree: dict[str, Any]) -> list[dict[str, Any]]:
    if tree["level"] == 0:
        return list(tree["entries"])
    out: list[dict[str, Any]] = []
    for entry in tree["entries"]:
        out.extend(_golden_leaf_entries(entry["tree"]))
    return out


def _nid(node: NodeId) -> dict[str, Any]:
    """Our id in the golden parser's shape (a type the enum lacks prints as `invalid`, as upstream's does)."""
    return parse_node_id(str(node))


def _golden_nodes(page: dict[str, Any]) -> list[dict[str, Any]]:
    if "entries" in page:
        return list(page["entries"])
    out: list[dict[str, Any]] = []
    for child in page["children"]:
        if child["page"] is not None:
            out.extend(_golden_nodes(child["page"]))
    return out


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_read_data_and_subnode_trees_match_the_golden_values(store: Path, golden) -> None:
    """Every node's data length, XBLOCK header and entries, and every subnode entry, against the parsed golden."""
    expected = parse_read_btrees(golden(store, "read_btrees"))
    golden_nodes = _golden_nodes(expected["node_btree"])
    problems: list[str] = []
    nodes = subnodes = 0
    with store.open("rb") as f:
        header = read_header(f)
        nbt = NodeBTree(f, header.root.node_btree)
        reader = BlockReader(f, header, BlockBTree(f, header.root.block_btree))
        for entry, g in zip(nbt, golden_nodes, strict=True):
            where = str(entry.node)
            assert _nid(entry.node) == g["node"], where
            _check_data(reader, {"internal": entry.data.is_internal, "index": entry.data.index}, g["data"], problems, where)
            if entry.data.search_key != 0:
                assert reader.node_data(entry) == reader.read_data(entry.data)
            subnodes += _check_subnodes(reader, g["sub_node"], problems, where)
            nodes += 1
    assert not problems, f"{store.stem}: {problems[:5]}"
    assert nodes == len(golden_nodes) > 0


@pytest.mark.parametrize("store", ANSI_STORES, ids=ANSI_IDS)
def test_ansi_store_is_refused_at_the_header(store: Path) -> None:
    with store.open("rb") as f, pytest.raises(PstUnsupportedError):
        read_header(f)
    assert debug.main(["node", str(store), "21"]) == 1


# --- the node dumper ------------------------------------------------------------------------


def test_debug_node_prints_length_crc_and_subnode_count(capsys: pytest.CaptureFixture[str]) -> None:
    with EMPTY_PATH.open("rb") as f:
        header = read_header(f)
        nbt = NodeBTree(f, header.root.node_btree)
        reader = BlockReader(f, header, BlockBTree(f, header.root.block_btree))
        entry = nbt.find(NodeId(0x21))
        data = reader.node_data(entry)
    for spelling in ("21", "0x21", "0X21"):
        assert debug.main(["node", str(EMPTY_PATH), spelling]) == 0
        lines = capsys.readouterr().out.splitlines()
        assert lines == [
            "Node: NodeId { Internal: 0x1 }",
            f"Data Length: {len(data)}",
            f"Data CRC32: 0x{zlib.crc32(data):08X}",
            "Sub-Nodes: 0",
        ]
    assert len(data) > 0


def test_debug_node_refusals(capsys: pytest.CaptureFixture[str]) -> None:
    assert debug.main(["node", str(EMPTY_PATH), "0x7FFFFFFF"]) == 1  # not in the NBT
    assert capsys.readouterr().err.startswith("Error:")
    assert debug.main(["node", str(EMPTY_PATH), "zz"]) == 1
    assert capsys.readouterr().err.startswith("Error:")
    with pytest.raises(SystemExit) as info:
        debug.main(["node", str(EMPTY_PATH)])
    assert info.value.code == 2
    with pytest.raises(SystemExit) as info:
        debug.main(["header", str(EMPTY_PATH), "21"])
    assert info.value.code == 2
    assert "node" in debug.DUMPERS and "btrees" in debug.DUMPERS


def test_nothing_but_pst_error_escapes_the_reader() -> None:
    """Every byte of a small store flipped, one at a time: the reader raises PstError or returns."""
    _, f, _ = _xtree()
    original = f.getvalue()
    for offset in range(BBT_OFFSET, len(original)):
        buf = io.BytesIO(corrupt.flip_byte(original, offset))
        bbt = BlockBTree(buf, PageRef(PageId(BBT_PAGE_ID), ByteIndex(BBT_OFFSET)))
        fresh = BlockReader(buf, EMPTY_HEADER, bbt)
        try:
            fresh.read_data(BlockId(0x20 | INTERNAL))
            fresh.read_subnode_tree(BlockId(0x20 | INTERNAL))
        except PstError:
            pass


# --- differential: private stores against the live oracle ----------------------------------


@pytest.mark.private
@pytest.mark.oracle
def test_private_node_data_lengths_match_live_oracle(private_stores: list[Path], oracle: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Structure only: per node, the data length and subnode count; reported by count, never by content."""
    if not private_stores:
        pytest.skip("no private stores present (this is a normal clean checkout)")
    assert oracle == REFERENCE
    checked = 0
    failures: list[str] = []
    for store in private_stores:
        try:
            with store.open("rb") as f:
                read_header(f)
        except PstUnsupportedError:
            continue  # an ANSI store: refused here, and upstream's example fails on it too
        expected = parse_read_btrees(run_oracle(oracle, "read_btrees", str(store)))
        golden_nodes = _golden_nodes(expected["node_btree"])
        problems: list[str] = []
        with store.open("rb") as f:
            header = read_header(f)
            nbt = NodeBTree(f, header.root.node_btree)
            reader = BlockReader(f, header, BlockBTree(f, header.root.block_btree))
            entries = list(nbt)
            if len(entries) != len(golden_nodes):
                failures.append(f"store {checked}: {len(entries)} nodes vs {len(golden_nodes)}")
                continue
            for entry, g in zip(entries, golden_nodes, strict=True):
                _check_data(reader, {"internal": entry.data.is_internal, "index": entry.data.index}, g["data"], problems, "node")
                _check_subnodes(reader, g["sub_node"], problems, "node")
                if entry.data.search_key != 0:
                    # The dumper's length agrees with the walk's; its output is captured and discarded.
                    assert debug.main(["node", str(store), f"{entry.node.raw:x}"]) == 0
                    lines = capsys.readouterr().out.splitlines()
                    if lines[1] != f"Data Length: {len(reader.node_data(entry))}":
                        problems.append("node: dumper length")
        if problems:
            failures.append(f"store {checked}: {len(problems)} problem(s)")
        checked += 1
    assert checked > 0, "no Unicode private store"
    assert not failures, f"{len(failures)} of {checked} private store(s) differ from the oracle: {failures}"
