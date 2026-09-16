"""BTree-on-Heap: refused when the header or a page lies; the same pairs by descent as by walk.

Denial first, on synthetic heaps from `tests/corrupt.py` (`bth_heap`,
`bth_header`, `bth_leaf`, `bth_index`): a `bType` that is not bTypeBTH, a
`cbKey` outside {2, 4, 8, 16}, a `cbEnt` of 0 or 33, more index levels than
the limit, a root HID with type bits, a page that is not a whole number of
records (the upstream `while let Ok` bug, refused here), an index record
naming a page that is not there, a root that names itself and two pages
that name each other (cycles, `PstLimitError`), a record count over
`limits.max_items`. Then the walks: leaf-only and one-, two- and
three-level trees at every key width give back their pairs in order, and
`find` agrees with the walk on every present key and answers None for
every absent one; on every Unicode store the three fixed PCs' trees are
sorted, `find` matches `entries`, and `python -m pypst.debug bth` prints
the records.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from pypst import debug
from pypst.errors import PstError, PstFormatError, PstLimitError
from pypst.limits import MAX_HEAP_TREE_DEPTH, Limits
from pypst.ltp.heap import HeapId, HeapNode
from pypst.ltp.tree import (
    BTH_HEADER_SIZE,
    KEY_SIZES,
    MAX_ENTRY_SIZE,
    HeapTree,
    HeapTreeHeader,
)
from pypst.ndb.block import BlockReader
from pypst.ndb.btree import BlockBTree, NodeBTree
from pypst.ndb.header import read_header
from pypst.ndb.ids import NID_MESSAGE_STORE, NID_NAME_TO_ID_MAP, NID_ROOT_FOLDER
from tests import corrupt
from tests.conftest import FIXTURES, public_fixture_paths

EMPTY_PATH = FIXTURES / "Empty.pst"
ANSI_STEMS = {"pstsdk-test_ansi", "pstsdk-sample2"}
UNICODE_STORES = [p for p in [EMPTY_PATH, *public_fixture_paths()] if p.stem not in ANSI_STEMS]
UNICODE_IDS = [p.stem for p in UNICODE_STORES]

HID = corrupt.hid


def _pairs(n: int, key_size: int = 2, entry_size: int = 6, step: int = 3) -> list[tuple[bytes, bytes]]:
    """`n` sorted pairs: keys 1, 1+step, … as little-endian ints, values that name their key."""
    return [((1 + i * step).to_bytes(key_size, "little"), (i * 7 + 1).to_bytes(entry_size, "little")) for i in range(n)]


def _tree(items: list[bytes], **kwargs: object) -> HeapTree:
    return HeapTree(HeapNode([corrupt.heap_node(items)], **kwargs))  # type: ignore[arg-type]


# --- header denials -------------------------------------------------------------------------


@pytest.mark.parametrize("btype", [0xBC, 0x7C, 0x00, 0xB4, 0xFF])
def test_header_type_that_is_not_bth_is_refused(btype: int) -> None:
    with pytest.raises(PstFormatError, match="BTH header type|client signature"):
        _tree([corrupt.bth_header(btype=btype)])


@pytest.mark.parametrize("key_size", [0, 1, 3, 5, 6, 7, 9, 15, 17, 32, 255])
def test_key_size_outside_the_four_widths_is_refused(key_size: int) -> None:
    with pytest.raises(PstFormatError, match="key size"):
        _tree([corrupt.bth_header(key_size=key_size)])


@pytest.mark.parametrize("entry_size", [0, MAX_ENTRY_SIZE + 1, 64, 255])
def test_entry_size_outside_one_to_thirty_two_is_refused(entry_size: int) -> None:
    with pytest.raises(PstFormatError, match="entry size"):
        _tree([corrupt.bth_header(entry_size=entry_size)])


@pytest.mark.parametrize("key_size", KEY_SIZES)
@pytest.mark.parametrize("entry_size", [1, MAX_ENTRY_SIZE])
def test_every_allowed_width_is_accepted(key_size: int, entry_size: int) -> None:
    tree = _tree([corrupt.bth_header(key_size, entry_size)])
    assert (tree.key_size, tree.entry_size, tree.levels, tree.root.is_null) == (key_size, entry_size, 0, True)
    assert isinstance(tree.header, HeapTreeHeader) and HeapTreeHeader.SIZE == BTH_HEADER_SIZE == 8


def test_root_with_type_bits_is_refused() -> None:
    with pytest.raises(PstFormatError, match="type bits"):
        _tree([corrupt.bth_header(root=HID(2) | 0x03)])


def test_header_item_shorter_than_eight_bytes_is_refused() -> None:
    with pytest.raises(PstFormatError, match="BTHHEADER"):
        _tree([corrupt.bth_header()[:7]])


def test_header_at_a_user_root_that_is_not_there_is_refused() -> None:
    with pytest.raises(PstFormatError, match="past the block"):
        HeapTree(HeapNode([corrupt.heap_node([corrupt.bth_header()], user_root=HID(2))]))
    with pytest.raises(PstFormatError, match="null"):
        HeapTree(HeapNode([corrupt.heap_node([corrupt.bth_header()], user_root=0)]))


@pytest.mark.parametrize("levels", [MAX_HEAP_TREE_DEPTH + 1, 200, 255])
def test_more_index_levels_than_the_limit_is_a_limit_error_even_for_an_empty_tree(levels: int) -> None:
    with pytest.raises(PstLimitError, match="BTH index levels"):
        _tree([corrupt.bth_header(levels=levels)])
    assert _tree([corrupt.bth_header(levels=MAX_HEAP_TREE_DEPTH)]).levels == MAX_HEAP_TREE_DEPTH


def test_a_smaller_depth_limit_is_honoured_and_the_ceiling_passes() -> None:
    limits = Limits(max_heap_tree_depth=2)
    assert _tree([corrupt.bth_header(levels=2)], limits=limits).levels == 2
    with pytest.raises(PstLimitError):
        _tree([corrupt.bth_header(levels=3)], limits=limits)


# --- page denials ---------------------------------------------------------------------------


def test_leaf_page_that_is_not_a_whole_number_of_records_is_refused() -> None:
    """Upstream's `while let Ok` would return the whole records and drop the tail; this port refuses (module docstring)."""
    pairs = _pairs(2)
    for tail in (b"\x01", b"\x01\x02\x03", bytes(7)):
        tree = _tree([corrupt.bth_header(root=HID(2)), corrupt.bth_leaf(pairs) + tail])
        with pytest.raises(PstFormatError, match="not a whole number of 8-byte records"):
            list(tree)
        with pytest.raises(PstFormatError):
            tree.find(pairs[0][0])


def test_index_page_that_is_not_a_whole_number_of_records_is_refused() -> None:
    leaf = corrupt.bth_leaf(_pairs(2))
    index = corrupt.bth_index([(b"\x01\x00", HID(3))]) + b"\x00"
    with pytest.raises(PstFormatError, match="not a whole number of 6-byte records"):
        list(_tree([corrupt.bth_header(levels=1, root=HID(2)), index, leaf]))


def test_index_record_with_type_bits_in_its_hid_is_refused_not_skipped() -> None:
    leaf = corrupt.bth_leaf(_pairs(2))
    index = corrupt.bth_index([(b"\x01\x00", HID(3) | 0x01)])
    with pytest.raises(PstFormatError, match="type bits"):
        list(_tree([corrupt.bth_header(levels=1, root=HID(2)), index, leaf]))


@pytest.mark.parametrize("target", [HID(0x7FF), HID(4), HID(1, block=1), 0])
def test_index_record_naming_a_page_that_is_not_there_is_refused(target: int) -> None:
    leaf = corrupt.bth_leaf(_pairs(2))
    index = corrupt.bth_index([(b"\x01\x00", target)])
    tree = _tree([corrupt.bth_header(levels=1, root=HID(2)), index, leaf])
    with pytest.raises(PstFormatError):
        list(tree)
    with pytest.raises(PstFormatError):
        tree.find(b"\x01\x00")


def test_index_record_naming_the_header_item_is_refused_as_a_ragged_page() -> None:
    # The 8-byte BTHHEADER read as 8-byte leaf records would be one garbage record;
    # read as 6-byte index records it is ragged. Both are refused, the second by length.
    index = corrupt.bth_index([(b"\x01\x00", HID(1))])
    with pytest.raises(PstFormatError, match="not a whole number of 6-byte records"):
        list(_tree([corrupt.bth_header(levels=2, root=HID(2)), index]))


def test_levels_that_lie_about_a_leaf_are_refused() -> None:
    pairs = _pairs(3)  # 24 bytes: a whole number of 6-byte index records, each with a garbage HID
    tree = _tree([corrupt.bth_header(levels=1, root=HID(2)), corrupt.bth_leaf(pairs)])
    with pytest.raises(PstFormatError):
        list(tree)


def test_root_that_names_itself_is_a_cycle() -> None:
    root = HID(2)
    tree = _tree([corrupt.bth_header(levels=1, root=root), corrupt.bth_index([(b"\x01\x00", root)])])
    with pytest.raises(PstLimitError, match="cycle"):
        list(tree)
    with pytest.raises(PstLimitError, match="cycle"):
        tree.find(b"\x01\x00")


def test_two_index_pages_that_name_each_other_are_a_cycle() -> None:
    a, b = HID(2), HID(3)
    tree = _tree([corrupt.bth_header(levels=2, root=a), corrupt.bth_index([(b"\x01\x00", b)]), corrupt.bth_index([(b"\x01\x00", a)])])
    with pytest.raises(PstLimitError, match="cycle"):
        list(tree)


def test_a_leaf_reached_twice_is_a_cycle_not_a_repeat() -> None:
    """Upstream would list the records twice; a page visited twice is refused here (module docstring)."""
    leaf = corrupt.bth_leaf(_pairs(2))
    index = corrupt.bth_index([(b"\x01\x00", HID(3)), (b"\x04\x00", HID(3))])
    with pytest.raises(PstLimitError, match="cycle"):
        list(_tree([corrupt.bth_header(levels=1, root=HID(2)), index, leaf]))


def test_record_count_over_the_limit_is_refused_and_at_it_passes() -> None:
    heap = corrupt.bth_heap(_pairs(4))
    assert len(list(HeapTree(HeapNode([heap], limits=Limits(max_items=4))))) == 4
    with pytest.raises(PstLimitError, match="BTH records: 4 exceeds limit 3"):
        list(HeapTree(HeapNode([heap], limits=Limits(max_items=3))))


def test_find_with_a_key_of_the_wrong_width_is_refused() -> None:
    tree = HeapTree(HeapNode([corrupt.bth_heap(_pairs(2))]))
    with pytest.raises(PstFormatError, match="must be 2 bytes"):
        tree.find(b"\x01")


def test_every_byte_flip_of_a_three_level_tree_leaks_nothing_but_pst_error() -> None:
    base = corrupt.bth_heap(_pairs(9), levels=2, fanout=2)
    assert [k for k, _v in HeapTree(HeapNode([base]))] == [k for k, _v in _pairs(9)]
    for offset in range(len(base)):
        for mask in (0x01, 0x10, 0xFF):
            mutant = corrupt.flip_byte(base, offset, mask)
            try:
                tree = HeapTree(HeapNode([mutant]))
                list(tree)
                tree.find(b"\x04\x00")
            except PstError:
                pass


# --- the walks ------------------------------------------------------------------------------


def test_empty_tree_iterates_nothing_and_finds_nothing() -> None:
    tree = HeapTree(HeapNode([corrupt.bth_heap([])]))
    assert tree.root.is_null and list(tree) == [] and tree.entries() == [] and tree.find(b"\x01\x00") is None


@pytest.mark.parametrize("key_size", KEY_SIZES)
@pytest.mark.parametrize("entry_size", [1, 6, MAX_ENTRY_SIZE])
@pytest.mark.parametrize(("levels", "fanout", "count"), [(0, 0, 1), (0, 0, 13), (1, 2, 5), (1, 3, 9), (2, 2, 9), (3, 2, 17), (3, 1, 1)])
def test_walk_returns_the_pairs_in_order_and_find_agrees(key_size: int, entry_size: int, levels: int, fanout: int, count: int) -> None:
    pairs = _pairs(count, key_size, entry_size)
    tree = HeapTree(HeapNode([corrupt.bth_heap(pairs, key_size=key_size, entry_size=entry_size, levels=levels, fanout=fanout)]))
    assert (tree.key_size, tree.entry_size, tree.levels) == (key_size, entry_size, levels)
    assert list(tree) == pairs and tree.entries() == pairs
    for key, value in pairs:
        assert tree.find(key) == value
    absent = [(0).to_bytes(key_size, "little"), (2).to_bytes(key_size, "little"), (1 + count * 3).to_bytes(key_size, "little"), b"\xff" * key_size]
    assert [tree.find(k) for k in absent] == [None] * 4


def test_eight_index_levels_walk_and_nine_are_refused() -> None:
    pairs = _pairs(1)
    assert list(HeapTree(HeapNode([corrupt.bth_heap(pairs, levels=8, fanout=1)]))) == pairs
    with pytest.raises(PstLimitError, match="BTH index levels: 9 exceeds limit 8"):
        HeapTree(HeapNode([corrupt.bth_heap(pairs, levels=9, fanout=1)]))


def test_tree_at_an_explicit_root_other_than_the_user_root() -> None:
    """A TC's row-index BTH is rooted at a TCINFO field, not the heap's user root."""
    pairs = _pairs(3, key_size=4, entry_size=4)
    # The user root is a non-BTH item; the BTHHEADER is item 2 and names the leaf, item 3.
    heap = HeapNode([corrupt.heap_node([b"not a BTH header", corrupt.bth_header(4, 4, 0, HID(3)), corrupt.bth_leaf(pairs)])])
    with pytest.raises(PstFormatError):
        HeapTree(heap)
    tree = HeapTree(heap, HeapId(HID(2)))
    assert tree.heap is heap and tree.root == HeapId(HID(3))
    assert list(tree) == pairs


# --- the corpus -----------------------------------------------------------------------------


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_fixed_pcs_are_sorted_and_find_agrees_with_the_walk(store: Path) -> None:
    with store.open("rb") as f:
        header = read_header(f)
        reader = BlockReader(f, header, BlockBTree(f, header.root.block_btree))
        nbt = NodeBTree(f, header.root.node_btree)
        for nid in (NID_MESSAGE_STORE, NID_ROOT_FOLDER, NID_NAME_TO_ID_MAP):
            tree = HeapTree(HeapNode.from_node(reader, nbt.find(nid)))
            pairs = tree.entries()
            assert (tree.key_size, tree.entry_size) == (2, 6) and len(pairs) > 0, f"{store.stem} {nid}"
            keys = [struct.unpack("<H", k)[0] for k, _v in pairs]
            assert keys == sorted(keys) and len(set(keys)) == len(keys), f"{store.stem} {nid}"
            for key, value in pairs:
                assert tree.find(key) == value, f"{store.stem} {nid}"
            assert tree.find(b"\xff\xff") is None and tree.find(b"\x00\x00") is None


def test_debug_bth_prints_the_header_and_every_record(capsys: pytest.CaptureFixture[str]) -> None:
    assert debug.main(["bth", str(EMPTY_PATH), "0x21"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[:5] == [
        "Node: NodeId { Internal: 0x1 }",
        "Key Size: 2",
        "Entry Size: 6",
        "Levels: 0",
        "Root: HeapId(NodeId { HeapNode: 0x2 })",
    ]
    assert lines[5] == " Record: key=340e value=0201a0000000"
    assert lines[-1] == "Records: 13" and len(lines) == 5 + 13 + 1
