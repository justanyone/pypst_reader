"""The two B-tree walks: refused when the tree lies, exact against the oracle when it does not.

Denial first, in three shapes: Empty.pst mutated in memory (a root that
names itself, a bad CRC, a count over the maximum, a truncated file);
synthetic trees built page by page (a two-page cycle, a chain deeper than
the ceiling, a reference past EOF); and the limits, each shown to trip as
`PstLimitError` — distinguishable from `PstFormatError` — before any walk
could hang.

Then the differential claim. `python -m pypstreader.debug btrees` over every
Unicode store in the corpus, parsed by the same parser as the committed
`read_btrees` golden: the block B-tree section equal as text and as values;
the node B-tree section equal on everything a page holds (the data-tree
and sub-node lines the oracle prints come from blocks, which is P03, and
are projected away on both sides). And the same facts read straight off
the walks, so a type slip behind a lucky `__str__` cannot hide.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from pypstreader import debug
from pypstreader.errors import (
    PstError,
    PstFormatError,
    PstLimitError,
    PstNotFoundError,
    PstUnsupportedError,
)
from pypstreader.limits import DEFAULT_LIMITS, MAX_BTREE_DEPTH, Limits
from pypstreader.ndb.btree import BlockBTree, NodeBTree, read_density_list, read_page
from pypstreader.ndb.header import read_header
from pypstreader.ndb.ids import BlockId, ByteIndex, NodeId, PageId, PageRef
from pypstreader.ndb.page import (
    BTreePage,
    DensityListPage,
    IntermediateEntry,
    NodeBTreeEntry,
    PageType,
)
from tests import corrupt
from tests.conftest import FIXTURES, REFERENCE, public_fixture_paths, run_oracle
from tests.golden_parsers import parse_read_btrees, parse_read_density_list

EMPTY_PATH = FIXTURES / "Empty.pst"
EMPTY = EMPTY_PATH.read_bytes()
ANSI_STEMS = {"pstsdk-test_ansi", "pstsdk-sample2"}

ALL_STORES = [EMPTY_PATH, *public_fixture_paths()]
UNICODE_STORES = [p for p in ALL_STORES if p.stem not in ANSI_STEMS]
UNICODE_IDS = [p.stem for p in UNICODE_STORES]
ANSI_STORES = [p for p in ALL_STORES if p.stem in ANSI_STEMS]
ANSI_IDS = [p.stem for p in ANSI_STORES]

# Empty.pst's roots (pinned by tests/test_header.py) and the layout of its NBT
# root page: level 1, four BTENTRYs of 24 bytes.
NBT_ROOT = PageRef(PageId(0x17D), ByteIndex(0x9200))
BBT_ROOT = PageRef(PageId(0x17B), ByteIndex(0x8400))


def _trees(data: bytes, limits: Limits = DEFAULT_LIMITS) -> tuple[NodeBTree, BlockBTree]:
    f = io.BytesIO(data)
    return NodeBTree(f, NBT_ROOT, limits), BlockBTree(f, BBT_ROOT, limits)


def _synthetic_nbt(pages: dict[int, bytes], root: PageRef, limits: Limits = DEFAULT_LIMITS, size: int | None = None) -> NodeBTree:
    return NodeBTree(io.BytesIO(corrupt.file_with_pages(pages, size)), root, limits)


def _chain(length: int, *, page_type: int = corrupt.PTYPE_NBT) -> tuple[dict[int, bytes], PageRef]:
    """`length` intermediate pages each pointing at the next, then one leaf; root first."""
    pages: dict[int, bytes] = {}
    for i in range(length):
        offset, child = 0x1000 * (i + 1), 0x1000 * (i + 2)
        pages[offset] = corrupt.btree_page(page_type, 1, [corrupt.bt_entry(0x21, 0x100 + i + 1, child)], 0x100 + i, offset)
    leaf_offset = 0x1000 * (length + 1)
    pages[leaf_offset] = corrupt.btree_page(page_type, 0, [corrupt.nbt_entry(0x21, 0x2)], 0x100 + length, leaf_offset)
    return pages, PageRef(PageId(0x100), ByteIndex(0x1000))


# --- denial: cycles and depth (PstLimitError, never a hang) -----------------------


def test_root_pointing_at_itself_is_a_limit_error() -> None:
    """Empty.pst's NBT root, first BTENTRY's BREF rewritten to the root itself, CRC fixed."""
    entry0 = NBT_ROOT.index.value + 8  # past btkey: bid then ib
    bad = corrupt.set_bytes(EMPTY, entry0, NBT_ROOT.pack())
    bad = corrupt.reseal_page(bad, NBT_ROOT.index.value)
    nbt, _ = _trees(bad)
    with pytest.raises(PstLimitError) as info:
        list(nbt)
    assert "cycle" in str(info.value)
    with pytest.raises(PstLimitError):
        list(nbt.pages())
    # A lookup that descends into the loop is guarded the same way.
    with pytest.raises(PstLimitError):
        nbt.find(NodeId(0x21))


def test_two_page_cycle_is_a_limit_error() -> None:
    a, b = 0x1000, 0x2000
    pages = {
        a: corrupt.btree_page(corrupt.PTYPE_NBT, 1, [corrupt.bt_entry(0x21, 0x2, b)], 0x1, a),
        b: corrupt.btree_page(corrupt.PTYPE_NBT, 1, [corrupt.bt_entry(0x21, 0x1, a)], 0x2, b),
    }
    nbt = _synthetic_nbt(pages, PageRef(PageId(0x1), ByteIndex(a)))
    with pytest.raises(PstLimitError):
        list(nbt)
    with pytest.raises(PstLimitError):
        nbt.find(NodeId(0x21))


def test_page_reachable_twice_is_refused() -> None:
    """A DAG (one leaf under two entries) is not a B-tree; the visited set refuses the second path."""
    root, leaf = 0x1000, 0x2000
    pages = {
        root: corrupt.btree_page(
            corrupt.PTYPE_NBT, 1, [corrupt.bt_entry(0x21, 0x2, leaf), corrupt.bt_entry(0x41, 0x2, leaf)], 0x1, root
        ),
        leaf: corrupt.btree_page(corrupt.PTYPE_NBT, 0, [corrupt.nbt_entry(0x21, 0x2)], 0x2, leaf),
    }
    with pytest.raises(PstLimitError):
        list(_synthetic_nbt(pages, PageRef(PageId(0x1), ByteIndex(root))))


def test_chain_deeper_than_the_ceiling_is_a_limit_error() -> None:
    pages, root = _chain(MAX_BTREE_DEPTH + 1)  # the leaf sits at depth 9
    with pytest.raises(PstLimitError) as info:
        list(_synthetic_nbt(pages, root))
    assert "depth" in str(info.value)
    with pytest.raises(PstLimitError):
        _synthetic_nbt(pages, root).find(NodeId(0x21))


def test_chain_at_the_ceiling_is_walked() -> None:
    """The ceiling is inclusive: a leaf at depth 8 (nine pages, what cLevel ≤ 8 allows) is read."""
    pages, root = _chain(MAX_BTREE_DEPTH)
    entries = list(_synthetic_nbt(pages, root))
    assert [e.node for e in entries] == [NodeId(0x21)]
    assert _synthetic_nbt(pages, root).find(NodeId(0x21)).data == BlockId(0x2)


def test_depth_ceiling_comes_from_limits() -> None:
    pages, root = _chain(4)
    with pytest.raises(PstLimitError):
        list(_synthetic_nbt(pages, root, Limits(max_btree_depth=3)))
    assert len(list(_synthetic_nbt(pages, root, Limits(max_btree_depth=4)))) == 1


def test_item_ceilings_come_from_limits() -> None:
    nbt, bbt = _trees(EMPTY, Limits(max_items=10))
    with pytest.raises(PstLimitError):
        list(nbt)  # 47 entries
    with pytest.raises(PstLimitError):
        list(bbt)  # 31 entries
    nbt, _ = _trees(EMPTY, Limits(max_items=2))
    with pytest.raises(PstLimitError):
        list(nbt.pages())  # the visited set is capped too: five pages
    nbt, bbt = _trees(EMPTY, Limits(max_items=47))
    assert len(list(nbt)) == 47 and len(list(bbt)) == 31


def test_limit_errors_are_not_format_errors() -> None:
    pages, root = _chain(MAX_BTREE_DEPTH + 1)
    with pytest.raises(PstLimitError) as info:
        list(_synthetic_nbt(pages, root))
    assert not isinstance(info.value, PstFormatError)
    assert isinstance(info.value, PstError)


# --- denial: the file does not hold the page ----------------------------------


def test_page_ref_past_eof_is_a_format_error() -> None:
    for index in (len(EMPTY), len(EMPTY) - 100, len(EMPTY) - 511):
        tree = NodeBTree(io.BytesIO(EMPTY), PageRef(PageId(0x17D), ByteIndex(index)))
        with pytest.raises(PstFormatError):
            list(tree)


def test_truncated_final_page_is_a_format_error() -> None:
    """The file cut inside the NBT root page: a short read, never a struct.error."""
    for length in (NBT_ROOT.index.value, NBT_ROOT.index.value + 1, NBT_ROOT.index.value + 511):
        nbt, _ = _trees(corrupt.truncate(EMPTY, length))
        with pytest.raises(PstFormatError):
            list(nbt)


def test_page_ref_beyond_any_file_is_a_format_error() -> None:
    for index in (2**63, 2**64 - 1, DEFAULT_LIMITS.max_file_size - 1):
        with pytest.raises(PstFormatError):
            read_page(io.BytesIO(EMPTY), ByteIndex(index))


def test_child_ref_past_eof_is_a_format_error() -> None:
    entry0 = NBT_ROOT.index.value + 8
    bad = corrupt.set_bytes(EMPTY, entry0, PageRef(PageId(0x17E), ByteIndex(len(EMPTY) + 0x1000)).pack())
    bad = corrupt.reseal_page(bad, NBT_ROOT.index.value)
    nbt, _ = _trees(bad)
    with pytest.raises(PstFormatError):
        list(nbt)


# --- denial: the page lies about itself (reached through the walk) -------------


def _mutate_root(offset_in_page: int, value: bytes, *, reseal: bool = True) -> bytes:
    out = corrupt.set_bytes(EMPTY, NBT_ROOT.index.value + offset_in_page, value)
    return corrupt.reseal_page(out, NBT_ROOT.index.value) if reseal else out


@pytest.mark.parametrize(
    ("offset", "value", "reseal", "what"),
    [
        (corrupt.PAGE_TRAILER_OFFSET + 1, b"\x80", False, "ptypeRepeat"),
        (corrupt.PAGE_TRAILER_OFFSET, b"\x84\x84", True, "map page type"),
        (corrupt.PAGE_TRAILER_OFFSET, b"\x00\x00", True, "unknown page type"),
        (100, b"\xff", False, "bad CRC"),
        (corrupt.BTREE_HEADER_OFFSET, b"\x15", True, "cEnt > cEntMax"),
        (corrupt.BTREE_HEADER_OFFSET + 2, b"\x10", True, "cbEnt too small"),
        (corrupt.BTREE_HEADER_OFFSET + 1, b"\x40", True, "cEntMax too big"),
        (corrupt.BTREE_HEADER_OFFSET + 3, b"\x09", True, "cLevel 9"),
        (corrupt.BTREE_HEADER_OFFSET + 4, b"\x01", True, "dwPadding"),
    ],
    ids=lambda v: v if isinstance(v, str) else None,
)
def test_root_page_mutations_are_format_errors(offset: int, value: bytes, reseal: bool, what: str) -> None:
    nbt, _ = _trees(_mutate_root(offset, value, reseal=reseal))
    with pytest.raises(PstFormatError):
        list(nbt.pages())
    with pytest.raises(PstFormatError):
        nbt.find(NodeId(0x21))


def test_intermediate_nbt_key_wider_than_a_nid_is_refused() -> None:
    """The example prints `Invalid Key` and skips the subtree; this port refuses (module docstring)."""
    bad = _mutate_root(0, (1 << 32).to_bytes(8, "little"))
    nbt, _ = _trees(bad)
    with pytest.raises(PstFormatError):
        list(nbt.pages())
    # The BBT has no such rule: a 64-bit key is a BID.
    big = corrupt.set_bytes(EMPTY, BBT_ROOT.index.value, (1 << 40).to_bytes(8, "little"))
    _, bbt = _trees(corrupt.reseal_page(big, BBT_ROOT.index.value))
    assert len(list(bbt)) == 31


def test_wrong_signature_and_wrong_bid_are_read_as_upstream_does() -> None:
    """Pinned: neither is checked on read, because upstream reads stores where they are wrong."""
    sig = _mutate_root(corrupt.PAGE_TRAILER_OFFSET + 2, b"\0\0")
    bid = _mutate_root(corrupt.PAGE_TRAILER_OFFSET + 8, (0x999).to_bytes(8, "little"))
    for data in (sig, bid):
        nbt, _ = _trees(data)
        assert len(list(nbt)) == 47


def _refused(walk: Callable[[], object]) -> bool:
    try:
        walk()
    except PstError:
        return True
    return False


def _refusals(data: bytes, *, with_bbt: bool) -> list[bool]:
    nbt, bbt = _trees(data)
    results = [_refused(lambda: list(nbt)), _refused(lambda: nbt.find(NodeId(0x21)))]
    if with_bbt:
        results.append(_refused(lambda: list(bbt)))
    return results


def test_every_refusal_through_the_walk_is_a_pst_error() -> None:
    attempts = [b"", bytes(0x9400), EMPTY[:0x8500], corrupt.flip_byte(EMPTY, 0x9200 + 489)]
    for data in attempts:
        # The flip is inside the NBT root; the BBT is untouched by it.
        assert all(_refusals(data, with_bbt=data != attempts[-1])), "accepted a broken store"


# --- find: hits and misses ----------------------------------------------------


def test_find_every_node_and_block_in_empty_pst() -> None:
    nbt, bbt = _trees(EMPTY)
    nodes = list(nbt)
    for entry in nodes:
        assert nbt.find(entry.node) == entry
        assert nbt.find(entry.node.raw) == entry
    blocks = list(bbt)
    for entry in blocks:
        assert bbt.find(entry.block.block) == entry
        assert bbt.find(entry.key) == entry
        # The reserved bit is not part of the key ([MS-PST] 2.2.2.2).
        assert bbt.find(BlockId(entry.block.block.raw | 1)) == entry


def test_find_misses_raise_not_found() -> None:
    nbt, bbt = _trees(EMPTY)
    nodes = [e.node.raw for e in nbt]
    assert nodes == sorted(nodes)
    gap = next(i for i in range(len(nodes) - 1) if nodes[i + 1] - nodes[i] > 1)
    between = nodes[gap] + 1  # strictly between two existing keys
    assert between not in nodes and nodes[gap] < between < nodes[gap + 1]
    for missing in (between, 0, nodes[0] - 1, nodes[-1] + 1, 0xFFFFFFFF):
        with pytest.raises(PstNotFoundError) as info:
            nbt.find(NodeId(missing))
        assert isinstance(info.value, PstFormatError)
    for missing in (0, 3, 0x4C + 4, 1 << 40):
        with pytest.raises(PstNotFoundError):
            bbt.find(BlockId(missing))


def test_find_uses_the_cache_and_still_verifies() -> None:
    """A second lookup hits the cached root; a corrupt leaf is still refused on every lookup."""
    nbt, _ = _trees(EMPTY)
    nbt.find(NodeId(0x21))
    assert NBT_ROOT.index.value in nbt._cache
    root = BTreePage.parse(EMPTY[0x9200 : 0x9200 + 512], PageType.NBT, NBT_ROOT.index)
    first_leaf = root.entries[0]
    assert isinstance(first_leaf, IntermediateEntry)
    bad = corrupt.flip_byte(EMPTY, first_leaf.ref.index.value + 5)
    nbt, _ = _trees(bad)
    for _ in range(2):
        with pytest.raises(PstFormatError):
            nbt.find(NodeId(0x21))


# --- the walks on Empty.pst: order and shape -------------------------------------


def test_pages_are_pre_order_and_entries_are_in_key_order() -> None:
    nbt, bbt = _trees(EMPTY)
    pages = list(nbt.pages())
    assert [p.level for p in pages] == [1, 0, 0, 0, 0]
    assert pages[0].trailer.block_id == NBT_ROOT.page
    keys = [e.key for e in nbt]
    assert keys == sorted(keys) and len(keys) == len(set(keys)) == 47
    assert all(isinstance(e, NodeBTreeEntry) for e in nbt)
    assert [p.level for p in bbt.pages()] == [1, 0, 0]
    bkeys = [e.key for e in bbt]
    assert bkeys == sorted(bkeys) and len(bkeys) == 31


def test_root_and_limits_are_exposed() -> None:
    nbt, _ = _trees(EMPTY, Limits(max_btree_depth=5))
    assert nbt.root == NBT_ROOT and nbt.limits.max_btree_depth == 5


def test_walk_from_a_real_file_handle(empty_pst: Path) -> None:
    with empty_pst.open("rb") as f:
        header = read_header(f)
        nbt = NodeBTree(f, header.root.node_btree)
        bbt = BlockBTree(f, header.root.block_btree)
        assert len(list(nbt)) == 47 and len(list(bbt)) == 31
        assert nbt.find(NodeId(0x21)).data == BlockId.from_parts(False, 0x42)
        assert bbt.find(BlockId.from_parts(False, 0x42)).size == 0x126


# --- the density list ------------------------------------------------------------


def test_density_list_of_empty_pst() -> None:
    page = read_density_list(io.BytesIO(EMPTY))
    assert isinstance(page, DensityListPage) and page.entries == ()


def test_density_list_absent_or_broken_is_a_format_error() -> None:
    with pytest.raises(PstFormatError):
        read_density_list(io.BytesIO(corrupt.set_bytes(EMPTY, 0x4200, bytes(512))))
    with pytest.raises(PstFormatError):
        read_density_list(io.BytesIO(corrupt.flip_byte(EMPTY, 0x4200 + 3)))
    with pytest.raises(PstFormatError):
        read_density_list(io.BytesIO(EMPTY[:0x4300]))


# --- the ANSI stores are refused (ADR-0003) -----------------------------------------


@pytest.mark.parametrize("store", ANSI_STORES, ids=ANSI_IDS)
def test_ansi_store_is_refused_before_any_page(store: Path, golden_exit) -> None:
    assert golden_exit(store, "read_btrees") == 101  # upstream's own panic on ANSI
    with store.open("rb") as f, pytest.raises(PstUnsupportedError):
        read_header(f)
    for layer in ("btrees", "density_list"):
        assert debug.main([layer, str(store)]) == 1


# --- differential: the goldens ---------------------------------------------------


def _node_view(node: NodeId) -> dict[str, Any]:
    """`parse_node_id`'s dict for a NodeId, including the `invalid` form."""
    try:
        return {"type": node.id_type.debug_name, "index": node.index}
    except PstFormatError:
        return {"type": "invalid", "index": node.raw}


def _block_view(block: BlockId) -> dict[str, Any]:
    return {"internal": block.is_internal, "index": block.index}


def _data_view(data: dict[str, Any]) -> tuple[Any, ...]:
    """What a page knows of a node's data: an XBLOCK tree is only 'internal' at this layer."""
    if "level" in data:
        return ("internal",)
    if data["block"]["internal"]:
        # The oracle never prints a Size for an internal block (it prints the tree instead).
        return ("internal",) if "size" not in data else ("internal", data["size"])
    if "size" in data:
        return ("leaf", data["block"]["index"], data["size"])
    return ("empty", data["block"]["index"])


def _p02_view(page: dict[str, Any]) -> dict[str, Any]:
    """The node-tree golden reduced to what pages hold (sub-node trees and data trees are P03)."""
    if "entries" in page:
        return {
            "level": 0,
            "entries": [
                {
                    "node": e["node"],
                    "data": _data_view(e["data"]),
                    "sub_node": None if e["sub_node"] is None else e["sub_node"]["block"],
                    "parent": e["parent"],
                }
                for e in page["entries"]
            ],
        }
    return {"level": page["level"], "children": [{"key": c["key"], "page": _p02_view(c["page"])} for c in page["children"]]}


def _golden_skeleton(page: dict[str, Any], node_tree: bool) -> list[tuple[int, list[Any]]]:
    """Pre-order (level, keys) per page: intermediate keys, or leaf entry keys."""
    if "entries" in page:
        keys = [e["node"] for e in page["entries"]] if node_tree else [e["block"]["block"] for e in page["entries"]]
        return [(0, keys)]
    out = [(page["level"], [c["key"] for c in page["children"]])]
    for c in page["children"]:
        out.extend(_golden_skeleton(c["page"], node_tree))
    return out


def _our_skeleton(tree: NodeBTree | BlockBTree) -> list[tuple[int, list[Any]]]:
    out = []
    for page in tree.pages():
        if page.is_leaf:
            keys = [_node_view(e.node) if isinstance(e, NodeBTreeEntry) else _block_view(e.block.block) for e in page.entries]
        else:
            keys = [_node_view(NodeId(e.key)) if tree.KIND is PageType.NBT else e.key for e in page.entries]
        out.append((page.level, keys))
    return out


def _golden_leaves(page: dict[str, Any]) -> list[dict[str, Any]]:
    if "entries" in page:
        return list(page["entries"])
    return [e for c in page["children"] for e in _golden_leaves(c["page"])]


def _compare_walk(store: Path, expected: dict[str, Any]) -> list[str]:
    """Walk both trees of `store` and return the mismatches against the parsed golden, by count only."""
    problems: list[str] = []
    with store.open("rb") as f:
        header = read_header(f)
        nbt = NodeBTree(f, header.root.node_btree)
        bbt = BlockBTree(f, header.root.block_btree)
        if _our_skeleton(bbt) != _golden_skeleton(expected["block_btree"], node_tree=False):
            problems.append("block B-tree page skeleton")
        if _our_skeleton(nbt) != _golden_skeleton(expected["node_btree"], node_tree=True):
            problems.append("node B-tree page skeleton")
        golden_blocks = _golden_leaves(expected["block_btree"])
        ours_blocks = [
            {"block": {"block": _block_view(e.block.block), "index": e.block.index.value}, "size": e.size, "ref_count": e.ref_count}
            for e in bbt
        ]
        if ours_blocks != golden_blocks:
            problems.append(f"block entries ({len(ours_blocks)} ours, {len(golden_blocks)} golden)")
        golden_nodes = _golden_leaves(expected["node_btree"])
        ours_nodes = []
        for e in nbt:
            if e.data.search_key == 0:
                data: tuple[Any, ...] = ("empty", e.data.index)
            elif e.data.is_internal:
                data = ("internal",)
            else:
                data = ("leaf", e.data.index, bbt.find(e.data).size)
            ours_nodes.append(
                {
                    "node": _node_view(e.node),
                    "data": data,
                    "sub_node": None if e.sub_node is None else _block_view(e.sub_node),
                    "parent": None if e.parent is None else _node_view(e.parent),
                }
            )
        golden_view = [
            {
                "node": g["node"],
                "data": _data_view(g["data"]),
                "sub_node": None if g["sub_node"] is None else g["sub_node"]["block"],
                "parent": g["parent"],
            }
            for g in golden_nodes
        ]
        if ours_nodes != golden_view:
            problems.append(f"node entries ({len(ours_nodes)} ours, {len(golden_view)} golden)")
    return problems


def _strip_prefix(text: str) -> str:
    return text.replace("Unicode", "")


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_debug_btrees_matches_golden(store: Path, golden, golden_exit, capsys: pytest.CaptureFixture[str]) -> None:
    """Dumper text vs golden: block tree identical as text and values; node tree equal at page level."""
    assert golden_exit(store, "read_btrees") == 0
    golden_text = golden(store, "read_btrees")
    expected = parse_read_btrees(golden_text)
    assert debug.main(["btrees", str(store)]) == 0
    out = capsys.readouterr().out
    ours = parse_read_btrees(out)
    assert ours["block_btree"] == expected["block_btree"], f"{store.stem}: block B-tree differs from the oracle"
    # Byte for byte on the block section (everything before the blank line).
    assert out.split("\n\n", 1)[0] == _strip_prefix(golden_text).split("\n\n", 1)[0], f"{store.stem}: block B-tree text"
    assert _p02_view(ours["node_btree"]) == _p02_view(expected["node_btree"]), f"{store.stem}: node B-tree differs"


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_walk_values_match_golden(store: Path, golden) -> None:
    """Every entry of both walks, in order, against the parsed golden — values, not printed forms."""
    expected = parse_read_btrees(golden(store, "read_btrees"))
    problems = _compare_walk(store, expected)
    assert not problems, f"{store.stem}: {', '.join(problems)}"
    with store.open("rb") as f:
        header = read_header(f)
        nbt = NodeBTree(f, header.root.node_btree)
        bbt = BlockBTree(f, header.root.block_btree)
        for entry in nbt:
            assert isinstance(entry.node, NodeId) and isinstance(entry.data, BlockId)
            assert entry.sub_node is None or isinstance(entry.sub_node, BlockId)
            assert entry.parent is None or isinstance(entry.parent, NodeId)
            assert nbt.find(entry.node) == entry
        for entry in bbt:
            assert isinstance(entry.size, int) and 0 <= entry.size <= 0xFFFF
            assert bbt.find(entry.block.block) == entry


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_debug_density_list_matches_golden(store: Path, golden, golden_exit, capsys: pytest.CaptureFixture[str]) -> None:
    assert golden_exit(store, "read_density_list") == 0
    expected = parse_read_density_list(golden(store, "read_density_list"))
    code = debug.main(["density_list", str(store)])
    captured = capsys.readouterr()
    if expected is None:
        # Upstream prints its error on stdout with exit 0; pypstreader refuses (stderr, exit 1).
        assert code == 1 and captured.out == "" and captured.err.startswith("Error:"), store.stem
        with store.open("rb") as f, pytest.raises(PstFormatError):
            read_density_list(f)
        return
    assert code == 0
    assert parse_read_density_list(captured.out) == expected, f"{store.stem}: density list differs from the oracle"
    with store.open("rb") as f:
        page = read_density_list(f)
    assert page.backfill_complete == expected["backfill_complete"]
    assert page.current_page == expected["current_page"]
    assert [e.raw for e in page.entries] == expected["entries"]
    assert page.trailer.page_type.debug_name == expected["page_type"]
    assert page.trailer.signature == expected["signature"] == page.trailer.expected_signature(ByteIndex(0x4200))
    assert page.trailer.crc == expected["crc"]
    assert page.trailer.block_id.raw == expected["block_id"]


# --- differential: private stores against the live oracle -----------------------------


@pytest.mark.private
@pytest.mark.oracle
def test_private_stores_match_live_oracle(private_stores: list[Path], oracle: Path) -> None:
    """Structure only. A mismatch is reported by count, never by content."""
    if not private_stores:
        pytest.skip("no private stores present (this is a normal clean checkout)")
    assert oracle == REFERENCE
    failures = 0
    for store in private_stores:
        expected = parse_read_btrees(run_oracle(oracle, "read_btrees", str(store)))
        if _compare_walk(store, expected):
            failures += 1
    if failures:
        pytest.fail(f"{failures} of {len(private_stores)} private store(s) differ from the oracle's read_btrees")


@pytest.mark.private
@pytest.mark.oracle
def test_private_density_lists_match_live_oracle(private_stores: list[Path], oracle: Path) -> None:
    if not private_stores:
        pytest.skip("no private stores present (this is a normal clean checkout)")
    failures = 0
    for store in private_stores:
        expected = parse_read_density_list(run_oracle(oracle, "read_density_list", str(store)))
        with store.open("rb") as f:
            try:
                page = read_density_list(f)
            except PstFormatError:
                ours = None
            else:
                ours = {
                    "backfill_complete": page.backfill_complete,
                    "current_page": page.current_page,
                    "entries": [e.raw for e in page.entries],
                    "page_type": page.trailer.page_type.debug_name,
                    "signature": page.trailer.signature,
                    "crc": page.trailer.crc,
                    "block_id": page.trailer.block_id.raw,
                }
        if ours != expected:
            failures += 1
    if failures:
        pytest.fail(f"{failures} of {len(private_stores)} private store(s) differ from the oracle's read_density_list")
