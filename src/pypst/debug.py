"""Per-layer dump entry point: ``python -m pypst.debug <layer> <file>``.

Ported from: not a port
Harness code with no upstream counterpart: upstream ships one example binary
per layer; here they are one dispatcher so that every ported layer registers
its dumper in ``DUMPERS`` and the goldens in ``tests/golden/`` are compared
by ``tests/golden_parsers.py`` parsing both sides with the same parser.

A dumper is ``Callable[[Path], None]``: it prints upstream's example output
for that layer (``read_header``'s ten lines, and so on) and raises
``PstError`` on refusal, which this module turns into ``Error: …`` on stderr
and exit status 1. Nothing else may escape a dumper: a ``struct.error`` here
is the same bug it would be anywhere in the package.

Registration is one line in the layer's module or here, never in a test:
``DUMPERS["header"] = dump_header``.
"""

from __future__ import annotations

import argparse
import inspect
import sys
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path

from pypst.errors import PstError, PstFormatError
from pypst.limits import DEFAULT_LIMITS
from pypst.ndb.block import BlockReader, DataBlock, SubNodeLeafBlock
from pypst.ndb.btree import BlockBTree, NodeBTree, read_density_list
from pypst.ndb.header import read_header
from pypst.ndb.ids import BlockId, NodeId
from pypst.ndb.page import BlockBTreeEntry, BTreePage, IntermediateEntry, NodeBTreeEntry

# A dumper takes the store's path and, for the few that need one, the
# extra positional arguments from the command line (`node <nid-hex>`).
DUMPERS: dict[str, Callable[..., None]] = {}


def dump_header(path: Path) -> None:
    """The ten lines of upstream's `read_header` example (P01).

    Prints the `__str__` forms from docs/INTERFACES.md § ids, which carry no
    `Unicode` prefix; `parse_read_header` accepts both spellings.
    """
    with path.open("rb") as f:
        header = read_header(f)
    root = header.root
    print(f"File Version: {header.version}")
    print(f"Next Block: {header.next_block}")
    print(f"Next Page: {header.next_page}")
    print(f"File EOF Index: {root.file_eof_index}")
    print(f"AMAP Last Index: {root.amap_last_index}")
    print(f"AMAP Free Size: {root.amap_free_size}")
    print(f"PMAP Free Size: {root.pmap_free_size}")
    print(f"NBT BlockRef: {root.node_btree}")
    print(f"BBT BlockRef: {root.block_btree}")
    print(f"AMAP Valid: {root.amap_is_valid}")


DUMPERS["header"] = dump_header


def _dump_btree_pages(pages: Iterator[BTreePage], root_level: int, kind: str, leaf: Callable[[str, object], None]) -> None:
    """Print one tree as upstream's `read_btrees` does: pre-order, indented by distance from the root.

    `pages` is a `pages()` iterator, whose order is exactly the recursion
    here; `leaf` prints one leaf entry at the given indent. An intermediate
    page is indented by `root_level - level` spaces and a leaf by
    `root_level`, so that the leaves of a tree line up.
    """
    page = next(pages)
    if page.is_leaf:
        indent = " " * root_level
        print(f"{indent}{kind} Page Entries: {len(page.entries)}")
        for entry in page.entries:
            leaf(indent, entry)
        return
    indent = " " * (root_level - page.level)
    print(f"{indent}{kind} BTree Level: {page.level}: Entries: {len(page.entries)}")
    for entry in page.entries:
        assert isinstance(entry, IntermediateEntry)
        key = f"{entry.key}" if kind == "Block" else str(NodeId(entry.key))
        print(f"{indent} Key: {key}")
        _dump_btree_pages(pages, root_level, kind, leaf)


def _root_level(tree: BlockBTree | NodeBTree) -> int:
    """The root page's level, which fixes every indent; read once, cheaply."""
    return next(tree.pages()).level


def _dump_data_tree(reader: BlockReader, indent: str, max_level: int | None, block: BlockId) -> None:
    """Upstream's `output_data_tree`: a data block's id and size, or an XBLOCK's header and children.

    `max_level` is the level of the tree's root once inside one (`None` at
    the top), and fixes the indent of everything under it, as upstream's.
    The recursion is bounded by `read_data`'s limits only indirectly — the
    dumper reads block by block — so it carries its own depth: an internal
    block deeper than `limits.max_xblock_depth` is a refusal here too.
    """
    _dump_data_tree_at(reader, indent, max_level, block, 1)


def _dump_data_tree_at(reader: BlockReader, indent: str, max_level: int | None, block: BlockId, depth: int) -> None:
    node = reader.read_data_tree(block)
    if isinstance(node, DataBlock):
        sub = " " * max_level if max_level is not None else ""
        print(f"{indent}{sub}Data Block: {node.trailer.block_id}")
        print(f"{indent}{sub}Size: 0x{len(node.data):X}")
        return
    if depth > reader.limits.max_xblock_depth:
        raise PstFormatError(f"data tree depth: {depth} exceeds limit {reader.limits.max_xblock_depth}")
    sub = " " * (max_level - node.level) if max_level is not None else ""
    max_level = max_level if max_level is not None else node.level
    print(f"{indent}{sub}Data Tree Level: {node.level}: Entries: {len(node.entries)}")
    print(f"{indent}{sub}Total Size: 0x{node.total_size:X}")
    for child in node.entries:
        print(f"{indent}{sub} Block: {child}")
        _dump_data_tree_at(reader, indent, max_level, child, depth + 1)


def _dump_sub_node_tree(reader: BlockReader, indent: str, max_level: int | None, block: BlockId, depth: int = 1) -> None:
    """Upstream's `output_sub_node_tree`, quirks included: an SIBLOCK's entry lines omit `indent`."""
    node = reader.read_subnode_block(block)
    if isinstance(node, SubNodeLeafBlock):
        sub = " " * max_level if max_level is not None else ""
        print(f"{indent}{sub}Sub-Node Block Entries: {len(node.entries)}")
        for entry in node.entries:
            print(f"{indent}{sub} Node: {entry.node}")
            _dump_data_tree(reader, f"{indent}{sub} ", None, entry.data)
            print(f"{indent}{sub}  PageRef: {reader.find(entry.data).block}")
            if entry.sub_node is not None:
                inner = f"{indent}{sub}  "
                print(f"{inner}Sub-Node Block: {entry.sub_node}")
                _dump_sub_node_tree(reader, inner, None, entry.sub_node)
            else:
                print(f"{indent}{sub}  Sub-Node Block: None")
        return
    if depth > reader.limits.max_subnode_depth:
        raise PstFormatError(f"subnode tree depth: {depth} exceeds limit {reader.limits.max_subnode_depth}")
    sub = " " * (max_level - node.level) if max_level is not None else ""
    max_level = max_level if max_level is not None else node.level
    print(f"{indent}{sub}Sub-Node BTree Level: {node.level}: Entries: {len(node.entries)}")
    for entry in node.entries:
        print(f"{sub} Node: {entry.node}")
        print(f"{sub} Block: {entry.next_level}")
        _dump_sub_node_tree(reader, indent, max_level, entry.next_level, depth + 1)


def dump_btrees(path: Path) -> None:
    """Upstream's `read_btrees` example: the block B-tree, a blank line, the node B-tree.

    Byte for byte upstream's output (modulo the `Unicode` prefix): the
    block B-tree section (P02), and the node B-tree section with every
    leaf entry's data tree and sub-node tree descended as the example
    descends them (P03). A data block prints the id its TRAILER carries and
    the length of its decoded data, as upstream; an entry whose `bidData`
    is zero prints just the id.
    """
    with path.open("rb") as f:
        header = read_header(f)
        root = header.root
        block_btree = BlockBTree(f, root.block_btree, DEFAULT_LIMITS)
        node_btree = NodeBTree(f, root.node_btree, DEFAULT_LIMITS)
        reader = BlockReader(f, header, block_btree, DEFAULT_LIMITS)

        def block_leaf(indent: str, entry: object) -> None:
            assert isinstance(entry, BlockBTreeEntry)
            print(f"{indent} Block: {entry.block}")
            print(f"{indent}  Size: {entry.size}")
            print(f"{indent}  Ref-Count: {entry.ref_count}")

        def node_leaf(indent: str, entry: object) -> None:
            assert isinstance(entry, NodeBTreeEntry)
            print(f"{indent} Node: {entry.node}")
            inner = f"{indent}  "
            if entry.data.search_key == 0:
                print(f"{inner}Data Block: {entry.data}")
            else:
                _dump_data_tree(reader, inner, None, entry.data)
            if entry.sub_node is not None:
                print(f"{inner}Sub-Node Block: {entry.sub_node}")
                _dump_sub_node_tree(reader, f"{inner} ", None, entry.sub_node)
            else:
                print(f"{inner}Sub-Node Block: None")
            parent = f"Some({entry.parent})" if entry.parent is not None else "None"
            print(f"{inner}Parent Node: {parent}")

        _dump_btree_pages(block_btree.pages(), _root_level(block_btree), "Block", block_leaf)
        print()
        _dump_btree_pages(node_btree.pages(), _root_level(node_btree), "Node", node_leaf)


DUMPERS["btrees"] = dump_btrees


def dump_node(path: Path, nid: str) -> None:
    """`node <file> <nid-hex>`: a node's data length, its CRC-32, and its sub-node count — never its bytes.

    The cheapest way to prove that two readers produced the same bytes
    without printing either's: `zlib.crc32` of `node_data`, which a test
    on a private store can compare with the oracle's length and a later
    row can compare across layers. The nid is hex, with or without `0x`.
    """
    try:
        raw = int(nid, 16)
    except ValueError:
        raise PstFormatError(f"not a hex node id: {nid!r}") from None
    node = NodeId(raw)
    with path.open("rb") as f:
        header = read_header(f)
        root = header.root
        block_btree = BlockBTree(f, root.block_btree, DEFAULT_LIMITS)
        node_btree = NodeBTree(f, root.node_btree, DEFAULT_LIMITS)
        reader = BlockReader(f, header, block_btree, DEFAULT_LIMITS)
        entry = node_btree.find(node)
        data = reader.node_data(entry)
        sub_nodes = reader.read_subnode_tree(entry.sub_node) if entry.sub_node is not None else {}
    print(f"Node: {entry.node}")
    print(f"Data Length: {len(data)}")
    print(f"Data CRC32: 0x{zlib.crc32(data):08X}")
    print(f"Sub-Nodes: {len(sub_nodes)}")


DUMPERS["node"] = dump_node


def dump_density_list(path: Path) -> None:
    """Upstream's `read_density_list` example (P02): seven `Label: value` lines.

    Upstream prints `Error: …` on stdout and exits 0 when the page is
    absent; here the absence is the `PstFormatError` `read_density_list`
    raises, reported by `main` on stderr with exit 1, as every dumper does.
    """
    with path.open("rb") as f:
        read_header(f)  # a non-PST is refused as such, not as "no density list"
        page = read_density_list(f)
    entries = ", ".join(str(entry) for entry in page.entries)
    trailer = page.trailer
    print(f"Backfill Complete: {'true' if page.backfill_complete else 'false'}")
    print(f"Current Page: {page.current_page}")
    print(f"Density List Entries: [{entries}]")
    print(f"Page Type: {trailer.page_type}")
    print(f"Page Signature: 0x{trailer.signature:x}")
    print(f"Page CRC: 0x{trailer.crc:08x}")
    print(f"Block ID: {trailer.block_id}")


DUMPERS["density_list"] = dump_density_list


def main(argv: list[str] | None = None) -> int:
    names = ", ".join(sorted(DUMPERS)) or "(none registered yet)"
    parser = argparse.ArgumentParser(
        prog="python -m pypst.debug",
        description="Print one layer of a PST in the upstream example's format.",
        epilog=f"registered layers: {names}",
    )
    parser.add_argument("--list", action="store_true", help="print the registered layer names and exit")
    parser.add_argument("layer", nargs="?", help="which layer to dump")
    parser.add_argument("file", nargs="?", type=Path, help="the .pst to read")
    parser.add_argument("extra", nargs="*", help="layer-specific arguments (`node` takes a hex nid)")
    args = parser.parse_args(argv)

    if args.list:
        for name in sorted(DUMPERS):
            print(name)
        return 0
    if args.layer is None or args.file is None:
        parser.error("both <layer> and <file> are required (or use --list)")
    dumper = DUMPERS.get(args.layer)
    if dumper is None:
        parser.error(f"unknown layer {args.layer!r}; registered layers: {names}")
    wanted = len(inspect.signature(dumper).parameters) - 1
    if len(args.extra) != wanted:
        parser.error(f"layer {args.layer!r} takes {wanted} extra argument(s), got {len(args.extra)}")
    try:
        dumper(args.file, *args.extra)
    except PstError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
