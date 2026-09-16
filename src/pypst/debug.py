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
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

from pypst.errors import PstError
from pypst.limits import DEFAULT_LIMITS
from pypst.ndb.btree import BlockBTree, NodeBTree, read_density_list
from pypst.ndb.header import read_header
from pypst.ndb.ids import NodeId
from pypst.ndb.page import BlockBTreeEntry, BTreePage, IntermediateEntry, NodeBTreeEntry

DUMPERS: dict[str, Callable[[Path], None]] = {}


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


def dump_btrees(path: Path) -> None:
    """Upstream's `read_btrees` example (P02): the block B-tree, a blank line, the node B-tree.

    The block B-tree section is upstream's byte for byte (modulo the
    `Unicode` prefix). The node B-tree section prints each leaf entry's
    node, data block, sub-node block and parent as upstream does, and the
    `Size:` of a leaf data block from the block B-tree's entry (upstream
    reads the block and prints its data length, which is that entry's `cb`).
    Where upstream then descends into an internal data block (`Data Tree
    Level: …`) or a sub-node block (`Sub-Node Block Entries: …`) this
    dumper stops at the block id: those trees are blocks, which is P03.
    `tests/golden_parsers.parse_read_btrees` reads both forms.
    """
    with path.open("rb") as f:
        header = read_header(f)
        root = header.root
        block_btree = BlockBTree(f, root.block_btree, DEFAULT_LIMITS)
        node_btree = NodeBTree(f, root.node_btree, DEFAULT_LIMITS)

        def block_leaf(indent: str, entry: object) -> None:
            assert isinstance(entry, BlockBTreeEntry)
            print(f"{indent} Block: {entry.block}")
            print(f"{indent}  Size: {entry.size}")
            print(f"{indent}  Ref-Count: {entry.ref_count}")

        def node_leaf(indent: str, entry: object) -> None:
            assert isinstance(entry, NodeBTreeEntry)
            print(f"{indent} Node: {entry.node}")
            print(f"{indent}  Data Block: {entry.data}")
            if entry.data.search_key != 0 and not entry.data.is_internal:
                print(f"{indent}  Size: 0x{block_btree.find(entry.data).size:X}")
            print(f"{indent}  Sub-Node Block: {entry.sub_node if entry.sub_node is not None else 'None'}")
            parent = f"Some({entry.parent})" if entry.parent is not None else "None"
            print(f"{indent}  Parent Node: {parent}")

        _dump_btree_pages(block_btree.pages(), _root_level(block_btree), "Block", block_leaf)
        print()
        _dump_btree_pages(node_btree.pages(), _root_level(node_btree), "Node", node_leaf)


DUMPERS["btrees"] = dump_btrees


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
    try:
        dumper(args.file)
    except PstError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
