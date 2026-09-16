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
import struct
import sys
import unicodedata
import uuid
import zlib
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path

from pypst.errors import PstError, PstFormatError
from pypst.limits import DEFAULT_LIMITS
from pypst.ltp.heap import HeapId, HeapNode
from pypst.ltp.prop_context import PropertyContext, PropertyRecord
from pypst.ltp.prop_type import ObjectRef, PropType, PropValue, datetime_to_filetime
from pypst.ltp.table_context import CellKind, CellRecord, ColumnDescriptor, TableContext
from pypst.ltp.tree import HeapTree
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
    node = _parse_nid(nid)
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


def _parse_nid(nid: str) -> NodeId:
    """A hex node id from the command line, with or without `0x`."""
    try:
        return NodeId(int(nid, 16))
    except ValueError:
        raise PstFormatError(f"not a hex node id: {nid!r}") from None


def _open_heap(path: Path, nid: str) -> tuple[NodeBTreeEntry, HeapNode]:
    """The heap over node `nid`, read whole (its blocks and sub-node tree) so the file can close."""
    node = _parse_nid(nid)
    with path.open("rb") as f:
        header = read_header(f)
        root = header.root
        block_btree = BlockBTree(f, root.block_btree, DEFAULT_LIMITS)
        node_btree = NodeBTree(f, root.node_btree, DEFAULT_LIMITS)
        reader = BlockReader(f, header, block_btree, DEFAULT_LIMITS)
        entry = node_btree.find(node)
        return entry, HeapNode.from_node(reader, entry)


def dump_heap(path: Path, nid: str) -> None:
    """`heap <file> <nid-hex>`: the HNHDR, then every block's page map as counts and item lengths (P04).

    No upstream twin — upstream has no heap example — so the format is this
    port's: `Client Signature`, `User Root`, `Fill Levels`, `Blocks`, then
    per block `Block N: Allocations: A, Free: F` and one ` Item i: n bytes`
    line per allocation (1-based, as HIDs count them). Lengths, never
    contents, so it is safe on a private store.
    """
    entry, heap = _open_heap(path, nid)
    header = heap.header
    print(f"Node: {entry.node}")
    print(f"Client Signature: 0x{header.client_signature:02X}")
    print(f"User Root: {header.user_root}")
    print(f"Fill Levels: {list(header.fill_levels)}")
    print(f"Blocks: {heap.block_count}")
    for block_index in range(heap.block_count):
        page_map = heap.page_map(block_index)
        print(f"Block {block_index}: Allocations: {page_map.count}, Free: {page_map.free_count}")
        for i, size in enumerate(page_map.sizes, start=1):
            print(f" Item {i}: {size} bytes")


DUMPERS["heap"] = dump_heap


def dump_bth(path: Path, nid: str) -> None:
    """`bth <file> <nid-hex>`: the BTH at the heap's user root — its header and every leaf record as hex (P04).

    `key=` and `value=` are the raw record bytes: for a PC the u16 property
    id and the 6-byte type + HNID record, which name structure and not
    content; a TC's user root is a TCINFO, not a BTHHEADER, and is refused
    by the header check as it should be.
    """
    entry, heap = _open_heap(path, nid)
    tree = HeapTree(heap)
    print(f"Node: {entry.node}")
    print(f"Key Size: {tree.key_size}")
    print(f"Entry Size: {tree.entry_size}")
    print(f"Levels: {tree.levels}")
    print(f"Root: {tree.root}")
    count = 0
    for key, value in tree:
        print(f" Record: key={key.hex()} value={value.hex()}")
        count += 1
    print(f"Records: {count}")


DUMPERS["bth"] = dump_bth


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


# --- upstream's `Debug` for property values (P05) ------------------------------------------


def _rust_float(value: float, *, single: bool = False) -> str:
    """Rust's `{:?}` for an f64 (or an f32 when `single`): the shortest round-tripping decimal.

    Rust and Python agree on when to switch to an exponent (below 1e-4 or
    from 1e16 up); Rust writes `1e16` / `1e-5` where Python writes `1e+16` /
    `1e-05`, always keeps a `.0` on an integral value, and spells the
    specials `NaN`, `inf`, `-inf`. An f32 is the shortest decimal that
    round-trips through `<f`, not the f64 the bytes widened to.
    """
    if value != value:  # noqa: PLR0124 — NaN is the one value unequal to itself
        return "NaN"
    if value in (float("inf"), float("-inf")):
        return "inf" if value > 0 else "-inf"
    text = repr(value)
    if single:
        packed = struct.pack("<f", value)
        for precision in range(1, 10):
            candidate = f"{value:.{precision}g}"
            try:
                if struct.pack("<f", float(candidate)) == packed:
                    text = candidate
                    break
            except OverflowError:  # rounded past f32::MAX; a longer form will not be
                continue
    mantissa, _, exponent = text.partition("e")
    if exponent:
        sign = "-" if exponent.startswith("-") else ""
        return f"{mantissa}e{sign}{int(exponent.lstrip('+-'))}"
    if "." not in mantissa and mantissa.strip("-").isdigit():
        mantissa += ".0"
    return mantissa


_SIMPLE_ESCAPES = {"\t": "\\t", "\r": "\\r", "\n": "\\n", "\\": "\\\\", '"': '\\"', "\0": "\\0"}


def _rust_str(text: str) -> str:
    r"""Rust's `{:?}` for a `str`: `"…"` with `escape_debug` applied to every char.

    `\t \r \n \\ \" \0` by name; a grapheme extender (Mn/Me here — Rust
    tests `Grapheme_Extend`, which those two categories approximate) or a
    char that is not printable (Rust's `is_printable`, approximated by
    `str.isprintable`) as `\u{x}` in minimal lowercase hex; everything
    else, a single quote included, as itself.
    """
    out = []
    for ch in text:
        if ch in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[ch])
        elif ch.isprintable() and unicodedata.category(ch) not in ("Mn", "Me"):
            out.append(ch)
        else:
            out.append(f"\\u{{{ord(ch):x}}}")
    return '"' + "".join(out) + '"'


def _rust_guid(value: uuid.UUID) -> str:
    """Upstream's `GuidValue` Debug: the registry form in upper case."""
    return f"GuidValue {{ {str(value).upper()} }}"


def _rust_binary(value: bytes) -> str:
    """Upstream's `BinaryValue` Debug: `AA-BB-CC`, and `BinaryValue {  }` (two spaces) when empty."""
    return f"BinaryValue {{ {'-'.join(f'{b:02X}' for b in value)} }}"


def _rust_element(base: PropType, value: PropValue) -> str:
    """One scalar as it appears inside its variant — bare for the numbers, wrapped for the struct-like values."""
    if base is PropType.BOOLEAN:
        return "true" if value else "false"
    if base in (PropType.FLOAT, PropType.DOUBLE, PropType.APPTIME):
        assert isinstance(value, float)
        return _rust_float(value, single=base is PropType.FLOAT)
    if base is PropType.SYSTIME:
        assert isinstance(value, datetime)
        return str(datetime_to_filetime(value))
    if base is PropType.GUID:
        assert isinstance(value, uuid.UUID)
        return _rust_guid(value)
    if base is PropType.BINARY:
        assert isinstance(value, bytes)
        return _rust_binary(value)
    if base is PropType.UNICODE:
        assert isinstance(value, str)
        return f"UnicodeValue {{ {_rust_str(value)} }}"
    if base is PropType.STRING8:
        assert isinstance(value, str)
        return f"String8Value {{ {_rust_str(value)} }}"
    if base is PropType.OBJECT:
        assert isinstance(value, ObjectRef)
        return f"ObjectValue {{ {value.node}, size: 0x{value.size:X} }}"
    assert isinstance(value, int) and not isinstance(value, bool), (base, value)
    return str(value)


def format_property_value(prop_type: PropType, value: PropValue) -> str:
    """Upstream's `Debug for PropertyValue` for a value this port decoded as `prop_type` (P05).

    `Null` for `None` whatever the declared type — upstream's `Null` is a
    value, not a type. A `Time` is printed as the FILETIME ticks the
    `datetime` converts back to, which drops the sub-microsecond digit
    `filetime_to_datetime` dropped (P22): a golden `Time(n)` compares equal
    to this only when `n % 10 == 0`. A multi-value is `Multiple…([a, b])`,
    Rust's `Vec` Debug.
    """
    if value is None:
        return "Null"
    name = prop_type.debug_name
    if isinstance(value, tuple):
        base = PropType.from_wire(int(prop_type) & ~0x1000)
        return f"{name}([{', '.join(_rust_element(base, item) for item in value)}])"
    return f"{name}({_rust_element(prop_type, value)})"


# Upstream's examples have no code page at all: `String8Value` is built by
# widening each byte to U+00XX, which is exactly `latin-1`. The dumper uses
# it so that its output is byte-comparable with the goldens; `cp1252`, the
# library default, differs on 0x80..0x9F.
DUMP_CODEPAGE = "latin-1"


def property_lines(prop_id: int, record: PropertyRecord, value: PropValue) -> list[str]:
    """The three lines `read_store_props` and `dump_pc` print for one property.

    `Type:` is the VALUE's variant, as upstream's example computes it
    (`PropertyType::from(&value)`), so a variable-size record whose HNID is
    0 prints `Type: Null` and `Value: Null` whatever `wPropType` says.
    `Record:` is upstream's `PropertyValueRecord` Debug; the store-props
    example does not print it, the table examples print their own.
    """
    return [
        f" Property ID: 0x{prop_id:04X}, Type: {record.value_type.debug_name}",
        f"  Record: {record}",
        f"  Value: {format_property_value(record.prop_type, value)}",
    ]


def dump_pc(path: Path, nid: str) -> None:
    """`pc <file> <nid-hex>`: the node's property context as upstream's `read_store_props` prints one (P05).

    Every property in ascending id order as ` Property ID: 0x%04X, Type: %s`,
    then `  Record: %s` (upstream's `PropertyValueRecord` Debug — `Small(0x…)`,
    the HeapId, or the sub-node NodeId; the store-props example does not print
    it, the table examples print their own) and `  Value: %s`, the value's
    `Debug`. `Type:` is the VALUE's variant as upstream's example computes
    it (`PropertyType::from(&value)`), so a zero HNID prints `Type: Null` and
    `Value: Null`. String8 values are decoded as latin-1, which is upstream's
    (code-page-less) reading, so the two outputs are byte-comparable. The
    store's `Display Name:` and entry-id lines are the messaging layer's
    (P07) and are not printed here.
    """
    node = _parse_nid(nid)
    with path.open("rb") as f:
        header = read_header(f)
        root = header.root
        block_btree = BlockBTree(f, root.block_btree, DEFAULT_LIMITS)
        node_btree = NodeBTree(f, root.node_btree, DEFAULT_LIMITS)
        reader = BlockReader(f, header, block_btree, DEFAULT_LIMITS)
        pc = PropertyContext.from_node(reader, node_btree.find(node), codepage=DUMP_CODEPAGE)
        for prop_id, record in pc.records.items():
            for line in property_lines(prop_id, record, pc.read(record)):
                print(line)


DUMPERS["pc"] = dump_pc


def format_cell_record(prop_type: PropType, record: CellRecord, value: PropValue) -> str:
    """Upstream's `Debug for TableRowColumnValue` for one cell of a table row (P06).

    `Small(<the value's Debug>)` for an inline cell — upstream's variant
    wraps the `PropertyValue` itself, so this needs the decoded value where
    a PC's `Record:` needed only the raw field — `Heap(<HeapId>)` for a heap
    id, `Node(<NodeId>)` for a sub-node.
    """
    if record.kind is CellKind.SMALL:
        return f"Small({format_property_value(prop_type, value)})"
    if record.kind is CellKind.HEAP:
        return f"Heap({HeapId(record.raw)})"
    return f"Node({NodeId(record.raw)})"


def cell_lines(column: ColumnDescriptor, record: CellRecord | None, value: PropValue) -> list[str]:
    """The lines `read_root_folder` / `read_ipm_subtree` print for one column of one row.

    Two lines for an absent cell (the column, then `Value: None`) and three
    for a present one. `Type:` is the COLUMN's declared type, not the
    value's variant — the table examples print `column.prop_type()`, where
    `read_store_props` prints the variant of what it decoded.
    """
    head = f" Column: Property ID: 0x{column.prop_id:04X}, Type: {column.prop_type.debug_name}"
    if record is None:
        return [head, "  Value: None"]
    return [
        head,
        f"  Record: {format_cell_record(column.prop_type, record, value)}",
        f"  Value: {format_property_value(column.prop_type, value)}",
    ]


def dump_tc(path: Path, nid: str) -> None:
    """`tc <file> <nid-hex>`: the node's table context as `read_root_folder` / `read_ipm_subtree` print one (P06).

    Every row of the row matrix in matrix order — `Row:` and `Version:` in
    upstream's minimal hex, then each column of the schema in `rgTCOLDESC`
    order, with `Value: None` where the row's cell existence bitmap says the
    column is absent. String8 values are decoded as latin-1 (`DUMP_CODEPAGE`),
    which is upstream's code-page-less reading, so the two outputs are
    byte-comparable.
    """
    node = _parse_nid(nid)
    with path.open("rb") as f:
        header = read_header(f)
        root = header.root
        block_btree = BlockBTree(f, root.block_btree, DEFAULT_LIMITS)
        node_btree = NodeBTree(f, root.node_btree, DEFAULT_LIMITS)
        reader = BlockReader(f, header, block_btree, DEFAULT_LIMITS)
        tc = TableContext.from_node(reader, node_btree.find(node), codepage=DUMP_CODEPAGE)
        for row in tc.rows():
            print(f"Row: 0x{row.id:X}")
            print(f"Version: 0x{row.unique:X}")
            for column, record in zip(tc.columns, row.records, strict=True):
                value = None if record is None else tc.read_cell(record, column.prop_type)
                for line in cell_lines(column, record, value):
                    print(line)


DUMPERS["tc"] = dump_tc


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
