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

from pypst.eml import eml_bytes, export_folder, folder_paths
from pypst.errors import PstError, PstFormatError
from pypst.limits import DEFAULT_LIMITS
from pypst.ltp.heap import HeapId, HeapNode
from pypst.ltp.prop_context import PropertyContext, PropertyRecord
from pypst.ltp.prop_type import ObjectRef, PropType, PropValue, datetime_to_filetime
from pypst.ltp.table_context import (
    CellKind,
    CellRecord,
    ColumnDescriptor,
    TableContext,
    TableRow,
)
from pypst.ltp.tree import HeapTree
from pypst.mbox import export_mbox
from pypst.messaging import attachment as attachment_mod
from pypst.messaging import folder as folder_mod
from pypst.messaging import message as message_mod
from pypst.messaging.attachment import Attachment
from pypst.messaging.folder import Folder
from pypst.messaging.message import Message
from pypst.messaging.named_prop import PS_MAPI, PS_PUBLIC_STRINGS
from pypst.messaging.store import Store
from pypst.ndb.block import BlockReader, DataBlock, SubNodeLeafBlock
from pypst.ndb.btree import BlockBTree, NodeBTree, read_density_list
from pypst.ndb.header import read_header
from pypst.ndb.ids import NID_ROOT_FOLDER, BlockId, NodeId, NodeIdType
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
# --- the message store and its named properties (P07) ----------------------------------------


def dump_store(path: Path) -> None:
    """Upstream's `read_store_props` example (P07): four header lines, then the store PC.

    `Display Name:`, `IPM Subtree:`, `Deleted Items:`, `Finder:` — each
    evaluated and printed in turn, exactly as the example's `?` operators
    order them — and then every property of `NID_MESSAGE_STORE` in
    ascending id order, as ` Property ID: …` / `  Value: …` (the example
    prints no `Record:` line; `dump_pc` does, and that is the only
    difference between the two dumpers' property sections).

    **The store opens where the example fails.** `pypst.messaging.store`
    treats an absent `PidTagIpmWastebasketEntryId` or `PidTagFinderEntryId`
    as `None` rather than a refusal (its module docstring says why), so
    `pstd-inline-cid.pst` opens here and does not upstream. This dumper's
    contract is the *example's*, not the library's: it refuses the same
    absence at the same point, so its stdout and its exit status match the
    golden byte for byte (two lines, exit 1) on that store.
    """
    with Store.open(path, codepage=DUMP_CODEPAGE) as store:
        print(f"Display Name: {store.display_name}")
        print(f"IPM Subtree: {store.ipm_subtree}")
        wastebasket = store.wastebasket
        if wastebasket is None:
            raise PstFormatError("Missing PidTagIpmWastebasketEntryId on store")
        print(f"Deleted Items: {wastebasket}")
        finder = store.finder
        if finder is None:
            raise PstFormatError("Missing PidTagFinderEntryId on store")
        print(f"Finder: {finder}")
        pc = store.properties
        for prop_id, record in pc.records.items():
            for line in property_lines(prop_id, record, pc.read(record)):
                if not line.startswith("  Record: "):
                    print(line)


DUMPERS["store"] = dump_store


def dump_named_props(path: Path) -> None:
    """Upstream's `read_named_props` example (P07): every NAMEID of `NID_NAME_TO_ID_MAP`.

    Per entry: `Named Property ID: 0x%04X`, ` GUID Index: %s` (upstream's
    `Debug for NamedPropertyGuid` — `None`, `Mapi`, `PublicStrings`,
    `GuidIndex(n)`), the GUID itself on the next line for the three cases
    that have one, and then either ` Number: 0x%08X` or ` String[0x%08X]:
    %s` with the name in Rust's `{:?}` spelling.
    """
    with Store.open(path) as store:
        named = store.named_properties
        for entry in named.entries:
            print(f"Named Property ID: 0x{entry.prop_id:04X}")
            print(f" GUID Index: {entry.guid}")
            if entry.guid.well_known == PS_MAPI:
                print(f" PS_MAPI: {_rust_guid(PS_MAPI)}")
            elif entry.guid.well_known == PS_PUBLIC_STRINGS:
                print(f" PS_PUBLIC_STRINGS: {_rust_guid(PS_PUBLIC_STRINGS)}")
            elif entry.guid.is_index:
                print(f" Other: {_rust_guid(named.guid_of(entry))}")
            if entry.is_string:
                print(f" String[0x{entry.name_id:08X}]: {_rust_str(named.lookup_string(entry.name_id))}")
            else:
                print(f" Number: 0x{entry.name_id:08X}")


DUMPERS["named_props"] = dump_named_props


# --- the folder tree (P08) ---------------------------------------------------------------

# Upstream's `MessagingError` variant names, per property, for the two shapes
# `FolderProperties`' accessors can fail in: absent, and present-but-wrong-type.
_FOLDER_ERRORS: dict[int, tuple[str, str]] = {
    folder_mod.PID_TAG_DISPLAY_NAME: ("FolderDisplayNameNotFound", "InvalidFolderDisplayName"),
    folder_mod.PID_TAG_CONTENT_COUNT: ("FolderContentCountNotFound", "InvalidFolderContentCount"),
    folder_mod.PID_TAG_CONTENT_UNREAD_COUNT: ("FolderUnreadCountNotFound", "InvalidFolderUnreadCount"),
    folder_mod.PID_TAG_SUBFOLDERS: ("FolderHasSubfoldersNotFound", "InvalidFolderHasSubfolders"),
}


def _messaging_error(name: str) -> str:
    """Upstream's `Debug` for the `io::Error` a `MessagingError` converts into."""
    return f"Error: Custom {{ kind: InvalidData, error: {name} }}"


def folder_accessor(folder: Folder, prop_id: int, render: Callable[[], str]) -> str:
    """One accessor's value, or the oracle's `Error: …` text in its place (`result_debug` in dump_messages.rs).

    The accessor is the library's, so what is printed is what a caller would
    get. Only the *refusal* is re-rendered: upstream names the property and
    the variant of the value it found, which `PropertyRecord.value_type`
    gives, so `Name: Error: Custom { kind: InvalidData, error:
    InvalidFolderDisplayName(Null) }` reproduces exactly.
    """
    try:
        return render()
    except PstError:
        missing, invalid = _FOLDER_ERRORS[prop_id]
        record = folder.properties.records.get(prop_id)
        if record is None:
            return _messaging_error(missing)
        return _messaging_error(f"{invalid}({record.value_type.debug_name})")


def folder_table(folder: Folder, node_type: NodeIdType) -> TableContext | None:
    """Upstream's `self.read_table(kind).ok()?`: a table that will not parse is reported as absent.

    A deliberate re-creation of upstream's swallow, and the one place this
    port does it. `Folder.table` refuses a present-but-corrupt table
    (`pypst.messaging.folder`'s module docstring says why), which is the
    right answer for a caller; here the contract is the *example's*, so that
    the dumper's output matches `dump_messages.txt` byte for byte on
    `pstd-inline-cid.pst`, whose three root-folder tables are all present in
    the node B-tree and all unreadable by upstream and by this port alike.
    The same pattern as `dump_store`, which reproduces its example's refusal.
    """
    try:
        return folder.table(node_type)
    except PstError:
        return None


def folder_lines(folder: Folder) -> list[str]:
    """The six-to-eight line block `dump_messages` prints for one folder, without the `Folder:` line.

    Upstream's order, which is not the obvious one: the four properties,
    then the ASSOCIATED table's row count, then the contents table (whose
    rows are the `Message:` blocks this dumper stops before) and then the
    hierarchy table — each printing a `… Table: None` line only when it is
    absent.
    """
    out = [
        f"  Name: {folder_accessor(folder, folder_mod.PID_TAG_DISPLAY_NAME, lambda: _rust_str(folder.display_name))}",
        f"  Content Count: {folder_accessor(folder, folder_mod.PID_TAG_CONTENT_COUNT, lambda: str(folder.content_count))}",
        f"  Unread Count: {folder_accessor(folder, folder_mod.PID_TAG_CONTENT_UNREAD_COUNT, lambda: str(folder.unread_count))}",
        f"  Has Sub Folders: {folder_accessor(folder, folder_mod.PID_TAG_SUBFOLDERS, lambda: 'true' if folder.has_subfolders else 'false')}",
    ]
    associated = folder_table(folder, NodeIdType.ASSOC_CONTENTS_TABLE)
    out.append("  Associated Table: None" if associated is None else f"  Associated Count: {len(associated)}")
    if folder_table(folder, NodeIdType.CONTENTS_TABLE) is None:
        out.append("  Contents Table: None")
    if folder_table(folder, NodeIdType.HIERARCHY_TABLE) is None:
        out.append("  Hierarchy Table: None")
    return out


def dump_folders(path: Path) -> None:
    """`folders <file>`: the folder blocks of `oracle/examples/dump_messages.rs`, and nothing else (P08).

    A pre-order walk from `NID_ROOT_FOLDER` (0x122 — NOT the IPM subtree:
    starting above it is what puts the wastebasket, the search root and the
    search folders in the dump), children in row-matrix order, each folder's
    block at column 0 whatever its depth — all exactly as `dump_folder` does
    it. The `Message:` blocks the oracle prints between a folder's
    `Associated Count:` and its children are P09's and are omitted here, as
    is the `Errors:` trailer, which counts errors this dumper cannot see;
    `tests/golden_parsers.dump_messages_folder_lines` filters a golden down
    to exactly what this prints.

    Error handling is the example's, not the library's: a folder that cannot
    be opened prints an indented `Error:` line and the walk continues, so
    one unreadable folder does not hide the rest of the tree. No corpus
    store has one — the text of that line is this port's, since the
    exception is — and `python -m pypst.debug folders` still exits 0, as the
    example does when its `Errors:` count is what makes it exit 1.
    """
    limits = DEFAULT_LIMITS
    with Store.open(path, codepage=DUMP_CODEPAGE) as store:
        seen: set[NodeId] = set()
        stack: list[tuple[NodeId, int]] = [(NID_ROOT_FOLDER, 0)]
        while stack:
            node, depth = stack.pop()
            print(f"Folder: {node}")
            if depth > limits.max_folder_depth:
                print(f'  Error: "folder depth exceeds {limits.max_folder_depth}"')
                continue
            if node in seen:
                print('  Error: "folder already visited (cycle in the hierarchy)"')
                continue
            seen.add(node)
            try:
                folder = store.open_folder(node)
                lines = folder_lines(folder)
                children = folder.subfolder_ids() if folder_table(folder, NodeIdType.HIERARCHY_TABLE) is not None else ()
            except PstError as exc:
                print(f"  Error: {exc}")
                continue
            for line in lines:
                print(line)
            stack.extend((child, depth + 1) for child in reversed(children))


DUMPERS["folders"] = dump_folders


# --- messages, recipients and attachments (P09) -------------------------------------------

# The property types upstream's `PropertyType::try_from(u16)` accepts at the
# pinned revision (ltp/prop_type.rs). `PtypObject` (0x000D) is NOT among them
# although the enum declares the variant, and upstream's BTH leaf walk stops
# at the first record it cannot decode, so upstream's view of a property
# context ENDS at the first property whose type is outside this set — in
# property-id order, because a BTH's leaves are sorted by key. That is why
# every embedded-message attachment fails upstream with
# `AttachmentMethodNotFound`: `PidTagAttachDataObject` (0x3701) is a
# `PtypObject` and sorts before `PidTagAttachMethod` (0x3705).
UPSTREAM_PROPERTY_TYPES = frozenset(
    {
        0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x000A, 0x000B,
        0x0014, 0x001E, 0x001F, 0x0040, 0x0048, 0x0102,
        0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007, 0x1014, 0x101E, 0x101F,
        0x1040, 0x1048, 0x1102,
    }
)


def upstream_records(pc: PropertyContext) -> dict[int, PropertyRecord]:
    """The records upstream's `PropertyContext::properties()` would see: ours, truncated where its walk stops.

    A deliberate re-creation of an upstream limitation, in the dumper and
    nowhere else — `pypst.messaging.attachment`'s module docstring
    arbitrates the divergence. Without it `debug messages` would print the
    embedded-message attachments the library can read and the goldens, which
    upstream produced, could not be matched byte for byte.
    """
    out: dict[int, PropertyRecord] = {}
    for prop_id, record in pc.records.items():  # ascending id: the BTH's own order
        if int(record.prop_type) not in UPSTREAM_PROPERTY_TYPES:
            break
        out[prop_id] = record
    return out


def _filetime_debug(pc: PropertyContext, record: PropertyRecord) -> str | None:
    """`Time(<ticks>)` straight from the stored 8 bytes, for a `PtypTime`; None for anything else.

    `format_property_value` prints a time by converting the `datetime` back
    to FILETIME, and `filetime_to_datetime` (P22) drops the sub-microsecond
    tick that does not fit a `datetime` — so a store that wrote
    `Time(131485947642894527)` would print `…520`. Three corpus messages
    have such a delivery time, and upstream prints the `i64` it read. The
    ticks are the fact; this reads them where the dumper needs them, and
    `Message.delivery_filetime` is the same thing for a caller.
    """
    if record.prop_type is not PropType.SYSTIME or record.is_null:
        return None
    hnid = record.hnid
    if hnid is None:
        return None
    raw = pc.heap.get_hnid(hnid)
    if len(raw) != FILETIME_SIZE:
        return None
    return f"Time({int.from_bytes(raw, 'little', signed=True)})"


FILETIME_SIZE = 8


def _value_debug(pc: PropertyContext, records: dict[int, PropertyRecord], prop_id: int) -> str:
    """`value_debug` in dump_messages.rs: `None`, or upstream's `Debug` for the decoded value."""
    record = records.get(prop_id)
    if record is None:
        return "None"
    ticks = _filetime_debug(pc, record)
    if ticks is not None:
        return ticks
    return format_property_value(record.prop_type, pc.read(record))


def _value_bytes(record: PropertyRecord, value: PropValue) -> tuple[bytes, str] | None:
    """The raw bytes behind a body-like value and upstream's name for its variant, or None for anything else."""
    if isinstance(value, bytes):
        return value, "Binary"
    if isinstance(value, str):
        if record.prop_type is PropType.UNICODE:
            return value.encode("utf-16-le"), "Unicode"
        if record.prop_type is PropType.STRING8:
            return value.encode(DUMP_CODEPAGE), "String8"
    return None


def _bytes_debug(pc: PropertyContext, records: dict[int, PropertyRecord], prop_id: int) -> str:
    """`bytes_debug` in dump_messages.rs: `<n> bytes crc 0x… type=…`, the LENGTH and CRC of a body, never its text."""
    record = records.get(prop_id)
    if record is None:
        return "None"
    value = pc.read(record)
    raw = _value_bytes(record, value)
    if raw is None:
        return format_property_value(record.prop_type, value)
    data, kind = raw
    return f"{len(data)} bytes crc 0x{zlib.crc32(data) & 0xFFFFFFFF:08X} type={kind}"


# Upstream's `MessagingError` variants for the accessors the dumper calls,
# as `_FOLDER_ERRORS` does for a folder's four.
_MESSAGE_ERRORS: dict[int, tuple[str, str]] = {
    message_mod.PID_TAG_MESSAGE_CLASS: ("MessageClassNotFound", "InvalidMessageClass"),
}
_ATTACHMENT_ERRORS: dict[int, tuple[str, str]] = {
    attachment_mod.PID_TAG_ATTACH_METHOD: ("AttachmentMethodNotFound", "InvalidAttachmentMethod"),
    attachment_mod.PID_TAG_ATTACH_SIZE: ("AttachmentSizeNotFound", "InvalidAttachmentSize"),
}


def _accessor(
    records: dict[int, PropertyRecord],
    errors: dict[int, tuple[str, str]],
    prop_id: int,
    render: Callable[[], str],
) -> str:
    """`result_debug` in dump_messages.rs, for one named accessor: its value, or upstream's `Error: …` in its place."""
    try:
        return render()
    except PstError:
        missing, invalid = errors[prop_id]
        record = records.get(prop_id)
        if record is None:
            return _messaging_error(missing)
        return _messaging_error(f"{invalid}({record.value_type.debug_name})")


def message_accessor(message: Message, prop_id: int, render: Callable[[], str]) -> str:
    """One message accessor's value, or the oracle's `Error: …` text in its place (`folder_accessor`'s twin)."""
    return _accessor(upstream_records(message.properties), _MESSAGE_ERRORS, prop_id, render)


def attachment_accessor(attachment: Attachment, prop_id: int, render: Callable[[], str]) -> str:
    """One attachment accessor's value, or the oracle's `Error: …` text in its place."""
    return _accessor(upstream_records(attachment.properties), _ATTACHMENT_ERRORS, prop_id, render)


def _message_open_error(store: Store, node: NodeId, exc: PstError) -> str:
    """Upstream's `Debug` for the refusal `Store::open_message` would have produced, when this port refused too.

    Only the conditions upstream checks in the same order are re-rendered —
    a NID whose type is not a message's, and a message node with no sub-node
    tree, which `javalibpst-dist-list.pst` has one of. Anything else is this
    port's own refusal and is printed as its own text, because inventing an
    upstream variant name for it would be a lie.
    """
    try:
        node_type = node.id_type
    except PstError:
        return f"Error: {exc}"
    if node_type not in message_mod.MESSAGE_NODE_TYPES:
        return _messaging_error(f"InvalidMessageEntryIdType({node_type.debug_name})")
    try:
        if store.nbt.find(node).sub_node is None:
            return _messaging_error("MessageSubNodeTreeNotFound")
    except PstError:
        pass
    return f"Error: {exc}"


def _open_message_as_upstream(store: Store, node: NodeId) -> Message:
    """Open a message and force everything upstream's `MessageInner::read` forces before it returns.

    Upstream decodes every property and reads both sub-node tables while
    opening, so a message this port would open lazily and refuse later is a
    message upstream never returns at all. The dumper has to fail in the
    same place to print the same lines; the library's laziness is the
    divergence `pypst.messaging.message`'s docstring records.
    """
    message = store.open_message(node)
    # `upstream_records`, not every record: a property upstream's walk never
    # reaches cannot be what its open failed on.
    for record in upstream_records(message.properties).values():
        message.properties.read(record)
    _ = (message.recipient_table, message.attachment_table)
    return message


def _cell_debug(table: TableContext, row: TableRow, prop_id: int, *, integer: bool = False) -> str:
    """One cell of a table row by property id — `cell()` in dump_messages.rs, with `int_debug` for the two counts.

    `None` when the table has no such column or the row has no value there,
    which is upstream's `?` on both lookups; otherwise the value's `Debug`,
    or a bare number when `integer` and the value is an Integer32.
    """
    index = next((i for i, column in enumerate(table.columns) if column.prop_id == prop_id), None)
    if index is None or row.records[index] is None:
        return "None"
    column = table.columns[index]
    value = row.get(prop_id)
    if integer and isinstance(value, int) and not isinstance(value, bool) and column.prop_type is PropType.LONG:
        return str(value)
    return format_property_value(column.prop_type, value)


def message_lines(message: Message, indent: int) -> list[str]:
    """The twelve property lines `dump_message_properties` prints, at `indent` + 2."""
    pad = " " * (indent + 2)
    pc = message.properties
    records = upstream_records(pc)
    klass = message_accessor(message, message_mod.PID_TAG_MESSAGE_CLASS, lambda: _rust_str(message.message_class))
    out = [f"{pad}Class: {klass}"]
    for label, prop_id in (
        ("Subject", message_mod.PID_TAG_SUBJECT),
        ("Normalized Subject", message_mod.PID_TAG_NORMALIZED_SUBJECT),
        ("Sender Name", message_mod.PID_TAG_SENDER_NAME),
        ("Sender Email", message_mod.PID_TAG_SENDER_EMAIL_ADDRESS),
        ("Sender SMTP", message_mod.PID_TAG_SENDER_SMTP_ADDRESS),
        ("Delivery Time", message_mod.PID_TAG_MESSAGE_DELIVERY_TIME),
        ("Client Submit Time", message_mod.PID_TAG_CLIENT_SUBMIT_TIME),
    ):
        out.append(f"{pad}{label}: {_value_debug(pc, records, prop_id)}")
    for label, prop_id in (
        ("Body Text", message_mod.PID_TAG_BODY),
        ("Body HTML", message_mod.PID_TAG_HTML),
        ("Body RTF", message_mod.PID_TAG_RTF_COMPRESSED),
        ("Transport Headers", message_mod.PID_TAG_TRANSPORT_MESSAGE_HEADERS),
    ):
        out.append(f"{pad}{label}: {_bytes_debug(pc, records, prop_id)}")
    return out


class _MessageDumper:
    """The walk `oracle/examples/dump_messages.rs` performs, printing as it goes and counting its refusals."""

    def __init__(self, store: Store) -> None:
        self.store = store
        self.errors = 0
        self.seen: set[NodeId] = set()

    def error(self, indent: int, text: str) -> None:
        """One counted `Error:` line — `Dumper::error`, whose count decides the example's exit status."""
        print(f"{' ' * indent}{text}")
        self.errors += 1

    def message(self, node: NodeId, indent: int) -> None:
        print(f"{' ' * indent}Message: {node}")
        try:
            message = _open_message_as_upstream(self.store, node)
        except PstError as exc:
            self.error(indent + 2, _message_open_error(self.store, node, exc))
            return
        for line in message_lines(message, indent):
            print(line)
        self.recipients(message, indent)
        self.attachments(message, indent)

    def recipients(self, message: Message, indent: int) -> None:
        pad = " " * (indent + 2)
        table = message.recipient_table
        if table is None:
            print(f"{pad}Recipients: None")
            return
        print(f"{pad}Recipients: {len(table)}")
        for row in table.rows():
            fields = " ".join(
                f"{name}={_cell_debug(table, row, prop_id, integer=name == 'type')}"
                for name, prop_id in (
                    ("type", message_mod.PID_TAG_RECIPIENT_TYPE),
                    ("name", message_mod.PID_TAG_DISPLAY_NAME),
                    ("email", message_mod.PID_TAG_EMAIL_ADDRESS),
                    ("smtp", message_mod.PID_TAG_SMTP_ADDRESS),
                )
            )
            print(f"{' ' * (indent + 4)}Recipient: {fields}")

    def attachments(self, message: Message, indent: int) -> None:
        pad = " " * (indent + 2)
        table = message.attachment_table
        if table is None:
            print(f"{pad}Attachments: None")
            return
        rows = list(table.rows())
        print(f"{pad}Attachments: {len(rows)}")
        for row in rows:
            node = NodeId(row.id)
            print(f"{' ' * (indent + 4)}Attachment: {node}")
            fields = " ".join(
                f"{name}={_cell_debug(table, row, prop_id, integer=name in ('method', 'size'))}"
                for name, prop_id in (
                    ("method", attachment_mod.PID_TAG_ATTACH_METHOD),
                    ("filename", attachment_mod.PID_TAG_ATTACH_FILENAME),
                    ("size", attachment_mod.PID_TAG_ATTACH_SIZE),
                )
            )
            print(f"{' ' * (indent + 6)}Row: {fields}")
            self.attachment(message, node, indent + 6)

    def attachment(self, message: Message, node: NodeId, indent: int) -> None:
        """One attachment's own property context, or the refusal upstream's `open_attachment` would have made."""
        pad = " " * indent
        try:
            attachment = Attachment(message, node)
            records = upstream_records(attachment.properties)
            for record in records.values():
                attachment.properties.read(record)
        except PstError as exc:
            self.error(indent, f"Error: {exc}")
            return
        refusal = _upstream_attachment_refusal(attachment, records)
        if refusal is not None:
            self.error(indent, _messaging_error(refusal))
            return
        print(f"{pad}Method: {attachment_accessor(attachment, attachment_mod.PID_TAG_ATTACH_METHOD, lambda: str(attachment.method_value))}")
        pc = attachment.properties
        for label, prop_id in (
            ("Filename", attachment_mod.PID_TAG_ATTACH_FILENAME),
            ("Long Filename", attachment_mod.PID_TAG_ATTACH_LONG_FILENAME),
            ("Mime Tag", attachment_mod.PID_TAG_ATTACH_MIME_TAG),
            ("Content Id", attachment_mod.PID_TAG_ATTACH_CONTENT_ID),
        ):
            print(f"{pad}{label}: {_value_debug(pc, records, prop_id)}")
        print(f"{pad}Size: {attachment_accessor(attachment, attachment_mod.PID_TAG_ATTACH_SIZE, lambda: str(attachment.size))}")
        try:
            data = attachment.data()
        except PstError as exc:
            self.error(indent, f"Error: {exc}")
            return
        if data is None:
            print(f"{pad}Data: None")
        else:
            print(f"{pad}Data: {len(data)} bytes crc 0x{zlib.crc32(data) & 0xFFFFFFFF:08X}")

    def folder(self, node: NodeId, depth: int) -> None:
        limits = self.store.limits
        print(f"Folder: {node}")
        if depth > limits.max_folder_depth:
            self.error(2, f'"folder depth exceeds {limits.max_folder_depth}"')
            return
        if node in self.seen:
            self.error(2, '"folder already visited (cycle in the hierarchy)"')
            return
        self.seen.add(node)
        try:
            folder = self.store.open_folder(node)
            lines = folder_lines(folder)
        except PstError as exc:
            self.error(2, f"Error: {exc}")
            return
        # `folder_lines` prints the four properties, the associated count and
        # then the two `… Table: None` lines; the messages go between them,
        # which is where `dump_folder` prints them.
        for line in lines[:_FOLDER_LINES_BEFORE_MESSAGES]:
            print(line)
        contents = folder_table(folder, NodeIdType.CONTENTS_TABLE)
        if contents is not None:
            for row in contents.rows():
                self.message(NodeId(row.id), 2)
        for line in lines[_FOLDER_LINES_BEFORE_MESSAGES:]:
            print(line)
        children = folder.subfolder_ids() if folder_table(folder, NodeIdType.HIERARCHY_TABLE) is not None else ()
        for child in children:
            self.folder(child, depth + 1)


# `folder_lines`' first five lines are the four named properties and the
# associated table's count; anything after them is a `… Table: None` line,
# which `dump_folder` prints AFTER the folder's messages.
_FOLDER_LINES_BEFORE_MESSAGES = 5


def _upstream_attachment_refusal(attachment: Attachment, records: dict[int, PropertyRecord]) -> str | None:
    """The `MessagingError` variant `AttachmentInner::read` would fail with, or None when it would succeed.

    Upstream's order: the method, then the data property its arm needs.
    Only the *view* is upstream's (`upstream_records`); the values are read
    through the library, so a mistake here shows up as a golden diff.
    """
    pc = attachment.properties
    record = records.get(attachment_mod.PID_TAG_ATTACH_METHOD)
    if record is None:
        return "AttachmentMethodNotFound"
    method = pc.read(record)
    if not isinstance(method, int) or isinstance(method, bool):
        return f"InvalidAttachmentMethod({record.value_type.debug_name})"
    if method not in _UPSTREAM_ATTACHMENT_METHODS:
        return f"UnknownAttachmentMethod({method})"
    if method not in _UPSTREAM_METHODS_WITH_DATA:
        return None
    data = records.get(attachment_mod.PID_TAG_ATTACH_DATA_BINARY)
    if data is None:
        return "AttachmentMessageObjectDataNotFound"
    wanted = PropType.BINARY if method == attachment_mod.AttachMethod.BY_VALUE else PropType.OBJECT
    if data.prop_type is not wanted:
        return f"InvalidMessageObjectData({data.value_type.debug_name})"
    return None


# Upstream's `TryFrom<i32> for AttachmentMethod` has no arm for 3
# (`afByReferenceResolve`), which [MS-OXCMSG] 2.2.2.9 defines and this port
# accepts; the dumper needs upstream's set, not this port's.
_UPSTREAM_ATTACHMENT_METHODS = frozenset({0, 1, 2, 4, 5, 6, 7})
_UPSTREAM_METHODS_WITH_DATA = frozenset({1, 5, 6})


def dump_messages(path: Path) -> None:
    """`messages <file>`: the whole of `oracle/examples/dump_messages.rs` — folders, messages, recipients, attachments.

    `debug folders` prints this dump's folder blocks; this prints all of it,
    including the `Message:` blocks under each folder's contents table, the
    recipient and attachment rows, each attachment's own property context,
    and the `Errors: <n>` trailer. As the example does, a folder, message or
    attachment that cannot be opened prints an indented `Error:` line, is
    counted, and the walk goes on; an accessor that refuses prints its
    refusal in place of the value and is not counted.

    Two of the example's contracts are re-created here rather than taken
    from the library, both so that the output still matches the goldens the
    pinned Rust produced: `folder_table`'s swallow (P08), and
    `upstream_records`, which truncates a property context where upstream's
    BTH walk stops. The second is what prints
    `Error: … AttachmentMethodNotFound` for the embedded-message
    attachments that `pypst.messaging.attachment` can and upstream cannot
    open — see that module's docstring.

    Exit status is the example's: `PstError` (and so exit 1) when the
    trailer is not `Errors: 0`, after the whole dump has been printed.
    """
    with Store.open(path, codepage=DUMP_CODEPAGE) as store:
        dumper = _MessageDumper(store)
        dumper.folder(NID_ROOT_FOLDER, 0)
        print(f"Errors: {dumper.errors}")
        if dumper.errors:
            raise PstFormatError(f"{dumper.errors} object(s) in {path.name} could not be read")


DUMPERS["messages"] = dump_messages


# --- P10: the .eml and mbox exporters ----------------------------------------------


def dump_eml(path: Path, nid: str) -> None:
    """`eml <file> <nid-hex>`: one message as RFC 5322, on stdout.

    The bytes `pypst.eml.eml_bytes` produces, which are pure ASCII with CRLF
    line endings, written through the text stream so that a terminal and a
    `>` redirect agree. The nid is hex, with or without `0x` — the raw NID,
    as `messages` prints it in `Message: NodeId { NormalMessage: 0x…}` shifted
    left five bits, or as `export` names the file.
    """
    node = _parse_nid(nid)
    with Store.open(path, codepage=DUMP_CODEPAGE) as store:
        data = eml_bytes(store.open_message(node))
    sys.stdout.write(data.decode("ascii"))


DUMPERS["eml"] = dump_eml


def dump_export(path: Path, dest: str, *, as_eml: bool = False) -> None:
    """`export <file> <dir>`: every folder of the store as `<nid>.mbox`, plus `folders.txt`.

    `--eml` writes one `<nid>.eml` per message into the same directory
    instead. Both walk the whole store from the root folder and skip what
    refuses (`pypst.eml.export_folder`'s `strict=False`), so one unreadable
    folder does not cost the export; the counts printed are what was
    written, and the mbox index records which folders were skipped.
    """
    target = Path(dest)
    with Store.open(path, codepage=DUMP_CODEPAGE) as store:
        root = store.root_folder
        folders = sum(1 for _ in folder_paths(root))
        written = export_folder(root, target) if as_eml else export_mbox(root, target)
    print(f"Format: {'eml' if as_eml else 'mbox'}")
    print(f"Folders: {folders}")
    print(f"Messages: {written}")


DUMPERS["export"] = dump_export


def dumper_arguments(dumper: Callable[..., None]) -> list[str]:
    """The names of a dumper's extra POSITIONAL parameters, after the store's path.

    Keyword-only parameters are the CLI's flags (`export`'s `as_eml`), not
    its positional arguments, so they are not counted here — `main` maps a
    flag to one, and `tests/contract.py` builds the positional ones by name.
    """
    positional = (
        param
        for param in inspect.signature(dumper).parameters.values()
        if param.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    )
    return [param.name for param in positional][1:]


def main(argv: list[str] | None = None) -> int:
    names = ", ".join(sorted(DUMPERS)) or "(none registered yet)"
    parser = argparse.ArgumentParser(
        prog="python -m pypst.debug",
        description="Print one layer of a PST in the upstream example's format.",
        epilog=f"registered layers: {names}",
    )
    parser.add_argument("--list", action="store_true", help="print the registered layer names and exit")
    parser.add_argument(
        "--eml",
        action="store_true",
        help="`export`: write one .eml per message instead of one .mbox per folder",
    )
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
    wanted = len(dumper_arguments(dumper))
    if len(args.extra) != wanted:
        parser.error(f"layer {args.layer!r} takes {wanted} extra argument(s), got {len(args.extra)}")
    options: dict[str, bool] = {}
    if args.eml:
        if "as_eml" not in inspect.signature(dumper).parameters:
            parser.error(f"--eml applies to the `export` layer, not to {args.layer!r}")
        options["as_eml"] = True
    try:
        dumper(args.file, *args.extra, **options)
    except PstError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
