"""Parsers that turn the Rust oracle's ``Debug`` text into plain Python values.

One parser per upstream example (the eight captured by
``scripts/capture_oracle.py``), plus the shared value parsers for the id
types that every example prints. A differential test parses the committed
golden with one of these, parses ``python -m pypst.debug <layer>`` output
with the *same* function, and compares the values — never the strings, since
upstream's formatting is upstream's to change.

Two rules every parser here keeps:

- **Never return a partial result.** A truncated or garbled input raises
  ``ValueError`` naming the line (number and text) that broke the shape. A
  parser that silently returns nine of ten fields turns a corrupted golden
  into a passing test.
- **The ``Unicode``/``Ansi`` prefix is optional.** Upstream prints
  ``UnicodeBlockId { leaf: 0x4C }``; ``pypst`` has no ANSI variant and its
  ``__str__`` prints ``BlockId { leaf: 0x4C }`` (``docs/INTERFACES.md`` §
  ids). One parser reads both sides, so the prefix is stripped, not required.

``parse_read_header``, ``parse_read_btrees`` and ``parse_read_density_list``
are complete. The other five are stubs whose
``NotImplementedError`` describes the golden's shape, so the layer row that
lands the parser knows what it is parsing. ``PARSERS`` maps every captured
example name to its parser, complete or stub.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

_PREFIX = r"(?:Unicode|Ansi)?"
_HEX = r"0x([0-9A-Fa-f]+)"

_BLOCK_ID = re.compile(rf"^{_PREFIX}BlockId \{{ (leaf|internal): {_HEX} \}}$")
_PAGE_ID = re.compile(rf"^{_PREFIX}PageId: {_HEX}$")
_BYTE_INDEX = re.compile(rf"^{_PREFIX}ByteIndex \{{ {_HEX} \}}$")
_NODE_ID = re.compile(rf"^NodeId \{{ ([A-Za-z]+): {_HEX} \}}$")
_BLOCK_REF = re.compile(rf"^{_PREFIX}BlockRef \{{ block: (.+?), index: (.+?) \}}$")
_PAGE_REF = re.compile(rf"^{_PREFIX}PageRef \{{ page: (.+?), index: (.+?) \}}$")


def _match(pattern: re.Pattern[str], what: str, text: str) -> re.Match[str]:
    m = pattern.match(text)
    if m is None:
        raise ValueError(f"not a {what}: {text!r}")
    return m


def parse_block_id(text: str) -> dict[str, Any]:
    """``UnicodeBlockId { leaf: 0x4C }`` -> ``{"internal": False, "index": 0x4C}``."""
    m = _match(_BLOCK_ID, "BlockId", text)
    return {"internal": m.group(1) == "internal", "index": int(m.group(2), 16)}


def parse_page_id(text: str) -> int:
    """``UnicodePageId: 0x17F`` -> ``0x17F``."""
    return int(_match(_PAGE_ID, "PageId", text).group(1), 16)


def parse_byte_index(text: str) -> int:
    """``UnicodeByteIndex { 0x42400 }`` -> ``0x42400``."""
    return int(_match(_BYTE_INDEX, "ByteIndex", text).group(1), 16)


def parse_node_id(text: str) -> dict[str, Any]:
    """``NodeId { NormalFolder: 0x404 }`` -> ``{"type": "NormalFolder", "index": 0x404}``."""
    m = _match(_NODE_ID, "NodeId", text)
    return {"type": m.group(1), "index": int(m.group(2), 16)}


def parse_block_ref(text: str) -> dict[str, Any]:
    """``UnicodeBlockRef { block: <BlockId>, index: <ByteIndex> }`` -> ``{"block": …, "index": int}``."""
    m = _match(_BLOCK_REF, "BlockRef", text)
    return {"block": parse_block_id(m.group(1)), "index": parse_byte_index(m.group(2))}


def parse_page_ref(text: str) -> dict[str, Any]:
    """``UnicodePageRef { page: <PageId>, index: <ByteIndex> }`` -> ``{"page": int, "index": int}``."""
    m = _match(_PAGE_REF, "PageRef", text)
    return {"page": parse_page_id(m.group(1)), "index": parse_byte_index(m.group(2))}


# --- line-oriented helpers -------------------------------------------------


def _lines(text: str) -> list[str]:
    """Split into lines, dropping only trailing blank lines (the final newline)."""
    lines = text.splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def _labelled(lines: list[str], i: int, label: str) -> str:
    """Return the value of ``lines[i]``, which must read ``<label>: <value>``."""
    if i >= len(lines):
        raise ValueError(f"line {i + 1}: expected {label!r}, got end of input ({len(lines)} line(s))")
    prefix = f"{label}: "
    if not lines[i].startswith(prefix):
        raise ValueError(f"line {i + 1}: expected {label!r}, got {lines[i]!r}")
    return lines[i][len(prefix) :]


# --- read_header (complete) -------------------------------------------------

_VERSIONS = {"Unicode", "Ansi"}
_AMAP_STATUS = re.compile(r"^(Invalid|Valid1|Valid2)$")

READ_HEADER_LABELS = (
    "File Version",
    "Next Block",
    "Next Page",
    "File EOF Index",
    "AMAP Last Index",
    "AMAP Free Size",
    "PMAP Free Size",
    "NBT BlockRef",
    "BBT BlockRef",
    "AMAP Valid",
)


def parse_read_header(text: str) -> dict[str, Any]:
    """The ten lines of upstream's ``read_header`` example, as values.

    Keys mirror ``docs/INTERFACES.md`` § header (``Header`` and its ``Root``
    flattened): ``version`` ("Unicode"/"Ansi"), ``next_block``
    (``{"internal": bool, "index": int}``), ``next_page`` (int),
    ``file_eof_index``, ``amap_last_index``, ``amap_free_size``,
    ``pmap_free_size`` (ints), ``node_btree`` and ``block_btree``
    (``{"page": int, "index": int}``), ``amap_is_valid`` ("Valid2" etc.).
    """
    lines = _lines(text)
    if len(lines) != len(READ_HEADER_LABELS):
        # Name the first line that is wrong, not just the count.
        for i, label in enumerate(READ_HEADER_LABELS):
            _labelled(lines, i, label)
        raise ValueError(f"line {len(READ_HEADER_LABELS) + 1}: unexpected trailing line {lines[len(READ_HEADER_LABELS)]!r}")
    values = [_labelled(lines, i, label) for i, label in enumerate(READ_HEADER_LABELS)]

    version = values[0]
    if version not in _VERSIONS:
        raise ValueError(f"line 1: unknown file version {version!r}")
    amap = values[9]
    if not _AMAP_STATUS.match(amap):
        raise ValueError(f"line 10: unknown AMAP status {amap!r}")

    def at(i: int, parse: Callable[[str], Any]) -> Any:
        try:
            return parse(values[i])
        except ValueError as exc:
            raise ValueError(f"line {i + 1}: {exc}") from None

    return {
        "version": version,
        "next_block": at(1, parse_block_id),
        "next_page": at(2, parse_page_id),
        "file_eof_index": at(3, parse_byte_index),
        "amap_last_index": at(4, parse_byte_index),
        "amap_free_size": at(5, parse_byte_index),
        "pmap_free_size": at(6, parse_byte_index),
        "node_btree": at(7, parse_page_ref),
        "block_btree": at(8, parse_page_ref),
        "amap_is_valid": amap,
    }


# --- the other five: stubs describing the golden's shape --------------------


class _Cursor:
    """A line cursor that names the line it is on when a shape breaks."""

    __slots__ = ("i", "lines")

    def __init__(self, text: str) -> None:
        self.lines = _lines(text)
        self.i = 0

    def done(self) -> bool:
        return self.i >= len(self.lines)

    def peek(self) -> str:
        if self.done():
            raise ValueError(f"line {self.i + 1}: unexpected end of input ({len(self.lines)} line(s))")
        return self.lines[self.i].lstrip(" ")

    def take(self, pattern: re.Pattern[str], what: str) -> re.Match[str]:
        """Consume the next line, which must match `pattern` after its indent is stripped."""
        line = self.peek()
        m = pattern.match(line)
        if m is None:
            raise ValueError(f"line {self.i + 1}: expected {what}, got {self.lines[self.i]!r}")
        self.i += 1
        return m

    def next_is(self, pattern: re.Pattern[str]) -> bool:
        return not self.done() and pattern.match(self.peek()) is not None

    def value(self, parse: Callable[[str], Any], text: str) -> Any:
        """Apply a value parser to text from the line just consumed, naming that line on failure."""
        try:
            return parse(text)
        except ValueError as exc:
            raise ValueError(f"line {self.i}: {exc}") from None


# --- read_btrees (complete) ---------------------------------------------------
#
# The grammar is upstream's examples/read_btrees.rs. Indentation encodes only
# the distance from the root, which the counts on the header lines already
# fix, so every pattern matches after the indent is stripped and the values
# are compared, not the spacing. The node section descends into each node's
# data tree and sub-node tree (blocks: P03); the parser reads those into
# nested values so that P03 can diff them, and accepts a `Sub-Node Block:`
# line with no tree after it, which is what P02's dumper prints.

_INT = r"(\d+)"
_HEXV = r"0x([0-9A-Fa-f]+)"
_BLOCK_LEVEL = re.compile(rf"^Block BTree Level: {_INT}: Entries: {_INT}$")
_BLOCK_LEAF = re.compile(rf"^Block Page Entries: {_INT}$")
_NODE_LEVEL = re.compile(rf"^Node BTree Level: {_INT}: Entries: {_INT}$")
_NODE_LEAF = re.compile(rf"^Node Page Entries: {_INT}$")
_KEY_INT = re.compile(rf"^Key: {_INT}$")
_KEY_NODE = re.compile(r"^Key: (NodeId \{.*\})$")
_KEY_INVALID = re.compile(rf"^Invalid Key: {_HEXV}$")
_BLOCK_LINE = re.compile(r"^Block: (.+)$")
_SIZE_DEC = re.compile(rf"^Size: {_INT}$")
_SIZE_HEX = re.compile(rf"^Size: {_HEXV}$")
_REF_COUNT = re.compile(rf"^Ref-Count: {_INT}$")
_NODE_LINE = re.compile(r"^Node: (.+)$")
_DATA_BLOCK = re.compile(r"^Data Block: (.+)$")
_DATA_TREE = re.compile(rf"^Data Tree Level: {_INT}: Entries: {_INT}$")
_TOTAL_SIZE = re.compile(rf"^Total Size: {_HEXV}$")
_SUB_NODE = re.compile(r"^Sub-Node Block: (None|.+)$")
_SUB_NODE_LEAF = re.compile(rf"^Sub-Node Block Entries: {_INT}$")
_SUB_NODE_LEVEL = re.compile(rf"^Sub-Node BTree Level: {_INT}: Entries: {_INT}$")
_PAGE_REF_LINE = re.compile(r"^PageRef: (.+)$")
_PARENT = re.compile(r"^Parent Node: (None|Some\((.+)\))$")


def _parse_block_page(c: _Cursor) -> dict[str, Any]:
    if c.next_is(_BLOCK_LEAF):
        (count,) = c.take(_BLOCK_LEAF, "`Block Page Entries: N`").groups()
        entries = []
        for _ in range(int(count)):
            block = c.value(parse_block_ref, c.take(_BLOCK_LINE, "`Block: <BlockRef>`").group(1))
            size = int(c.take(_SIZE_DEC, "`Size: N`").group(1))
            ref_count = int(c.take(_REF_COUNT, "`Ref-Count: N`").group(1))
            entries.append({"block": block, "size": size, "ref_count": ref_count})
        return {"level": 0, "entries": entries}
    level, count = c.take(_BLOCK_LEVEL, "`Block BTree Level: L: Entries: N`").groups()
    children = []
    for _ in range(int(count)):
        key = int(c.take(_KEY_INT, "`Key: N`").group(1))
        children.append({"key": key, "page": _parse_block_page(c)})
    return {"level": int(level), "children": children}


def _parse_data_tree(c: _Cursor) -> dict[str, Any]:
    """`Data Block:` (+ optional `Size:`) or a `Data Tree Level:` block with its children."""
    if c.next_is(_DATA_TREE):
        level, count = c.take(_DATA_TREE, "`Data Tree Level: L: Entries: N`").groups()
        total = int(c.take(_TOTAL_SIZE, "`Total Size: 0x..`").group(1), 16)
        blocks = []
        for _ in range(int(count)):
            block = c.value(parse_block_id, c.take(_BLOCK_LINE, "`Block: <BlockId>`").group(1))
            blocks.append({"block": block, "tree": _parse_data_tree(c)})
        return {"level": int(level), "total_size": total, "blocks": blocks}
    block = c.value(parse_block_id, c.take(_DATA_BLOCK, "`Data Block: <BlockId>`").group(1))
    if c.next_is(_SIZE_HEX):
        return {"block": block, "size": int(c.take(_SIZE_HEX, "`Size: 0x..`").group(1), 16)}
    return {"block": block}


def _parse_sub_node_ref(c: _Cursor) -> dict[str, Any] | None:
    """`Sub-Node Block: None` -> None; `Sub-Node Block: <BlockId>` -> the id and the tree under it, if printed."""
    m = c.take(_SUB_NODE, "`Sub-Node Block: None|<BlockId>`")
    if m.group(1) == "None":
        return None
    block = c.value(parse_block_id, m.group(1))
    tree = _parse_sub_node_tree(c) if c.next_is(_SUB_NODE_LEAF) or c.next_is(_SUB_NODE_LEVEL) else None
    return {"block": block, "tree": tree}


def _parse_sub_node_tree(c: _Cursor) -> dict[str, Any]:
    if c.next_is(_SUB_NODE_LEVEL):
        level, count = c.take(_SUB_NODE_LEVEL, "`Sub-Node BTree Level: L: Entries: N`").groups()
        entries = []
        for _ in range(int(count)):
            node = c.value(parse_node_id, c.take(_NODE_LINE, "`Node: <NodeId>`").group(1))
            block = c.value(parse_block_id, c.take(_BLOCK_LINE, "`Block: <BlockId>`").group(1))
            entries.append({"node": node, "block": block, "tree": _parse_sub_node_tree(c)})
        return {"level": int(level), "entries": entries}
    (count,) = c.take(_SUB_NODE_LEAF, "`Sub-Node Block Entries: N`").groups()
    entries = []
    for _ in range(int(count)):
        node = c.value(parse_node_id, c.take(_NODE_LINE, "`Node: <NodeId>`").group(1))
        data = _parse_data_tree(c)
        ref = c.value(parse_block_ref, c.take(_PAGE_REF_LINE, "`PageRef: <BlockRef>`").group(1))
        entries.append({"node": node, "data": data, "ref": ref, "sub_node": _parse_sub_node_ref(c)})
    return {"level": 0, "entries": entries}


def _parse_node_page(c: _Cursor) -> dict[str, Any]:
    if c.next_is(_NODE_LEAF):
        (count,) = c.take(_NODE_LEAF, "`Node Page Entries: N`").groups()
        entries = []
        for _ in range(int(count)):
            node = c.value(parse_node_id, c.take(_NODE_LINE, "`Node: <NodeId>`").group(1))
            data = _parse_data_tree(c)
            sub_node = _parse_sub_node_ref(c)
            m = c.take(_PARENT, "`Parent Node: None|Some(<NodeId>)`")
            parent = None if m.group(1) == "None" else c.value(parse_node_id, m.group(2))
            entries.append({"node": node, "data": data, "sub_node": sub_node, "parent": parent})
        return {"level": 0, "entries": entries}
    level, count = c.take(_NODE_LEVEL, "`Node BTree Level: L: Entries: N`").groups()
    children: list[dict[str, Any]] = []
    for _ in range(int(count)):
        if c.next_is(_KEY_INVALID):
            # Upstream prints this and skips the subtree; pypst refuses such a store.
            key = int(c.take(_KEY_INVALID, "`Invalid Key: 0x..`").group(1), 16)
            children.append({"invalid_key": key, "page": None})
            continue
        key = c.value(parse_node_id, c.take(_KEY_NODE, "`Key: <NodeId>`").group(1))
        children.append({"key": key, "page": _parse_node_page(c)})
    return {"level": int(level), "children": children}


def parse_read_btrees(text: str) -> dict[str, Any]:
    """Upstream's ``read_btrees`` example, as nested values.

    ``{"block_btree": page, "node_btree": page}``. A page is
    ``{"level": L, "children": [{"key": K, "page": page}, …]}`` (``K`` an
    int for the block tree, a NodeId dict for the node tree; an
    ``{"invalid_key": int, "page": None}`` child where upstream printed
    ``Invalid Key``) or ``{"level": 0, "entries": [...]}``. A block entry is
    ``{"block": BlockRef, "size": int, "ref_count": int}``. A node entry is
    ``{"node": NodeId, "data": data, "sub_node": None | {"block": BlockId,
    "tree": subnode | None}, "parent": None | NodeId}``, where ``data`` is
    ``{"block": BlockId}`` (an empty node), ``{"block": BlockId, "size":
    int}`` (a leaf data block) or ``{"level": L, "total_size": int,
    "blocks": [{"block": BlockId, "tree": data}, …]}`` (an XBLOCK tree). A
    ``subnode`` is ``{"level": 0, "entries": [{"node", "data", "ref":
    BlockRef, "sub_node"}]}`` or ``{"level": L, "entries": [{"node",
    "block", "tree"}]}``. The two sections are separated by one blank line.
    """
    c = _Cursor(text)
    block_btree = _parse_block_page(c)
    if c.done() or c.lines[c.i] != "":
        raise ValueError(f"line {c.i + 1}: expected the blank line between the two trees")
    c.i += 1
    node_btree = _parse_node_page(c)
    if not c.done():
        raise ValueError(f"line {c.i + 1}: unexpected trailing line {c.lines[c.i]!r}")
    return {"block_btree": block_btree, "node_btree": node_btree}


# --- read_density_list (complete) ---------------------------------------------

READ_DENSITY_LIST_LABELS = (
    "Backfill Complete",
    "Current Page",
    "Density List Entries",
    "Page Type",
    "Page Signature",
    "Page CRC",
    "Block ID",
)
_DL_ENTRY = re.compile(r"^[A-Za-z]+\((\d+)\)$")
_DL_HEX = re.compile(r"^0x([0-9A-Fa-f]+)$")


def parse_read_density_list(text: str) -> dict[str, Any] | None:
    """Upstream's ``read_density_list`` example, as values; ``None`` for its ``Error:`` line.

    ``{"backfill_complete": bool, "current_page": int, "entries": [int, …]
    (the raw u32s), "page_type": str, "signature": int, "crc": int,
    "block_id": int}``. A store with no density list makes upstream print a
    single ``Error: …`` line (exit 0), which parses to ``None``; pypst's
    dumper refuses such a store instead (exit 1), so a test compares
    ``None`` with that refusal.
    """
    lines = _lines(text)
    if len(lines) == 1 and lines[0].startswith("Error: "):
        return None
    if len(lines) != len(READ_DENSITY_LIST_LABELS):
        for i, label in enumerate(READ_DENSITY_LIST_LABELS):
            _labelled(lines, i, label)
        raise ValueError(f"line {len(READ_DENSITY_LIST_LABELS) + 1}: unexpected trailing line {lines[7]!r}")
    values = [_labelled(lines, i, label) for i, label in enumerate(READ_DENSITY_LIST_LABELS)]
    if values[0] not in ("true", "false"):
        raise ValueError(f"line 1: not a bool: {values[0]!r}")
    if not values[1].isdigit():
        raise ValueError(f"line 2: not an int: {values[1]!r}")
    if not (values[2].startswith("[") and values[2].endswith("]")):
        raise ValueError(f"line 3: not a list: {values[2]!r}")
    entries = []
    inner = values[2][1:-1].strip()
    for item in inner.split(", ") if inner else []:
        m = _DL_ENTRY.match(item)
        if m is None:
            raise ValueError(f"line 3: not a density list entry: {item!r}")
        entries.append(int(m.group(1)))
    if not re.fullmatch(r"[A-Za-z]+", values[3]):
        raise ValueError(f"line 4: not a page type name: {values[3]!r}")
    hexes = []
    for i in (4, 5):
        m = _DL_HEX.match(values[i])
        if m is None:
            raise ValueError(f"line {i + 1}: not a hex value: {values[i]!r}")
        hexes.append(int(m.group(1), 16))
    try:
        block_id = parse_page_id(values[6])
    except ValueError as exc:
        raise ValueError(f"line 7: {exc}") from None
    return {
        "backfill_complete": values[0] == "true",
        "current_page": int(values[1]),
        "entries": entries,
        "page_type": values[3],
        "signature": hexes[0],
        "crc": hexes[1],
        "block_id": block_id,
    }


def parse_read_store_props(text: str) -> Any:
    raise NotImplementedError(
        "read_store_props (P07): `Display Name:`, then `IPM Subtree:`, `Deleted Items:`, `Finder:` each an "
        "`EntryId { record_key: XX-XX-.., node_id: <NodeId> }`; then repeated pairs of "
        "` Property ID: 0x...., Type: <PropType>` + `  Value: <Type>(<Debug value>)`. "
        "pstd-inline-cid stops after `IPM Subtree:` with exit 1."
    )


def parse_read_named_props(text: str) -> Any:
    raise NotImplementedError(
        "read_named_props (P07): repeated groups of `Named Property ID: 0x8xxx`, ` GUID Index: GuidIndex(n)|None`, "
        "optional ` Other: GuidValue { <guid> }` or ` PS_PUBLIC_STRINGS: GuidValue { <guid> }`, then either "
        "` Number: 0x........` or ` String[0x........]: \"<name>\"`. pstd-inline-cid: one group with GUID Index None."
    )


def parse_read_root_folder(text: str) -> Any:
    raise NotImplementedError(
        "read_root_folder (P08): repeated row blocks of `Row: 0x....` + `Version: 0x..`, each followed by "
        "` Column: Property ID: 0x...., Type: <PropType>` entries with an optional `  Record: Small(..)|Heap(HeapId(<NodeId>))` "
        "and a `  Value: None|<Type>(<Debug value>)`. pstd-inline-cid: empty text, exit 1."
    )


def parse_read_ipm_subtree(text: str) -> Any:
    raise NotImplementedError(
        "read_ipm_subtree (P08): same row-block shape as read_root_folder (`Row:`/`Version:` then ` Column:` "
        "with optional `  Record:` and a `  Value:`), for the IPM subtree's hierarchy table. "
        "pstd-inline-cid: empty text, exit 1."
    )


def parse_read_search_updates(text: str) -> Any:
    raise NotImplementedError(
        "read_search_updates (P09): `SearchManagementQueue Length: N` then N lines ` <i>: SearchUpdate { flags: n, "
        "data: None|Some(<Variant> { parent: <NodeId>, folder: <NodeId>, reserved1: 0, reserved2: 0 }) }`. "
        "pstd-inline-cid: empty text, exit 1."
    )


PARSERS: dict[str, Callable[[str], Any]] = {
    "read_header": parse_read_header,
    "read_btrees": parse_read_btrees,
    "read_density_list": parse_read_density_list,
    "read_store_props": parse_read_store_props,
    "read_named_props": parse_read_named_props,
    "read_root_folder": parse_read_root_folder,
    "read_ipm_subtree": parse_read_ipm_subtree,
    "read_search_updates": parse_read_search_updates,
}
