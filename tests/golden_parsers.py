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

``parse_read_header`` is complete. The other seven are stubs whose
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


# --- the other seven: stubs describing the golden's shape -------------------


def parse_read_btrees(text: str) -> Any:
    raise NotImplementedError(
        "read_btrees (P02): two sections, `Block BTree Level: N: Entries: M` then "
        "`Node BTree Level: N: Entries: M`, each holding M groups of ` Key: <int|NodeId>` + "
        "` Block Page Entries: K` / ` Node Page Entries: K`; a block entry is `  Block: <BlockRef>` "
        "with `   Size:` and `   Ref-Count:`; a node entry is `  Node: <NodeId>` with `   Data Block: <BlockId>`, "
        "`   Size: 0x..`, `   Sub-Node Block: None|Some(<BlockId>)`, `   Parent Node: None|Some(<NodeId>)`. "
        "ANSI stores: empty text, exit 101."
    )


def parse_read_density_list(text: str) -> Any:
    raise NotImplementedError(
        "read_density_list (P02): seven `Label: value` lines — Backfill Complete (bool), Current Page (int), "
        "Density List Entries ([] or a Debug list), Page Type, Page Signature (0x..), Page CRC (0x........), "
        "Block ID (<PageId>). A store with no DList prints one `Error: Custom { kind: InvalidData, "
        "error: InvalidPageType(0) }` line with exit 0."
    )


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
