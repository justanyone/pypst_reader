"""Table Context (TC) — rows of properties: a column schema, a row matrix, and a BTH index from row id to row number.

Ported from: crates/pst/src/ltp/table_context.rs (the Unicode arm of
             `TableContextInfo`, `TableColumnDescriptor`, `TableRowData` and
             `TableContextInner::read` / `read_column`; the value decoders are
             P22's `pypst.ltp.prop_type`)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.3.4 Table Context, 2.3.4.1 TCINFO, 2.3.4.2 TCOLDESC,
             2.3.4.3 The Row Index (TCROWID), 2.3.4.4 The Row Matrix,
             2.3.4.4.1 Row Data Format

A TC is what a folder's hierarchy, contents and associated-contents tables,
a message's recipient table and an attachment table are: a heap
(`pypst.ltp.heap`) whose client signature is `bTypeTC` (0x7C), whose user
root is a **TCINFO** (not a BTHHEADER — a TC's heap has two trees in it),
and whose rows are fixed-width records in a **row matrix**.

**Three structures, and they are indexed differently.** The TCINFO names
them: `rgTCOLDESC` is the column schema (a property id, a type, and the
column's byte offset and width inside a row); `hidRowIndex` is a BTH
(`pypst.ltp.tree`) keyed by the 4-byte row id whose 4-byte value is the
row's ORDINAL in the matrix; `hnidRows` is an HNID for the matrix itself —
a heap item when it is small enough, otherwise a sub-node whose data tree
holds it. `rows()` yields the matrix in matrix order, which is what
upstream's `rows_matrix()` iterates and what `read_root_folder` /
`read_ipm_subtree` print; the row index is for `find_row`, and its order
(ascending row id) is NOT the matrix's.

**The row matrix is packed per block and rows never straddle one.**
[MS-PST] 2.3.4.4: each block of the matrix holds `floor(len / rgib[TCI_bm])`
rows and whatever is left over is padding. So the row count is the sum of
the per-block floors, never `total // width`, and this layer needs the
sub-node's data BLOCKS rather than its joined bytes — `HeapNode.get_hnid_blocks`,
added for it, is upstream's `data_tree.blocks(...)`.

**The cell existence bitmap is the trap.** Every row ends with
`ceil(cCols / 8)` bytes in which bit `iBit` of column `i` (most significant
bit first, [MS-PST] 2.3.4.4.1) says whether this row HAS that column. A
column present in the schema whose bit is clear is ABSENT from the row: its
bytes in the row are stale and mean nothing. `TableRow.cells` omits it —
absent is not `None`, and the two are told apart by `TableRow.records`
(`None` at that column's position) exactly as upstream's
`Vec<Option<TableRowColumnValue>>` does. The examples print `Value: None`
for it and no `Record:` line.

**Cell → value, exactly upstream's `TableRowData::columns` + `read_column`.**
A column's type decides where its value is. Boolean is one byte in the
1-byte-aligned region, Integer16 two in the 2-byte region, the 4- and
8-byte scalars are inline in the 4-byte region, and every variable-size
type (String8, Unicode, Guid, Binary, Object and all the multi-valued
forms) is a 4-byte HNID there — a heap id into this heap, or the NID of one
of the node's sub-nodes ([MS-PST] 2.3.4.4.1). Upstream reads a column of
type Integer32 at offset 0 or 4 from the row's `dwRowID` / `rgdwData[0]`
fields rather than from its `align_4byte` buffer (which starts at offset
8); those are the same bytes, and this port slices them from the row for
the same answer.

**Deliberate divergences from upstream**, each chosen to fail closed or to
keep a real store readable:

- `rgib[TCI_4b]` (the end of the 4-byte region) must be at least 8. Upstream
  validates only `% 4 == 0` and then reads `vec![0; end_4byte_values - 8]`,
  which underflows a `usize` for 0 or 4 — a panic in a debug build and a
  4 GB allocation in a release one. Every row begins with `dwRowID` and
  `rgdwData[0]`, so 8 is the format's own floor ([MS-PST] 2.3.4.4.1).
- A cell whose HNID is 0 on a variable-size type is `None` (no value), not
  a refusal. Upstream's `read_column` hands the 0 to `HeapId::index()`,
  which refuses index 0, so ONE such cell fails the whole table; the PC
  arm of the same convention (`dwValueHnid` 0 is `PropertyValue::Null`,
  [MS-PST] 2.3.3.3) is upstream's own reading, and a property that is not
  there is not corruption. No corpus store carries one, so no golden
  output changes; the dumper prints `Value: Null` where upstream would
  have exited.
- `PtypObject` columns are readable, because P22/P05 decode the type at all
  (upstream's `PropertyType::try_from` has no arm for it — P19's finding).
  Upstream's TCOLDESC validation lists `Object` among the 4-byte types, so
  the intent is there; the type simply cannot be parsed upstream.
- A row id that appears twice in the row index is `PstFormatError`
  (upstream's `collect` into a `BTreeMap` keeps the last silently; a BTH's
  keys are unique by construction, [MS-PST] 2.3.2).
- A row index entry pointing past the end of the matrix is `PstFormatError`
  from `find_row`; upstream indexes `self.rows[index]` and panics.
- Counts and allocations are bounded by `limits`: more rows than
  `limits.max_items` is `PstLimitError`, and the matrix's total size goes
  through `limits.max_allocation` before it is assembled. The row index
  BTH's own depth, page and record ceilings are P04's.

**Followed, not fixed.** A partial row at the end of a matrix block is
DROPPED, not refused — that is padding ([MS-PST] 2.3.4.4), and upstream's
`data.len() / end_existence_bitmap` floor is the specification's reading.
Every corpus store's matrix happens to divide exactly, so nothing here is
guesswork about which rows exist. The `hidIndex` field is read and kept
and never used (it is deprecated, [MS-PST] 2.3.4.1).

Nothing but `PstError` subclasses escapes for any input bytes: an unknown
`wPropType` in a column is `PstUnsupportedError` naming it, a sub-node an
HNID names that the node's tree does not hold is `PstNotFoundError`, a
ceiling is `PstLimitError`, and everything else about the bytes is
`PstFormatError`.
"""

from __future__ import annotations

import bisect
import struct
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import ClassVar

from pypst.errors import PstFormatError, PstNotFoundError, PstUnsupportedError
from pypst.limits import Limits, check_allocation, check_count
from pypst.ltp.heap import HeapId, HeapNode, HeapNodeId, HeapNodeType
from pypst.ltp.prop_type import PropType, PropValue, decode
from pypst.ltp.tree import HeapTree
from pypst.ndb.block import BlockReader, SubNodeLeafEntry
from pypst.ndb.ids import NodeId, _unpack
from pypst.ndb.page import NodeBTreeEntry

__all__ = [
    "LTP_ROW_ID_PROP_ID",
    "LTP_ROW_VERSION_PROP_ID",
    "ROW_INDEX_ENTRY_SIZE",
    "ROW_INDEX_KEY_SIZE",
    "TCINFO_FORMAT",
    "TCINFO_SIZE",
    "TCOLDESC_FORMAT",
    "TCOLDESC_SIZE",
    "CellKind",
    "CellRecord",
    "ColumnDescriptor",
    "TableContext",
    "TableContextInfo",
    "TableRow",
    "check_existence_bitmap",
    "existence_bitmap_size",
]

# [MS-PST] 2.3.4.3.1 TCROWID: the row index BTH is keyed by the u32 row id and
# its value is the u32 ordinal of the row in the matrix (a u16 for an ANSI
# store, which this port does not read — ADR-0003).
LTP_ROW_ID_PROP_ID = 0x67F2
LTP_ROW_VERSION_PROP_ID = 0x67F3
ROW_INDEX_KEY_SIZE = 4
ROW_INDEX_ENTRY_SIZE = 4

# [MS-PST] 2.3.4.1 TCINFO: bType, cCols, rgib[4], hidRowIndex, hnidRows, hidIndex.
TCINFO_FORMAT = "<BBHHHHIII"
TCINFO_SIZE = struct.calcsize(TCINFO_FORMAT)

# [MS-PST] 2.3.4.2 TCOLDESC: tag (wPropType, wPropId), ibData, cbData, iBit.
TCOLDESC_FORMAT = "<HHHBB"
TCOLDESC_SIZE = struct.calcsize(TCOLDESC_FORMAT)

# The rgib indices of [MS-PST] 2.3.4.1, by their specification names.
TCI_4b, TCI_2b, TCI_1b, TCI_bm = 0, 1, 2, 3

# Every row starts with dwRowID and rgdwData[0] ([MS-PST] 2.3.4.4.1).
ROW_HEADER_SIZE = 8

# cCols is a single byte, so this is the format's own ceiling (upstream checks it too).
MAX_COLUMNS = 0xFF

# The column types a TC may carry, by the shape of their cell — upstream's
# three `match` arms in `TableContextInfo::new`, which agree with
# [MS-PST] 2.3.4.2's cbData column.
_ONE_BYTE_TYPES = frozenset({PropType.BOOLEAN})
_TWO_BYTE_TYPES = frozenset({PropType.SHORT})
_FOUR_BYTE_TYPES = frozenset({PropType.LONG, PropType.FLOAT, PropType.ERROR})
_EIGHT_BYTE_TYPES = frozenset(
    {PropType.DOUBLE, PropType.CURRENCY, PropType.APPTIME, PropType.LONGLONG, PropType.SYSTIME}
)
# Variable-size (and the 16-byte Guid): the cell is a 4-byte HNID, not the value.
_HNID_TYPES = frozenset(
    {
        PropType.STRING8,
        PropType.UNICODE,
        PropType.GUID,
        PropType.BINARY,
        PropType.OBJECT,
        PropType.MV_SHORT,
        PropType.MV_LONG,
        PropType.MV_FLOAT,
        PropType.MV_DOUBLE,
        PropType.MV_CURRENCY,
        PropType.MV_APPTIME,
        PropType.MV_LONGLONG,
        PropType.MV_STRING8,
        PropType.MV_UNICODE,
        PropType.MV_SYSTIME,
        PropType.MV_GUID,
        PropType.MV_BINARY,
    }
)

# prop type -> the cbData a TCOLDESC must declare for it.
_COLUMN_WIDTHS: dict[PropType, int] = {
    **dict.fromkeys(_ONE_BYTE_TYPES, 1),
    **dict.fromkeys(_TWO_BYTE_TYPES, 2),
    **dict.fromkeys(_FOUR_BYTE_TYPES, 4),
    **dict.fromkeys(_EIGHT_BYTE_TYPES, 8),
    **dict.fromkeys(_HNID_TYPES, 4),
}


def existence_bitmap_size(column_count: int) -> int:
    """`ceil(column_count / 8)` — upstream's `existence_bitmap_size`, the rgbCEB width ([MS-PST] 2.3.4.4.1)."""
    return -(-column_count // 8)


def check_existence_bitmap(column: int, bitmap: bytes | memoryview) -> bool:
    """Whether column `column`'s bit is set in `bitmap` — the most significant bit of a byte is column 0, 8, 16, …

    `PstFormatError` when the bit is past the bitmap, which is upstream's
    `InvalidTableContextColumnCount`: a schema and a row that disagree
    about how many columns there are is not a row this reader guesses at.
    """
    if column >= len(bitmap) * 8:
        raise PstFormatError(f"existence bit {column} is past the row's {len(bitmap)}-byte bitmap")
    return bitmap[column // 8] & (1 << (7 - (column % 8))) != 0


@dataclass(frozen=True, slots=True)
class ColumnDescriptor:
    """One TCOLDESC ([MS-PST] 2.3.4.2) — upstream's `TableColumnDescriptor`."""

    prop_type: PropType
    prop_id: int
    offset: int
    size: int
    existence_bit: int

    SIZE: ClassVar[int] = TCOLDESC_SIZE

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> ColumnDescriptor:
        """One TCOLDESC at `offset`; an unknown `wPropType` is `PstUnsupportedError` naming the column and the type."""
        wire_type, prop_id, ib, cb, bit = _unpack(TCOLDESC_FORMAT, buf, offset, "TCOLDESC")
        try:
            prop_type = PropType.from_wire(wire_type)
        except PstUnsupportedError:
            raise PstUnsupportedError(f"column 0x{prop_id:04X}: property type 0x{wire_type:04X}") from None
        return cls(prop_type, prop_id, ib, cb, bit)

    def __str__(self) -> str:
        return f"Column 0x{self.prop_id:04X} ({self.prop_type.name}) at {self.offset}+{self.size}, bit {self.existence_bit}"


@dataclass(frozen=True, slots=True)
class TableContextInfo:
    """The TCINFO at a TC heap's user root ([MS-PST] 2.3.4.1) — upstream's `TableContextInfo`.

    `rows` is `None` for a table with no matrix at all (`hnidRows` == 0,
    upstream's `Option<NodeId>`); `deprecated_index` is `hidIndex`, read
    and never used.
    """

    end_4byte: int
    end_2byte: int
    end_1byte: int
    end_bitmap: int
    row_index: HeapId
    rows: HeapNodeId | None
    deprecated_index: int
    columns: tuple[ColumnDescriptor, ...]

    @property
    def row_width(self) -> int:
        """`rgib[TCI_bm]`: the bytes one row occupies in the matrix, bitmap included."""
        return self.end_bitmap

    @property
    def bitmap_size(self) -> int:
        return existence_bitmap_size(len(self.columns))

    @classmethod
    def unpack(cls, data: bytes | bytearray | memoryview) -> TableContextInfo:
        """The whole TCINFO item — header, then `cCols` TCOLDESCs — validated as upstream's `read` + `new`."""
        (
            btype,
            column_count,
            end_4byte,
            end_2byte,
            end_1byte,
            end_bitmap,
            row_index,
            rows,
            deprecated_index,
        ) = _unpack(TCINFO_FORMAT, data, 0, "TCINFO")
        signature = HeapNodeType.from_wire(btype)
        if signature is not HeapNodeType.TABLE:
            raise PstFormatError(f"TCINFO bType 0x{btype:02X} is not bTypeTC 0x{HeapNodeType.TABLE:02X}")
        columns = tuple(
            ColumnDescriptor.unpack_from(data, TCINFO_SIZE + i * TCOLDESC_SIZE) for i in range(column_count)
        )
        info = cls(
            end_4byte,
            end_2byte,
            end_1byte,
            end_bitmap,
            HeapId(row_index),
            HeapNodeId(rows) if rows else None,
            deprecated_index,
            columns,
        )
        info._validate()
        return info

    def _validate(self) -> None:
        """Upstream's `TableContextInfo::new`, check for check, plus the one divergence the docstring names."""
        if len(self.columns) > MAX_COLUMNS:
            raise PstFormatError(f"TCINFO has {len(self.columns)} columns, more than {MAX_COLUMNS}")
        if self.end_4byte % 4:
            raise PstFormatError(f"TCINFO rgib[TCI_4b] {self.end_4byte} is not a multiple of 4")
        if self.end_2byte % 2 or self.end_2byte < self.end_4byte:
            raise PstFormatError(f"TCINFO rgib[TCI_2b] {self.end_2byte} is odd or before rgib[TCI_4b] {self.end_4byte}")
        if self.end_1byte < self.end_2byte:
            raise PstFormatError(f"TCINFO rgib[TCI_1b] {self.end_1byte} is before rgib[TCI_2b] {self.end_2byte}")
        if self.end_bitmap < self.end_1byte or self.end_bitmap - self.end_1byte != self.bitmap_size:
            raise PstFormatError(
                f"TCINFO rgib[TCI_bm] {self.end_bitmap} leaves {self.end_bitmap - self.end_1byte} bitmap byte(s), "
                f"not the {self.bitmap_size} that {len(self.columns)} columns need"
            )
        if self.end_4byte < ROW_HEADER_SIZE:
            # Divergence (module docstring): upstream computes `end_4byte - 8`
            # as a usize and underflows. dwRowID and rgdwData[0] are always there.
            raise PstFormatError(
                f"TCINFO rgib[TCI_4b] {self.end_4byte} is inside the row header's {ROW_HEADER_SIZE} bytes"
            )
        for column in self.columns:
            self._validate_column(column)

    def _validate_column(self, column: ColumnDescriptor) -> None:
        prop_type, offset = column.prop_type, column.offset
        # The two reserved columns every TC carries, at the two fixed offsets.
        if prop_type is PropType.LONG and column.prop_id in (LTP_ROW_ID_PROP_ID, LTP_ROW_VERSION_PROP_ID):
            wanted = (0, 0) if column.prop_id == LTP_ROW_ID_PROP_ID else (4, 1)
            if (offset, column.existence_bit) != wanted:
                raise PstFormatError(
                    f"{column}: property 0x{column.prop_id:04X} must be at offset {wanted[0]} with bit {wanted[1]}"
                )
        width = _COLUMN_WIDTHS.get(prop_type)
        if width is None:
            # A type from_wire accepts that no TC column may have — PtypNull.
            raise PstFormatError(f"{column}: {prop_type.name} is not a table column type")
        if prop_type in _ONE_BYTE_TYPES:
            if not self.end_2byte <= offset < self.end_1byte:
                raise PstFormatError(f"{column}: a 1-byte cell is not in [{self.end_2byte}, {self.end_1byte})")
        elif prop_type in _TWO_BYTE_TYPES:
            if offset % 2 or offset < self.end_4byte or offset + 2 > self.end_2byte:
                raise PstFormatError(f"{column}: a 2-byte cell is not in [{self.end_4byte}, {self.end_2byte})")
        elif offset % 4 or offset + width > self.end_4byte:
            raise PstFormatError(f"{column}: a {width}-byte cell is not aligned inside [0, {self.end_4byte})")
        if column.size != width:
            raise PstFormatError(f"{column}: cbData {column.size} is not the {width} bytes {prop_type.name} takes")
        if column.existence_bit > len(self.columns):
            # Upstream's off-by-one `>` — a bit ON the boundary is caught per
            # row by `check_existence_bitmap`, which is where upstream catches it.
            raise PstFormatError(f"{column}: existence bit {column.existence_bit} is past the {len(self.columns)} columns")


class CellKind(Enum):
    """Where a cell's value is — upstream's `TableRowColumnValue` variants."""

    SMALL = "Small"
    HEAP = "Heap"
    NODE = "Node"


@dataclass(frozen=True, slots=True)
class CellRecord:
    """One present cell as it is on the wire — upstream's `TableRowColumnValue`.

    `SMALL` carries the cell's inline bytes (exactly the column's width);
    `HEAP` and `NODE` carry the 4-byte HNID, and the value is elsewhere.
    A `TableContext` turns one into a value with `read_cell`.
    """

    kind: CellKind
    raw: int = 0
    data: bytes = b""

    @property
    def hnid(self) -> HeapNodeId | None:
        """The HNID, or None for an inline cell."""
        return None if self.kind is CellKind.SMALL else HeapNodeId(self.raw)

    @property
    def heap(self) -> HeapId | None:
        return HeapId(self.raw) if self.kind is CellKind.HEAP else None

    @property
    def node(self) -> NodeId | None:
        return NodeId(self.raw) if self.kind is CellKind.NODE else None

    @property
    def is_null(self) -> bool:
        """An HNID of 0 — no value ([MS-PST] 2.3.4.4.1; the divergence in the module docstring)."""
        return self.kind is not CellKind.SMALL and self.raw == 0


@dataclass(frozen=True, slots=True)
class TableRow:
    """One row of a TC: its id, its version, its decoded cells and the records they came from.

    `cells` holds only the columns this row HAS — a column whose existence
    bit is clear is absent, not `None`. `records` is parallel to
    `TableContext.columns` with `None` in an absent column's place, which
    is upstream's `Vec<Option<TableRowColumnValue>>` and what the examples
    print `Value: None` for.
    """

    id: int
    unique: int
    cells: Mapping[int, PropValue]
    records: tuple[CellRecord | None, ...]

    def get(self, prop_id: int, default: PropValue = None) -> PropValue:
        return self.cells.get(prop_id, default)

    def __contains__(self, prop_id: object) -> bool:
        return prop_id in self.cells

    def __len__(self) -> int:
        return len(self.cells)


class TableContext:
    """The rows of one node — upstream's `UnicodeTableContext` plus its `read_column`.

    Built over a `HeapNode` whose client signature is `bTypeTC`;
    `from_node` is the constructor every caller wants. The TCINFO is read
    and validated at construction; the row index and the row matrix on
    first use, and then kept.
    """

    __slots__ = ("_codepage", "_counts", "_heap", "_index", "_info", "_limits", "_matrix", "_starts", "_tree")

    def __init__(self, heap: HeapNode, limits: Limits | None = None, *, codepage: str = "cp1252") -> None:
        if not isinstance(heap, HeapNode):
            raise TypeError(f"TableContext takes a HeapNode, not {type(heap).__name__}")
        if heap.client_signature is not HeapNodeType.TABLE:
            raise PstFormatError(
                f"heap client signature 0x{heap.client_signature:02X} is not bTypeTC 0x{HeapNodeType.TABLE:02X}"
            )
        self._heap = heap
        self._limits = heap.limits if limits is None else limits
        self._codepage = codepage
        self._info = TableContextInfo.unpack(heap.get(heap.user_root))
        self._tree = HeapTree(heap, self._info.row_index)
        if self._tree.key_size != ROW_INDEX_KEY_SIZE or self._tree.entry_size != ROW_INDEX_ENTRY_SIZE:
            raise PstFormatError(
                f"TC row index has {self._tree.key_size}-byte keys and {self._tree.entry_size}-byte entries, "
                f"not {ROW_INDEX_KEY_SIZE} and {ROW_INDEX_ENTRY_SIZE}"
            )
        self._index: Mapping[int, int] | None = None
        self._matrix: tuple[bytes, ...] | None = None
        self._counts: tuple[int, ...] = ()
        self._starts: tuple[int, ...] = ()

    @classmethod
    def from_node(
        cls,
        reader: BlockReader,
        entry: NodeBTreeEntry | SubNodeLeafEntry,
        limits: Limits | None = None,
        *,
        codepage: str = "cp1252",
    ) -> TableContext:
        """The TC of the node `entry` names, read through `reader` (a `SubNodeLeafEntry` for an attachment or recipient table)."""
        return cls(HeapNode.from_node(reader, entry, limits), limits, codepage=codepage)

    # --- structure ---------------------------------------------------------------

    @property
    def heap(self) -> HeapNode:
        return self._heap

    @property
    def info(self) -> TableContextInfo:
        return self._info

    @property
    def tree(self) -> HeapTree:
        """The row index BTH: row id → the row's ordinal in the matrix."""
        return self._tree

    @property
    def limits(self) -> Limits:
        return self._limits

    @property
    def codepage(self) -> str:
        return self._codepage

    @property
    def columns(self) -> tuple[ColumnDescriptor, ...]:
        """The column schema, in `rgTCOLDESC` order — the order the examples print a row's cells in."""
        return self._info.columns

    @property
    def row_index(self) -> Mapping[int, int]:
        """Every row id in the index BTH mapped to its ordinal in the matrix; read-only, parsed once."""
        if self._index is None:
            found: dict[int, int] = {}
            for key, value in self._tree:
                (row_id,) = _unpack("<I", key, 0, "TCROWID key")
                (index,) = _unpack("<I", value, 0, "TCROWID value")
                if row_id in found:
                    raise PstFormatError(f"row id 0x{row_id:08X} appears twice in the TC row index")
                found[row_id] = index
                # Redundant by design: `HeapTree` bounds the records it yields by
                # the same ceiling (P04), so this one can only fire if that
                # changes. It names the TC rather than the tree when it does.
                check_count(len(found), self._limits.max_items, "TC row index entries")
            self._index = MappingProxyType(found)
        return self._index

    @property
    def row_count(self) -> int:
        """The rows in the matrix — the sum of the per-block floors ([MS-PST] 2.3.4.4), not `total // width`."""
        self._read_matrix()
        return self._starts[-1]

    def __len__(self) -> int:
        return self.row_count

    # --- rows ---------------------------------------------------------------------

    def _read_matrix(self) -> None:
        """The matrix blocks, once: the heap item or the sub-node's data blocks, and the rows each holds."""
        if self._matrix is not None:
            return
        blocks: Sequence[bytes] = ()
        if self._info.rows is not None:
            blocks = self._heap.get_hnid_blocks(self._info.rows)
            check_allocation(sum(len(b) for b in blocks), self._limits.max_allocation, "TC row matrix")
        width = self._info.row_width
        counts = tuple(len(block) // width for block in blocks)
        starts = [0]
        for count in counts:
            starts.append(starts[-1] + count)
        check_count(starts[-1], self._limits.max_items, "TC rows")
        self._matrix = tuple(blocks)
        self._counts = counts
        self._starts = tuple(starts)

    def _row_bytes(self, index: int) -> memoryview:
        """The `row_width` bytes of row `index` in matrix order; `PstFormatError` past the last row."""
        self._read_matrix()
        assert self._matrix is not None
        if not 0 <= index < self._starts[-1]:
            raise PstFormatError(f"row index {index} is past the matrix's {self._starts[-1]} row(s)")
        block = bisect.bisect_right(self._starts, index) - 1
        offset = (index - self._starts[block]) * self._info.row_width
        return memoryview(self._matrix[block])[offset : offset + self._info.row_width]

    def row(self, index: int) -> TableRow:
        """Row `index` of the matrix (0-based, matrix order), decoded."""
        return self._read_row(self._row_bytes(index))

    def rows(self) -> Iterator[TableRow]:
        """Every row in matrix order — upstream's `rows_matrix()`, which is the order the examples print."""
        self._read_matrix()
        for index in range(self._starts[-1]):
            yield self._read_row(self._row_bytes(index))

    def __iter__(self) -> Iterator[TableRow]:
        return self.rows()

    def find_row(self, row_id: int) -> TableRow:
        """The row the index BTH maps `row_id` to; `PstNotFoundError` when the id is not in the index."""
        index = self.row_index.get(row_id)
        if index is None:
            raise PstNotFoundError(f"row id 0x{row_id:08X} is not in the TC row index")
        return self.row(index)

    # --- cells --------------------------------------------------------------------

    def _read_row(self, row: memoryview) -> TableRow:
        """One row's bytes → its id, its version, its records and its decoded cells ([MS-PST] 2.3.4.4.1)."""
        info = self._info
        row_id, unique = _unpack("<II", row, 0, "row header")
        bitmap = row[info.end_1byte : info.end_bitmap]
        records: list[CellRecord | None] = []
        cells: dict[int, PropValue] = {}
        for i, column in enumerate(info.columns):
            if not check_existence_bitmap(column.existence_bit, bitmap):
                records.append(None)
                continue
            record = self._cell_record(row, column, i)
            records.append(record)
            cells[column.prop_id] = self.read_cell(record, column.prop_type)
        return TableRow(row_id, unique, MappingProxyType(cells), tuple(records))

    def _cell_record(self, row: memoryview, column: ColumnDescriptor, position: int) -> CellRecord:
        """The wire form of one present cell — upstream's `TableRowData::columns` arms."""
        info = self._info
        offset, size = column.offset, column.size
        if column.prop_type in _HNID_TYPES:
            (raw,) = _unpack("<I", row, self._check_offset(column, position, 8, info.end_4byte), "cell HNID")
            hnid = HeapNodeId(raw)
            return CellRecord(CellKind.HEAP if hnid.is_heap else CellKind.NODE, raw)
        if column.prop_type in _ONE_BYTE_TYPES:
            start = self._check_offset(column, position, info.end_2byte, info.end_1byte)
        elif column.prop_type in _TWO_BYTE_TYPES:
            start = self._check_offset(column, position, info.end_4byte, info.end_2byte)
        elif column.prop_type is PropType.LONG and offset in (0, 4):
            # Upstream reads these from `dwRowID` / `rgdwData[0]`; the same bytes.
            start = offset
        else:
            start = self._check_offset(column, position, ROW_HEADER_SIZE, info.end_4byte)
        return CellRecord(CellKind.SMALL, data=bytes(row[start : start + size]))

    def _check_offset(self, column: ColumnDescriptor, position: int, low: int, high: int) -> int:
        """`column.offset`, once it is inside `[low, high)` with room for the whole cell — upstream's `read_*_offset`.

        Redundant by design, as it is upstream: `TableContextInfo._validate`
        has already refused every offset this could catch, and the row is
        exactly `row_width` bytes. Both checks are kept because they are the
        two places a future caller could reach the row bytes from.
        """
        if column.offset < low or column.offset + column.size > high:
            raise PstFormatError(f"column {position} ({column}) is not inside the row's [{low}, {high}) region")
        return column.offset

    def read_cell(self, record: CellRecord, prop_type: PropType) -> PropValue:
        """Upstream's `read_column`: the decoded value of one cell record.

        An inline cell decodes from its own bytes; a `HEAP` or `NODE`
        record's value is the whole heap item or sub-node data the HNID
        names, through `HeapNode.get_hnid`. An HNID of 0 is `None` (the
        divergence in the module docstring).
        """
        if not isinstance(record, CellRecord):
            raise TypeError(f"TableContext.read_cell takes a CellRecord, not {type(record).__name__}")
        if record.kind is CellKind.SMALL:
            return decode(prop_type, record.data, codepage=self._codepage, max_items=self._limits.max_mv_items)
        if record.raw == 0:
            return None
        data = self._heap.get_hnid(HeapNodeId(record.raw))
        return decode(prop_type, data, codepage=self._codepage, max_items=self._limits.max_mv_items)
