"""Table contexts: refused when the TCINFO, a column or the row index lies; exact against the goldens when they do not.

Denial first, on synthetic TCs built from `tests/corrupt.py`'s heap, BTH and
TC builders: a client signature that is not `bTypeTC`, a TCINFO whose `bType`
is not 0x7C, a `cCols` the four `rgib` offsets cannot carry, rgib offsets that
are unaligned, not monotonic, or inside the row header, a column whose type
this port does not read, whose cell runs past its region, whose `cbData` is
not its type's width or whose existence bit is past the schema, a row index
BTH with the wrong key/entry widths, a duplicate row id, a row index entry
pointing past the matrix, a row id that is not in the index, an HNID past
`cAlloc` or naming an absent sub-node, a row count over `limits.max_items`
and a matrix over `limits.max_allocation` — each the right `PstError`
subclass, with `PstLimitError` kept apart from `PstFormatError`.

**The trap this row was warned about has its own tests.** A column present in
the schema whose existence bit is CLEAR is absent from the row, not `None`:
`test_a_sparse_column_is_absent_not_none` and the ones around it pin that
`cells` omits it, that `records` has `None` in its place, that the stale
bytes still in the row are never decoded, and that the examples print
`Value: None` for it.

Then the differential claim. `python -m pypst.debug tc <store> <nid>` is
compared to `read_root_folder`'s and `read_ipm_subtree`'s goldens line for
line, byte for byte, on every Unicode corpus store — sixteen tables over
eight stores, including the two where the ORACLE ITSELF exits 1
(pstd-inline-cid's only table context declares five existence-bitmap bytes
for five columns, where [MS-PST] 2.3.4.1 allows one, so upstream refuses it
and so does this port). The same goldens are compared again through
`tests/golden_parsers.parse_read_root_folder` / `parse_read_ipm_subtree`,
row for row, cell for cell and value for value, so that a formatting
accident cannot hide a typed one.

Private stores are STRUCTURE ONLY: row counts, column ids and column types.
No cell value from a private store is printed, logged or asserted on
(CLAUDE.md).
"""

from __future__ import annotations

import io
import re
import struct
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from pypst import debug
from pypst.errors import (
    PstFormatError,
    PstLimitError,
    PstNotFoundError,
    PstUnsupportedError,
)
from pypst.limits import DEFAULT_LIMITS, Limits
from pypst.ltp.heap import HeapId, HeapNode, HeapNodeId, HeapNodeType
from pypst.ltp.prop_type import PropType
from pypst.ltp.table_context import (
    LTP_ROW_ID_PROP_ID,
    LTP_ROW_VERSION_PROP_ID,
    ROW_INDEX_ENTRY_SIZE,
    ROW_INDEX_KEY_SIZE,
    TCINFO_SIZE,
    TCOLDESC_SIZE,
    CellKind,
    CellRecord,
    ColumnDescriptor,
    TableContext,
    TableContextInfo,
    check_existence_bitmap,
    existence_bitmap_size,
)
from pypst.ndb.block import BlockReader, SubNodeLeafEntry
from pypst.ndb.btree import BlockBTree, NodeBTree
from pypst.ndb.header import read_header
from pypst.ndb.ids import BlockId, NodeId, NodeIdType
from tests import corrupt
from tests.conftest import FIXTURES, REFERENCE, public_fixture_paths
from tests.golden_parsers import (
    parse_read_ipm_subtree,
    parse_read_root_folder,
    parse_read_store_props,
)

ALL_STORES = [FIXTURES / "Empty.pst", *public_fixture_paths()]
ANSI_STEMS = {"pstsdk-sample2", "pstsdk-test_ansi"}
UNICODE_STORES = [p for p in ALL_STORES if p.stem not in ANSI_STEMS]
UNICODE_IDS = [p.stem for p in UNICODE_STORES]

# The one corpus store whose table contexts UPSTREAM refuses: its root
# hierarchy table declares rgib[TCI_bm] - rgib[TCI_1b] = 5 bitmap bytes for 5
# columns, where [MS-PST] 2.3.4.1 (and upstream's `TableContextInfo::new`)
# allow ceil(5/8) = 1. Both example goldens are empty with exit 1.
REFUSED_TABLES = {"pstd-inline-cid"}

# NID_ROOT_FOLDER (0x122) is a normal folder; its hierarchy table is the same
# index with nidType NID_TYPE_HIERARCHY_TABLE ([MS-PST] 2.4.4.4).
NID_ROOT_HIERARCHY = NodeId(0x12D)


def hierarchy_nid(folder: NodeId) -> NodeId:
    return NodeId.from_parts(NodeIdType.HIERARCHY_TABLE, folder.index)


# --- synthetic table contexts ---------------------------------------------------------
#
# One heap block holding a whole TC: item 1 the TCINFO, item 2 the row index
# BTHHEADER, item 3 its leaf page, item 4 the row matrix, items 5.. the
# values that variable-size cells point at.

# (wPropType, wPropId, ibData, cbData, iBit) — one column of each shape a row
# can hold: the two reserved Integer32s, an inline Integer32, a Unicode HNID,
# an 8-byte Integer64, an Integer16 in the 2-byte region and a Boolean in the
# 1-byte region.
SCHEMA: list[tuple[int, int, int, int, int]] = [
    (0x0003, LTP_ROW_ID_PROP_ID, 0, 4, 0),
    (0x0003, LTP_ROW_VERSION_PROP_ID, 4, 4, 1),
    (0x0003, 0x3602, 8, 4, 2),
    (0x001F, 0x3001, 12, 4, 3),
    (0x0014, 0x0E33, 16, 8, 4),
    (0x0002, 0x3600, 24, 2, 5),
    (0x000B, 0x360A, 26, 1, 6),
]
RGIB = (24, 26, 27, 28)  # TCI_4b, TCI_2b, TCI_1b, TCI_bm
ROW_WIDTH = RGIB[3]
ALL_PRESENT = 0xFE  # bits 0..6 set, most significant bit first ([MS-PST] 2.3.4.4.1)

ROW_INDEX_HID = corrupt.hid(2)
ROW_INDEX_PAGE_HID = corrupt.hid(3)
MATRIX_HID = corrupt.hid(4)


def value_hnid(index: int) -> int:
    """The HNID of the `index`-th (0-based) item in `make_tc_bytes`'s `values`."""
    return corrupt.hid(5 + index)


def make_row(
    row_id: int,
    unique: int = 0,
    *,
    i32: int = 0,
    hnid: int = 0,
    i64: int = 0,
    i16: int = 0,
    boolean: int = 0,
    bits: int = ALL_PRESENT,
) -> bytes:
    """One row of `SCHEMA`'s matrix ([MS-PST] 2.3.4.4.1): the header, the three regions, the bitmap."""
    cells = struct.pack("<IIq", i32 & 0xFFFFFFFF, hnid, i64) + struct.pack("<h", i16) + bytes([boolean])
    return corrupt.tc_row(row_id, unique, cells, bytes([bits]))


def make_tc_bytes(
    rows: list[bytes],
    values: list[bytes] | None = None,
    *,
    schema: list[tuple[int, int, int, int, int]] | None = None,
    rgib: tuple[int, ...] = RGIB,
    client_sig: int = corrupt.CLIENT_SIG_TC,
    btype: int = corrupt.CLIENT_SIG_TC,
    column_count: int | None = None,
    row_index: int = ROW_INDEX_HID,
    matrix_hnid: int = MATRIX_HID,
    key_size: int = ROW_INDEX_KEY_SIZE,
    entry_size: int = ROW_INDEX_ENTRY_SIZE,
    index_entries: list[tuple[int, int]] | None = None,
    matrix: bytes | None = None,
) -> bytes:
    """A single-block heap holding one TC; every argument is a place a denial test lies."""
    columns = [corrupt.tcoldesc(*column) for column in (SCHEMA if schema is None else schema)]
    if index_entries is None:
        index_entries = [(struct.unpack_from("<I", row, 0)[0], i) for i, row in enumerate(rows)]
    page = corrupt.bth_leaf([corrupt.tcrowid(row_id, index) for row_id, index in index_entries])
    items = [
        corrupt.tcinfo(columns, rgib, row_index=row_index, rows=matrix_hnid, btype=btype, count=column_count),
        corrupt.bth_header(key_size, entry_size, 0, ROW_INDEX_PAGE_HID if index_entries else 0),
        page or b"\0",  # an empty BTH page would be a zero-length (freed) item
        matrix if matrix is not None else b"".join(rows),
        *(values or []),
    ]
    return corrupt.heap_node(items, client_sig=client_sig)


def make_tc(
    rows: list[bytes] | None = None,
    values: list[bytes] | None = None,
    *,
    limits: Limits | None = None,
    subnodes: dict[NodeId, SubNodeLeafEntry] | None = None,
    reader: object | None = None,
    **kwargs: object,
) -> TableContext:
    heap = HeapNode(
        [make_tc_bytes([] if rows is None else rows, values, **kwargs)],  # type: ignore[arg-type]
        subnodes=subnodes,
        reader=reader,  # type: ignore[arg-type]
        limits=limits or DEFAULT_LIMITS,
    )
    return TableContext(heap, limits)


def utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


# --- denial: the container is not a TC ------------------------------------------------


@pytest.mark.parametrize("client_sig", [t for t in HeapNodeType if t is not HeapNodeType.TABLE])
def test_a_heap_that_is_not_a_tc_is_refused(client_sig: HeapNodeType) -> None:
    with pytest.raises(PstFormatError, match="bTypeTC"):
        make_tc([make_row(1)], client_sig=int(client_sig))


def test_a_tc_takes_a_heap_node_not_bytes() -> None:
    with pytest.raises(TypeError):
        TableContext(make_tc_bytes([make_row(1)]))  # type: ignore[arg-type]


@pytest.mark.parametrize("btype", [0x00, 0xBC, 0xB5, 0xFF])
def test_a_tcinfo_whose_btype_is_not_bTypeTC_is_refused(btype: int) -> None:
    with pytest.raises(PstFormatError):
        make_tc([make_row(1)], btype=btype)


def test_a_truncated_tcinfo_is_refused() -> None:
    """The user root item is shorter than the 22-byte TCINFO header."""
    heap = HeapNode([corrupt.heap_node([b"\x7c\x00\x00"], client_sig=corrupt.CLIENT_SIG_TC)])
    with pytest.raises(PstFormatError, match="TCINFO"):
        TableContext(heap)


def test_a_tcinfo_whose_columns_run_past_the_item_is_refused() -> None:
    """cCols says there are more TCOLDESCs than the heap item holds."""
    with pytest.raises(PstFormatError, match="TCOLDESC"):
        make_tc([make_row(1)], column_count=len(SCHEMA) + 4)


# --- denial: the rgib offsets -----------------------------------------------------------


def test_ccols_inconsistent_with_the_bitmap_offsets_is_refused() -> None:
    """rgib[TCI_bm] - rgib[TCI_1b] must be exactly ceil(cCols / 8) ([MS-PST] 2.3.4.1)."""
    with pytest.raises(PstFormatError, match="bitmap byte"):
        make_tc([make_row(1)], rgib=(24, 26, 27, 29))
    with pytest.raises(PstFormatError, match="bitmap byte"):
        make_tc([make_row(1)], rgib=(24, 26, 27, 27))


@pytest.mark.parametrize(
    ("rgib", "match"),
    [
        ((25, 26, 27, 28), "multiple of 4"),
        ((24, 23, 27, 28), "odd or before"),
        ((24, 25, 27, 28), "odd or before"),
        ((24, 26, 25, 27), "before"),
    ],
)
def test_rgib_offsets_that_are_unaligned_or_not_monotonic_are_refused(rgib: tuple[int, ...], match: str) -> None:
    with pytest.raises(PstFormatError, match=match):
        make_tc([make_row(1)], rgib=rgib)


def test_a_four_byte_region_that_cannot_hold_the_row_id_column_is_refused_at_parse_time() -> None:
    """`rgib[TCI_4b] = 0` cannot even carry the row-id column (offset 0, width 4) — a structural, eager
    refusal (P06's column-offset check) that has nothing to do with row count.
    """
    schema = [(0x0003, LTP_ROW_ID_PROP_ID, 0, 4, 0)]
    with pytest.raises(PstFormatError, match="aligned inside"):
        make_tc([], schema=schema, rgib=(0, 0, 0, 1))


def test_a_four_byte_region_inside_the_row_header_is_refused_once_a_row_exists() -> None:
    """The documented divergence: upstream computes `end_4byte - 8` as a usize and underflows — but only
    when it actually reads a row (`TableRowData::read`). `rgib[TCI_4b] = 4` is `synth-basics.pst`'s own
    shape (P06b): too small for the 8-byte row header, but large enough for the lone row-id column, so the
    eager column-offset check does not catch it; only a non-empty matrix does, and only once read.
    """
    schema = [(0x0003, LTP_ROW_ID_PROP_ID, 0, 4, 0)]
    tc = make_tc([bytes(5)], schema=schema, rgib=(4, 4, 4, 5))
    with pytest.raises(PstFormatError, match="row header"):
        _ = tc.row_count


def test_a_four_byte_region_inside_the_row_header_is_accepted_while_the_matrix_is_empty() -> None:
    """`synth-basics.pst` (EMLtoPST, P06b): `rgib[TCI_4b] = 4` on an empty associated-contents table.

    Upstream's `rows_matrix()` never reads a row of an empty table, so it
    never underflows and prints `Associated Count: 0`; this port now agrees
    (the module docstring's divergence, narrowed to a non-empty matrix).
    """
    schema = [(0x0003, LTP_ROW_ID_PROP_ID, 0, 4, 0)]
    # `matrix_hnid=0`, exactly `synth-basics.pst`'s own `hnidRows`: no matrix
    # item at all (upstream's `Option<NodeId>` None), not a present-but-empty one.
    tc = make_tc([], schema=schema, rgib=(4, 4, 4, 5), matrix_hnid=0)
    assert tc.row_count == 0
    assert list(tc.rows()) == []


def test_a_nine_column_schema_needs_two_bitmap_bytes() -> None:
    """Nine columns need two bitmap bytes; a TCINFO that leaves one is refused before any row is read."""
    schema = [
        (0x0003, LTP_ROW_ID_PROP_ID, 0, 4, 0),
        (0x0003, LTP_ROW_VERSION_PROP_ID, 4, 4, 1),
        *[(0x0003, 0x3600 + i, 8 + 4 * i, 4, 2 + i) for i in range(7)],
    ]
    assert existence_bitmap_size(len(schema)) == 2
    with pytest.raises(PstFormatError, match="bitmap byte"):
        make_tc([], schema=schema, rgib=(36, 36, 36, 37))
    # ... and is accepted with two.
    tc = make_tc([], schema=schema, rgib=(36, 36, 36, 38))
    assert len(tc.columns) == 9


# --- denial: the column descriptors -------------------------------------------------------


@pytest.mark.parametrize("wire", [0x0000, 0x0009, 0x000C, 0x1234, 0xFFFF])
def test_an_unknown_column_type_is_refused_by_name(wire: int) -> None:
    schema = [(wire, 0x3001, 12, 4, 3), *SCHEMA[:3]]
    with pytest.raises(PstUnsupportedError, match=f"0x{wire:04X}"):
        make_tc([], schema=schema)


def test_a_ptypnull_column_is_refused() -> None:
    """PtypNull is a property type but never a column type — upstream's `InvalidTableColumnPropertyType`."""
    schema = [*SCHEMA, (0x0001, 0x3700, 20, 4, 7)]
    with pytest.raises(PstFormatError, match="NULL is not a table column type"):
        make_tc([], schema=schema, rgib=(24, 26, 27, 28))


@pytest.mark.parametrize(
    "column",
    [
        (0x0003, 0x3602, 24, 4, 2),  # a 4-byte cell past rgib[TCI_4b]
        (0x0003, 0x3602, 9, 4, 2),  # ... and one that is not 4-aligned
        (0x0014, 0x0E33, 20, 8, 4),  # an 8-byte cell that overruns the region
        (0x0002, 0x3600, 26, 2, 5),  # a 2-byte cell past rgib[TCI_2b]
        (0x0002, 0x3600, 25, 2, 5),  # ... and one that is not 2-aligned
        (0x000B, 0x360A, 27, 1, 6),  # a 1-byte cell past rgib[TCI_1b]
        (0x000B, 0x360A, 8, 1, 6),  # ... and one before rgib[TCI_2b]
        (0x001F, 0x3001, 22, 4, 3),  # an HNID cell that overruns the 4-byte region
    ],
)
def test_a_column_whose_cell_is_outside_its_region_is_refused(column: tuple[int, int, int, int, int]) -> None:
    schema = [c for c in SCHEMA if c[1] != column[1]] + [column]
    with pytest.raises(PstFormatError):
        make_tc([], schema=schema)


@pytest.mark.parametrize(
    "column",
    [
        (0x0003, 0x3602, 8, 8, 2),  # Integer32 in 8 bytes
        (0x0014, 0x0E33, 16, 4, 4),  # Integer64 in 4
        (0x001F, 0x3001, 12, 8, 3),  # a Unicode HNID in 8
        (0x000B, 0x360A, 26, 4, 6),  # Boolean in 4 (pstd-inline-cid writes this)
        (0x0002, 0x3600, 24, 1, 5),  # Integer16 in 1
    ],
)
def test_a_column_whose_cbdata_is_not_its_types_width_is_refused(column: tuple[int, int, int, int, int]) -> None:
    schema = [c for c in SCHEMA if c[1] != column[1]] + [column]
    with pytest.raises(PstFormatError):
        make_tc([], schema=schema)


def test_an_existence_bit_past_the_schema_is_refused() -> None:
    schema = [*SCHEMA[:-1], (0x000B, 0x360A, 26, 1, len(SCHEMA) + 1)]
    with pytest.raises(PstFormatError, match="existence bit"):
        make_tc([], schema=schema)


def test_an_existence_bit_on_the_boundary_is_refused_when_the_row_is_read() -> None:
    """Upstream's TCINFO check is `>` — a bit EQUAL to cCols passes it and is caught per row, as upstream catches it."""
    schema = [
        (0x0003, LTP_ROW_ID_PROP_ID, 0, 4, 0),
        (0x0003, LTP_ROW_VERSION_PROP_ID, 4, 4, 1),
        *[(0x0003, 0x3600 + i, 8 + 4 * i, 4, 2 + i) for i in range(5)],
        (0x0003, 0x3700, 28, 4, 7),  # bit 7 == cCols - 1 is fine ...
    ]
    tc = make_tc([], schema=schema, rgib=(32, 32, 32, 33))
    assert len(tc.columns) == 8
    boundary = [*schema[:-1], (0x0003, 0x3700, 28, 4, 8)]  # ... bit 8 is not, but only a row can tell
    tc = make_tc([bytes(33)], schema=boundary, rgib=(32, 32, 32, 33))
    with pytest.raises(PstFormatError, match="past the row"):
        list(tc.rows())


@pytest.mark.parametrize(
    ("prop_id", "offset", "bit"),
    [(LTP_ROW_ID_PROP_ID, 8, 0), (LTP_ROW_ID_PROP_ID, 0, 2), (LTP_ROW_VERSION_PROP_ID, 8, 1), (LTP_ROW_VERSION_PROP_ID, 4, 3)],
)
def test_the_two_reserved_columns_must_be_where_the_row_header_is(prop_id: int, offset: int, bit: int) -> None:
    """[MS-PST] 2.3.4.4.1: PidTagLtpRowId is the row's first dword and PidTagLtpRowVer its second."""
    schema = [c for c in SCHEMA if c[1] != prop_id] + [(0x0003, prop_id, offset, 4, bit)]
    with pytest.raises(PstFormatError, match="must be at offset"):
        make_tc([], schema=schema)


# --- denial: the row index ----------------------------------------------------------------


@pytest.mark.parametrize(("key_size", "entry_size"), [(2, 4), (4, 2), (2, 6), (8, 4), (4, 8), (16, 16)])
def test_a_row_index_bth_with_the_wrong_widths_is_refused(key_size: int, entry_size: int) -> None:
    with pytest.raises(PstFormatError, match="row index"):
        make_tc([make_row(1)], key_size=key_size, entry_size=entry_size)


def test_a_row_index_that_is_not_a_bth_is_refused() -> None:
    """hidRowIndex naming the TCINFO item itself: a BTHHEADER whose bType is 0x7C."""
    with pytest.raises(PstFormatError):
        make_tc([make_row(1)], row_index=corrupt.hid(1))


def test_a_null_hid_row_index_is_refused() -> None:
    with pytest.raises(PstFormatError):
        make_tc([make_row(1)], row_index=0)


def test_a_row_index_hid_past_the_heap_is_refused() -> None:
    with pytest.raises(PstFormatError):
        make_tc([make_row(1)], row_index=corrupt.hid(0x7FF))


def test_a_repeated_row_id_is_refused() -> None:
    """Upstream's `BTreeMap` keeps the last; a BTH's keys are unique by construction ([MS-PST] 2.3.2)."""
    tc = make_tc([make_row(1), make_row(2)], index_entries=[(7, 0), (7, 1)])
    with pytest.raises(PstFormatError, match="twice"):
        _ = tc.row_index


def test_more_row_index_entries_than_the_limit_is_a_limit_error() -> None:
    rows = [make_row(i + 1) for i in range(4)]
    tc = make_tc(rows, limits=Limits(max_items=3))
    with pytest.raises(PstLimitError):
        _ = tc.row_index


def test_a_row_id_that_is_not_in_the_index_is_not_found() -> None:
    tc = make_tc([make_row(1)])
    assert tc.find_row(1).id == 1
    with pytest.raises(PstNotFoundError, match="0x00000002"):
        tc.find_row(2)


def test_a_row_index_entry_past_the_matrix_is_refused() -> None:
    tc = make_tc([make_row(1)], index_entries=[(1, 0), (2, 9)])
    assert tc.row_count == 1
    with pytest.raises(PstFormatError, match="past the matrix"):
        tc.find_row(2)


# --- denial: the row matrix ---------------------------------------------------------------


def test_more_rows_than_the_limit_is_a_limit_error() -> None:
    rows = [make_row(i + 1) for i in range(4)]
    with pytest.raises(PstLimitError):
        _ = make_tc(rows, limits=Limits(max_items=3)).row_count


def test_a_matrix_bigger_than_the_allocation_limit_is_a_limit_error() -> None:
    rows = [make_row(i + 1) for i in range(4)]
    with pytest.raises(PstLimitError):
        _ = make_tc(rows, limits=Limits(max_allocation=ROW_WIDTH * 2)).row_count


def test_a_matrix_hnid_past_the_heap_is_refused() -> None:
    with pytest.raises(PstFormatError):
        _ = make_tc([make_row(1)], matrix_hnid=corrupt.hid(0x7FF)).row_count


def test_a_matrix_in_an_absent_sub_node_is_not_found() -> None:
    with pytest.raises(PstNotFoundError, match="sub-node"):
        _ = make_tc([make_row(1)], matrix_hnid=0x4000_0021).row_count


def test_a_row_past_the_end_of_the_matrix_is_refused() -> None:
    tc = make_tc([make_row(1)])
    with pytest.raises(PstFormatError, match="past the matrix"):
        tc.row(1)
    with pytest.raises(PstFormatError, match="past the matrix"):
        tc.row(-1)


def test_a_partial_row_at_the_end_of_a_block_is_padding_and_is_dropped() -> None:
    """Followed, not fixed: [MS-PST] 2.3.4.4 pads a matrix block, and upstream floors. Pinned so a "fix" is red."""
    matrix = make_row(1) + make_row(2) + bytes(ROW_WIDTH - 1)
    tc = make_tc([make_row(1), make_row(2)], matrix=matrix)
    assert tc.row_count == 2
    assert [row.id for row in tc.rows()] == [1, 2]


def test_a_table_with_no_matrix_at_all_has_no_rows() -> None:
    tc = make_tc([], matrix_hnid=0, index_entries=[])
    assert tc.row_count == 0
    assert list(tc.rows()) == []
    assert dict(tc.row_index) == {}
    assert tc.info.rows is None


# --- denial: the cells --------------------------------------------------------------------


def test_a_cell_hnid_past_the_heap_is_refused() -> None:
    tc = make_tc([make_row(1, hnid=corrupt.hid(0x7FF))])
    with pytest.raises(PstFormatError):
        list(tc.rows())


def test_a_cell_hnid_naming_an_absent_sub_node_is_not_found() -> None:
    tc = make_tc([make_row(1, hnid=0x4000_0021)])
    with pytest.raises(PstNotFoundError, match="sub-node"):
        list(tc.rows())


def test_an_odd_length_unicode_cell_is_refused() -> None:
    tc = make_tc([make_row(1, hnid=value_hnid(0))], [b"abc"])
    with pytest.raises(PstFormatError):
        list(tc.rows())


@pytest.mark.parametrize("raw", [0x02, 0xFF])
def test_a_boolean_cell_that_is_neither_zero_nor_one_is_refused(raw: int) -> None:
    tc = make_tc([make_row(1, boolean=raw)])
    with pytest.raises(PstFormatError):
        list(tc.rows())


def test_a_multi_value_cell_over_the_item_limit_is_a_limit_error() -> None:
    schema = [*SCHEMA[:3], (0x101F, 0x3001, 12, 4, 3), *SCHEMA[4:]]
    value = struct.pack("<I", 0xFFFF_FFFF)
    tc = make_tc([make_row(1, hnid=value_hnid(0))], [value], schema=schema)
    with pytest.raises(PstLimitError):
        list(tc.rows())


def test_read_cell_takes_a_cell_record() -> None:
    tc = make_tc([make_row(1)])
    with pytest.raises(TypeError):
        tc.read_cell(b"\0\0\0\0", PropType.LONG)  # type: ignore[arg-type]


# --- the existence bitmap: the trap this row was warned about -------------------------------


def test_a_sparse_column_is_absent_not_none() -> None:
    """A column in the schema whose bit is clear is ABSENT: not in `cells`, `None` in `records`."""
    # Bit 3 is PidTagDisplayName's; clear it while leaving stale bytes in the cell.
    bits = ALL_PRESENT & ~(1 << (7 - 3))
    tc = make_tc([make_row(1, hnid=value_hnid(0), bits=bits)], [utf16("Inbox")])
    (row,) = tc.rows()
    assert 0x3001 not in row.cells
    assert row.get(0x3001) is None
    assert row.records[3] is None
    # The other columns are still there, and the stale HNID was never followed.
    assert set(row.cells) == {0x67F2, 0x67F3, 0x3602, 0x0E33, 0x3600, 0x360A}
    assert len(row) == 6


def test_a_present_column_with_the_same_bytes_decodes_where_the_sparse_one_did_not() -> None:
    """The same row twice, one bit apart: the value is real only when the bit is set."""
    present = make_tc([make_row(1, hnid=value_hnid(0))], [utf16("Inbox")])
    absent = make_tc([make_row(1, hnid=value_hnid(0), bits=ALL_PRESENT & ~(1 << (7 - 3)))], [utf16("Inbox")])
    assert next(iter(present.rows())).cells[0x3001] == "Inbox"
    assert 0x3001 not in next(iter(absent.rows())).cells


def test_a_row_with_no_columns_at_all_is_legal() -> None:
    tc = make_tc([make_row(1, bits=0)])
    (row,) = tc.rows()
    assert row.id == 1
    assert dict(row.cells) == {}
    assert row.records == (None,) * len(SCHEMA)


def test_check_existence_bitmap_reads_the_most_significant_bit_first() -> None:
    bitmap = bytes([0b1000_0001, 0b0100_0000])
    assert [check_existence_bitmap(i, bitmap) for i in range(16)] == [
        True, False, False, False, False, False, False, True,
        False, True, False, False, False, False, False, False,
    ]  # fmt: skip
    with pytest.raises(PstFormatError, match="past the row"):
        check_existence_bitmap(16, bitmap)


@pytest.mark.parametrize(("count", "size"), [(0, 0), (1, 1), (7, 1), (8, 1), (9, 2), (16, 2), (17, 3), (255, 32)])
def test_existence_bitmap_size_is_ceil_over_eight(count: int, size: int) -> None:
    assert existence_bitmap_size(count) == size


# --- the happy path ------------------------------------------------------------------------


def test_every_shape_of_cell_decodes() -> None:
    row = make_row(0x8022, unique=0xE, i32=-3 & 0xFFFFFFFF, hnid=value_hnid(0), i64=1234567890123, i16=-7, boolean=1)
    tc = make_tc([row], [utf16("Top of Personal Folders")])
    (parsed,) = tc.rows()
    assert parsed.id == 0x8022
    assert parsed.unique == 0xE
    assert parsed.cells == {
        LTP_ROW_ID_PROP_ID: 0x8022,
        LTP_ROW_VERSION_PROP_ID: 0xE,
        0x3602: -3,
        0x3001: "Top of Personal Folders",
        0x0E33: 1234567890123,
        0x3600: -7,
        0x360A: True,
    }
    kinds = [None if r is None else r.kind for r in parsed.records]
    assert kinds == [CellKind.SMALL] * 3 + [CellKind.HEAP] + [CellKind.SMALL] * 3


def test_the_reserved_columns_read_the_rows_own_header() -> None:
    """Upstream reads Integer32 at offsets 0 and 4 from `dwRowID` / `rgdwData[0]`; the same bytes."""
    tc = make_tc([make_row(0xFFFF_FFFF, unique=0x8000_0000)])
    (row,) = tc.rows()
    assert row.id == 0xFFFF_FFFF
    assert row.unique == 0x8000_0000
    # The cells are the same dwords read as the signed Integer32s upstream prints.
    assert row.cells[LTP_ROW_ID_PROP_ID] == -1
    assert row.cells[LTP_ROW_VERSION_PROP_ID] == -(2**31)


def test_rows_are_yielded_in_matrix_order_not_row_id_order() -> None:
    """`rows()` is upstream's `rows_matrix()`; the row index's order (ascending id) is a different order."""
    rows = [make_row(0x8082), make_row(0x2223), make_row(0x8022)]
    tc = make_tc(rows)
    assert [row.id for row in tc.rows()] == [0x8082, 0x2223, 0x8022]
    assert sorted(tc.row_index) == [0x2223, 0x8022, 0x8082]
    assert [tc.find_row(i).id for i in (0x8082, 0x2223, 0x8022)] == [0x8082, 0x2223, 0x8022]
    assert [row.id for row in tc] == [0x8082, 0x2223, 0x8022]
    assert len(tc) == 3


def test_a_zero_cell_hnid_is_no_value() -> None:
    """The divergence: upstream hands the 0 to `HeapId::index()`, which refuses index 0 and fails the whole table."""
    tc = make_tc([make_row(1, hnid=0)])
    (row,) = tc.rows()
    assert row.cells[0x3001] is None
    record = row.records[3]
    assert record is not None and record.is_null and record.kind is CellKind.HEAP


def test_a_cell_in_a_sub_node_is_read_through_the_nodes_sub_node_tree() -> None:
    entry = SubNodeLeafEntry(NodeId(0x8021), BlockId.from_parts(False, 4), None)
    reader = _StubReader({BlockId.from_parts(False, 4): [utf16("Deleted Items")]})
    heap = HeapNode(
        [make_tc_bytes([make_row(1, hnid=0x8021)])],
        subnodes={NodeId(0x8021): entry},
        reader=reader,  # type: ignore[arg-type]
    )
    (row,) = TableContext(heap).rows()
    assert row.cells[0x3001] == "Deleted Items"
    record = row.records[3]
    assert record is not None and record.kind is CellKind.NODE and record.node == NodeId(0x8021)


def test_the_row_matrix_never_straddles_a_block_boundary() -> None:
    """[MS-PST] 2.3.4.4: each block holds floor(len / row width) rows and the rest is padding.

    The matrix lives in a sub-node here, which is the only way it can be
    more than one block; `_StubReader` stands in for the data tree so the
    per-block counting is testable without a synthetic store. The real
    multi-block path is exercised by javalibpst-dist-list, whose IPM
    hierarchy table keeps its matrix in a sub-node.
    """
    first = make_row(1) + make_row(2) + bytes(ROW_WIDTH - 3)  # 2 rows and padding
    second = make_row(3) + bytes(2)  # 1 row and padding
    block = BlockId.from_parts(False, 4)
    reader = _StubReader({block: [first, second]})
    heap = HeapNode(
        [make_tc_bytes([], matrix_hnid=0x8021, index_entries=[(1, 0), (2, 1), (3, 2)])],
        subnodes={NodeId(0x8021): SubNodeLeafEntry(NodeId(0x8021), block, None)},
        reader=reader,  # type: ignore[arg-type]
    )
    tc = TableContext(heap)
    assert tc.row_count == 3
    assert [row.id for row in tc.rows()] == [1, 2, 3]
    assert tc.find_row(3).id == 3


class _StubReader:
    """The one method `HeapNode.get_hnid_blocks` needs of a `BlockReader`, for the multi-block matrix test."""

    def __init__(self, blocks: dict[BlockId, list[bytes]]) -> None:
        self._blocks = blocks
        self.limits = DEFAULT_LIMITS

    def read_data_blocks(self, block: BlockId) -> list[bytes]:
        return self._blocks[block]

    def read_data(self, block: BlockId) -> bytes:
        return b"".join(self._blocks[block])


def test_the_tc_exposes_its_heap_tree_columns_limits_and_codepage() -> None:
    limits = Limits(max_items=1000)
    tc = make_tc([make_row(1)], limits=limits)
    assert isinstance(tc.heap, HeapNode)
    assert tc.tree.key_size == ROW_INDEX_KEY_SIZE and tc.tree.entry_size == ROW_INDEX_ENTRY_SIZE
    assert tc.limits is limits
    assert tc.codepage == "cp1252"
    assert [c.prop_id for c in tc.columns] == [c[1] for c in SCHEMA]
    assert tc.info.row_width == ROW_WIDTH
    assert tc.info.bitmap_size == 1
    assert tc.info.row_index == HeapId(ROW_INDEX_HID)
    assert tc.info.rows == HeapNodeId(MATRIX_HID)
    assert tc.info.deprecated_index == 0


def test_string8_uses_the_codepage_it_is_given() -> None:
    schema = [*SCHEMA[:3], (0x001E, 0x3001, 12, 4, 3), *SCHEMA[4:]]
    heap = HeapNode([make_tc_bytes([make_row(1, hnid=value_hnid(0))], [b"\x80"], schema=schema)])
    assert next(iter(TableContext(heap, codepage="cp1252").rows())).cells[0x3001] == "€"
    assert next(iter(TableContext(heap, codepage="latin-1").rows())).cells[0x3001] == ""


def test_column_descriptor_and_tcinfo_are_readable_structures() -> None:
    column = ColumnDescriptor.unpack_from(corrupt.tcoldesc(0x001F, 0x3001, 12, 4, 3))
    assert (column.prop_type, column.prop_id, column.offset, column.size, column.existence_bit) == (
        PropType.UNICODE,
        0x3001,
        12,
        4,
        3,
    )
    assert column.SIZE == TCOLDESC_SIZE == 8
    assert "0x3001" in str(column)
    info = TableContextInfo.unpack(
        corrupt.tcinfo([corrupt.tcoldesc(*c) for c in SCHEMA], RGIB, row_index=ROW_INDEX_HID, rows=MATRIX_HID)
    )
    assert TCINFO_SIZE == 22
    assert (info.end_4byte, info.end_2byte, info.end_1byte, info.end_bitmap) == RGIB
    assert len(info.columns) == len(SCHEMA)


def test_a_cell_record_names_where_its_value_is() -> None:
    small = CellRecord(CellKind.SMALL, data=b"\x01\x00\x00\x00")
    assert small.hnid is None and small.heap is None and small.node is None and not small.is_null
    heap = CellRecord(CellKind.HEAP, corrupt.hid(5))
    assert heap.heap == HeapId(corrupt.hid(5)) and heap.node is None and not heap.is_null
    node = CellRecord(CellKind.NODE, 0x8021)
    assert node.node == NodeId(0x8021) and node.heap is None and node.hnid == HeapNodeId(0x8021)
    assert CellRecord(CellKind.HEAP, 0).is_null


# --- opening real stores --------------------------------------------------------------------


@contextmanager
def opened(path: Path) -> Iterator[tuple[BlockReader, NodeBTree]]:
    with path.open("rb") as f:
        header = read_header(f)
        bbt = BlockBTree(f, header.root.block_btree, DEFAULT_LIMITS)
        nbt = NodeBTree(f, header.root.node_btree, DEFAULT_LIMITS)
        yield BlockReader(f, header, bbt, DEFAULT_LIMITS), nbt


@contextmanager
def store_tc(path: Path, nid: NodeId, *, codepage: str = "cp1252") -> Iterator[TableContext]:
    """One node's TC with the file still open: a sub-node matrix is read on demand, not up front."""
    with opened(path) as (reader, nbt):
        yield TableContext.from_node(reader, nbt.find(nid), DEFAULT_LIMITS, codepage=codepage)


def ipm_subtree_nid(store: Path) -> NodeId:
    """The IPM subtree folder's NID, from the `read_store_props` golden's entry id."""
    text = (Path(__file__).parent / "golden" / store.stem / "read_store_props.txt").read_text()
    ipm = parse_read_store_props(text)["ipm_subtree"]
    return NodeId.from_parts(NodeIdType.NORMAL_FOLDER, int(ipm["node_id"]["index"]))


def table_nids(store: Path) -> dict[str, NodeId]:
    """The two tables the oracle's examples print: the root folder's and the IPM subtree's hierarchy tables."""
    return {
        "read_root_folder": NID_ROOT_HIERARCHY,
        "read_ipm_subtree": hierarchy_nid(ipm_subtree_nid(store)),
    }


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_from_node_opens_both_hierarchy_tables_on_every_unicode_store(store: Path) -> None:
    refused = store.stem in REFUSED_TABLES
    with opened(store) as (reader, nbt):
        for name, nid in table_nids(store).items():
            entry = nbt.find(nid)
            if refused:
                with pytest.raises(PstFormatError, match="bitmap byte"):
                    TableContext.from_node(reader, entry)
                continue
            tc = TableContext.from_node(reader, entry, DEFAULT_LIMITS)
            assert tc.heap.client_signature is HeapNodeType.TABLE, f"{store.stem} {name}"
            assert len(tc.columns) > 0 and tc.row_count > 0, f"{store.stem} {name}"
            assert len(tc.row_index) == tc.row_count, f"{store.stem} {name}"
            # Every row decodes, and every row id in the index finds its row.
            by_index = sorted(tc.row_index.items(), key=lambda pair: pair[1])
            assert [row.id for row in tc.rows()] == [tc.find_row(row_id).id for row_id, _ in by_index]


def test_from_node_accepts_a_sub_node_leaf_entry() -> None:
    """A recipient or attachment table arrives as a `SubNodeLeafEntry`, not an NBT entry (P09)."""
    with opened(FIXTURES / "Empty.pst") as (reader, nbt):
        entry = nbt.find(NID_ROOT_HIERARCHY)
        direct = TableContext.from_node(reader, entry)
        as_leaf = TableContext.from_node(reader, SubNodeLeafEntry(entry.node, entry.data, entry.sub_node))
        assert [row.id for row in as_leaf.rows()] == [row.id for row in direct.rows()]


def test_a_corpus_store_keeps_its_row_matrix_in_a_sub_node() -> None:
    """The sub-node arm of the matrix is not hypothetical: javalibpst-dist-list's IPM hierarchy table uses it."""
    store = next(p for p in UNICODE_STORES if p.stem == "javalibpst-dist-list")
    with store_tc(store, hierarchy_nid(ipm_subtree_nid(store))) as tc:
        assert tc.info.rows is not None and not tc.info.rows.is_heap
        assert tc.row_count == 12


# --- differential: the dumper against read_root_folder / read_ipm_subtree ---------------------


def dump_tc_lines(store: Path, nid: NodeId) -> list[str]:
    out = io.StringIO()
    stdout, sys.stdout = sys.stdout, out
    try:
        debug.dump_tc(store, f"{nid.raw:X}")
    finally:
        sys.stdout = stdout
    return out.getvalue().splitlines()


@pytest.mark.parametrize("example", ["read_root_folder", "read_ipm_subtree"])
@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_dump_tc_reproduces_the_table_goldens_byte_for_byte(store: Path, example: str, golden, golden_exit) -> None:
    """The whole claim of this row: same bytes in, same characters out."""
    expected = golden(store, example).splitlines()
    nid = table_nids(store)[example]
    if store.stem in REFUSED_TABLES:
        # The oracle refuses this table too, and prints nothing before it does.
        assert golden_exit(store, example) == 1 and expected == []
        with pytest.raises(PstFormatError, match="bitmap byte"):
            dump_tc_lines(store, nid)
        return
    assert golden_exit(store, example) == 0
    assert dump_tc_lines(store, nid) == expected, f"{store.stem}: {example} differs"
    assert len(expected) >= 30, store.stem


@pytest.mark.parametrize("example", ["read_root_folder", "read_ipm_subtree"])
@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_table_rows_equal_the_golden_values(store: Path, example: str, golden, golden_exit) -> None:
    """The same goldens read as data, not text: a formatting accident cannot pass this one."""
    if store.stem in REFUSED_TABLES:
        pytest.skip("the oracle refuses this store's table contexts too")
    parse = parse_read_root_folder if example == "read_root_folder" else parse_read_ipm_subtree
    expected = parse(golden(store, example))
    assert golden_exit(store, example) == 0
    nid = table_nids(store)[example]
    compared = 0
    with store_tc(store, nid, codepage="latin-1") as tc:
        rows = list(tc.rows())
        assert len(rows) == len(expected), f"{store.stem} {example}: row count"
        for row, wanted in zip(rows, expected, strict=True):
            where = f"{store.stem} {example} row 0x{row.id:X}"
            assert row.id == wanted["id"], where
            assert row.unique == wanted["version"], where
            assert len(wanted["columns"]) == len(tc.columns), where
            for column, record, cell in zip(tc.columns, row.records, wanted["columns"], strict=True):
                assert column.prop_id == cell["id"], where
                assert column.prop_type.debug_name == cell["type"], where
                if cell["value"] is None:  # `Value: None` — the column is absent from this row
                    assert record is None and column.prop_id not in row.cells, where
                    assert cell["record"] is None, where
                    continue
                assert record is not None, where
                assert _record_kind(cell["record"]) == record.kind, where
                variant, value = cell["value"]
                assert variant == column.prop_type.debug_name, where
                assert row.cells[column.prop_id] == _golden_value(column.prop_type, value), where
                compared += 1
    assert compared >= 5, f"{store.stem} {example}: nothing compared"


def _record_kind(record: dict[str, object]) -> CellKind:
    return {"small": CellKind.SMALL, "heap": CellKind.HEAP, "node": CellKind.NODE}[str(record["kind"])]


def _golden_value(prop_type: PropType, parsed: object) -> object:
    """A `parse_value` payload in this port's decoded form (upstream prints a Time as its FILETIME ticks)."""
    if prop_type is PropType.SYSTIME:
        from pypst.ltp.prop_type import filetime_to_datetime

        assert isinstance(parsed, int)
        return filetime_to_datetime(parsed)
    return parsed


def test_at_least_one_corpus_table_has_a_sparse_column_and_one_has_every_column() -> None:
    """The goldens' `Value: None` lines are not a theory: a real hierarchy table leaves columns out of rows."""
    store = next(p for p in UNICODE_STORES if p.stem == "Empty")
    with store_tc(store, NID_ROOT_HIERARCHY) as tc:
        sparse = [row for row in tc.rows() if len(row.cells) < len(tc.columns)]
        assert sparse, "Empty.pst's root hierarchy table has a row with every column"
        assert any(record is None for record in sparse[0].records)
        assert all(prop_id in {c.prop_id for c in tc.columns} for prop_id in sparse[0].cells)


# --- the dumper's own entry point ------------------------------------------------------------


def test_tc_is_registered_and_takes_a_nid() -> None:
    assert debug.DUMPERS["tc"] is debug.dump_tc
    assert debug.main(["--list"]) == 0


@pytest.mark.parametrize("extra", [[], ["12D", "2"]])
def test_tc_needs_exactly_one_nid(extra: list[str]) -> None:
    with pytest.raises(SystemExit):
        debug.main(["tc", str(FIXTURES / "Empty.pst"), *extra])


@pytest.mark.parametrize("nid", ["zzz", "FFFFFF"])
def test_tc_refuses_a_bad_or_absent_nid(nid: str, capsys) -> None:
    assert debug.main(["tc", str(FIXTURES / "Empty.pst"), nid]) == 1
    assert capsys.readouterr().err.startswith("Error: ")


def test_tc_of_a_node_that_is_not_a_tc_exits_one(capsys) -> None:
    """NID 0x21 is the message store's PC: a refusal, printed and exit 1, not a traceback."""
    assert debug.main(["tc", str(FIXTURES / "Empty.pst"), "21"]) == 1
    assert "bTypeTC" in capsys.readouterr().err


def test_cell_lines_print_two_lines_for_an_absent_cell_and_three_for_a_present_one() -> None:
    column = ColumnDescriptor.unpack_from(corrupt.tcoldesc(0x001F, 0x3001, 12, 4, 3))
    assert debug.cell_lines(column, None, None) == [
        " Column: Property ID: 0x3001, Type: Unicode",
        "  Value: None",
    ]
    record = CellRecord(CellKind.HEAP, corrupt.hid(5))
    assert debug.cell_lines(column, record, "Inbox") == [
        " Column: Property ID: 0x3001, Type: Unicode",
        "  Record: Heap(HeapId(NodeId { HeapNode: 0x5 }))",
        '  Value: Unicode(UnicodeValue { "Inbox" })',
    ]


def test_format_cell_record_spells_each_variant_as_rust_does() -> None:
    assert debug.format_cell_record(PropType.LONG, CellRecord(CellKind.SMALL, data=b"\x03\x00\x00\x00"), 3) == "Small(Integer32(3))"
    assert debug.format_cell_record(PropType.BOOLEAN, CellRecord(CellKind.SMALL, data=b"\x00"), False) == "Small(Boolean(false))"
    assert debug.format_cell_record(PropType.BINARY, CellRecord(CellKind.HEAP, corrupt.hid(7)), b"") == (
        "Heap(HeapId(NodeId { HeapNode: 0x7 }))"
    )
    assert debug.format_cell_record(PropType.UNICODE, CellRecord(CellKind.NODE, 0x8021), "x") == (
        "Node(NodeId { Internal: 0x401 })"
    )


def test_the_dumper_reads_string8_the_way_upstream_does() -> None:
    """`DUMP_CODEPAGE` is latin-1, which is upstream's code-page-less widening of each byte."""
    assert debug.DUMP_CODEPAGE == "latin-1"


# --- private stores: STRUCTURE ONLY ----------------------------------------------------------


@pytest.mark.private
def test_private_store_tables_open_without_leaking_anything(private_stores: list[Path]) -> None:
    """Every table context in a real store opens and every cell decodes. Counts only — never a value."""
    if not private_stores:
        pytest.skip("no private stores")
    seen = 0
    for store in private_stores:
        with opened(store) as (reader, nbt):
            for entry in nbt:
                try:  # a real store carries node types [MS-PST] 2.2.2.1 does not name
                    node_type = entry.node.id_type
                except PstFormatError:
                    continue
                if node_type not in _TABLE_NODE_TYPES:
                    continue
                tc = TableContext.from_node(reader, entry, DEFAULT_LIMITS)
                rows = list(tc.rows())
                assert len(rows) == tc.row_count
                assert all(0 <= len(row.cells) <= len(tc.columns) for row in rows)
                seen += 1
    assert seen > 0, "no table context in any private store"


_TABLE_NODE_TYPES = frozenset(
    {
        NodeIdType.HIERARCHY_TABLE,
        NodeIdType.CONTENTS_TABLE,
        NodeIdType.ASSOC_CONTENTS_TABLE,
        NodeIdType.ATTACHMENT_TABLE,
        NodeIdType.RECIPIENT_TABLE,
    }
)

_PREBUILT = REFERENCE / "target" / "debug" / "examples"


@pytest.mark.private
@pytest.mark.oracle
def test_private_store_table_structure_matches_the_live_oracle(private_stores: list[Path]) -> None:
    """The oracle's own `read_ipm_subtree` over a real store: row ids, column ids and types only.

    Runs the PREBUILT example binary (never `cargo`, which would rebuild the
    world on a loaded box) and skips when it is not there. Nothing from the
    store is printed or asserted on but structure: the `Row:` ids, the
    ` Column:` ids and their type names, and which cells are absent.
    """
    if not private_stores:
        pytest.skip("no private stores")
    binary = _PREBUILT / "read_ipm_subtree"
    if not binary.exists():
        pytest.skip("reference/outlook-pst-rs/target/debug/examples/read_ipm_subtree is not built")
    checked = 0
    for store in private_stores:
        result = subprocess.run([str(binary), str(store)], capture_output=True, text=True, timeout=300, check=False)
        if result.returncode != 0:
            continue
        expected = parse_read_ipm_subtree(result.stdout)
        text = subprocess.run(
            [sys.executable, "-m", "pypst.debug", "pc", str(store), "21"],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        assert text.returncode == 0
        ipm_index = _ipm_index_from_dump(text.stdout)
        nid = hierarchy_nid(NodeId.from_parts(NodeIdType.NORMAL_FOLDER, ipm_index))
        with store_tc(store, nid) as tc:
            rows = list(tc.rows())
            assert [row.id for row in rows] == [row["id"] for row in expected]
            assert [row.unique for row in rows] == [row["version"] for row in expected]
            for row, wanted in zip(rows, expected, strict=True):
                assert [c.prop_id for c in tc.columns] == [c["id"] for c in wanted["columns"]]
                assert [c.prop_type.debug_name for c in tc.columns] == [c["type"] for c in wanted["columns"]]
                present = [c["value"] is not None for c in wanted["columns"]]
                assert [r is not None for r in row.records] == present
        checked += 1
    if not checked:
        pytest.skip("the oracle could not read any private store's IPM subtree")


_IPM_ENTRY_ID = re.compile(r"Property ID: 0x35E0.*?Value: Binary\(BinaryValue \{ ([0-9A-F-]+) \}\)", re.DOTALL)


def _ipm_index_from_dump(text: str) -> int:
    """The IPM subtree folder's node index from the store PC dump's PidTagIpmSubTreeEntryId — structure, not content."""
    match = _IPM_ENTRY_ID.search(text)
    assert match, "the store PC has no PidTagIpmSubTreeEntryId"
    entry_id = bytes.fromhex(match.group(1).replace("-", ""))
    (nid,) = struct.unpack_from("<I", entry_id, 20)
    return NodeId(nid).index
