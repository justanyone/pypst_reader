"""Property contexts: refused when the signature, the widths or a record lies; exact against the goldens when they do not.

Denial first, on synthetic PCs built from `tests/corrupt.py`'s heap and BTH
builders: a client signature that is not `bTypePC`, BTH key/record widths
that are not 2 and 6, an unknown `wPropType`, a repeated property id, a
record count over `limits.max_property_count`, an HNID past `cAlloc`, an
HNID naming a sub-node the node does not have, an HNID whose type bits sit
on an 8- or 16-byte scalar, a multi-value claiming four billion items, an
odd-length PtypUnicode value, a `PtypBoolean` whose low byte is 2 — each the
right `PstError` subclass, with `PstLimitError` kept apart from
`PstFormatError`. The four deliberate divergences from upstream (PtypNull
decodes, PtypObject decodes, type bits on a fixed HNID are refused, a
duplicate key is refused) are pinned by name so that "fixing" one back is a
red test.

Then the differential claim. `python -m pypst.debug pc <store> 21` is
compared to `read_store_props`'s golden line for line, byte for byte, on
every Unicode corpus store whose golden is complete (`pstd-inline-cid`'s is
not: the oracle exits 1 before printing any property, and the PC is only
shown to open). The same goldens are compared again through
`tests/golden_parsers.parse_read_store_props`, property for property and
value for value, so that a formatting accident cannot hide a typed one. The
name-to-id map's PC (NID 0x61) is checked value for value against
`read_named_props`: the entry stream, the GUID stream and the string stream
are decoded from the PC and the named properties reconstructed from them
must equal the oracle's list exactly. The root folder's and the IPM
subtree's PCs are opened and their properties decoded (their goldens are
table contexts — P06's oracle, not this row's).

Private stores are STRUCTURE ONLY, here and in the live-oracle test: property
ids, type codes and counts. No value from a private store is printed, logged
or asserted on (CLAUDE.md).
"""

from __future__ import annotations

import io
import struct
import subprocess
import sys
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
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
from pypst.ltp.heap import HeapNode, HeapNodeId, HeapNodeType
from pypst.ltp.prop_context import (
    PC_KEY_SIZE,
    PC_RECORD_SIZE,
    PropertyContext,
    PropertyRecord,
)
from pypst.ltp.prop_type import ObjectRef, PropType
from pypst.ndb.block import BlockReader, SubNodeLeafEntry
from pypst.ndb.btree import BlockBTree, NodeBTree
from pypst.ndb.header import read_header
from pypst.ndb.ids import NodeId, NodeIdType
from tests import corrupt
from tests.conftest import FIXTURES, REFERENCE, public_fixture_paths, run_oracle
from tests.golden_parsers import parse_read_named_props, parse_read_store_props

ALL_STORES = [FIXTURES / "Empty.pst", *public_fixture_paths()]
ANSI_STEMS = {"pstsdk-sample2", "pstsdk-test_ansi"}
UNICODE_STORES = [p for p in ALL_STORES if p.stem not in ANSI_STEMS]
UNICODE_IDS = [p.stem for p in UNICODE_STORES]

# The oracle's own failure, not ours: `read_store_props` prints the store's
# Deleted Items entry id before any property, and pstd-inline-cid has none,
# so the example exits 1 with two lines of output and no property list.
PARTIAL_STORE_PROPS = {"pstd-inline-cid"}

NID_MESSAGE_STORE = NodeId(0x21)
NID_NAME_TO_ID_MAP = NodeId(0x61)
NID_ROOT_FOLDER = NodeId(0x122)


# --- synthetic PCs ------------------------------------------------------------------


def make_pc_bytes(
    records: list[tuple[int, int, int]],
    values: list[bytes] | None = None,
    *,
    client_sig: int = corrupt.CLIENT_SIG_PC,
    key_size: int = PC_KEY_SIZE,
    entry_size: int = PC_RECORD_SIZE,
    leaf: bytes | None = None,
) -> bytes:
    """One heap block holding a PC: item 1 the BTHHEADER, item 2 the leaf page, items 3.. the values.

    `records` are `(prop_id, wPropType, dwValueHnid)` in key order; a value
    item's HNID is `corrupt.hid(3 + i)`. `leaf` replaces the leaf page's
    bytes for a lie about the record shape.
    """
    page = bth_leaf_bytes(records) if leaf is None else leaf
    items = [
        corrupt.bth_header(key_size, entry_size, 0, corrupt.hid(2)),
        page,
        *(values or []),
    ]
    return corrupt.heap_node(items, client_sig=client_sig)


def bth_leaf_bytes(records: list[tuple[int, int, int]]) -> bytes:
    return corrupt.bth_leaf([(struct.pack("<H", pid), corrupt.pc_record(t, h)) for pid, t, h in records])


def value_hnid(index: int) -> int:
    """The HNID of the `index`-th (0-based) item in `make_pc_bytes`'s `values`."""
    return corrupt.hid(3 + index)


def make_pc(
    records: list[tuple[int, int, int]],
    values: list[bytes] | None = None,
    *,
    limits: Limits | None = None,
    **kwargs: object,
) -> PropertyContext:
    heap = HeapNode([make_pc_bytes(records, values, **kwargs)], limits=limits or DEFAULT_LIMITS)  # type: ignore[arg-type]
    return PropertyContext(heap, limits)


def utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


# --- denial: the container is not a PC ------------------------------------------------


@pytest.mark.parametrize("client_sig", [t for t in HeapNodeType if t is not HeapNodeType.PROPERTIES], ids=lambda t: t.name)
def test_a_heap_that_is_not_a_pc_is_refused(client_sig: HeapNodeType) -> None:
    """Only `bTypePC` (0xBC) is a property context; a TC's heap is a perfectly good heap and not one."""
    with pytest.raises(PstFormatError, match="bTypePC"):
        make_pc([(0x3001, 0x0003, 7)], client_sig=int(client_sig))


def test_a_pc_takes_a_heap_node_not_bytes() -> None:
    with pytest.raises(TypeError, match="HeapNode"):
        PropertyContext(b"not a heap")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="HeapNode"):
        PropertyContext(None)  # type: ignore[arg-type]


@pytest.mark.parametrize(("key_size", "entry_size"), [(4, 6), (8, 6), (16, 6), (2, 4), (2, 8), (2, 1), (4, 4)])
def test_bth_widths_that_are_not_two_and_six_are_refused(key_size: int, entry_size: int) -> None:
    """[MS-PST] 2.3.3.3 fixes the PC BTH at a 2-byte key and a 6-byte record; anything else is not a PC."""
    records = [(0x3001, 0x0003, 7)]
    page = b"\x00" * ((key_size + entry_size) * 2)
    with pytest.raises(PstFormatError, match="PC BTH has"):
        make_pc(records, key_size=key_size, entry_size=entry_size, leaf=page)


def test_an_empty_pc_is_legal_and_empty() -> None:
    """An empty BTH (hidRoot 0) is a PC with no properties, not a refusal."""
    heap = HeapNode([corrupt.bth_heap([])])
    pc = PropertyContext(heap)
    assert len(pc) == 0
    assert dict(pc.records) == {}
    assert list(pc) == []
    assert pc.get(0x3001) is None
    assert 0x3001 not in pc


# --- denial: the records ---------------------------------------------------------------


@pytest.mark.parametrize("wire", [0x0000, 0x0009, 0x000C, 0x000E, 0x00FB, 0x1234, 0xFFFF])
def test_an_unknown_property_type_is_refused_by_name(wire: int) -> None:
    """Never raw bytes, never a guess: `PstUnsupportedError` naming both the property and the type."""
    with pytest.raises(PstUnsupportedError) as info:
        _ = make_pc([(0x3001, wire, 0)]).records
    assert "0x3001" in str(info.value) and f"0x{wire:04X}" in str(info.value)


def test_a_repeated_property_id_is_refused() -> None:
    """A BTH's keys are unique by construction ([MS-PST] 2.3.2); upstream's BTreeMap keeps the last silently."""
    with pytest.raises(PstFormatError, match="appears twice"):
        _ = make_pc([(0x3001, 0x0003, 1), (0x3001, 0x0003, 2)]).records


def test_more_records_than_the_limit_is_a_limit_error() -> None:
    records = [(pid, 0x0003, pid) for pid in range(1, 40)]
    tight = Limits(max_property_count=10)
    with pytest.raises(PstLimitError, match="PC records"):
        _ = make_pc(records, limits=tight).records
    # One under the ceiling is fine, and the class is distinguishable.
    assert len(make_pc(records[:10], limits=tight)) == 10


def test_a_truncated_record_is_refused() -> None:
    """A leaf page that is not a whole number of 8-byte records: the BTH refuses it, as a PstError."""
    short = bth_leaf_bytes([(0x3001, 0x001F, 0)])[:-1]
    with pytest.raises(PstFormatError):
        _ = make_pc([], leaf=short).records


def test_an_hnid_past_the_heap_is_refused() -> None:
    pc = make_pc([(0x3001, 0x001F, corrupt.hid(0x7FF))], [utf16("x")])
    with pytest.raises(PstFormatError):
        pc.get(0x3001)


def test_an_hnid_to_a_freed_item_is_refused() -> None:
    """A zero-length allocation is a freed item; upstream returns its empty slice, this port refuses."""
    block = corrupt.heap_block(
        [corrupt.bth_header(2, 6, 0, corrupt.hid(2)), bth_leaf_bytes([(0x3001, 0x001F, corrupt.hid(3))]), b""],
    )
    pc = PropertyContext(HeapNode([block]))
    with pytest.raises(PstFormatError):
        pc.get(0x3001)


def test_an_hnid_to_an_absent_sub_node_is_not_found() -> None:
    """Upstream's `PropertySubNodeValueNotFound`; here a `PstNotFoundError`, which is a `PstFormatError`."""
    pc = make_pc([(0x3001, 0x001F, 0x4000_0001)])
    with pytest.raises(PstNotFoundError):
        pc.get(0x3001)
    assert pc.records[0x3001].hnid.as_node == NodeId(0x4000_0001)


# The types whose record is ALWAYS a heap id, with the width of the value
# they name ([MS-PST] 2.3.3.3; PtypObject's 8 bytes are node id + size).
HEAP_ONLY_WIDTHS = [(0x0005, 8), (0x0006, 8), (0x0007, 8), (0x0014, 8), (0x0040, 8), (0x0048, 16), (0x000D, 8)]


@pytest.mark.parametrize(("wire", "width"), HEAP_ONLY_WIDTHS, ids=lambda v: f"0x{v:04X}" if v > 16 else str(v))
def test_type_bits_on_a_fixed_width_hnid_are_refused(wire: int, width: int) -> None:
    """DIVERGENCE: upstream builds a HeapId from the field regardless and reads the item at `raw >> 5`."""
    item = b"\x00" * width
    pc = make_pc([(0x3001, wire, value_hnid(0) | 0x01)], [item])
    with pytest.raises(PstFormatError, match="with type bits"):
        pc.get(0x3001)
    # The same HNID without them names the item upstream would have read anyway.
    clean = make_pc([(0x3001, wire, value_hnid(0))], [item])
    assert clean.records[0x3001].hnid.is_heap
    assert clean.get(0x3001) is not None
    assert "HeapId(NodeId" in str(pc.records[0x3001])


def test_a_multi_value_claiming_four_billion_items_is_a_limit_error() -> None:
    pc = make_pc([(0x3001, 0x101F, value_hnid(0))], [struct.pack("<I", 0xFFFF_FFFF)])
    with pytest.raises(PstLimitError):
        pc.get(0x3001)


def test_an_odd_length_unicode_value_is_refused() -> None:
    pc = make_pc([(0x3001, 0x001F, value_hnid(0))], [b"abc"])
    with pytest.raises(PstFormatError):
        pc.get(0x3001)


@pytest.mark.parametrize("raw", [0x02, 0xFF, 0x0000_FF02])
def test_a_boolean_that_is_neither_zero_nor_one_is_refused(raw: int) -> None:
    """P22 takes the spec's strict reading; upstream's PC arm is `value & 0xFF != 0`."""
    with pytest.raises(PstFormatError):
        make_pc([(0x6633, 0x000B, raw)]).get(0x6633)


def test_read_takes_a_property_record() -> None:
    pc = make_pc([(0x3001, 0x0003, 7)])
    with pytest.raises(TypeError, match="PropertyRecord"):
        pc.read((0x3001, PropType.LONG, 7))  # type: ignore[arg-type]


# --- PropertyRecord ---------------------------------------------------------------------


@pytest.mark.parametrize(("prop_id", "raw"), [(-1, 0), (0x10000, 0), (0, -1), (0, 2**32), (True, 0), (0, True)])
def test_property_record_refuses_values_that_are_not_its_width(prop_id: object, raw: object) -> None:
    with pytest.raises(PstFormatError):
        PropertyRecord(prop_id, PropType.LONG, raw)  # type: ignore[arg-type]


def test_property_record_refuses_a_type_that_is_not_a_prop_type() -> None:
    with pytest.raises(PstFormatError, match="not a PropType"):
        PropertyRecord(0x3001, 0x0003, 0)  # type: ignore[arg-type]


def test_property_record_unpack_refuses_short_buffers() -> None:
    with pytest.raises(PstFormatError):
        PropertyRecord.unpack(b"\x01", corrupt.pc_record(0x0003, 0))
    with pytest.raises(PstFormatError):
        PropertyRecord.unpack(b"\x01\x30", b"\x03\x00\x00")


def test_property_record_classifies_inline_and_hnid_records() -> None:
    inline = PropertyRecord.unpack(struct.pack("<H", 0x0E38), corrupt.pc_record(0x0003, 0x0018B2B3))
    assert inline.is_inline and inline.hnid is None and not inline.is_null
    assert inline.value_type is PropType.LONG
    assert str(inline) == "Small(0x0018B2B3)"

    heap = PropertyRecord.unpack(struct.pack("<H", 0x3001), corrupt.pc_record(0x001F, 0xA0))
    assert not heap.is_inline and heap.hnid == HeapNodeId(0xA0) and not heap.is_null
    assert str(heap) == "HeapId(NodeId { HeapNode: 0x5 })"

    node = PropertyRecord.unpack(struct.pack("<H", 0x0003), corrupt.pc_record(0x0102, 0x8025))
    assert node.hnid.as_node == NodeId(0x8025)
    assert str(node) == str(NodeId(0x8025))

    null = PropertyRecord.unpack(struct.pack("<H", 0x67FF), corrupt.pc_record(0x001F, 0))
    assert null.is_null and null.value_type is PropType.NULL and null.prop_type is PropType.UNICODE
    assert str(null) == "HeapId(NodeId { HeapNode: 0x0 })"


@pytest.mark.parametrize(
    ("wire", "raw", "expected"),
    [
        (0x0002, 0xFFFF_FFFF, -1),  # Integer16: masked to 0xFFFF, then signed
        (0x0002, 0x0000_7FFF, 0x7FFF),
        (0x0003, 0xFFFF_FFFF, -1),  # Integer32: the whole field, signed
        (0x000A, 0x8007_0057, -0x7FF8_FFA9),  # ErrorCode, signed i32 as upstream
        (0x000B, 0x0000_FF01, True),  # Boolean: only the low byte is read
        (0x000B, 0x0000_FF00, False),
        (0x0004, 0x3FC0_0000, 1.5),  # Floating32 from the raw bits
    ],
)
def test_inline_values_are_masked_to_their_width_as_upstream_masks_them(wire: int, raw: int, expected: object) -> None:
    value = make_pc([(0x3001, wire, raw)]).get(0x3001)
    assert value == expected and type(value) is type(expected)


# --- the four deliberate divergences ----------------------------------------------------


def test_ptyp_null_decodes_to_none_instead_of_failing_the_whole_store() -> None:
    """DIVERGENCE: upstream reads PtypNull as `Small(0)`, which `small_value` has no arm for."""
    pc = make_pc([(0x0001, 0x0001, 0x1234_5678)])
    assert pc.get(0x0001) is None
    assert pc.records[0x0001].is_inline and pc.records[0x0001].value_type is PropType.NULL
    assert str(pc.records[0x0001]) == "Small(0x00000000)"


def test_ptyp_object_decodes_where_upstream_cannot_read_it_at_all() -> None:
    """DIVERGENCE: `PropertyType::try_from` has no PtypObject arm at the pin (P19; todo/T03 § P09)."""
    pc = make_pc([(0x3701, 0x000D, value_hnid(0))], [struct.pack("<II", 0x8025, 0x1234)])
    value = pc.get(0x3701)
    assert value == ObjectRef(NodeId(0x8025), 0x1234)
    assert value.node.id_type is NodeIdType.ATTACHMENT


def test_a_zero_hnid_is_null_and_an_absent_property_is_also_none() -> None:
    """`get` cannot tell them apart, as upstream's `Option<&PropertyValue>` cannot; `records` can."""
    pc = make_pc([(0x67FF, 0x001F, 0)])
    assert pc.get(0x67FF) is None
    assert pc.get(0x3001) is None
    assert 0x67FF in pc and 0x3001 not in pc
    assert pc.records[0x67FF].prop_type is PropType.UNICODE
    assert pc.records[0x67FF].value_type is PropType.NULL


# --- the good path -----------------------------------------------------------------------


def test_every_shape_of_value_decodes() -> None:
    guid = uuid.UUID("00062002-0000-0000-c000-000000000046")
    pc = make_pc(
        [
            (0x0002, 0x0002, 0xFFFF_FFFE),
            (0x0003, 0x0003, 7),
            (0x0004, 0x000B, 1),
            (0x0005, 0x0014, value_hnid(0)),
            (0x0006, 0x0040, value_hnid(1)),
            (0x0007, 0x0048, value_hnid(2)),
            (0x0008, 0x001F, value_hnid(3)),
            (0x0009, 0x001E, value_hnid(4)),
            (0x000A, 0x0102, value_hnid(5)),
            (0x000B, 0x1003, value_hnid(6)),
        ],
        [
            struct.pack("<q", -5),
            struct.pack("<q", 116444736000000000),
            guid.bytes_le,
            utf16("IPF.Note"),
            b"Search Root",
            b"\x01\x02\x03",
            struct.pack("<III", 1, 2, 3),
        ],
    )
    assert dict(pc) == {
        0x0002: -2,
        0x0003: 7,
        0x0004: True,
        0x0005: -5,
        0x0006: datetime(1970, 1, 1, tzinfo=UTC),
        0x0007: guid,
        0x0008: "IPF.Note",
        0x0009: "Search Root",
        0x000A: b"\x01\x02\x03",
        0x000B: (1, 2, 3),
    }
    assert len(pc) == 10


def test_records_are_sorted_read_only_and_parsed_once() -> None:
    pc = make_pc([(0x6633, 0x000B, 1), (0x0E38, 0x0003, 4), (0x3001, 0x0003, 9)])
    assert list(pc.records) == [0x0E38, 0x3001, 0x6633]
    assert [pid for pid, _ in pc] == [0x0E38, 0x3001, 0x6633]
    assert pc.records is pc.records, "the record map is parsed once and kept"
    with pytest.raises(TypeError):
        pc.records[0x1234] = None  # type: ignore[index]


def test_string8_uses_the_codepage_it_is_given() -> None:
    """Upstream has no code page at all (a byte becomes U+00XX); `latin-1` reproduces that exactly."""
    records = [(0x3001, 0x001E, value_hnid(0))]
    assert make_pc(records, [b"caf\xe9"]).get(0x3001) == "café"
    heap = HeapNode([make_pc_bytes(records, [b"caf\xe9"])])
    assert PropertyContext(heap, codepage="latin-1").get(0x3001) == "café"
    assert PropertyContext(heap, codepage="cp437").get(0x3001) == b"caf\xe9".decode("cp437")
    with pytest.raises(PstUnsupportedError):
        PropertyContext(heap, codepage="not-a-codepage").get(0x3001)


def test_the_pc_exposes_its_heap_tree_limits_and_codepage() -> None:
    limits = Limits(max_property_count=99)
    heap = HeapNode([make_pc_bytes([(0x3001, 0x0003, 1)])], limits=limits)
    pc = PropertyContext(heap, limits)
    assert pc.heap is heap and pc.limits is limits and pc.codepage == "cp1252"
    assert pc.tree.key_size == PC_KEY_SIZE and pc.tree.entry_size == PC_RECORD_SIZE
    assert pc.tree.heap is heap
    # With no explicit limits the heap's own are used.
    assert PropertyContext(heap).limits is limits


# --- opening real stores -------------------------------------------------------------------


@contextmanager
def opened(path: Path) -> Iterator[tuple[BlockReader, NodeBTree]]:
    with path.open("rb") as f:
        header = read_header(f)
        bbt = BlockBTree(f, header.root.block_btree, DEFAULT_LIMITS)
        nbt = NodeBTree(f, header.root.node_btree, DEFAULT_LIMITS)
        yield BlockReader(f, header, bbt, DEFAULT_LIMITS), nbt


@contextmanager
def store_pc(path: Path, nid: NodeId = NID_MESSAGE_STORE, *, codepage: str = "cp1252") -> Iterator[PropertyContext]:
    """The PC of one node, with the file still open: a sub-node value is read on demand, not up front."""
    with opened(path) as (reader, nbt):
        yield PropertyContext.from_node(reader, nbt.find(nid), DEFAULT_LIMITS, codepage=codepage)


def test_from_node_accepts_a_sub_node_leaf_entry() -> None:
    """An attachment's or an embedded message's PC arrives as a `SubNodeLeafEntry`, not an NBT entry."""
    with opened(FIXTURES / "Empty.pst") as (reader, nbt):
        entry = nbt.find(NID_MESSAGE_STORE)
        direct = PropertyContext.from_node(reader, entry)
        as_leaf = PropertyContext.from_node(reader, SubNodeLeafEntry(entry.node, entry.data, entry.sub_node))
        assert dict(as_leaf.records) == dict(direct.records)
        assert len(direct) > 0


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_the_four_well_known_pcs_open_on_every_unicode_store(store: Path) -> None:
    """The message store, the name-to-id map, the root folder and the IPM subtree all keep their properties in a PC."""
    text = (Path(__file__).parent / "golden" / store.stem / "read_store_props.txt").read_text()
    ipm = parse_read_store_props(text)["ipm_subtree"]
    ipm_nid = NodeId.from_parts(NodeIdType.NORMAL_FOLDER, int(ipm["node_id"]["index"]))
    with opened(store) as (reader, nbt):
        for nid in (NID_MESSAGE_STORE, NID_NAME_TO_ID_MAP, NID_ROOT_FOLDER, ipm_nid):
            pc = PropertyContext.from_node(reader, nbt.find(nid), DEFAULT_LIMITS)
            assert pc.heap.client_signature is HeapNodeType.PROPERTIES, f"{store.stem} {nid}"
            assert len(pc) > 0, f"{store.stem} {nid}"
            # Every value decodes; nothing escapes as anything but a PstError.
            assert len(list(pc)) == len(pc)


# --- differential: the dumper against read_store_props ---------------------------------------


def golden_property_lines(text: str) -> list[str]:
    """The ` Property ID:` / `  Value:` lines of a `read_store_props` golden — the part that is P05's."""
    header = (" Property ID: ", "  Value: ")
    return [line for line in text.splitlines() if line.startswith(header)]


def dump_pc_lines(store: Path, nid: str) -> list[str]:
    out = io.StringIO()
    stdout, sys.stdout = sys.stdout, out
    try:
        debug.dump_pc(store, nid)
    finally:
        sys.stdout = stdout
    return out.getvalue().splitlines()


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_dump_pc_reproduces_read_store_props_byte_for_byte(store: Path, golden, golden_exit) -> None:
    """The whole claim of this row: same bytes in, same characters out."""
    expected = golden_property_lines(golden(store, "read_store_props"))
    ours = [line for line in dump_pc_lines(store, "21") if not line.startswith("  Record: ")]
    if store.stem in PARTIAL_STORE_PROPS:
        assert golden_exit(store, "read_store_props") == 1
        assert expected == [] and len(ours) >= 2, "the oracle failed early; the PC still opened"
        return
    assert golden_exit(store, "read_store_props") == 0
    assert ours == expected, f"{store.stem}: pc differs from read_store_props"
    assert len(expected) >= 8, store.stem


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_store_pc_values_equal_the_golden_values(store: Path, golden, golden_exit) -> None:
    """The same goldens read as data, not text: a formatting accident cannot pass this one."""
    if store.stem in PARTIAL_STORE_PROPS:
        pytest.skip("the oracle exits 1 before printing any property")
    assert golden_exit(store, "read_store_props") == 0
    expected = parse_read_store_props(golden(store, "read_store_props"))
    with store_pc(store, codepage="latin-1") as pc:
        assert [g["id"] for g in expected["properties"]] == list(pc.records), store.stem
        compared = 0
        for group in expected["properties"]:
            record = pc.records[group["id"]]
            where = f"{store.stem} 0x{group['id']:04X}"
            assert record.value_type.debug_name == group["type"], where
            variant, wanted = group["value"]
            assert variant == record.value_type.debug_name, where
            assert pc.read(record) == golden_value(record.value_type, wanted), where
            compared += 1
        assert compared == len(pc) >= 8, store.stem
        assert pc.get(0x3001) == expected["display_name"], f"{store.stem}: PR_DISPLAY_NAME"


def golden_value(prop_type: PropType, parsed: object) -> object:
    """A `parse_value` payload in this port's decoded form (upstream prints a Time as its FILETIME ticks)."""
    if prop_type is PropType.SYSTIME:
        from pypst.ltp.prop_type import filetime_to_datetime

        return filetime_to_datetime(int(parsed))  # type: ignore[arg-type]
    if isinstance(parsed, list):
        return tuple(parsed)
    return parsed


# --- differential: the name-to-id map's PC against read_named_props ----------------------------


# `messaging::named_prop::{PS_MAPI, PS_PUBLIC_STRINGS}` — the two GUIDs the
# entry stream names by index instead of storing ([MS-OXPROPS] 1.3.2).
PS_MAPI = uuid.UUID("00020328-0000-0000-c000-000000000046")
PS_PUBLIC_STRINGS = uuid.UUID("00020329-0000-0000-c000-000000000046")


def named_properties_from_pc(pc: PropertyContext) -> list[dict[str, object]]:
    """The NAMEID entries of NID 0x61, rebuilt from its PC alone — `read_named_props`'s shape.

    [MS-PST] 2.4.7: property 0x0002 is the GUID stream, 0x0003 the entry
    stream (8 bytes per NAMEID: dwPropertyID, wGuid, wPropIdx) and 0x0004
    the string stream (a u32 length then UTF-16LE). Upstream reads them
    through `messaging::named_prop`, which is row P07's port; unpacked here
    so that P05's reading of this PC can be diffed today.
    """
    guids = pc.get(0x0002) or b""
    entries = pc.get(0x0003) or b""
    strings = pc.get(0x0004) or b""
    out: list[dict[str, object]] = []
    for at in range(0, len(entries) - 7, 8):
        prop_number, guid_field, index = struct.unpack_from("<IHH", entries, at)
        guid_index = guid_field >> 1
        named: dict[str, object] = {
            "prop_id": 0x8000 + index,
            "guid_index": {0: None, 1: "Mapi", 2: "PublicStrings"}.get(guid_index, guid_index - 3),
            "guid": None,
            "number": None,
            "string_offset": None,
            "name": None,
        }
        if isinstance(named["guid_index"], int):
            start = 16 * named["guid_index"]
            named["guid"] = uuid.UUID(bytes_le=bytes(guids[start : start + 16]))
        elif named["guid_index"] is not None:
            named["guid"] = PS_MAPI if named["guid_index"] == "Mapi" else PS_PUBLIC_STRINGS
        if guid_field & 1:
            named["string_offset"] = prop_number
            (length,) = struct.unpack_from("<I", strings, prop_number)
            named["name"] = bytes(strings[prop_number + 4 : prop_number + 4 + length]).decode("utf-16-le")
        else:
            named["number"] = prop_number
        out.append(named)
    return out


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_name_to_id_map_pc_reproduces_read_named_props(store: Path, golden, golden_exit) -> None:
    """NID 0x61's PC, value for value: every named property the oracle printed, rebuilt from three properties."""
    assert golden_exit(store, "read_named_props") == 0
    expected = parse_read_named_props(golden(store, "read_named_props"))
    with store_pc(store, NID_NAME_TO_ID_MAP) as pc:
        assert {0x0002, 0x0003, 0x0004} <= set(pc.records), store.stem
        ours = named_properties_from_pc(pc)
    assert ours == expected, f"{store.stem}: {len(ours)} named properties vs {len(expected)}"
    assert len(expected) >= 1, store.stem


def test_a_corpus_store_keeps_a_pc_value_in_a_sub_node() -> None:
    """So the `Node` arm of `read_property` is exercised by a real store, not only by a refusal."""
    found = []
    for store in UNICODE_STORES:
        with store_pc(store, NID_NAME_TO_ID_MAP) as pc:
            if any(r.hnid is not None and r.hnid.as_node is not None for r in pc.records.values()):
                found.append(store.stem)
                assert len(pc.get(0x0003)) > 0
    assert found, "no corpus store keeps a name-to-id-map stream in a sub-node"


def test_a_corpus_store_carries_a_ptyp_object_property() -> None:
    """The divergence is not theoretical: pstsdk-submessage has an embedded message, which upstream cannot read."""
    with opened(FIXTURES / "public" / "pstsdk-submessage.pst") as (reader, nbt):
        found = []
        for entry in nbt:
            if entry.sub_node is None:
                continue
            for sub in reader.read_subnode_tree(entry.sub_node).values():
                try:
                    pc = PropertyContext.from_node(reader, sub, DEFAULT_LIMITS)
                    records = pc.records
                except PstFormatError:
                    continue
                for record in records.values():
                    if record.prop_type is PropType.OBJECT:
                        value = pc.read(record)
                        assert isinstance(value, ObjectRef) and isinstance(value.node, NodeId)
                        found.append(record.prop_id)
        assert found, "pstsdk-submessage has no PtypObject property any more"


# --- the dumper's command line ---------------------------------------------------------------


def test_pc_is_registered_and_takes_a_nid() -> None:
    assert debug.DUMPERS["pc"] is debug.dump_pc
    assert debug.main(["--list"]) == 0


@pytest.mark.parametrize("extra", [[], ["21", "extra"]], ids=["no-nid", "two-nids"])
def test_pc_needs_exactly_one_nid(extra: list[str]) -> None:
    with pytest.raises(SystemExit) as info:
        debug.main(["pc", str(FIXTURES / "Empty.pst"), *extra])
    assert info.value.code == 2


@pytest.mark.parametrize("nid", ["zz", "0x", "-1", "1"], ids=["not-hex", "empty-hex", "negative", "absent"])
def test_pc_refuses_a_bad_or_absent_nid(nid: str, capsys) -> None:
    """A PstError, printed and exit 1 — never a traceback out of the CLI."""
    assert debug.main(["pc", str(FIXTURES / "Empty.pst"), nid]) == 1
    assert "Error:" in capsys.readouterr().err


def test_pc_of_a_node_that_is_not_a_pc_exits_one(capsys) -> None:
    """NID 0x122's hierarchy table (0x0D) is a TC: a refusal, printed and exit 1, not a traceback."""
    code = debug.main(["pc", str(FIXTURES / "Empty.pst"), "0x0D"])
    assert code == 1
    assert "Error:" in capsys.readouterr().err


def test_pc_of_the_store_prints_the_record_line(capsys) -> None:
    assert debug.main(["pc", str(FIXTURES / "Empty.pst"), "21"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert any(line.startswith("  Record: Small(0x") for line in out)
    assert any(line.startswith("  Record: HeapId(NodeId {") for line in out)


def test_property_lines_name_the_value_type_not_the_declared_one() -> None:
    """A variable-size record with a zero HNID prints `Type: Null` — what `read_store_props` prints for one."""
    null = PropertyRecord.unpack(struct.pack("<H", 0x67FF), corrupt.pc_record(0x001F, 0))
    assert debug.property_lines(0x67FF, null, None) == [
        " Property ID: 0x67FF, Type: Null",
        "  Record: HeapId(NodeId { HeapNode: 0x0 })",
        "  Value: Null",
    ]
    real = PropertyRecord.unpack(struct.pack("<H", 0x3001), corrupt.pc_record(0x001F, 0xA0))
    assert debug.property_lines(0x3001, real, "Empty") == [
        " Property ID: 0x3001, Type: Unicode",
        "  Record: HeapId(NodeId { HeapNode: 0x5 })",
        '  Value: Unicode(UnicodeValue { "Empty" })',
    ]


def test_the_dumper_reads_string8_the_way_upstream_does() -> None:
    """Upstream has no code page: a byte becomes U+00XX, which is latin-1 and is NOT the library default."""
    assert debug.DUMP_CODEPAGE == "latin-1"
    # 0x80, 0x93, 0x99 are defined in both, and differ: cp1252 maps them to
    # €, an en dash and ™; upstream widens them to U+0080, U+0093, U+0099.
    raw = b"\x80\x93\x99"
    heap = HeapNode([make_pc_bytes([(0x001A, 0x001E, value_hnid(0))], [raw])])
    upstream = raw.decode("latin-1")
    assert PropertyContext(heap, codepage=debug.DUMP_CODEPAGE).get(0x001A) == upstream
    assert PropertyContext(heap).get(0x001A) != upstream, "cp1252 and latin-1 must differ on 0x80..0x9F"


def test_a_tight_mv_ceiling_is_a_limit_error_before_any_allocation() -> None:
    """`limits.max_mv_items` reaches the decoder: a count of three under a ceiling of two is refused."""
    records = [(0x3001, 0x1003, value_hnid(0))]
    values = [struct.pack("<III", 1, 2, 3)]
    assert make_pc(records, values).get(0x3001) == (1, 2, 3)
    with pytest.raises(PstLimitError):
        make_pc(records, values, limits=Limits(max_mv_items=2)).get(0x3001)


def test_format_property_value_spells_null_and_multi_values_as_rust_does() -> None:
    assert debug.format_property_value(PropType.UNICODE, None) == "Null"
    assert debug.format_property_value(PropType.MV_LONG, (1, 2)) == "MultipleInteger32([1, 2])"
    assert debug.format_property_value(PropType.MV_LONG, ()) == "MultipleInteger32([])"
    assert debug.format_property_value(PropType.BINARY, b"") == "Binary(BinaryValue {  })"
    assert debug.format_property_value(PropType.DOUBLE, 1e16) == "Floating64(1e16)"
    assert debug.format_property_value(PropType.DOUBLE, 2.0) == "Floating64(2.0)"
    assert debug.format_property_value(PropType.FLOAT, 1.5) == "Floating32(1.5)"
    assert debug.format_property_value(PropType.BOOLEAN, True) == "Boolean(true)"
    assert debug.format_property_value(PropType.SYSTIME, datetime(1970, 1, 1, tzinfo=UTC)) == "Time(116444736000000000)"
    # An f32 prints the shortest decimal that round-trips through `<f`, with
    # Rust's `.0` on an integral value, not Python's bare `2`.
    assert debug.format_property_value(PropType.FLOAT, 2.0) == "Floating32(2.0)"
    assert debug.format_property_value(PropType.FLOAT, -0.0) == "Floating32(-0.0)"
    assert debug.format_property_value(PropType.DOUBLE, 1e-5) == "Floating64(1e-5)"
    assert debug.format_property_value(PropType.DOUBLE, float("nan")) == "Floating64(NaN)"
    assert debug.format_property_value(PropType.DOUBLE, float("-inf")) == "Floating64(-inf)"
    # Upstream's `GuidValue` Debug is the registry form in UPPER case.
    guid = uuid.UUID("00062002-0000-0000-c000-000000000046")
    assert debug.format_property_value(PropType.GUID, guid) == "Guid(GuidValue { 00062002-0000-0000-C000-000000000046 })"
    assert debug.format_property_value(PropType.STRING8, 'a"b') == 'String8(String8Value { "a\\"b" })'


# --- private stores: STRUCTURE ONLY -------------------------------------------------------------


@pytest.mark.private
def test_private_store_pcs_open_without_leaking_anything(private_stores: list[Path]) -> None:
    """Every PC in every node and sub-node opens or is refused with a PstError. Counts only — never a value."""
    if not private_stores:
        pytest.skip("no private stores present (this is a normal clean checkout)")
    for index, store in enumerate(private_stores):
        with store.open("rb") as f:
            read_header(f)
        with store_pc(store) as pc:
            assert len(pc) > 0, f"private store {index}: the message store PC is empty"
            assert list(pc.records) == sorted(pc.records), f"private store {index}: records not in id order"
            assert all(isinstance(v, PropType) for v in (r.prop_type for r in pc.records.values()))
            assert len(list(pc)) == len(pc), f"private store {index}: a value did not decode"


@pytest.mark.private
def test_no_private_store_carries_an_mv_guid_property(private_stores: list[Path]) -> None:
    """P22 left MV_GUID pinned to upstream's count-prefixed reading for want of a store that has one.

    Structure only: this asserts on wPropType codes, never on a value. When
    it goes red, a real store finally carries PtypMultipleGuid and
    `_decode_mv_guid` can be settled against it — see the module docstring
    of `pypst.ltp.prop_context`.
    """
    if not private_stores:
        pytest.skip("no private stores present (this is a normal clean checkout)")
    for index, store in enumerate(private_stores):
        with store.open("rb") as f:
            read_header(f)
        seen: set[int] = set()
        contexts = 0
        with opened(store) as (reader, nbt):
            for entry in nbt:
                targets = [entry]
                if entry.sub_node is not None:
                    try:
                        targets.extend(reader.read_subnode_tree(entry.sub_node).values())
                    except PstFormatError:
                        pass
                for target in targets:
                    try:
                        pc = PropertyContext.from_node(reader, target, DEFAULT_LIMITS)
                        records = pc.records
                    except (PstFormatError, PstUnsupportedError):
                        continue
                    contexts += 1
                    seen.update(int(r.prop_type) for r in records.values())
        assert contexts > 0, f"private store {index}: no property context found"
        assert int(PropType.MV_GUID) not in seen, (
            f"private store {index}: a PtypMultipleGuid property exists — settle the MV_GUID layout on it"
        )


@pytest.mark.private
@pytest.mark.oracle
def test_private_store_pc_structure_matches_the_live_oracle(private_stores: list[Path], oracle: Path) -> None:
    """Property ids and type names in order, from the oracle and from this port. No values (CLAUDE.md)."""
    if not private_stores:
        pytest.skip("no private stores present (this is a normal clean checkout)")
    assert oracle == REFERENCE
    checked = 0
    for index, store in enumerate(private_stores):
        with store.open("rb") as f:
            read_header(f)
        try:
            text = run_oracle(oracle, "read_store_props", str(store))
        except (AssertionError, subprocess.TimeoutExpired):
            continue  # the oracle refuses this store; a structure claim needs both sides
        expected = parse_read_store_props(text)["properties"]
        with store_pc(store) as pc:
            ours = [(r.prop_id, r.value_type.debug_name) for r in pc.records.values()]
        theirs = [(g["id"], g["type"]) for g in expected]
        assert len(ours) == len(theirs), f"private store {index}: {len(ours)} properties vs {len(theirs)}"
        assert ours == theirs, f"private store {index}: property ids/types differ at {next(i for i, (a, b) in enumerate(zip(ours, theirs, strict=True)) if a != b)}"
        checked += 1
    if not checked:
        pytest.skip("the oracle could not read any private store")
