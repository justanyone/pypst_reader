"""Heap-on-Node: refused when the header, the page map or the id lies; exact against the goldens when they do not.

Denial first, on synthetic heaps from `tests/corrupt.py` (`heap_node`,
`heap_block`, `bth_heap`): a bad `bSig`, an unknown `bClientSig`, a page map
past the block, a `cAlloc` the block cannot hold, decreasing or overrunning
`rgibAlloc`, a `cFree` that disagrees with the zero-length spans, an HID
with type bits, the null HID, an item index past `cAlloc`, a freed item, a
block index past the last block, the HNBITMAPHDR cadence (blocks 8 and
136), the allocation ceiling — each the right `PstError` subclass, with
`PstLimitError` kept apart from `PstFormatError`. The two ids are shown to
be distinct types that the heap refuses to conflate.

Then the differential claim, which is indirect (P04's oracle is P05's and
P06's examples): on every Unicode store, the message store's PC (NID 0x21),
the root folder's PC (0x122), the name-to-id map (0x61) and the root and
IPM-subtree hierarchy tables open as heaps with the right client
signature; the BTH under the store PC's user root has exactly the records
`read_store_props` prints, key for key and type for type, and every
heap-borne value resolved through `get_hnid` DECODES (P22) to the value the
golden prints — Unicode, String8, Binary, Integer64 — with the inline
Integer32 and Boolean records equal to theirs; a table's row-index BTH has
the row ids `read_root_folder` / `read_ipm_subtree` print, and every
`Record: Heap(HeapId(…))` those goldens show resolves through `get` to the
value printed under it. The private stores against the live oracle by
property ids and types only.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from pypstreader import debug
from pypstreader.errors import (
    PstError,
    PstFormatError,
    PstLimitError,
    PstNotFoundError,
    PstUnsupportedError,
)
from pypstreader.limits import DEFAULT_LIMITS, MAX_HEAP_ITEMS, Limits
from pypstreader.ltp.heap import (
    HEAP_HEADER_SIZE,
    MAX_HEAP_ITEM_INDEX,
    HeapId,
    HeapNode,
    HeapNodeHeader,
    HeapNodeId,
    HeapNodeType,
    HeapPageMap,
)
from pypstreader.ltp.prop_type import PropType, decode
from pypstreader.ltp.tree import HeapTree
from pypstreader.ndb.block import BlockReader, SubNodeLeafEntry
from pypstreader.ndb.btree import BlockBTree, NodeBTree
from pypstreader.ndb.header import read_header
from pypstreader.ndb.ids import (
    NID_MESSAGE_STORE,
    NID_NAME_TO_ID_MAP,
    NID_ROOT_FOLDER,
    NodeId,
    NodeIdType,
)
from tests import corrupt
from tests.conftest import FIXTURES, REFERENCE, public_fixture_paths, run_oracle
from tests.test_prop_type import UPSTREAM_VARIANT_TO_PROPTYPE

EMPTY_PATH = FIXTURES / "Empty.pst"
ANSI_STEMS = {"pstsdk-test_ansi", "pstsdk-sample2"}
ALL_STORES = [EMPTY_PATH, *public_fixture_paths()]
UNICODE_STORES = [p for p in ALL_STORES if p.stem not in ANSI_STEMS]
UNICODE_IDS = [p.stem for p in UNICODE_STORES]

HID = corrupt.hid
PC = HeapNodeType.PROPERTIES
TC = HeapNodeType.TABLE

# [MS-PST] 2.3.4.1 TCINFO: bType, cCols, rgib[4], hidRowIndex, hnidRows, hidIndex — only the
# row-index HID is needed here, and only to prove the BTH under it.
TCINFO_FORMAT = "<BB4HIII"
NID_TYPE_HIERARCHY_TABLE = NodeIdType.HIERARCHY_TABLE


# --- the ids --------------------------------------------------------------------------------


@pytest.mark.parametrize("raw", [0x01, 0x1F, 0x21, 0x0000_0002, 0xFFFF_FFFF])
def test_heap_id_refuses_type_bits(raw: int) -> None:
    with pytest.raises(PstFormatError, match="type bits"):
        HeapId(raw)


@pytest.mark.parametrize("raw", [-1, 2**32, "0x20", True, 1.0])
def test_heap_id_refuses_what_is_not_a_u32(raw: object) -> None:
    with pytest.raises(PstFormatError):
        HeapId(raw)  # type: ignore[arg-type]


def test_heap_id_parts_round_trip_and_null() -> None:
    h = HeapId.from_parts(5, 3)
    assert (h.index, h.block_index, h.raw) == (5, 3, (3 << 16) | (5 << 5))
    assert HeapId(HID(5, block=3)) == h
    assert HeapId.unpack_from(h.pack()) == h
    assert not h.is_null
    null = HeapId(0)
    assert null.is_null and null.index == 0 and null.block_index == 0
    assert HeapId.from_parts(0) == null
    assert HeapId.from_parts(MAX_HEAP_ITEM_INDEX, 0xFFFF).index == 2047


@pytest.mark.parametrize(("index", "block"), [(2048, 0), (-1, 0), (1, 65536), (1, -1), (True, 0)])
def test_heap_id_from_parts_refuses_out_of_range(index: int, block: int) -> None:
    with pytest.raises(PstFormatError):
        HeapId.from_parts(index, block)


def test_heap_id_str_is_upstreams_debug_form() -> None:
    # `Record: Heap(HeapId(NodeId { HeapNode: 0x5 }))` in the goldens is the HID 0xA0.
    assert str(HeapId(0xA0)) == "HeapId(NodeId { HeapNode: 0x5 })"
    assert str(HeapId.from_parts(1, 1)) == "HeapId(NodeId { HeapNode: 0x801 })"


def test_heap_id_short_buffer_is_refused() -> None:
    with pytest.raises(PstFormatError):
        HeapId.unpack_from(b"\x20\x00\x00")


def test_heap_node_id_is_one_of_two_things_and_never_both() -> None:
    heap = HeapNodeId(0xA0)
    assert heap.is_heap and heap.as_heap == HeapId(0xA0) and heap.as_node is None
    node = HeapNodeId(0x21)  # NID_TYPE_INTERNAL, index 1
    assert not node.is_heap and node.as_heap is None and node.as_node == NodeId(0x21)
    unknown = HeapNodeId(0x1B)  # a type no enum member names: still a node, as upstream's `_ =>` arm
    assert unknown.as_node == NodeId(0x1B) and unknown.as_heap is None
    assert str(heap) == "HeapId(NodeId { HeapNode: 0x5 })"
    assert str(node) == "NodeId { Internal: 0x1 }"
    assert HeapNodeId.unpack_from(node.pack()) == node
    assert not isinstance(heap, HeapId) and not isinstance(heap, NodeId)


def test_heap_node_id_refuses_what_is_not_a_u32() -> None:
    with pytest.raises(PstFormatError):
        HeapNodeId(2**32)


def test_the_two_ids_do_not_conflate_at_the_heap() -> None:
    """The T02 trap: an HNID handed to `get`, or an HID to `get_hnid`, is a TypeError, not a read."""
    heap = HeapNode([corrupt.heap_node([b"one"])])
    with pytest.raises(TypeError):
        heap.get(HeapNodeId(HID(1)))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        heap.get_hnid(HeapId(HID(1)))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        heap.get(HID(1))  # type: ignore[arg-type]


# --- header denials -------------------------------------------------------------------------


def test_no_blocks_is_refused() -> None:
    with pytest.raises(PstFormatError, match="no data blocks"):
        HeapNode([])


def test_block_zero_shorter_than_the_header_is_refused() -> None:
    with pytest.raises(PstFormatError, match="HNHDR"):
        HeapNode([corrupt.heap_node([b"x"])[: HEAP_HEADER_SIZE - 1]])


@pytest.mark.parametrize("signature", [0x00, 0xEB, 0xED, 0xFF])
def test_bad_heap_signature_is_refused(signature: int) -> None:
    with pytest.raises(PstFormatError, match="heap signature"):
        HeapNode([corrupt.heap_node([b"x"], signature=signature)])


@pytest.mark.parametrize("client_sig", [0x00, 0x01, 0x7D, 0xBD, 0xFF])
def test_unknown_client_signature_is_refused(client_sig: int) -> None:
    with pytest.raises(PstFormatError, match="client signature"):
        HeapNode([corrupt.heap_node([b"x"], client_sig=client_sig)])


@pytest.mark.parametrize("client_sig", list(HeapNodeType))
def test_every_spec_client_signature_is_accepted(client_sig: HeapNodeType) -> None:
    heap = HeapNode([corrupt.heap_node([b"x"], client_sig=int(client_sig))])
    assert heap.client_signature is client_sig
    assert HeapNodeType.from_wire(int(client_sig)) is client_sig


def test_user_root_with_type_bits_is_refused_at_the_header() -> None:
    with pytest.raises(PstFormatError, match="type bits"):
        HeapNode([corrupt.heap_node([b"x"], user_root=HID(1) | 0x02)])


def test_header_fields_and_fill_levels() -> None:
    heap = HeapNode([corrupt.heap_node([b"abc", b"de"], user_root=HID(2), fill_levels=0x8765_4321)])
    header = heap.header
    assert isinstance(header, HeapNodeHeader)
    assert header.client_signature is PC and heap.client_signature is PC
    assert header.user_root == HeapId(HID(2)) and heap.user_root.index == 2
    assert header.fill_levels == (1, 2, 3, 4, 5, 6, 7, 8)  # low nibble first, as upstream unpacks them
    assert header.page_map_offset == HEAP_HEADER_SIZE + 5
    assert heap.block_count == 1 and heap.limits is DEFAULT_LIMITS


# --- page map denials -----------------------------------------------------------------------


@pytest.mark.parametrize("offset", [0xFFFF, 100, 99, 98])
def test_page_map_offset_past_the_block_is_refused(offset: int) -> None:
    block = corrupt.heap_block([b"abc"], page_map_offset=offset)  # 15 body bytes + 8 of page map = 23; 98+ is past
    block = block + bytes(75) if offset < 0xFFFF else block  # 98 bytes long: cAlloc at 98 needs 4
    with pytest.raises(PstFormatError, match="HNPAGEMAP|rgibAlloc"):
        HeapNode([block]).get(HeapId(HID(1)))


def test_unaligned_page_map_is_read_as_upstream_reads_it() -> None:
    """[MS-PST] 2.3.1.5 says 2-byte aligned; pstd-inline-cid's root-folder heap has ibHnpm 121 and upstream reads it."""
    heap = HeapNode([corrupt.heap_block([b"abcd"], pad=1)])
    assert heap.header.page_map_offset == 17
    assert bytes(heap.get(HeapId(HID(1)))) == b"abcd"


@pytest.mark.parametrize("count", [0xFFFF, 0x1000, 4])
def test_alloc_count_the_block_cannot_hold_is_refused(count: int) -> None:
    with pytest.raises(PstFormatError, match="rgibAlloc"):
        HeapNode([corrupt.heap_block([b"abc", b"de"], count=count)]).get(HeapId(HID(1)))


def test_alloc_count_that_under_reports_hides_the_later_items() -> None:
    heap = HeapNode([corrupt.heap_block([b"abc", b"de"], count=1)])
    assert bytes(heap.get(HeapId(HID(1)))) == b"abc"
    with pytest.raises(PstFormatError, match="past the block's 1 allocation"):
        heap.get(HeapId(HID(2)))


def test_decreasing_offsets_are_refused() -> None:
    with pytest.raises(PstFormatError, match="before the previous"):
        HeapNode([corrupt.heap_block([b"abc", b"de"], offsets=[12, 15, 14])]).get(HeapId(HID(1)))


@pytest.mark.parametrize("past", [0xFFFF - 27, 200, 3, 1])
def test_offset_past_the_block_is_refused(past: int) -> None:
    # The block is 12 + 5 + 4 + 6 = 27 bytes; an item that ends one byte past it is outside it (mutation-found boundary).
    block = corrupt.heap_block([b"abc", b"de"])
    assert len(block) == 27
    with pytest.raises(PstFormatError, match="past the block"):
        HeapNode([corrupt.heap_block([b"abc", b"de"], offsets=[12, 15, len(block) + past])]).get(HeapId(HID(1)))


def test_offset_exactly_at_the_end_of_the_block_is_allowed() -> None:
    # `offset <= len(block)`: an item may end where the block ends (the page map is then inside it — as upstream).
    block = corrupt.heap_block([b"abc", b"de"])
    heap = HeapNode([corrupt.heap_block([b"abc", b"de"], offsets=[12, 15, len(block)])])
    assert len(heap.get(HeapId(HID(2)))) == len(block) - 15


@pytest.mark.parametrize(("items", "free"), [([b"abc", b"de"], 1), ([b"abc", b"", b"de"], 0), ([b"abc", b"", b""], 1)])
def test_free_count_that_disagrees_with_the_zero_length_spans_is_refused(items: list[bytes], free: int) -> None:
    with pytest.raises(PstFormatError, match="cFree"):
        HeapNode([corrupt.heap_block(items, free=free)]).get(HeapId(HID(1)))


def test_freed_item_is_counted_and_refused_while_its_neighbours_read() -> None:
    heap = HeapNode([corrupt.heap_block([b"abc", b"", b"de"])])
    page_map = heap.page_map(0)
    assert isinstance(page_map, HeapPageMap)
    assert (page_map.count, page_map.free_count, page_map.sizes) == (3, 1, (3, 0, 2))
    assert page_map.size(1) == 0 and page_map.fill_levels is None
    assert bytes(heap.get(HeapId(HID(1)))) == b"abc"
    assert bytes(heap.get(HeapId(HID(3)))) == b"de"
    with pytest.raises(PstFormatError, match="freed"):
        heap.get(HeapId(HID(2)))


# --- item denials ---------------------------------------------------------------------------


def test_null_hid_is_refused() -> None:
    with pytest.raises(PstFormatError, match="null"):
        HeapNode([corrupt.heap_node([b"abc"])]).get(HeapId(0))


@pytest.mark.parametrize("index", [3, 4, 100, MAX_HEAP_ITEM_INDEX])
def test_item_index_past_the_allocation_count_is_refused(index: int) -> None:
    with pytest.raises(PstFormatError, match="past the block's 2 allocation"):
        HeapNode([corrupt.heap_node([b"abc", b"de"])]).get(HeapId(HID(index)))


@pytest.mark.parametrize("block", [1, 2, 0xFFFF])
def test_block_index_past_the_last_block_is_refused(block: int) -> None:
    with pytest.raises(PstFormatError, match="block index"):
        HeapNode([corrupt.heap_node([b"abc"])]).get(HeapId(HID(1, block=block)))
    with pytest.raises(PstFormatError, match="block index"):
        HeapNode([corrupt.heap_node([b"abc"])]).block(block)


def test_get_returns_a_view_of_the_item_bytes() -> None:
    heap = HeapNode([corrupt.heap_node([b"abc", b"de", b"f"])])
    item = heap.get(HeapId(HID(2)))
    assert isinstance(item, memoryview) and bytes(item) == b"de"
    assert [bytes(heap.get(HeapId(HID(i)))) for i in (1, 2, 3)] == [b"abc", b"de", b"f"]
    assert heap.page_map(0).sizes == (3, 2, 1)


# --- HNIDs ----------------------------------------------------------------------------------


def test_get_hnid_resolves_a_heap_item_and_refuses_an_absent_sub_node() -> None:
    heap = HeapNode([corrupt.heap_node([b"abc"])])
    assert heap.get_hnid(HeapNodeId(HID(1))) == b"abc"
    with pytest.raises(PstNotFoundError):
        heap.get_hnid(HeapNodeId(0x21))
    with pytest.raises(PstFormatError, match="null"):
        heap.get_hnid(HeapNodeId(0))


def test_get_hnid_with_a_sub_node_map_but_no_reader_is_not_found() -> None:
    entry = SubNodeLeafEntry(NodeId(0x21), corrupt.BlockId(4) if hasattr(corrupt, "BlockId") else _bid(4), None)
    heap = HeapNode([corrupt.heap_node([b"abc"])], subnodes={NodeId(0x21): entry})
    with pytest.raises(PstNotFoundError):
        heap.get_hnid(HeapNodeId(0x21))


def _bid(index: int):
    from pypstreader.ndb.ids import BlockId

    return BlockId.from_parts(False, index)


# --- multi-block heaps ----------------------------------------------------------------------


def _blocks(count: int, *, short: int | None = None) -> list[bytes]:
    """`count` heap blocks, item 1 of block k spelling k; block 8/136/… gets a bitmap header, or a short page header at `short`."""
    out = []
    for k in range(count):
        item = f"block{k}".encode()
        if k == 0:
            header = corrupt.heap_header()
        elif k % 128 == 8 and k != short:
            header = corrupt.bitmap_header()
        else:
            header = corrupt.page_header()
        out.append(corrupt.heap_block([item], header=header))
    return out


def test_items_resolve_by_block_index_across_page_and_bitmap_headers() -> None:
    heap = HeapNode(_blocks(10))
    assert heap.block_count == 10
    for k in range(10):
        assert bytes(heap.get(HeapId(HID(1, block=k)))) == f"block{k}".encode()
    assert heap.page_map(8).fill_levels == (0,) * 128
    assert heap.page_map(7).fill_levels is None


@pytest.mark.parametrize("bitmap_block", [8, 136, 264])
def test_bitmap_header_cadence_is_block_8_then_every_128(bitmap_block: int) -> None:
    """[MS-PST] 2.3.1.4: a block at the cadence needs the 66-byte HNBITMAPHDR; a 2-byte header there is short."""
    blocks = _blocks(bitmap_block + 1, short=bitmap_block)
    heap = HeapNode(blocks)
    assert bytes(heap.get(HeapId(HID(1, block=bitmap_block - 1)))) == f"block{bitmap_block - 1}".encode()
    with pytest.raises(PstFormatError, match="HNBITMAPHDR"):
        heap.get(HeapId(HID(1, block=bitmap_block)))


def test_a_page_map_is_parsed_on_first_use_so_a_bad_block_only_fails_its_own_items() -> None:
    blocks = _blocks(3)
    blocks[1] = b"\xff" * 20
    heap = HeapNode(blocks)
    assert bytes(heap.get(HeapId(HID(1, block=2)))) == b"block2"
    with pytest.raises(PstFormatError):
        heap.get(HeapId(HID(1, block=1)))


def test_block_with_fewer_bytes_than_its_page_header_is_refused() -> None:
    blocks = _blocks(2)
    blocks[1] = b"\x00"
    with pytest.raises(PstFormatError, match="HNPAGEHDR"):
        HeapNode(blocks).get(HeapId(HID(1, block=1)))


def test_allocation_ceiling_counts_across_blocks_and_the_ceiling_itself_passes() -> None:
    blocks = [corrupt.heap_block([b"a", b"b"]), corrupt.heap_block([b"c", b"d"], header=corrupt.page_header())]
    at_ceiling = HeapNode(blocks, limits=Limits(max_heap_items=4))
    assert bytes(at_ceiling.get(HeapId(HID(2, block=1)))) == b"d"
    over = HeapNode(blocks, limits=Limits(max_heap_items=3))
    assert bytes(over.get(HeapId(HID(1)))) == b"a"
    with pytest.raises(PstLimitError, match="heap allocations: 4 exceeds limit 3"):
        over.get(HeapId(HID(1, block=1)))
    assert MAX_HEAP_ITEMS == 65_536 * 2_047


# --- nothing but PstError -------------------------------------------------------------------


def _exercise(blocks: list[bytes]) -> None:
    heap = HeapNode(blocks)
    for block in range(heap.block_count):
        page_map = heap.page_map(block)
        for i in range(1, page_map.count + 1):
            heap.get(HeapId(HID(i, block=block)))
    list(HeapTree(heap))


def test_every_byte_flip_and_truncation_leaks_nothing_but_pst_error() -> None:
    base = corrupt.bth_heap([(b"\x01\x00", corrupt.pc_record(0x1F, HID(3))), (b"\x02\x00", corrupt.pc_record(3, 7))], levels=0)
    base = corrupt.heap_node([base[12:20], base[20:36], b"hello"])  # header, leaf, a value item
    _exercise([base])
    for offset in range(len(base)):
        for mask in (0x01, 0x80, 0xFF):
            try:
                _exercise([corrupt.flip_byte(base, offset, mask)])
            except PstError:
                pass
    for length in range(len(base)):
        try:
            _exercise([base[:length]])
        except PstError:
            pass


# --- the dumper -----------------------------------------------------------------------------


def test_debug_heap_prints_header_blocks_and_item_lengths(capsys: pytest.CaptureFixture[str]) -> None:
    assert debug.main(["heap", str(EMPTY_PATH), "21"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[:6] == [
        "Node: NodeId { Internal: 0x1 }",
        "Client Signature: 0xBC",
        "User Root: HeapId(NodeId { HeapNode: 0x1 })",
        "Fill Levels: [0, 0, 0, 0, 0, 0, 0, 0]",
        "Blocks: 1",
        "Block 0: Allocations: 9, Free: 0",
    ]
    assert lines[6] == " Item 1: 8 bytes" and len(lines) == 6 + 9
    assert debug.main(["heap", str(EMPTY_PATH), "12d"]) == 0
    assert "Client Signature: 0x7C" in capsys.readouterr().out


@pytest.mark.parametrize("args", [["heap", "zz"], ["heap", "1"], ["bth", "12d"], ["heap"]])
def test_debug_heap_and_bth_refusals(args: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    if len(args) == 1:
        with pytest.raises(SystemExit):
            debug.main([*args, str(EMPTY_PATH)])
        return
    assert debug.main([args[0], str(EMPTY_PATH), args[1]]) == 1
    assert capsys.readouterr().err.startswith("Error: ")


# --- differential: the goldens ----------------------------------------------------------------

_PROP_LINE = re.compile(r"^ (?:Column: )?Property ID: 0x([0-9A-Fa-f]{4}), Type: (\w+)$")
_VALUE_LINE = re.compile(r"^  Value: (.*)$")
_RECORD_LINE = re.compile(r"^  Record: (.*)$")
_HEAP_RECORD = re.compile(r"^Heap\(HeapId\(NodeId \{ HeapNode: 0x([0-9A-Fa-f]+) \}\)\)$")
_ROW_LINE = re.compile(r"^Row: 0x([0-9A-Fa-f]+)$")
_STRING_VALUE = re.compile(r'^(Unicode|String8)\((?:Unicode|String8)Value \{ "(.*)" \}\)$', re.DOTALL)
_BINARY_VALUE = re.compile(r"^Binary\(BinaryValue \{ ?([0-9A-F-]*) ?\}\)$")
_INT_VALUE = re.compile(r"^(Integer32|Integer64)\((-?\d+)\)$")
_BOOL_VALUE = re.compile(r"^Boolean\((true|false)\)$")
_RUST_ESCAPE = re.compile(r"\\(u\{([0-9a-fA-F]+)\}|.)")


def _unescape(text: str) -> str:
    """Rust's `Debug` string escapes back to the string."""
    simple = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'", "0": "\0"}

    def one(m: re.Match[str]) -> str:
        if m.group(2) is not None:
            return chr(int(m.group(2), 16))
        return simple[m.group(1)]

    return _RUST_ESCAPE.sub(one, text)


def _golden_properties(text: str) -> list[dict[str, object]]:
    """Every ` Property ID:` / `  Record:` / `  Value:` group of a store-props or table golden, in order."""
    out: list[dict[str, object]] = []
    for line in text.splitlines():
        m = _PROP_LINE.match(line)
        if m:
            out.append({"id": int(m.group(1), 16), "type": m.group(2), "record": None, "value": None})
            continue
        m = _RECORD_LINE.match(line)
        if m and out:
            out[-1]["record"] = m.group(1)
            continue
        m = _VALUE_LINE.match(line)
        if m and out:
            out[-1]["value"] = m.group(1)
    return out


def _check_decoded_value(type_name: str, data: bytes, printed: str, where: str, problems: list[str]) -> bool:
    """Compare P22's decode of `data` with the golden's printed value; True when the type is one compared."""
    m = _STRING_VALUE.match(printed)
    if m:
        prop_type = PropType.UNICODE if m.group(1) == "Unicode" else PropType.STRING8
        # Upstream has no code page: String8 bytes become U+00XX (INTERFACES § prop_type).
        got = decode(prop_type, data, codepage="latin-1")
        if got != _unescape(m.group(2)):
            problems.append(f"{where}: {type_name} decodes differently")
        return True
    m = _BINARY_VALUE.match(printed)
    if m:
        expected = bytes.fromhex(m.group(1).replace("-", ""))
        if decode(PropType.BINARY, data) != expected:
            problems.append(f"{where}: Binary differs ({len(data)} vs {len(expected)} bytes)")
        return True
    m = _INT_VALUE.match(printed)
    if m and m.group(1) == "Integer64":
        if decode(PropType.LONGLONG, data) != int(m.group(2)):
            problems.append(f"{where}: Integer64 differs")
        return True
    return False


def _check_inline_value(prop_type: PropType, raw: int, printed: str, where: str, problems: list[str]) -> bool:
    m = _INT_VALUE.match(printed)
    if m and m.group(1) == "Integer32" and prop_type is PropType.LONG:
        if struct.unpack("<i", struct.pack("<I", raw))[0] != int(m.group(2)):
            problems.append(f"{where}: Integer32 differs")
        return True
    m = _BOOL_VALUE.match(printed)
    if m and prop_type is PropType.BOOLEAN:
        # Upstream's PC arm: `value & 0xFF != 0`.
        if ((raw & 0xFF) != 0) != (m.group(1) == "true"):
            problems.append(f"{where}: Boolean differs")
        return True
    return False


@contextmanager
def _opened(store: Path) -> Iterator[tuple[BlockReader, NodeBTree]]:
    with store.open("rb") as f:
        header = read_header(f)
        yield BlockReader(f, header, BlockBTree(f, header.root.block_btree)), NodeBTree(f, header.root.node_btree)


# The types upstream's `PropertyValueRecord::small_value` decodes from the 4 inline bytes; every
# other type's record is an HNID, and an HNID of 0 is printed by the examples as `Null`
# (`PropertyType::from(value)` names the VALUE's variant, not `wPropType`).
_SMALL_TYPES = frozenset({PropType.SHORT, PropType.LONG, PropType.FLOAT, PropType.ERROR, PropType.BOOLEAN})


def _printed_type(prop_type: PropType, hnid: HeapNodeId) -> PropType:
    """The `Type:` upstream's examples print for a PC record."""
    return PropType.NULL if prop_type not in _SMALL_TYPES and hnid.raw == 0 else prop_type


def _pc_records(heap: HeapNode) -> list[tuple[int, PropType, HeapNodeId]]:
    """The PC's BTH as (prop id, type, HNID) — the 2-byte key and 6-byte value of [MS-PST] 2.3.3.3, decoded here only as far as this row needs."""
    out = []
    for key, value in HeapTree(heap):
        (prop_id,) = struct.unpack("<H", key)
        (wire_type,) = struct.unpack_from("<H", value, 0)
        out.append((prop_id, PropType.from_wire(wire_type), HeapNodeId.unpack_from(value, 2)))
    return out


def _compare_pc_with_golden(heap: HeapNode, expected: list[dict[str, object]], where: str) -> tuple[int, int, list[str]]:
    """Keys, types, and every comparable value; returns (records compared, values compared, problems)."""
    problems: list[str] = []
    records = _pc_records(heap)
    if [r[0] for r in records] != [e["id"] for e in expected]:
        problems.append(f"{where}: property ids {[hex(r[0]) for r in records]} != golden {[hex(int(e['id'])) for e in expected]}")
        return len(records), 0, problems
    values = 0
    for (prop_id, prop_type, hnid), e in zip(records, expected, strict=True):
        tag = f"{where} 0x{prop_id:04X}"
        if UPSTREAM_VARIANT_TO_PROPTYPE[str(e["type"])] is not _printed_type(prop_type, hnid):
            problems.append(f"{tag}: type {prop_type.name} != golden {e['type']}")
            continue
        printed = str(e["value"])
        if prop_type in (PropType.LONG, PropType.BOOLEAN):
            values += _check_inline_value(prop_type, hnid.raw, printed, tag, problems)
        elif hnid.raw != 0:
            values += _check_decoded_value(str(e["type"]), heap.get_hnid(hnid), printed, tag, problems)
    return len(records), values, problems


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_store_pc_records_and_values_match_read_store_props_golden(store: Path, golden, golden_exit) -> None:
    text = golden(store, "read_store_props")
    expected = _golden_properties(text)
    display_name = next(line.removeprefix("Display Name: ") for line in text.splitlines() if line.startswith("Display Name: "))
    with _opened(store) as (reader, nbt):
        heap = HeapNode.from_node(reader, nbt.find(NID_MESSAGE_STORE))
        assert heap.client_signature is PC, store.stem
        records = _pc_records(heap)
        by_id = {prop_id: (prop_type, hnid) for prop_id, prop_type, hnid in records}
        prop_type, hnid = by_id[0x3001]
        assert prop_type is PropType.UNICODE and decode(prop_type, heap.get_hnid(hnid)) == display_name, store.stem
        if golden_exit(store, "read_store_props") != 0:
            # pstd-inline-cid: the example fails before printing the properties; the PC itself opened.
            assert not expected and len(records) > 0, store.stem
            return
        count, values, problems = _compare_pc_with_golden(heap, expected, store.stem)
    assert not problems, "\n".join(problems)
    assert count == len(expected) > 0 and values >= 3, f"{store.stem}: {count} records, {values} values compared"


def _hierarchy_table_nid(folder_index: int) -> NodeId:
    return NodeId.from_parts(NID_TYPE_HIERARCHY_TABLE, folder_index)


def _row_index_tree(heap: HeapNode) -> HeapTree:
    """The TC's row-index BTH: `hidRowIndex` of the TCINFO at the user root ([MS-PST] 2.3.4.1)."""
    info = heap.get(heap.user_root)
    fields = struct.unpack_from(TCINFO_FORMAT, info, 0)
    assert fields[0] == int(TC)
    return HeapTree(heap, HeapId(fields[6]))


def _compare_tc_with_golden(heap: HeapNode, text: str, where: str) -> tuple[int, int, list[str]]:
    problems: list[str] = []
    row_ids = [int(m.group(1), 16) for m in map(_ROW_LINE.match, text.splitlines()) if m]
    tree = _row_index_tree(heap)
    assert tree.key_size == 4 and tree.entry_size == 4, where
    keys = sorted(struct.unpack("<I", k)[0] for k, _v in tree)
    if keys != sorted(row_ids):
        problems.append(f"{where}: row ids {keys} != golden {sorted(row_ids)}")
    values = 0
    for e in _golden_properties(text):
        m = _HEAP_RECORD.match(str(e["record"]))
        if not m:
            continue
        hid = HeapId(int(m.group(1), 16) << 5)
        values += _check_decoded_value(str(e["type"]), bytes(heap.get(hid)), str(e["value"]), f"{where} 0x{int(e['id']):04X}", problems)
    return len(keys), values, problems


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_folder_pcs_and_hierarchy_tables_match_the_table_goldens(store: Path, golden, golden_exit) -> None:
    """The root folder and IPM subtree: PC signature 0xBC; their hierarchy tables 0x7C, with the goldens' row ids and heap values."""
    store_props = golden(store, "read_store_props")
    ipm = re.search(r"^IPM Subtree: EntryId \{ .*node_id: NodeId \{ NormalFolder: 0x([0-9A-Fa-f]+) \} \}$", store_props, re.MULTILINE)
    assert ipm is not None, store.stem
    ipm_index = int(ipm.group(1), 16)
    problems: list[str] = []
    rows = values = 0
    with _opened(store) as (reader, nbt):
        for folder in (NID_ROOT_FOLDER, NodeId.from_parts(NodeIdType.NORMAL_FOLDER, ipm_index)):
            pc = HeapNode.from_node(reader, nbt.find(folder))
            assert pc.client_signature is PC and len(_pc_records(pc)) > 0, f"{store.stem} {folder}"
        for example, folder_index in (("read_root_folder", NID_ROOT_FOLDER.index), ("read_ipm_subtree", ipm_index)):
            if golden_exit(store, example) != 0:
                continue  # pstd-inline-cid: the example itself fails; nothing to compare
            tc = HeapNode.from_node(reader, nbt.find(_hierarchy_table_nid(folder_index)))
            assert tc.client_signature is TC, f"{store.stem} {example}"
            r, v, p = _compare_tc_with_golden(tc, golden(store, example), f"{store.stem} {example}")
            rows += r
            values += v
            problems += p
    assert not problems, "\n".join(problems)
    if store.stem != "pstd-inline-cid":
        assert rows > 0 and values > 0, f"{store.stem}: {rows} rows, {values} heap values compared"


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_name_to_id_map_entry_stream_has_the_goldens_entry_count(store: Path, golden) -> None:
    """NID 0x61's PC: property 0x0003 is the NAMEID entry stream, 8 bytes per `Named Property ID:` group the golden prints."""
    groups = sum(1 for line in golden(store, "read_named_props").splitlines() if line.startswith("Named Property ID: "))
    with _opened(store) as (reader, nbt):
        heap = HeapNode.from_node(reader, nbt.find(NID_NAME_TO_ID_MAP))
        assert heap.client_signature is PC
        by_id = {prop_id: (prop_type, hnid) for prop_id, prop_type, hnid in _pc_records(heap)}
        prop_type, hnid = by_id[0x0003]
        assert prop_type is PropType.BINARY
        entries = heap.get_hnid(hnid)
        assert len(entries) % 8 == 0 and len(entries) // 8 == groups, store.stem
        # A sub-node absent from the tree, on a store whose map has one and on one that does not.
        with pytest.raises(PstNotFoundError):
            heap.get_hnid(HeapNodeId(0x7FFF_FFE1))
        if hnid.as_node is not None:
            # The entry stream in a sub-node: `get_hnid` went through the sub-node tree.
            assert reader.read_data(reader.read_subnode_tree(nbt.find(NID_NAME_TO_ID_MAP).sub_node)[hnid.as_node].data) == entries


def test_at_least_one_corpus_store_keeps_its_entry_stream_in_a_sub_node() -> None:
    """So that the sub-node arm of `get_hnid` is exercised by a real store, not only refused."""
    found = []
    for store in UNICODE_STORES:
        with _opened(store) as (reader, nbt):
            heap = HeapNode.from_node(reader, nbt.find(NID_NAME_TO_ID_MAP))
            by_id = {prop_id: hnid for prop_id, _t, hnid in _pc_records(heap)}
            if by_id[0x0003].as_node is not None:
                found.append(store.stem)
    assert found, "no corpus store has a sub-node-backed entry stream"


def test_from_node_accepts_a_sub_node_leaf_entry() -> None:
    with _opened(EMPTY_PATH) as (reader, nbt):
        entry = nbt.find(NID_MESSAGE_STORE)
        via_node = HeapNode.from_node(reader, entry)
        via_leaf = HeapNode.from_node(reader, SubNodeLeafEntry(entry.node, entry.data, entry.sub_node))
        assert via_leaf.header == via_node.header and via_leaf.block_count == 1


@pytest.mark.parametrize("store", [p for p in ALL_STORES if p.stem in ANSI_STEMS], ids=sorted(ANSI_STEMS))
def test_ansi_store_is_refused_before_any_heap(store: Path) -> None:
    with pytest.raises(PstUnsupportedError), store.open("rb") as f:
        read_header(f)


# --- differential: private stores against the live oracle ----------------------------------


@pytest.mark.private
@pytest.mark.oracle
def test_private_store_pc_ids_and_types_match_live_oracle(private_stores: list[Path], oracle: Path) -> None:
    """Structure only: the store PC's property ids and types in order, and the root hierarchy table's row ids."""
    if not private_stores:
        pytest.skip("no private stores present (this is a normal clean checkout)")
    assert oracle == REFERENCE
    checked = 0
    failures: list[str] = []
    for store in private_stores:
        try:
            with store.open("rb") as f:
                read_header(f)
        except PstUnsupportedError:
            continue
        expected = _golden_properties(run_oracle(oracle, "read_store_props", str(store)))
        rows = [int(m.group(1), 16) for m in map(_ROW_LINE.match, run_oracle(oracle, "read_root_folder", str(store)).splitlines()) if m]
        with _opened(store) as (reader, nbt):
            heap = HeapNode.from_node(reader, nbt.find(NID_MESSAGE_STORE))
            records = _pc_records(heap)
            ours = [(prop_id, _printed_type(prop_type, hnid)) for prop_id, prop_type, hnid in records]
            theirs = [(int(e["id"]), UPSTREAM_VARIANT_TO_PROPTYPE[str(e["type"])]) for e in expected]
            if ours != theirs:
                failures.append(f"store {checked}: {len(ours)} store properties vs {len(theirs)}")
            tc = HeapNode.from_node(reader, nbt.find(_hierarchy_table_nid(NID_ROOT_FOLDER.index)))
            keys = sorted(struct.unpack("<I", k)[0] for k, _v in _row_index_tree(tc))
            if keys != sorted(rows):
                failures.append(f"store {checked}: {len(keys)} root rows vs {len(rows)}")
        checked += 1
    assert checked > 0, "no Unicode private store"
    assert not failures, f"{len(failures)} of {checked} private store(s) differ from the oracle: {failures}"
