"""The identifier types: refused when wrong, exact when right.

Denial first: every way an index, a type or a buffer can be out of range is
a `PstFormatError` and nothing else. Then the differential check that gives
these types their claim to correctness — every id the oracle printed in the
read_header and read_btrees goldens, rebuilt from its parts and printed
back, must reproduce the oracle's text. Then the round-trip property over
seeded random values, which is what `hypothesis` will replace (P25).
"""

from __future__ import annotations

import random
import re
from pathlib import Path

import pytest

from pypst.errors import PstError, PstFormatError
from pypst.ndb.ids import (
    MAX_BLOCK_INDEX,
    MAX_NODE_INDEX,
    NID_MESSAGE_STORE,
    NID_NAME_TO_ID_MAP,
    NID_ROOT_FOLDER,
    NID_SEARCH_GATHERER_FOLDER_QUEUE,
    BlockId,
    BlockRef,
    ByteIndex,
    NodeId,
    NodeIdType,
    PageId,
    PageRef,
)
from tests.conftest import FIXTURES, public_fixture_ids, public_fixture_paths

GOLDEN = Path(__file__).resolve().parent / "golden"
GOLDEN_FIXTURES = sorted(p.name for p in GOLDEN.iterdir() if p.is_dir())

# The oracle prints the variant it read; the Unicode and ANSI arms share one
# text shape, so the prefix is stripped before comparing with our `str()`.
_VARIANT_PREFIX = re.compile(r"\b(Unicode|Ansi)(?=BlockId|PageId|ByteIndex|BlockRef|PageRef)")


def _golden(fixture: str, example: str) -> str:
    return (GOLDEN / fixture / f"{example}.txt").read_text()


def _stripped(text: str) -> str:
    return _VARIANT_PREFIX.sub("", text)


# --- denial -----------------------------------------------------------------


@pytest.mark.parametrize("index", [MAX_NODE_INDEX + 1, 1 << 40, -1])
def test_node_index_out_of_range_is_refused(index: int) -> None:
    with pytest.raises(PstFormatError):
        NodeId.from_parts(NodeIdType.HID, index)


@pytest.mark.parametrize("bad_type", [0x09, 0x14, 0x1E, 0x20, -1])
def test_unknown_node_type_is_refused_by_from_parts(bad_type: int) -> None:
    with pytest.raises(PstFormatError):
        NodeId.from_parts(bad_type, 1)  # type: ignore[arg-type]


@pytest.mark.parametrize("raw", [0x09, 0x14, 0x6B6, 0xFFFFFFFE])
def test_unknown_node_type_is_refused_by_id_type(raw: int) -> None:
    """A raw NID from the file is held; asking what it is is the refusal."""
    node = NodeId(raw)
    with pytest.raises(PstFormatError):
        _ = node.id_type


@pytest.mark.parametrize("raw", [-1, 1 << 32, 2**64])
def test_node_id_wider_than_u32_is_refused(raw: int) -> None:
    with pytest.raises(PstFormatError):
        NodeId(raw)


@pytest.mark.parametrize("index", [MAX_BLOCK_INDEX + 1, 1 << 64, -1])
def test_block_index_out_of_range_is_refused(index: int) -> None:
    with pytest.raises(PstFormatError):
        BlockId.from_parts(False, index)


@pytest.mark.parametrize("cls", [BlockId, PageId])
@pytest.mark.parametrize("raw", [-1, 1 << 64])
def test_u64_ids_wider_than_u64_are_refused(cls: type, raw: int) -> None:
    with pytest.raises(PstFormatError):
        cls(raw)


@pytest.mark.parametrize("value", [-1, 1 << 64])
def test_byte_index_wider_than_u64_is_refused(value: int) -> None:
    with pytest.raises(PstFormatError):
        ByteIndex(value)


@pytest.mark.parametrize("cls", [NodeId, BlockId, PageId, ByteIndex])
def test_non_integer_raw_is_refused(cls: type) -> None:
    """A float or a bool would pack, and would be a lie. Refuse them."""
    with pytest.raises(PstFormatError):
        cls(1.5)
    with pytest.raises(PstFormatError):
        cls(True)


@pytest.mark.parametrize("cls", [NodeId, BlockId, PageId, ByteIndex, BlockRef, PageRef])
def test_short_buffer_is_refused(cls: type) -> None:
    """Every length from empty to one byte short, at offset zero."""
    for length in range(cls.SIZE):
        with pytest.raises(PstFormatError):
            cls.unpack_from(bytes(length))


@pytest.mark.parametrize("cls", [NodeId, BlockId, PageId, ByteIndex, BlockRef, PageRef])
def test_offset_past_the_end_is_refused(cls: type) -> None:
    buf = bytes(cls.SIZE * 2)
    with pytest.raises(PstFormatError):
        cls.unpack_from(buf, cls.SIZE + 1)
    with pytest.raises(PstFormatError):
        cls.unpack_from(buf, len(buf))


@pytest.mark.parametrize("cls", [NodeId, BlockId, PageId, ByteIndex, BlockRef, PageRef])
def test_negative_offset_is_refused(cls: type) -> None:
    """`struct` would count a negative offset from the end. We do not.

    `-SIZE` is the case that matters: `struct` would happily read the last
    SIZE bytes of the buffer, which is exactly the misdirected read a
    file-driven offset gone negative must not be allowed to make.
    """
    buf = bytes(cls.SIZE * 2)
    for offset in (-cls.SIZE, -1, -cls.SIZE * 2, -(1 << 40)):
        with pytest.raises(PstFormatError):
            cls.unpack_from(buf, offset)


@pytest.mark.parametrize("cls", [NodeId, BlockId, PageId, ByteIndex, BlockRef, PageRef])
def test_every_refusal_is_a_pst_error(cls: type) -> None:
    """The contract: nothing but the PstError family escapes."""
    for attempt in (lambda: cls.unpack_from(b""), lambda: cls.unpack_from(bytes(64), -3)):
        try:
            attempt()
        except PstError:
            pass
        else:
            pytest.fail(f"{cls.__name__} accepted bad input")


def test_byte_indices_cannot_be_added() -> None:
    """An offset plus an offset is not a thing; the type must not allow it."""
    with pytest.raises(TypeError):
        _ = ByteIndex(1) + ByteIndex(2)  # type: ignore[operator]


def test_types_are_frozen() -> None:
    node = NodeId(0x21)
    with pytest.raises(AttributeError):
        node.raw = 0  # type: ignore[misc]


# --- the bit layouts --------------------------------------------------------


def test_node_id_layout() -> None:
    """[MS-PST] 2.2.2.1: low 5 bits type, high 27 bits index."""
    node = NodeId.from_parts(NodeIdType.NORMAL_FOLDER, 0x9)
    assert node.raw == (0x9 << 5) | 0x02 == 0x122
    assert node == NID_ROOT_FOLDER
    assert node.id_type is NodeIdType.NORMAL_FOLDER
    assert node.index == 0x9


def test_node_id_extremes() -> None:
    top = NodeId.from_parts(NodeIdType.LTP, MAX_NODE_INDEX)
    assert top.raw == 0xFFFFFFFF
    assert top.index == MAX_NODE_INDEX
    assert top.id_type is NodeIdType.LTP
    assert NodeId.from_parts(NodeIdType.HID, 0).raw == 0


def test_fixed_nids_are_the_spec_values() -> None:
    """[MS-PST] 2.4.1 — and each decodes to the type the section says it is."""
    assert NID_MESSAGE_STORE.raw == 0x21
    assert NID_MESSAGE_STORE.id_type is NodeIdType.INTERNAL
    assert NID_MESSAGE_STORE.index == 1
    assert NID_NAME_TO_ID_MAP.raw == 0x61
    assert NID_ROOT_FOLDER.raw == 0x122
    assert NID_SEARCH_GATHERER_FOLDER_QUEUE.raw == 0x321
    assert NID_SEARCH_GATHERER_FOLDER_QUEUE.index == 0x19


def test_every_node_type_round_trips_its_debug_name() -> None:
    for member in NodeIdType:
        assert NodeIdType.from_debug_name(member.debug_name) is member
    with pytest.raises(PstFormatError):
        NodeIdType.from_debug_name("NotAType")


def test_node_type_values_are_the_spec_table() -> None:
    """[MS-PST] 2.2.2.1: 0x09 and 0x14-0x1E are unassigned; 0x1F is LTP."""
    assert {int(m) for m in NodeIdType} == set(range(0x09)) | set(range(0x0A, 0x14)) | {0x1F}


def test_block_id_layout() -> None:
    """[MS-PST] 2.2.2.2: bit 1 internal, bit 0 reserved, rest index."""
    leaf = BlockId.from_parts(False, 0x4C)
    internal = BlockId.from_parts(True, 0x4C)
    assert leaf.raw == 0x4C << 2
    assert internal.raw == (0x4C << 2) | 0x2
    assert not leaf.is_internal
    assert internal.is_internal
    assert leaf.index == internal.index == 0x4C


def test_block_id_search_key_clears_only_the_reserved_bit() -> None:
    assert BlockId(0x133).search_key == 0x132
    assert BlockId(0x132).search_key == 0x132
    assert BlockId(0xFFFFFFFFFFFFFFFF).search_key == 0xFFFFFFFFFFFFFFFE
    assert BlockId(0xFFFFFFFFFFFFFFFF).index == MAX_BLOCK_INDEX


def test_page_id_is_flat() -> None:
    page = PageId(0x17D)
    assert page.index == page.search_key == 0x17D
    assert not page.is_internal


def test_block_ref_unpacks_little_endian_pairs() -> None:
    buf = bytes.fromhex("3201000000000000" "0046000000000000")
    ref = BlockRef.unpack_from(buf)
    assert ref.block == BlockId(0x132)
    assert ref.index == ByteIndex(0x4600)
    assert ref.pack() == buf
    page = PageRef.unpack_from(b"\xff" * 4 + buf, 4)
    assert page.page == PageId(0x132)
    assert page.index == ByteIndex(0x4600)


def test_unpack_accepts_memoryview_and_bytearray() -> None:
    raw = NID_ROOT_FOLDER.pack()
    assert NodeId.unpack_from(memoryview(raw)) == NID_ROOT_FOLDER
    assert NodeId.unpack_from(bytearray(raw)) == NID_ROOT_FOLDER


# --- the printed forms, exactly ---------------------------------------------


def test_str_forms_are_upstreams_debug_text_without_the_prefix() -> None:
    assert str(BlockId.from_parts(False, 0x4C)) == "BlockId { leaf: 0x4C }"
    assert str(BlockId.from_parts(True, 0x1)) == "BlockId { internal: 0x1 }"
    assert str(PageId(0x17F)) == "PageId: 0x17F"
    assert str(ByteIndex(0x42400)) == "ByteIndex { 0x42400 }"
    assert str(ByteIndex(0)) == "ByteIndex { 0x0 }"
    assert str(PageRef(PageId(0x17D), ByteIndex(0x9200))) == (
        "PageRef { page: PageId: 0x17D, index: ByteIndex { 0x9200 } }"
    )
    assert str(BlockRef(BlockId.from_parts(True, 0x1), ByteIndex(0x4F40))) == (
        "BlockRef { block: BlockId { internal: 0x1 }, index: ByteIndex { 0x4F40 } }"
    )
    assert str(NodeId.from_parts(NodeIdType.HID, 0x5)) == "NodeId { HeapNode: 0x5 }"
    assert str(NID_ROOT_FOLDER) == "NodeId { NormalFolder: 0x9 }"
    assert str(NodeId(0x6B6)) == "NodeId { invalid: 0x000006B6 }"


# --- differential: the goldens ----------------------------------------------

_HEADER_BLOCK = re.compile(r"^Next Block: \w*BlockId \{ (leaf|internal): 0x([0-9A-F]+) \}$", re.MULTILINE)
_HEADER_PAGE = re.compile(r"^Next Page: \w*PageId: 0x([0-9A-F]+)$", re.MULTILINE)
_HEADER_EOF = re.compile(r"^File EOF Index: \w*ByteIndex \{ 0x([0-9A-F]+) \}$", re.MULTILINE)
_HEADER_REF = re.compile(
    r"^(NBT|BBT) BlockRef: \w*PageRef \{ page: \w*PageId: 0x([0-9A-F]+), index: \w*ByteIndex \{ 0x([0-9A-F]+) \} \}$",
    re.MULTILINE,
)


def _one(pattern: re.Pattern[str], text: str, fixture: str) -> re.Match[str]:
    match = pattern.search(text)
    assert match is not None, f"{fixture}: read_header golden has no line matching {pattern.pattern!r}"
    return match


@pytest.mark.parametrize("fixture", GOLDEN_FIXTURES)
def test_header_ids_reproduce_the_golden(fixture: str) -> None:
    """Rebuild every id the oracle printed for the header and print it back."""
    text = _golden(fixture, "read_header")

    m = _one(_HEADER_BLOCK, text, fixture)
    block = BlockId.from_parts(m.group(1) == "internal", int(m.group(2), 16))
    assert f"Next Block: {block}" == _stripped(m.group(0)), fixture

    m = _one(_HEADER_PAGE, text, fixture)
    page = PageId(int(m.group(1), 16))
    assert f"Next Page: {page}" == _stripped(m.group(0)), fixture

    m = _one(_HEADER_EOF, text, fixture)
    eof = ByteIndex(int(m.group(1), 16))
    assert f"File EOF Index: {eof}" == _stripped(m.group(0)), fixture

    refs = list(_HEADER_REF.finditer(text))
    assert [m.group(1) for m in refs] == ["NBT", "BBT"], fixture
    for m in refs:
        ref = PageRef(PageId(int(m.group(2), 16)), ByteIndex(int(m.group(3), 16)))
        assert f"{m.group(1)} BlockRef: {ref}" == _stripped(m.group(0)), fixture


# [MS-PST] 2.2.2.6 HEADER (Unicode) and 2.2.2.7 ROOT: the byte offsets of the
# fields read_header prints. Fixed by the specification, so a test may read
# them without a header parser (P01 owns the parser; this only checks ids).
_HEADER_FIELDS: tuple[tuple[str, type, int], ...] = (
    ("Next Block", BlockId, 516),  # bidNextB
    ("Next Page", PageId, 32),  # bidNextP
    ("File EOF Index", ByteIndex, 180 + 4),  # ROOT.ibFileEof
    ("NBT BlockRef", PageRef, 180 + 36),  # ROOT.BREFNBT
    ("BBT BlockRef", PageRef, 180 + 52),  # ROOT.BREFBBT
)
_UNICODE_VERSIONS = {23, 36, 37}


@pytest.mark.parametrize("store", [FIXTURES / "Empty.pst", *public_fixture_paths()], ids=["Empty", *public_fixture_ids()])
def test_header_ids_from_the_file_bytes_match_the_golden(store: Path) -> None:
    """The one differential here whose VALUES come from somewhere other than
    the golden: the fixture's own header bytes, unpacked by these types and
    printed, must be the oracle's text. Endianness, the bit layouts, and the
    printed forms are all on the line at once.
    """
    header = store.read_bytes()[:600]
    if int.from_bytes(header[10:12], "little") not in _UNICODE_VERSIONS:
        pytest.skip(f"{store.name}: ANSI store, refused by design (ADR-0003)")
    golden = _stripped(_golden(store.stem, "read_header")).splitlines()
    for label, cls, offset in _HEADER_FIELDS:
        assert f"{label}: {cls.unpack_from(header, offset)}" in golden, (store.name, label)


_BTREE_NODE = re.compile(r"NodeId \{ (\w+): 0x([0-9A-F]+) \}")
_BTREE_REF = re.compile(
    r"\w*BlockRef \{ block: \w*BlockId \{ (leaf|internal): 0x([0-9A-F]+) \}, index: \w*ByteIndex \{ 0x([0-9A-F]+) \} \}"
)


@pytest.mark.parametrize("fixture", GOLDEN_FIXTURES)
def test_btree_ids_reproduce_the_golden(fixture: str) -> None:
    """Every NodeId and BlockRef in read_btrees, rebuilt from parts and printed back.

    This is what checks the type-name table: eighteen of the twenty node
    types appear across the corpus, plus the `invalid` form for a type the
    enum does not have.
    """
    text = _golden(fixture, "read_btrees")
    if not text:
        pytest.skip(f"{fixture}: the oracle refused this store (recorded exit code)")

    nodes = _BTREE_NODE.findall(text)
    refs = _BTREE_REF.finditer(text)
    assert nodes, f"{fixture}: read_btrees golden has no NodeId lines"

    seen_kinds: set[str] = set()
    for name, digits in nodes:
        if name == "invalid":
            node = NodeId(int(digits, 16))
        else:
            node = NodeId.from_parts(NodeIdType.from_debug_name(name), int(digits, 16))
        assert str(node) == f"NodeId {{ {name}: 0x{digits} }}", fixture
        seen_kinds.add(name)

    ref_count = 0
    for m in refs:
        ref = BlockRef(BlockId.from_parts(m.group(1) == "internal", int(m.group(2), 16)), ByteIndex(int(m.group(3), 16)))
        assert str(ref) == _stripped(m.group(0)), fixture
        ref_count += 1
    assert ref_count, f"{fixture}: read_btrees golden has no BlockRef lines"


def test_corpus_exercises_the_type_table_broadly() -> None:
    """A guard on the differential above: it must cover most of the enum,
    or a wrong name for a rare type would never be noticed."""
    seen: set[str] = set()
    for fixture in GOLDEN_FIXTURES:
        seen.update(name for name, _ in _BTREE_NODE.findall(_golden(fixture, "read_btrees")))
    assert "invalid" in seen
    assert len(seen - {"invalid"}) >= 15, sorted(seen)


# --- round-trip property, seeded --------------------------------------------


def test_pack_unpack_round_trips_over_random_values() -> None:
    rng = random.Random(20260915)
    for _ in range(500):
        node = NodeId.from_parts(rng.choice(list(NodeIdType)), rng.getrandbits(27))
        assert NodeId.unpack_from(node.pack()) == node
        assert NodeId.from_parts(node.id_type, node.index) == node

        block = BlockId.from_parts(rng.random() < 0.5, rng.getrandbits(62))
        assert BlockId.unpack_from(block.pack()) == block
        assert BlockId.from_parts(block.is_internal, block.index) == block

        page = PageId(rng.getrandbits(64))
        assert PageId.unpack_from(page.pack()) == page

        index = ByteIndex(rng.getrandbits(64))
        assert ByteIndex.unpack_from(index.pack()) == index

        ref = BlockRef(block, index)
        assert BlockRef.unpack_from(ref.pack()) == ref
        pref = PageRef(page, index)
        assert PageRef.unpack_from(pref.pack()) == pref

        # And at a random offset inside a larger buffer.
        pad = rng.randint(0, 40)
        buf = bytes(pad) + ref.pack() + bytes(rng.randint(0, 40))
        assert BlockRef.unpack_from(buf, pad) == ref


def test_random_raw_values_print_and_reparse() -> None:
    """`str()` is what the golden parsers consume: it must be parseable back."""
    rng = random.Random(1)
    for _ in range(500):
        node = NodeId(rng.getrandbits(32))
        m = _BTREE_NODE.fullmatch(str(node))
        assert m is not None, str(node)
        if m.group(1) == "invalid":
            assert NodeId(int(m.group(2), 16)) == node
        else:
            assert NodeId.from_parts(NodeIdType.from_debug_name(m.group(1)), int(m.group(2), 16)) == node
