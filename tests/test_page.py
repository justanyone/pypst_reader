"""Pages: refused when wrong, exact when right — the unit level under the walks.

Denial first: every check upstream makes on a page trailer, a B-tree page
or the density list page, provoked on a real page of Empty.pst (mutated in
memory, tests/corrupt.py) or on a synthetic page built by the same helpers,
must be a `PstFormatError` and nothing else. Then the things upstream reads
and does NOT check — the signature, the trailer's bid — pinned as accepted,
so that a later "fix" that starts refusing real stores is a red test and a
decision, not an accident. The walks and the oracle diff are in
tests/test_btree.py.
"""

from __future__ import annotations

import struct

import pytest

from pypstreader.block_sig import compute_sig
from pypstreader.errors import PstError, PstFormatError
from pypstreader.ndb.ids import BlockId, BlockRef, ByteIndex, NodeId, PageId, PageRef
from pypstreader.ndb.page import (
    BTREE_ENTRIES_SIZE,
    DENSITY_LIST_MAX_ENTRIES,
    DENSITY_LIST_OFFSET,
    MAX_BTREE_LEVEL,
    PAGE_DATA_SIZE,
    PAGE_SIZE,
    BlockBTreeEntry,
    BTreePage,
    DensityListEntry,
    DensityListPage,
    IntermediateEntry,
    NodeBTreeEntry,
    PageTrailer,
    PageType,
)
from tests import corrupt
from tests.conftest import FIXTURES

EMPTY = (FIXTURES / "Empty.pst").read_bytes()

# Empty.pst's two root pages, from its header (tests/test_header.py pins them).
NBT_ROOT = PageRef(PageId(0x17D), ByteIndex(0x9200))
BBT_ROOT = PageRef(PageId(0x17B), ByteIndex(0x8400))
DL_INDEX = ByteIndex(DENSITY_LIST_OFFSET)


def _page(data: bytes, index: ByteIndex) -> bytes:
    return data[index.value : index.value + PAGE_SIZE]


NBT_ROOT_PAGE = _page(EMPTY, NBT_ROOT.index)
BBT_ROOT_PAGE = _page(EMPTY, BBT_ROOT.index)
DL_PAGE = _page(EMPTY, DL_INDEX)


def _mutate_page(page: bytes, offset: int, value: bytes, *, index: ByteIndex, reseal: bool = True) -> bytes:
    """Overwrite bytes of a standalone page and (by default) fix its CRC."""
    out = corrupt.set_bytes(page, offset, value)
    return corrupt.reseal_page(out, 0) if reseal else out


# --- PageType ----------------------------------------------------------------


def test_page_type_values_are_the_specs() -> None:
    assert [int(t) for t in PageType] == [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86]
    assert [str(t) for t in PageType] == [
        "BlockBTree",
        "NodeBTree",
        "FreeMap",
        "AllocationPageMap",
        "AllocationMap",
        "FreePageMap",
        "DensityList",
    ]


@pytest.mark.parametrize("value", [0x00, 0x01, 0x7F, 0x87, 0xFF])
def test_unknown_page_type_is_refused(value: int) -> None:
    with pytest.raises(PstFormatError):
        PageType.from_byte(value)


def test_known_page_types_round_trip() -> None:
    for t in PageType:
        assert PageType.from_byte(int(t)) is t


def test_signature_rule_per_type() -> None:
    """BBT, NBT, DL carry compute_sig(ib, bid); the four maps carry 0 — [MS-PST] 2.2.2.7.1."""
    for t in (PageType.BBT, PageType.NBT, PageType.DL):
        assert t.is_signed
        assert t.signature(0x9200, 0x17D) == compute_sig(0x9200, 0x17D) == 0x937D
        # Only the low 32 bits of each input count (upstream's `as u32`).
        assert t.signature(0x9200 | (1 << 40), 0x17D | (1 << 33)) == t.signature(0x9200, 0x17D)
    for t in (PageType.FMAP, PageType.PMAP, PageType.AMAP, PageType.FPMAP):
        assert not t.is_signed
        assert t.signature(0x9200, 0x17D) == 0


# --- PageTrailer: denial ----------------------------------------------------


def test_trailer_short_buffer_is_refused() -> None:
    for length in (0, 1, 15):
        with pytest.raises(PstFormatError):
            PageTrailer.unpack_from(NBT_ROOT_PAGE[-16:][:length], 0)
    with pytest.raises(PstFormatError):
        PageTrailer.unpack_from(NBT_ROOT_PAGE, PAGE_SIZE - 15)
    with pytest.raises(PstFormatError):
        PageTrailer.unpack_from(NBT_ROOT_PAGE, -1)


def test_trailer_ptype_repeat_mismatch_is_refused() -> None:
    bad = corrupt.set_u8(NBT_ROOT_PAGE, corrupt.PAGE_TRAILER_OFFSET + 1, 0x80)
    with pytest.raises(PstFormatError) as info:
        PageTrailer.unpack_from(bad)
    assert "ptypeRepeat" in str(info.value)


@pytest.mark.parametrize("value", [0x00, 0x87, 0xFF])
def test_trailer_unknown_type_is_refused(value: int) -> None:
    bad = corrupt.set_bytes(NBT_ROOT_PAGE, corrupt.PAGE_TRAILER_OFFSET, bytes([value, value]))
    with pytest.raises(PstFormatError):
        PageTrailer.unpack_from(bad)


def test_trailer_verify_refuses_a_flipped_data_byte() -> None:
    trailer = PageTrailer.unpack_from(NBT_ROOT_PAGE)
    trailer.verify(NBT_ROOT_PAGE, NBT_ROOT.index)
    for offset in (0, 100, PAGE_DATA_SIZE - 1):
        with pytest.raises(PstFormatError) as info:
            trailer.verify(corrupt.flip_byte(NBT_ROOT_PAGE, offset), NBT_ROOT.index)
        assert "CRC" in str(info.value)


def test_trailer_verify_refuses_a_wrong_length() -> None:
    trailer = PageTrailer.unpack_from(NBT_ROOT_PAGE)
    with pytest.raises(PstFormatError):
        trailer.verify(NBT_ROOT_PAGE[:-1], NBT_ROOT.index)
    with pytest.raises(PstFormatError):
        trailer.verify(NBT_ROOT_PAGE + b"\0", NBT_ROOT.index)


# --- PageTrailer: what upstream reads and does not check --------------------


def test_trailer_signature_is_carried_not_enforced() -> None:
    """Upstream never compares wSig on read (pstd-inline-cid has zeros); neither do we."""
    trailer = PageTrailer.unpack_from(NBT_ROOT_PAGE)
    assert trailer.signature == trailer.expected_signature(NBT_ROOT.index) == 0x9200 ^ 0x17D
    wrong = corrupt.reseal_page(corrupt.set_u16(NBT_ROOT_PAGE, corrupt.PAGE_TRAILER_OFFSET + 2, 0), 0)
    bad = PageTrailer.unpack_from(wrong)
    assert bad.signature == 0 != bad.expected_signature(NBT_ROOT.index)
    bad.verify(wrong, NBT_ROOT.index)  # accepted
    assert BTreePage.parse(wrong, PageType.NBT, NBT_ROOT.index).trailer.signature == 0


def test_trailer_verify_ignores_the_trailer_bytes() -> None:
    """The CRC covers the 496 data bytes only ([MS-PST] 2.2.2.7.1); the bid is not verified."""
    other_bid = corrupt.set_bytes(NBT_ROOT_PAGE, corrupt.PAGE_TRAILER_OFFSET + 8, (0xABCDEF).to_bytes(8, "little"))
    trailer = PageTrailer.unpack_from(other_bid)
    assert trailer.block_id == PageId(0xABCDEF)
    trailer.verify(other_bid, NBT_ROOT.index)


def test_empty_pst_root_trailers() -> None:
    nbt = PageTrailer.unpack_from(NBT_ROOT_PAGE)
    assert nbt.page_type is PageType.NBT
    assert nbt.block_id == NBT_ROOT.page
    bbt = PageTrailer.unpack_from(BBT_ROOT_PAGE)
    assert bbt.page_type is PageType.BBT
    assert bbt.block_id == BBT_ROOT.page
    assert bbt.signature == bbt.expected_signature(BBT_ROOT.index)
    assert PageTrailer.SIZE == 16 and PAGE_SIZE == 512 and PAGE_DATA_SIZE == 496 and BTREE_ENTRIES_SIZE == 488


# --- the entries ---------------------------------------------------------------


def test_entry_sizes_are_the_specs() -> None:
    assert IntermediateEntry.SIZE == 24
    assert BlockBTreeEntry.SIZE == 24
    assert NodeBTreeEntry.SIZE == 32


@pytest.mark.parametrize("entry_type", [IntermediateEntry, BlockBTreeEntry, NodeBTreeEntry])
def test_entry_short_buffer_is_refused(entry_type: type) -> None:
    for length in (0, entry_type.SIZE - 1):
        with pytest.raises(PstFormatError):
            entry_type.unpack_from(bytes(length))
    with pytest.raises(PstFormatError):
        entry_type.unpack_from(bytes(entry_type.SIZE), 1)
    with pytest.raises(PstFormatError):
        entry_type.unpack_from(bytes(entry_type.SIZE), -1)


def test_intermediate_entry_fields() -> None:
    entry = IntermediateEntry.unpack_from(corrupt.bt_entry(0x21, 0x17D, 0x9200))
    assert entry == IntermediateEntry(0x21, PageRef(PageId(0x17D), ByteIndex(0x9200)))


def test_block_entry_fields_and_key() -> None:
    entry = BlockBTreeEntry.unpack_from(corrupt.bbt_entry(0x4D, 0x4C00, 156, 4, padding=0xDEAD))
    assert entry == BlockBTreeEntry(BlockRef(BlockId(0x4D), ByteIndex(0x4C00)), 156, 4)
    # The key clears the reserved bit: 0x4D and 0x4C are the same block.
    assert entry.key == 0x4C
    assert BlockBTreeEntry.unpack_from(corrupt.bbt_entry(0x4C, 0x4C00, 156)).key == 0x4C


def test_node_entry_fields_and_options() -> None:
    entry = NodeBTreeEntry.unpack_from(corrupt.nbt_entry(0x122, 0x42, 0x9A, 0x122, padding=7))
    assert entry == NodeBTreeEntry(NodeId(0x122), BlockId(0x42), BlockId(0x9A), NodeId(0x122))
    assert entry.key == 0x122
    empty = NodeBTreeEntry.unpack_from(corrupt.nbt_entry(0x1E1, 0, 0, 0))
    assert empty.sub_node is None and empty.parent is None
    assert empty.data == BlockId(0) and empty.data.search_key == 0
    # bidSub with only the reserved bit set is still "none" (search_key == 0), as upstream.
    assert NodeBTreeEntry.unpack_from(corrupt.nbt_entry(0x1E1, 0, 1, 0)).sub_node is None


@pytest.mark.parametrize("nid", [1 << 32, 0xFFFFFFFF00000021, 1 << 63])
def test_node_entry_nid_wider_than_32_bits_is_refused(nid: int) -> None:
    """Upstream's InvalidNodeBTreeEntryNodeId: the u64 must hold a zero-extended NID."""
    with pytest.raises(PstFormatError):
        NodeBTreeEntry.unpack_from(corrupt.nbt_entry(nid, 0x42))


def test_node_entry_unknown_node_type_is_carried() -> None:
    """A NID whose 5-bit type is unknown is read (goldens print it `invalid`); refused only at `id_type`."""
    entry = NodeBTreeEntry.unpack_from(corrupt.nbt_entry(0x6B6, 0x9))
    assert str(entry.node) == "NodeId { invalid: 0x000006B6 }"
    with pytest.raises(PstFormatError):
        _ = entry.node.id_type


# --- BTreePage: denial, each of upstream's checks ---------------------------


def test_good_root_pages_parse() -> None:
    nbt = BTreePage.parse(NBT_ROOT_PAGE, PageType.NBT, NBT_ROOT.index)
    assert nbt.level == 1 and not nbt.is_leaf and nbt.page_type is PageType.NBT
    assert len(nbt.entries) == 4 and nbt.max_entries == 20 and nbt.entry_size == 24
    assert all(isinstance(e, IntermediateEntry) for e in nbt.entries)
    bbt = BTreePage.parse(BBT_ROOT_PAGE, PageType.BBT, BBT_ROOT.index)
    assert bbt.level == 1 and [e.key for e in bbt.entries] == [4, 128]


def test_page_wrong_length_is_refused() -> None:
    for page in (NBT_ROOT_PAGE[:-1], NBT_ROOT_PAGE + b"\0", b"", NBT_ROOT_PAGE[:PAGE_DATA_SIZE]):
        with pytest.raises(PstFormatError):
            BTreePage.parse(page, PageType.NBT, NBT_ROOT.index)


def test_non_btree_kind_is_refused() -> None:
    for kind in (PageType.AMAP, PageType.DL):
        with pytest.raises(PstFormatError):
            BTreePage.parse(NBT_ROOT_PAGE, kind, NBT_ROOT.index)


def test_count_over_max_is_refused() -> None:
    bad = _mutate_page(NBT_ROOT_PAGE, corrupt.BTREE_HEADER_OFFSET, bytes([21]), index=NBT_ROOT.index)
    with pytest.raises(PstFormatError) as info:
        BTreePage.parse(bad, PageType.NBT, NBT_ROOT.index)
    assert "cEnt" in str(info.value)


def test_count_at_max_is_accepted() -> None:
    """cEnt == cEntMax passes: the entries beyond the real ones are zero bytes, which parse."""
    page = _mutate_page(NBT_ROOT_PAGE, corrupt.BTREE_HEADER_OFFSET, bytes([20]), index=NBT_ROOT.index)
    assert len(BTreePage.parse(page, PageType.NBT, NBT_ROOT.index).entries) == 20


@pytest.mark.parametrize(("kind", "page", "index", "too_small"), [
    (PageType.NBT, NBT_ROOT_PAGE, NBT_ROOT.index, 23),
    (PageType.BBT, BBT_ROOT_PAGE, BBT_ROOT.index, 0),
])
def test_entry_size_smaller_than_the_structure_is_refused(kind: PageType, page: bytes, index: ByteIndex, too_small: int) -> None:
    bad = _mutate_page(page, corrupt.BTREE_HEADER_OFFSET + 2, bytes([too_small]), index=index)
    with pytest.raises(PstFormatError) as info:
        BTreePage.parse(bad, kind, index)
    assert "cbEnt" in str(info.value)


def test_entry_size_is_the_stride_and_may_exceed_the_structure() -> None:
    """[MS-PST] 2.2.2.7.7.1: cbEnt MUST be used to advance; a padded 32-byte BTENTRY stride parses."""
    entries = [corrupt.bt_entry(k, 0x100 + k, 0x1000 * k) + bytes(8) for k in (1, 2, 3)]
    page = corrupt.btree_page(corrupt.PTYPE_BBT, 1, entries, 0x7, 0x2000, entry_size=32, max_entries=15)
    parsed = BTreePage.parse(page, PageType.BBT, ByteIndex(0x2000))
    assert parsed.entry_size == 32 and [e.key for e in parsed.entries] == [1, 2, 3]
    assert parsed.entries[2] == IntermediateEntry(3, PageRef(PageId(0x103), ByteIndex(0x3000)))


def test_leaf_entry_size_for_the_wrong_level_is_refused() -> None:
    """An NBT leaf with cbEnt 24 (a BTENTRY's size) cannot hold a 32-byte NBTENTRY."""
    entries = [corrupt.nbt_entry(0x21, 0x2)]
    page = corrupt.btree_page(corrupt.PTYPE_NBT, 0, entries, 0x7, 0x2000, entry_size=24, max_entries=20)
    with pytest.raises(PstFormatError):
        BTreePage.parse(page, PageType.NBT, ByteIndex(0x2000))


def test_max_entries_over_what_fits_is_refused() -> None:
    bad = _mutate_page(NBT_ROOT_PAGE, corrupt.BTREE_HEADER_OFFSET + 1, bytes([21]), index=NBT_ROOT.index)
    with pytest.raises(PstFormatError) as info:
        BTreePage.parse(bad, PageType.NBT, NBT_ROOT.index)
    assert "cEntMax" in str(info.value)


@pytest.mark.parametrize("level", [MAX_BTREE_LEVEL + 1, 0x80, 0xFF])
def test_level_over_eight_is_a_format_error(level: int) -> None:
    """Upstream's InvalidBTreePageLevel — a format refusal, not a limit trip."""
    bad = _mutate_page(NBT_ROOT_PAGE, corrupt.BTREE_HEADER_OFFSET + 3, bytes([level]), index=NBT_ROOT.index)
    with pytest.raises(PstFormatError) as info:
        BTreePage.parse(bad, PageType.NBT, NBT_ROOT.index)
    assert "cLevel" in str(info.value)


def test_level_eight_is_accepted() -> None:
    page = corrupt.btree_page(corrupt.PTYPE_NBT, MAX_BTREE_LEVEL, [corrupt.bt_entry(1, 2, 0x200)], 0x7, 0x2000)
    assert BTreePage.parse(page, PageType.NBT, ByteIndex(0x2000)).level == 8


def test_padding_not_zero_is_refused() -> None:
    bad = _mutate_page(NBT_ROOT_PAGE, corrupt.BTREE_HEADER_OFFSET + 4, b"\x01\0\0\0", index=NBT_ROOT.index)
    with pytest.raises(PstFormatError) as info:
        BTreePage.parse(bad, PageType.NBT, NBT_ROOT.index)
    assert "dwPadding" in str(info.value)


def test_bad_crc_is_refused() -> None:
    for offset in (0, 200, corrupt.BTREE_HEADER_OFFSET - 1):
        with pytest.raises(PstFormatError) as info:
            BTreePage.parse(corrupt.flip_byte(NBT_ROOT_PAGE, offset), PageType.NBT, NBT_ROOT.index)
        assert "CRC" in str(info.value)
    # A flip in the header fields is refused by the field check that precedes the CRC (upstream's order).
    with pytest.raises(PstFormatError):
        BTreePage.parse(corrupt.flip_byte(NBT_ROOT_PAGE, corrupt.BTREE_HEADER_OFFSET + 6), PageType.NBT, NBT_ROOT.index)


def test_flipped_trailer_byte_outside_the_crc_is_a_type_or_ptype_error() -> None:
    bad = corrupt.flip_byte(NBT_ROOT_PAGE, corrupt.PAGE_TRAILER_OFFSET)  # ptype only
    with pytest.raises(PstFormatError):
        BTreePage.parse(bad, PageType.NBT, NBT_ROOT.index)


@pytest.mark.parametrize("ptype", [0x82, 0x83, 0x84, 0x85, 0x86])
def test_map_or_dl_page_in_a_btree_is_refused(ptype: int) -> None:
    bad = _mutate_page(NBT_ROOT_PAGE, corrupt.PAGE_TRAILER_OFFSET, bytes([ptype, ptype]), index=NBT_ROOT.index)
    with pytest.raises(PstFormatError):
        BTreePage.parse(bad, PageType.NBT, NBT_ROOT.index)


def test_leaf_of_the_other_tree_is_refused() -> None:
    """A BBT-typed leaf handed to the NBT is refused (upstream's UnexpectedPageType on the leaf ctor).

    The stride is 32 so that an NBTENTRY would fit: only the page type can refuse it.
    """
    entries = [corrupt.bbt_entry(0x4C, 0x4C00, 156) + bytes(8)]
    page = corrupt.btree_page(corrupt.PTYPE_BBT, 0, entries, 0x7, 0x2000, entry_size=32, max_entries=15)
    assert BTreePage.parse(page, PageType.BBT, ByteIndex(0x2000)).entries[0].size == 156
    with pytest.raises(PstFormatError) as info:
        BTreePage.parse(page, PageType.NBT, ByteIndex(0x2000))
    assert "leaf page" in str(info.value)


def test_intermediate_of_either_type_is_accepted_as_upstream() -> None:
    """Upstream's UnicodeBTreeEntryPage::new accepts BBT or NBT for an intermediate page; pinned."""
    page = corrupt.btree_page(corrupt.PTYPE_BBT, 1, [corrupt.bt_entry(1, 2, 0x200)], 0x7, 0x2000)
    assert BTreePage.parse(page, PageType.NBT, ByteIndex(0x2000)).page_type is PageType.BBT


def test_leaf_nbt_entry_over_32_bits_is_refused_in_a_page() -> None:
    page = corrupt.btree_page(corrupt.PTYPE_NBT, 0, [corrupt.nbt_entry(1 << 32, 0x2)], 0x7, 0x2000)
    with pytest.raises(PstFormatError):
        BTreePage.parse(page, PageType.NBT, ByteIndex(0x2000))


def test_every_refusal_is_a_pst_error() -> None:
    """For any 512 bytes: a page or a PstError, nothing else."""
    attempts = [bytes(PAGE_SIZE), b"\xff" * PAGE_SIZE, corrupt.flip_byte(NBT_ROOT_PAGE, 490), NBT_ROOT_PAGE[:100]]
    for data in attempts:
        for kind in (PageType.NBT, PageType.BBT):
            try:
                BTreePage.parse(data, kind, NBT_ROOT.index)
            except PstError:
                pass
            else:
                pytest.fail("accepted garbage")


def test_parsed_pages_are_frozen() -> None:
    page = BTreePage.parse(NBT_ROOT_PAGE, PageType.NBT, NBT_ROOT.index)
    with pytest.raises(AttributeError):
        page.level = 0  # type: ignore[misc]
    with pytest.raises(AttributeError):
        page.trailer.crc = 0  # type: ignore[misc]
    assert isinstance(page.entries, tuple)


def test_parse_accepts_memoryview_and_bytearray() -> None:
    a = BTreePage.parse(memoryview(NBT_ROOT_PAGE), PageType.NBT, NBT_ROOT.index)
    b = BTreePage.parse(bytearray(NBT_ROOT_PAGE), PageType.NBT, NBT_ROOT.index)
    assert a == b == BTreePage.parse(NBT_ROOT_PAGE, PageType.NBT, NBT_ROOT.index)


# --- the density list -----------------------------------------------------------


def test_empty_pst_density_list() -> None:
    page = DensityListPage.parse(DL_PAGE, DL_INDEX)
    assert page.backfill_complete is False and page.current_page == 0 and page.entries == ()
    assert page.trailer.page_type is PageType.DL and page.trailer.block_id == PageId(0x17F)
    assert page.trailer.signature == 0x437F == page.trailer.expected_signature(DL_INDEX)
    assert page.trailer.crc == 0  # the CRC of 496 zero bytes, un-inverted, is 0
    assert DENSITY_LIST_MAX_ENTRIES == 119 and DENSITY_LIST_OFFSET == 0x4200


def test_density_list_entries_split_their_bits() -> None:
    raw = (0xABC << 20) | 0x12345
    page = DensityListPage.parse(corrupt.density_list_page([raw, 7], 0x17F, backfill_complete=True, current_page=9))
    assert page.backfill_complete is True and page.current_page == 9
    assert page.entries == (DensityListEntry(raw), DensityListEntry(7))
    assert page.entries[0].page == 0x12345 and page.entries[0].free_slots == 0xABC
    assert str(page.entries[1]) == "DensityListPageEntry(7)"


def test_density_list_full_page_is_accepted() -> None:
    page = DensityListPage.parse(corrupt.density_list_page(list(range(119)), 0x17F))
    assert len(page.entries) == 119


def test_density_list_count_over_119_is_refused() -> None:
    with pytest.raises(PstFormatError):
        DensityListPage.parse(corrupt.density_list_page([], 0x17F, count=120))


def test_density_list_padding_is_refused() -> None:
    with pytest.raises(PstFormatError):
        DensityListPage.parse(corrupt.density_list_page([], 0x17F, padding=1))
    with pytest.raises(PstFormatError):
        DensityListPage.parse(corrupt.density_list_page([], 0x17F, tail=b"\0" * 11 + b"\x01"))


def test_density_list_wrong_type_bad_crc_and_length_are_refused() -> None:
    not_dl = corrupt.reseal_page(corrupt.set_bytes(DL_PAGE, corrupt.PAGE_TRAILER_OFFSET, b"\x80\x80"), 0)
    with pytest.raises(PstFormatError):
        DensityListPage.parse(not_dl, DL_INDEX)
    with pytest.raises(PstFormatError):
        DensityListPage.parse(corrupt.flip_byte(DL_PAGE, 8), DL_INDEX)
    with pytest.raises(PstFormatError):
        DensityListPage.parse(DL_PAGE[:-1], DL_INDEX)
    with pytest.raises(PstFormatError):
        DensityListPage.parse(bytes(PAGE_SIZE), DL_INDEX)  # ptype 0: upstream's InvalidPageType(0)


def test_density_list_only_reads_the_counted_entries() -> None:
    """Bytes past cEntDList are covered by the CRC but never interpreted ([MS-PST] 2.2.2.7.2)."""
    page_bytes = corrupt.density_list_page([5], 0x17F)
    page_bytes = corrupt.reseal_page(corrupt.set_u32(page_bytes, 12, 0xFFFFFFFF), 0)
    assert DensityListPage.parse(page_bytes).entries == (DensityListEntry(5),)


def test_trailer_struct_layout_is_the_specs() -> None:
    """ptype, ptypeRepeat, wSig, dwCRC, bid — read straight off the bytes, independent of the module."""
    ptype, rep, sig, crc, bid = struct.unpack_from("<BBHIQ", NBT_ROOT_PAGE, 496)
    trailer = PageTrailer.unpack_from(NBT_ROOT_PAGE)
    assert (ptype, rep, sig, crc, bid) == (0x81, 0x81, trailer.signature, trailer.crc, trailer.block_id.raw)
