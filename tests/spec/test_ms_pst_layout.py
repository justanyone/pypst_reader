"""[MS-PST] 2.2.2.1–2.2.2.6: the identifier bit layouts and the header/root field offsets.

Offsets are DERIVED by summing the field widths the spec lists, in the order
it lists them — the arithmetic is the `_offsets()` helper, so a reader can
check any one offset against the page. Then the real bytes of Empty.pst and
the public corpus are read at those offsets and the fields the spec marks
MUST are asserted. No pypstreader header module is imported: this file must stay
valid whatever shape P01 takes, because it is what P01 gets checked against.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from pypstreader.errors import PstFormatError
from pypstreader.ndb.ids import (
    BLOCK_ID_FORMAT,
    BLOCK_REF_FORMAT,
    BYTE_INDEX_FORMAT,
    MAX_BLOCK_INDEX,
    MAX_NODE_INDEX,
    NODE_ID_FORMAT,
    BlockId,
    BlockRef,
    ByteIndex,
    NodeId,
    NodeIdType,
)
from tests.conftest import FIXTURES, public_fixture_ids, public_fixture_paths

# --- 2.2.2.1 NID ---------------------------------------------------------------


def test_nid_type_table_is_verbatim() -> None:
    """[MS-PST] 2.2.2.1, the nidType table: 20 values. Verbatim."""
    spec = {
        0x00: "NID_TYPE_HID", 0x01: "NID_TYPE_INTERNAL", 0x02: "NID_TYPE_NORMAL_FOLDER",
        0x03: "NID_TYPE_SEARCH_FOLDER", 0x04: "NID_TYPE_NORMAL_MESSAGE", 0x05: "NID_TYPE_ATTACHMENT",
        0x06: "NID_TYPE_SEARCH_UPDATE_QUEUE", 0x07: "NID_TYPE_SEARCH_CRITERIA_OBJECT",
        0x08: "NID_TYPE_ASSOC_MESSAGE", 0x0A: "NID_TYPE_CONTENTS_TABLE_INDEX",
        0x0B: "NID_TYPE_RECEIVE_FOLDER_TABLE", 0x0C: "NID_TYPE_OUTGOING_QUEUE_TABLE",
        0x0D: "NID_TYPE_HIERARCHY_TABLE", 0x0E: "NID_TYPE_CONTENTS_TABLE",
        0x0F: "NID_TYPE_ASSOC_CONTENTS_TABLE", 0x10: "NID_TYPE_SEARCH_CONTENTS_TABLE",
        0x11: "NID_TYPE_ATTACHMENT_TABLE", 0x12: "NID_TYPE_RECIPIENT_TABLE",
        0x13: "NID_TYPE_SEARCH_TABLE_INDEX", 0x1F: "NID_TYPE_LTP",
    }  # fmt: skip
    ours = {int(m): f"NID_TYPE_{m.name}" for m in NodeIdType}
    assert ours == spec


def test_nid_is_5_bits_of_type_then_27_of_index() -> None:
    """[MS-PST] 2.2.2.1: nidType (5 bits), nidIndex (27 bits), 32 bits total. Derived."""
    assert struct.calcsize(NODE_ID_FORMAT) == 4 and NodeId.SIZE == 4
    assert MAX_NODE_INDEX == 2**27 - 1
    assert NodeId.from_parts(NodeIdType.NORMAL_FOLDER, 2**27 - 1).raw == 0xFFFF_FFE2
    with pytest.raises(PstFormatError):
        NodeId.from_parts(NodeIdType.NORMAL_FOLDER, 2**27)


# [MS-PST] 2.4.1 "Special Internal NIDs", verbatim values; the type and index
# columns are derived: type = value & 0x1F, index = value >> 5.
SPECIAL_NIDS = [
    (0x21, "NID_MESSAGE_STORE", NodeIdType.INTERNAL, 1),
    (0x61, "NID_NAME_TO_ID_MAP", NodeIdType.INTERNAL, 3),
    (0xA1, "NID_NORMAL_FOLDER_TEMPLATE", NodeIdType.INTERNAL, 5),
    (0xC1, "NID_SEARCH_FOLDER_TEMPLATE", NodeIdType.INTERNAL, 6),
    (0x122, "NID_ROOT_FOLDER", NodeIdType.NORMAL_FOLDER, 9),
    (0x1E1, "NID_SEARCH_MANAGEMENT_QUEUE", NodeIdType.INTERNAL, 15),
    (0x201, "NID_SEARCH_ACTIVITY_LIST", NodeIdType.INTERNAL, 16),
    (0x321, "NID_SEARCH_GATHERER_FOLDER_QUEUE", NodeIdType.INTERNAL, 25),
]


@pytest.mark.parametrize(("raw", "name", "id_type", "index"), SPECIAL_NIDS, ids=[n for _, n, _, _ in SPECIAL_NIDS])
def test_special_nids_split_as_the_layout_says(raw: int, name: str, id_type: NodeIdType, index: int) -> None:
    """[MS-PST] 2.4.1 values (verbatim), split by the 2.2.2.1 layout (derived)."""
    nid = NodeId(raw)
    assert nid.id_type is id_type, name
    assert nid.index == index, name
    assert NodeId.from_parts(id_type, index).raw == raw, name
    assert NodeId.unpack_from(struct.pack("<I", raw)).raw == raw, name


# --- 2.2.2.2 BID ---------------------------------------------------------------


def test_bid_flag_bits_and_index_width() -> None:
    """[MS-PST] 2.2.2.2 (Unicode): bit 0 "r" reserved, bit 1 "i" internal, bidIndex 62 bits. Derived."""
    assert struct.calcsize(BLOCK_ID_FORMAT) == 8 and BlockId.SIZE == 8
    assert MAX_BLOCK_INDEX == 2**62 - 1
    assert BlockId(0b110).is_internal and BlockId(0b110).index == 1
    assert not BlockId(0b100).is_internal and BlockId(0b100).index == 1
    assert BlockId.from_parts(True, 1).raw == 0b110
    assert BlockId.from_parts(False, 2**62 - 1).raw == 0xFFFF_FFFF_FFFF_FFFC
    with pytest.raises(PstFormatError):
        BlockId.from_parts(False, 2**62)


def test_bid_reserved_bit_is_ignored_for_lookup() -> None:
    """[MS-PST] 2.2.2.2: "Readers MUST ignore this bit and treat it as zero before looking up the BID". Verbatim rule."""
    assert BlockId(0b101).search_key == BlockId(0b100).search_key == 0b100
    assert BlockId(0b101).search_key != BlockId(0b110).search_key


def test_block_bids_advance_by_four() -> None:
    """[MS-PST] 2.2.2.2: block BIDs "increment by 4 each time a new one is assigned". Derived."""
    assert BlockId.from_parts(False, 8).raw - BlockId.from_parts(False, 7).raw == 4


# --- 2.2.2.3 IB, 2.2.2.4 BREF --------------------------------------------------


def test_ib_is_64_bits_and_bref_is_bid_then_ib() -> None:
    """[MS-PST] 2.2.2.3 (IB: 64 bits Unicode) and 2.2.2.4 (BREF: bid then ib, 16 bytes). Derived."""
    assert struct.calcsize(BYTE_INDEX_FORMAT) == 8 and ByteIndex.SIZE == 8
    assert struct.calcsize(BLOCK_REF_FORMAT) == 16 and BlockRef.SIZE == 16
    raw = struct.pack("<QQ", 0x2A4, 0x5000)
    bref = BlockRef.unpack_from(raw)
    assert bref.block.raw == 0x2A4 and bref.index.value == 0x5000
    assert bref.pack() == raw


# --- 2.2.2.5 ROOT and 2.2.2.6 HEADER: offsets summed from the spec's widths ---

# (field, width) in the spec's order. Verbatim widths; the offsets are the
# running sum, which is the only arithmetic in this file.
ROOT_UNICODE = [
    ("dwReserved", 4), ("ibFileEof", 8), ("ibAMapLast", 8), ("cbAMapFree", 8), ("cbPMapFree", 8),
    ("BREFNBT", 16), ("BREFBBT", 16), ("fAMapValid", 1), ("bReserved", 1), ("wReserved", 2),
]  # fmt: skip
ROOT_ANSI = [
    ("dwReserved", 4), ("ibFileEof", 4), ("ibAMapLast", 4), ("cbAMapFree", 4), ("cbPMapFree", 4),
    ("BREFNBT", 8), ("BREFBBT", 8), ("fAMapValid", 1), ("bReserved", 1), ("wReserved", 2),
]  # fmt: skip
HEADER_UNICODE = [
    ("dwMagic", 4), ("dwCRCPartial", 4), ("wMagicClient", 2), ("wVer", 2), ("wVerClient", 2),
    ("bPlatformCreate", 1), ("bPlatformAccess", 1), ("dwReserved1", 4), ("dwReserved2", 4),
    ("bidUnused", 8), ("bidNextP", 8), ("dwUnique", 4), ("rgnid", 128), ("qwUnused", 8),
    ("root", 72), ("dwAlign", 4), ("rgbFM", 128), ("rgbFP", 128), ("bSentinel", 1),
    ("bCryptMethod", 1), ("rgbReserved", 2), ("bidNextB", 8), ("dwCRCFull", 4),
    ("rgbReserved2", 3), ("bReserved", 1), ("rgbReserved3", 32),
]  # fmt: skip
HEADER_ANSI = [
    ("dwMagic", 4), ("dwCRCPartial", 4), ("wMagicClient", 2), ("wVer", 2), ("wVerClient", 2),
    ("bPlatformCreate", 1), ("bPlatformAccess", 1), ("dwReserved1", 4), ("dwReserved2", 4),
    ("bidNextB", 4), ("bidNextP", 4), ("dwUnique", 4), ("rgnid", 128), ("root", 40),
    ("rgbFM", 128), ("rgbFP", 128), ("bSentinel", 1), ("bCryptMethod", 1), ("rgbReserved", 2),
    ("ullReserved", 8), ("dwReserved", 4), ("rgbReserved2", 3), ("bReserved", 1), ("rgbReserved3", 32),
]  # fmt: skip


def _offsets(layout: list[tuple[str, int]]) -> dict[str, int]:
    out, pos = {}, 0
    for name, width in layout:
        out[name] = pos
        pos += width
    out["__size__"] = pos
    return out


U = _offsets(HEADER_UNICODE)
A = _offsets(HEADER_ANSI)
RU = _offsets(ROOT_UNICODE)
RA = _offsets(ROOT_ANSI)

MAGIC = 0x4E444221  # [MS-PST] 2.2.2.6 dwMagic "{ 0x21, 0x42, 0x44, 0x4E }" ("!BDN"), little-endian
MAGIC_CLIENT = 0x4D53  # wMagicClient "{ 0x53, 0x4D }" — the BYTES; as a little-endian WORD that is 0x4D53 ("SM")
SENTINEL = 0x80
CRYPT_METHODS = {0x00, 0x01, 0x02, 0x10}
AMAP_FIRST, AMAP_INTERVAL = 0x4400, 253_952  # [MS-PST] 2.2.2.7.2
PTYPE_BBT, PTYPE_NBT = 0x80, 0x81  # [MS-PST] 2.2.2.7.1


def test_derived_header_offsets_are_the_well_known_ones() -> None:
    """[MS-PST] 2.2.2.6 Unicode: the offsets every PST tool hard-codes, here summed from the widths."""
    assert U["dwMagic"] == 0x00 and U["dwCRCPartial"] == 0x04 and U["wMagicClient"] == 0x08
    assert U["wVer"] == 0x0A and U["wVerClient"] == 0x0C
    assert U["bidNextP"] == 0x20 and U["dwUnique"] == 0x28 and U["rgnid"] == 0x2C
    assert U["root"] == 0xB4 and U["rgbFM"] == 0x100
    assert U["bSentinel"] == 0x200 and U["bCryptMethod"] == 0x201
    assert U["bidNextB"] == 0x204 and U["dwCRCFull"] == 0x20C
    assert U["__size__"] == 564
    assert RU["__size__"] == 72 and RA["__size__"] == 40 and A["__size__"] == 512
    assert A["root"] == 0xA4 and A["bSentinel"] == 0x1CC and A["bCryptMethod"] == 0x1CD


def test_magic_bytes_are_a_little_endian_bdn() -> None:
    """[MS-PST] 2.2.2.6 dwMagic and wMagicClient. Verbatim bytes; the ints are derived."""
    assert struct.unpack("<I", b"!BDN")[0] == MAGIC == 0x4E444221
    assert struct.unpack("<H", bytes([0x53, 0x4D]))[0] == MAGIC_CLIENT == 0x4D53
    assert MAGIC_CLIENT.to_bytes(2, "little") == b"SM"


_ALL = list(zip(["Empty", *public_fixture_ids()], [FIXTURES / "Empty.pst", *public_fixture_paths()]))


@pytest.mark.parametrize(("name", "store"), _ALL, ids=[n for n, _ in _ALL])
def test_header_musts_hold_on_real_stores(name: str, store: Path) -> None:
    """[MS-PST] 2.2.2.6 MUST fields, read at the derived offsets of whichever layout wVer selects."""
    data = store.read_bytes()
    (magic, _crc, magic_client, w_ver) = struct.unpack_from("<IIHH", data, 0)
    assert magic == MAGIC and magic_client == MAGIC_CLIENT, name
    ansi = w_ver in (14, 15)
    assert ansi or w_ver >= 23, f"{name}: wVer {w_ver} is neither ANSI (14/15) nor Unicode (>=23)"
    h, r = (A, RA) if ansi else (U, RU)
    assert data[h["bPlatformCreate"]] == 1 and data[h["bPlatformAccess"]] == 1, name
    assert data[h["bSentinel"]] == SENTINEL, name
    assert data[h["bCryptMethod"]] in CRYPT_METHODS, name
    root = h["root"]
    q = "<I" if ansi else "<Q"
    (ib_file_eof,) = struct.unpack_from(q, data, root + r["ibFileEof"])
    assert ib_file_eof == len(data), f"{name}: ibFileEof {ib_file_eof} != file size {len(data)}"
    (ib_amap_last,) = struct.unpack_from(q, data, root + r["ibAMapLast"])
    assert (ib_amap_last - AMAP_FIRST) % AMAP_INTERVAL == 0 and ib_amap_last < len(data), name
    assert data[root + r["fAMapValid"]] in (0x00, 0x01, 0x02), name
    # BREF order (bid, then ib): follow each root BREF to a page and check its
    # PAGETRAILER ptype; swapped fields would land on garbage.
    # 2.2.2.7.1 PAGETRAILER at the end of the 512-byte page: Unicode
    # (ptype, ptypeRepeat, wSig, dwCRC, bid) is 16 bytes at 496; ANSI
    # (ptype, ptypeRepeat, wSig, bid, dwCRC) is 12 bytes at 500.
    bref_fmt, trailer_at, trailer_fmt = ("<II", 500, "<BBHII") if ansi else ("<QQ", 496, "<BBHIQ")
    for field, ptype in (("BREFNBT", PTYPE_NBT), ("BREFBBT", PTYPE_BBT)):
        bid, ib = struct.unpack_from(bref_fmt, data, root + r[field])
        trailer = struct.unpack_from(trailer_fmt, data, ib + trailer_at)
        page_bid = trailer[3] if ansi else trailer[4]
        assert trailer[0] == trailer[1] == ptype, f"{name}: {field} -> wrong page type"
        assert page_bid == bid, f"{name}: {field} bid != page trailer bid"


def test_empty_pst_header_is_the_documented_blank_store() -> None:
    """[MS-PST] 2.2.2.6 on Microsoft's own blank store: the SHOULD/MUST-zero fields, rgbFM/rgbFP, wVerClient 19, rgnid start values.

    Verbatim values from the section. Checked on Empty.pst only: the corpus
    stores written by other tools break the MUST-zero of qwUnused and the
    0xFF fill of rgbFM (the spec tells readers to ignore both), and that is
    recorded here rather than asserted away.
    """
    data = (FIXTURES / "Empty.pst").read_bytes()
    assert struct.unpack_from("<H", data, U["wVer"])[0] == 23
    assert struct.unpack_from("<H", data, U["wVerClient"])[0] == 19
    assert data[U["qwUnused"] : U["qwUnused"] + 8] == bytes(8)
    assert data[U["dwAlign"] : U["dwAlign"] + 4] == bytes(4)
    assert data[U["rgbReserved"] : U["rgbReserved"] + 2] == bytes(2)
    assert data[U["rgbFM"] : U["rgbFM"] + 256] == b"\xff" * 256  # rgbFM then rgbFP
    assert data[U["bCryptMethod"]] == 0x01  # NDB_CRYPT_PERMUTE — what Outlook writes by default
    # rgnid: "the last nidIndex value that had been allocated for the
    # corresponding NID_TYPE", seeded from the 2.2.2.6 starting table. The
    # bytes are bare nidIndex counters (0x400 in slot 2 is 1024, not a NID
    # with type 0 and index 32), so they are read as plain u32 here.
    rgnid = struct.unpack_from("<32I", data, U["rgnid"])
    starts = {NodeIdType.NORMAL_FOLDER: 1024, NodeIdType.SEARCH_FOLDER: 16384,
              NodeIdType.NORMAL_MESSAGE: 65536, NodeIdType.ASSOC_MESSAGE: 32768}  # fmt: skip
    for slot in range(32):
        assert rgnid[slot] >= starts.get(slot, 1024), f"rgnid[{slot:#x}] below its documented start"
    assert rgnid[NodeIdType.SEARCH_FOLDER] == 16384
    assert rgnid[NodeIdType.NORMAL_MESSAGE] == 65536
    assert rgnid[NodeIdType.ASSOC_MESSAGE] == 32768
