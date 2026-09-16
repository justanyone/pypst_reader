"""The header: refused when wrong, exact when right.

Denial first: every field upstream validates, mutated in memory on a real
corpus store (tests/corrupt.py), must be a `PstFormatError` — or a
`PstUnsupportedError` where the file is recognised and deliberately not
read — and never anything else. Then the differential check that gives the
parse its claim to correctness: `python -m pypstreader.debug header` over every
Unicode store in the corpus, parsed by the same parser as the committed
oracle golden, compared as values; and the same values read straight off
the `Header` object, so a type slip behind a lucky `__str__` cannot hide.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

from pypstreader import debug
from pypstreader.encode import CryptMethod
from pypstreader.errors import PstError, PstFormatError, PstUnsupportedError
from pypstreader.ndb.header import (
    HEADER_MAGIC,
    HEADER_MAGIC_CLIENT,
    Header,
    Version,
    read_header,
)
from pypstreader.ndb.ids import BlockId, ByteIndex, PageId, PageRef
from pypstreader.ndb.root import AmapStatus, Root
from tests import corrupt
from tests.conftest import (
    FIXTURES,
    REFERENCE,
    public_fixture_ids,
    public_fixture_paths,
    run_oracle,
)
from tests.golden_parsers import parse_read_header

EMPTY = FIXTURES / "Empty.pst"
ANSI_STEMS = {"pstsdk-test_ansi", "pstsdk-sample2"}

ALL_STORES = [EMPTY, *public_fixture_paths()]
ALL_IDS = ["Empty", *public_fixture_ids()]
UNICODE_STORES = [p for p in ALL_STORES if p.stem not in ANSI_STEMS]
UNICODE_IDS = [p.stem for p in UNICODE_STORES]
ANSI_STORES = [p for p in ALL_STORES if p.stem in ANSI_STEMS]
ANSI_IDS = [p.stem for p in ANSI_STORES]

# The store the mutation tests start from. Empty.pst is Microsoft's own and
# the one every contributor has; a mutation of it is a mutation of a header
# Outlook wrote.
GOOD = EMPTY.read_bytes()[: corrupt.HEADER_SIZE]


def _parsed_values(header: Header) -> dict[str, Any]:
    """`Header` as the dict `parse_read_header` returns — values, not strings."""
    root = header.root

    def page_ref(ref: PageRef) -> dict[str, int]:
        return {"page": ref.page.raw, "index": ref.index.value}

    return {
        "version": header.version.debug_name,
        "next_block": {"internal": header.next_block.is_internal, "index": header.next_block.index},
        "next_page": header.next_page.raw,
        "file_eof_index": root.file_eof_index.value,
        "amap_last_index": root.amap_last_index.value,
        "amap_free_size": root.amap_free_size.value,
        "pmap_free_size": root.pmap_free_size.value,
        "node_btree": page_ref(root.node_btree),
        "block_btree": page_ref(root.block_btree),
        "amap_is_valid": root.amap_is_valid.debug_name,
    }


# --- denial: the file is not what it claims ---------------------------------


def test_good_header_parses() -> None:
    """The baseline every mutation below starts from must itself be accepted."""
    assert Header.parse(GOOD).version is Version.UNICODE


def test_bad_magic_is_refused() -> None:
    with pytest.raises(PstFormatError):
        Header.parse(corrupt.set_bytes(GOOD, corrupt.MAGIC_OFFSET, b"!BDM"))
    with pytest.raises(PstFormatError):
        Header.parse(corrupt.reseal_header(corrupt.set_bytes(GOOD, corrupt.MAGIC_OFFSET, b"PK\x03\x04")))


def test_wrong_magic_client_is_refused() -> None:
    bad = corrupt.reseal_header(corrupt.set_u16(GOOD, corrupt.MAGIC_CLIENT_OFFSET, 0x4D54))
    with pytest.raises(PstFormatError):
        Header.parse(bad)


def test_partial_crc_region_flip_is_refused() -> None:
    """One bit in rgnid, inside the partial-CRC range, and no resealing."""
    with pytest.raises(PstFormatError) as info:
        Header.parse(corrupt.flip_byte(GOOD, corrupt.RGNID_OFFSET + 3))
    # Every byte the partial CRC covers, the full CRC covers too; naming the
    # check is what proves the partial one is made at all.
    assert "dwCRCPartial" in str(info.value)


def test_full_crc_only_region_flip_is_refused() -> None:
    """A byte of rgbFP past the partial range: only dwCRCFull covers it."""
    offset = corrupt.CRC_PARTIAL_END + 10
    assert corrupt.CRC_PARTIAL_END <= offset < corrupt.CRC_FULL_END
    with pytest.raises(PstFormatError) as info:
        Header.parse(corrupt.flip_byte(GOOD, offset))
    assert "CRC" in str(info.value)


def test_full_crc_region_flip_passes_partial_crc() -> None:
    """The two CRCs are distinct checks: the mutation above must not trip the partial one."""
    offset = corrupt.CRC_PARTIAL_END + 10
    flipped = corrupt.flip_byte(GOOD, offset)
    with pytest.raises(PstFormatError) as info:
        Header.parse(flipped)
    assert "dwCRCFull" in str(info.value)


def test_flip_past_both_crcs_is_accepted() -> None:
    """rgbReserved3 is outside both CRCs and is not validated (as upstream)."""
    assert Header.parse(corrupt.flip_byte(GOOD, corrupt.HEADER_SIZE - 1)) == Header.parse(GOOD)


@pytest.mark.parametrize("version", [0x99, 0, 16, 22, 24, 0xFFFF])
def test_unknown_version_is_refused(version: int) -> None:
    bad = corrupt.reseal_header(corrupt.set_u16(GOOD, corrupt.VERSION_OFFSET, version))
    with pytest.raises(PstFormatError):
        Header.parse(bad)


@pytest.mark.parametrize("version", [14, 15])
def test_ansi_version_on_a_unicode_body_is_unsupported(version: int) -> None:
    """wVer alone decides: the refusal happens before any Unicode-only field is read."""
    bad = corrupt.reseal_header(corrupt.set_u16(GOOD, corrupt.VERSION_OFFSET, version))
    with pytest.raises(PstUnsupportedError) as info:
        Header.parse(bad)
    assert "pypstreader_nu" in str(info.value)


def test_ansi_version_is_refused_before_the_crc_is_checked() -> None:
    """Unsealed: a bad CRC and an ANSI wVer together are reported as ANSI."""
    bad = corrupt.set_u16(GOOD, corrupt.VERSION_OFFSET, 14)
    with pytest.raises(PstUnsupportedError):
        Header.parse(bad)


@pytest.mark.parametrize("version", [36, 37])
def test_4k_page_version_is_unsupported(version: int) -> None:
    bad = corrupt.reseal_header(corrupt.set_u16(GOOD, corrupt.VERSION_OFFSET, version))
    with pytest.raises(PstUnsupportedError) as info:
        Header.parse(bad)
    assert str(version) in str(info.value)


def test_edp_crypt_method_is_unsupported() -> None:
    bad = corrupt.reseal_header(corrupt.set_u8(GOOD, corrupt.CRYPT_METHOD_OFFSET, 0x10))
    with pytest.raises(PstUnsupportedError) as info:
        Header.parse(bad)
    assert "0x10" in str(info.value)


@pytest.mark.parametrize("method", [0x03, 0x7F, 0xFF])
def test_unknown_crypt_method_is_refused(method: int) -> None:
    bad = corrupt.reseal_header(corrupt.set_u8(GOOD, corrupt.CRYPT_METHOD_OFFSET, method))
    with pytest.raises(PstFormatError):
        Header.parse(bad)


@pytest.mark.parametrize("method", [0x00, 0x01, 0x02])
def test_every_known_crypt_method_is_accepted(method: int) -> None:
    good = corrupt.reseal_header(corrupt.set_u8(GOOD, corrupt.CRYPT_METHOD_OFFSET, method))
    assert Header.parse(good).crypt_method is CryptMethod(method)


@pytest.mark.parametrize(
    ("offset", "value"),
    [
        (corrupt.CLIENT_VERSION_OFFSET, 18),
        (corrupt.CLIENT_VERSION_OFFSET, 20),
        (corrupt.PLATFORM_CREATE_OFFSET, 0),
        (corrupt.PLATFORM_ACCESS_OFFSET, 2),
        (corrupt.SENTINEL_OFFSET, 0x00),
        (corrupt.SENTINEL_OFFSET, 0x81),
        (corrupt.RESERVED_OFFSET, 1),
        (corrupt.ALIGN_OFFSET, 1),
    ],
    ids=["client-18", "client-20", "platform-create", "platform-access", "sentinel-0", "sentinel-81", "reserved", "align"],
)
def test_fixed_fields_upstream_checks_are_refused(offset: int, value: int) -> None:
    """wVerClient, the two platform bytes, bSentinel, rgbReserved, dwAlign — upstream refuses each."""
    bad = corrupt.reseal_header(corrupt.set_u8(GOOD, offset, value))
    with pytest.raises(PstFormatError):
        Header.parse(bad)


@pytest.mark.parametrize("length", [*range(0, corrupt.HEADER_SIZE, 8), corrupt.HEADER_SIZE - 1])
def test_truncation_is_refused(length: int) -> None:
    """Every 8-byte boundary of the header, and one byte short."""
    with pytest.raises(PstFormatError):
        Header.parse(corrupt.truncate(GOOD, length))
    with pytest.raises(PstFormatError):
        read_header(io.BytesIO(corrupt.truncate(GOOD, length)))


def test_zero_length_file_is_refused(tmp_path: Path) -> None:
    empty = tmp_path / "zero.pst"
    empty.write_bytes(b"")
    with empty.open("rb") as f, pytest.raises(PstFormatError):
        read_header(f)


def test_every_refusal_is_a_pst_error() -> None:
    """The contract: for any bytes, a Header or a PstError, nothing else."""
    attempts = [
        b"",
        GOOD[:100],
        bytes(corrupt.HEADER_SIZE),
        b"\xff" * corrupt.HEADER_SIZE,
        corrupt.flip_byte(GOOD, 5),
        corrupt.reseal_header(corrupt.set_u16(GOOD, corrupt.VERSION_OFFSET, 0x99)),
    ]
    for data in attempts:
        try:
            Header.parse(data)
        except PstError:
            pass
        else:
            pytest.fail(f"accepted {len(data)} bad bytes")


# --- denial and behaviour: Root on its own ----------------------------------


def test_root_short_buffer_is_refused() -> None:
    for length in (0, 1, Root.SIZE - 1):
        with pytest.raises(PstFormatError):
            Root.unpack_from(bytes(length))


def test_root_bad_offset_is_refused() -> None:
    buf = bytes(Root.SIZE * 2)
    with pytest.raises(PstFormatError):
        Root.unpack_from(buf, Root.SIZE + 1)
    with pytest.raises(PstFormatError):
        Root.unpack_from(buf, -1)


@pytest.mark.parametrize("value", [0x03, 0x7F, 0xFF])
def test_unknown_amap_status_reads_as_invalid(value: int) -> None:
    """Upstream's `unwrap_or(Invalid)` (read_write.rs); pinned so it cannot drift silently."""
    bad = corrupt.reseal_header(corrupt.set_u8(GOOD, corrupt.AMAP_VALID_OFFSET, value))
    assert Header.parse(bad).root.amap_is_valid is AmapStatus.INVALID
    with pytest.raises(PstFormatError):
        AmapStatus.from_byte(value)


@pytest.mark.parametrize("value", [0x00, 0x01, 0x02])
def test_known_amap_status_round_trips(value: int) -> None:
    good = corrupt.reseal_header(corrupt.set_u8(GOOD, corrupt.AMAP_VALID_OFFSET, value))
    assert Header.parse(good).root.amap_is_valid is AmapStatus(value)
    assert AmapStatus.from_byte(value) is AmapStatus(value)


def test_debug_names_are_upstreams() -> None:
    assert [str(s) for s in AmapStatus] == ["Invalid", "Valid1", "Valid2"]
    assert str(Version.UNICODE) == "Unicode"
    assert str(Version.ANSI_14) == str(Version.ANSI_15) == "Ansi"
    assert str(Version.UNICODE_4K_37) == "Unicode"


def test_sizes_and_magic() -> None:
    assert Header.SIZE == 564
    assert Root.SIZE == 72
    assert HEADER_MAGIC.to_bytes(4, "little") == b"!BDN"
    assert HEADER_MAGIC_CLIENT.to_bytes(2, "little") == b"SM"


def test_parsed_structures_are_frozen() -> None:
    header = Header.parse(GOOD)
    with pytest.raises(AttributeError):
        header.unique_value = 0  # type: ignore[misc]
    with pytest.raises(AttributeError):
        header.root.amap_is_valid = AmapStatus.INVALID  # type: ignore[misc]


# --- the real ANSI stores are refused (ADR-0003) ----------------------------


@pytest.mark.parametrize("store", ANSI_STORES, ids=ANSI_IDS)
def test_ansi_store_is_refused(store: Path) -> None:
    with store.open("rb") as f, pytest.raises(PstUnsupportedError) as info:
        read_header(f)
    message = str(info.value)
    assert "pypstreader_nu" in message
    assert "wVer=14" in message or "wVer=15" in message


@pytest.mark.parametrize("store", ANSI_STORES, ids=ANSI_IDS)
def test_debug_header_exits_one_on_ansi(store: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert debug.main(["header", str(store)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("Error: ANSI")
    assert "pypstreader_nu" in captured.err


# --- differential: the goldens ---------------------------------------------


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_debug_header_matches_golden(store: Path, golden, golden_exit, capsys: pytest.CaptureFixture[str]) -> None:
    """The dumper's text, parsed as the golden is parsed, is the golden's values."""
    assert golden_exit(store, "read_header") == 0
    expected = parse_read_header(golden(store, "read_header"))
    assert debug.main(["header", str(store)]) == 0
    ours = parse_read_header(capsys.readouterr().out)
    assert ours == expected, f"{store.stem}: header differs from the oracle"


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_header_values_match_golden(store: Path, golden) -> None:
    """The same comparison on the Header's attributes: values, not their printed forms."""
    expected = parse_read_header(golden(store, "read_header"))
    with store.open("rb") as f:
        header = read_header(f)
    ours = _parsed_values(header)
    assert ours == expected, f"{store.stem}: header differs from the oracle"
    # And the types behind those values, which a string comparison cannot see.
    assert header.version is Version.UNICODE
    assert isinstance(header.crypt_method, CryptMethod)
    assert isinstance(header.next_block, BlockId)
    assert isinstance(header.next_page, PageId)
    assert isinstance(header.root.file_eof_index, ByteIndex)
    assert isinstance(header.root.node_btree, PageRef)
    assert isinstance(header.root.amap_is_valid, AmapStatus)
    assert header.client_version == 19
    assert 0 <= header.unique_value <= 0xFFFFFFFF


def test_empty_pst_spot_values(empty_pst: Path) -> None:
    """Numbers read straight off the file, independent of the golden parser."""
    with empty_pst.open("rb") as f:
        header = read_header(f)
    assert header.crypt_method is CryptMethod.PERMUTE
    assert header.next_block == BlockId.from_parts(False, 0x4C)
    assert header.next_page == PageId(0x17F)
    assert header.root.file_eof_index == ByteIndex(0x42400)
    assert header.root.file_eof_index.value == empty_pst.stat().st_size
    assert header.root.node_btree == PageRef(PageId(0x17D), ByteIndex(0x9200))
    assert header.root.block_btree == PageRef(PageId(0x17B), ByteIndex(0x8400))
    assert header.root.amap_is_valid is AmapStatus.VALID2


def test_fields_the_oracle_never_prints() -> None:
    """dwUnique and wVerClient are not in read_header's output; read them off the bytes."""
    header = Header.parse(GOOD)
    assert header.unique_value == int.from_bytes(GOOD[40:44], "little")
    assert header.client_version == int.from_bytes(GOOD[12:14], "little") == 19
    bumped = corrupt.reseal_header(corrupt.set_u32(GOOD, 40, 0xDEADBEEF))
    assert Header.parse(bumped).unique_value == 0xDEADBEEF


def test_read_header_from_a_file_handle_and_a_bytesio(empty_pst: Path) -> None:
    with empty_pst.open("rb") as f:
        f.seek(100)  # read_header must not depend on where the handle is
        from_file = read_header(f)
    from_memory = read_header(io.BytesIO(empty_pst.read_bytes()))
    assert from_file == from_memory == Header.parse(GOOD)


def test_parse_accepts_memoryview_and_bytearray() -> None:
    assert Header.parse(memoryview(GOOD)) == Header.parse(bytearray(GOOD)) == Header.parse(GOOD)


def test_extra_bytes_after_the_header_are_ignored() -> None:
    assert Header.parse(GOOD + b"junk" * 100) == Header.parse(GOOD)


# --- differential: private stores against the live oracle -------------------


@pytest.mark.private
@pytest.mark.oracle
def test_private_stores_match_live_oracle(private_stores: list[Path], oracle: Path) -> None:
    """Structure only. A mismatch is reported by count, never by content."""
    if not private_stores:
        pytest.skip("no private stores present (this is a normal clean checkout)")
    assert oracle == REFERENCE
    mismatched = 0
    for store in private_stores:
        expected = parse_read_header(run_oracle(oracle, "read_header", str(store)))
        with store.open("rb") as f:
            ours = _parsed_values(read_header(f))
        if ours != expected:
            mismatched += 1
    if mismatched:
        pytest.fail(f"{mismatched} of {len(private_stores)} private store header(s) differ from the oracle")
