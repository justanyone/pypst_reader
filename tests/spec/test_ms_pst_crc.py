"""[MS-PST] 5.3 CRC Calculation — the spec's table and algorithm versus `zlib`.

crc.py claims MS-PST's CRC is CRC-32 without zlib's pre/post inversion.
tests/test_crc.py proves that against *upstream's* table. This file proves
it against the *specification's* table and pseudocode, and then against
CRCs that Outlook itself wrote into real headers.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

import pytest

from pypstreader.crc import compute_crc
from tests.conftest import FIXTURES, public_fixture_ids, public_fixture_paths

# [MS-PST] 5.3 `CrcTableOffset32[256]`: the first eight entries and the last.
# Verbatim, including the spec's upper-case hex.
SPEC_TABLE_HEAD = (
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
    0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
)  # fmt: skip
SPEC_TABLE_LAST = 0x2D02EF8D

# zlib's CRC-32 is the reflected polynomial 0x04C11DB7, i.e. 0xEDB88320 in the
# bit order the table-driven loop uses. Not from the PST spec: from RFC 1952
# section 8 / ISO/IEC 3309, which is the point — an independent source.
REFLECTED_POLY = 0xEDB88320

# The universal CRC-32 check value: crc32(b"123456789") with init 0xFFFFFFFF
# and final XOR 0xFFFFFFFF (ISO/IEC 3309, ITU-T V.42; zlib documents it).
ISO_CHECK_INPUT = b"123456789"
ISO_CHECK_VALUE = 0xCBF43926


def _table_from_polynomial() -> list[int]:
    """The 256-entry reflected table for REFLECTED_POLY, built from the definition."""
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (REFLECTED_POLY if c & 1 else 0)
        table.append(c)
    return table


def _spec_crc(crc: int, data: bytes) -> int:
    """[MS-PST] 5.3 ComputeCRC, the byte-at-a-time arm, transcribed:

        dwCRC = CrcTableOffset32[(dwCRC ^ *pbBuffer++) & 0xFF] ^ (dwCRC >> 8);

    The spec's 8-byte main loop with the other eight tables is an
    optimisation of this same recurrence (that is what slicing-by-8 is), so
    the one-table form is the definition. No inversion before or after.
    """
    table = _table_from_polynomial()
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


def test_spec_table_is_the_reflected_crc32_table() -> None:
    """[MS-PST] 5.3 CrcTableOffset32 entries 0..7 and 255. Verbatim vs derived-from-polynomial.

    This is the link that makes the zlib shortcut the spec's CRC and not
    merely upstream's: the spec's constants ARE the 0xEDB88320 table.
    """
    table = _table_from_polynomial()
    assert tuple(table[:8]) == SPEC_TABLE_HEAD
    assert table[255] == SPEC_TABLE_LAST


def test_compute_crc_is_the_spec_recurrence_with_seed_zero() -> None:
    """[MS-PST] 5.3: dwCRC "MUST be zero in the context of this document". Derived.

    The spec loop, seeded with 0 and with no final XOR, over the ISO check
    input. The value 0x2DFD2D88 is what the transcription above produces;
    it is not a published constant, and the assertion that matters is the
    equality between the transcription and `compute_crc`.
    """
    assert _spec_crc(0, ISO_CHECK_INPUT) == compute_crc(0, ISO_CHECK_INPUT) == 0x2DFD2D88


def test_zlib_form_is_the_spec_form_wrapped_in_inversions() -> None:
    """ISO/IEC 3309 check value 0xCBF43926 for "123456789". Verbatim (external).

    zlib.crc32 = ~spec_crc(~0, data). Undoing both inversions is exactly what
    crc.py does, so the standard check value must fall out of `compute_crc`
    when the inversions are put back by hand — and the spec recurrence must
    reproduce zlib the same way.
    """
    assert zlib.crc32(ISO_CHECK_INPUT) == ISO_CHECK_VALUE
    assert compute_crc(0xFFFFFFFF, ISO_CHECK_INPUT) ^ 0xFFFFFFFF == ISO_CHECK_VALUE
    assert _spec_crc(0xFFFFFFFF, ISO_CHECK_INPUT) ^ 0xFFFFFFFF == ISO_CHECK_VALUE


def test_spec_and_compute_crc_agree_with_a_running_seed() -> None:
    """[MS-PST] 5.3: dwCRC is a seed, so a chunked computation composes. Derived."""
    data = bytes(range(256)) * 3
    running_spec = running_ours = 0
    for start in range(0, len(data), 61):
        chunk = data[start : start + 61]
        running_spec = _spec_crc(running_spec, chunk)
        running_ours = compute_crc(running_ours, chunk)
    assert running_spec == running_ours == compute_crc(0, data)


# --- CRCs Outlook wrote: the header ---------------------------------------------
#
# [MS-PST] 2.2.2.6:
#   dwCRCPartial (offset 4): "the 32-bit CRC value of the 471 bytes of data
#                             starting from wMagicClient (offset 0x0008)"
#   dwCRCFull (Unicode only): "the 32-bit CRC value of the 516 bytes of data
#                             starting from wMagicClient to bidNextB, inclusive"
# dwCRCFull's offset is derived in test_ms_pst_layout.py (0x20C).

_ALL_STORES = [FIXTURES / "Empty.pst", *public_fixture_paths()]
_ALL_IDS = ["Empty", *public_fixture_ids()]


@pytest.mark.parametrize("store", _ALL_STORES, ids=_ALL_IDS)
def test_header_crc_partial_matches_the_spec_on_real_stores(store: Path) -> None:
    """[MS-PST] 2.2.2.6 dwCRCPartial over 471 bytes from offset 8, by 5.3 with seed 0.

    Derived from the field definition; the expected value is the one the
    store's writer put on disk. Both ANSI and Unicode headers define the
    field the same way, so every public store is checked.
    """
    header = store.read_bytes()[:564]
    (stored,) = struct.unpack_from("<I", header, 4)
    assert compute_crc(0, header[8 : 8 + 471]) == stored, f"dwCRCPartial mismatch in {store.name}"


@pytest.mark.parametrize("store", _ALL_STORES, ids=_ALL_IDS)
def test_header_crc_full_matches_the_spec_on_unicode_stores(store: Path) -> None:
    """[MS-PST] 2.2.2.6 dwCRCFull over 516 bytes from offset 8, Unicode only. Derived."""
    header = store.read_bytes()[:564]
    (w_ver,) = struct.unpack_from("<H", header, 10)
    if w_ver < 23:
        pytest.skip("dwCRCFull is a Unicode-header field; this store is ANSI")
    (stored,) = struct.unpack_from("<I", header, 0x20C)
    assert compute_crc(0, header[8 : 8 + 516]) == stored, f"dwCRCFull mismatch in {store.name}"


def test_a_flipped_header_byte_changes_the_partial_crc() -> None:
    """The check above has teeth: corrupt one byte inside the covered range and it must fail."""
    header = bytearray((FIXTURES / "Empty.pst").read_bytes()[:564])
    (stored,) = struct.unpack_from("<I", header, 4)
    header[100] ^= 0x01
    assert compute_crc(0, bytes(header[8 : 8 + 471])) != stored
