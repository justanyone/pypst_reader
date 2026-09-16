"""[MS-OXCDATA] 2.11.1 property data types, [MS-DTYP] 2.3.4.2 GUIDs, and the
[MS-PST] 2.3.3.4 multi-value layouts, against `pypstreader.ltp.prop_type`.
"""

from __future__ import annotations

import struct
import uuid
from datetime import UTC, date, datetime, timedelta

import pytest

from pypstreader.errors import PstFormatError, PstUnsupportedError
from pypstreader.ltp.prop_type import (
    PropType,
    decode,
    filetime_to_datetime,
    fixed_size,
    is_fixed_size,
)

# [MS-OXCDATA] 2.11.1, the "Property type value" column and the byte count in
# the "Property type specification" column. Verbatim. `None` means the spec
# says "Variable size" (or "Any"/"None" for Unspecified/Null/Object).
SPEC_TYPES = {
    "PtypInteger16": (0x0002, 2), "PtypInteger32": (0x0003, 4), "PtypFloating32": (0x0004, 4),
    "PtypFloating64": (0x0005, 8), "PtypCurrency": (0x0006, 8), "PtypFloatingTime": (0x0007, 8),
    "PtypErrorCode": (0x000A, 4), "PtypBoolean": (0x000B, 1), "PtypInteger64": (0x0014, 8),
    "PtypString": (0x001F, None), "PtypString8": (0x001E, None), "PtypTime": (0x0040, 8),
    "PtypGuid": (0x0048, 16), "PtypBinary": (0x0102, None),
    "PtypMultipleInteger16": (0x1002, None), "PtypMultipleInteger32": (0x1003, None),
    "PtypMultipleFloating32": (0x1004, None), "PtypMultipleFloating64": (0x1005, None),
    "PtypMultipleCurrency": (0x1006, None), "PtypMultipleFloatingTime": (0x1007, None),
    "PtypMultipleInteger64": (0x1014, None), "PtypMultipleString": (0x101F, None),
    "PtypMultipleString8": (0x101E, None), "PtypMultipleTime": (0x1040, None),
    "PtypMultipleGuid": (0x1048, None), "PtypMultipleBinary": (0x1102, None),
    "PtypUnspecified": (0x0000, None), "PtypNull": (0x0001, None), "PtypObject": (0x000D, None),
}  # fmt: skip

# The spec's Ptyp* name for each of our PT_*-style members.
OUR_NAMES = {
    "PtypInteger16": PropType.SHORT, "PtypInteger32": PropType.LONG, "PtypFloating32": PropType.FLOAT,
    "PtypFloating64": PropType.DOUBLE, "PtypCurrency": PropType.CURRENCY, "PtypFloatingTime": PropType.APPTIME,
    "PtypErrorCode": PropType.ERROR, "PtypBoolean": PropType.BOOLEAN, "PtypInteger64": PropType.LONGLONG,
    "PtypString": PropType.UNICODE, "PtypString8": PropType.STRING8, "PtypTime": PropType.SYSTIME,
    "PtypGuid": PropType.GUID, "PtypBinary": PropType.BINARY,
    "PtypMultipleInteger16": PropType.MV_SHORT, "PtypMultipleInteger32": PropType.MV_LONG,
    "PtypMultipleFloating32": PropType.MV_FLOAT, "PtypMultipleFloating64": PropType.MV_DOUBLE,
    "PtypMultipleCurrency": PropType.MV_CURRENCY, "PtypMultipleFloatingTime": PropType.MV_APPTIME,
    "PtypMultipleInteger64": PropType.MV_LONGLONG, "PtypMultipleString": PropType.MV_UNICODE,
    "PtypMultipleString8": PropType.MV_STRING8, "PtypMultipleTime": PropType.MV_SYSTIME,
    "PtypMultipleGuid": PropType.MV_GUID, "PtypMultipleBinary": PropType.MV_BINARY,
    "PtypUnspecified": PropType.UNSPECIFIED, "PtypNull": PropType.NULL, "PtypObject": PropType.OBJECT,
}  # fmt: skip


@pytest.mark.parametrize("spec_name", sorted(SPEC_TYPES), ids=sorted(SPEC_TYPES))
def test_type_code_and_size_are_verbatim(spec_name: str) -> None:
    """[MS-OXCDATA] 2.11.1: one row of the property type table. Verbatim."""
    code, size = SPEC_TYPES[spec_name]
    ours = OUR_NAMES[spec_name]
    assert int(ours) == code, spec_name
    if size is not None:
        assert is_fixed_size(ours) and fixed_size(ours) == size, spec_name
    elif ours is PropType.NULL:
        assert fixed_size(ours) == 0  # "None: This property is a placeholder" — no bytes
    else:
        assert not is_fixed_size(ours), spec_name
        with pytest.raises(PstFormatError):
            fixed_size(ours)


def test_types_the_spec_lists_but_a_store_never_holds_are_refused() -> None:
    """[MS-OXCDATA] 2.11.1 PtypServerId 0x00FB, PtypRestriction 0x00FD, PtypRuleAction 0x00FE. Verbatim.

    They are wire-protocol types with no PST encoding; the port must refuse
    them as unsupported, not misread them as something else.
    """
    for code in (0x00FB, 0x00FD, 0x00FE):
        with pytest.raises(PstUnsupportedError):
            PropType.from_wire(code)


def test_boolean_is_one_byte_restricted_to_1_or_0() -> None:
    """[MS-OXCDATA] 2.11.1 PtypBoolean: "1 byte; restricted to 1 or 0". Verbatim rule."""
    assert decode(PropType.BOOLEAN, b"\x01") is True
    assert decode(PropType.BOOLEAN, b"\x00") is False
    with pytest.raises(PstFormatError):
        decode(PropType.BOOLEAN, b"\x02")
    with pytest.raises(PstFormatError):
        decode(PropType.BOOLEAN, b"\x01\x00")


# --- PtypTime / FILETIME -------------------------------------------------------
#
# [MS-OXCDATA] 2.11.1 PtypTime: "a 64-bit integer representing the number of
# 100-nanosecond intervals since January 1, 1601". Derived vector: the Unix
# epoch.
#   days 1601-01-01 .. 1970-01-01 = 134,774   (369 years, 89 of them leap)
#   134774 * 86400 s/day * 10,000,000 ticks/s = 116,444,736,000,000,000
UNIX_EPOCH_FILETIME = 116_444_736_000_000_000


def test_filetime_unix_epoch_arithmetic() -> None:
    """[MS-OXCDATA] 2.11.1 PtypTime definition. Derived (arithmetic above)."""
    days = (date(1970, 1, 1) - date(1601, 1, 1)).days
    assert days == 134_774
    assert days * 86_400 * 10_000_000 == UNIX_EPOCH_FILETIME
    assert filetime_to_datetime(UNIX_EPOCH_FILETIME) == datetime(1970, 1, 1, tzinfo=UTC)
    assert decode(PropType.SYSTIME, struct.pack("<q", UNIX_EPOCH_FILETIME)) == datetime(1970, 1, 1, tzinfo=UTC)


def test_filetime_tick_is_100_nanoseconds() -> None:
    """[MS-OXCDATA] 2.11.1: one interval is 100 ns, so ten of them are one microsecond. Derived."""
    epoch = datetime(1601, 1, 1, tzinfo=UTC)
    assert filetime_to_datetime(0) == epoch
    assert filetime_to_datetime(10) == epoch + timedelta(microseconds=1)
    assert filetime_to_datetime(10_000_000) == epoch + timedelta(seconds=1)


# --- PtypGuid ------------------------------------------------------------------
#
# [MS-OXCDATA] 2.11.1 PtypGuid: "16 bytes; a GUID with Data1, Data2, and Data3
# fields in little-endian format". [MS-DTYP] 2.3.4.2 packet representation:
# Data1 (4, LE) Data2 (2, LE) Data3 (2, LE) Data4 (8 bytes, in order).
# The vector is PS_MAPI, {00020328-0000-0000-C000-000000000046}:
#   Data1 0x00020328 -> 28 03 02 00 ; Data2 0x0000 -> 00 00 ; Data3 0x0000 -> 00 00
#   Data4 C0 00 00 00 00 00 00 46
PS_MAPI_PACKET = bytes.fromhex("28030200" "0000" "0000" "c000000000000046")
PS_MAPI = uuid.UUID("00020328-0000-0000-c000-000000000046")


def test_guid_packet_representation_decodes_to_the_braced_string() -> None:
    """[MS-DTYP] 2.3.4.2 packet layout applied to PS_MAPI. Derived (bytes above)."""
    assert decode(PropType.GUID, PS_MAPI_PACKET) == PS_MAPI
    # and the layout is not accidentally big-endian:
    assert decode(PropType.GUID, PS_MAPI.bytes) != PS_MAPI


def test_guid_must_be_exactly_16_bytes() -> None:
    """[MS-OXCDATA] 2.11.1 PtypGuid is "16 bytes". Denial: 15 or 17 is a refusal."""
    with pytest.raises(PstFormatError):
        decode(PropType.GUID, PS_MAPI_PACKET[:15])
    with pytest.raises(PstFormatError):
        decode(PropType.GUID, PS_MAPI_PACKET + b"\x00")


# --- [MS-PST] 2.3.3.4 multi-valued layouts in a store --------------------------


def test_fixed_base_mv_count_is_size_over_element_size() -> None:
    """[MS-PST] 2.3.3.4.1 worked example: 64 bytes of PtypInteger64 -> 64 / 8 = 8 items. Verbatim."""
    values = decode(PropType.MV_LONGLONG, struct.pack("<8q", *range(8)))
    assert values == tuple(range(8))
    assert len(values) == 8


def test_fixed_base_mv_that_is_not_a_whole_number_of_elements_is_refused() -> None:
    """[MS-PST] 2.3.3.4.1: "The size ... MUST be an integer multiple of the data type size". Denial."""
    with pytest.raises(PstFormatError):
        decode(PropType.MV_LONGLONG, bytes(63))
    with pytest.raises(PstFormatError):
        decode(PropType.MV_LONG, bytes(6))
    with pytest.raises(PstFormatError):
        decode(PropType.MV_SHORT, bytes(3))


@pytest.mark.xfail(
    strict=True,
    raises=(PstFormatError, AssertionError),
    reason="[MS-PST] 2.3.3.4.1 names PtypGuid as a fixed-size MV base (no count field); "
    "upstream reads PtypMultipleGuid with a leading u32 count and this port follows upstream "
    "(prop_type.py docstring). Strict: if the port ever moves to the spec's layout, this must be flipped.",
)
def test_mv_guid_by_the_spec_layout_is_two_guids_in_32_bytes() -> None:
    """[MS-PST] 2.3.3.4.1 applied to PtypGuid: 32 bytes -> 32 / 16 = 2 items. Derived.

    THE spec-vs-upstream disagreement this tier exists to surface. Kept as a
    strict xfail so every run prints it rather than hiding it in a comment.
    """
    values = decode(PropType.MV_GUID, PS_MAPI_PACKET * 2)
    assert values == (PS_MAPI, PS_MAPI)


def test_variable_base_mv_layout_is_count_offsets_items() -> None:
    """[MS-PST] 2.3.3.4.2: ulCount, rgulDataOffsets (relative to the record start), rgDataItems. Derived.

    Two PtypBinary items b"abc" and b"de": ulCount = 2 at 0, offsets at 4
    and 8 (so the items begin at 4 + 2*4 = 12), item 0 at 12..15, item 1 at
    15..end. The last item's length is "the total size of the MV property
    data record" minus its offset.
    """
    record = struct.pack("<III", 2, 12, 15) + b"abc" + b"de"
    assert decode(PropType.MV_BINARY, record) == (b"abc", b"de")


def test_variable_base_mv_offset_past_the_record_is_refused() -> None:
    """[MS-PST] 2.3.3.4.2: an offset beyond the record cannot delimit an item. Denial."""
    with pytest.raises(PstFormatError):
        decode(PropType.MV_BINARY, struct.pack("<III", 2, 12, 99) + b"abcde")
