"""Property-type decoders: refusals first, then known bytes, then round-trips.

Every input here is built with `struct` in the test, so a failure prints the
bytes that provoked it and nothing else. The one external input is the set of
`Value:` / `Type:` variant names the Rust oracle printed into
`tests/golden/`, which pins the promise that each variant has a decoder.

`UPSTREAM_VARIANT_TO_PROPTYPE` is the bridge the layer rows reuse when they
parse a golden's `Type: Integer32` into the `PropType` they decode with.
"""

from __future__ import annotations

import math
import random
import re
import struct
import uuid
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from pypst.errors import PstError, PstFormatError, PstLimitError, PstUnsupportedError
from pypst.ltp.prop_type import (
    ObjectRef,
    PropType,
    datetime_to_filetime,
    decode,
    filetime_to_datetime,
    fixed_size,
    is_fixed_size,
)
from pypst.ndb.ids import NodeId

GOLDEN = Path(__file__).resolve().parent / "golden"

# Upstream's `PropertyType` / `PropertyValue` variant names, as `Debug` prints
# them in the goldens, to the `PropType` this port decodes them with. Every
# variant upstream defines is here, whether or not the corpus exercised it.
UPSTREAM_VARIANT_TO_PROPTYPE: dict[str, PropType] = {
    "Null": PropType.NULL,
    "Integer16": PropType.SHORT,
    "Integer32": PropType.LONG,
    "Floating32": PropType.FLOAT,
    "Floating64": PropType.DOUBLE,
    "Currency": PropType.CURRENCY,
    "FloatingTime": PropType.APPTIME,
    "ErrorCode": PropType.ERROR,
    "Boolean": PropType.BOOLEAN,
    "Integer64": PropType.LONGLONG,
    "String8": PropType.STRING8,
    "Unicode": PropType.UNICODE,
    "Time": PropType.SYSTIME,
    "Guid": PropType.GUID,
    "Binary": PropType.BINARY,
    "Object": PropType.OBJECT,
    "MultipleInteger16": PropType.MV_SHORT,
    "MultipleInteger32": PropType.MV_LONG,
    "MultipleFloating32": PropType.MV_FLOAT,
    "MultipleFloating64": PropType.MV_DOUBLE,
    "MultipleCurrency": PropType.MV_CURRENCY,
    "MultipleFloatingTime": PropType.MV_APPTIME,
    "MultipleInteger64": PropType.MV_LONGLONG,
    "MultipleString8": PropType.MV_STRING8,
    "MultipleUnicode": PropType.MV_UNICODE,
    "MultipleTime": PropType.MV_SYSTIME,
    "MultipleGuid": PropType.MV_GUID,
    "MultipleBinary": PropType.MV_BINARY,
}

# [MS-OXCDATA] 2.11.1, transcribed from the spec table, not from the code.
SPEC_CODES = {
    "UNSPECIFIED": 0x0000,
    "NULL": 0x0001,
    "SHORT": 0x0002,
    "LONG": 0x0003,
    "FLOAT": 0x0004,
    "DOUBLE": 0x0005,
    "CURRENCY": 0x0006,
    "APPTIME": 0x0007,
    "ERROR": 0x000A,
    "BOOLEAN": 0x000B,
    "OBJECT": 0x000D,
    "LONGLONG": 0x0014,
    "STRING8": 0x001E,
    "UNICODE": 0x001F,
    "SYSTIME": 0x0040,
    "GUID": 0x0048,
    "CLSID": 0x0048,
    "BINARY": 0x0102,
    "MV_SHORT": 0x1002,
    "MV_LONG": 0x1003,
    "MV_FLOAT": 0x1004,
    "MV_DOUBLE": 0x1005,
    "MV_CURRENCY": 0x1006,
    "MV_APPTIME": 0x1007,
    "MV_LONGLONG": 0x1014,
    "MV_STRING8": 0x101E,
    "MV_UNICODE": 0x101F,
    "MV_SYSTIME": 0x1040,
    "MV_GUID": 0x1048,
    "MV_BINARY": 0x1102,
}

FIXED_WIDTHS = {
    PropType.NULL: 0,
    PropType.SHORT: 2,
    PropType.LONG: 4,
    PropType.FLOAT: 4,
    PropType.DOUBLE: 8,
    PropType.CURRENCY: 8,
    PropType.APPTIME: 8,
    PropType.ERROR: 4,
    PropType.BOOLEAN: 1,
    PropType.LONGLONG: 8,
    PropType.SYSTIME: 8,
    PropType.GUID: 16,
}

# PS_MAPI as upstream's messaging/named_prop.rs spells it: GuidValue::new(
# 0x00020328, 0x0000, 0x0000, [C0 00 00 00 00 00 00 46]) — and its textual
# form from [MS-OXPROPS] 1.3.2.
PS_MAPI_BYTES = struct.pack("<IHH8s", 0x00020328, 0x0000, 0x0000, bytes([0xC0, 0, 0, 0, 0, 0, 0, 0x46]))
PS_MAPI_TEXT = "00020328-0000-0000-c000-000000000046"

UNIX_EPOCH_FILETIME = 116_444_736_000_000_000
FILETIME_MAX = 2_650_467_743_999_999_999  # 9999-12-31 23:59:59.9999999


def utf16(s: str) -> bytes:
    return s.encode("utf-16-le")


def mv_variable(items: list[bytes]) -> bytes:
    """Build a [MS-PST] 2.3.3.4.2 record: count, offsets, then the items."""
    count = len(items)
    offsets = []
    pos = 4 * (count + 1)
    for item in items:
        offsets.append(pos)
        pos += len(item)
    return struct.pack(f"<I{count}I", count, *offsets) + b"".join(items)


# --- the enum ----------------------------------------------------------------


def test_every_member_has_the_spec_code() -> None:
    assert {name: int(m) for name, m in PropType.__members__.items()} == SPEC_CODES


def test_clsid_is_an_alias_of_guid_not_a_second_member() -> None:
    assert PropType.CLSID is PropType.GUID
    assert PropType.CLSID.name == "GUID"


@pytest.mark.parametrize("code", [0x0000, 0x0008, 0x00FB, 0x00FD, 0x00FE, 0x0103, 0x1001, 0x1000, 0xFFFF, 0x2002])
def test_unknown_wire_code_is_refused_by_name(code: int) -> None:
    with pytest.raises(PstUnsupportedError) as info:
        PropType.from_wire(code)
    assert f"0x{code:04X}" in str(info.value)


@pytest.mark.parametrize("code", [-1, 0x10000])
def test_non_u16_wire_code_is_a_format_error(code: int) -> None:
    with pytest.raises(PstFormatError):
        PropType.from_wire(code)


@pytest.mark.parametrize("member", [m for m in PropType if m is not PropType.UNSPECIFIED], ids=lambda m: m.name)
def test_every_storable_member_round_trips_through_from_wire(member: PropType) -> None:
    assert PropType.from_wire(int(member)) is member


def test_decode_accepts_a_raw_wire_code() -> None:
    assert decode(0x0003, struct.pack("<i", 7)) == 7
    with pytest.raises(PstUnsupportedError):
        decode(0x00FB, b"")


def test_unspecified_has_no_value_encoding() -> None:
    with pytest.raises(PstFormatError):
        decode(PropType.UNSPECIFIED, b"")


# --- widths ------------------------------------------------------------------


@pytest.mark.parametrize("member", list(PropType), ids=lambda m: m.name)
def test_fixed_size_agrees_with_the_spec_widths(member: PropType) -> None:
    if member in FIXED_WIDTHS:
        assert is_fixed_size(member)
        assert fixed_size(member) == FIXED_WIDTHS[member]
    else:
        assert not is_fixed_size(member)
        with pytest.raises(PstFormatError):
            fixed_size(member)


# --- denial: every fixed-size scalar ----------------------------------------

SCALAR_SAMPLES: list[tuple[PropType, bytes]] = [
    (PropType.SHORT, struct.pack("<h", -2)),
    (PropType.LONG, struct.pack("<i", -113532656)),
    (PropType.FLOAT, struct.pack("<f", 1.5)),
    (PropType.DOUBLE, struct.pack("<d", -2.25)),
    (PropType.CURRENCY, struct.pack("<q", 123456)),
    (PropType.APPTIME, struct.pack("<d", 45000.5)),
    (PropType.ERROR, struct.pack("<i", -2147221233)),
    (PropType.BOOLEAN, b"\x01"),
    (PropType.LONGLONG, struct.pack("<q", 2520)),
    (PropType.SYSTIME, struct.pack("<q", UNIX_EPOCH_FILETIME)),
    (PropType.GUID, PS_MAPI_BYTES),
    (PropType.OBJECT, struct.pack("<II", 0x8025, 0x1234)),
]


@pytest.mark.parametrize(("t", "good"), SCALAR_SAMPLES, ids=lambda x: x.name if isinstance(x, PropType) else "")
def test_fixed_value_short_by_one_byte_is_refused(t: PropType, good: bytes) -> None:
    with pytest.raises(PstFormatError):
        decode(t, good[:-1])
    with pytest.raises(PstFormatError):
        decode(t, b"")


@pytest.mark.parametrize(("t", "good"), SCALAR_SAMPLES, ids=lambda x: x.name if isinstance(x, PropType) else "")
def test_fixed_value_long_by_one_byte_is_refused(t: PropType, good: bytes) -> None:
    with pytest.raises(PstFormatError):
        decode(t, good + b"\0")


def test_null_takes_no_bytes() -> None:
    assert decode(PropType.NULL, b"") is None
    with pytest.raises(PstFormatError):
        decode(PropType.NULL, b"\0")


@pytest.mark.parametrize("byte", [b"\x02", b"\xff", b"\x80"])
def test_boolean_must_be_zero_or_one(byte: bytes) -> None:
    with pytest.raises(PstFormatError):
        decode(PropType.BOOLEAN, byte)


# --- denial: text ------------------------------------------------------------


def test_unicode_odd_length_is_refused() -> None:
    with pytest.raises(PstFormatError):
        decode(PropType.UNICODE, utf16("ab") + b"\0")


def test_unicode_lone_surrogate_is_a_format_error_not_a_unicode_error() -> None:
    lone = struct.pack("<H", 0xD800)
    with pytest.raises(PstFormatError):
        decode(PropType.UNICODE, lone)
    with pytest.raises(PstFormatError):
        decode(PropType.MV_UNICODE, mv_variable([lone]))


def test_string8_unknown_codepage_is_unsupported() -> None:
    with pytest.raises(PstUnsupportedError):
        decode(PropType.STRING8, b"abc", codepage="cp99999")
    with pytest.raises(PstUnsupportedError):
        decode(PropType.MV_STRING8, mv_variable([b"abc"]), codepage="no-such-codec")


def test_string8_undefined_byte_in_codepage_is_a_format_error() -> None:
    # 0x81 is unassigned in cp1252; latin-1 has no holes, so the same bytes
    # decode under it — that is the documented escape hatch.
    with pytest.raises(PstFormatError):
        decode(PropType.STRING8, b"a\x81b")
    assert decode(PropType.STRING8, b"a\x81b", codepage="latin-1") == "a\x81b"


# --- denial: multi-valued ----------------------------------------------------

MV_FIXED = [
    (PropType.MV_SHORT, "<h", 2),
    (PropType.MV_LONG, "<i", 4),
    (PropType.MV_FLOAT, "<f", 4),
    (PropType.MV_DOUBLE, "<d", 8),
    (PropType.MV_CURRENCY, "<q", 8),
    (PropType.MV_APPTIME, "<d", 8),
    (PropType.MV_LONGLONG, "<q", 8),
    (PropType.MV_SYSTIME, "<q", 8),
]


@pytest.mark.parametrize(("t", "fmt", "size"), MV_FIXED, ids=lambda x: x.name if isinstance(x, PropType) else "")
def test_mv_fixed_partial_trailing_element_is_refused(t: PropType, fmt: str, size: int) -> None:
    # `match` pins the whole-buffer check, [MS-PST] 2.3.3.4.1's MUST; without
    # it the per-element width check would refuse the tail anyway.
    two = struct.pack(fmt, 1) + struct.pack(fmt, 2)
    for bad_len in range(1, size):
        with pytest.raises(PstFormatError, match="not a multiple"):
            decode(t, two + b"\0" * bad_len)
        with pytest.raises(PstFormatError, match="not a multiple"):
            decode(t, two[:-bad_len])


@pytest.mark.parametrize(("t", "fmt", "size"), MV_FIXED, ids=lambda x: x.name if isinstance(x, PropType) else "")
def test_mv_fixed_count_over_max_items_is_a_limit_error(t: PropType, fmt: str, size: int) -> None:
    data = b"\0" * (size * 5)
    with pytest.raises(PstLimitError) as info:
        decode(t, data, max_items=4)
    assert not isinstance(info.value, PstFormatError)
    assert len(decode(t, data, max_items=5)) == 5


@pytest.mark.parametrize("t", [PropType.MV_STRING8, PropType.MV_UNICODE, PropType.MV_BINARY, PropType.MV_GUID])
def test_mv_counted_short_of_its_count_is_refused(t: PropType) -> None:
    for n in range(4):
        with pytest.raises(PstFormatError):
            decode(t, struct.pack("<I", 1)[:n])


@pytest.mark.parametrize("t", [PropType.MV_STRING8, PropType.MV_UNICODE, PropType.MV_BINARY])
def test_mv_variable_offset_table_beyond_buffer_is_refused(t: PropType) -> None:
    with pytest.raises(PstFormatError):
        decode(t, struct.pack("<II", 2, 12))  # claims two offsets, holds one


@pytest.mark.parametrize("t", [PropType.MV_STRING8, PropType.MV_UNICODE, PropType.MV_BINARY])
def test_mv_variable_first_offset_must_follow_the_table(t: PropType) -> None:
    with pytest.raises(PstFormatError):
        decode(t, struct.pack("<II", 1, 9) + b"\0\0")  # should be 8
    with pytest.raises(PstFormatError):
        decode(t, struct.pack("<II", 1, 4) + b"\0\0")  # points into the table


@pytest.mark.parametrize("t", [PropType.MV_STRING8, PropType.MV_UNICODE, PropType.MV_BINARY])
def test_mv_variable_offset_past_end_is_refused(t: PropType) -> None:
    with pytest.raises(PstFormatError):
        decode(t, struct.pack("<III", 2, 12, 100) + b"\0\0\0\0")


@pytest.mark.parametrize("t", [PropType.MV_STRING8, PropType.MV_UNICODE, PropType.MV_BINARY])
def test_mv_variable_non_monotonic_offsets_are_refused(t: PropType) -> None:
    data = struct.pack("<IIII", 3, 16, 20, 18) + b"\0" * 8
    with pytest.raises(PstFormatError):
        decode(t, data)


@pytest.mark.parametrize("t", [PropType.MV_STRING8, PropType.MV_UNICODE, PropType.MV_BINARY, PropType.MV_GUID])
def test_mv_counted_count_over_max_items_is_a_limit_error_before_anything_is_read(t: PropType) -> None:
    # Only the count is present: a format check would say "truncated", the
    # limit check must win and say "too many".
    with pytest.raises(PstLimitError) as info:
        decode(t, struct.pack("<I", 0xFFFFFFFF))
    assert not isinstance(info.value, PstFormatError)
    with pytest.raises(PstLimitError):
        decode(t, struct.pack("<I", 3), max_items=2)


def test_mv_unicode_odd_item_span_is_refused() -> None:
    with pytest.raises(PstFormatError):
        decode(PropType.MV_UNICODE, mv_variable([b"a", utf16("b")]))


def test_mv_guid_wrong_length_for_its_count_is_refused() -> None:
    with pytest.raises(PstFormatError, match="MV_GUID"):
        decode(PropType.MV_GUID, struct.pack("<I", 1) + PS_MAPI_BYTES[:-1])
    with pytest.raises(PstFormatError, match="MV_GUID"):
        decode(PropType.MV_GUID, struct.pack("<I", 1) + PS_MAPI_BYTES + b"\0")


# --- known bytes → known values ---------------------------------------------


@pytest.mark.parametrize(
    ("t", "data", "expected"),
    [
        (PropType.SHORT, struct.pack("<h", -2), -2),
        (PropType.SHORT, b"\xff\xff", -1),
        (PropType.LONG, struct.pack("<i", 917521), 917521),
        (PropType.LONG, struct.pack("<i", -113532656), -113532656),
        (PropType.FLOAT, struct.pack("<f", 1.5), 1.5),
        (PropType.DOUBLE, struct.pack("<d", -2.25), -2.25),
        (PropType.CURRENCY, struct.pack("<q", 123456), 123456),  # 12.3456 in 1/10000 units
        (PropType.APPTIME, struct.pack("<d", 45000.5), 45000.5),
        (PropType.ERROR, struct.pack("<I", 0x8004010F), -2147221233),  # MAPI_E_NOT_FOUND as upstream's i32
        (PropType.BOOLEAN, b"\x00", False),
        (PropType.BOOLEAN, b"\x01", True),
        (PropType.LONGLONG, struct.pack("<q", 2520), 2520),
        (PropType.LONGLONG, struct.pack("<q", -(1 << 63)), -(1 << 63)),
        (PropType.BINARY, b"", b""),
        (PropType.BINARY, b"\x01\x04\x00\x00\x10\x00", b"\x01\x04\x00\x00\x10\x00"),
        (PropType.OBJECT, struct.pack("<II", 0x8025, 0x1234), ObjectRef(node=NodeId(0x8025), size=0x1234)),
        (PropType.UNICODE, utf16("IPF.Note"), "IPF.Note"),
        (PropType.UNICODE, b"", ""),
        (PropType.STRING8, b"Search Root", "Search Root"),
        (PropType.STRING8, b"", ""),
        (PropType.STRING8, b"caf\xe9", "café"),
    ],
    ids=lambda x: x.name if isinstance(x, PropType) else "",
)
def test_known_bytes_decode_to_known_values(t: PropType, data: bytes, expected: object) -> None:
    value = decode(t, data)
    assert value == expected
    assert type(value) is type(expected)


def test_boolean_is_a_bool_not_an_int() -> None:
    assert decode(PropType.BOOLEAN, b"\x01") is True
    assert decode(PropType.BOOLEAN, b"\x00") is False


def test_decode_accepts_a_memoryview() -> None:
    view = memoryview(struct.pack("<i", 14) + b"tail")[:4]
    assert decode(PropType.LONG, view) == 14
    assert decode(PropType.BINARY, view) == struct.pack("<i", 14)


def test_strings_stop_at_the_first_nul_like_upstream() -> None:
    assert decode(PropType.STRING8, b"Inbox\0garbage") == "Inbox"
    assert decode(PropType.UNICODE, utf16("Inbox") + b"\0\0" + utf16("garbage")) == "Inbox"


def test_unicode_nul_scan_respects_code_unit_alignment() -> None:
    # U+0100 U+0001 is bytes 00 01 01 00: the "\0\0" straddling units 0 and 1
    # is not a terminator.
    assert decode(PropType.UNICODE, utf16("Ā")) == "Ā"


def test_guid_uses_little_endian_data1_2_3() -> None:
    assert decode(PropType.GUID, PS_MAPI_BYTES) == uuid.UUID(PS_MAPI_TEXT)
    assert str(decode(PropType.GUID, PS_MAPI_BYTES)) == PS_MAPI_TEXT
    # The big-endian reading of the same bytes is a different GUID.
    assert decode(PropType.GUID, PS_MAPI_BYTES) != uuid.UUID(bytes=PS_MAPI_BYTES)


def test_mv_fixed_known_arrays() -> None:
    assert decode(PropType.MV_LONG, struct.pack("<3i", 1, -2, 3)) == (1, -2, 3)
    assert decode(PropType.MV_SHORT, b"") == ()
    assert decode(PropType.MV_SYSTIME, struct.pack("<2q", 0, UNIX_EPOCH_FILETIME)) == (
        datetime(1601, 1, 1, tzinfo=UTC),
        datetime(1970, 1, 1, tzinfo=UTC),
    )


def test_mv_guid_follows_upstream_count_prefix() -> None:
    # Pinned so a switch to the [MS-PST] 2.3.3.4.1 packed form is deliberate.
    two = struct.pack("<I", 2) + PS_MAPI_BYTES + PS_MAPI_BYTES
    assert decode(PropType.MV_GUID, two) == (uuid.UUID(PS_MAPI_TEXT),) * 2
    assert decode(PropType.MV_GUID, struct.pack("<I", 0)) == ()
    with pytest.raises(PstFormatError):
        decode(PropType.MV_GUID, PS_MAPI_BYTES)  # packed form, no count


def test_mv_variable_known_records() -> None:
    assert decode(PropType.MV_BINARY, mv_variable([b"ab", b"", b"c"])) == (b"ab", b"", b"c")
    assert decode(PropType.MV_UNICODE, mv_variable([utf16("ab"), utf16("cd") + b"\0\0", b""])) == ("ab", "cd", "")
    assert decode(PropType.MV_STRING8, mv_variable([b"a\0", b"bc\0zz", b""])) == ("a", "bc", "")


@pytest.mark.parametrize("t", [PropType.MV_STRING8, PropType.MV_UNICODE, PropType.MV_BINARY])
def test_mv_variable_zero_items(t: PropType) -> None:
    assert decode(t, struct.pack("<I", 0)) == ()
    # With no items there is no last item to own trailing bytes; upstream
    # ignores them and so does this port.
    assert decode(t, struct.pack("<I", 0) + b"tail") == ()


# --- FILETIME ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("ft", "expected"),
    [
        (0, datetime(1601, 1, 1, tzinfo=UTC)),
        (7, datetime(1601, 1, 1, tzinfo=UTC)),
        (10, datetime(1601, 1, 1, 0, 0, 0, 1, tzinfo=UTC)),
        (UNIX_EPOCH_FILETIME, datetime(1970, 1, 1, tzinfo=UTC)),
        (FILETIME_MAX - 9, datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC)),
        (FILETIME_MAX, datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC)),
    ],
)
def test_filetime_edge_cases(ft: int, expected: datetime) -> None:
    value = filetime_to_datetime(ft)
    assert value == expected
    assert value.tzinfo is UTC


@pytest.mark.parametrize("ft", [-1, FILETIME_MAX + 1, 0x7FFFFFFFFFFFFFFF, -(1 << 63), 1 << 64])
def test_filetime_out_of_range_is_a_format_error(ft: int) -> None:
    with pytest.raises(PstFormatError):
        filetime_to_datetime(ft)


def test_systime_out_of_range_never_escapes_as_overflow() -> None:
    for raw in (0x7FFFFFFFFFFFFFFF, -1):
        with pytest.raises(PstError):
            decode(PropType.SYSTIME, struct.pack("<q", raw))


def test_filetime_max_constant_is_datetime_max() -> None:
    assert datetime_to_filetime(datetime.max.replace(tzinfo=UTC)) == FILETIME_MAX - 9


def test_datetime_to_filetime_pins() -> None:
    assert datetime_to_filetime(datetime(1601, 1, 1, tzinfo=UTC)) == 0
    assert datetime_to_filetime(datetime(1970, 1, 1, tzinfo=UTC)) == UNIX_EPOCH_FILETIME
    eastern = timezone(timedelta(hours=-5))
    assert datetime_to_filetime(datetime(1969, 12, 31, 19, tzinfo=eastern)) == UNIX_EPOCH_FILETIME


def test_datetime_to_filetime_refuses_naive_and_pre_epoch() -> None:
    with pytest.raises(TypeError):
        datetime_to_filetime(datetime(1970, 1, 1))  # noqa: DTZ001 — naive on purpose
    with pytest.raises(ValueError):
        datetime_to_filetime(datetime(1600, 12, 31, tzinfo=UTC))


def test_filetime_round_trips_on_microsecond_ticks() -> None:
    rng = random.Random(20260915)
    for _ in range(500):
        ft = rng.randrange(0, FILETIME_MAX // 10) * 10
        assert datetime_to_filetime(filetime_to_datetime(ft)) == ft, ft
        dt = filetime_to_datetime(ft)
        assert filetime_to_datetime(datetime_to_filetime(dt)) == dt, dt


# --- seeded round-trips for every invertible fixed type ---------------------


def test_fixed_scalars_round_trip_through_struct() -> None:
    rng = random.Random(20260915)
    for _ in range(300):
        i16 = rng.randrange(-(1 << 15), 1 << 15)
        i32 = rng.randrange(-(1 << 31), 1 << 31)
        i64 = rng.randrange(-(1 << 63), 1 << 63)
        f64 = rng.uniform(-1e300, 1e300)
        f32 = struct.unpack("<f", struct.pack("<f", rng.uniform(-1e30, 1e30)))[0]
        assert decode(PropType.SHORT, struct.pack("<h", i16)) == i16
        assert decode(PropType.LONG, struct.pack("<i", i32)) == i32
        assert decode(PropType.ERROR, struct.pack("<i", i32)) == i32
        assert decode(PropType.LONGLONG, struct.pack("<q", i64)) == i64
        assert decode(PropType.CURRENCY, struct.pack("<q", i64)) == i64
        assert decode(PropType.DOUBLE, struct.pack("<d", f64)) == f64
        assert decode(PropType.APPTIME, struct.pack("<d", f64)) == f64
        assert decode(PropType.FLOAT, struct.pack("<f", f32)) == f32
        assert decode(PropType.MV_LONGLONG, struct.pack("<3q", i64, 0, -i64 - 1)) == (i64, 0, -i64 - 1)
        guid = uuid.UUID(int=rng.getrandbits(128))
        assert decode(PropType.GUID, guid.bytes_le) == guid
        node, size = rng.getrandbits(32), rng.getrandbits(32)
        assert decode(PropType.OBJECT, struct.pack("<II", node, size)) == ObjectRef(NodeId(node), size)
        ft = rng.randrange(0, FILETIME_MAX // 10) * 10
        assert datetime_to_filetime(decode(PropType.SYSTIME, struct.pack("<q", ft))) == ft


def test_float_nan_survives_decoding() -> None:
    assert math.isnan(decode(PropType.DOUBLE, struct.pack("<d", math.nan)))
    assert math.isnan(decode(PropType.FLOAT, struct.pack("<f", math.nan)))


def test_object_ref_is_frozen() -> None:
    ref = ObjectRef(NodeId(1), 2)
    with pytest.raises(AttributeError):
        ref.node = 3  # type: ignore[misc]


# --- the goldens: every variant upstream printed has a decoder ---------------

# `Value: Unicode(...)`, `Type: Integer32`, `Record: Small(Integer64(100))`.
VARIANT = re.compile(r"\b(?:Value: |Type: |Record: Small\()([A-Z][A-Za-z0-9]*)")


# The examples that print property values. (`read_density_list` prints a page
# `Type:`, which is a different enum.)
PROPERTY_GOLDENS = ("read_store_props.txt", "read_root_folder.txt", "read_ipm_subtree.txt", "read_named_props.txt")


def golden_variants() -> set[str]:
    names: set[str] = set()
    for path in GOLDEN.rglob("*.txt"):
        if path.name in PROPERTY_GOLDENS:
            names.update(VARIANT.findall(path.read_text(errors="replace")))
    # `None` is Rust's `Option::None` for an absent table cell, not a type;
    # `Heap` is a `PropertyValueRecord::Heap(HeapId)` reference, not a value.
    return names - {"None", "Heap"}


def test_goldens_exist() -> None:
    assert GOLDEN.is_dir() and any(GOLDEN.rglob("*.txt"))


def test_every_golden_variant_maps_to_a_decoded_proptype() -> None:
    seen = golden_variants()
    assert seen, "no Value:/Type: lines found in the goldens"
    unmapped = seen - UPSTREAM_VARIANT_TO_PROPTYPE.keys()
    assert not unmapped, f"golden variants with no PropType: {sorted(unmapped)}"


def test_variant_map_covers_every_upstream_variant_and_is_injective() -> None:
    assert len(set(UPSTREAM_VARIANT_TO_PROPTYPE.values())) == len(UPSTREAM_VARIANT_TO_PROPTYPE)
    unmapped = {m for m in PropType} - set(UPSTREAM_VARIANT_TO_PROPTYPE.values())
    assert unmapped == {PropType.UNSPECIFIED}


def test_debug_name_is_the_upstream_variant_map_both_ways() -> None:
    """`PropType.debug_name` (P05, for the dumper) agrees with the map this file transcribed from the goldens."""
    for variant, t in UPSTREAM_VARIANT_TO_PROPTYPE.items():
        assert t.debug_name == variant
        assert PropType.from_debug_name(variant) is t
    with pytest.raises(PstUnsupportedError):
        _ = PropType.UNSPECIFIED.debug_name
    with pytest.raises(PstFormatError):
        PropType.from_debug_name("Integer128")
    assert PropType.CLSID.debug_name == "Guid"


def test_object_ref_node_is_a_node_id() -> None:
    """P22 left `ObjectRef.node` a raw int; P05 wrapped it (INTERFACES changelog)."""
    ref = decode(PropType.OBJECT, struct.pack("<II", 0x8025, 0x1234))
    assert isinstance(ref, ObjectRef) and isinstance(ref.node, NodeId)
    assert ref.node.index == 0x401 and ref.node.id_type.name == "ATTACHMENT" and ref.size == 0x1234
    # An unknown 5-bit type is carried (as NodeId does) and refused only at id_type.
    odd = decode(PropType.OBJECT, struct.pack("<II", 0x0000_0019, 0))
    with pytest.raises(PstFormatError):
        _ = odd.node.id_type


@pytest.mark.parametrize("variant", sorted(UPSTREAM_VARIANT_TO_PROPTYPE), ids=str)
def test_every_mapped_variant_decodes_something(variant: str) -> None:
    """Each variant's type accepts a well-formed value of the right shape."""
    t = UPSTREAM_VARIANT_TO_PROPTYPE[variant]
    sample: dict[PropType, bytes] = {
        PropType.NULL: b"",
        PropType.BOOLEAN: b"\x01",
        PropType.GUID: PS_MAPI_BYTES,
        PropType.OBJECT: struct.pack("<II", 1, 2),
        PropType.STRING8: b"x",
        PropType.UNICODE: utf16("x"),
        PropType.BINARY: b"x",
        PropType.MV_STRING8: mv_variable([b"x"]),
        PropType.MV_UNICODE: mv_variable([utf16("x")]),
        PropType.MV_BINARY: mv_variable([b"x"]),
        PropType.MV_GUID: struct.pack("<I", 1) + PS_MAPI_BYTES,
    }
    if t in sample:
        data = sample[t]
    elif is_fixed_size(t):
        data = b"\0" * fixed_size(t)
    else:
        data = b"\0" * fixed_size(UPSTREAM_VARIANT_TO_PROPTYPE[variant.removeprefix("Multiple")])
    decode(t, data)  # must not raise
