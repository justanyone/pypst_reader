"""Property types and the decoders that turn their bytes into Python values.

Ported from: crates/pst/src/ltp/prop_type.rs, crates/pst/src/ltp/prop_context.rs (value decoders only)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-OXCDATA] 2.11.1 Property Data Types (the type codes and sizes)
             [MS-PST] 2.3.3.4.1 / 2.3.3.4.2 (multi-valued layouts in a store)

Every property in a PST is a (type, bytes) pair. This module is the bottom of
the LTP layer: it knows the sixteen-bit type codes and, for each one, how to
read a value out of a buffer that the property context (P05) or table context
(P06) has already located. It knows nothing about heaps, nodes or contexts,
which is what makes it a leaf that can be ported and tested on its own.

Upstream spreads this over two places — the `PropertyType` enum, and the
`read` arms of `PropertyValue` plus the inline `small_value` / table-column
arms — because Rust wants a typed enum per value. Python does not: a decoder
returns `int`, `float`, `bool`, `bytes`, `str`, `datetime`, `uuid.UUID`, an
`ObjectRef`, `None` for PtypNull, or a `tuple` of those for the multi-valued
forms. The value-to-type direction is therefore not recoverable from a value
alone; a caller that needs it keeps the `PropType` it decoded with.

**Multi-valued layouts, and the one place upstream contradicts the spec.**
[MS-OXCDATA] describes every PtypMultiple* value as "a COUNT followed by that
many values" — but that is the ROP wire form. Inside a PST the count of a
multi-valued property with a *fixed-size* base type is not stored: [MS-PST]
2.3.3.4.1 derives it from the allocation size, and the buffer is a tightly
packed array. Only the *variable-size* base types (String8, Unicode, Binary;
[MS-PST] 2.3.3.4.2) carry `ulCount` and an offset table. Upstream reads
MultipleInteger16/32/64, MultipleFloating32/64, MultipleCurrency,
MultipleFloatingTime and MultipleTime exactly that way. It reads MultipleGuid
with a leading u32 count, although [MS-PST] names PtypGuid as a fixed-size
example. This port follows upstream (the `rust-port` rule: the implementation
that opens real files wins a disagreement), and `_decode_mv_guid` says so
again where it happens. If a real store proves upstream wrong, that is the one
function to change, and `test_prop_type.py` pins the current behaviour so the
change is deliberate.

**Deliberate divergences from upstream**, each chosen to fail closed on a
buffer an attacker wrote:

- A fixed-size scalar must be *exactly* its size. Upstream's heap-read arms
  (`read_i64` on a cursor) accept trailing bytes silently; here a 9-byte
  PtypInteger64 is `PstFormatError`. Heap allocations carry exact sizes, so a
  correct writer never produces the padded form.
- A fixed-base multi-value must be an exact multiple of the element size —
  the spec's MUST. Upstream drops a trailing partial element without comment.
- PtypBoolean is one byte and must be 0 or 1, as [MS-OXCDATA] says and as
  upstream's table-column arm enforces (`InvalidTableColumnBooleanValue`).
  Upstream's *property-context* arm is looser (`value & 0xFF != 0`); the
  strict form is used for both, so a byte of 0x02 is refused rather than
  read as true.
- Text is decoded strictly. PtypString in upstream is `from_utf16_lossy`
  (a lone surrogate becomes U+FFFD); here it is `PstFormatError`. PtypString8
  in upstream has no code page at all — its display widens each byte to
  U+00XX, i.e. Latin-1 — whereas here the caller names one (default cp1252,
  the Windows default; `codecs` resolves it). A byte undefined in that code
  page is `PstFormatError`. To reproduce upstream's output byte for byte,
  pass `codepage="latin-1"`, which cannot fail.
- A multi-value count is capped (`max_items`, default one million) before
  anything is allocated for it, and the trip is `PstLimitError`, kept distinct
  from `PstFormatError` so a caller can raise the ceiling for a legitimate
  giant and discard the corrupt one.
- PtypTime becomes an aware UTC `datetime` instead of a raw i64. FILETIME
  counts 100 ns ticks since 1601; `datetime` resolves microseconds, so the
  last decimal digit is dropped (`filetime_to_datetime(7) == epoch`). A value
  below zero or past 9999-12-31 is `PstFormatError`, never `OverflowError`.
  Zero decodes to the epoch itself, 1601-01-01T00:00:00+00:00: MAPI uses zero
  to mean "no time", but that is a policy for the messaging layer, not a
  fact about the bytes.
- PtypObject's node id is a `NodeId` (`ObjectRef.node`), as upstream's
  `ObjectValue { node_id: NodeId, size }`. It was a raw `int` while P23 was
  in flight; P05 wrapped it. An unknown 5-bit type is accepted here, as
  `NodeId(raw)` accepts it, and refused where `id_type` is asked for.
"""

from __future__ import annotations

import codecs
import struct
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import IntEnum

from pypst.errors import PstFormatError, PstLimitError, PstUnsupportedError
from pypst.limits import MAX_MV_ITEMS
from pypst.ndb.ids import NodeId

DEFAULT_MAX_ITEMS = MAX_MV_ITEMS  # the named home is pypst.limits (P11)


class PropType(IntEnum):
    """The sixteen-bit property type codes, [MS-OXCDATA] 2.11.1.

    Named by the `PT_*` aliases the spec lists alongside each `Ptyp*` name,
    because those are what every MAPI reference, header and forensic tool
    calls them. Upstream's Rust names (`Integer32`, `Time`, ...) are what the
    goldens print; tests/test_prop_type.py holds that mapping.

    `UNSPECIFIED` is a real spec value ("matches any type") but has no value
    encoding and never appears in a store, so `from_wire` refuses it exactly
    as upstream's `TryFrom<u16>` does. It is a member only so a caller can
    name it. `CLSID` is the spec's own alias for `GUID`, not a second type.
    """

    UNSPECIFIED = 0x0000
    NULL = 0x0001
    SHORT = 0x0002
    LONG = 0x0003
    FLOAT = 0x0004
    DOUBLE = 0x0005
    CURRENCY = 0x0006
    APPTIME = 0x0007
    ERROR = 0x000A
    BOOLEAN = 0x000B
    OBJECT = 0x000D
    LONGLONG = 0x0014
    STRING8 = 0x001E
    UNICODE = 0x001F
    SYSTIME = 0x0040
    GUID = 0x0048
    CLSID = 0x0048
    BINARY = 0x0102

    MV_SHORT = 0x1002
    MV_LONG = 0x1003
    MV_FLOAT = 0x1004
    MV_DOUBLE = 0x1005
    MV_CURRENCY = 0x1006
    MV_APPTIME = 0x1007
    MV_LONGLONG = 0x1014
    MV_STRING8 = 0x101E
    MV_UNICODE = 0x101F
    MV_SYSTIME = 0x1040
    MV_GUID = 0x1048
    MV_BINARY = 0x1102

    @classmethod
    def from_wire(cls, value: int) -> PropType:
        """The type a `wPropType` field names, or a refusal.

        `PstUnsupportedError` for a code this port does not decode — which
        includes the spec's PtypServerId / PtypRestriction / PtypRuleAction
        (never stored in a PST) and PtypUnspecified. `PstFormatError` for a
        value that is not even a u16.
        """
        if not 0 <= value <= 0xFFFF:
            raise PstFormatError(f"property type {value!r} is not a 16-bit value")
        if value == cls.UNSPECIFIED or value not in _WIRE_CODES:
            raise PstUnsupportedError(f"property type 0x{value:04X}")
        return cls(value)

    @property
    def debug_name(self) -> str:
        """The variant name upstream's `Debug` prints for this type (`Integer32`, `Time`, ...) — what the goldens contain.

        `UNSPECIFIED` has no upstream variant and is refused with
        `PstUnsupportedError`, as `from_wire` refuses it.
        """
        try:
            return _DEBUG_NAMES[self]
        except KeyError:
            raise PstUnsupportedError(f"property type 0x{int(self):04X} has no upstream name") from None

    @classmethod
    def from_debug_name(cls, name: str) -> PropType:
        """The inverse of `debug_name`, for parsing the oracle's output; an unknown name is `PstFormatError`."""
        try:
            return _TYPES_BY_DEBUG_NAME[name]
        except KeyError:
            raise PstFormatError(f"unknown property type name {name!r}") from None


_WIRE_CODES = frozenset(int(m) for m in PropType)

# Upstream's `PropertyType` variant names ([MS-OXCDATA]'s `Ptyp*` names minus
# the prefix), in the order of the enum in `ltp/prop_type.rs`.
_DEBUG_NAMES: dict[PropType, str] = {
    PropType.NULL: "Null",
    PropType.SHORT: "Integer16",
    PropType.LONG: "Integer32",
    PropType.FLOAT: "Floating32",
    PropType.DOUBLE: "Floating64",
    PropType.CURRENCY: "Currency",
    PropType.APPTIME: "FloatingTime",
    PropType.ERROR: "ErrorCode",
    PropType.BOOLEAN: "Boolean",
    PropType.OBJECT: "Object",
    PropType.LONGLONG: "Integer64",
    PropType.STRING8: "String8",
    PropType.UNICODE: "Unicode",
    PropType.SYSTIME: "Time",
    PropType.GUID: "Guid",
    PropType.BINARY: "Binary",
    PropType.MV_SHORT: "MultipleInteger16",
    PropType.MV_LONG: "MultipleInteger32",
    PropType.MV_FLOAT: "MultipleFloating32",
    PropType.MV_DOUBLE: "MultipleFloating64",
    PropType.MV_CURRENCY: "MultipleCurrency",
    PropType.MV_APPTIME: "MultipleFloatingTime",
    PropType.MV_LONGLONG: "MultipleInteger64",
    PropType.MV_STRING8: "MultipleString8",
    PropType.MV_UNICODE: "MultipleUnicode",
    PropType.MV_SYSTIME: "MultipleTime",
    PropType.MV_GUID: "MultipleGuid",
    PropType.MV_BINARY: "MultipleBinary",
}
_TYPES_BY_DEBUG_NAME = {name: member for member, name in _DEBUG_NAMES.items()}


# The fixed-size scalars and their little-endian struct formats. Sizes are
# the ones [MS-OXCDATA] 2.11.1 states; the format letters decide signedness,
# and every one follows upstream (i16 / i32 / i64, never unsigned).
_SCALAR_FORMATS: dict[PropType, str] = {
    PropType.SHORT: "<h",
    PropType.LONG: "<i",
    PropType.FLOAT: "<f",
    PropType.DOUBLE: "<d",
    PropType.CURRENCY: "<q",
    PropType.APPTIME: "<d",
    PropType.ERROR: "<i",
    PropType.BOOLEAN: "<B",
    PropType.LONGLONG: "<q",
    PropType.SYSTIME: "<q",
}

# Every fixed-size type and its width. NULL has a size and no bytes: upstream
# stores it as `Small(0)` in a property context and gives its table column a
# cbData of 0. GUID is here rather than in _SCALAR_FORMATS because it is not
# one struct field.
_FIXED_SIZES: dict[PropType, int] = {
    PropType.NULL: 0,
    **{t: struct.calcsize(fmt) for t, fmt in _SCALAR_FORMATS.items()},
    PropType.GUID: 16,
}

# Which fixed-size scalar each fixed-base multi-value repeats.
_MV_FIXED_BASE: dict[PropType, PropType] = {
    PropType.MV_SHORT: PropType.SHORT,
    PropType.MV_LONG: PropType.LONG,
    PropType.MV_FLOAT: PropType.FLOAT,
    PropType.MV_DOUBLE: PropType.DOUBLE,
    PropType.MV_CURRENCY: PropType.CURRENCY,
    PropType.MV_APPTIME: PropType.APPTIME,
    PropType.MV_LONGLONG: PropType.LONGLONG,
    PropType.MV_SYSTIME: PropType.SYSTIME,
}


def is_fixed_size(t: PropType) -> bool:
    """True for the types whose value has one width, [MS-OXCDATA] 2.11.1.

    PtypObject is *not* fixed: it is an 8-byte record in a heap allocation
    (node id, size) reached through an HNID, and a 4-byte HNID in a table
    row — never an inline value.
    """
    return t in _FIXED_SIZES


def fixed_size(t: PropType) -> int:
    """The width in bytes of a fixed-size type; `PstFormatError` otherwise.

    The error is a `PstFormatError` rather than a `ValueError` because the
    only way to ask this of a variable type at runtime is to have read a
    structure that claimed a fixed-width value of a variable-width type,
    which is a fact about the file.
    """
    try:
        return _FIXED_SIZES[t]
    except KeyError:
        raise PstFormatError(f"{t.name} is not a fixed-size property type") from None


@dataclass(frozen=True, slots=True)
class ObjectRef:
    """A PtypObject value: the subnode holding an attachment or embedded message.

    Upstream's `ObjectValue { node_id: NodeId, size: u32 }`: the NID of the
    sub-node (of the owning node) that holds the object's bytes — an
    attachment's data, or an embedded message's own property context — and
    the byte size upstream carries alongside it.
    """

    node: NodeId
    size: int


type PropValue = (
    int | float | bool | bytes | str | datetime | uuid.UUID | ObjectRef | None | tuple[PropValue, ...]
)

# --- FILETIME ----------------------------------------------------------------

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_TICKS_PER_MICROSECOND = 10
_TICKS_PER_SECOND = 10_000_000
_TICKS_PER_DAY = 86_400 * _TICKS_PER_SECOND


def datetime_to_filetime(dt: datetime) -> int:
    """The FILETIME for an aware datetime — the inverse of `filetime_to_datetime`.

    Here for the round-trip tests and for a caller building a filter; nothing
    in the read path calls it. A naive datetime is a `TypeError` (it is a
    programming error, not a file's), and a time before 1601 a `ValueError`,
    because no FILETIME can express it.
    """
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise TypeError("datetime_to_filetime needs an aware datetime")
    delta = dt - _FILETIME_EPOCH
    if delta < timedelta(0):
        raise ValueError(f"{dt.isoformat()} is before the FILETIME epoch")
    return (
        delta.days * _TICKS_PER_DAY
        + delta.seconds * _TICKS_PER_SECOND
        + delta.microseconds * _TICKS_PER_MICROSECOND
    )


# The last tick datetime can hold: 9999-12-31 23:59:59.999999 plus the nine
# sub-microsecond ticks that truncate onto it. Derived, not typed, so it is
# right by construction; the test suite pins the number anyway.
_FILETIME_MAX = datetime_to_filetime(datetime.max.replace(tzinfo=UTC)) + _TICKS_PER_MICROSECOND - 1


def filetime_to_datetime(ft: int) -> datetime:
    """An aware UTC datetime for a FILETIME (100 ns ticks since 1601-01-01).

    Sub-microsecond ticks are dropped. Out of range — negative, or past
    `datetime.max` — is `PstFormatError`: the value came from the file.
    """
    if not 0 <= ft <= _FILETIME_MAX:
        raise PstFormatError(f"FILETIME {ft:#x} is outside 1601-01-01..9999-12-31")
    return _FILETIME_EPOCH + timedelta(microseconds=ft // _TICKS_PER_MICROSECOND)


# --- scalar decoders ---------------------------------------------------------


def _exact(t: PropType, data: bytes | memoryview, size: int) -> None:
    if len(data) != size:
        raise PstFormatError(f"{t.name} value is {len(data)} bytes, expected {size}")


def _decode_scalar(t: PropType, data: bytes | memoryview) -> int | float:
    fmt = _SCALAR_FORMATS[t]
    _exact(t, data, struct.calcsize(fmt))
    return struct.unpack(fmt, data)[0]


def _decode_boolean(data: bytes | memoryview) -> bool:
    value = _decode_scalar(PropType.BOOLEAN, data)
    if value not in (0, 1):
        raise PstFormatError(f"BOOLEAN byte is {value:#04x}, not 0 or 1")
    return value == 1


def _decode_systime(data: bytes | memoryview) -> datetime:
    return filetime_to_datetime(_decode_scalar(PropType.SYSTIME, data))


def _decode_guid(data: bytes | memoryview) -> uuid.UUID:
    # Data1/2/3 are little-endian on disk ([MS-OXCDATA] 2.11.1), which is
    # exactly the layout `bytes_le` names; Data4 is a byte array either way.
    _exact(PropType.GUID, data, 16)
    return uuid.UUID(bytes_le=bytes(data))


def _decode_object(data: bytes | memoryview) -> ObjectRef:
    _exact(PropType.OBJECT, data, 8)
    node, size = struct.unpack("<II", data)
    return ObjectRef(NodeId(node), size)


def _decode_binary(data: bytes | memoryview) -> bytes:
    return bytes(data)


def _decode_null(data: bytes | memoryview) -> None:
    _exact(PropType.NULL, data, 0)


# --- text --------------------------------------------------------------------


def _lookup_codepage(codepage: str) -> codecs.CodecInfo:
    try:
        return codecs.lookup(codepage)
    except LookupError:
        raise PstUnsupportedError(f"code page {codepage!r} is not available") from None


def _decode_string8_bytes(raw: bytes, codec: codecs.CodecInfo) -> str:
    # Upstream truncates at the first NUL and ignores whatever follows.
    end = raw.find(b"\0")
    if end >= 0:
        raw = raw[:end]
    try:
        return codec.decode(raw, "strict")[0]
    except UnicodeDecodeError as exc:
        raise PstFormatError(f"STRING8 is not valid {codec.name}: {exc.reason}") from None


def _decode_unicode_bytes(raw: bytes) -> str:
    if len(raw) % 2:
        raise PstFormatError(f"UNICODE value is {len(raw)} bytes, not a whole number of UTF-16 units")
    # Upstream stops at the first 0x0000 code unit. `find` on bytes does not
    # know about alignment, so an odd hit (the low byte of one unit and the
    # high byte of the next) is skipped past.
    start = 0
    while (nul := raw.find(b"\0\0", start)) >= 0:
        if nul % 2 == 0:
            raw = raw[:nul]
            break
        start = nul + 1
    try:
        return raw.decode("utf-16-le", "strict")
    except UnicodeDecodeError as exc:
        raise PstFormatError(f"UNICODE value is not valid UTF-16LE: {exc.reason}") from None


def _decode_string8(data: bytes | memoryview, codepage: str) -> str:
    return _decode_string8_bytes(bytes(data), _lookup_codepage(codepage))


def _decode_unicode(data: bytes | memoryview) -> str:
    return _decode_unicode_bytes(bytes(data))


# --- multi-valued ------------------------------------------------------------


def _check_count(count: int, max_items: int) -> None:
    if count > max_items:
        raise PstLimitError(f"multi-value count {count} exceeds {max_items}")


def _decode_mv_fixed(t: PropType, data: bytes | memoryview, max_items: int) -> tuple[PropValue, ...]:
    """[MS-PST] 2.3.3.4.1: a packed array, its count implied by the length."""
    base = _MV_FIXED_BASE[t]
    size = _FIXED_SIZES[base]
    if len(data) % size:
        raise PstFormatError(f"{t.name} value is {len(data)} bytes, not a multiple of {size}")
    count = len(data) // size
    _check_count(count, max_items)
    decoder = _DECODERS[base]
    return tuple(decoder(data[i : i + size]) for i in range(0, len(data), size))


def _decode_mv_guid(data: bytes | memoryview, max_items: int) -> tuple[uuid.UUID, ...]:
    """Upstream's layout: u32 count, then that many 16-byte GUIDs.

    NOT the [MS-PST] 2.3.3.4.1 packed form that the other fixed-base
    multi-values use — see the module docstring for why upstream wins.
    """
    if len(data) < 4:
        raise PstFormatError(f"MV_GUID value is {len(data)} bytes, too short for its count")
    (count,) = struct.unpack_from("<I", data)
    _check_count(count, max_items)
    _exact(PropType.MV_GUID, data, 4 + 16 * count)
    return tuple(_decode_guid(data[i : i + 16]) for i in range(4, len(data), 16))


def _mv_variable_items(t: PropType, data: bytes | memoryview, max_items: int) -> list[bytes]:
    """[MS-PST] 2.3.3.4.2: ulCount, rgulDataOffsets, rgDataItems.

    The offsets must start immediately after the table and never run
    backwards — upstream's `InvalidMultiValuePropertyOffset` conditions, plus
    the bound against the buffer that Rust gets from `read_exact`. The last
    item runs to the end of the buffer.
    """
    if len(data) < 4:
        raise PstFormatError(f"{t.name} value is {len(data)} bytes, too short for its count")
    (count,) = struct.unpack_from("<I", data)
    _check_count(count, max_items)
    table_end = 4 * (count + 1)
    if len(data) < table_end:
        raise PstFormatError(f"{t.name} claims {count} items but is only {len(data)} bytes")
    offsets = struct.unpack_from(f"<{count}I", data, 4)
    if count == 0:
        return []
    if offsets[0] != table_end:
        raise PstFormatError(f"{t.name} first offset {offsets[0]:#x} is not {table_end:#x}")
    items: list[bytes] = []
    for i, start in enumerate(offsets):
        end = offsets[i + 1] if i + 1 < count else len(data)
        if end < start or end > len(data):
            raise PstFormatError(f"{t.name} offset {end:#x} is out of range")
        items.append(bytes(data[start:end]))
    return items


def _decode_mv_string8(data: bytes | memoryview, codepage: str, max_items: int) -> tuple[str, ...]:
    codec = _lookup_codepage(codepage)
    return tuple(
        _decode_string8_bytes(item, codec) for item in _mv_variable_items(PropType.MV_STRING8, data, max_items)
    )


def _decode_mv_unicode(data: bytes | memoryview, max_items: int) -> tuple[str, ...]:
    return tuple(_decode_unicode_bytes(item) for item in _mv_variable_items(PropType.MV_UNICODE, data, max_items))


def _decode_mv_binary(data: bytes | memoryview, max_items: int) -> tuple[bytes, ...]:
    return tuple(_mv_variable_items(PropType.MV_BINARY, data, max_items))


# --- dispatch ----------------------------------------------------------------

# Single-valued decoders that need only the bytes. The multi-valued and
# text forms take extra arguments, so `decode` dispatches them by hand.
_DECODERS: dict[PropType, Callable[[bytes | memoryview], PropValue]] = {
    PropType.NULL: _decode_null,
    PropType.BOOLEAN: _decode_boolean,
    PropType.SYSTIME: _decode_systime,
    PropType.GUID: _decode_guid,
    PropType.OBJECT: _decode_object,
    PropType.BINARY: _decode_binary,
    PropType.UNICODE: _decode_unicode,
    **{
        t: (lambda data, t=t: _decode_scalar(t, data))
        for t in _SCALAR_FORMATS
        if t not in (PropType.BOOLEAN, PropType.SYSTIME)
    },
}


def decode(
    t: PropType | int,
    data: bytes | memoryview,
    *,
    codepage: str = "cp1252",
    max_items: int = DEFAULT_MAX_ITEMS,
) -> PropValue:
    """Decode the bytes of one property value of type `t`.

    `data` is the whole value: the inline bytes of a fixed-size property, or
    the complete heap / subnode allocation of a variable-size one. `codepage`
    names the encoding of STRING8 values (`PstUnsupportedError` if Python
    lacks it); `max_items` caps any multi-value count (`PstLimitError`).
    Everything else that can go wrong is `PstFormatError`.
    """
    if not isinstance(t, PropType):
        t = PropType.from_wire(t)
    if t is PropType.STRING8:
        return _decode_string8(data, codepage)
    if t is PropType.MV_STRING8:
        return _decode_mv_string8(data, codepage, max_items)
    if t is PropType.MV_UNICODE:
        return _decode_mv_unicode(data, max_items)
    if t is PropType.MV_BINARY:
        return _decode_mv_binary(data, max_items)
    if t is PropType.MV_GUID:
        return _decode_mv_guid(data, max_items)
    if t in _MV_FIXED_BASE:
        return _decode_mv_fixed(t, data, max_items)
    try:
        decoder = _DECODERS[t]
    except KeyError:
        raise PstFormatError(f"{t.name} has no value encoding") from None
    return decoder(data)


__all__ = [
    "DEFAULT_MAX_ITEMS",
    "ObjectRef",
    "PropType",
    "PropValue",
    "datetime_to_filetime",
    "decode",
    "filetime_to_datetime",
    "fixed_size",
    "is_fixed_size",
]
