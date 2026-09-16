"""The Named Property Lookup Map — the 0x8000+ property ids, and what each one actually means.

Ported from: crates/pst/src/messaging/named_prop.rs (the read half: `NamedPropertyId`,
             `NamedPropertyGuid`, `NamedPropertyIndex`, `NameIdEntry`, `StringEntry` and
             the accessors of `NamedPropertyMapProperties`; the write half and the ANSI
             arm are not ported — ADR-0003)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.4.7 Named Property Lookup Map, 2.4.7.1 NAMEID, 2.4.7.2 GUID Stream,
             2.4.7.3 Entry Stream, 2.4.7.4 String Stream, 2.4.7.5 Hash Table;
             [MS-OXPROPS] 1.3.2 (the two GUIDs named by index rather than stored)

`NID_NAME_TO_ID_MAP` (0x61) is a property context whose four interesting
properties are streams rather than values:

| prop id | [MS-PST] | what |
|---|---|---|
| 0x0001 | `PidTagNameidBucketCount` | how many hash buckets the map has |
| 0x0002 | `PidTagNameidStreamGuid`  | GUIDs, 16 bytes each, indexed from `wGuid - 3` |
| 0x0003 | `PidTagNameidStreamEntry` | NAMEIDs, 8 bytes each, in `wPropIdx` order |
| 0x0004 | `PidTagNameidStreamString`| u32 length + UTF-16LE name, at 4-byte boundaries |

One NAMEID ([MS-PST] 2.4.7.1) is `dwPropertyID` (a number, or an offset
into the string stream), `wGuid` and `wPropIdx`. The low bit of `wGuid`
says which of the two `dwPropertyID` is; `wGuid >> 1` is 0 for "no GUID",
1 for `PS_MAPI`, 2 for `PS_PUBLIC_STRINGS`, and otherwise names the
`(wGuid >> 1) - 3`rd GUID in the GUID stream. `wPropIdx` is the property's
index in the named range: the id a message's PC actually uses is
`0x8000 + wPropIdx`.

**Why this matters more than it looks.** Every Outlook-specific property —
the conversation index, the internet headers on some stores, every custom
field an add-in wrote — has an id above 0x8000, and those ids mean nothing
without this map: the same 0x8042 is a different property in two different
stores. A reader without the map cannot see them and, worse, cannot tell
that it cannot see them.

**Deliberate divergences from upstream**, each chosen to fail closed:

- **A stream that is not a whole number of records is refused.** Upstream
  reads each stream with `while let Ok(value) = …::read(&mut cursor)`, so a
  trailing partial record — or any record that fails its own checks, such
  as a `wPropIdx` of 0x8000 or above — silently truncates the map and the
  reader sees a shorter list with no indication that anything was dropped.
  Here a GUID stream whose length is not a multiple of 16, or an entry
  stream whose length is not a multiple of 8, is `PstFormatError`. All 8
  Unicode corpus stores are exact multiples.
- **A duplicate `wPropIdx` is `PstFormatError`.** Two NAMEIDs claiming the
  same 0x8000+ id cannot both be right, and upstream, which never indexes
  the entries by id, has no opinion. The corpus has none (964 entries over
  8 stores, every one of them contiguous from 0).
- **A `PidTagNameidBucketCount` of 0 is refused when the map has entries.**
  Upstream computes `hash_value % bucket_count`, which panics on zero; a
  map with entries and no buckets cannot be probed and is corrupt by
  [MS-PST] 2.4.7.5.
- **A hash bucket property at or past `bucket_count` is refused.** The
  buckets are `PidTagNameidBucketBase + n` for `n < cBuckets`
  ([MS-PST] 2.4.7.5); one beyond that is a count that does not describe
  the map it is in.
- **`hash_entry` keeps the entry's `wGuid`; upstream clears it.** Upstream
  rebuilds a string-named NAMEID as `NameIdEntry::new(StringOffset(crc),
  NamedPropertyGuid::None, prop_index)`, so its hash is `crc ^ 1` whatever
  property set the name belongs to — and that is not where the store put
  it. Measured over the whole corpus: with `wGuid` cleared, 9 of Empty's
  35 entries and 34 of tika-variousBodyTypes' 56 land in a bucket that
  does not hold them (every string-named one); with `wGuid` kept, all 964
  entries of all 8 Unicode stores land in the bucket that does
  (`tests/test_named_prop.py::test_every_entry_is_in_the_bucket_its_hash_names`).
  [MS-PST] 2.4.7.5 says the hash key is computed from the NAMEID, and
  nothing in it drops `wGuid`. Upstream never notices because nothing in
  its read path calls `hash_entry`.
- **`stream_string()` is not ported.** Upstream's whole-stream walk advances
  by the entry it just read *and then* by a padded length again, so it
  skips every other entry; nothing in the read path calls it, and
  `lookup_string` — which the example and this map use — is exact.
- Counts are bounded by `limits.max_items` before anything is allocated.

Nothing but `PstError` escapes: a stream that is absent, not binary, or
malformed is `PstFormatError`, a bucket the map does not hold is
`PstNotFoundError`, a ceiling is `PstLimitError`.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from typing import ClassVar

from pypstreader.crc import compute_crc
from pypstreader.errors import PstFormatError, PstNotFoundError
from pypstreader.limits import Limits, check_count
from pypstreader.ltp.prop_context import PropertyContext
from pypstreader.ltp.prop_type import PropType
from pypstreader.ndb.block import BlockReader, SubNodeLeafEntry
from pypstreader.ndb.ids import _unpack
from pypstreader.ndb.page import NodeBTreeEntry

__all__ = [
    "GUID_SIZE",
    "NAME_ID_FORMAT",
    "NAME_ID_SIZE",
    "PID_TAG_NAMEID_BUCKET_BASE",
    "PID_TAG_NAMEID_BUCKET_COUNT",
    "PID_TAG_NAMEID_STREAM_ENTRY",
    "PID_TAG_NAMEID_STREAM_GUID",
    "PID_TAG_NAMEID_STREAM_STRING",
    "PS_MAPI",
    "PS_PUBLIC_STRINGS",
    "STRING_LENGTH_FORMAT",
    "STRING_LENGTH_SIZE",
    "NameIdEntry",
    "NamedProperty",
    "NamedPropertyGuid",
    "NamedPropertyMap",
]

# [MS-PST] 2.4.7: the four stream properties, and the base of the hash buckets.
PID_TAG_NAMEID_BUCKET_COUNT = 0x0001
PID_TAG_NAMEID_STREAM_GUID = 0x0002
PID_TAG_NAMEID_STREAM_ENTRY = 0x0003
PID_TAG_NAMEID_STREAM_STRING = 0x0004
PID_TAG_NAMEID_BUCKET_BASE = 0x1000

# [MS-PST] 2.4.7.1 NAMEID: dwPropertyID (u32), wGuid (u16), wPropIdx (u16).
NAME_ID_FORMAT = "<IHH"
NAME_ID_SIZE = struct.calcsize(NAME_ID_FORMAT)
GUID_SIZE = 16
STRING_LENGTH_FORMAT = "<I"
STRING_LENGTH_SIZE = struct.calcsize(STRING_LENGTH_FORMAT)

# Upstream's guard on the bucket count: `0x1000 + count` must stay a u16.
MAX_BUCKET_COUNT = 0xFFFF - PID_TAG_NAMEID_BUCKET_BASE

# The first named property id. [MS-PST] 2.4.7.1: `wPropIdx` is the index
# into the named range, so the id a PC uses is this plus wPropIdx.
NAMED_PROPERTY_BASE = 0x8000

# [MS-OXPROPS] 1.3.2 — the two GUIDs `wGuid` names by number instead of storing.
PS_MAPI = uuid.UUID("00020328-0000-0000-c000-000000000046")
PS_PUBLIC_STRINGS = uuid.UUID("00020329-0000-0000-c000-000000000046")

_GUID_NONE = 0
_GUID_MAPI = 1
_GUID_PUBLIC_STRINGS = 2
_GUID_INDEX_BASE = 3


@dataclass(frozen=True, slots=True)
class NamedPropertyGuid:
    """`wGuid >> 1` of a NAMEID — upstream's `NamedPropertyGuid`, which GUID (if any) names the property set.

    0 is "none", 1 is `PS_MAPI`, 2 is `PS_PUBLIC_STRINGS`, and 3 and above
    name the `raw - 3`rd GUID of the GUID stream ([MS-PST] 2.4.7.1).
    """

    raw: int

    def __post_init__(self) -> None:
        if isinstance(self.raw, bool) or not isinstance(self.raw, int) or not 0 <= self.raw <= 0x7FFF:
            # Upstream's `TryFrom<u16>` refuses `value & 0x8000`; the field is
            # 15 bits wide because the low bit of wGuid is the string flag.
            raise PstFormatError(f"NAMEID wGuid is out of bounds: {self.raw!r}")

    @classmethod
    def from_wire(cls, value: int) -> NamedPropertyGuid:
        """The `wGuid >> 1` field as read; 0x8000 and above is `PstFormatError` (upstream's `try_from`)."""
        return cls(value)

    @property
    def is_index(self) -> bool:
        """True when this names a GUID in the stream rather than one of the two well-known ones."""
        return self.raw >= _GUID_INDEX_BASE

    @property
    def index(self) -> int | None:
        """The 0-based position in the GUID stream, or None for none/`PS_MAPI`/`PS_PUBLIC_STRINGS`."""
        return self.raw - _GUID_INDEX_BASE if self.is_index else None

    @property
    def well_known(self) -> uuid.UUID | None:
        """`PS_MAPI` or `PS_PUBLIC_STRINGS` when this names one of them, else None."""
        if self.raw == _GUID_MAPI:
            return PS_MAPI
        if self.raw == _GUID_PUBLIC_STRINGS:
            return PS_PUBLIC_STRINGS
        return None

    def __str__(self) -> str:
        # Upstream's `Debug for NamedPropertyGuid`, which the goldens print.
        if self.raw == _GUID_NONE:
            return "None"
        if self.raw == _GUID_MAPI:
            return "Mapi"
        if self.raw == _GUID_PUBLIC_STRINGS:
            return "PublicStrings"
        return f"GuidIndex({self.raw - _GUID_INDEX_BASE})"


@dataclass(frozen=True, slots=True)
class NameIdEntry:
    """One NAMEID — [MS-PST] 2.4.7.1: 8 bytes of the entry stream.

    `name_id` is `dwPropertyID`: the property's own number when `is_string`
    is false, and an offset into the string stream when it is true.
    """

    name_id: int
    guid: NamedPropertyGuid
    prop_index: int
    is_string: bool

    SIZE: ClassVar[int] = NAME_ID_SIZE

    def __post_init__(self) -> None:
        if isinstance(self.name_id, bool) or not isinstance(self.name_id, int) or not 0 <= self.name_id <= 0xFFFFFFFF:
            raise PstFormatError(f"NAMEID dwPropertyID {self.name_id!r} is not a 32-bit value")
        if not isinstance(self.guid, NamedPropertyGuid):
            raise PstFormatError(f"NAMEID wGuid is {type(self.guid).__name__}, not a NamedPropertyGuid")
        if isinstance(self.prop_index, bool) or not isinstance(self.prop_index, int) or not 0 <= self.prop_index < NAMED_PROPERTY_BASE:
            # Upstream's `NamedPropertyIndex::try_from` refuses >= 0x8000.
            raise PstFormatError(f"NAMEID wPropIdx is out of bounds: {self.prop_index!r}")

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> NameIdEntry:
        """Read one NAMEID from `buf` at `offset`; a short buffer or a `wPropIdx` past the range is `PstFormatError`."""
        name_id, guid_field, prop_index = _unpack(NAME_ID_FORMAT, buf, offset, "NAMEID")
        return cls(name_id, NamedPropertyGuid(guid_field >> 1), prop_index, bool(guid_field & 0x0001))

    @property
    def prop_id(self) -> int:
        """The property id a message's PC carries for this name: `0x8000 + wPropIdx`."""
        return NAMED_PROPERTY_BASE + self.prop_index

    @property
    def hash_value(self) -> int:
        """Upstream's `hash_value`: the key this entry hashes to in the bucket table ([MS-PST] 2.4.7.5)."""
        guid_index = (self.guid.raw << 1) & 0xFFFF
        if self.is_string:
            guid_index |= 0x0001
        return (self.name_id ^ guid_index) & 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class NamedProperty:
    """What a 0x8000+ property id means: the property set's GUID and the name or number inside it."""

    guid: uuid.UUID
    name: str | int

    @property
    def is_string(self) -> bool:
        return isinstance(self.name, str)


class NamedPropertyMap:
    """`NID_NAME_TO_ID_MAP` (0x61) — upstream's `NamedPropertyMapProperties` over its property context.

    The streams are parsed on first use and kept; `lookup` and `resolve`
    index the entry stream, which is the same list the `read_named_props`
    example walks.
    """

    __slots__ = ("_by_name", "_by_prop_id", "_entries", "_guids", "_limits", "_pc")

    def __init__(self, properties: PropertyContext, limits: Limits | None = None) -> None:
        if not isinstance(properties, PropertyContext):
            raise TypeError(f"NamedPropertyMap takes a PropertyContext, not {type(properties).__name__}")
        self._pc = properties
        self._limits = properties.limits if limits is None else limits
        self._guids: tuple[uuid.UUID, ...] | None = None
        self._entries: tuple[NameIdEntry, ...] | None = None
        self._by_prop_id: dict[int, NameIdEntry] | None = None
        self._by_name: dict[tuple[uuid.UUID, str | int], int] | None = None

    @classmethod
    def from_node(
        cls,
        reader: BlockReader,
        entry: NodeBTreeEntry | SubNodeLeafEntry,
        limits: Limits | None = None,
        *,
        codepage: str = "cp1252",
    ) -> NamedPropertyMap:
        """The map over the node `entry` names — `NID_NAME_TO_ID_MAP` in a well-formed store."""
        return cls(PropertyContext.from_node(reader, entry, limits, codepage=codepage), limits)

    @property
    def properties(self) -> PropertyContext:
        """The underlying property context, for a caller that wants the raw streams."""
        return self._pc

    @property
    def limits(self) -> Limits:
        return self._limits

    # --- the four stream properties -------------------------------------------------

    def _stream(self, prop_id: int, what: str) -> bytes:
        record = self._pc.records.get(prop_id)
        if record is None:
            raise PstFormatError(f"missing {what} on Named Property Lookup Map")
        value = self._pc.read(record)
        if value is None:
            # Upstream's `PropertyValue::Null` arm: not Binary, so `invalid`.
            raise PstFormatError(f"invalid {what} on Named Property Lookup Map: Null, not Binary")
        if not isinstance(value, bytes):
            raise PstFormatError(
                f"invalid {what} on Named Property Lookup Map: {record.value_type.debug_name}, not Binary"
            )
        return value

    @property
    def bucket_count(self) -> int:
        """`PidTagNameidBucketCount` (0x0001) — how many hash buckets the map has ([MS-PST] 2.4.7.5)."""
        record = self._pc.records.get(PID_TAG_NAMEID_BUCKET_COUNT)
        if record is None:
            raise PstFormatError("missing PidTagNameidBucketCount on Named Property Lookup Map")
        if record.prop_type is not PropType.LONG:
            raise PstFormatError(
                f"invalid PidTagNameidBucketCount on Named Property Lookup Map: "
                f"{record.value_type.debug_name}, not Integer32"
            )
        value = self._pc.read(record)
        assert isinstance(value, int)  # PropType.LONG decodes to an int or raises
        if not 0 <= value <= MAX_BUCKET_COUNT:
            raise PstFormatError(f"PidTagNameidBucketCount on Named Property Lookup Map is out of bounds: 0x{value:08X}")
        if value == 0 and self.entries:
            # Upstream divides by this; a map with entries and no buckets cannot be probed.
            raise PstFormatError(
                f"PidTagNameidBucketCount is 0 on a Named Property Lookup Map with {len(self.entries)} entries"
            )
        highest = max((prop_id for prop_id in self._pc.records if prop_id >= PID_TAG_NAMEID_BUCKET_BASE), default=None)
        if highest is not None and highest - PID_TAG_NAMEID_BUCKET_BASE >= value:
            raise PstFormatError(
                f"Named Property Lookup Map has hash bucket 0x{highest:04X} "
                f"but PidTagNameidBucketCount is {value}"
            )
        return value

    @property
    def guids(self) -> tuple[uuid.UUID, ...]:
        """`PidTagNameidStreamGuid` (0x0002) — the GUID stream, one entry per 16 bytes ([MS-PST] 2.4.7.2)."""
        if self._guids is None:
            data = self._stream(PID_TAG_NAMEID_STREAM_GUID, "PidTagNameidStreamGuid")
            if len(data) % GUID_SIZE:
                raise PstFormatError(
                    f"PidTagNameidStreamGuid is {len(data)} bytes, not a whole number of {GUID_SIZE}-byte GUIDs"
                )
            check_count(len(data) // GUID_SIZE, self._limits.max_items, "named property GUIDs")
            self._guids = tuple(
                uuid.UUID(bytes_le=data[at : at + GUID_SIZE]) for at in range(0, len(data), GUID_SIZE)
            )
        return self._guids

    @property
    def entries(self) -> tuple[NameIdEntry, ...]:
        """`PidTagNameidStreamEntry` (0x0003) — every NAMEID, in stream order ([MS-PST] 2.4.7.3)."""
        if self._entries is None:
            data = self._stream(PID_TAG_NAMEID_STREAM_ENTRY, "PidTagNameidStreamEntry")
            if len(data) % NAME_ID_SIZE:
                raise PstFormatError(
                    f"PidTagNameidStreamEntry is {len(data)} bytes, not a whole number of {NAME_ID_SIZE}-byte NAMEIDs"
                )
            check_count(len(data) // NAME_ID_SIZE, self._limits.max_items, "named property entries")
            self._entries = tuple(
                NameIdEntry.unpack_from(data, at) for at in range(0, len(data), NAME_ID_SIZE)
            )
        return self._entries

    def string_bytes(self, offset: int) -> bytes:
        """The raw UTF-16LE name at `offset` in `PidTagNameidStreamString` (0x0004) — upstream's `StringEntry` buffer.

        A u32 byte length then that many bytes ([MS-PST] 2.4.7.4). The
        length must be even and inside the stream; upstream checks the same
        two things (`InvalidNamedPropertyMapStreamString`,
        `NamedPropertyMapStringEntryOutOfBounds`) and then panics on a slice
        past the end, which this refuses instead.
        """
        if isinstance(offset, bool) or not isinstance(offset, int):
            raise TypeError(f"string_bytes takes an int offset, not {type(offset).__name__}")
        data = self._stream(PID_TAG_NAMEID_STREAM_STRING, "PidTagNameidStreamString")
        (size,) = _unpack(STRING_LENGTH_FORMAT, data, offset, "PidTagNameidStreamString entry")
        if size % 2:
            raise PstFormatError(f"PidTagNameidStreamString entry at 0x{offset:08X} has odd length {size}")
        start = offset + STRING_LENGTH_SIZE
        if start + size > len(data):
            raise PstFormatError(
                f"PidTagNameidStreamString entry at 0x{offset:08X} claims {size} bytes, past the {len(data)}-byte stream"
            )
        return data[start : start + size]

    def lookup_string(self, offset: int) -> str:
        """The name at `offset` in the string stream, decoded.

        Upstream's `Display for StringEntry` is `String::from_utf16_lossy`,
        which substitutes U+FFFD for an unpaired surrogate rather than
        failing; a name is a label, and refusing a whole map over one bad
        code unit in one of them is the worse answer.
        """
        return self.string_bytes(offset).decode("utf-16-le", errors="replace")

    # --- what an entry means ----------------------------------------------------------

    def guid_of(self, entry: NameIdEntry) -> uuid.UUID:
        """The property set GUID of one NAMEID — one of the two well-known ones, or the GUID stream's."""
        if not isinstance(entry, NameIdEntry):
            raise TypeError(f"guid_of takes a NameIdEntry, not {type(entry).__name__}")
        known = entry.guid.well_known
        if known is not None:
            return known
        index = entry.guid.index
        if index is None:
            # wGuid >> 1 == 0: upstream prints `None` and never looks a GUID
            # up, so there is nothing to return but the null GUID.
            return uuid.UUID(int=0)
        guids = self.guids
        if index >= len(guids):
            raise PstFormatError(f"NAMEID wGuid index {index} is past the {len(guids)}-GUID stream")
        return guids[index]

    def name_of(self, entry: NameIdEntry) -> str | int:
        """The name of one NAMEID: the string the string stream holds, or `dwPropertyID` as a number."""
        if not isinstance(entry, NameIdEntry):
            raise TypeError(f"name_of takes a NameIdEntry, not {type(entry).__name__}")
        return self.lookup_string(entry.name_id) if entry.is_string else entry.name_id

    def _index(self) -> dict[int, NameIdEntry]:
        if self._by_prop_id is None:
            found: dict[int, NameIdEntry] = {}
            for entry in self.entries:
                if entry.prop_id in found:
                    raise PstFormatError(f"named property 0x{entry.prop_id:04X} appears twice in the entry stream")
                found[entry.prop_id] = entry
            self._by_prop_id = found
        return self._by_prop_id

    def lookup(self, prop_id: int) -> NamedProperty | None:
        """What the 0x8000+ id `prop_id` means in this store, or None when the map does not hold it."""
        if isinstance(prop_id, bool) or not isinstance(prop_id, int):
            raise TypeError(f"lookup takes an int property id, not {type(prop_id).__name__}")
        entry = self._index().get(prop_id)
        if entry is None:
            return None
        return NamedProperty(self.guid_of(entry), self.name_of(entry))

    def resolve(self, guid: uuid.UUID, name: str | int) -> int | None:
        """The 0x8000+ id this store gave `(guid, name)`, or None — the inverse of `lookup`.

        The first entry wins when two claim the same name: upstream has no
        opinion (it never builds this index) and a repeated name is not, by
        itself, evidence of corruption the way a repeated id is.
        """
        if not isinstance(guid, uuid.UUID):
            raise TypeError(f"resolve takes a uuid.UUID, not {type(guid).__name__}")
        if isinstance(name, bool) or not isinstance(name, (str, int)):
            raise TypeError(f"resolve takes a str or int name, not {type(name).__name__}")
        if self._by_name is None:
            index: dict[tuple[uuid.UUID, str | int], int] = {}
            for entry in self.entries:
                index.setdefault((self.guid_of(entry), self.name_of(entry)), entry.prop_id)
            self._by_name = index
        return self._by_name.get((guid, name))

    def hash_entry(self, entry: NameIdEntry) -> NameIdEntry:
        """Upstream's `hash_entry`: the form of a NAMEID that the hash table is keyed by ([MS-PST] 2.4.7.5).

        A numeric name hashes as itself. A **string** name does not hash by
        its offset into the string stream — the offset is where this store
        happened to put it — but by the CRC-32 of the name's bytes, which is
        what the hash table's own NAMEIDs carry. `wGuid` is kept: see the
        divergence in the module docstring, and
        `tests/test_named_prop.py::test_every_entry_is_in_the_bucket_its_hash_names`,
        which checks the result against 964 real entries.

        Upstream leaves this call to the caller (`read_named_props` never
        makes it); `hash_bucket` here applies it, because a `hash_bucket`
        that silently misses every string-named property is a trap.
        """
        if not isinstance(entry, NameIdEntry):
            raise TypeError(f"hash_entry takes a NameIdEntry, not {type(entry).__name__}")
        if not entry.is_string:
            return entry
        return NameIdEntry(compute_crc(0, self.string_bytes(entry.name_id)), entry.guid, entry.prop_index, True)

    def hash_bucket(self, entry: NameIdEntry) -> tuple[NameIdEntry, ...]:
        """Upstream's `hash_bucket`: the NAMEIDs in the hash bucket `entry` belongs to ([MS-PST] 2.4.7.5)."""
        entry = self.hash_entry(entry)
        count = self.bucket_count
        if count == 0:
            raise PstFormatError("Named Property Lookup Map has no hash buckets")
        offset = entry.hash_value % count
        prop_id = PID_TAG_NAMEID_BUCKET_BASE + offset
        if prop_id not in self._pc.records:
            raise PstNotFoundError(
                f"missing PidTagNameidBucketBase + hash on Named Property Lookup Map: 0x{offset:04X}"
            )
        data = self._stream(prop_id, f"PidTagNameidBucketBase + 0x{offset:04X}")
        if len(data) % NAME_ID_SIZE:
            raise PstFormatError(
                f"hash bucket 0x{prop_id:04X} is {len(data)} bytes, not a whole number of {NAME_ID_SIZE}-byte NAMEIDs"
            )
        check_count(len(data) // NAME_ID_SIZE, self._limits.max_items, "hash bucket entries")
        return tuple(NameIdEntry.unpack_from(data, at) for at in range(0, len(data), NAME_ID_SIZE))

    def __len__(self) -> int:
        return len(self.entries)
