"""Property Context (PC) — a node's properties, as a BTH of (id → type, value-or-HNID) records over its heap.

Ported from: crates/pst/src/ltp/prop_context.rs (the record types, `PropertyContextInner::properties`
             and `read_property`; the value decoders are P22's `pypstreader.ltp.prop_type`)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.3.3 Property Context, 2.3.3.1 PC BTH record layout, 2.3.3.2 HNID,
             2.3.3.3 PC BTH Record (wPropType, dwValueHnid), 2.3.3.4 multi-valued properties

A PC is what the message store (NID 0x21), every folder, every message,
every attachment and the name-to-id map (NID 0x61) keep their properties
in: a heap (`pypstreader.ltp.heap`) whose client signature is `bTypePC` (0xBC)
and whose user root is a BTH (`pypstreader.ltp.tree`) keyed by the 2-byte
property id, each leaf carrying a 6-byte record — `wPropType` and
`dwValueHnid`. That last field is the whole subtlety of the layer. For a
fixed-size type of four bytes or fewer the value IS the field
(`PropertyValueRecord::Small`); for every other type the field is an HNID
([MS-PST] 2.3.3.2): an HID into this heap when its type bits are zero
(`Heap`), the NID of a sub-node of the same node when they are not
(`Node`), whose data is the value. An HNID of zero means the property has no
value — upstream's `PropertyValue::Null`.

**Record → value, exactly upstream's `read_property`.** Upstream's
`PropertyTreeRecordValue::read` decides the record's shape by type: `Null`
and the ≤ 4-byte scalars (Integer16, Integer32, Floating32, ErrorCode,
Boolean) are `Small`, masked to their width (`& 0xFFFF`, `& 0xFF`); the
8- and 16-byte scalars (Floating64, Currency, FloatingTime, Integer64,
Time, Guid) and Object are always `Heap`; every remaining type is `Heap` or
`Node` by the HNID's type bits. `read_property` then returns `Null` for a
heap id of 0, `find_entry`'s bytes for a heap id, the sub-node's whole data
tree for a node id, and `small_value` for a `Small`. `PropertyRecord` here
carries the raw field and derives the same classification (`is_inline`,
`hnid`, `is_null`); `PropertyContext.read` follows the same arms and hands
the bytes to `prop_type.decode`. `HeapNode.get_hnid` is the `Heap`/`Node`
switch, `PstNotFoundError` when the sub-node is not in the node's tree
(upstream's `PropertySubNodeValueNotFound`).

**What upstream's examples print, and what its library returns.**
`read_store_props` prints `Type: Null` for a variable-size record whose
HNID is 0 — `PropertyType::from(&value)` names the VALUE's variant, not
`wPropType`. The library returns `PropertyValue::Null` for it; here `get`
returns `None`, `PropertyRecord.prop_type` keeps the declared type and
`PropertyRecord.value_type` is the printed one (`NULL` for a null HNID).
`get` also returns `None` for a property that is absent — `records` and
`__contains__` tell the two apart, as upstream's `Option<&PropertyValue>`
does.

**Order.** Upstream collects the records into a `BTreeMap<u16, _>`, so its
examples print properties in ascending id order whatever order the BTH
holds them in; `records` and `__iter__` sort the same way.

**Deliberate divergences from upstream**, each chosen to fail closed:

- A `PtypNull` record (wPropType 0x0001) decodes to `None`. Upstream reads
  it as `Small(0)` and then `small_value` has no `Null` arm, so
  `read_property` fails with `InvalidSmallPropertyType(Null)` — which, since
  the store reads every property eagerly, makes the whole store unopenable.
  [MS-OXCDATA] 2.11.1 says PtypNull is "a placeholder"; a placeholder is
  `None`.
- An 8- or 16-byte scalar or Object whose HNID has non-zero type bits is
  `PstFormatError`. Upstream builds `HeapId::from(value)` regardless and
  reads the heap item at `raw >> 5` with the type bits ignored — some bytes
  from somewhere. Such a value always fits the heap ([MS-PST] 2.3.3.3), so
  a correct writer never produces the form.
- A duplicate property id is `PstFormatError`. Upstream's `collect` into a
  `BTreeMap` keeps the last silently; a BTH's keys are unique by
  construction ([MS-PST] 2.3.2), so a repeat is corruption.
- The BTH must be keyed by 2 bytes with 6-byte records before anything is
  read (upstream checks `K::SIZE`/`V::SIZE` in `HeapTree::new` too — this
  is the same check, named here so a TC's user root or a garbage header is
  refused as "not a PC" rather than mid-walk).
- Counts are bounded: more than `limits.max_property_count` records is
  `PstLimitError` (checked as the BTH is walked, before the next record is
  kept); a multi-value's item count goes through `decode`'s `max_items`
  (`limits.max_mv_items`).
- `PtypBoolean` inline is the strict form — the low byte must be 0 or 1,
  as P22 decided for every path; upstream's PC arm is `value & 0xFF != 0`.
  The other three bytes are ignored, as upstream ignores them.
- `PtypObject` (0x000D) IS decoded, to an `ObjectRef(NodeId, size)`. At the
  pin, upstream's `PropertyType::try_from` has no `PtypObject` arm, so it
  cannot open any PC that carries one (every attachment with an embedded
  message — P19's finding, todo/T03-messaging.md § P09); the spec lists
  the type ([MS-OXCDATA] 2.11.1) and `pstsdk-submessage.pst` has one.
- An unknown `wPropType` is `PstUnsupportedError` naming the property and
  the type, raised when `records` is built — as upstream's `try_from` fails
  its `properties()` call — never read as raw bytes.

**MV_GUID, settled as far as the evidence goes.** P22 followed upstream in
reading `PtypMultipleGuid` with a leading u32 count where [MS-PST]
2.3.3.4.1 implies a packed array, and asked this row to settle it on a real
store. Neither private store on the developer's box carries a 0x1048
property (a structure-only survey of every PC in every node and sub-node
of both, 2026-09-16: 98 contexts, types seen 0x0003, 0x000B, 0x001F,
0x0040, 0x0048, 0x0102, 0x1102), nor does any corpus store (0x0005,
0x000D, 0x0014 and 0x1003 appear there, 0x1048 does not). Upstream's
reading and P22's pin (`test_mv_guid_follows_upstream_count_prefix`)
stand. The survey is a standing test (`tests/test_prop_context.py`,
`test_no_private_store_carries_an_mv_guid_property`), so the first real
store that has one turns red and `_decode_mv_guid` gets settled on it.

**Strings.** Upstream has no code page: a `PtypString8` byte becomes
U+00XX. `PropertyContext` takes `codepage` (default cp1252, the Windows
default) and hands it to `decode`; the dumper passes `latin-1` so that it
reproduces upstream's output byte for byte.

Nothing but `PstError` subclasses escapes for any input bytes: a sub-node
absent from the tree is `PstNotFoundError` (a `PstFormatError`), a type this
port does not decode is `PstUnsupportedError`, a ceiling is `PstLimitError`,
and everything else about the bytes is `PstFormatError`.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import ClassVar

from pypstreader.errors import PstFormatError, PstUnsupportedError
from pypstreader.limits import Limits, check_count
from pypstreader.ltp.heap import HeapNode, HeapNodeId, HeapNodeType
from pypstreader.ltp.prop_type import PropType, PropValue, decode
from pypstreader.ltp.tree import HeapTree
from pypstreader.ndb.block import BlockReader, SubNodeLeafEntry
from pypstreader.ndb.ids import _unpack
from pypstreader.ndb.page import NodeBTreeEntry

__all__ = [
    "PC_KEY_FORMAT",
    "PC_KEY_SIZE",
    "PC_RECORD_FORMAT",
    "PC_RECORD_SIZE",
    "PropertyContext",
    "PropertyRecord",
]

# [MS-PST] 2.3.3.3: the BTH key is the u16 property id; the record is wPropType (u16) + dwValueHnid (u32).
PC_KEY_FORMAT = "<H"
PC_KEY_SIZE = 2
PC_RECORD_FORMAT = "<HI"
PC_RECORD_SIZE = 6

# Upstream's `PropertyTreeRecordValue::read`: the types whose value is the
# dwValueHnid field itself (`Small`), by width.
_INLINE_WIDTHS: dict[PropType, int] = {
    PropType.NULL: 0,
    PropType.SHORT: 2,
    PropType.LONG: 4,
    PropType.FLOAT: 4,
    PropType.ERROR: 4,
    PropType.BOOLEAN: 1,
}

# ... and the types whose record is always a heap id (`Heap`), never a sub-node.
_HEAP_ONLY_TYPES = frozenset(
    {
        PropType.DOUBLE,
        PropType.CURRENCY,
        PropType.APPTIME,
        PropType.LONGLONG,
        PropType.SYSTIME,
        PropType.GUID,
        PropType.OBJECT,
    }
)


@dataclass(frozen=True, slots=True)
class PropertyRecord:
    """One PC BTH leaf — upstream's `PropertyTreeRecord`: the property id, its type, and `dwValueHnid` as read.

    `raw` is the 4-byte field whatever it means: the inline value of a
    ≤ 4-byte scalar, or an HNID. The properties below say which, as
    upstream's `PropertyValueRecord` variants do.
    """

    prop_id: int
    prop_type: PropType
    raw: int

    SIZE: ClassVar[int] = PC_KEY_SIZE + PC_RECORD_SIZE

    def __post_init__(self) -> None:
        if isinstance(self.prop_id, bool) or not isinstance(self.prop_id, int) or not 0 <= self.prop_id <= 0xFFFF:
            raise PstFormatError(f"property id {self.prop_id!r} is not a 16-bit value")
        if isinstance(self.raw, bool) or not isinstance(self.raw, int) or not 0 <= self.raw <= 0xFFFFFFFF:
            raise PstFormatError(f"property 0x{self.prop_id:04X}: dwValueHnid {self.raw!r} is not a 32-bit value")
        if not isinstance(self.prop_type, PropType):
            raise PstFormatError(f"property 0x{self.prop_id:04X}: {self.prop_type!r} is not a PropType")

    @classmethod
    def unpack(cls, key: bytes, value: bytes) -> PropertyRecord:
        """From a PC BTH leaf's key and value bytes; an unknown `wPropType` is `PstUnsupportedError` naming both."""
        (prop_id,) = _unpack(PC_KEY_FORMAT, key, 0, "PC record key")
        wire_type, raw = _unpack(PC_RECORD_FORMAT, value, 0, f"property 0x{prop_id:04X} record")
        try:
            prop_type = PropType.from_wire(wire_type)
        except PstUnsupportedError:
            raise PstUnsupportedError(f"property 0x{prop_id:04X}: property type 0x{wire_type:04X}") from None
        return cls(prop_id, prop_type, raw)

    @property
    def is_inline(self) -> bool:
        """True when `raw` is the value itself (upstream's `Small`): Null and the ≤ 4-byte scalars."""
        return self.prop_type in _INLINE_WIDTHS

    @property
    def hnid(self) -> HeapNodeId | None:
        """The HNID this record carries, or None for an inline record."""
        return None if self.is_inline else HeapNodeId(self.raw)

    @property
    def is_null(self) -> bool:
        """An HNID of 0 on a non-inline type — upstream's `PropertyValue::Null`; `get` returns None."""
        return not self.is_inline and self.raw == 0

    @property
    def value_type(self) -> PropType:
        """The type of the decoded value — `prop_type`, or `NULL` for a null HNID — which is the `Type:` the goldens print."""
        return PropType.NULL if self.is_null else self.prop_type

    def __str__(self) -> str:
        # Upstream's `Debug for PropertyValueRecord`: `Small(0x%08X)`, the HeapId's Debug, or the NodeId's.
        if self.is_inline:
            width = _INLINE_WIDTHS[self.prop_type]
            masked = self.raw & ((1 << (8 * width)) - 1) if width else 0
            return f"Small(0x{masked:08X})"
        hnid = HeapNodeId(self.raw)
        if self.prop_type in _HEAP_ONLY_TYPES and not hnid.is_heap:
            # Upstream would print it as a HeapId with the type bits ignored; this port refuses to read it.
            return f"HeapId(NodeId {{ HeapNode: 0x{self.raw >> 5:X} }})"
        return str(hnid)


class PropertyContext:
    """The properties of one node — upstream's `UnicodePropertyContext` plus its `read_property`.

    Built over a `HeapNode` whose client signature is `bTypePC`; `from_node`
    is the constructor every caller wants. Records are parsed once, on the
    first use of `records` / `get` / iteration; values are decoded on
    demand and never cached (a caller that wants them all iterates once).
    """

    __slots__ = ("_codepage", "_heap", "_limits", "_records", "_tree")

    def __init__(self, heap: HeapNode, limits: Limits | None = None, *, codepage: str = "cp1252") -> None:
        if not isinstance(heap, HeapNode):
            raise TypeError(f"PropertyContext takes a HeapNode, not {type(heap).__name__}")
        if heap.client_signature is not HeapNodeType.PROPERTIES:
            raise PstFormatError(
                f"heap client signature 0x{heap.client_signature:02X} is not bTypePC 0x{HeapNodeType.PROPERTIES:02X}"
            )
        self._heap = heap
        self._limits = heap.limits if limits is None else limits
        self._codepage = codepage
        self._tree = HeapTree(heap)
        if self._tree.key_size != PC_KEY_SIZE or self._tree.entry_size != PC_RECORD_SIZE:
            raise PstFormatError(
                f"PC BTH has {self._tree.key_size}-byte keys and {self._tree.entry_size}-byte records, "
                f"not {PC_KEY_SIZE} and {PC_RECORD_SIZE}"
            )
        self._records: Mapping[int, PropertyRecord] | None = None

    @classmethod
    def from_node(
        cls,
        reader: BlockReader,
        entry: NodeBTreeEntry | SubNodeLeafEntry,
        limits: Limits | None = None,
        *,
        codepage: str = "cp1252",
    ) -> PropertyContext:
        """The PC of the node `entry` names, read through `reader` (a `SubNodeLeafEntry` for an attachment's or embedded message's)."""
        return cls(HeapNode.from_node(reader, entry, limits), limits, codepage=codepage)

    # --- structure ---------------------------------------------------------------

    @property
    def heap(self) -> HeapNode:
        return self._heap

    @property
    def tree(self) -> HeapTree:
        return self._tree

    @property
    def limits(self) -> Limits:
        return self._limits

    @property
    def codepage(self) -> str:
        return self._codepage

    @property
    def records(self) -> Mapping[int, PropertyRecord]:
        """Every record by property id, in ascending id order (upstream's `properties()` BTreeMap); read-only."""
        if self._records is None:
            ceiling = self._limits.max_property_count
            found: dict[int, PropertyRecord] = {}
            for key, value in self._tree:
                record = PropertyRecord.unpack(key, value)
                if record.prop_id in found:
                    raise PstFormatError(f"property 0x{record.prop_id:04X} appears twice in the PC")
                found[record.prop_id] = record
                check_count(len(found), ceiling, "PC records")
            self._records = MappingProxyType(dict(sorted(found.items())))
        return self._records

    def __len__(self) -> int:
        return len(self.records)

    def __contains__(self, prop_id: object) -> bool:
        return prop_id in self.records

    # --- values ------------------------------------------------------------------

    def read(self, record: PropertyRecord) -> PropValue:
        """Upstream's `read_property`: the decoded value of one record (module docstring for the arms)."""
        if not isinstance(record, PropertyRecord):
            raise TypeError(f"PropertyContext.read takes a PropertyRecord, not {type(record).__name__}")
        t = record.prop_type
        width = _INLINE_WIDTHS.get(t)
        if width is not None:
            # `Small`: the value is the field, masked to its width as upstream masks it.
            return decode(t, (record.raw & ((1 << (8 * width)) - 1)).to_bytes(width, "little"))
        if record.raw == 0:
            return None
        hnid = HeapNodeId(record.raw)
        if t in _HEAP_ONLY_TYPES and not hnid.is_heap:
            raise PstFormatError(
                f"property 0x{record.prop_id:04X}: {t.name} value has HNID 0x{record.raw:08X} with type bits, not an HID"
            )
        data = self._heap.get_hnid(hnid)
        return decode(t, data, codepage=self._codepage, max_items=self._limits.max_mv_items)

    def get(self, prop_id: int) -> PropValue | None:
        """The decoded value of `prop_id`, or None when the property is absent or its HNID is 0 (`records` tells which)."""
        record = self.records.get(prop_id)
        return None if record is None else self.read(record)

    def __iter__(self) -> Iterator[tuple[int, PropValue]]:
        """`(prop_id, value)` for every record in ascending id order — the order `read_store_props` prints."""
        for prop_id, record in self.records.items():
            yield prop_id, self.read(record)
