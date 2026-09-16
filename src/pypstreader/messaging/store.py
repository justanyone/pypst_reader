"""The Message Store — the PST's root object: its name, its record key and the entry ids it points at.

Ported from: crates/pst/src/messaging/store.rs (`StoreRecordKey`, `EntryId`, `StoreProperties`
             and the read half of `StoreInner`/`UnicodeStore`; the write half and the ANSI arm
             are not ported — ADR-0003)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.4.3 Message Store, 2.4.3.1 Minimum Set of Required Properties,
             2.4.3.2 Mapping between EntryID and NID, 2.2.2.1 NID

Every PST has exactly one message store node, `NID_MESSAGE_STORE` (0x21),
and it is a property context ([MS-PST] 2.4.3). Four of its properties are
the doorway to everything else: `PidTagRecordKey` (0x0FF9), the 16-byte
identifier every EntryID in this store repeats; `PidTagDisplayName`
(0x3001); `PidTagIpmSubTreeEntryId` (0x35E0), the root of the user-visible
folder tree; and `PidTagIpmWastebasketEntryId` (0x35E3) and
`PidTagFinderEntryId` (0x35E7) beside it.

An **EntryID** is 24 bytes ([MS-PST] 2.4.3.2): a u32 `rgbFlags` that must
be zero, the store's 16-byte record key, and the 4-byte NID of the node it
names. It carries the record key so that a caller can tell an id from this
store from an id from another one — `matches_record_key` is that check,
and P08 will refuse a folder id that fails it.

`Store` owns the open file. `Store.open(path)` is the constructor and a
context manager; `close()` releases the handle and is idempotent. What it
reads eagerly is what upstream's `StoreInner::read` reads eagerly: the
header, the node and block B-trees, a `BlockReader`, and the store PC's
record table. Named properties are read on first use, as upstream's
`store.named_property_map()` is.

**`root_folder` and `open_folder` were added by P08** (folders) and return
`pypstreader.messaging.folder.Folder`; **`open_message` was added by P09** and
returns `pypstreader.messaging.message.Message`. Both `folder` and `message`
import this module, so the three accessors import them inside the call
rather than at module scope — the cycle is real and is broken at the only
points where it does not matter.

**Deliberate divergences from upstream**, each chosen to fail closed or to
fit Python's conventions:

- **A missing `PidTagIpmWastebasketEntryId` or `PidTagFinderEntryId` is
  `None`, not a refusal, and the store still opens.** Upstream's accessors
  return `Err(StoreIpmWastebasketEntryIdNotFound)` / `Err(StoreFinderEntryIdNotFound)`,
  which is why `read_store_props` exits 1 on `pstd-inline-cid.pst` (a store
  written by EMLtoPST, not Outlook: it has the IPM subtree and neither of
  the other two). Note what upstream does *not* do: `open_store` itself
  succeeds on that file — `read_named_props` exits 0 on it — so the store
  is readable and only those two accessors fail. [MS-PST] 2.4.3.1 lists
  neither property as required. Refusing the whole store for an absent
  optional property would make this reader useless on a family of real
  files that the upstream *library* opens happily, so both accessors are
  `EntryId | None` (as docs/INTERFACES.md already typed them) and
  `ipm_subtree` stays mandatory. `python -m pypstreader.debug store` still
  reproduces the oracle's refusal exactly, because the example's contract
  is the example's: see `pypstreader.debug.dump_store`.
- **An EntryID property must be exactly 24 bytes.** Upstream reads 24 bytes
  out of a `Cursor` and ignores whatever follows, so a 25-byte value parses.
  All 8 Unicode corpus stores write exactly 24; a longer value is a writer
  this port has not seen and should not guess at.
- **Property values are decoded on demand**, where upstream decodes every
  store property while opening and fails the open if any one of them fails.
  Nothing observable changes on the corpus (no store has a property upstream
  can read and this port cannot), and failing at the property a caller asked
  for beats failing at a property nobody wanted.
- **`open()` lets `OSError` through.** Opening the path is the operating
  system's business — `FileNotFoundError`, `IsADirectoryError`,
  `PermissionError` — and a Python caller expects those by name and catches
  them where it handles paths. Everything about the *bytes* of a file that
  did open is a `PstError`, which is the promise CLAUDE.md makes.

Nothing but `PstError` escapes once the file is open: an absent node is
`PstNotFoundError`, an ANSI store is `PstUnsupportedError` (from
`read_header`), a ceiling is `PstLimitError`, and everything else about the
bytes is `PstFormatError`.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, BinaryIO, ClassVar, Self

from pypstreader.errors import PstFormatError
from pypstreader.limits import DEFAULT_LIMITS, Limits
from pypstreader.ltp.prop_context import PropertyContext, PropertyRecord
from pypstreader.ltp.prop_type import PropValue
from pypstreader.messaging.named_prop import NamedPropertyMap
from pypstreader.ndb.block import BlockReader
from pypstreader.ndb.btree import BlockBTree, NodeBTree
from pypstreader.ndb.header import Header, read_header
from pypstreader.ndb.ids import (
    NID_MESSAGE_STORE,
    NID_NAME_TO_ID_MAP,
    NID_ROOT_FOLDER,
    NodeId,
    _unpack,
)

if TYPE_CHECKING:
    from pypstreader.messaging.folder import Folder
    from pypstreader.messaging.message import Message

__all__ = [
    "ENTRY_ID_FORMAT",
    "ENTRY_ID_SIZE",
    "PID_TAG_DISPLAY_NAME",
    "PID_TAG_FINDER_ENTRY_ID",
    "PID_TAG_IPM_SUB_TREE_ENTRY_ID",
    "PID_TAG_IPM_WASTEBASKET_ENTRY_ID",
    "PID_TAG_RECORD_KEY",
    "RECORD_KEY_SIZE",
    "EntryId",
    "Store",
    "open_store",
]

# [MS-PST] 2.4.3.2: rgbFlags (u32, zero), uid (the store's 16-byte record key), nid (u32).
ENTRY_ID_FORMAT = "<I16sI"
ENTRY_ID_SIZE = struct.calcsize(ENTRY_ID_FORMAT)
RECORD_KEY_SIZE = 16

# [MS-PST] 2.4.3.1 — the store properties this layer reads by name.
PID_TAG_RECORD_KEY = 0x0FF9
PID_TAG_DISPLAY_NAME = 0x3001
PID_TAG_IPM_SUB_TREE_ENTRY_ID = 0x35E0
PID_TAG_IPM_WASTEBASKET_ENTRY_ID = 0x35E3
PID_TAG_FINDER_ENTRY_ID = 0x35E7


@dataclass(frozen=True, slots=True)
class EntryId:
    """An EntryID — [MS-PST] 2.4.3.2: the store's record key plus the NID of one node.

    24 bytes on the wire: `rgbFlags` (must be zero), `uid` (16 bytes), `nid`
    (4 bytes). `record_key` is the same 16 bytes for every id in one store,
    which is what makes an id from another store detectable.
    """

    record_key: bytes
    node: NodeId

    SIZE: ClassVar[int] = ENTRY_ID_SIZE

    def __post_init__(self) -> None:
        if not isinstance(self.record_key, (bytes, bytearray)):
            raise PstFormatError(f"EntryId record key is {type(self.record_key).__name__}, not bytes")
        if len(self.record_key) != RECORD_KEY_SIZE:
            raise PstFormatError(f"EntryId record key is {len(self.record_key)} bytes, not {RECORD_KEY_SIZE}")
        if not isinstance(self.node, NodeId):
            raise PstFormatError(f"EntryId node is {type(self.node).__name__}, not a NodeId")
        object.__setattr__(self, "record_key", bytes(self.record_key))

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> EntryId:
        """Read an EntryID from `buf` at `offset`; a short buffer or a non-zero `rgbFlags` is `PstFormatError`."""
        flags, record_key, node = _unpack(ENTRY_ID_FORMAT, buf, offset, "EntryId")
        if flags != 0:
            raise PstFormatError(f"EntryId rgbFlags is 0x{flags:08X}, not 0")
        return cls(record_key, NodeId(node))

    def pack(self) -> bytes:
        """The on-disk bytes; exists so a round trip can be tested."""
        return struct.pack(ENTRY_ID_FORMAT, 0, self.record_key, self.node.raw)

    def __str__(self) -> str:
        # Upstream's `Debug for EntryId`, with `StoreRecordKey`'s `AA-BB-…` inside it.
        key = "-".join(f"{b:02X}" for b in self.record_key)
        return f"EntryId {{ record_key: {key}, node_id: {self.node} }}"


class Store:
    """An open PST: the file, the parsed NDB layer over it, and the message store's properties.

    `Store.open(path)` is the constructor and a context manager. The
    instance owns the file handle when it opened one itself; a caller that
    passes its own `BinaryIO` keeps ownership (`owns_file=False`, the
    default) and `close()` leaves it alone.
    """

    __slots__ = (
        "_bbt",
        "_codepage",
        "_f",
        "_header",
        "_limits",
        "_named",
        "_nbt",
        "_owns_file",
        "_path",
        "_properties",
        "_reader",
    )

    def __init__(
        self,
        f: BinaryIO,
        *,
        path: Path | None = None,
        limits: Limits = DEFAULT_LIMITS,
        codepage: str = "cp1252",
        owns_file: bool = False,
    ) -> None:
        """Read the header, both B-trees and the message store's property records from `f`.

        Exactly what upstream's `StoreInner::read` reads before it returns;
        a store whose 0x21 node is absent or is not a property context is
        refused here rather than at the first property access. `codepage` is
        handed to every property context this store builds, for `PtypString8`
        (`pypstreader.ltp.prop_type.decode`).
        """
        self._f = f
        self._path = path
        self._limits = limits
        self._codepage = codepage
        self._owns_file = owns_file
        self._named: NamedPropertyMap | None = None
        self._header = read_header(f)
        root = self._header.root
        self._bbt = BlockBTree(f, root.block_btree, limits)
        self._nbt = NodeBTree(f, root.node_btree, limits)
        self._reader = BlockReader(f, self._header, self._bbt, limits)
        self._properties = PropertyContext.from_node(
            self._reader, self._nbt.find(NID_MESSAGE_STORE), limits, codepage=codepage
        )
        self._properties.records  # noqa: B018 — materialised here, as upstream reads them at open

    @classmethod
    def open(
        cls,
        path: str | os.PathLike[str],
        *,
        limits: Limits = DEFAULT_LIMITS,
        codepage: str = "cp1252",
    ) -> Store:
        """Open the store at `path`. The returned object owns the file and is a context manager.

        `OSError` from opening the path is the operating system's and is not
        wrapped (module docstring); everything about the bytes is a
        `PstError`, and the file is closed before one propagates.
        """
        p = Path(path)
        f = p.open("rb")
        try:
            return cls(f, path=p, limits=limits, codepage=codepage, owns_file=True)
        except BaseException:
            f.close()
            raise

    def close(self) -> None:
        """Release the file handle if this store opened it. Idempotent."""
        if self._owns_file and not self._f.closed:
            self._f.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # --- the layers underneath ------------------------------------------------------

    @property
    def path(self) -> Path | None:
        """Where the store was opened from, or None when it was handed a file object."""
        return self._path

    @property
    def limits(self) -> Limits:
        return self._limits

    @property
    def codepage(self) -> str:
        """The code page `PtypString8` values are decoded with (`pypstreader.debug` passes latin-1)."""
        return self._codepage

    @property
    def header(self) -> Header:
        return self._header

    @property
    def reader(self) -> BlockReader:
        return self._reader

    @property
    def nbt(self) -> NodeBTree:
        return self._nbt

    @property
    def bbt(self) -> BlockBTree:
        return self._bbt

    # --- the message store's own properties -----------------------------------------

    @property
    def properties(self) -> PropertyContext:
        """The property context of `NID_MESSAGE_STORE` (0x21) — upstream's `StoreProperties`."""
        return self._properties

    def _record(self, prop_id: int, what: str) -> PropertyRecord:
        record = self._properties.records.get(prop_id)
        if record is None or record.is_null:
            raise PstFormatError(f"missing {what} on store")
        return record

    def _binary(self, prop_id: int, what: str) -> bytes:
        record = self._record(prop_id, what)
        value = self._properties.read(record)
        if not isinstance(value, bytes):
            raise PstFormatError(f"invalid {what} on store: {record.value_type.debug_name}, not Binary")
        return value

    def _entry_id(self, prop_id: int, what: str, *, required: bool) -> EntryId | None:
        """One of the three EntryID properties; `None` for an absent optional one (module docstring)."""
        record = self._properties.records.get(prop_id)
        if record is None or record.is_null:
            if required:
                raise PstFormatError(f"missing {what} on store")
            return None
        value = self._properties.read(record)
        if not isinstance(value, bytes):
            raise PstFormatError(f"invalid {what} on store: {record.value_type.debug_name}, not Binary")
        if len(value) != ENTRY_ID_SIZE:
            raise PstFormatError(f"invalid {what} on store: {len(value)} bytes, not {ENTRY_ID_SIZE}")
        return EntryId.unpack_from(value)

    @property
    def record_key(self) -> bytes:
        """`PidTagRecordKey` (0x0FF9) — the 16 bytes every EntryID in this store repeats."""
        value = self._binary(PID_TAG_RECORD_KEY, "PidTagRecordKey")
        if len(value) != RECORD_KEY_SIZE:
            raise PstFormatError(f"invalid PidTagRecordKey size on store: 0x{len(value):X}")
        return value

    @property
    def display_name(self) -> str:
        """`PidTagDisplayName` (0x3001) — the store's name, as Outlook shows it."""
        record = self._record(PID_TAG_DISPLAY_NAME, "PidTagDisplayName")
        value = self._properties.read(record)
        if not isinstance(value, str):
            raise PstFormatError(f"invalid PidTagDisplayName on store: {record.value_type.debug_name}, not a string")
        return value

    @property
    def ipm_subtree(self) -> EntryId:
        """`PidTagIpmSubTreeEntryId` (0x35E0) — the root of the user-visible folder tree. Required."""
        entry = self._entry_id(PID_TAG_IPM_SUB_TREE_ENTRY_ID, "PidTagIpmSubTreeEntryId", required=True)
        assert entry is not None  # required=True: absent is a refusal, never None
        return entry

    @property
    def wastebasket(self) -> EntryId | None:
        """`PidTagIpmWastebasketEntryId` (0x35E3), or None when the store has none (module docstring)."""
        return self._entry_id(PID_TAG_IPM_WASTEBASKET_ENTRY_ID, "PidTagIpmWastebasketEntryId", required=False)

    @property
    def finder(self) -> EntryId | None:
        """`PidTagFinderEntryId` (0x35E7), or None when the store has none (module docstring)."""
        return self._entry_id(PID_TAG_FINDER_ENTRY_ID, "PidTagFinderEntryId", required=False)

    def entry_id(self, node: NodeId) -> EntryId:
        """Upstream's `make_entry_id`: this store's record key plus `node`, for a caller holding only a NID."""
        if not isinstance(node, NodeId):
            raise TypeError(f"Store.entry_id takes a NodeId, not {type(node).__name__}")
        return EntryId(self.record_key, node)

    def matches_record_key(self, entry: EntryId) -> bool:
        """True when `entry` was issued by this store — upstream's `matches_record_key`, P08's `EntryIdWrongStore`."""
        if not isinstance(entry, EntryId):
            raise TypeError(f"Store.matches_record_key takes an EntryId, not {type(entry).__name__}")
        return entry.record_key == self.record_key

    def get(self, prop_id: int) -> PropValue | None:
        """One store property by id, decoded — `None` when it is absent or its HNID is 0."""
        return self._properties.get(prop_id)

    # --- the folder tree (P08) --------------------------------------------------------

    @property
    def root_folder(self) -> Folder:
        """`NID_ROOT_FOLDER` (0x122) — the walk's origin, above the IPM subtree.

        The oracle's `dump_messages` starts here rather than at
        `ipm_subtree`, so that the wastebasket, the search root and the
        search folders are all reachable; `Folder.walk()` from here visits
        every folder in the store.
        """
        return self.open_folder(NID_ROOT_FOLDER)

    def open_folder(self, entry: EntryId | NodeId) -> Folder:
        """Upstream's `Store::open_folder`: one folder by EntryID (or bare NID).

        `PstFormatError` for a NID whose type is neither `NormalFolder` nor
        `SearchFolder`, and for an `EntryId` whose record key is another
        store's (upstream's `EntryIdWrongStore`); `PstNotFoundError` when the
        node B-tree does not hold the node.
        """
        from pypstreader.messaging.folder import (
            Folder,  # the import cycle, broken here (module docstring)
        )

        return Folder.open(self, entry)

    # --- messages (P09) ----------------------------------------------------------------

    def open_message(self, entry: EntryId | NodeId, *, parent: Folder | None = None) -> Message:
        """Upstream's `Store::open_message`: one message by EntryID (or bare NID).

        `PstFormatError` for a NID whose type is none of `NormalMessage`,
        `AssociatedMessage` and `Attachment` (upstream accepts all three),
        and for an `EntryId` whose record key is another store's;
        `PstNotFoundError` when the node B-tree does not hold the node.
        `parent` is the folder the caller found the message in, remembered
        on the message for the layers above (`pypstreader.messaging.message`'s
        module docstring); it is never read back by this layer.
        """
        from pypstreader.messaging.message import (
            Message,  # the import cycle, broken here (module docstring)
        )

        return Message.open(self, entry, parent=parent)

    # --- the named property map ------------------------------------------------------

    @property
    def named_properties(self) -> NamedPropertyMap:
        """The map over `NID_NAME_TO_ID_MAP` (0x61), read on first use and kept."""
        if self._named is None:
            self._named = NamedPropertyMap.from_node(
                self._reader, self._nbt.find(NID_NAME_TO_ID_MAP), self._limits, codepage=self._codepage
            )
        return self._named


def open_store(path: str | os.PathLike[str], *, limits: Limits = DEFAULT_LIMITS, codepage: str = "cp1252") -> Store:
    """Open a PST store — exported as `pypstreader.open`. See `Store.open`."""
    return Store.open(path, limits=limits, codepage=codepage)
