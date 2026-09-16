"""Folders — a property context for the folder's own properties, plus the three tables beside it.

Ported from: crates/pst/src/messaging/folder.rs (`FolderProperties`, the read half of
             `FolderInner` and `UnicodeFolder`; the write half and the ANSI arm are not
             ported — ADR-0003)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.4.4 Folders, 2.4.4.1 Folder object PC, 2.4.4.4 Hierarchy Table,
             2.4.4.5 Contents Table, 2.4.4.6 FAI Contents Table, 2.2.2.1 NID

A folder is four nodes that share one 27-bit NID *index* and differ only in
the 5-bit NID type ([MS-PST] 2.4.4.1):

| type | what |
|---|---|
| `NormalFolder` (0x02) / `SearchFolder` (0x03) | the folder's own property context |
| `HierarchyTable` (0x0D) | one row per sub-folder; the row id IS the child's NID |
| `ContentsTable` (0x0E) | one row per message |
| `AssociatedContentsTable` (0x0F) | one row per FAI (associated) message |

So a folder is opened from one NID and the other three are derived, exactly
as upstream's `read_table` derives them (`NodeId::new(type, self.node.index())`).
Any of the three may be absent from the node B-tree — `Empty.pst`'s search
folder `SearchFolder: 0x111` has none of them — and an absent table is
`None`, not a refusal, because a folder with no sub-folders legitimately has
no hierarchy table.

`display_name`, `content_count`, `unread_count` and `has_subfolders` are
upstream's four accessors over `PidTagDisplayName` (0x3001),
`PidTagContentCount` (0x3602), `PidTagContentUnreadCount` (0x3603) and
`PidTagSubfolders` (0x360A), with upstream's behaviour on a missing or
wrongly typed property: a refusal, not a default. That matters on the root
folder of several corpus stores, whose `PidTagDisplayName` record has a zero
HNID (`PtypNull`): the oracle prints `Name: Error: … InvalidFolderDisplayName(Null)`
there, and so this port raises `PstFormatError` rather than returning `None`
(see "the display-name decision" below).

**Deliberate divergences from upstream**, each chosen to fail closed or to
fit Python's conventions:

- **A table node that exists but is not a readable table context is a
  refusal, not `None`.** Upstream's `hierarchy_table()` is
  `self.read_table(HierarchyTable).ok()?` — `.ok()?` turns *every* error,
  including a corrupt TCINFO, into "there is no such table". That is how
  `dump_messages` prints `Hierarchy Table: None` for `pstd-inline-cid.pst`,
  whose three tables are all present in the NBT and all refused by upstream's
  own table-context reader (its `read_root_folder` golden is empty with exit
  1 for the same reason). Silently reporting a corrupt table as an absent one
  is exactly the guessing CLAUDE.md forbids: a caller cannot tell "this
  folder has no sub-folders" from "this folder's sub-folder list is
  unreadable", and the two lead to opposite actions. So here `None` means
  **the node is not in the node B-tree** (`PstNotFoundError` from the NBT)
  and nothing else; anything else the table layer refuses propagates.
  `pypst.debug`'s `folders` dumper reproduces upstream's `.ok()?` itself, so
  its output still matches the goldens byte for byte — the dumper's contract
  is the example's, as `dump_store`'s is.
- **The two synthetic properties upstream injects are attributes here.**
  `FolderInner::read` inserts `PidTagEntryId` (0x0FFF) and
  `PidTagFolderType` (0x3601) into the property map it hands back, so its
  `properties()` is not what the file holds. `Folder.properties` is the
  file's property context, untouched, and the two computed values are
  `Folder.entry_id` and `Folder.folder_type` (upstream's arithmetic: 0 for
  `NID_ROOT_FOLDER`, 2 for a search folder, 1 otherwise). A property context
  that reports properties the store did not write is a trap for every layer
  above it.
- **`walk()` is iterative, bounded, and cycle-guarded.** Upstream has no
  walk at all; the recursion lives in its examples. A hierarchy table whose
  row id is the folder itself, or an ancestor, is a walk that never ends —
  and in Python that is a hang rather than Rust's survivable stack overflow.
  So `walk()` keeps an explicit stack (no Python recursion to overflow), a
  `VisitedSet` over the NIDs it has yielded (`PstLimitError` on a revisit,
  which is what `pypst.limits` prescribes for a cycle) and a depth ceiling,
  `limits.max_folder_depth`, added by this row.
- **`PstError` or nothing.** An absent node is `PstNotFoundError`, a ceiling
  is `PstLimitError`, and everything else about the bytes is
  `PstFormatError`.

**The display-name decision: refuse, as upstream does.** Six of the eight
Unicode corpus stores — `Empty.pst`, `javalibpst-dist-list`,
`pstsdk-sample1`, `pstsdk-submessage`, `pstsdk-test_unicode` and
`tika-variousBodyTypes`; the two written by EMLtoPST rather than by Outlook
are the exceptions — have a root folder whose `PidTagDisplayName` record has
a zero HNID, which decodes to no value at all. Returning `None` would be friendlier and is wrong: `PidTagDisplayName`
is a required property of a folder object ([MS-PST] 2.4.4.1), a folder with
no name is a fact about a damaged or unusual store, and a caller that gets
`None` will write it into a path or a report as the empty string. Upstream
refuses (`InvalidFolderDisplayName(Null)`), the oracle prints that refusal in
place of the value, and this port raises `PstFormatError` at the same point —
so the two agree, and `python -m pypst.debug folders` reproduces the golden's
`Name: Error: …` line by catching it. A caller that wants the lenient form
asks for it: `folder.properties.get(0x3001)`.
"""

from __future__ import annotations

from collections.abc import Iterator

from pypst.errors import PstFormatError, PstNotFoundError
from pypst.limits import VisitedSet, check_count, check_depth
from pypst.ltp.prop_context import PropertyContext, PropertyRecord
from pypst.ltp.prop_type import PropValue
from pypst.ltp.table_context import TableContext
from pypst.messaging.store import EntryId, Store
from pypst.ndb.ids import NID_ROOT_FOLDER, NodeId, NodeIdType

__all__ = [
    "FOLDER_NODE_TYPES",
    "PID_TAG_CONTENT_COUNT",
    "PID_TAG_CONTENT_UNREAD_COUNT",
    "PID_TAG_DISPLAY_NAME",
    "PID_TAG_SUBFOLDERS",
    "Folder",
]

# [MS-PST] 2.4.4.1 — the four properties upstream's `FolderProperties` reads by name.
PID_TAG_DISPLAY_NAME = 0x3001
PID_TAG_CONTENT_COUNT = 0x3602
PID_TAG_CONTENT_UNREAD_COUNT = 0x3603
PID_TAG_SUBFOLDERS = 0x360A

# Upstream's `match node_id_type { NormalFolder | SearchFolder => {} }`.
FOLDER_NODE_TYPES = (NodeIdType.NORMAL_FOLDER, NodeIdType.SEARCH_FOLDER)

# Upstream's `folder_type`: the value it injects as PidTagFolderType (0x3601).
_FOLDER_TYPE_ROOT = 0
_FOLDER_TYPE_GENERIC = 1
_FOLDER_TYPE_SEARCH = 2


class Folder:
    """One folder: its own property context, and the three tables at its NID's sibling types.

    Built from an open `Store` and the folder's `NodeId`; `Folder.open` takes
    an `EntryId` as well and is what `Store.open_folder` calls. The property
    context is read eagerly (as upstream's `FolderInner::read` reads it); the
    three tables are read on first use and kept, as upstream's `OnceCell`s.
    """

    __slots__ = ("_node", "_properties", "_store", "_tables")

    def __init__(self, store: Store, node: NodeId) -> None:
        """Open the folder node `node` of `store`; a NID of the wrong type is refused before anything is read."""
        if not isinstance(store, Store):
            raise TypeError(f"Folder takes a Store, not {type(store).__name__}")
        if not isinstance(node, NodeId):
            raise TypeError(f"Folder takes a NodeId, not {type(node).__name__}")
        node_type = node.id_type  # an unknown 5-bit type is a PstFormatError here
        if node_type not in FOLDER_NODE_TYPES:
            raise PstFormatError(f"invalid folder EntryID NID_TYPE: {node_type.debug_name}")
        self._store = store
        self._node = node
        self._tables: dict[NodeIdType, TableContext | None] = {}
        self._properties = PropertyContext.from_node(
            store.reader, store.nbt.find(node), store.limits, codepage=store.codepage
        )

    @classmethod
    def open(cls, store: Store, entry: EntryId | NodeId) -> Folder:
        """Upstream's `UnicodeFolder::read`: an `EntryId` from another store is refused (`EntryIdWrongStore`)."""
        if isinstance(entry, EntryId):
            if not store.matches_record_key(entry):
                raise PstFormatError("EntryID in wrong store")
            node = entry.node
        elif isinstance(entry, NodeId):
            node = entry
        else:
            raise TypeError(f"Folder.open takes an EntryId or a NodeId, not {type(entry).__name__}")
        return cls(store, node)

    def __str__(self) -> str:
        return f"Folder {{ {self._node} }}"

    # --- identity -------------------------------------------------------------------

    @property
    def store(self) -> Store:
        return self._store

    @property
    def node(self) -> NodeId:
        """The NID of the folder's own property context — `NormalFolder` or `SearchFolder`."""
        return self._node

    @property
    def entry_id(self) -> EntryId:
        """This folder's EntryID — upstream injects it as `PidTagEntryId` (0x0FFF); see the module docstring."""
        return self._store.entry_id(self._node)

    @property
    def folder_type(self) -> int:
        """Upstream's `PidTagFolderType` (0x3601): 0 for the root folder, 2 for a search folder, 1 otherwise."""
        if self._node == NID_ROOT_FOLDER:
            return _FOLDER_TYPE_ROOT
        if self._node.id_type is NodeIdType.SEARCH_FOLDER:
            return _FOLDER_TYPE_SEARCH
        return _FOLDER_TYPE_GENERIC

    @property
    def properties(self) -> PropertyContext:
        """The folder's own property context — what the FILE holds, with nothing injected."""
        return self._properties

    def get(self, prop_id: int) -> PropValue | None:
        """One folder property by id, decoded — `None` when it is absent or its HNID is 0."""
        return self._properties.get(prop_id)

    # --- the four named properties ([MS-PST] 2.4.4.1) --------------------------------

    def _record(self, prop_id: int, what: str) -> PropertyRecord:
        record = self._properties.records.get(prop_id)
        if record is None:
            raise PstFormatError(f"missing {what} on folder")
        return record

    @property
    def display_name(self) -> str:
        """`PidTagDisplayName` (0x3001). Absent or not a string is `PstFormatError` — see the module docstring."""
        record = self._record(PID_TAG_DISPLAY_NAME, "PidTagDisplayName")
        value = self._properties.read(record)
        if not isinstance(value, str):
            raise PstFormatError(f"invalid PidTagDisplayName on folder: {record.value_type.debug_name}, not a string")
        return value

    def _int32(self, prop_id: int, what: str) -> int:
        record = self._record(prop_id, what)
        value = self._properties.read(record)
        if not isinstance(value, int) or isinstance(value, bool):
            raise PstFormatError(f"invalid {what} on folder: {record.value_type.debug_name}, not Integer32")
        return value

    @property
    def content_count(self) -> int:
        """`PidTagContentCount` (0x3602) — the number of messages in the contents table, as the folder claims."""
        return self._int32(PID_TAG_CONTENT_COUNT, "PidTagContentCount")

    @property
    def unread_count(self) -> int:
        """`PidTagContentUnreadCount` (0x3603)."""
        return self._int32(PID_TAG_CONTENT_UNREAD_COUNT, "PidTagContentUnreadCount")

    @property
    def has_subfolders(self) -> bool:
        """`PidTagSubfolders` (0x360A). A claim, not a fact: a store may say `true` and hold no hierarchy table."""
        record = self._record(PID_TAG_SUBFOLDERS, "PidTagSubfolders")
        value = self._properties.read(record)
        if not isinstance(value, bool):
            raise PstFormatError(f"invalid PidTagSubfolders on folder: {record.value_type.debug_name}, not Boolean")
        return value

    # --- the three tables ------------------------------------------------------------

    def table(self, node_type: NodeIdType) -> TableContext | None:
        """The table at this folder's index and `node_type`, or `None` when the NBT does not hold that node.

        Upstream's `read_table`. A node that IS there but is not a readable
        table context propagates its refusal, where upstream's `.ok()?`
        reports it as absent (module docstring).
        """
        node_type = NodeIdType(node_type)
        if node_type in self._tables:
            return self._tables[node_type]
        node = NodeId.from_parts(node_type, self._node.index)
        try:
            entry = self._store.nbt.find(node)
        except PstNotFoundError:
            self._tables[node_type] = None
            return None
        table = TableContext.from_node(self._store.reader, entry, self._store.limits, codepage=self._store.codepage)
        self._tables[node_type] = table
        return table

    @property
    def hierarchy_table(self) -> TableContext | None:
        """[MS-PST] 2.4.4.4 — one row per sub-folder, the row id being the child's NID."""
        return self.table(NodeIdType.HIERARCHY_TABLE)

    @property
    def contents_table(self) -> TableContext | None:
        """[MS-PST] 2.4.4.5 — one row per message."""
        return self.table(NodeIdType.CONTENTS_TABLE)

    @property
    def associated_table(self) -> TableContext | None:
        """[MS-PST] 2.4.4.6 — one row per FAI (associated) message."""
        return self.table(NodeIdType.ASSOC_CONTENTS_TABLE)

    # --- what the tables name --------------------------------------------------------

    def _row_ids(self, table: TableContext | None, ceiling: int, what: str) -> tuple[NodeId, ...]:
        """Every row id of `table` as a NID, in MATRIX order — the order the oracle walks."""
        if table is None:
            return ()
        ids: list[NodeId] = []
        for row in table.rows():
            check_count(len(ids) + 1, ceiling, what)
            ids.append(NodeId(row.id))
        return tuple(ids)

    def subfolder_ids(self) -> tuple[NodeId, ...]:
        """The NIDs of this folder's children, in row-matrix order; `()` when there is no hierarchy table."""
        return self._row_ids(self.hierarchy_table, self._store.limits.max_folders, "folders in one hierarchy table")

    def message_ids(self) -> tuple[NodeId, ...]:
        """The NIDs of this folder's messages, in row-matrix order; `()` when there is no contents table."""
        return self._row_ids(self.contents_table, self._store.limits.max_messages, "messages in one contents table")

    def associated_ids(self) -> tuple[NodeId, ...]:
        """The NIDs of this folder's associated (FAI) messages; `()` when there is no associated contents table."""
        return self._row_ids(self.associated_table, self._store.limits.max_messages, "messages in one associated table")

    def contents(self) -> tuple[EntryId, ...]:
        """`message_ids()` as EntryIDs — what P09's `Store.open_message` will take."""
        return tuple(self._store.entry_id(node) for node in self.message_ids())

    def subfolders(self) -> Iterator[Folder]:
        """Each child of `subfolder_ids()`, opened, in row-matrix order.

        Lazy: a child that is not in the node B-tree raises `PstNotFoundError`
        when the walk reaches it, and the children before it have already
        been yielded.
        """
        for node in self.subfolder_ids():
            yield Folder(self._store, node)

    def walk(self, *, max_depth: int | None = None) -> Iterator[Folder]:
        """Pre-order, self first, children in row-matrix order — the oracle's `dump_folder` order.

        `max_depth` defaults to `limits.max_folder_depth`; this folder is
        depth 0. A folder that names itself or an ancestor — indeed any
        folder reached twice — is a cycle and raises `PstLimitError`, as does
        a tree deeper than the ceiling. Iterative, so no Python recursion
        limit is involved (module docstring).
        """
        limits = self._store.limits
        ceiling = limits.max_folder_depth if max_depth is None else max_depth
        if isinstance(ceiling, bool) or not isinstance(ceiling, int):
            raise TypeError(f"Folder.walk takes an int max_depth, not {type(max_depth).__name__}")
        seen = VisitedSet("folder tree", limits.max_folders)
        stack: list[tuple[Folder, int]] = [(self, 0)]
        while stack:
            folder, depth = stack.pop()
            check_depth(depth, ceiling, "folder tree depth")
            seen.add(folder.node)
            yield folder
            children = list(folder.subfolders())
            stack.extend((child, depth + 1) for child in reversed(children))
