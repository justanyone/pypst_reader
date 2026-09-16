"""The contract harness (docs/TEST-PLAN.md T5): every public entry point, `PstError` or nothing.

`tests/corruption_harness.py` (P12) runs a hand-written list of calls over a
corrupt store. This module is its generalisation: the entry points are
**discovered**, not listed, so that a layer landing later joins the contract
by existing, and the only way to escape it is to be named in one of two
explicit tables here — with a reason.

Three parts.

**Discovery** — `entry_points()` walks the `pypst` package with `pkgutil`,
imports every public module, and collects every public callable: the names
in a module's `__all__` when it has one, else every public top-level function
or class defined in it. For a class it also collects every public classmethod
and public method (`__iter__` included) along the class's `pypst` MRO. Each
is classified by its parameters into a `Kind` — `bytes` (a buffer),
`file` (a `BinaryIO`), `reader` (a file plus something a parsed header
yields: a `Header`, `PageRef`, `BlockBTree`…), `path` (a store on disk),
`wire` (an int or enum from the wire), `method` (needs an instance of a
`reader` class) or `other`. Re-exports dedupe by identity, so a name lives
once, under the module that defines it.

**Reach** — `ADAPTERS` maps each entry point to a builder that, given a
`Store` (the bytes, a `Limits`, and lazily the parsed header, the two
B-trees, a `BlockReader`, the NBT and BBT entries, a handful of pages,
every node opened as a heap, the BTH over each of those, and the property
or table context of each heap that is one, a temp file for the dumpers),
yields the argument tuples to call it with.
`NOT_STORE_INPUT` names, with a reason, every public callable that takes
no store-derived input (a check helper, a dataclass over already-parsed
values, an id's `pack`). Three rules exclude classes automatically:
exception types, `Enum` types (their `from_wire`-style classmethods are
still entry points) and dataclass constructors (they hold what a
classmethod parsed). **Everything else must be in one table or the other,
and `uncovered()` lists what is not.** `tests/test_contract.py` fails on a
non-empty list, so a new module's public surface cannot slip past the
contract; `stale()` catches the reverse, an adapter for a name that no
longer exists. Builders that need a prerequisite the store refused
(`Store.header` on an ANSI store) raise `Unreachable`, recorded as a `SKIP`
outcome — the refusal itself is judged where it happened.

**Judgement** — `judge(fn, call)` runs one call and returns an `Outcome`:
`OK` (returned; an iterator is drained), `PST_ERROR` (a `PstError`
subclass — the type is kept), `LEAK` (anything else, with the innermost
frame), `HANG` (outlived the watchdog). `sweep(data, limits=…)` runs every
adapter over one store under P12's `Watchdog` — one worker submission per
store rather than per call, since a submission costs more than most calls;
the worker records which entry point it is in, so a hang still names it —
and `problems(outcomes)` reduces the result to the lines that violate the
contract: `LEAK` and `HANG`, nothing else. What a call *should* return or
raise is the layer's own tests' business; this harness says only what must
never come out.

**Dumpers.** Every function registered in `pypst.debug.DUMPERS` gets its
adapter automatically (the store on disk, stdout and stderr to a sink), so
a dumper registered by a later row is covered on landing; a dumper with an
extra positional parameter names it, and `EXTRA_ARGS` must know that name
(`nid`) or building its calls raises `KeyError` by that name. The process
boundary — exit codes, `Error:` on stderr, no traceback — is the slow
subprocess test in `test_contract.py`.

Never point this at `tests/fixtures/private/`: outcomes carry exception
messages, which carry field values.
"""

from __future__ import annotations

import contextlib
import dataclasses
import enum
import importlib
import inspect
import io
import pkgutil
import random
import struct
import tempfile
import time
import traceback
import uuid
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import pypst
from pypst import block_sig, crc, debug, encode, limits, rtf
from pypst.errors import PstError, PstFormatError
from pypst.limits import DEFAULT_LIMITS, Limits
from pypst.ltp import heap, prop_context, prop_type, table_context, tree
from pypst.ltp.heap import HeapId, HeapNode, HeapNodeId
from pypst.ltp.prop_context import PropertyContext, PropertyRecord
from pypst.ltp.prop_type import PropType
from pypst.ltp.table_context import CellKind, CellRecord, TableContext, TableRow
from pypst.messaging import attachment as attachment_mod
from pypst.messaging import folder as folder_mod
from pypst.messaging import message as message_mod
from pypst.messaging import named_prop
from pypst.messaging import store as messaging
from pypst.messaging.attachment import Attachment, AttachMethod
from pypst.messaging.folder import Folder
from pypst.messaging.message import Message
from pypst.messaging.named_prop import NamedPropertyGuid, NamedPropertyMap, NameIdEntry
from pypst.messaging.store import EntryId
from pypst.ndb import block, btree, header, ids, page, root
from pypst.ndb.block import SubNodeLeafEntry
from pypst.ndb.ids import NID_ROOT_FOLDER, BlockId, ByteIndex, NodeId, NodeIdType
from tests.corruption_harness import DEFAULT_TIMEOUT, Hang, Watchdog

# --- discovery ---------------------------------------------------------------------

Kind = str  # "bytes" | "file" | "reader" | "path" | "wire" | "method" | "other"

# A parameter annotated with one of these (as text: the package uses
# `from __future__ import annotations`) marks a callable as needing a parsed
# store — the `reader` kind. Extend it when a new layer's reader class takes
# a new kind of parsed argument.
READER_TYPES = (
    "Header",
    "Root",
    "PageRef",
    "BlockBTree",
    "NodeBTree",
    "BlockReader",
    "NodeBTreeEntry",
    "BlockBTreeEntry",
    "HeapNode",
    "PropertyContext",  # P07: NamedPropertyMap is built over one, so it is a reader class
    "Store",  # P08: a Folder is built over an open Store, so it is a reader class
    "Folder",  # P08: `pypst.debug`'s folder helpers take one, so they need one too
    "Message",  # P09: an Attachment is built over an open Message, as a Folder is over a Store
    "Attachment",  # P09: `pypst.debug`'s attachment helpers take one
)
WIRE_TYPES = ("PropType", "int")


@dataclass(frozen=True, slots=True)
class EntryPoint:
    """One public callable: its dotted name, the object to call, and how it takes its input."""

    name: str
    obj: Callable[..., object]
    kind: Kind
    owner: type | None = None  # the class, for a classmethod or method


def public_modules() -> list[ModuleType]:
    """Every importable module under `pypst` whose name has no private segment, the package first."""
    found = [pypst]
    for info in pkgutil.walk_packages(pypst.__path__, prefix="pypst."):
        if any(part.startswith("_") for part in info.name.split(".")):
            continue
        found.append(importlib.import_module(info.name))
    return found


def _public_names(module: ModuleType) -> list[tuple[str, object]]:
    exported = getattr(module, "__all__", None)
    if exported is None:
        exported = [n for n in vars(module) if not n.startswith("_")]
    return [(n, getattr(module, n)) for n in exported]


def _annotation(param: inspect.Parameter) -> str:
    return "" if param.annotation is inspect.Parameter.empty else str(param.annotation)


def _classify(fn: Callable[..., object], *, is_method: bool = False) -> Kind:
    try:
        params = list(inspect.signature(fn).parameters.values())
    except (TypeError, ValueError):
        return "other"
    if is_method:
        params = params[1:]
    if not params:
        return "other"
    texts = [_annotation(p) for p in params]
    first = texts[0]
    if any(t and any(r in t for r in READER_TYPES) for t in texts):
        return "reader"
    if "BinaryIO" in first:
        return "file"
    if "Path" in first:
        return "path"
    if any("bytes" in t or "memoryview" in t for t in texts):
        return "bytes"
    if first in WIRE_TYPES or params[0].name in ("value", "ft", "raw", "size"):
        return "wire"
    return "other"


def _class_kind(cls: type) -> Kind:
    if issubclass(cls, BaseException) or issubclass(cls, enum.Enum):
        return "other"
    init = cls.__init__
    if init is object.__init__:
        return "other"
    return _classify(init, is_method=True)


def _members(cls: type) -> Iterator[tuple[str, Callable[..., object], bool]]:
    """(name, callable-as-accessed-on-the-class, is-instance-method) for every public member on the pypst MRO."""
    seen: set[str] = set()
    for klass in cls.__mro__:
        if not klass.__module__.startswith("pypst"):
            continue
        for attr, raw in vars(klass).items():
            if attr in seen or (attr.startswith("_") and attr != "__iter__"):
                continue
            if isinstance(raw, (classmethod, staticmethod)):
                seen.add(attr)
                yield attr, getattr(cls, attr), False
            elif inspect.isfunction(raw):
                seen.add(attr)
                yield attr, getattr(cls, attr), True


def _key(obj: object) -> object:
    """Identity for dedup and table lookup: a bound classmethod is its function plus its class."""
    if inspect.ismethod(obj):
        return (obj.__func__, obj.__self__)
    return obj


def entry_points() -> list[EntryPoint]:
    """Every public callable under `pypst`, once each, in module walk order."""
    found: dict[object, EntryPoint] = {}

    def add(ep: EntryPoint) -> None:
        found.setdefault(_key(ep.obj), ep)

    for module in public_modules():
        for name, obj in _public_names(module):
            if not callable(obj) or getattr(obj, "__module__", None) != module.__name__:
                continue  # a constant, a type alias, or a re-export (found under its own module)
            qual = f"{module.__name__}.{name}"
            if inspect.isclass(obj):
                add(EntryPoint(qual, obj, _class_kind(obj), obj))
                class_kind = _class_kind(obj)
                for attr, member, is_method in _members(obj):
                    kind = "method" if is_method and class_kind in ("file", "reader") else _classify(member, is_method=is_method)
                    add(EntryPoint(f"{qual}.{attr}", member, kind, obj))
            else:
                add(EntryPoint(qual, obj, _classify(obj)))
    return list(found.values())


# --- the store a builder draws from -----------------------------------------------


class Unreachable(Exception):
    """A prerequisite refused this store with a `PstError`; the entry point cannot be reached on it."""


PAGE = page.PAGE_SIZE
ROOT_OFFSET = 180  # the ROOT inside the header, [MS-PST] 2.2.2.6
WIRE_BYTES = (0, 1, 2, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0xFE, 0xFF)
KNOWN_NIDS = (0x21, 0x122, 0x2123)  # NID_MESSAGE_STORE, NID_ROOT_FOLDER, a search folder root
# [MS-PST] 2.3.4.1 TCINFO, at a table context's user root; only `hidRowIndex`
# (field 6) is read here, to reach the row-index BTH a TC hangs off it.
TCINFO_FORMAT = "<BB4HIII"
MAX_HEAP_BLOCK_INDEX = 0xFFFF  # [MS-PST] 2.3.1.1 `hidBlockIndex` is 16 bits; past this `HeapId.from_parts` refuses
MAX_SUBNODE_HEAPS = 8  # sub-node heaps opened per store: an attachment's or an embedded message's own PC
ABSENT_SUBNODE = 0xFFFF_FFE2  # an HNID with type bits, naming a sub-node no tree holds
BAD_CODEPAGE = "no-such-codepage"  # a PC built on it must refuse when it decodes a string, never raise LookupError
MAX_TABLE_ROWS = 8  # rows per table kept for the per-row and per-cell adapters; `rows()` still walks every one
RECORD_KEY_SIZE = messaging.RECORD_KEY_SIZE
# `wGuid >> 1` values for NamedPropertyGuid.from_wire: none, the two well-known
# sets, the first stream index, the last legal value and the three past it.
NAMED_GUID_CODES = (0, 1, 2, 3, 0x7FFE, 0x7FFF, 0x8000, 0xFFFF, -1)


@dataclass(frozen=True, slots=True)
class OpenHeap:
    """One node opened as a heap, with the sub-node ids its HNIDs can name."""

    label: str
    heap: HeapNode
    subnode_nids: tuple[int, ...]


class Store:
    """One store's bytes plus, lazily, everything a builder may ask of it. A `PstError` on the way is `Unreachable`."""

    def __init__(self, data: bytes, limits: Limits = DEFAULT_LIMITS, workdir: Path | None = None, *, thorough: bool = True) -> None:
        self.data = data
        self.limits = limits
        # `thorough` is the breadth of ARGUMENTS, never the set of entry points:
        # the fixture lanes take every variant, the corruption lane (hundreds of
        # stores per seed) the cheap core of each, so it stays inside its budget.
        self.thorough = thorough
        self.f = io.BytesIO(data)
        self._workdir = workdir
        self._cache: dict[str, object] = {}
        self._refused: dict[str, BaseException] = {}

    def _lazy(self, name: str, build: Callable[[], object]) -> Any:
        if name in self._refused:
            raise Unreachable(f"{name}: {type(self._refused[name]).__name__}")
        if name not in self._cache:
            try:
                self._cache[name] = build()
            except PstError as exc:
                self._refused[name] = exc
                raise Unreachable(f"{name}: {type(exc).__name__}") from None
        return self._cache[name]

    @property
    def header(self) -> header.Header:
        return self._lazy("header", lambda: header.read_header(self.f))

    @property
    def nbt(self) -> btree.NodeBTree:
        return self._lazy("nbt", lambda: btree.NodeBTree(self.f, self.header.root.node_btree, self.limits))

    @property
    def bbt(self) -> btree.BlockBTree:
        return self._lazy("bbt", lambda: btree.BlockBTree(self.f, self.header.root.block_btree, self.limits))

    @property
    def reader(self) -> block.BlockReader:
        return self._lazy("reader", lambda: block.BlockReader(self.f, self.header, self.bbt, self.limits))

    @staticmethod
    def _drain(it: Iterable[Any]) -> list[Any]:
        """As many entries as the walk yields before it refuses; the refusal is judged at `__iter__`."""
        out: list[Any] = []
        with contextlib.suppress(PstError):
            out.extend(it)
        return out

    @property
    def nbt_entries(self) -> list[page.NodeBTreeEntry]:
        return self._lazy("nbt_entries", lambda: self._drain(self.nbt))

    @property
    def bbt_entries(self) -> list[page.BlockBTreeEntry]:
        return self._lazy("bbt_entries", lambda: self._drain(self.bbt))

    def _held(self, name: str, pick: Callable[[Any], int]) -> list[int]:
        """The first and last key of a walk, or none when the store refused the walk (the lookup still runs)."""
        try:
            entries = getattr(self, name)
        except Unreachable:
            return []
        return [pick(e) for e in entries[:1] + entries[-1:]]

    @property
    def nids(self) -> list[int]:
        """NIDs to look up: the first and last the store holds, the well-known ones, and two that cannot exist."""
        held = self._held("nbt_entries", lambda e: e.node.raw)
        if not self.thorough:
            return [*held[:1], KNOWN_NIDS[0], 0xFFFFFFFF]
        return [*held, *KNOWN_NIDS, 0, 0xFFFFFFFF]

    @property
    def bids(self) -> list[int]:
        held = self._held("bbt_entries", lambda e: e.block.block.raw)
        if not self.thorough:
            return [*held[:1], 4, 2**64 - 1]
        return [*held, 4, 0, 2**64 - 1]

    @property
    def wire_codes(self) -> list[int]:
        """Property type codes for `decode`/`from_wire`: every member, the edges, and (thorough) a fixed random sample."""
        return WIRE_CODES if self.thorough else WIRE_CODES_CORE

    @property
    def pages(self) -> list[tuple[ByteIndex, bytes]]:
        """Up to nine 512-byte pages: the two roots as the raw header names them, the density list, the first slots, the last page."""
        offsets = [page.DENSITY_LIST_OFFSET, 0x4400, 0x4600, 0x4800, 0x4A00]
        with contextlib.suppress(struct.error):  # a raw read of the header's ROOT: garbage is fine, a short file is not
            values = struct.unpack_from(root.ROOT_FORMAT, self.data, ROOT_OFFSET)
            offsets += [values[6], values[8]]
        if len(self.data) >= PAGE:
            offsets.append((len(self.data) - PAGE) // PAGE * PAGE)
        out = []
        for off in dict.fromkeys(offsets):
            if 0 <= off and off + PAGE <= len(self.data):
                out.append((ByteIndex(off), self.data[off : off + PAGE]))
        return out

    @property
    def slices(self) -> list[bytes]:
        """Buffers for the pure decoders: empty, a byte, a record's worth, a page's worth, and (thorough) half a block."""
        d = self.data
        return [b"", d[:1], d[:16], d[:512], *([d[:4096]] if self.thorough else [])]

    def _open_heaps(self) -> list[OpenHeap]:
        """Every node opened as a heap, and the first sub-node leaves' own heaps; a node that is not a heap is left out.

        The refusal of a node that is not a heap is judged at the
        `HeapNode.from_node` adapter, which calls it over every node; here
        it only means there is no heap to exercise the methods on.
        """
        reader = self.reader  # Unreachable on a store whose header or BBT was refused: no heap is reachable either
        out: list[OpenHeap] = []
        budget = MAX_SUBNODE_HEAPS if self.thorough else 1
        for entry in self.nbt_entries if self.thorough else self.nbt_entries[:4]:
            leaves: list[SubNodeLeafEntry] = []
            if entry.sub_node is not None:
                with contextlib.suppress(PstError):
                    leaves = list(reader.read_subnode_tree(entry.sub_node).values())[:2]
            with contextlib.suppress(PstError):
                out.append(OpenHeap(str(entry.node), HeapNode.from_node(reader, entry, self.limits), tuple(leaf.node.raw for leaf in leaves)))
            for leaf in leaves:
                if budget <= 0:
                    break
                budget -= 1
                with contextlib.suppress(PstError):
                    out.append(OpenHeap(f"{entry.node}/{leaf.node}", HeapNode.from_node(reader, leaf, self.limits), ()))
        return out

    @property
    def heaps(self) -> list[OpenHeap]:
        """The store's nodes as heaps, in NBT order (`HeapNode.from_node`)."""
        return self._lazy("heaps", self._open_heaps)

    def _open_trees(self) -> list[tuple[str, tree.HeapTree]]:
        out: list[tuple[str, tree.HeapTree]] = []
        for h in self.heaps if self.thorough else self.heaps[:2]:
            roots: list[tuple[str, HeapId | None]] = [(f"{h.label} user root", None)]
            row_index = _row_index_hid(h.heap)
            if row_index is not None:
                roots.append((f"{h.label} row index", row_index))
            for label, root_hid in roots:
                with contextlib.suppress(PstError):
                    out.append((label, tree.HeapTree(h.heap, root_hid)))
        return out

    @property
    def trees(self) -> list[tuple[str, tree.HeapTree]]:
        """The BTH at each heap's user root — and, for a table context, at its TCINFO's `hidRowIndex`."""
        return self._lazy("trees", self._open_trees)

    @property
    def heap_buffers(self) -> list[tuple[str, bytes]]:
        """Real heap bytes for the record decoders: the first heaps' block 0 and their user-root items.

        Empty when the store has no readable heap — the decoders are `bytes`
        entry points and must be reached on every store, ANSI included, so
        this swallows the refusal instead of raising `Unreachable`.
        """
        try:
            heaps = self.heaps
        except Unreachable:
            return []
        out: list[tuple[str, bytes]] = []
        for h in heaps[: 3 if self.thorough else 1]:
            out.append((f"{h.label} block 0", h.heap.block(0)))
            with contextlib.suppress(PstError):
                out.append((f"{h.label} user root", bytes(h.heap.get(h.heap.user_root))))
        return out

    def _open_contexts(self) -> list[tuple[str, PropertyContext]]:
        """The PC over every heap that is one; a TABLE or TREE heap refuses, and that refusal is judged at the constructor's own adapter."""
        out: list[tuple[str, PropertyContext]] = []
        for h in self.heaps if self.thorough else self.heaps[:2]:
            with contextlib.suppress(PstError):
                out.append((h.label, PropertyContext(h.heap, self.limits)))
        return out

    @property
    def contexts(self) -> list[tuple[str, PropertyContext]]:
        """Every node's property context, where the node has one (`PropertyContext(heap)`)."""
        return self._lazy("contexts", self._open_contexts)

    def _read_pc_records(self) -> list[tuple[str, PropertyContext, int, PropertyRecord]]:
        out: list[tuple[str, PropertyContext, int, PropertyRecord]] = []
        for label, pc in self.contexts:
            try:
                items = list(pc.records.items())
            except PstError:
                continue  # the walk's refusal is judged at `__iter__`/`get`, which parse the same records
            for prop_id, record in items if self.thorough else items[:4]:
                out.append((label, pc, prop_id, record))
        return out

    @property
    def pc_records(self) -> list[tuple[str, PropertyContext, int, PropertyRecord]]:
        """Every record of every property context: (label, its PC, its id, the record)."""
        return self._lazy("pc_records", self._read_pc_records)

    def _decode_pc_values(self) -> list[tuple[str, int, PropertyRecord, object]]:
        out: list[tuple[str, int, PropertyRecord, object]] = []
        for label, pc, prop_id, record in self.pc_records:
            with contextlib.suppress(PstError):  # a value that refuses is judged at `PropertyContext.read`
                out.append((label, prop_id, record, pc.read(record)))
        return out

    @property
    def pc_values(self) -> list[tuple[str, int, PropertyRecord, object]]:
        """Every record decoded, for the dumper's formatters.

        Empty when no PC opens — `format_property_value` and `property_lines`
        are `wire` entry points, which must be reached on every store, ANSI
        included, so this swallows the refusal instead of raising it.
        """
        try:
            return self._lazy("pc_values", self._decode_pc_values)
        except Unreachable:
            return []

    @property
    def bth_leaves(self) -> list[tuple[str, bytes, bytes]]:
        """Raw BTH leaves to read as PC records — real (key, value) pairs, a TC's 4-byte keys included."""
        try:
            trees = self.trees
        except Unreachable:
            return []
        out: list[tuple[str, bytes, bytes]] = []
        for label, t in trees[: 3 if self.thorough else 1]:
            with contextlib.suppress(PstError):  # the walk's refusal is judged at `HeapTree.__iter__`
                for i, (key, value) in enumerate(t):
                    if i >= (4 if self.thorough else 1):
                        break
                    out.append((f"{label} #{i}", key, value))
        return out

    def _open_tables(self) -> list[tuple[str, TableContext]]:
        """The TC over every heap that is one; a PC or a bare BTH refuses, and that refusal is judged at the constructor's own adapter."""
        out: list[tuple[str, TableContext]] = []
        for h in self.heaps if self.thorough else self.heaps[:2]:
            with contextlib.suppress(PstError):
                out.append((h.label, TableContext(h.heap, self.limits)))
        return out

    @property
    def tables(self) -> list[tuple[str, TableContext]]:
        """Every node's table context, where the node has one (`TableContext(heap)`)."""
        return self._lazy("tables", self._open_tables)

    def _read_table_rows(self) -> list[tuple[str, TableContext, int, TableRow]]:
        out: list[tuple[str, TableContext, int, TableRow]] = []
        for label, tc in self.tables:
            try:
                rows = list(tc.rows())
            except PstError:
                continue  # the walk's refusal is judged at `rows`/`__iter__`
            for index, row in enumerate(rows[: MAX_TABLE_ROWS if self.thorough else 2]):
                out.append((label, tc, index, row))
        return out

    @property
    def table_rows(self) -> list[tuple[str, TableContext, int, TableRow]]:
        """The first rows of every table, decoded: (label, its TC, its matrix index, the row)."""
        return self._lazy("table_rows", self._read_table_rows)

    def _read_table_cells(self) -> list[tuple[str, table_context.ColumnDescriptor, CellRecord | None, object]]:
        out: list[tuple[str, table_context.ColumnDescriptor, CellRecord | None, object]] = []
        for label, tc, index, row in self.table_rows:
            for column, record in zip(tc.columns, row.records, strict=False):
                if record is None:
                    out.append((f"{label} #{index}", column, None, None))
                    continue
                with contextlib.suppress(PstError):  # a cell that refuses is judged at `read_cell`
                    out.append((f"{label} #{index}", column, record, tc.read_cell(record, column.prop_type)))
        return out

    @property
    def table_cells(self) -> list[tuple[str, table_context.ColumnDescriptor, CellRecord | None, object]]:
        """Every cell of those rows, decoded, for the dumper's formatters; empty when no table opens (as `pc_values`)."""
        try:
            return self._lazy("table_cells", self._read_table_cells)
        except Unreachable:
            return []

    @property
    def tcinfo_buffers(self) -> list[tuple[str, bytes]]:
        """Real TCINFO items ([MS-PST] 2.3.4.1) — the user root of each of the first table heaps."""
        try:
            heaps = self.heaps
        except Unreachable:
            return []
        out: list[tuple[str, bytes]] = []
        for h in heaps:
            if h.heap.client_signature is not heap.HeapNodeType.TABLE:
                continue
            with contextlib.suppress(PstError):
                out.append((h.label, bytes(h.heap.get(h.heap.user_root))))
            if len(out) >= (3 if self.thorough else 1):
                break
        return out

    # --- the messaging layer over the same bytes (P07) ----------------------------

    @property
    def store(self) -> messaging.Store:
        """The message store over these bytes — over a `BytesIO`, so the sweep opens no file descriptor.

        `Unreachable` when the header, a B-tree or the 0x21 node refused:
        the refusal is judged at `Store` / `Store.open`, whose adapters call
        the constructor themselves.
        """
        return self._lazy("store", lambda: messaging.Store(io.BytesIO(self.data), limits=self.limits))

    @property
    def named_map(self) -> NamedPropertyMap:
        """The named property map of the 0x61 node; `Unreachable` when the node is absent or is not a PC."""
        return self._lazy("named_map", lambda: self.store.named_properties)

    @property
    def name_ids(self) -> list[NameIdEntry]:
        """A few NAMEIDs the store actually holds, plus two no store wrote (a GUID index and a string offset past their streams)."""
        forged = [
            NameIdEntry(0xFFFFFFFF, NamedPropertyGuid(0x7FFF), 0x7FFF, True),
            NameIdEntry(0xFFFFFFFF, NamedPropertyGuid(0x7FFF), 0, False),
        ]
        try:
            held = list(self.named_map.entries)
        except (Unreachable, PstError):  # the walk's refusal is judged at NamedPropertyMap's own adapters
            return forged
        keep = held[:4] if self.thorough else held[:1]
        return [*keep, *held[-1:], *forged]

    @property
    def named_streams(self) -> dict[int, bytes]:
        """The 0x61 node's four stream properties as raw bytes — empty when the map does not open."""
        out: dict[int, bytes] = {}
        try:
            pc = self.named_map.properties
        except (Unreachable, PstError):
            return out
        for prop_id in (named_prop.PID_TAG_NAMEID_STREAM_GUID, named_prop.PID_TAG_NAMEID_STREAM_ENTRY, named_prop.PID_TAG_NAMEID_STREAM_STRING):
            with contextlib.suppress(PstError):
                value = pc.get(prop_id)
                if isinstance(value, bytes):
                    out[prop_id] = value
        return out

    @property
    def entry_id_buffers(self) -> list[tuple[str, bytes]]:
        """The store's own EntryID property values — 24 real bytes each — or none when the store does not open."""
        out: list[tuple[str, bytes]] = []
        try:
            pc = self.store.properties
        except (Unreachable, PstError):
            return out
        for prop_id in (messaging.PID_TAG_IPM_SUB_TREE_ENTRY_ID, messaging.PID_TAG_IPM_WASTEBASKET_ENTRY_ID, messaging.PID_TAG_FINDER_ENTRY_ID):
            with contextlib.suppress(PstError):
                value = pc.get(prop_id)
                if isinstance(value, bytes):
                    out.append((f"0x{prop_id:04X}", value))
        return out

    # --- the folder tree over the same bytes (P08) --------------------------------

    @property
    def folders(self) -> list[Folder]:
        """The root folder and every folder `walk()` reaches before it refuses; `Unreachable` when 0x122 will not open.

        `_drain` keeps the partial walk on purpose: `pstd-inline-cid.pst`'s
        root folder opens and its hierarchy table does not, and the folder
        entry points must still be reached on that store.
        """
        return self._lazy("folders", lambda: self._drain(self.store.root_folder.walk()))

    @property
    def folder_nids(self) -> list[NodeId]:
        """Every NID a folder adapter aims at: the ones the store holds, and four no store can open.

        The forged four are a folder NID the NBT does not hold, a NID whose
        5-bit type is not a folder's, a NID whose type is not a type at all
        (0x09 is unassigned in [MS-PST] 2.2.2.1), and 0.
        """
        forged = [NodeId(0xFFFF_FFE2), NodeId(0x21), NodeId(0x9), NodeId(0)]
        held: list[NodeId] = [NID_ROOT_FOLDER]
        try:
            held += [f.node for f in self.folders]
            with contextlib.suppress(PstError):
                held += list(self.folders[0].subfolder_ids())
        except Unreachable:
            pass
        keep = list(dict.fromkeys(held))
        return [*(keep if self.thorough else keep[:2]), *forged]

    # --- the messages and attachments over the same bytes (P09) --------------------

    @property
    def messages(self) -> list[Message]:
        """Every message of every folder that opens, in walk order; `Unreachable` when the root folder does not.

        As `folders`, a refusal partway through is kept rather than
        discarded: `javalibpst-dist-list.pst` holds a message with no
        sub-node tree, and the entry points must still be reached on the
        messages either side of it.
        """

        def build() -> list[Message]:
            out: list[Message] = []
            for f in self.folders:
                with contextlib.suppress(PstError):
                    for message in f.messages():
                        out.append(message)
                        if not self.thorough and len(out) >= 1:
                            return out
            return out

        return self._lazy("messages", build)

    @property
    def message_nids(self) -> list[NodeId]:
        """Every NID a message adapter aims at: the ones the store holds, and four no store can open.

        The forged four are a message NID the NBT does not hold, a NID whose
        5-bit type is not a message's, a NID whose type is not a type at all
        (0x09 is unassigned in [MS-PST] 2.2.2.1), and 0.
        """
        forged = [NodeId(0xFFFF_FFE4), NID_ROOT_FOLDER, NodeId(0x9), NodeId(0)]
        held: list[NodeId] = []
        with contextlib.suppress(Unreachable, PstError):
            held = [m.node for m in self.messages]
        keep = list(dict.fromkeys(held))
        if self.thorough:
            return [*keep, *forged]
        # The exhaustive mutation lane builds a Message per call, so it takes
        # one real NID and the two forged ones that reach different branches.
        return [*keep[:1], *forged[:2]]

    @property
    def attachments(self) -> list[Attachment]:
        """Every attachment of every message that opens; empty when nothing in the store has one."""

        def build() -> list[Attachment]:
            out: list[Attachment] = []
            for m in self.messages:
                with contextlib.suppress(PstError):
                    for attachment in m.attachments():
                        out.append(attachment)
                        if not self.thorough and len(out) >= 1:
                            return out
            return out

        return self._lazy("attachments", build)

    @property
    def subjects(self) -> list[str]:
        """Real `PidTagSubject` values from the store, plus the prefixes no writer should produce."""
        held: list[str] = []
        with contextlib.suppress(Unreachable, PstError):
            held = [m.subject_raw for m in self.messages if m.subject_raw is not None]
        forged = ["", "\x01", "\x01\x01", "\x01\x00x", "\x01\xffshort", "plain subject"]
        return [*(held if self.thorough else held[:1]), *forged]

    @property
    def path(self) -> Path:
        """The store on disk, for the dumpers: written once, into `workdir` (a temp dir if none was given)."""
        if "path" not in self._cache:
            if self._workdir is None:
                tmp = tempfile.TemporaryDirectory(prefix="pypst-contract-")
                self._cache["tmpdir"] = tmp
                self._workdir = Path(tmp.name)
            p = self._workdir / "store.pst"
            p.write_bytes(self.data)
            self._cache["path"] = p
        return self._cache["path"]  # type: ignore[return-value]

    def close(self) -> None:
        opened = self._cache.pop("store", None)
        if opened is not None:
            opened.close()  # type: ignore[union-attr]
        tmp = self._cache.pop("tmpdir", None)
        if tmp is not None:
            tmp.cleanup()  # type: ignore[union-attr]


# --- the adapters -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Call:
    """One argument set for an entry point, with a short label for the outcome table."""

    args: tuple[Any, ...] = ()
    kwargs: dict[str, Any] = field(default_factory=dict)
    label: str = ""


def call(*args: Any, label: str = "", **kwargs: Any) -> Call:
    return Call(args, kwargs, label)


Builder = Callable[[Store], Iterable[Call]]


def _offsets(s: Store, size: int) -> list[int]:
    """Offsets to unpack a `size`-byte record at: the start, straddling the end, at the end, past it."""
    n = len(s.data)
    return [0, max(n - size + 1, 0), n, n + 1]


def _unpack_from(size: int) -> Builder:
    return lambda s: [call(s.data, off, label=f"@{off}") for off in _offsets(s, size)] + [call(b"", 0, label="empty")]


def _per_page(*extra: Callable[[ByteIndex, bytes], Call]) -> Builder:
    return lambda s: [fn(idx, buf) for idx, buf in s.pages for fn in extra]


def _page_entries(size: int) -> Builder:
    """An entry record at the start of every page and straddling its trailer."""
    return lambda s: [call(buf, off, label=f"{idx}+{off}") for idx, buf in s.pages for off in (0, page.PAGE_DATA_SIZE - size + 1)]


def _slices(**kwargs: Any) -> Builder:
    return lambda s: [call(sl, label=f"[:{len(sl)}]", **kwargs) for sl in s.slices]


def _tree_pages(s: Store) -> list[Call]:
    return [call(s.nbt, label="nbt"), call(s.bbt, label="bbt")]


def _read_block_calls(s: Store) -> Iterator[Call]:
    for i, e in enumerate(s.bbt_entries):
        yield call(s.reader, e.block, e.size, is_internal=e.block.block.is_internal, label=f"{e.block.block}")
        if i < 4:  # the wrong flag on a few: a refusal, never a leak
            yield call(s.reader, e.block, e.size, is_internal=not e.block.block.is_internal, label=f"{e.block.block} wrong flag")


def _trailer_verify_calls(s: Store) -> Iterator[Call]:
    for idx, buf in s.pages:
        with contextlib.suppress(PstError):  # a page whose trailer does not unpack is judged at unpack_from
            yield call(page.PageTrailer.unpack_from(buf), buf, idx, label=str(idx))


def _subnode_roots(s: Store) -> list[BlockId]:
    return [e.sub_node for e in s.nbt_entries if e.sub_node is not None]


# --- the heap and the BTH over it (P04) ----------------------------------------------


def _row_index_hid(node: HeapNode) -> HeapId | None:
    """A table context's `hidRowIndex` ([MS-PST] 2.3.4.1), or None when the heap is not a TC or its TCINFO does not read."""
    if node.client_signature is not heap.HeapNodeType.TABLE:
        return None
    with contextlib.suppress(PstError, struct.error):
        return HeapId(struct.unpack_from(TCINFO_FORMAT, node.get(node.user_root), 0)[6])
    return None


def _from_node_calls(s: Store) -> Iterator[Call]:
    """Every node as a heap, and the first nodes' sub-node leaves too: a node that is not a heap must refuse, never leak."""
    for i, entry in enumerate(s.nbt_entries if s.thorough else s.nbt_entries[:4]):
        yield call(s.reader, entry, label=str(entry.node))
        if i >= 4 or entry.sub_node is None:
            continue
        leaves: list[SubNodeLeafEntry] = []
        with contextlib.suppress(PstError):  # the subnode tree's own refusal is judged at read_subnode_tree
            leaves = list(s.reader.read_subnode_tree(entry.sub_node).values())[:2]
        for leaf in leaves:
            yield call(s.reader, leaf, label=f"{entry.node}/{leaf.node}")


def _heap_ctor_calls(s: Store) -> Iterator[Call]:
    """The raw constructor over each node's blocks, and over what is not a heap at all."""
    reader = s.reader
    for entry in s.nbt_entries if s.thorough else s.nbt_entries[:4]:
        try:
            blocks = reader.read_data_blocks(entry.data)
        except PstError:
            continue  # the refusal is read_data_blocks', and is judged there
        yield call(blocks, reader=reader, limits=s.limits, label=str(entry.node))
    yield call([], label="no blocks")
    yield call([b""], label="empty block")
    yield call(s.slices[1:], label="raw slices")


def _block_indices(h: OpenHeap) -> list[int]:
    """0, the last block, one past it, and a negative — the last two must refuse."""
    count = h.heap.block_count
    return list(dict.fromkeys([0, count - 1, count, -1]))


def _heap_ids(h: OpenHeap) -> Iterator[tuple[str, HeapId]]:
    """HIDs to resolve in `h`: the user root, item 1 of the first and the last block, the null HID, one past `cAlloc`, one past the last block."""
    count = min(h.heap.block_count, MAX_HEAP_BLOCK_INDEX)
    yield "user root", h.heap.user_root
    yield "item 1", HeapId.from_parts(1, 0)
    yield "item 1 of the last block", HeapId.from_parts(1, count - 1)
    yield "null", HeapId(0)
    yield "past cAlloc", HeapId.from_parts(heap.MAX_HEAP_ITEM_INDEX, 0)
    yield "past the last block", HeapId.from_parts(1, count)


def _hnid_calls(s: Store) -> Iterator[Call]:
    """An HNID on the heap side (the user root), on the node side (a sub-node the tree holds), and one no tree holds."""
    for h in s.heaps:
        yield call(h.heap, HeapNodeId(h.heap.user_root.raw), label=f"{h.label} user root")
        for nid in h.subnode_nids:
            yield call(h.heap, HeapNodeId(nid), label=f"{h.label} sub-node {nid:#x}")
        yield call(h.heap, HeapNodeId(ABSENT_SUBNODE), label=f"{h.label} absent sub-node")


def _tree_ctor_calls(s: Store) -> Iterator[Call]:
    """The BTH at the user root, at a TC's `hidRowIndex`, and at two HIDs whose item is no BTHHEADER."""
    for h in s.heaps if s.thorough else s.heaps[:2]:
        yield call(h.heap, label=f"{h.label} user root")
        row_index = _row_index_hid(h.heap)
        if row_index is not None:
            yield call(h.heap, row_index, label=f"{h.label} row index")
        if s.thorough:
            yield call(h.heap, HeapId.from_parts(1, 0), label=f"{h.label} item 1")
            yield call(h.heap, HeapId(0), label=f"{h.label} null root")


def _find_calls(s: Store) -> Iterator[Call]:
    """A key the tree holds, two it does not, and one of the wrong length."""
    for label, t in s.trees:
        try:
            held = next(iter(t))[0]
        except (PstError, StopIteration):
            held = None  # the walk's refusal is judged at __iter__; an empty tree holds nothing
        if held is not None:
            yield call(t, held, label=f"{label} held")
        yield call(t, bytes(t.key_size), label=f"{label} zero key")
        yield call(t, b"\xff" * t.key_size, label=f"{label} absent")
        yield call(t, b"", label=f"{label} wrong length")


def _heap_records(size: int) -> Builder:
    """`_unpack_from` over the whole store, plus the same offsets inside real heap bytes (none when no heap opens)."""
    whole = _unpack_from(size)

    def build(s: Store) -> Iterator[Call]:
        yield from whole(s)
        for label, buf in s.heap_buffers:
            for off in (0, max(len(buf) - size + 1, 0), len(buf), len(buf) + 1):
                yield call(buf, off, label=f"{label}@{off}")

    return build


# --- the property context over a heap (P05) -------------------------------------------


def _context_from_node_calls(s: Store) -> Iterator[Call]:
    """`PropertyContext.from_node` / `TableContext.from_node` over every node and the first sub-node leaves.

    Both take `(reader, entry, *, codepage=)`, and both must refuse — never
    leak — for a node whose heap is the other kind, or no heap at all.
    """
    for i, entry in enumerate(s.nbt_entries if s.thorough else s.nbt_entries[:4]):
        yield call(s.reader, entry, label=str(entry.node))
        if i >= 4 or entry.sub_node is None:
            continue
        leaves: list[SubNodeLeafEntry] = []
        with contextlib.suppress(PstError):  # the subnode tree's own refusal is judged at read_subnode_tree
            leaves = list(s.reader.read_subnode_tree(entry.sub_node).values())[:2]
        for leaf in leaves:
            yield call(s.reader, leaf, label=f"{entry.node}/{leaf.node}")
    if s.thorough and s.nbt_entries:
        yield call(s.reader, s.nbt_entries[0], codepage=BAD_CODEPAGE, label="bad codepage")


def _forged_records(prop_id: int) -> Iterator[tuple[str, PropertyRecord]]:
    """Records no store wrote: an HNID naming a sub-node no tree holds, type bits on a heap-only type, a null HNID, an HID past cAlloc."""
    yield "absent sub-node", PropertyRecord(prop_id, PropType.BINARY, ABSENT_SUBNODE)
    yield "type bits on a GUID", PropertyRecord(prop_id, PropType.GUID, ABSENT_SUBNODE)
    yield "null HNID", PropertyRecord(prop_id, PropType.UNICODE, 0)
    yield "HID past cAlloc", PropertyRecord(prop_id, PropType.BINARY, HeapId.from_parts(heap.MAX_HEAP_ITEM_INDEX, 0).raw)


def _pc_read_calls(s: Store) -> Iterator[Call]:
    """Every record of every PC, the forged records on each PC, and the first PC read through a code page that does not exist."""
    for label, pc, prop_id, record in s.pc_records:
        yield call(pc, record, label=f"{label} 0x{prop_id:04X}")
    for label, pc in s.contexts if s.thorough else s.contexts[:1]:
        for why, forged in _forged_records(0x3001):
            yield call(pc, forged, label=f"{label} {why}")
    if s.thorough and s.contexts:
        # The same records through a code page that does not exist: a String8
        # must refuse as a `PstError`, never as the `LookupError` the codecs raise.
        label, pc = s.contexts[0]
        broken: list[tuple[PropertyContext, PropertyRecord]] = []
        with contextlib.suppress(PstError):
            other = PropertyContext(pc.heap, s.limits, codepage=BAD_CODEPAGE)
            broken = [(other, record) for record in other.records.values()]
        for other, record in broken:
            yield call(other, record, label=f"{label} 0x{record.prop_id:04X} bad codepage")


def _pc_get_calls(s: Store) -> Iterator[Call]:
    """A property id the PC holds, one whose HNID is 0, one it does not hold, and 0."""
    for label, pc in s.contexts:
        ids_: list[int] = []
        with contextlib.suppress(PstError):  # the walk's refusal is judged at `__iter__`
            records = pc.records
            ids_ = list(records)[:1] + [prop_id for prop_id, record in records.items() if record.is_null][:1]
        for prop_id in ids_:
            yield call(pc, prop_id, label=f"{label} 0x{prop_id:04X}")
        yield call(pc, 0xFFFE, label=f"{label} absent")
        yield call(pc, 0, label=f"{label} 0x0000")


def _pc_unpack_calls(s: Store) -> Iterator[Call]:
    """Real BTH leaves, truncated and doubled on both sides, and every wire type code in a record."""
    for label, key, value in s.bth_leaves:
        yield call(key, value, label=label)
        yield call(key[:1], value, label=f"{label} short key")
        yield call(key, value[: prop_context.PC_RECORD_SIZE - 1], label=f"{label} short value")
        yield call(key + key, value + value, label=f"{label} doubled")
    for code in s.wire_codes:
        yield call(b"\x01\x30", struct.pack(prop_context.PC_RECORD_FORMAT, code, 0x20), label=f"type {code:#06x}")
    yield call(b"", b"", label="empty")


def _format_value_calls(s: Store) -> Iterator[Call]:
    """Every value a store's PCs decoded to, and `None` under every type — what `dump_pc` prints with."""
    for label, prop_id, record, value in s.pc_values:
        yield call(record.prop_type, value, label=f"{label} 0x{prop_id:04X}")
    for t in PropType:
        yield call(t, None, label=f"{t.name} null")


def _property_line_calls(s: Store) -> Iterator[Call]:
    for label, prop_id, record, value in s.pc_values:
        yield call(prop_id, record, value, label=f"{label} 0x{prop_id:04X}")
    yield call(0, PropertyRecord(0, PropType.NULL, 0), None, label="null record")


# --- the table context over a heap (P06) ----------------------------------------------


def _tables_or_none(s: Store) -> list[tuple[str, TableContext]]:
    """`Store.tables`, or none when the store refused: for the `bytes` and `wire` entry points, which must be reached anyway."""
    try:
        return s.tables
    except Unreachable:
        return []


def _rows_or_none(s: Store) -> list[tuple[str, TableContext, int, TableRow]]:
    """`Store.table_rows`, or none when the store refused (as `_tables_or_none`)."""
    try:
        return s.table_rows
    except Unreachable:
        return []


def _forged_cells() -> Iterator[tuple[str, CellRecord, PropType]]:
    """Cell records no matrix wrote: an HID past `cAlloc`, a sub-node no tree holds, a null HNID, an inline cell too short for its type."""
    yield "HID past cAlloc", CellRecord(CellKind.HEAP, HeapId.from_parts(heap.MAX_HEAP_ITEM_INDEX, 0).raw), PropType.BINARY
    yield "absent sub-node", CellRecord(CellKind.NODE, ABSENT_SUBNODE), PropType.BINARY
    yield "null HNID", CellRecord(CellKind.HEAP, 0), PropType.UNICODE
    yield "short inline cell", CellRecord(CellKind.SMALL, data=b"\x01"), PropType.SYSTIME


def _tc_row_calls(s: Store) -> Iterator[Call]:
    """Row 0, the last row, one past the last, and a negative index — the last two must refuse."""
    for label, tc in s.tables:
        count = 0
        with contextlib.suppress(PstError):  # the matrix's own refusal is judged at `rows`
            count = tc.row_count
        for index in dict.fromkeys([0, count - 1, count, -1]):
            yield call(tc, index, label=f"{label} row {index}")


def _tc_find_row_calls(s: Store) -> Iterator[Call]:
    """A row id the index holds, one it does not, and 0."""
    for label, tc in s.tables:
        held: list[int] = []
        with contextlib.suppress(PstError):  # the index's own refusal is judged at `rows`
            held = list(tc.row_index)[:1]
        for row_id in (*held, 0xFFFF_FFFF, 0):
            yield call(tc, row_id, label=f"{label} 0x{row_id:08X}")


def _tc_read_cell_calls(s: Store) -> Iterator[Call]:
    """Every present cell of the rows kept, and the forged records on every table."""
    for label, tc, index, row in s.table_rows:
        for column, record in zip(tc.columns, row.records, strict=False):
            if record is not None:
                yield call(tc, record, column.prop_type, label=f"{label} #{index} 0x{column.prop_id:04X}")
    for label, tc in s.tables if s.thorough else s.tables[:1]:
        for why, record, cell_type in _forged_cells():
            yield call(tc, record, cell_type, label=f"{label} {why}")


def _table_row_get_calls(s: Store) -> Iterator[Call]:
    """A property id the row has and one it does not — `get` answers `default` for an absent column, never raises.

    A `wire` entry point, so the refusal of a store with no table is
    swallowed: only the readers may SKIP (`test_fixture_never_leaks`).
    """
    for label, _tc, index, row in _rows_or_none(s):
        for prop_id in (*list(row.cells)[:1], 0xFFFE):
            yield call(row, prop_id, label=f"{label} #{index} 0x{prop_id:04X}")
    yield call(TableRow(0, 0, {}, ()), 0x3001, label="empty row")


def _tcinfo_calls(s: Store) -> Iterator[Call]:
    """Real TCINFO items whole, short and doubled, and the store's own bytes — `unpack` takes the whole item, no offset."""
    for label, buf in s.tcinfo_buffers:
        yield call(buf, label=label)
        yield call(buf[: table_context.TCINFO_SIZE - 1], label=f"{label} short")
        yield call(buf[:-1], label=f"{label} truncated")
        yield call(buf + buf, label=f"{label} doubled")
    for sl in s.slices:
        yield call(sl, label=f"[:{len(sl)}]")


def _tcoldesc_calls(s: Store) -> Iterator[Call]:
    """A TCOLDESC at every edge of a real TCINFO, and one carrying every wire type code."""
    size = table_context.TCOLDESC_SIZE
    for label, buf in s.tcinfo_buffers:
        for off in dict.fromkeys([0, table_context.TCINFO_SIZE, max(len(buf) - size + 1, 0), len(buf), len(buf) + 1]):
            yield call(buf, off, label=f"{label}@{off}")
    for code in s.wire_codes:
        yield call(struct.pack(table_context.TCOLDESC_FORMAT, code, 0x3001, 8, 4, 2), 0, label=f"type {code:#06x}")
    yield call(b"", 0, label="empty")


def _existence_bitmap_calls(s: Store) -> Iterator[Call]:
    """Every column's `iBit` against a full and an empty bitmap of the schema's own width, and three bits past it.

    The column index is `iBit`, a u8 out of a TCOLDESC, so it is never
    negative here: a negative index is a caller's bug, not a file's — the
    reason `HeapPageMap.size` is in `NOT_STORE_INPUT`.
    """
    tables = _tables_or_none(s)
    for label, tc in tables if s.thorough else tables[:1]:
        width = tc.info.bitmap_size
        for bitmap in (b"\xff" * width, bytes(width)):
            for column in tc.columns:
                yield call(column.existence_bit, bitmap, label=f"{label} bit {column.existence_bit}")
            for bit in (0, width * 8, 0xFF):
                yield call(bit, bitmap, label=f"{label} bit {bit} of {width}")
    yield call(0, b"\x80", label="bit 0 set")
    yield call(8, b"\x80", label="bit past a one-byte bitmap")


def _cell_record_calls(s: Store) -> Iterator[Call]:
    """Every present cell the corpus decoded, plus the three kinds under a synthetic record."""
    for label, column, record, value in s.table_cells:
        if record is not None:
            yield call(column.prop_type, record, value, label=label)
    for kind in CellKind:
        yield call(PropType.BINARY, CellRecord(kind, 0x20, b"\x00\x00\x00\x00"), None, label=kind.name)


def _cell_line_calls(s: Store) -> Iterator[Call]:
    """Every cell of every row kept, absent columns included — two lines for those, three for a present one."""
    for label, column, record, value in s.table_cells:
        yield call(column, record, value, label=label)
    yield call(table_context.ColumnDescriptor(PropType.LONG, 0x67F2, 0, 4, 0), None, None, label="absent cell")
# --- the message store and its named properties (P07) ----------------------------------


def _store_ctor_calls(s: Store) -> Iterator[Call]:
    """The constructor over the raw bytes, and over a slice of them: a store that is not one must refuse."""
    yield call(io.BytesIO(s.data), limits=s.limits, label="whole")
    if s.thorough:
        yield call(io.BytesIO(s.data[: page.PAGE_SIZE]), limits=s.limits, label="first page only")
        yield call(io.BytesIO(b""), limits=s.limits, label="empty")


def _store_open_calls(s: Store) -> Iterator[Call]:
    """`Store.open` over the store on disk — the entry point `pypst.open` is."""
    yield call(s.path, limits=s.limits, label="default")
    if s.thorough:
        yield call(s.path, limits=s.limits, codepage=BAD_CODEPAGE, label="bad codepage")


def _store_close_calls(s: Store) -> Iterator[Call]:
    """`close()` on a store of this adapter's own, twice: it must be idempotent and must not touch `s.store`."""
    own = messaging.Store(io.BytesIO(s.data), limits=s.limits)  # a PstError here is the SKIP the sweep records
    yield call(own, label="first")
    yield call(own, label="again")


def _store_entry_id_calls(s: Store) -> Iterator[Call]:
    """A well-known NID, one no store holds, and a NID whose 5-bit type is not a known one."""
    for nid in (0x21, 0x122, 0xFFFFFFFF, 0):
        yield call(s.store, NodeId(nid), label=f"{nid:#x}")


def _store_matches_calls(s: Store) -> Iterator[Call]:
    """An EntryID this store issued, and one whose record key is another store's."""
    store = s.store
    yield call(store, EntryId(bytes(RECORD_KEY_SIZE), NodeId(0x21)), label="foreign")
    own = None
    with contextlib.suppress(PstError):  # a store with no PidTagRecordKey is judged at the dumper
        own = store.entry_id(NodeId(0x21))
    if own is not None:
        yield call(store, own, label="own")


def _store_get_calls(s: Store) -> Iterator[Call]:
    """The four properties this layer reads by name, one the store cannot hold, and 0."""
    for prop_id in (messaging.PID_TAG_RECORD_KEY, messaging.PID_TAG_DISPLAY_NAME, messaging.PID_TAG_IPM_SUB_TREE_ENTRY_ID, messaging.PID_TAG_FINDER_ENTRY_ID, 0xFFFF, 0):
        yield call(s.store, prop_id, label=f"0x{prop_id:04X}")


def _entry_id_unpack_calls(s: Store) -> Iterator[Call]:
    """The 24-byte record at the start, straddling the end, at the end and past it — and over the store's own EntryID values."""
    yield from _unpack_from(EntryId.SIZE)(s)
    for label, buf in s.entry_id_buffers:
        for off in (0, 1, len(buf), len(buf) + 1):
            yield call(buf, off, label=f"{label}@{off}")


def _name_id_unpack_calls(s: Store) -> Iterator[Call]:
    """The same four offsets over the whole store and over the real entry stream, where one opens."""
    yield from _unpack_from(NameIdEntry.SIZE)(s)
    data = s.named_streams.get(named_prop.PID_TAG_NAMEID_STREAM_ENTRY)
    if data is not None:
        for off in (0, max(len(data) - NameIdEntry.SIZE + 1, 0), len(data), len(data) + 1):
            yield call(data, off, label=f"entry stream@{off}")


def _named_map_ctor_calls(s: Store) -> Iterator[Call]:
    """The map over every property context: the 0x61 node is one, and every other PC must refuse as "not a map"."""
    for label, pc in s.contexts if s.thorough else s.contexts[:2]:
        yield call(pc, s.limits, label=label)


def _named_map_from_node_calls(s: Store) -> Iterator[Call]:
    """The named nodes, plus the first node or two: a node that is not the map must refuse."""
    wanted = [e for e in s.nbt_entries if e.node.raw in (0x61, 0x21, 0x122)]
    extra = s.nbt_entries[:2] if s.thorough else s.nbt_entries[:1]
    for entry in dict.fromkeys([*wanted, *extra]):
        yield call(s.reader, entry, s.limits, label=str(entry.node))


def _named_lookup_calls(s: Store) -> Iterator[Call]:
    """Every id the map holds (or the first few), one below the named range, one above it, and 0."""
    held: list[int] = []
    with contextlib.suppress(Unreachable, PstError):  # the walk's refusal is judged at NamedPropertyMap's constructor
        entries = s.named_map.entries
        held = [e.prop_id for e in (entries if s.thorough else entries[:2])]
    for prop_id in [*held, 0x7FFF, 0xFFFF, 0]:
        yield call(s.named_map, prop_id, label=f"0x{prop_id:04X}")


def _named_resolve_calls(s: Store) -> Iterator[Call]:
    """A (GUID, name) pair the map issued, one it did not, and a name of the wrong shape for its GUID."""
    named = s.named_map
    pairs: list[tuple[uuid.UUID, str | int]] = []
    with contextlib.suppress(PstError):
        for entry in named.entries[: 4 if s.thorough else 1]:
            pairs.append((named.guid_of(entry), named.name_of(entry)))
    pairs += [(named_prop.PS_MAPI, "no such named property"), (uuid.UUID(int=0), 0xFFFFFFFF)]
    for guid, name in pairs:
        yield call(named, guid, name, label=f"{guid}/{name!r:.32}")


def _named_entry_calls(s: Store) -> Iterator[Call]:
    return [call(s.named_map, entry, label=f"0x{entry.prop_id:04X}") for entry in s.name_ids]


def _named_string_calls(s: Store) -> Iterator[Call]:
    """The offsets the map's own entries name, plus 0, an odd offset, the end and past it."""
    named = s.named_map
    data = s.named_streams.get(named_prop.PID_TAG_NAMEID_STREAM_STRING, b"")
    offsets = [e.name_id for e in s.name_ids if e.is_string and e.name_id <= len(data)]
    return [call(named, off, label=f"@{off:#x}") for off in dict.fromkeys([*offsets, 0, 1, len(data), len(data) + 1, 0xFFFFFFFF])]


def _folders(s: Store) -> list[Folder]:
    """The folders an adapter calls a method on: all of them when thorough, else the first two."""
    return s.folders if s.thorough else s.folders[:2]


def _folder_ctor_calls(s: Store) -> Iterator[Call]:
    """Every folder NID the store holds, plus the four no store can open (`Store.folder_nids`)."""
    for nid in s.folder_nids:
        yield call(s.store, nid, label=str(nid))


def _folder_open_calls(s: Store) -> Iterator[Call]:
    """The same NIDs, plus this store's own EntryID for the root and another store's for the same node."""
    store = s.store
    for nid in s.folder_nids:
        yield call(store, nid, label=str(nid))
    with contextlib.suppress(PstError):  # a store with no PidTagRecordKey is judged at Store.entry_id
        yield call(store, store.entry_id(NID_ROOT_FOLDER), label="own entry id")
    yield call(store, EntryId(bytes(RECORD_KEY_SIZE), NID_ROOT_FOLDER), label="foreign entry id")


def _open_folder_calls(s: Store) -> Iterator[Call]:
    """`Store.open_folder` over the same set, through the store rather than the class."""
    store = s.store
    for nid in s.folder_nids:
        yield call(store, nid, label=str(nid))
    yield call(store, EntryId(bytes(RECORD_KEY_SIZE), NID_ROOT_FOLDER), label="foreign entry id")


def _folder_calls(s: Store) -> Iterator[Call]:
    """One call per folder, no arguments — the three id lists and the sub-folder walk."""
    for f in _folders(s):
        yield call(f, label=str(f.node))


def _folder_table_calls(s: Store) -> Iterator[Call]:
    """Every folder against every node type: the three tables it has, and types that are not tables at all."""
    types = tuple(NodeIdType) if s.thorough else (NodeIdType.HIERARCHY_TABLE, NodeIdType.NORMAL_FOLDER)
    for f in _folders(s):
        for node_type in types:
            yield call(f, node_type, label=f"{f.node} {node_type.debug_name}")


def _folder_get_calls(s: Store) -> Iterator[Call]:
    """The four properties this layer reads by name, one no folder holds, and 0."""
    ids = (
        folder_mod.PID_TAG_DISPLAY_NAME,
        folder_mod.PID_TAG_CONTENT_COUNT,
        folder_mod.PID_TAG_CONTENT_UNREAD_COUNT,
        folder_mod.PID_TAG_SUBFOLDERS,
        0xFFFF,
        0,
    )
    for f in _folders(s):
        for prop_id in ids if s.thorough else ids[:1]:
            yield call(f, prop_id, label=f"{f.node} 0x{prop_id:04X}")


def _folder_walk_calls(s: Store) -> Iterator[Call]:
    """The walk from every folder, at the default ceiling and at the two that must refuse a real tree."""
    for f in _folders(s):
        yield call(f, label=str(f.node))
        if s.thorough:
            yield call(f, max_depth=1, label=f"{f.node} max_depth=1")
            yield call(f, max_depth=0, label=f"{f.node} max_depth=0")


def _debug_folder_calls(s: Store) -> Iterator[Call]:
    """`debug.folder_lines` over every folder: the whole block the dumper prints, formatting included."""
    return _folder_calls(s)


def _debug_folder_accessor_calls(s: Store) -> Iterator[Call]:
    """Both arms of the example's `result_debug`: a renderer that returns, and one that refuses."""

    def refuse() -> str:
        raise PstFormatError("adapter: the accessor refused")

    for f in _folders(s):
        for prop_id in (folder_mod.PID_TAG_DISPLAY_NAME, folder_mod.PID_TAG_SUBFOLDERS):
            yield call(f, prop_id, lambda f=f: str(f.display_name), label=f"{f.node} 0x{prop_id:04X} value")
            yield call(f, prop_id, refuse, label=f"{f.node} 0x{prop_id:04X} refused")


def _messages(s: Store) -> list[Message]:
    """The messages an adapter calls a method on: all of them when thorough, else the first."""
    return s.messages if s.thorough else s.messages[:1]


def _message_ctor_calls(s: Store) -> Iterator[Call]:
    """Every message NID the store holds, plus the four no store can open (`Store.message_nids`)."""
    for nid in s.message_nids:
        yield call(s.store, nid, label=str(nid))


def _message_open_calls(s: Store) -> Iterator[Call]:
    """The same NIDs, plus this store's own EntryID for one and another store's."""
    store = s.store
    for nid in s.message_nids:
        yield call(store, nid, label=str(nid))
    with contextlib.suppress(PstError, Unreachable):
        yield call(store, store.entry_id(s.message_nids[0]), label="own entry id")
    yield call(store, EntryId(bytes(RECORD_KEY_SIZE), NodeId(0xFFFF_FFE4)), label="foreign entry id")


def _open_message_calls(s: Store) -> Iterator[Call]:
    """`Store.open_message` over the same set, through the store rather than the class."""
    store = s.store
    for nid in s.message_nids:
        yield call(store, nid, label=str(nid))
    yield call(store, EntryId(bytes(RECORD_KEY_SIZE), NodeId(0xFFFF_FFE4)), label="foreign entry id")


def _message_calls(s: Store) -> Iterator[Call]:
    """One call per message, no arguments — the recipients, the attachment ids and the RTF body."""
    for m in _messages(s):
        yield call(m, label=str(m.node))


def _message_get_calls(s: Store) -> Iterator[Call]:
    """The properties this layer reads by name, one no message holds, and 0."""
    ids = (
        message_mod.PID_TAG_MESSAGE_CLASS,
        message_mod.PID_TAG_SUBJECT,
        message_mod.PID_TAG_MESSAGE_DELIVERY_TIME,
        message_mod.PID_TAG_RTF_COMPRESSED,
        0xFFFF,
        0,
    )
    for m in _messages(s):
        for prop_id in ids if s.thorough else ids[:1]:
            yield call(m, prop_id, label=f"{m.node} 0x{prop_id:04X}")


def _message_table_calls(s: Store) -> Iterator[Call]:
    """Every message against every node type: the two tables it has, and types that are not tables at all."""
    types = tuple(NodeIdType) if s.thorough else (NodeIdType.RECIPIENT_TABLE, NodeIdType.ATTACHMENT_TABLE)
    for m in _messages(s):
        for node_type in types:
            yield call(m, node_type, label=f"{m.node} {node_type.debug_name}")


def _message_sub_node_calls(s: Store) -> Iterator[Call]:
    """Every sub-node NID a message holds, and two it does not."""
    for m in _messages(s):
        held = list(m.sub_nodes)
        for node in (held + [NodeId(0xFFFF_FFE5), NodeId(0)]) if s.thorough else (held[:1] + [NodeId(0)]):
            yield call(m, node, label=f"{m.node} {node}")


def _attachment_ctor_calls(s: Store) -> Iterator[Call]:
    """Every attachment NID every message names, plus NIDs no message can hold."""
    forged = [NodeId(0xFFFF_FFE5), NodeId(0x21), NodeId(0x9), NodeId(0)]
    for m in _messages(s):
        held: list[NodeId] = []
        with contextlib.suppress(PstError):
            held = list(m.attachment_ids())
        for node in (held + forged) if s.thorough else (held[:1] + forged[:2]):
            yield call(m, node, label=f"{m.node} {node}")


def _attachments(s: Store) -> list[Attachment]:
    return s.attachments if s.thorough else s.attachments[:1]


def _attachment_calls(s: Store) -> Iterator[Call]:
    """One call per attachment, no arguments — `data()` and `embedded_message()`."""
    for a in _attachments(s):
        yield call(a, label=str(a.node))


def _attachment_get_calls(s: Store) -> Iterator[Call]:
    ids = (
        attachment_mod.PID_TAG_ATTACH_METHOD,
        attachment_mod.PID_TAG_ATTACH_DATA_BINARY,
        attachment_mod.PID_TAG_ATTACH_LONG_FILENAME,
        0xFFFF,
        0,
    )
    for a in _attachments(s):
        for prop_id in ids if s.thorough else ids[:1]:
            yield call(a, prop_id, label=f"{a.node} 0x{prop_id:04X}")


def _attachment_sub_node_calls(s: Store) -> Iterator[Call]:
    for a in _attachments(s):
        held: list[NodeId] = []
        with contextlib.suppress(PstError):
            held = list(a.sub_nodes)
        for node in (held + [NodeId(0xFFFF_FFE5), NodeId(0)]) if s.thorough else (held[:1] + [NodeId(0)]):
            yield call(a, node, label=f"{a.node} {node}")


def _attach_method_calls(s: Store) -> Iterator[Call]:
    """Every method [MS-OXCMSG] 2.2.2.9 defines, the two upstream and this port disagree about, and nonsense."""
    values = [*range(-1, 9), 0x7FFF_FFFF, -0x8000_0000] if s.thorough else [5, 99]
    return (call(v, label=str(v)) for v in values)


def _split_subject_calls(s: Store) -> Iterator[Call]:
    """Real subjects out of the store, and the control prefixes a store should not have written."""
    return (call(text, label=repr(text[:24])) for text in (s.subjects if s.thorough else s.subjects[:3]))


def _recipient_get_calls(s: Store) -> Iterator[Call]:
    """`Recipient.get` over every recipient of every message, at a column it has and one it does not.

    A `Recipient` is a plain mapping over a row this layer already decoded,
    so a store with no readable message still gets one — forged here rather
    than reported `Unreachable`, because nothing about this call needs the
    store to have opened.
    """
    found = False
    with contextlib.suppress(Unreachable):
        for m in _messages(s):
            with contextlib.suppress(PstError):
                for recipient in m.recipients():
                    found = True
                    for prop_id in (message_mod.PID_TAG_DISPLAY_NAME, 0xFFFF):
                        yield call(recipient, prop_id, label=f"{m.node} 0x{prop_id:04X}")
                    if not s.thorough:
                        break
    if not found:
        forged = message_mod.Recipient(message_mod.RecipientType.TO, None, None, None, {})
        yield call(forged, message_mod.PID_TAG_DISPLAY_NAME, label="forged")


def _debug_message_lines_calls(s: Store) -> Iterator[Call]:
    """`debug.message_lines` over every message: the twelve property lines, formatting included."""
    for m in _messages(s):
        yield call(m, 2, label=str(m.node))


def _debug_upstream_records_calls(s: Store) -> Iterator[Call]:
    """Every property context the dumper truncates: a message's, an attachment's, and the store's."""
    seen: list[Call] = []
    with contextlib.suppress(Unreachable, PstError):
        seen.append(call(s.store.properties, label="store"))
    for m in _messages(s):
        seen.append(call(m.properties, label=str(m.node)))
    for a in _attachments(s):
        seen.append(call(a.properties, label=str(a.node)))
    return iter(seen)


def _debug_message_accessor_calls(s: Store) -> Iterator[Call]:
    """Both arms of the example's `result_debug`: a renderer that returns, and one that refuses."""

    def refuse() -> str:
        raise PstFormatError("adapter: the accessor refused")

    for m in _messages(s):
        prop_id = message_mod.PID_TAG_MESSAGE_CLASS
        yield call(m, prop_id, lambda m=m: str(m.message_class), label=f"{m.node} value")
        yield call(m, prop_id, refuse, label=f"{m.node} refused")


def _debug_attachment_accessor_calls(s: Store) -> Iterator[Call]:
    def refuse() -> str:
        raise PstFormatError("adapter: the accessor refused")

    for a in _attachments(s):
        for prop_id in (attachment_mod.PID_TAG_ATTACH_METHOD, attachment_mod.PID_TAG_ATTACH_SIZE):
            yield call(a, prop_id, lambda a=a: str(a.method_value), label=f"{a.node} 0x{prop_id:04X} value")
            yield call(a, prop_id, refuse, label=f"{a.node} 0x{prop_id:04X} refused")


def _dumper_calls(dumper: Callable[..., None]) -> Builder:
    """A registered dumper over the store on disk, its extra positional arguments built by parameter name."""
    extras = list(inspect.signature(dumper).parameters)[1:]

    def build(s: Store) -> Iterator[Call]:
        variants: list[list[str]] = [[]]
        for param in extras:
            variants = [v + [x] for v in variants for x in EXTRA_ARGS[param](s)]
        for extra in variants if s.thorough else variants[:1]:
            yield call(s.path, *extra, label=" ".join(extra))

    return build


def _main_calls(s: Store) -> list[Call]:
    """The CLI's dispatch and error mapping, once per store through the cheapest dumper; each dumper's own work is judged directly."""
    name = "header" if "header" in debug.DUMPERS else min(debug.DUMPERS)
    return [call([name, str(s.path)], label=name)]


EXTRA_ARGS: dict[str, Callable[[Store], list[str]]] = {
    "nid": lambda s: [f"{s.nids[0]:x}", "0x21", "zz", "0"],
}

_WIRE_RNG = random.Random(0x5054)  # a fixed sample of u16 property codes, the same every run
WIRE_CODES_CORE = sorted({*(int(t) for t in prop_type.PropType), 0, 0xFF, 0x1FFF, 0xFFFF})
WIRE_CODES = sorted({*WIRE_CODES_CORE, 0x100, 0x1000, 0x8000, *(_WIRE_RNG.randrange(1 << 16) for _ in range(48))})

ADAPTERS: dict[object, Builder] = {
    # pure functions over bytes
    crc.compute_crc: lambda s: [call(0, sl, label=f"[:{len(sl)}]") for sl in s.slices],
    encode.decode_permute: _slices(),
    encode.encode_permute: _slices(),
    encode.encode_decode_cyclic: lambda s: [call(sl, k, label=f"[:{len(sl)}] key={k}") for sl in s.slices for k in (0, 0xFFFFFFFF)],
    encode.decode_block: lambda s: [call(sl, m, 7, label=f"[:{len(sl)}] {m.name}") for sl in s.slices for m in encode.CryptMethod],
    rtf.read_header: _slices(),
    rtf.decompress_rtf: lambda s: [call(sl, max_output=s.limits.max_allocation, label=f"[:{len(sl)}]") for sl in s.slices],
    prop_type.decode: lambda s: [call(t, sl, max_items=s.limits.max_mv_items, label=f"{t:#06x} [:{len(sl)}]") for t in s.wire_codes for sl in s.slices[1:]]
    + [call(prop_type.PropType.STRING8, s.slices[2], codepage="no-such-codepage", label="bad codepage")],
    # wire integers
    prop_type.PropType.from_wire: lambda s: [call(v, label=f"{v:#06x}") for v in s.wire_codes],
    prop_type.filetime_to_datetime: lambda s: [call(v, label=f"{v:#x}") for v in (0, 1, 2**63 - 1, 2**64 - 1)],
    prop_type.fixed_size: lambda s: [call(t, label=t.name) for t in prop_type.PropType],
    prop_type.is_fixed_size: lambda s: [call(t, label=t.name) for t in prop_type.PropType],
    page.PageType.from_byte: lambda s: [call(v, label=f"{v:#04x}") for v in WIRE_BYTES],
    root.AmapStatus.from_byte: lambda s: [call(v, label=f"{v:#04x}") for v in WIRE_BYTES],
    root.AmapStatus.from_byte_lenient: lambda s: [call(v, label=f"{v:#04x}") for v in WIRE_BYTES],
    block.block_size: lambda s: [call(v, label=str(v)) for v in (0, 1, 8176, 8177, 2**32)],
    # records from a buffer
    header.Header.parse: lambda s: [call(s.data, label="whole"), call(s.data[: header.HEADER_SIZE - 1], label="short"), call(b"", label="empty")],
    root.Root.unpack_from: lambda s: [call(s.data, off, label=f"@{off}") for off in (ROOT_OFFSET, *_offsets(s, root.Root.SIZE))],
    ids.NodeId.unpack_from: _unpack_from(ids.NodeId.SIZE),
    ids.BlockId.unpack_from: _unpack_from(ids.BlockId.SIZE),
    ids.PageId.unpack_from: _unpack_from(ids.PageId.SIZE),
    ids.ByteIndex.unpack_from: _unpack_from(ids.ByteIndex.SIZE),
    ids.BlockRef.unpack_from: _unpack_from(ids.BlockRef.SIZE),
    ids.PageRef.unpack_from: _unpack_from(ids.PageRef.SIZE),
    block.BlockTrailer.unpack_from: _unpack_from(block.BlockTrailer.SIZE),
    block.SubNodeLeafEntry.unpack_from: _unpack_from(block.SubNodeLeafEntry.SIZE),
    block.SubNodeIntermediateEntry.unpack_from: _unpack_from(block.SubNodeIntermediateEntry.SIZE),
    page.PageTrailer.unpack_from: _per_page(lambda idx, buf: call(buf, label=str(idx))),
    page.PageTrailer.verify: _trailer_verify_calls,
    page.IntermediateEntry.unpack_from: _page_entries(page.IntermediateEntry.SIZE),
    page.BlockBTreeEntry.unpack_from: _page_entries(page.BlockBTreeEntry.SIZE),
    page.NodeBTreeEntry.unpack_from: _page_entries(page.NodeBTreeEntry.SIZE),
    page.BTreePage.parse: _per_page(
        lambda idx, buf: call(buf, page.PageType.NBT, idx, label=f"{idx} as NBT"),
        lambda idx, buf: call(buf, page.PageType.BBT, idx, label=f"{idx} as BBT"),
        lambda idx, buf: call(buf[:100], page.PageType.NBT, idx, label=f"{idx} short"),
    ),
    page.DensityListPage.parse: _per_page(lambda idx, buf: call(buf, idx, label=str(idx))),
    # a file
    header.read_header: lambda s: [call(s.f)],
    btree.read_density_list: lambda s: [call(s.f, s.limits)],
    btree.read_page: lambda s: [
        call(s.f, ByteIndex(i), s.limits, label=f"@{i:#x}") for i in (0, page.DENSITY_LIST_OFFSET, max(len(s.data) - PAGE, 0), len(s.data), 2**63 - PAGE, 2**64 - 1)
    ],
    # a file plus the parsed header: the readers and their walks
    btree.NodeBTree: lambda s: [call(s.f, s.header.root.node_btree, s.limits)],
    btree.BlockBTree: lambda s: [call(s.f, s.header.root.block_btree, s.limits)],
    btree.NodeBTree.__iter__: lambda s: [call(s.nbt)],
    btree.BlockBTree.__iter__: lambda s: [call(s.bbt)],
    btree.NodeBTree.pages: _tree_pages,
    btree.NodeBTree.find: lambda s: [call(s.nbt, k, label=f"{k:#x}") for k in s.nids] + [call(s.nbt, NodeId(s.nids[0]), label="NodeId")],
    btree.BlockBTree.find: lambda s: [call(s.bbt, k, label=f"{k:#x}") for k in s.bids] + [call(s.bbt, BlockId(s.bids[0]), label="BlockId")],
    block.BlockReader: lambda s: [call(s.f, s.header, s.bbt, s.limits)],
    block.BlockReader.find: lambda s: [call(s.reader, BlockId(k), label=f"{k:#x}") for k in s.bids],
    block.BlockReader.read_block: _read_block_calls,
    block.BlockReader.read_data_tree: lambda s: [call(s.reader, e.data, label=str(e.node)) for e in s.nbt_entries],
    block.BlockReader.read_data: lambda s: [call(s.reader, e.data, label=str(e.node)) for e in s.nbt_entries[:3]],
    block.BlockReader.read_data_blocks: lambda s: [call(s.reader, e.data, label=str(e.node)) for e in s.nbt_entries[:3]],
    block.BlockReader.node_data: lambda s: [call(s.reader, e, label=str(e.node)) for e in s.nbt_entries],
    block.BlockReader.node_data_blocks: lambda s: [call(s.reader, e, label=str(e.node)) for e in s.nbt_entries],
    block.BlockReader.read_subnode_block: lambda s: [call(s.reader, b, label=str(b)) for b in _subnode_roots(s)],
    block.BlockReader.read_subnode_tree: lambda s: [call(s.reader, b, label=str(b)) for b in _subnode_roots(s)],
    # the heap over a node, and the BTH over the heap (P04)
    heap.HeapNodeType.from_wire: lambda s: [call(v, label=f"{v:#04x}") for v in (*WIRE_BYTES, *heap.HeapNodeType)],  # bClientSig: the edges and all nine of 2.3.1.2
    heap.HeapId.unpack_from: _heap_records(HeapId.SIZE),
    heap.HeapNodeId.unpack_from: _heap_records(HeapNodeId.SIZE),
    heap.HeapNodeHeader.unpack_from: _heap_records(heap.HeapNodeHeader.SIZE),
    tree.HeapTreeHeader.unpack_from: _heap_records(tree.HeapTreeHeader.SIZE),
    heap.HeapNode: _heap_ctor_calls,
    heap.HeapNode.from_node: _from_node_calls,
    heap.HeapNode.block: lambda s: [call(h.heap, i, label=f"{h.label} block {i}") for h in s.heaps for i in _block_indices(h)],
    heap.HeapNode.page_map: lambda s: [call(h.heap, i, label=f"{h.label} page map {i}") for h in s.heaps for i in _block_indices(h)],
    heap.HeapNode.get: lambda s: [call(h.heap, hid, label=f"{h.label} {why}") for h in s.heaps for why, hid in _heap_ids(h)],
    heap.HeapNode.get_hnid: _hnid_calls,
    tree.HeapTree: _tree_ctor_calls,
    tree.HeapTree.__iter__: lambda s: [call(t, label=label) for label, t in s.trees],
    tree.HeapTree.entries: lambda s: [call(t, label=label) for label, t in s.trees],
    tree.HeapTree.find: _find_calls,
    # the property context over a heap, and the two formatters `pc` prints with (P05)
    prop_context.PropertyContext: lambda s: [call(h.heap, s.limits, label=h.label) for h in s.heaps],
    prop_context.PropertyContext.from_node: _context_from_node_calls,
    prop_context.PropertyContext.read: _pc_read_calls,
    prop_context.PropertyContext.get: _pc_get_calls,
    prop_context.PropertyContext.__iter__: lambda s: [call(pc, label=label) for label, pc in s.contexts],
    prop_context.PropertyRecord.unpack: _pc_unpack_calls,
    debug.format_property_value: _format_value_calls,
    debug.property_lines: _property_line_calls,
    # the table context over a heap, and the two formatters `tc` prints with (P06)
    table_context.existence_bitmap_size: lambda s: [call(v, label=str(v)) for v in (0, 1, 8, 9, 255, 256, 2**32, -1)],
    table_context.check_existence_bitmap: _existence_bitmap_calls,
    table_context.TableContextInfo.unpack: _tcinfo_calls,
    # P06b: the row-header-size check, deferred from `unpack` to `TableContext._read_matrix` —
    # exercised over every real table's own TCINFO, matrix rows or none.
    table_context.TableContextInfo.check_row_header_fits: lambda s: [call(tc.info, label=label) for label, tc in s.tables],
    table_context.ColumnDescriptor.unpack_from: _tcoldesc_calls,
    table_context.TableContext: lambda s: [call(h.heap, s.limits, label=h.label) for h in s.heaps],
    table_context.TableContext.from_node: _context_from_node_calls,
    table_context.TableContext.row: _tc_row_calls,
    table_context.TableContext.rows: lambda s: [call(tc, label=label) for label, tc in s.tables],
    table_context.TableContext.__iter__: lambda s: [call(tc, label=label) for label, tc in s.tables],
    table_context.TableContext.find_row: _tc_find_row_calls,
    table_context.TableContext.read_cell: _tc_read_cell_calls,
    table_context.TableRow.get: _table_row_get_calls,
    heap.HeapNode.get_hnid_blocks: _hnid_calls,  # the same HNIDs as get_hnid: a heap item, a sub-node, one no tree holds
    debug.format_cell_record: _cell_record_calls,
    debug.cell_lines: _cell_line_calls,
    # the message store and the named property map over it (P07)
    messaging.Store: _store_ctor_calls,
    messaging.Store.open: _store_open_calls,
    messaging.open_store: _store_open_calls,
    messaging.Store.close: _store_close_calls,
    messaging.Store.entry_id: _store_entry_id_calls,
    messaging.Store.matches_record_key: _store_matches_calls,
    messaging.Store.get: _store_get_calls,
    messaging.EntryId.unpack_from: _entry_id_unpack_calls,
    named_prop.NameIdEntry.unpack_from: _name_id_unpack_calls,
    named_prop.NamedPropertyGuid.from_wire: lambda s: [call(v, label=f"{v:#x}") for v in NAMED_GUID_CODES],
    named_prop.NamedPropertyMap: _named_map_ctor_calls,
    named_prop.NamedPropertyMap.from_node: _named_map_from_node_calls,
    named_prop.NamedPropertyMap.lookup: _named_lookup_calls,
    named_prop.NamedPropertyMap.resolve: _named_resolve_calls,
    named_prop.NamedPropertyMap.guid_of: _named_entry_calls,
    named_prop.NamedPropertyMap.name_of: _named_entry_calls,
    named_prop.NamedPropertyMap.hash_bucket: _named_entry_calls,
    named_prop.NamedPropertyMap.hash_entry: _named_entry_calls,
    named_prop.NamedPropertyMap.lookup_string: _named_string_calls,
    named_prop.NamedPropertyMap.string_bytes: _named_string_calls,
    # the folder tree over the store (P08)
    messaging.Store.open_folder: _open_folder_calls,
    folder_mod.Folder: _folder_ctor_calls,
    folder_mod.Folder.open: _folder_open_calls,
    folder_mod.Folder.get: _folder_get_calls,
    folder_mod.Folder.table: _folder_table_calls,
    folder_mod.Folder.subfolder_ids: _folder_calls,
    folder_mod.Folder.message_ids: _folder_calls,
    folder_mod.Folder.associated_ids: _folder_calls,
    folder_mod.Folder.contents: _folder_calls,
    folder_mod.Folder.subfolders: _folder_calls,
    folder_mod.Folder.walk: _folder_walk_calls,
    folder_mod.Folder.messages: _folder_calls,
    folder_mod.Folder.associated: _folder_calls,
    # messages, recipients and attachments (P09)
    messaging.Store.open_message: _open_message_calls,
    message_mod.Message: _message_ctor_calls,
    message_mod.Message.open: _message_open_calls,
    message_mod.Message.get: _message_get_calls,
    message_mod.Message.sub_node_table: _message_table_calls,
    message_mod.Message.sub_node_entry: _message_sub_node_calls,
    message_mod.Message.recipients: _message_calls,
    message_mod.Message.attachment_ids: _message_calls,
    message_mod.Message.attachments: _message_calls,
    message_mod.Message.body_rtf_decompressed: _message_calls,
    message_mod.Message.check_embedded_depth: _message_calls,
    message_mod.Recipient.get: _recipient_get_calls,
    message_mod.split_subject: _split_subject_calls,
    attachment_mod.Attachment: _attachment_ctor_calls,
    attachment_mod.Attachment.get: _attachment_get_calls,
    attachment_mod.Attachment.sub_node_entry: _attachment_sub_node_calls,
    attachment_mod.Attachment.data: _attachment_calls,
    attachment_mod.Attachment.embedded_message: _attachment_calls,
    AttachMethod.from_wire: _attach_method_calls,
    debug.upstream_records: _debug_upstream_records_calls,
    debug.message_lines: _debug_message_lines_calls,
    debug.message_accessor: _debug_message_accessor_calls,
    debug.attachment_accessor: _debug_attachment_accessor_calls,
    debug.folder_lines: _debug_folder_calls,
    debug.folder_table: _folder_table_calls,
    debug.folder_accessor: _debug_folder_accessor_calls,
    # the CLI's dispatch, and every registered dumper, in-process
    debug.main: _main_calls,
    **{dumper: _dumper_calls(dumper) for dumper in debug.DUMPERS.values()},
}

# Adapters whose arguments never derive from the store: the fixture lanes run
# them, the corruption lane (`thorough=False`) skips them — a mutation cannot
# change what they are called with.
STORE_FREE: frozenset[object] = frozenset(
    {
        prop_type.PropType.from_wire,
        prop_type.filetime_to_datetime,
        prop_type.fixed_size,
        prop_type.is_fixed_size,
        page.PageType.from_byte,
        root.AmapStatus.from_byte,
        root.AmapStatus.from_byte_lenient,
        block.block_size,
        heap.HeapNodeType.from_wire,
        table_context.existence_bitmap_size,
        named_prop.NamedPropertyGuid.from_wire,
    }
)

NOT_STORE_INPUT: dict[object, str] = {
    limits.VisitedSet: "a walk's own bookkeeping; its keys come from the walk, not the file",
    limits.VisitedSet.add: "as VisitedSet",
    limits.check_depth: "caller-side check; both arguments are the reader's own numbers",
    limits.check_count: "as check_depth",
    limits.check_allocation: "as check_depth",
    block_sig.compute_sig: "[MS-PST] 5.5 arithmetic over two ints; total",
    page.PageType.signature: "as compute_sig",
    page.PageTrailer.expected_signature: "as compute_sig",
    block.BlockTrailer.expected_signature: "as compute_sig",
    block.BlockTrailer.verify_block_id: "reached through BlockReader.read_block on every block",
    block.BlockTrailer.verify_crc: "as verify_block_id",
    ids.NodeIdType.from_debug_name: "golden-parser helper over a str upstream printed",
    prop_type.PropType.from_debug_name: "as NodeIdType.from_debug_name",
    ids.NodeId.from_parts: "typed parts, checked by the dataclass",
    ids.BlockId.from_parts: "as NodeId.from_parts",
    ids.NodeId.pack: "serialises a checked value",
    ids.BlockId.pack: "as NodeId.pack",
    ids.PageId.pack: "as NodeId.pack",
    ids.ByteIndex.pack: "as NodeId.pack",
    ids.BlockRef.pack: "as NodeId.pack",
    ids.PageRef.pack: "as NodeId.pack",
    prop_type.datetime_to_filetime: "takes a datetime the caller made",
    heap.HeapId.from_parts: "typed parts, checked by the dataclass; as NodeId.from_parts",
    heap.HeapId.pack: "as NodeId.pack",
    heap.HeapNodeId.pack: "as NodeId.pack",
    heap.HeapPageMap.size: "span arithmetic over offsets the page map already checked, at an index its caller range-checked",
    messaging.EntryId.pack: "serialises a checked value; as NodeId.pack",
}


def _auto_excluded(ep: EntryPoint) -> str | None:
    """The three rules that exclude a class without a table entry — see the module docstring."""
    obj = ep.obj
    if inspect.isclass(obj):
        if issubclass(obj, BaseException):
            return "exception type"
        if issubclass(obj, enum.Enum):
            return "enum type; its wire classmethods are entry points"
        if dataclasses.is_dataclass(obj):
            return "dataclass over parsed values; its classmethods are entry points"
    return None


def coverage() -> dict[str, str]:
    """Entry point name → how it is covered: 'adapter', 'excluded: <reason>', or 'UNCOVERED'."""
    out: dict[str, str] = {}
    adapted = {_key(k) for k in ADAPTERS}
    excluded = {_key(k): why for k, why in NOT_STORE_INPUT.items()}
    for ep in entry_points():
        key = _key(ep.obj)
        if key in adapted:
            out[ep.name] = "adapter"
        elif key in excluded:
            out[ep.name] = f"excluded: {excluded[key]}"
        elif (why := _auto_excluded(ep)) is not None:
            out[ep.name] = f"excluded: {why}"
        else:
            out[ep.name] = "UNCOVERED"
    return out


def uncovered() -> list[str]:
    """Public callables with neither an adapter nor a reason. Must be empty."""
    return [name for name, how in coverage().items() if how == "UNCOVERED"]


def stale() -> list[str]:
    """Table entries that no discovered entry point matches — a renamed or de-exported name."""
    known = {_key(ep.obj) for ep in entry_points()}
    return [_name(k) for k in (*ADAPTERS, *NOT_STORE_INPUT) if _key(k) not in known]


def _name(obj: object) -> str:
    fn = obj.__func__ if inspect.ismethod(obj) else obj
    return f"{getattr(fn, '__module__', '?')}.{getattr(fn, '__qualname__', repr(fn))}"


# --- judgement ----------------------------------------------------------------------


class Result(enum.Enum):
    OK = "OK"
    PST_ERROR = "PST_ERROR"
    LEAK = "LEAK"
    HANG = "HANG"
    SKIP = "SKIP"


@dataclass(frozen=True, slots=True)
class Outcome:
    """One call's result. `error` is the exception for PST_ERROR/LEAK; `where` the innermost frame for a LEAK."""

    entry_point: str
    label: str
    kind: Result
    error: BaseException | None = None
    where: str = ""
    seconds: float = 0.0

    @property
    def error_type(self) -> str:
        return type(self.error).__name__ if self.error is not None else ""

    def __str__(self) -> str:
        tag = f"{self.entry_point}[{self.label}]" if self.label else self.entry_point
        if self.kind is Result.OK:
            return f"OK    {tag}"
        if self.kind is Result.SKIP:
            return f"SKIP  {tag} ({self.where})"
        msg = f"{self.error_type}: {self.error!s:.120}" if self.error is not None else ""
        return f"{self.kind.value:5} {tag} {self.where} {msg}".rstrip()


def _innermost(exc: BaseException) -> str:
    frames = traceback.extract_tb(exc.__traceback__)
    if not frames:
        return ""
    f = frames[-1]
    return f"{Path(f.filename).name}:{f.lineno} in {f.name}"


def judge(fn: Callable[..., object], c: Call, name: str | None = None, watchdog: Watchdog | None = None) -> Outcome:
    """Run `fn(*c.args, **c.kwargs)` and say what came out; under `watchdog`, a timeout is HANG. Never raises."""
    name = name or _name(fn)
    if watchdog is None:
        return _attempt(fn, c, name)
    try:
        return watchdog.run(lambda: _attempt(fn, c, name))  # type: ignore[arg-type, return-value]
    except Hang as hang:
        return Outcome(name, c.label, Result.HANG, where=str(hang))


def _attempt(fn: Callable[..., object], c: Call, name: str) -> Outcome:
    start = time.perf_counter()
    try:
        result = fn(*c.args, **c.kwargs)
        if hasattr(result, "__next__"):  # a generator or iterator: the walk is the call
            for _ in result:  # type: ignore[attr-defined]
                pass
    except PstError as exc:
        return Outcome(name, c.label, Result.PST_ERROR, exc, seconds=time.perf_counter() - start)
    except Exception as exc:  # noqa: BLE001 — classifying, not handling, is the point
        return Outcome(name, c.label, Result.LEAK, exc, _innermost(exc), time.perf_counter() - start)
    return Outcome(name, c.label, Result.OK, seconds=time.perf_counter() - start)


class _Sink(io.StringIO):
    """Where the dumpers print. Bounded: a dumper over a corrupt store must not fill memory with output."""

    LIMIT = 1 << 22

    def write(self, s: str) -> int:
        if self.tell() < self.LIMIT:
            return super().write(s)
        return len(s)


def _run_all(store: Store, eps: list[EntryPoint], progress: list[object]) -> list[Outcome]:
    outcomes: list[Outcome] = []
    adapters = {_key(k): v for k, v in ADAPTERS.items()}
    store_free = {_key(k) for k in STORE_FREE}
    with contextlib.redirect_stdout(_Sink()), contextlib.redirect_stderr(_Sink()):
        for ep in eps:
            key = _key(ep.obj)
            builder = adapters.get(key)
            if builder is None or (not store.thorough and key in store_free):
                continue
            progress[0] = ep.name
            try:
                calls = list(builder(store))
            except (Unreachable, PstError) as why:
                # A prerequisite refused the store (a builder may itself parse a
                # record to hand on); the refusal is judged where it happened.
                outcomes.append(Outcome(ep.name, "", Result.SKIP, where=f"{type(why).__name__}: {why!s:.80}"))
                continue
            for c in calls:
                progress[0] = (ep.name, c.label)
                outcomes.append(judge(ep.obj, c, ep.name))
    return outcomes


def sweep(
    data: bytes,
    *,
    limits: Limits = DEFAULT_LIMITS,
    watchdog: Watchdog | None = None,
    workdir: Path | None = None,
    entry_points_: list[EntryPoint] | None = None,
    thorough: bool = True,
) -> list[Outcome]:
    """Every adapter over one store, under the watchdog. Never raises; a hang is an outcome naming its entry point.

    `thorough=False` narrows each adapter's argument set (`Store.thorough`), never the entry points.
    """
    eps = entry_points_ if entry_points_ is not None else entry_points()
    store = Store(data, limits, workdir, thorough=thorough)
    own = watchdog is None
    watchdog = watchdog or Watchdog(DEFAULT_TIMEOUT)
    progress: list[object] = [""]
    collected: list[Outcome] = []

    def run() -> list[Outcome]:
        collected.extend(_run_all(store, eps, progress))
        return collected

    try:
        return watchdog.run(run)  # type: ignore[return-value]
    except Hang as hang:
        name, label = progress[0] if isinstance(progress[0], tuple) else (str(progress[0]), "")
        return [*collected, Outcome(name, label, Result.HANG, where=str(hang))]
    finally:
        store.close()
        if own:
            watchdog.close()


def problems(outcomes: list[Outcome]) -> list[str]:
    """The contract violations in `outcomes`, one line each: every LEAK and every HANG. Empty means clean."""
    return [str(o) for o in outcomes if o.kind in (Result.LEAK, Result.HANG)]


def summary(outcomes: list[Outcome]) -> dict[str, dict[str, int]]:
    """entry point → {outcome or exception type → count}, for the table a test prints under `-s`."""
    table: dict[str, dict[str, int]] = {}
    for o in outcomes:
        row = table.setdefault(o.entry_point, {})
        key = o.error_type if o.kind is Result.PST_ERROR else o.kind.value
        row[key] = row.get(key, 0) + 1
    return table
