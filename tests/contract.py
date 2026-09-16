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
B-trees, a `BlockReader`, the NBT and BBT entries, a handful of pages, a
temp file for the dumpers), yields the argument tuples to call it with.
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
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import pypst
from pypst import block_sig, crc, debug, encode, limits, rtf
from pypst.errors import PstError
from pypst.limits import DEFAULT_LIMITS, Limits
from pypst.ltp import prop_type
from pypst.ndb import block, btree, header, ids, page, root
from pypst.ndb.ids import BlockId, ByteIndex, NodeId
from tests.corruption_harness import DEFAULT_TIMEOUT, Hang, Watchdog

# --- discovery ---------------------------------------------------------------------

Kind = str  # "bytes" | "file" | "reader" | "path" | "wire" | "method" | "other"

# A parameter annotated with one of these (as text: the package uses
# `from __future__ import annotations`) marks a callable as needing a parsed
# store — the `reader` kind. Extend it when a new layer's reader class takes
# a new kind of parsed argument.
READER_TYPES = ("Header", "Root", "PageRef", "BlockBTree", "NodeBTree", "BlockReader", "NodeBTreeEntry", "BlockBTreeEntry")
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
    block.BlockReader.node_data: lambda s: [call(s.reader, e, label=str(e.node)) for e in s.nbt_entries],
    block.BlockReader.read_subnode_block: lambda s: [call(s.reader, b, label=str(b)) for b in _subnode_roots(s)],
    block.BlockReader.read_subnode_tree: lambda s: [call(s.reader, b, label=str(b)) for b in _subnode_roots(s)],
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
    ids.NodeId.from_parts: "typed parts, checked by the dataclass",
    ids.BlockId.from_parts: "as NodeId.from_parts",
    ids.NodeId.pack: "serialises a checked value",
    ids.BlockId.pack: "as NodeId.pack",
    ids.PageId.pack: "as NodeId.pack",
    ids.ByteIndex.pack: "as NodeId.pack",
    ids.BlockRef.pack: "as NodeId.pack",
    ids.PageRef.pack: "as NodeId.pack",
    prop_type.datetime_to_filetime: "takes a datetime the caller made",
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
