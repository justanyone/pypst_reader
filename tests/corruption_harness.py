"""Run the landed entry points over one corrupt store and judge what came out.

Shared by `tests/test_corruption.py` (the per-family sweep in the suite) and
`scripts/fuzz_sweep.py` (many seeds, every fixture, on demand), so that the
two cannot disagree about what "leak" means:

- a return value is fine;
- a `PstError` is fine, and when the mutation says `expect`, it must be an
  instance of it;
- anything else that escapes — `struct.error`, `IndexError`, `KeyError`,
  `ValueError`, `MemoryError`, `RecursionError`, `OverflowError`,
  `UnicodeDecodeError`, `AssertionError`, … — is a LEAK, named with the
  mutation and the exception type;
- a call that does not return within the watchdog's deadline is a HANG.

The entry points here are the ones that exist today (header, the two
B-tree walks and lookups, the density list). Each later layer adds its
calls to `exercise` in its own row; the contract harness (P24) is the
generic version over `pypst.__all__`.

**The watchdog leaks a thread on a genuine hang.** Python has no portable
way to interrupt a thread that is spinning in pure Python, and
`signal.alarm` is neither portable nor usable off the main thread. So the
call runs on a worker thread and the test waits with a deadline; on a
timeout the worker is abandoned (the executor is shut down without
waiting) and the test fails. That is acceptable because a hang IS the bug
this suite hunts: the process is about to report it and exit. It does mean
a hung sweep may not end promptly at interpreter exit; that is the cost of
detecting it at all.
"""

from __future__ import annotations

import concurrent.futures
import io
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from pypst.errors import PstError
from pypst.limits import DEFAULT_LIMITS, Limits
from pypst.ltp.heap import HeapNode, HeapNodeId
from pypst.ltp.tree import HeapTree
from pypst.ndb.block import BlockReader
from pypst.ndb.btree import BlockBTree, NodeBTree, read_density_list
from pypst.ndb.header import Header, read_header
from pypst.ndb.ids import ByteIndex, NodeId, PageId, PageRef
from tests import corrupt

DEFAULT_TIMEOUT = 5.0


@dataclass(frozen=True, slots=True)
class BaseShape:
    """What the harness knows about the UNMUTATED store: where its trees start and one key in each.

    Read raw from the base's bytes (not through `read_header`), so that the
    harness can still aim at the right pages when the mutation has broken
    the header.
    """

    nbt_root: PageRef
    bbt_root: PageRef
    nid: int  # a NID the base's NBT holds
    bid: int  # a BID search key the base's BBT holds
    # Entry points that already raise on the UNMUTATED base, and what they
    # raise (pstd-inline-cid has no density list page, so `read_density_list`
    # is a PstFormatError before any mutation). A mutation's `expect` is not
    # held against a failure the base already had.
    baseline: dict[str, type[BaseException]] = field(default_factory=dict)

    @classmethod
    def of(cls, base: bytes) -> BaseShape:
        (nbt_id, nbt), (bbt_id, bbt) = corrupt.root_refs(base)
        bbt_leaf = corrupt.leaf_page(base, bbt)
        (bid,) = struct.unpack_from("<Q", base, bbt_leaf)
        shape = cls(
            nbt_root=PageRef(PageId(nbt_id), ByteIndex(nbt)),
            bbt_root=PageRef(PageId(bbt_id), ByteIndex(bbt)),
            nid=corrupt.first_leaf_key(base, nbt),
            bid=bid & ~0x1,  # the search key clears the reserved bit
        )
        baseline = {o.entry_point: type(o.error) for o in exercise(base, shape) if o.error is not None}
        leaks = [f"{name} -> {kind.__name__}" for name, kind in baseline.items() if not issubclass(kind, PstError)]
        if leaks:
            raise ValueError(f"the base store itself leaks: {', '.join(leaks)}; not a usable base")
        return replace(shape, baseline=baseline)


@dataclass(frozen=True, slots=True)
class Outcome:
    """One entry point's result over one mutation: returned, or raised `error`."""

    entry_point: str
    error: BaseException | None = None
    seconds: float = 0.0

    @property
    def returned(self) -> bool:
        return self.error is None


def _attempt(name: str, fn: Callable[[], object]) -> Outcome:
    start = time.perf_counter()
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 — classifying, not handling, is the point
        return Outcome(name, exc, time.perf_counter() - start)
    return Outcome(name, None, time.perf_counter() - start)


def exercise(data: bytes, shape: BaseShape, limits: Limits = DEFAULT_LIMITS) -> list[Outcome]:
    """Every landed entry point over `data`. Never raises: each call's result is an `Outcome`."""
    f = io.BytesIO(data)
    outcomes: list[Outcome] = []
    header = _attempt("read_header", lambda: read_header(f))
    outcomes.append(header)

    def trees(tag: str, nbt_root: PageRef, bbt_root: PageRef) -> None:
        nbt = NodeBTree(f, nbt_root, limits)
        bbt = BlockBTree(f, bbt_root, limits)
        outcomes.append(_attempt(f"nbt.iter[{tag}]", lambda: list(nbt)))
        outcomes.append(_attempt(f"nbt.find[{tag}]", lambda: nbt.find(shape.nid)))
        outcomes.append(_attempt(f"bbt.iter[{tag}]", lambda: list(bbt)))
        outcomes.append(_attempt(f"bbt.find[{tag}]", lambda: bbt.find(shape.bid)))

    trees("base", shape.nbt_root, shape.bbt_root)
    if header.returned:
        # The roots the mutated header names, when they differ from the base's:
        # a lie in the ROOT is only reachable this way.
        parsed = read_header(f).root
        if (parsed.node_btree, parsed.block_btree) != (shape.nbt_root, shape.bbt_root):
            trees("header", parsed.node_btree, parsed.block_btree)
    outcomes.append(_attempt("read_density_list", lambda: read_density_list(f, limits)))
    if header.returned:
        # P04: the message store's property context as a heap and a BTH,
        # every record's heap HNID resolved — through the roots this
        # file's own header names.
        outcomes.append(_attempt("heap.store_pc", lambda: walk_store_pc(f, read_header(f), limits)))
    return outcomes


# Property types whose PC record value is always an HNID ([MS-PST] 2.3.3.3:
# fixed types wider than 4 bytes, and every variable-size type).
_HNID_TYPES = frozenset({0x0005, 0x0006, 0x0007, 0x000D, 0x0014, 0x0040, 0x0048, 0x001E, 0x001F, 0x0102})


def walk_store_pc(f: io.BytesIO, header: Header, limits: Limits) -> int:
    """Open NID 0x21 as a heap, walk its BTH, resolve every HNID-bearing record; the count of records."""
    bbt = BlockBTree(f, header.root.block_btree, limits)
    entry = NodeBTree(f, header.root.node_btree, limits).find(NodeId(0x21))
    heap = HeapNode.from_node(BlockReader(f, header, bbt, limits), entry)
    count = 0
    for _key, value in HeapTree(heap):
        (prop_type,) = struct.unpack_from("<H", value, 0)
        hnid = HeapNodeId.unpack_from(value, 2)
        if (prop_type in _HNID_TYPES or prop_type & 0x1000) and hnid.raw != 0:
            heap.get_hnid(hnid)
        count += 1
    return count


class Hang(Exception):
    """The call outlived the watchdog. The worker thread has been abandoned (module docstring)."""


class Watchdog:
    """Run callables on a worker thread with a deadline; see the module docstring for the cost."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout
        self.hung = False
        self._executor = self._new_executor()

    @staticmethod
    def _new_executor() -> concurrent.futures.ThreadPoolExecutor:
        return concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="pypst-fuzz")

    def run(self, fn: Callable[[], list[Outcome]]) -> list[Outcome]:
        if self.hung:
            # The previous worker is stuck for good; a fresh one for the next call.
            self._executor = self._new_executor()
            self.hung = False
        future = self._executor.submit(fn)
        try:
            return future.result(timeout=self.timeout)
        except concurrent.futures.TimeoutError:
            self.hung = True
            self._executor.shutdown(wait=False)
            raise Hang(f"no result within {self.timeout}s") from None

    def close(self) -> None:
        self._executor.shutdown(wait=not self.hung)


def problems(mutation: corrupt.Mutation, outcomes: list[Outcome], shape: BaseShape) -> list[str]:
    """Every way `outcomes` violates the contract for `mutation`, as one line each. Empty means clean."""
    found: list[str] = []
    refused = False
    for outcome in outcomes:
        exc = outcome.error
        if exc is None:
            continue
        kind = type(exc).__name__
        if not isinstance(exc, PstError):
            found.append(f"LEAK  {mutation.name} :: {outcome.entry_point} raised {kind}: {exc!s:.120}")
        elif shape.baseline.get(outcome.entry_point) is type(exc):
            continue  # the base fails here the same way; the mutation changed nothing
        elif mutation.expect is not None and not isinstance(exc, mutation.expect):
            expected = (mutation.expect,) if isinstance(mutation.expect, type) else mutation.expect
            wanted = "|".join(t.__name__ for t in expected)
            found.append(f"TYPE  {mutation.name} :: {outcome.entry_point} raised {kind}, expected {wanted}: {exc!s:.120}")
        else:
            refused = True
    if mutation.must_raise and not refused:
        found.append(f"SILENT {mutation.name} :: no entry point refused it ({len(outcomes)} calls returned)")
    return found


@dataclass(frozen=True, slots=True)
class Verdict:
    """The sweep's record of one mutation."""

    name: str
    family: str
    outcomes: list[Outcome]
    problems: list[str]
    seconds: float

    @property
    def clean(self) -> bool:
        return not self.problems


def judge(mutation: corrupt.Mutation, shape: BaseShape, watchdog: Watchdog, limits: Limits = DEFAULT_LIMITS) -> Verdict:
    """Exercise one mutation under the watchdog and classify the result. Never raises."""
    family = mutation.name.split(":", 1)[0]
    start = time.perf_counter()
    try:
        outcomes = watchdog.run(lambda: exercise(mutation.data, shape, limits))
    except Hang as hang:
        return Verdict(mutation.name, family, [], [f"HANG  {mutation.name} :: {hang}"], time.perf_counter() - start)
    return Verdict(mutation.name, family, outcomes, problems(mutation, outcomes, shape), time.perf_counter() - start)
