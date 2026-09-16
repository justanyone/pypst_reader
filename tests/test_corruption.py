"""The corruption sweep (T4) and the named denial cases nobody else wrote.

Every mutation `tests/corrupt.py` generates is pushed through every landed
entry point (`tests/corruption_harness.py`), and the only acceptable
outcomes are a result or a `PstError` of the expected kind. A `struct.error`,
`IndexError`, `KeyError`, `ValueError`, `MemoryError`, `RecursionError`,
`OverflowError`, `UnicodeDecodeError` or `AssertionError` escaping is a
failure that names the mutation and the exception; so is a hang.

One test per (base store, family) rather than one per mutation: the
mutations of a 265 KB base are generated lazily inside the test, so the
suite never holds hundreds of copies of it at collection time, and a
failure still names every offending mutation. To reproduce one:

    corrupt.mutation(base_bytes, seed=SEED, name="field_lies:header.wVer=0")

The specific cases P01 and P02 already wrote (a bad CRC, a `wVer` from
the future, the NBT root that points at itself, a child past EOF) live in
tests/test_header.py and tests/test_btree.py and are not repeated; the
families here reach the same refusals systematically and pin the exact
type through `Mutation.expect`.

The `test_p03_*` stubs skip until `pypst.ndb.block` import; when they do,
the skip inside each names the mutation to build (the `P03 landed?` note in
tests/corrupt.py lists the builders that row adds). The `test_p04_*` cases
are live: P04 added the heap builders and the `heap_lies` family.
"""

from __future__ import annotations

import io
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from pypst.errors import PstFormatError, PstLimitError
from pypst.limits import DEFAULT_LIMITS
from pypst.ndb.btree import BlockBTree, NodeBTree
from pypst.ndb.header import Header, read_header
from tests import corrupt
from tests.conftest import FIXTURES, PUBLIC, REPO
from tests.corruption_harness import BaseShape, Verdict, Watchdog, exercise, judge

SEED = 20260915
TIMEOUT = 5.0

# Pinned here, in the consumer, so that a family dropped from the generator
# is a red test rather than a smaller number nobody reads.
EXPECTED_FAMILIES = (
    "truncations",
    "bit_flips",
    "field_lies",
    "pointer_cycles",
    "depth_bombs",
    "future_versions",
    "zero_files",
    "magic_only",
    "heap_lies",
)

# The smallest populated corpus store first (the default base), then
# Microsoft's own empty one, whose trees have intermediate pages.
BASES = [PUBLIC / "pstd-inline-cid.pst", FIXTURES / "Empty.pst"]
BASE_IDS = [p.stem for p in BASES]

_BASE_CACHE: dict[Path, tuple[bytes, BaseShape]] = {}


def _base(path: Path) -> tuple[bytes, BaseShape]:
    if path not in _BASE_CACHE:
        data = path.read_bytes()
        _BASE_CACHE[path] = (data, BaseShape.of(data))
    return _BASE_CACHE[path]


def _sweep(path: Path, family: corrupt.Family) -> list[Verdict]:
    base, shape = _base(path)
    watchdog = Watchdog(TIMEOUT)
    try:
        return [judge(m, shape, watchdog) for m in family(base, corrupt.family_rng(SEED, family))]
    finally:
        watchdog.close()


# --- the sweep ----------------------------------------------------------------------


@pytest.mark.parametrize("family", corrupt.FAMILIES, ids=corrupt.family_names())
@pytest.mark.parametrize("path", BASES, ids=BASE_IDS)
def test_family_never_leaks(path: Path, family: corrupt.Family) -> None:
    verdicts = _sweep(path, family)
    assert verdicts, f"{family.__name__} produced no mutations over {path.name}"
    failures = [line for v in verdicts if not v.clean for line in v.problems]
    assert not failures, f"{len(failures)} problem(s) in {family.__name__} over {path.name}:\n" + "\n".join(failures)


@pytest.mark.parametrize("path", BASES, ids=BASE_IDS)
def test_sweep_summary(path: Path) -> None:
    """Count what ran, per family, and print it (`-s`): a family that silently vanishes is caught here too."""
    base, _ = _base(path)
    counts = Counter(m.name.split(":", 1)[0] for m in corrupt.mutations(base, seed=SEED))
    print(f"\n{path.name}: {sum(counts.values())} mutations")
    for family in corrupt.family_names():
        print(f"  {family:16} {counts[family]:4}")
    assert tuple(corrupt.family_names()) == EXPECTED_FAMILIES
    assert set(counts) == set(EXPECTED_FAMILIES)
    assert all(counts[f] > 0 for f in EXPECTED_FAMILIES)


# --- named cases not in test_header.py / test_btree.py -------------------------------


def test_magic_and_then_nothing_is_a_format_error() -> None:
    """`!BDN` and the file ends: refused as short, exactly `PstFormatError`, before any field is read."""
    with pytest.raises(PstFormatError) as info:
        Header.parse(b"!BDN")
    assert type(info.value) is PstFormatError
    with pytest.raises(PstFormatError) as info:
        read_header(io.BytesIO(b"!BDN"))
    assert type(info.value) is PstFormatError


@pytest.mark.parametrize("tree", ["node_btree", "block_btree"])
@pytest.mark.parametrize("path", BASES, ids=BASE_IDS)
def test_root_byte_index_past_eof_in_the_header(path: Path, tree: str) -> None:
    """The header's ROOT names a root page beyond the file: the header parses, the walk is a format error.

    test_btree.py builds the bad `PageRef` by hand; here it arrives the way
    it would from a real file — through `read_header` — and both the walk
    and the lookup refuse it with exactly `PstFormatError`.
    """
    base, shape = _base(path)
    field = next(f for f in corrupt.header_fields() if f.name == ("BREFNBT.ib" if tree == "node_btree" else "BREFBBT.ib"))
    data = corrupt.reseal_header(field.write(base, len(base) + 0x1000))
    f = io.BytesIO(data)
    header = read_header(f)
    ref = getattr(header.root, tree)
    assert ref.index.value == len(base) + 0x1000
    walker = (NodeBTree if tree == "node_btree" else BlockBTree)(f, ref, DEFAULT_LIMITS)
    with pytest.raises(PstFormatError) as info:
        list(walker)
    assert type(info.value) is PstFormatError
    with pytest.raises(PstFormatError) as info:
        walker.find(shape.nid if tree == "node_btree" else shape.bid)
    assert type(info.value) is PstFormatError


# --- the slow path: many seeds, every fixture, through the script --------------------


@pytest.mark.slow
def test_fuzz_sweep_script_three_seeds() -> None:
    """`scripts/fuzz_sweep.py --seeds 3` over every Unicode fixture exits 0 and reports each family."""
    script = REPO / "scripts" / "fuzz_sweep.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--seeds", "3"], capture_output=True, text=True, check=False, cwd=REPO, timeout=1800
    )
    assert proc.returncode == 0, f"exit {proc.returncode}\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}"
    for family in corrupt.family_names():
        assert family in proc.stdout, f"{family} missing from the sweep table:\n{proc.stdout}"
    assert "LEAK" not in proc.stdout and "HANG" not in proc.stdout


# --- stubs for the layers that do not exist yet ---------------------------------------
#
# Each skips until its module imports, then skips again naming the mutation
# to build, so that the row landing the module sees exactly one task here
# and this row never edits that row's builders.


def _p03() -> None:
    pytest.importorskip("pypst.ndb.block")


def test_p03_leaf_entry_data_block_past_eof() -> None:
    _p03()
    pytest.skip("P03 landed: rewrite a leaf BBTENTRY's BREF.ib past EOF (reseal the page); BlockReader.read_block → PstFormatError")


def test_p03_block_size_larger_than_the_file() -> None:
    _p03()
    pytest.skip("P03 landed: a BBTENTRY `cb` larger than the file, and a block trailer `cb` that disagrees; → PstFormatError")


def test_p03_xxblock_ten_thousand_deep() -> None:
    _p03()
    pytest.skip("P03 landed: an XXBLOCK chain 10,000 deep via corrupt.xblock/file_with_blocks; read_data → PstLimitError, no RecursionError")


def test_p03_lcb_total_four_gigabytes() -> None:
    _p03()
    pytest.skip("P03 landed: an XBLOCK claiming lcbTotal = 4 GB in a 29 KB file; → PstLimitError before any allocation")


def test_p03_subnode_tree_cycle() -> None:
    _p03()
    pytest.skip("P03 landed: an SIBLOCK naming its own block via corrupt.siblock; read_subnode_tree → PstLimitError")


def test_p04_bth_cycle() -> None:
    """A BTH with one index level whose only record names the root page itself: iteration is a cycle, not a hang."""
    from pypst.ltp.heap import HeapNode
    from pypst.ltp.tree import HeapTree

    root = corrupt.hid(2)
    heap = HeapNode([corrupt.heap_node([corrupt.bth_header(2, 6, levels=1, root=root), corrupt.bth_index([(b"\x01\x00", root)])])])
    with pytest.raises(PstLimitError, match="cycle"):
        list(HeapTree(heap))
    # The same lie in a real store's message-store PC, through the family.
    base = (PUBLIC / "pstd-inline-cid.pst").read_bytes()
    m = corrupt.mutation(base, seed=SEED, name="heap_lies:bth.root_cycle")
    outcomes = exercise(m.data, BaseShape.of(base))
    assert any(o.entry_point == "heap.store_pc" and isinstance(o.error, PstLimitError) for o in outcomes)


def test_p04_heap_index_past_the_block() -> None:
    """An HID whose item index exceeds the block's cAlloc, and one whose block index exceeds the block count."""
    from pypst.ltp.heap import HeapId, HeapNode

    heap = HeapNode([corrupt.heap_node([b"first", b"second"])])
    assert bytes(heap.get(HeapId(corrupt.hid(2)))) == b"second"
    with pytest.raises(PstFormatError, match="past the block's 2 allocation"):
        heap.get(HeapId(corrupt.hid(3)))
    with pytest.raises(PstFormatError, match="block index 1 not found"):
        heap.get(HeapId(corrupt.hid(1, block=1)))
    base = (PUBLIC / "pstd-inline-cid.pst").read_bytes()
    m = corrupt.mutation(base, seed=SEED, name="heap_lies:hidUserRoot_past_cAlloc")
    outcomes = exercise(m.data, BaseShape.of(base))
    assert any(o.entry_point == "heap.store_pc" and isinstance(o.error, PstFormatError) for o in outcomes)
