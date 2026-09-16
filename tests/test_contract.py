"""The contract (docs/TEST-PLAN.md T5): every public entry point, over every store, `PstError` or nothing.

`tests/contract.py` discovers the entry points and knows how to reach each
one; this module says what must never come out of any of them. Four
contracts, each parametrised so a failure names the store (and the
mutation, and the entry point, and the exception type):

- **the corpus** — every fixture, every entry point, default limits: a
  result or a `PstError` subclass. ANSI stores are refused by `read_header`
  with `PstUnsupportedError` and nothing that needs a parsed header runs on
  them; on a Unicode store every entry point is reached (nothing is SKIP).
- **the corruption corpus** — P12's `mutations(pstd-inline-cid, seed=0)`,
  every family, every entry point (the argument set narrowed to each
  adapter's cheap core, `Store.thorough`): no leak, no hang. The slow lane
  is three seeds over every Unicode base.
- **limits bite** — every ceiling at 1 over every fixture: only OK,
  `PstLimitError` or `PstFormatError` from the readers, never a hang or a
  leak, and at least one `PstLimitError` on every Unicode store.
- **defaults are not tight** — every ceiling at `sys.maxsize` over every
  fixture produces exactly the default run's outcomes from every reader
  (file, parsed-store and dumper entry points — what `Limits` governs);
  a difference names the ceiling and the store (and is reported, not fixed
  here: `limits.py` is P11's). The pure decoders are outside this one: they
  take their `max_*` as arguments and are fed slices of the store, and a
  garbage count that the default refuses as a limit is refused as a format
  error a few bytes later when the ceiling is lifted.

Plus the process boundary, slow: `python -m pypst.debug <dumper> <store>`
for every registered dumper over every fixture and five mutations exits 0
or 1 with `Error:` on stderr, never a traceback.

A leak found here is pinned `xfail(strict=True)` naming module, exception
and mutation, and reported — never fixed in `src/` by this row.
"""

from __future__ import annotations

import builtins
import dataclasses
import inspect
import os
import struct
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

import pypst
from pypst import debug
from pypst.errors import PstFormatError, PstLimitError, PstUnsupportedError
from pypst.limits import DEFAULT_LIMITS, Limits
from pypst.messaging import store as messaging
from tests import contract, corrupt
from tests.conftest import FIXTURES, PUBLIC, REPO, public_fixture_paths
from tests.contract import EntryPoint, Outcome, Result
from tests.corruption_harness import Watchdog

CORPUS = [FIXTURES / "Empty.pst", *public_fixture_paths()]
CORPUS_IDS = [p.stem for p in CORPUS]
MUTATION_BASE = PUBLIC / "pstd-inline-cid.pst"
SEED = 0
SLOW_SEEDS = (0, 1, 2)
TIMEOUT = 5.0

# Every ceiling at its floor — except `max_file_size`, which stays at its
# default because at 1 no page can be read and no other ceiling is ever
# reached, so it gets its own case (`LIMITS_NO_FILE`) — and every ceiling at
# the largest value a file offset can hold (past `sys.maxsize` the OS `seek`
# itself overflows, which is the environment's limit, not the format's).
LIMITS_MIN = Limits(**{f.name: 1 for f in dataclasses.fields(Limits) if f.name != "max_file_size"})
LIMITS_NO_FILE = dataclasses.replace(DEFAULT_LIMITS, max_file_size=1)
LIMITS_MAX = Limits(**{f.name: sys.maxsize for f in dataclasses.fields(Limits)})

# The readers — everything whose input is a file or a parsed store — are what
# the limits govern; the pure decoders take their own `max_*` arguments.
READER_KINDS = frozenset({"file", "reader", "method", "path"})


def is_ansi(data: bytes) -> bool:
    return len(data) >= 12 and data[:4] == b"!BDN" and struct.unpack_from("<H", data, 10)[0] in (14, 15)


def _shape(o: Outcome) -> tuple[str, str, str, str]:
    return (o.entry_point, o.label, o.kind.value, o.error_type)


def _reader_shapes(outcomes: list[Outcome], kinds: dict[str, str]) -> list[tuple[str, str, str, str]]:
    return [_shape(o) for o in outcomes if kinds.get(o.entry_point) in READER_KINDS]


@pytest.fixture(scope="module")
def entry_points() -> list[EntryPoint]:
    return contract.entry_points()


@pytest.fixture(scope="module")
def watchdog() -> Iterator[Watchdog]:
    wd = Watchdog(TIMEOUT)
    yield wd
    wd.close()


_DATA: dict[Path, bytes] = {}


def _data(path: Path) -> bytes:
    if path not in _DATA:
        _DATA[path] = path.read_bytes()
    return _DATA[path]


# --- the enumerable contract ---------------------------------------------------------


def test_top_level_all_is_the_contract(entry_points: list[EntryPoint]) -> None:
    """Every name in `pypst.__all__` resolves, the list is sorted, and each callable in it is a discovered entry point."""
    assert pypst.__all__ == sorted(pypst.__all__), "pypst.__all__ is kept sorted"
    assert len(set(pypst.__all__)) == len(pypst.__all__)
    discovered = {contract._key(ep.obj) for ep in entry_points}
    for name in pypst.__all__:
        assert hasattr(pypst, name), f"pypst.__all__ names {name!r}, which pypst does not define"
        obj = getattr(pypst, name)
        if callable(obj):
            assert contract._key(obj) in discovered, f"pypst.{name} is exported but not discovered as an entry point"
    # P07 landed the messaging entry point: `pypst.open` and `pypst.Store`
    # are exported and are the real thing — the same objects the package
    # defines, not a stub, and discovered under their own module.
    assert {"EntryId", "Store", "open"} <= set(pypst.__all__), "P07 exports pypst.open, pypst.Store and pypst.EntryId"
    assert pypst.open is messaging.open_store
    assert pypst.Store is messaging.Store
    assert pypst.EntryId is messaging.EntryId
    assert pypst.open is not builtins.open, "pypst.open shadows the builtin deliberately; it must not BE it"
    assert inspect.signature(pypst.open).parameters.keys() == {"path", "limits", "codepage"}


def test_discovery_reaches_every_layer(entry_points: list[EntryPoint]) -> None:
    """The walk finds the modules and the shapes it must: functions, classmethods, methods along the MRO."""
    names = {ep.name for ep in entry_points}
    for expected in (
        "pypst.ndb.header.read_header",
        "pypst.ndb.header.Header.parse",
        "pypst.ndb.btree.NodeBTree.find",
        "pypst.ndb.btree.NodeBTree.__iter__",
        "pypst.ndb.btree.BlockBTree.pages",  # inherited from _BTree
        "pypst.ndb.block.BlockReader.node_data",
        "pypst.ltp.prop_type.decode",
        "pypst.rtf.decompress_rtf",
        "pypst.debug.main",
    ):
        assert expected in names, f"{expected} not discovered; discovery is broken or the name moved"
    assert not [n for n in names if n.split(".")[1].startswith("_")], "private modules are not part of the contract"


def test_every_public_callable_has_an_adapter_or_a_reason() -> None:
    """The loud failure: a public callable neither adapted nor excluded by name cannot join the package silently."""
    missing = contract.uncovered()
    assert not missing, (
        f"{len(missing)} public callable(s) have no adapter in tests/contract.py and no reason in NOT_STORE_INPUT:\n  "
        + "\n  ".join(missing)
        + "\nAdd an ADAPTERS entry (how to call it from a Store) or a NOT_STORE_INPUT entry (why it takes no store input)."
    )
    dead = contract.stale()
    assert not dead, "adapter table entries for names that no longer exist:\n  " + "\n  ".join(dead)


def test_every_registered_dumper_is_adapted() -> None:
    """A dumper registered by a later row is covered on landing, extra arguments included."""
    adapted = {contract._key(k) for k in contract.ADAPTERS}
    for name, dumper in debug.DUMPERS.items():
        assert dumper in adapted, f"dumper {name!r} has no adapter"
        for param in debug.dumper_arguments(dumper):
            assert param in contract.EXTRA_ARGS, f"dumper {name!r} takes {param!r}; tests/contract.py EXTRA_ARGS does not know how to build it"


# --- the judge -------------------------------------------------------------------------


def test_judge_classifies_every_kind() -> None:
    """OK for a value or a drained iterator, PST_ERROR for a PstError, LEAK (with the frame) for anything else, HANG past the deadline."""
    ok = contract.judge(lambda: 1, contract.call(), "ok")
    drained = contract.judge(lambda: iter([1, 2]), contract.call(), "iter")
    refused = contract.judge(lambda: (_ for _ in ()).throw(PstFormatError("bad")), contract.call(), "pst")
    leaked = contract.judge(lambda: {}["missing"], contract.call(), "leak")
    assert (ok.kind, drained.kind, refused.kind, leaked.kind) == (Result.OK, Result.OK, Result.PST_ERROR, Result.LEAK)
    assert refused.error_type == "PstFormatError" and leaked.error_type == "KeyError"
    assert "test_contract.py" in leaked.where
    assert contract.problems([ok, drained, refused, leaked]) == [str(leaked)]
    wd = Watchdog(0.1)
    try:
        hung = contract.judge(lambda: __import__("time").sleep(0.3), contract.call(), "slow")
        assert hung.kind is Result.OK  # no watchdog: it simply waits
        hung = contract.judge(lambda: __import__("time").sleep(0.3), contract.call(), "slow", watchdog=wd)
        assert hung.kind is Result.HANG and problems_names(contract.problems([hung])) == ["slow"]
    finally:
        wd.close()  # the sleeper finishes on its own; nothing is leaked


def problems_names(lines: list[str]) -> list[str]:
    return [line.split()[1] for line in lines]


# --- the corpus ------------------------------------------------------------------------


@pytest.mark.parametrize("store", CORPUS, ids=CORPUS_IDS)
def test_fixture_never_leaks(store: Path, entry_points: list[EntryPoint], watchdog: Watchdog, tmp_path: Path) -> None:
    data = _data(store)
    outcomes = contract.sweep(data, watchdog=watchdog, workdir=tmp_path, entry_points_=entry_points)
    assert outcomes
    failures = contract.problems(outcomes)
    assert not failures, f"{len(failures)} problem(s) over {store.name}:\n" + "\n".join(failures)

    by_name = {o.entry_point: o for o in outcomes}
    header = by_name["pypst.ndb.header.read_header"]
    adapted = {name for name, how in contract.coverage().items() if how == "adapter"}
    reader_points = {ep.name for ep in entry_points if ep.kind in ("reader", "method")} & adapted
    skipped = {o.entry_point for o in outcomes if o.kind is Result.SKIP}
    if is_ansi(data):
        assert header.error_type == "PstUnsupportedError", f"{store.name}: ANSI must be refused as unsupported, got {header}"
        whole = next(o for o in outcomes if o.entry_point == "pypst.ndb.header.Header.parse" and o.label == "whole")
        assert whole.error_type == "PstUnsupportedError"
        reached_readers = {o.entry_point for o in outcomes if o.kind is not Result.SKIP} & reader_points
        assert not reached_readers, f"{store.name}: entry points that need a parsed header ran on an ANSI store: {sorted(reached_readers)}"
        assert skipped == reader_points, f"{store.name}: SKIP set != the reader entry points: {sorted(skipped ^ reader_points)}"
    else:
        assert header.kind is Result.OK, f"{store.name}: {header}"
        assert not skipped, f"{store.name}: entry points not reached on a Unicode store: {sorted(skipped)}"


# --- the corruption corpus ------------------------------------------------------------


def _sweep_mutations(base: bytes, seed: int, family: corrupt.Family, watchdog: Watchdog, workdir: Path, eps: list[EntryPoint]) -> tuple[int, list[str]]:
    count, failures = 0, []
    for m in family(base, corrupt.family_rng(seed, family)):
        count += 1
        outcomes = contract.sweep(m.data, watchdog=watchdog, workdir=workdir, entry_points_=eps, thorough=False)
        failures += [f"{m.name} :: {line}" for line in contract.problems(outcomes)]
    return count, failures


@pytest.mark.parametrize("family", corrupt.FAMILIES, ids=corrupt.family_names())
def test_mutations_never_leak(family: corrupt.Family, entry_points: list[EntryPoint], watchdog: Watchdog, tmp_path: Path) -> None:
    """Every mutation of one family over the smallest Unicode base, every entry point: no leak, no hang.

    Reproduce one with `corrupt.mutation(base, seed=0, name=...)` and
    `contract.sweep(m.data, thorough=False)`.
    """
    base = _data(MUTATION_BASE)
    count, failures = _sweep_mutations(base, SEED, family, watchdog, tmp_path, entry_points)
    assert count, f"{family.__name__} produced no mutations"
    assert not failures, f"{len(failures)} problem(s) in {family.__name__} over {MUTATION_BASE.name} seed {SEED}:\n" + "\n".join(failures)


@pytest.mark.slow
def test_mutations_three_seeds_every_unicode_base(entry_points: list[EntryPoint], watchdog: Watchdog, tmp_path: Path) -> None:
    """The exhaustive lane: seeds 0-2, every family, every Unicode fixture as a base. Prints the count under `-s`."""
    total, failures = 0, []
    for store in CORPUS:
        base = _data(store)
        if is_ansi(base):
            continue
        for seed in SLOW_SEEDS:
            for family in corrupt.FAMILIES:
                count, bad = _sweep_mutations(base, seed, family, watchdog, tmp_path, entry_points)
                total += count
                failures += [f"{store.name}@{seed} {line}" for line in bad]
    print(f"\n{total} mutations x {len(contract.ADAPTERS)} adapters over {sum(not is_ansi(_data(s)) for s in CORPUS)} bases")
    assert total > 0
    assert not failures, f"{len(failures)} problem(s):\n" + "\n".join(failures)


# --- limits -------------------------------------------------------------------------------


@pytest.mark.parametrize("store", CORPUS, ids=CORPUS_IDS)
def test_limits_bite(store: Path, entry_points: list[EntryPoint], watchdog: Watchdog, tmp_path: Path) -> None:
    """Every ceiling at 1: the readers yield only OK, `PstLimitError` or `PstFormatError` — never a hang or a leak — and at least one limit trips."""
    data = _data(store)
    outcomes = contract.sweep(data, limits=LIMITS_MIN, watchdog=watchdog, workdir=tmp_path, entry_points_=entry_points, thorough=False)
    failures = contract.problems(outcomes)
    assert not failures, f"{len(failures)} problem(s) over {store.name} with every ceiling at 1:\n" + "\n".join(failures)
    kinds = {ep.name: ep.kind for ep in entry_points}
    for o in outcomes:
        if o.kind is Result.PST_ERROR and kinds.get(o.entry_point) in READER_KINDS:
            allowed = (PstLimitError, PstFormatError) + ((PstUnsupportedError,) if is_ansi(data) else ())
            assert isinstance(o.error, allowed), f"{store.name} with every ceiling at 1: {o}"
    if not is_ansi(data):
        # Only the readers count: the pure decoders trip their own `max_*` on
        # garbage counts at the DEFAULT ceilings too, which proves nothing here.
        tripped = [o for o in outcomes if o.error_type == "PstLimitError" and kinds.get(o.entry_point) in READER_KINDS]
        assert tripped, f"{store.name}: no reader tripped a ceiling set to 1 — the limits are not wired into the walks"

    # `max_file_size` alone at 1: nothing past the header can be read, and every
    # reader says so as `PstFormatError` (a lie about the file, not a budget).
    outcomes = contract.sweep(data, limits=LIMITS_NO_FILE, watchdog=watchdog, workdir=tmp_path, entry_points_=entry_points, thorough=False)
    assert not contract.problems(outcomes), f"{store.name} with max_file_size=1:\n" + "\n".join(contract.problems(outcomes))
    for o in outcomes:
        if kinds.get(o.entry_point) in READER_KINDS and o.kind is Result.PST_ERROR and o.entry_point != "pypst.ndb.header.read_header":
            assert isinstance(o.error, PstFormatError | PstUnsupportedError), f"{store.name} with max_file_size=1: {o}"


def _blame(data: bytes, baseline: list[tuple[str, str, str, str]], watchdog: Watchdog, workdir: Path, eps: list[EntryPoint]) -> list[str]:
    """Which single ceiling, raised alone to its max, changes the default outcomes."""
    kinds = {ep.name: ep.kind for ep in eps}
    culprits = []
    for f in dataclasses.fields(Limits):
        one = dataclasses.replace(DEFAULT_LIMITS, **{f.name: sys.maxsize})
        if _reader_shapes(contract.sweep(data, limits=one, watchdog=watchdog, workdir=workdir, entry_points_=eps), kinds) != baseline:
            culprits.append(f.name)
    return culprits


@pytest.mark.parametrize("store", CORPUS, ids=CORPUS_IDS)
def test_defaults_are_not_tight(store: Path, entry_points: list[EntryPoint], watchdog: Watchdog, tmp_path: Path) -> None:
    """Every ceiling at its max reproduces the default run exactly: a default that bites a real store is a bug, and this names the ceiling."""
    data = _data(store)
    kinds = {ep.name: ep.kind for ep in entry_points}
    default = _reader_shapes(contract.sweep(data, watchdog=watchdog, workdir=tmp_path, entry_points_=entry_points), kinds)
    widest = _reader_shapes(contract.sweep(data, limits=LIMITS_MAX, watchdog=watchdog, workdir=tmp_path, entry_points_=entry_points), kinds)
    assert default, "no reader outcomes to compare"
    if default != widest:
        differing = sorted({d[0] for d, w in zip(default, widest, strict=False) if d != w} | {d[0] for d in default[len(widest) :]} | {w[0] for w in widest[len(default) :]})
        culprits = _blame(data, default, watchdog, tmp_path, entry_points)
        pytest.fail(
            f"{store.name}: the default limits change the outcome of {differing} (ceiling(s) responsible: {culprits or 'the combination'}); "
            "a default that bites a corpus store is P11's to raise, not this row's"
        )


# --- the process boundary ----------------------------------------------------------------


def _cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-m", "pypst.debug", *args], capture_output=True, text=True, check=False, cwd=cwd, env=env, timeout=120)


def _cli_extras(dumper: object) -> list[str]:
    """One command-line argument per extra POSITIONAL parameter: a hex nid, or a directory to write into.

    `debug.dumper_arguments` and not the raw signature, because P10's
    `export` takes a keyword-only `as_eml` that the CLI supplies as a flag
    and that is not a positional argument.
    """
    return ["21" for _ in debug.dumper_arguments(dumper)]  # NID_MESSAGE_STORE as hex, or a dest directory


def _cli_stores(tmp_path: Path) -> list[tuple[str, Path]]:
    stores = [(p.stem, p) for p in CORPUS]
    base = _data(MUTATION_BASE)
    every = list(corrupt.mutations(base, seed=SEED))
    for m in every[:: max(len(every) // 5, 1)][:5]:
        path = tmp_path / (m.name.replace(":", "_").replace("/", "_").replace(" ", "_")[:80] + ".pst")
        path.write_bytes(m.data)
        stores.append((m.name, path))
    return stores


@pytest.mark.slow
def test_debug_cli_never_tracebacks(tmp_path: Path) -> None:
    """`python -m pypst.debug <dumper> <store>` over every fixture and five mutations: exit 0 clean, or exit 1 with `Error:` — never a traceback."""
    failures = []
    for label, path in _cli_stores(tmp_path):
        for name, dumper in sorted(debug.DUMPERS.items()):
            proc = _cli([name, str(path), *_cli_extras(dumper)], cwd=tmp_path)
            tag = f"{name} {label}"
            if "Traceback" in proc.stderr:
                failures.append(f"LEAK  {tag}: exit {proc.returncode}\n{proc.stderr[-800:]}")
            elif proc.returncode == 1:
                if not proc.stderr.startswith("Error: "):
                    failures.append(f"EXIT1 {tag}: stderr does not start with 'Error: ': {proc.stderr[:200]!r}")
            elif proc.returncode != 0:
                failures.append(f"EXIT{proc.returncode} {tag}: {proc.stderr[-400:]}")
            elif proc.stderr:
                failures.append(f"NOISE {tag}: exit 0 with stderr {proc.stderr[:200]!r}")
    assert not failures, f"{len(failures)} CLI problem(s):\n" + "\n".join(failures)
