#!/usr/bin/env python3
"""The corruption sweep at scale: N seeds x every family x every Unicode fixture.

The suite runs one seed over two bases so that it stays fast. This script
is the slow path — more seeds move the bit flips and the crypt-method
sample, more fixtures bring different tree shapes — and it prints, per
family, how many mutations ran and which exception types came out. It
exits non-zero on any LEAK (a non-PstError escaping), any HANG, or any
mutation whose `expect` was not honoured.

Stdlib only. Run from the repository root:

    uv run python scripts/fuzz_sweep.py                 # 5 seeds, every Unicode fixture
    uv run python scripts/fuzz_sweep.py --seeds 20 --fixtures Empty.pst pstd-inline-cid.pst
    uv run python scripts/fuzz_sweep.py --families bit_flips field_lies --timeout 10

A finding is reproduced with `tests.corrupt.mutation(base, seed=S, name=N)`;
the table names both. Never point this at tests/fixtures/private/: the
report prints mutation names, which carry offsets and field values, and
the corpus is the whole point of a generator that needs no real mail.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
for entry in (REPO / "src", REPO):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from tests import corrupt
from tests.conftest import FIXTURES, public_fixture_paths
from tests.corruption_harness import (
    DEFAULT_TIMEOUT,
    BaseShape,
    Verdict,
    Watchdog,
    judge,
)

ANSI_STEMS = {"pstsdk-test_ansi", "pstsdk-sample2"}


def unicode_fixtures() -> list[Path]:
    return [p for p in [FIXTURES / "Empty.pst", *public_fixture_paths()] if p.stem not in ANSI_STEMS]


def resolve(names: list[str]) -> list[Path]:
    known = {p.name: p for p in [FIXTURES / "Empty.pst", *public_fixture_paths()]}
    out: list[Path] = []
    for name in names:
        path = Path(name)
        out.append(path if path.exists() else known[name])
    return out


def sweep(paths: list[Path], seeds: list[int], families: tuple[corrupt.Family, ...], timeout: float) -> list[Verdict]:
    verdicts: list[Verdict] = []
    for path in paths:
        base = path.read_bytes()
        try:
            corrupt.check_unicode_base(base)
        except ValueError as exc:
            print(f"skip {path.name}: {exc}")
            continue
        shape = BaseShape.of(base)
        watchdog = Watchdog(timeout)
        try:
            for seed in seeds:
                for family in families:
                    for m in family(base, corrupt.family_rng(seed, family)):
                        v = judge(m, shape, watchdog)
                        verdicts.append(Verdict(f"{path.name}@{seed}:{v.name}", v.family, v.outcomes, v.problems, v.seconds))
        finally:
            watchdog.close()
    return verdicts


def report(verdicts: list[Verdict], elapsed: float) -> int:
    per_family: dict[str, Counter[str]] = defaultdict(Counter)
    ran: Counter[str] = Counter()
    slowest: dict[str, tuple[float, str]] = {}
    problems: list[str] = []
    for v in verdicts:
        ran[v.family] += 1
        for o in v.outcomes:
            per_family[v.family][type(o.error).__name__ if o.error else "ok"] += 1
        if v.seconds > slowest.get(v.family, (0.0, ""))[0]:
            slowest[v.family] = (v.seconds, v.name)
        problems.extend(v.problems)

    kinds = sorted({k for c in per_family.values() for k in c if k != "ok"})
    header = f"{'family':16} {'mutations':>9} {'ok':>6} " + " ".join(f"{k:>19}" for k in kinds) + "   slowest"
    print(header)
    print("-" * len(header))
    for family in corrupt.family_names():
        c = per_family[family]
        row = f"{family:16} {ran[family]:9} {c['ok']:6} " + " ".join(f"{c[k]:19}" for k in kinds)
        s, name = slowest.get(family, (0.0, "-"))
        print(f"{row}   {s * 1000:6.1f}ms {name}")
    print(f"\n{len(verdicts)} mutations in {elapsed:.1f}s; {len(problems)} problem(s)")
    for line in problems:
        print(line)
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--seeds", type=int, default=5, help="how many seeds (0, 1, ...) to sweep (default 5)")
    parser.add_argument("--first-seed", type=int, default=0)
    parser.add_argument("--fixtures", nargs="*", default=None, help="fixture file names or paths (default: every Unicode fixture)")
    parser.add_argument("--families", nargs="*", default=None, choices=corrupt.family_names())
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="seconds per mutation before it counts as a hang")
    args = parser.parse_args(argv)

    paths = resolve(args.fixtures) if args.fixtures else unicode_fixtures()
    families = tuple(f for f in corrupt.FAMILIES if not args.families or f.__name__ in args.families)
    seeds = list(range(args.first_seed, args.first_seed + args.seeds))
    print(f"sweeping {len(paths)} fixture(s) x {len(seeds)} seed(s) x {len(families)} families, timeout {args.timeout}s")
    start = time.perf_counter()
    verdicts = sweep(paths, seeds, families, args.timeout)
    return report(verdicts, time.perf_counter() - start)


if __name__ == "__main__":
    raise SystemExit(main())
