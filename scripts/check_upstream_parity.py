#!/usr/bin/env python3
"""Standing lint — every upstream `#[test]` has exactly one Python twin.

"Passes the same tests as upstream" is a claim, and this is what makes it a
checked one (docs/TEST-PLAN.md, tier T0). It enumerates every `#[test]`
function in the pinned Rust source and every Python test tagged

    @upstream_test("crates/pst/src/encode/permute.rs::test_decode_block")

(the decorator lives in tests/parity/__init__.py) and fails when the two sets
disagree:

- an upstream test has no twin and is not in scripts/parity-pending.txt
- an upstream test has more than one twin
- a twin's ref names no upstream test (a typo, or the pin moved)
- a pending entry has a twin (the row landed — delete its line)
- a pending entry names no upstream test (the pin moved — re-check the row)

The pending list is a debt ledger, not a waiver: each line names the row that
owes the twin, and the lint fails the moment that row lands with the line
still present. It is also how a moved pin tells us upstream added a test:
the new one is neither twinned nor pending, and the lint says so.

The lint SKIPS with exit 0 when `reference/` is absent. CI's lint job has no
oracle checkout, so it skips there; the nightly job (row P14-CI-ORACLE) checks
out the pinned upstream, and that is where this lint bites.

Usage: python3 scripts/check_upstream_parity.py
       [--reference DIR] [--tests DIR] [--pending FILE]   (for the unit tests)
"""

from __future__ import annotations

import argparse
import ast
import re
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REFERENCE = REPO / "reference" / "outlook-pst-rs"
TESTS = REPO / "tests"
PENDING = REPO / "scripts" / "parity-pending.txt"

DECORATOR = "upstream_test"

# `#[test]`, then any further attributes (`#[should_panic]`, `#[ignore]`,
# `#[cfg(...)]`), then the fn. `\s` spans newlines, so this is deliberately
# not line-based: rustfmt puts each attribute on its own line, but nothing
# requires it to.
RUST_TEST = re.compile(
    r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)"
)


def collect_upstream_tests(reference: Path) -> list[str]:
    """Every `<path relative to reference>::<fn name>` under crates/, sorted."""
    refs: list[str] = []
    for path in sorted((reference / "crates").rglob("*.rs")):
        rel = path.relative_to(reference).as_posix()
        for match in RUST_TEST.finditer(path.read_text(encoding="utf-8", errors="replace")):
            refs.append(f"{rel}::{match.group(1)}")
    return sorted(refs)


def _decorator_ref(node: ast.expr) -> str | None:
    """The ref string if `node` is a call `upstream_test("...")`, else None.

    Matched by decorator NAME, so `from tests.parity import upstream_test`,
    `import tests.parity as parity; @parity.upstream_test(...)` and any other
    alias all count.
    """
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
    if name != DECORATOR:
        return None
    args = list(node.args) + [kw.value for kw in node.keywords if kw.arg == "ref"]
    if len(args) == 1 and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
        return args[0].value
    return ""  # a call we cannot read statically — reported, never silently skipped


def collect_twins(tests_dir: Path) -> dict[str, list[str]]:
    """ref -> the tagged Python tests, as `<path relative to tests_dir>::<qualname>`."""
    twins: dict[str, list[str]] = {}
    for path in sorted(tests_dir.rglob("*.py")):
        rel = path.relative_to(tests_dir).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            twins.setdefault("", []).append(f"{rel}: does not parse ({exc})")
            continue
        parents: dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                ref = _decorator_ref(decorator)
                if ref is None:
                    continue
                qual = [node.name]
                parent = parents.get(node)
                while isinstance(parent, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    qual.insert(0, parent.name)
                    parent = parents.get(parent)
                twins.setdefault(ref, []).append(f"{rel}::{'.'.join(qual)}")
    return twins


def read_pending(path: Path) -> tuple[dict[str, str], list[str]]:
    """ref -> row id, plus the lines that could not be read."""
    pending: dict[str, str] = {}
    problems: list[str] = []
    if not path.exists():
        return pending, problems
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 2 or "::" not in fields[0]:
            problems.append(f"{path.name}:{lineno}: expected `<path>::<fn>  <ROW-ID>`, got: {raw.strip()}")
            continue
        ref, row = fields
        if ref in pending:
            problems.append(f"{path.name}:{lineno}: {ref} listed twice")
            continue
        pending[ref] = row
    return pending, problems


def check(
    upstream: list[str],
    twins: dict[str, list[str]],
    pending: dict[str, str],
) -> tuple[list[str], str]:
    """Compare the three sets. Returns (problems, one-line summary)."""
    problems: list[str] = []
    known = set(upstream)

    for unreadable in twins.pop("", []):
        problems.append(f"unreadable tag: {unreadable}")

    twinned = missing = 0
    for ref in upstream:
        found = twins.get(ref, [])
        if len(found) == 1:
            twinned += 1
            if ref in pending:
                problems.append(
                    f"stale pending entry: {ref} is twinned by {found[0]} — "
                    f"row {pending[ref]} landed; remove its line from {PENDING.name}"
                )
        elif len(found) > 1:
            twinned += 1
            problems.append(f"{ref} has {len(found)} twins (exactly one is allowed): {', '.join(found)}")
        elif ref not in pending:
            missing += 1
            problems.append(f"{ref} has no twin and is not pending — write it, or list it in {PENDING.name}")

    for ref in sorted(set(twins) - known):
        problems.append(
            f"{', '.join(twins[ref])} claims upstream {ref}, which does not exist "
            "(typo, or the pin moved)"
        )

    for ref, row in pending.items():
        if ref not in known:
            problems.append(f"pending entry {ref} ({row}) names no upstream test — the pin moved?")

    owed = Counter(row for ref, row in pending.items() if ref in known and ref not in twins)
    by_row = ", ".join(f"{row} ×{n}" for row, n in sorted(owed.items()))
    summary = (
        f"parity: {len(upstream)} upstream tests — {twinned} twinned, "
        f"{sum(owed.values())} pending" + (f" ({by_row})" if by_row else "") + f", {missing} missing"
    )
    return problems, summary


def run(reference: Path = REFERENCE, tests_dir: Path = TESTS, pending_path: Path = PENDING) -> int:
    if not (reference / "crates").is_dir():
        print(
            f"parity lint: {reference.relative_to(REPO) if reference.is_relative_to(REPO) else reference} "
            "absent — skipped. (CI's lint job has no oracle checkout; this lint bites in the "
            "nightly job, row P14-CI-ORACLE. Locally: scripts/get_rust_source.sh)"
        )
        return 0

    upstream = collect_upstream_tests(reference)
    twins = collect_twins(tests_dir)
    pending, problems = read_pending(pending_path)
    more, summary = check(upstream, twins, pending)
    problems.extend(more)

    if problems:
        print(f"parity lint: {len(problems)} problem(s)\n")
        for problem in problems:
            print(f"  {problem}")
        print(f"\n{summary}")
        print("\nWhy this matters: tier T0 (docs/TEST-PLAN.md) claims this port passes")
        print("every test upstream passes. Tag a twin with @upstream_test(...) from")
        print("tests/parity; a twin owed by an unlanded row goes in the pending list.")
        return 1

    print(summary)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--reference", type=Path, default=REFERENCE, help=argparse.SUPPRESS)
    parser.add_argument("--tests", type=Path, default=TESTS, help=argparse.SUPPRESS)
    parser.add_argument("--pending", type=Path, default=PENDING, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    return run(args.reference, args.tests, args.pending)


if __name__ == "__main__":
    raise SystemExit(main())
