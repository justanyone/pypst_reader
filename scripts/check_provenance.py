#!/usr/bin/env python3
"""Standing lint — every ported module says what it was ported from.

NOTICE makes a claim to the world: that this project is a port of
microsoft/outlook-pst-rs, MIT, at a named revision. That claim is only
checkable if each module records which upstream file it came from. This lint
is what keeps the claim true as the tree grows.

A module in `src/pypst/` must carry, inside its opening docstring:

    Ported from: <upstream path>          (or the literal: not a port)
    Upstream:    microsoft/outlook-pst-rs @ <40-char sha>

The escape hatch is deliberate and narrow: a module that is genuinely ours
writes `Ported from: not a port` and says why in the next line. That is a
sentence somebody has to choose to write, which is the point.

Usage: python3 scripts/check_provenance.py
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PACKAGE = REPO / "src" / "pypst"
PIN_FILE = REPO / "docs" / "UPSTREAM.txt"

PORTED_FROM = re.compile(r"^Ported from:\s*(\S.*)$", re.MULTILINE)
UPSTREAM = re.compile(r"^Upstream:\s*microsoft/outlook-pst-rs @ ([0-9a-f]{40}|unknown)$", re.MULTILINE)

# Modules that are infrastructure rather than ported logic.
EXEMPT = {"__init__.py"}


def pinned_revision() -> str | None:
    if not PIN_FILE.exists():
        return None
    match = re.search(r"^REV=([0-9a-f]{40})$", PIN_FILE.read_text(), re.MULTILINE)
    return match.group(1) if match else None


def main() -> int:
    pin = pinned_revision()
    if pin is None:
        print("docs/UPSTREAM.txt has no REV= line — the port has no pin")
        return 1

    problems: list[str] = []
    checked = 0

    for path in sorted(PACKAGE.rglob("*.py")):
        if path.name in EXEMPT:
            continue
        checked += 1
        rel = path.relative_to(REPO)
        try:
            doc = ast.get_docstring(ast.parse(path.read_text())) or ""
        except SyntaxError as exc:
            problems.append(f"{rel}: does not parse ({exc})")
            continue

        ported = PORTED_FROM.search(doc)
        if ported is None:
            problems.append(
                f"{rel}: no `Ported from:` line in the module docstring "
                "(write the upstream path, or `not a port` and why)"
            )
            continue

        if ported.group(1).strip() == "not a port":
            continue

        upstream = UPSTREAM.search(doc)
        if upstream is None:
            problems.append(
                f"{rel}: has `Ported from:` but no "
                "`Upstream: microsoft/outlook-pst-rs @ <sha>` line"
            )
        elif upstream.group(1) not in (pin, "unknown"):
            problems.append(
                f"{rel}: cites upstream {upstream.group(1)[:12]} but "
                f"docs/UPSTREAM.txt pins {pin[:12]} — re-verify the port against "
                "the pinned revision before updating the header"
            )

    if problems:
        print(f"provenance lint: {len(problems)} problem(s) in {checked} module(s)\n")
        for problem in problems:
            print(f"  {problem}")
        print("\nWhy this matters: NOTICE tells the world this is a port of MIT code.")
        print("These headers are how a reader checks that, and how the next person")
        print("finds the Rust to compare against. See the `rust-port` skill.")
        return 1

    print(f"provenance lint: {checked} module(s) all record their upstream ({pin[:12]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
