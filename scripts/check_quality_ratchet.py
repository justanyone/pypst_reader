#!/usr/bin/env python3
"""Standing lint — tier-1 rules are a gate, total debt is a ratchet.

Adapted from SkyKeep's scripts/check_quality_ratchet.py (ADR-0044), and the
reasoning transfers unchanged, so it is written down here rather than left as
folklore.

**Tier 1 is a real gate.** `TIER1_RULES` finds NOTHING in this tree today and
expresses defects rather than style: an undefined name, a comparison against a
literal with `is`, an argument shadowing a builtin, a broken f-string. Any
finding fails the build. It cannot be satisfied by accident and needs nobody
to clean anything up first.

**Tier 2 is a ratchet, and it claims less than it looks like it claims.** The
full default rule surface finds `BASELINE` findings today; this fails when
that number GOES UP. It does not claim the tree is clean and must never be
cited as evidence that the code is good. What it claims, exactly, is: *debt
did not grow on this commit.*

For a port specifically, tier 1 earns its keep in a way it would not in
ordinary code: the commonest porting slip is a name that exists in the Rust
and does not exist yet in the Python, and F821 catches exactly that.

Usage: python3 scripts/check_quality_ratchet.py [--update-baseline]
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TARGETS = ["src", "tests", "scripts"]

# Rule families that are defects, not taste. Every one scores zero today.
TIER1_RULES = [
    "F821",  # undefined name — the porting slip, caught
    "F811",  # redefinition of an unused name
    "F401",  # unused import (a leftover from a half-moved module)
    "F632",  # `is` against a literal
    "F502",  # broken percent-format
    "F522",  # broken .format()
    "E711",  # comparison to None with ==
    "E712",  # comparison to True/False with ==
    "E713",  # `not x in y`
    "E714",  # `not x is y`
    "A002",  # argument shadowing a builtin
    "B006",  # mutable default argument
    "B012",  # break/return in finally, swallowing an exception
]

BASELINE_FILE = REPO / "scripts" / "quality-baseline.txt"


def _ruff(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["ruff", "check", "--no-cache", "--output-format", "concise", *args, *TARGETS],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )


def _count(result: subprocess.CompletedProcess[str]) -> int:
    lines = [line for line in result.stdout.splitlines() if re.match(r"^\S+:\d+:\d+: ", line)]
    return len(lines)


def _read_baseline() -> int:
    if not BASELINE_FILE.exists():
        return 0
    for line in BASELINE_FILE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return int(line)
    return 0


def main() -> int:
    try:
        tier1 = _ruff(["--select", ",".join(TIER1_RULES)])
    except FileNotFoundError:
        print("ruff not found — run `uv sync` (it is a pinned dev dependency)")
        return 1

    tier1_count = _count(tier1)
    if tier1_count:
        print(f"TIER 1 FAILED — {tier1_count} finding(s). These are defects, not style:\n")
        print(tier1.stdout)
        return 1
    print(f"tier 1: clean ({len(TIER1_RULES)} rule families)")

    tier2 = _ruff([])
    tier2_count = _count(tier2)
    baseline = _read_baseline()

    if "--update-baseline" in sys.argv:
        BASELINE_FILE.write_text(
            "# Tier-2 ruff findings at the time this was last deliberately updated.\n"
            "# The ratchet fails when the count EXCEEDS this. Lower it freely;\n"
            "# raising it is a decision, not a chore — say why in the commit.\n"
            f"{tier2_count}\n"
        )
        print(f"baseline updated: {baseline} -> {tier2_count}")
        return 0

    if tier2_count > baseline:
        print(f"\nTIER 2 RATCHET FAILED — debt grew: {baseline} -> {tier2_count}")
        print("Fix the new findings, or (deliberately, with a reason in the commit)")
        print("run: python3 scripts/check_quality_ratchet.py --update-baseline\n")
        print(tier2.stdout[-4000:])
        return 1

    if tier2_count < baseline:
        print(f"tier 2: {tier2_count} (baseline {baseline} — debt shrank; lower the baseline)")
    else:
        print(f"tier 2: {tier2_count} (baseline {baseline})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
