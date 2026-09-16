"""The committed goldens still match the built oracle.

`scripts/capture_oracle.py --check` re-runs every captured upstream example
over every public fixture and diffs against tests/golden/. This is how a
moved upstream pin, or a hand-edited golden, announces itself: the everyday
golden tests only prove the Python agrees with the *file*; this proves the
file agrees with the Rust. It needs the oracle built, so it is `oracle` (skips
without reference/ or cargo) and `slow` (nine fixtures × eight examples).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import REPO

CAPTURE = REPO / "scripts" / "capture_oracle.py"


@pytest.mark.oracle
@pytest.mark.slow
def test_goldens_match_the_built_oracle(oracle: Path) -> None:
    assert oracle.is_dir()
    proc = subprocess.run(
        [sys.executable, str(CAPTURE), "--check"],
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    # --check prints only fixture/example names on drift, never content.
    assert proc.returncode == 0, (
        f"goldens drifted from the oracle (exit {proc.returncode}):\n"
        f"{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}"
    )
