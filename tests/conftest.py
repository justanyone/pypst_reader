"""Shared fixtures — and the one rule that matters about mail stores.

Two kinds of store may be committed, and both are pinned by hash:
`tests/fixtures/Empty.pst` (Microsoft, MIT, no mail) and the public corpus in
`tests/fixtures/public/` (licensed vendor test stores and synthetic stores,
every one listed in MANIFEST.sha256 — see ADR-0004 and the README there).
Tests may inspect those freely: they are published test data.

Everything under `tests/fixtures/private/` is real correspondence, is ignored
by git, is enforced-ignored by scripts/git-hooks/pre-commit, and MUST NOT be
read by any test that prints, logs, or asserts on its content. Tests may
assert that a private store *parses*; they may not assert what it says. A CI
log is a publication channel.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"
PRIVATE = FIXTURES / "private"
REFERENCE = REPO / "reference" / "outlook-pst-rs"


@pytest.fixture(scope="session")
def empty_pst() -> Path:
    """The committed, redistributable, message-free store."""
    path = FIXTURES / "Empty.pst"
    if not path.exists():
        pytest.fail(f"{path} is missing — it is committed; check out the repo again")
    return path


PUBLIC = FIXTURES / "public"


def public_fixture_paths() -> list[Path]:
    """Every store in the public corpus, in manifest order.

    Module-level (not a fixture) so tests can parametrize over it: a
    differential test should run once per fixture and report per fixture.
    """
    manifest = PUBLIC / "MANIFEST.sha256"
    if not manifest.exists():
        return []
    names = [line.split("  ", 1)[1].strip() for line in manifest.read_text().splitlines() if "  " in line]
    return [PUBLIC / name for name in names]


def public_fixture_ids() -> list[str]:
    return [p.stem for p in public_fixture_paths()]


@pytest.fixture(scope="session")
def public_stores() -> list[Path]:
    """The public corpus plus Empty.pst. Never empty on a correct checkout."""
    return [FIXTURES / "Empty.pst", *public_fixture_paths()]


@pytest.fixture(scope="session")
def private_stores() -> list[Path]:
    """Every real store the developer has placed locally. May be empty."""
    if not PRIVATE.is_dir():
        return []
    return sorted(p for p in PRIVATE.glob("*.pst") if p.is_file())


@pytest.fixture(scope="session")
def oracle() -> Path:
    """The upstream Rust checkout, for differential tests.

    Skips rather than fails when it is absent: a contributor who has not run
    scripts/get_rust_source.sh should still be able to run the unit suite.
    """
    if not REFERENCE.is_dir():
        pytest.skip("reference/outlook-pst-rs absent — run scripts/get_rust_source.sh")
    if shutil.which("cargo") is None:
        pytest.skip("cargo not on PATH — run scripts/setup.sh")
    return REFERENCE


def run_oracle(reference: Path, example: str, *args: str, timeout: int = 120) -> str:
    """Run one upstream example binary and return its stdout.

    This is the differential-testing primitive the whole port leans on: port a
    layer, run both implementations over the same bytes, diff. See the
    `rust-port` skill for how to use it without fooling yourself.
    """
    result = subprocess.run(
        ["cargo", "run", "--quiet", "--example", example, "--", *args],
        cwd=reference / "crates" / "pst",
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"oracle `{example}` failed ({result.returncode}):\n{result.stderr[-2000:]}"
        )
    return result.stdout
