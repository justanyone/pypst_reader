"""What the fixtures are, and what tests may do with them.

The content assertions here stop at the header on purpose. `Empty.pst` may be
inspected freely — it is Microsoft's, it is MIT, and it holds no mail. The
private stores may only be checked for *structure*: that they open, that the
magic is right, that a walk completes. Never what they say.
"""

from __future__ import annotations

from pathlib import Path

import pytest

PST_MAGIC = b"!BDN"
UNICODE_VERSIONS = {23, 36, 37}  # wVer values for Unicode stores ([MS-PST] 2.2.2.6)
ANSI_VERSIONS = {14, 15}


def _version(path: Path) -> int:
    with path.open("rb") as handle:
        header = handle.read(12)
    return int.from_bytes(header[10:12], "little")


def test_empty_fixture_is_a_unicode_pst(empty_pst: Path) -> None:
    with empty_pst.open("rb") as handle:
        assert handle.read(4) == PST_MAGIC
    assert _version(empty_pst) in UNICODE_VERSIONS


def test_empty_fixture_is_the_one_committed_store() -> None:
    """The fixture policy, enforced as a test rather than left to discipline.

    Anything else tracked by git that looks like a mail store is a mistake
    that must fail here, loudly, before it reaches a remote.
    """
    import subprocess

    repo = Path(__file__).resolve().parent.parent
    tracked = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.split("\0")
    stores = [f for f in tracked if f.lower().endswith((".pst", ".ost", ".pab"))]
    assert stores in ([], ["tests/fixtures/Empty.pst"]), (
        f"a mail store other than the MIT fixture is tracked by git: {stores}"
    )


@pytest.mark.private
def test_private_stores_are_readable_pst_files(private_stores: list[Path]) -> None:
    """Structure only — never content. See this module's docstring."""
    if not private_stores:
        pytest.skip("no private stores present (this is a normal clean checkout)")
    for store in private_stores:
        with store.open("rb") as handle:
            assert handle.read(4) == PST_MAGIC, store.name
        assert _version(store) in UNICODE_VERSIONS | ANSI_VERSIONS, store.name


@pytest.mark.private
def test_private_stores_are_not_tracked(private_stores: list[Path]) -> None:
    """The gitignore and the hook both hold. Cheap, and the failure is fatal."""
    import subprocess

    repo = Path(__file__).resolve().parent.parent
    for store in private_stores:
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", str(store.relative_to(repo))],
            cwd=repo,
            capture_output=True,
            check=False,
        )
        assert result.returncode != 0, f"{store.name} IS TRACKED BY GIT — remove it now"
