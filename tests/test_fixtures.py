"""What the fixtures are, and what tests may do with them.

`Empty.pst` and the public corpus (`tests/fixtures/public/`) may be inspected
freely — licensed, hash-pinned, published test data. The private stores may
only be checked for *structure*: that they open, that the magic is right, that
a walk completes. Never what they say.

The tests here are the fixture POLICY, executable: the set of committed stores
is exactly the manifest, and every one is the file it claims to be.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from tests.conftest import FIXTURES, PUBLIC, public_fixture_ids, public_fixture_paths

REPO = Path(__file__).resolve().parent.parent
MANIFEST = PUBLIC / "MANIFEST.sha256"

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


def _manifest_entries() -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in MANIFEST.read_text().splitlines():
        if "  " not in line:
            continue
        digest, name = line.split("  ", 1)
        entries[name.strip()] = digest.strip()
    return entries


def test_committed_stores_are_exactly_the_manifest() -> None:
    """The fixture policy, enforced as a test rather than left to discipline.

    Every tracked mail store is either Empty.pst or a manifest-listed member of
    the public corpus. Anything else is a mistake that must fail here, loudly,
    before it reaches a remote. And the converse: a corpus file present on disk
    but absent from the manifest is a smuggling attempt or a forgotten step.
    """
    tracked = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.split("\0")
    stores = sorted(f for f in tracked if f.lower().endswith((".pst", ".ost", ".pab")))
    allowed = sorted(
        ["tests/fixtures/Empty.pst"]
        + [f"tests/fixtures/public/{name}" for name in _manifest_entries()]
    )
    # A fresh, uncommitted corpus is allowed to be untracked; anything tracked
    # must be allowed.
    unexpected = [s for s in stores if s not in allowed]
    assert not unexpected, f"mail store(s) tracked by git outside the pinned corpus: {unexpected}"
    on_disk = sorted(p.name for p in PUBLIC.glob("*.pst"))
    assert on_disk == sorted(_manifest_entries()), (
        "tests/fixtures/public/ and MANIFEST.sha256 disagree — regenerate the manifest"
    )


@pytest.mark.parametrize("store", public_fixture_paths(), ids=public_fixture_ids())
def test_public_fixture_matches_its_pinned_hash(store: Path) -> None:
    """A corpus file that drifted from its hash is not the file we vetted."""
    expected = _manifest_entries()[store.name]
    actual = hashlib.sha256(store.read_bytes()).hexdigest()
    assert actual == expected, f"{store.name}: sha256 {actual} != manifest {expected}"


@pytest.mark.parametrize("store", public_fixture_paths(), ids=public_fixture_ids())
def test_public_fixture_is_a_pst(store: Path) -> None:
    with store.open("rb") as handle:
        assert handle.read(4) == PST_MAGIC, store.name
    assert _version(store) in UNICODE_VERSIONS | ANSI_VERSIONS, store.name


def test_corpus_format_split_is_as_documented() -> None:
    """Two ANSI stores are kept deliberately (the refusal path, ADR-0003).

    If this changes, the README table and the ADR are stale, not just this
    number.
    """
    ansi = sorted(p.name for p in public_fixture_paths() if _version(p) in ANSI_VERSIONS)
    assert ansi == ["pstsdk-sample2.pst", "pstsdk-test_ansi.pst"]


def test_empty_fixture_is_the_documented_md5() -> None:
    import hashlib as _h

    digest = _h.md5((FIXTURES / "Empty.pst").read_bytes()).hexdigest()
    assert digest == "13a1f7eb9e35fcac72cf37360e3a96bc"


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
