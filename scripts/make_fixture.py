#!/usr/bin/env python3
"""Generate a synthetic public fixture from EML sources we authored.

The vendor stores in tests/fixtures/public/ prove that structures parse; they
cannot prove that a message says what it should, because nobody here wrote
the mail. This script closes that gap: tests/fixtures/synthetic/<name>/ is a
folder tree of .eml files that WE wrote (example.test addresses, invented
names, fixed dates and Message-IDs), the pinned EMLtoPST turns it into a
Unicode PST, and tests may then assert on content — the subject of the third
message, the bytes of the second attachment — against the source.

    scripts/make_fixture.py basics            # writes tests/fixtures/public/synth-basics.pst
    scripts/make_fixture.py --check basics    # regenerates to a temp file, compares to the committed one

The output is byte-for-byte reproducible, which is what lets `--check` be a
test: the store's timestamps come from a fixed SOURCE_DATE_EPOCH, its record
key is derived from the fixture name, and the tool allocates ids
deterministically. A regenerated store that differs from the committed one
means the pin, the patch, or the sources moved.

EMLtoPST is a FIXTURE-BUILD tool only. It is fetched by
scripts/get_fixture_tools.sh into reference/EMLtoPST (gitignored, never
vendored) at the revision in docs/FIXTURE-TOOLS.txt, with
scripts/patches/emltopst-oracle-conformance.patch applied — unpatched, the
upstream Rust oracle refuses its output. It must never be imported by
src/pypst, listed as a dependency, or needed to run the test suite: a fresh
clone without it still runs green (the tests that need it skip).

The generated store is the store layout the oracle expects of Outlook:
root → "Top of Personal Folders" (the IPM subtree, PidTagIpmSubTreeEntryId)
and "Search Root" (PidTagFinderEntryId); the IPM subtree → "Deleted Items"
(PidTagIpmWastebasketEntryId) and one folder per source directory.

Stdlib only, like everything else in this repository.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PIN = REPO / "docs" / "FIXTURE-TOOLS.txt"
TOOL = REPO / "reference" / "EMLtoPST"
SYNTHETIC = REPO / "tests" / "fixtures" / "synthetic"
PUBLIC = REPO / "tests" / "fixtures" / "public"

# 2026-01-01T00:00:00Z. Every PR_CREATION_TIME / PR_LAST_MODIFICATION_TIME the
# tool stamps (folders and messages) is this instant; delivery and submit
# times come from each message's Date: header.
SOURCE_DATE_EPOCH = 1767225600

IPM_SUBTREE_NAME = "Top of Personal Folders"
FINDER_NAME = "Search Root"
WASTEBASKET_NAME = "Deleted Items"

EXIT_TOOL_MISSING = 3


def record_key_for(name: str) -> bytes:
    """The store's 16-byte PR_RECORD_KEY: derived, so two runs agree and two
    fixtures differ. tests/test_synthetic_content.py checks the golden shows it."""
    return hashlib.sha256(f"pypst synthetic fixture: {name}".encode()).digest()[:16]


def pinned() -> tuple[str, Path | None]:
    text = PIN.read_text()
    rev = re.search(r"^REV=([0-9a-f]{40})$", text, re.MULTILINE)
    patch = re.search(r"^PATCH=(\S+)$", text, re.MULTILINE)
    if not rev:
        raise SystemExit(f"{PIN.relative_to(REPO)} has no REV= line")
    return rev.group(1), (REPO / patch.group(1)) if patch else None


def require_tool() -> None:
    """Refuse to generate with anything but the pinned, patched tool.

    A store built from a different revision is a different fixture, and one
    built from an unpatched checkout is one the oracle refuses. Both would
    show up as a `--check` failure later, with less explanation than this."""
    rev, patch = pinned()
    if not (TOOL / ".git").exists():
        raise SystemExit(
            f"{TOOL.relative_to(REPO)} is absent — run scripts/get_fixture_tools.sh"
        )
    head = subprocess.run(
        ["git", "-C", str(TOOL), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    if head != rev:
        raise SystemExit(f"{TOOL.relative_to(REPO)} is at {head[:12]}, pinned {rev[:12]} — run scripts/get_fixture_tools.sh")
    if patch is not None and not exactly_patched(patch):
        raise SystemExit(
            f"{TOOL.relative_to(REPO)} is not HEAD plus exactly {patch.relative_to(REPO)} — run scripts/get_fixture_tools.sh"
        )


def exactly_patched(patch: Path) -> bool:
    """The working tree is HEAD + the patch and nothing else — the same test
    scripts/get_fixture_tools.sh makes: stage, reverse the patch in the
    index, demand an empty diff. A reverse `--check` alone would accept a
    stray edit beside the patch, and that edit would then be in the fixture."""

    def git(*args: str, check: bool = True) -> int:
        return subprocess.run(["git", "-C", str(TOOL), *args], capture_output=True, check=check).returncode

    try:
        git("add", "-u", "--", ".")
        return (
            git("apply", "--reverse", "--cached", str(patch), check=False) == 0
            and git("diff", "--cached", "--quiet", "HEAD", "--", ".", check=False) == 0
        )
    finally:
        git("reset", "-q", "--", ".")


def build(name: str, source: Path, output: Path) -> None:
    os.environ["SOURCE_DATE_EPOCH"] = str(SOURCE_DATE_EPOCH)
    sys.path.insert(0, str(TOOL))
    from eml2pst.eml_parser import parse_eml_file  # the external tool, on purpose
    from eml2pst.mapi.properties import NID_ROOT_FOLDER
    from eml2pst.pst_file import PSTFileBuilder

    builder = PSTFileBuilder(display_name=f"synth-{name}", record_key=record_key_for(name))
    ipm = builder.add_folder(IPM_SUBTREE_NAME, NID_ROOT_FOLDER)
    builder.finder_nid = builder.add_folder(FINDER_NAME, NID_ROOT_FOLDER)
    builder.wastebasket_nid = builder.add_folder(WASTEBASKET_NAME, ipm)
    builder.ipm_subtree_nid = ipm

    def add_tree(directory: Path, parent_nid: int) -> int:
        count = 0
        for eml in sorted(directory.glob("*.eml")):
            builder.add_message(parent_nid, parse_eml_file(eml))
            count += 1
        for sub in sorted(p for p in directory.iterdir() if p.is_dir()):
            count += add_tree(sub, builder.add_folder(sub.name, parent_nid))
        return count

    messages = add_tree(source, ipm)
    if messages == 0:
        raise SystemExit(f"{source.relative_to(REPO)} holds no .eml files")
    builder.write(output)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name", help="fixture name: sources in tests/fixtures/synthetic/<name>/, store synth-<name>.pst")
    ap.add_argument("--check", action="store_true", help="regenerate to a temp file and compare with the committed store")
    ap.add_argument("--output", type=Path, default=None, help="write here instead of tests/fixtures/public/")
    args = ap.parse_args()

    source = SYNTHETIC / args.name
    if not source.is_dir():
        print(f"no such fixture source: {source.relative_to(REPO)}", file=sys.stderr)
        return 2
    try:
        require_tool()
    except SystemExit as exc:
        print(f"make_fixture.py: {exc}", file=sys.stderr)
        return EXIT_TOOL_MISSING

    committed = PUBLIC / f"synth-{args.name}.pst"
    target = args.output or committed

    with tempfile.TemporaryDirectory(prefix="make_fixture-") as tmp:
        scratch = Path(tmp) / committed.name
        build(args.name, source, scratch)
        data = scratch.read_bytes()
        if args.check:
            if not committed.exists():
                print(f"{committed.relative_to(REPO)} is not committed; nothing to check against")
                return 1
            if committed.read_bytes() != data:
                print(f"{committed.relative_to(REPO)} does NOT regenerate from its sources with the pinned tool")
                return 1
            print(f"{committed.relative_to(REPO)} regenerates byte-for-byte ({len(data)} bytes)")
            return 0
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    digest = hashlib.sha256(data).hexdigest()
    print(f"wrote {target.relative_to(REPO) if target.is_relative_to(REPO) else target}  ({len(data)} bytes)")
    print(f"sha256  {digest}")
    print()
    print("manifest line (tests/fixtures/public/MANIFEST.sha256):")
    print(f"{digest}  {committed.name}")
    print()
    print("A new or changed store is a corpus change: README row, NOTICE, manifest,")
    print("then `scripts/capture_oracle.py --fixture synth-" + args.name + "` (ADR-0004).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
