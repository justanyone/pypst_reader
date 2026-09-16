"""The `dump_messages` goldens say what the corpus holds — and hold their shape.

`oracle/examples/dump_messages.rs` (P19) is our own non-interactive walk of a
store through the pinned upstream crate; `scripts/capture_oracle.py` captures
it into `tests/golden/<fixture>/dump_messages.txt` like upstream's eight
dumps. These tests need no Rust: they read the committed goldens and check the
facts P08/P09 will diff against — that the submessage fixture shows its
embedded-message attachment, that the three body kinds appear with non-zero
lengths, that the richest fixture has its twelve IPM folders, and that every
golden's `Errors: n` trailer agrees with its counted `Error:` lines and its
exit file. The one `oracle`-marked test re-runs the binary on Empty.pst and
compares byte for byte; it skips without reference/ or cargo.

Where the oracle cannot go, the test says so rather than looking away: at
upstream pin cfb721da `PropertyType::try_from` has no `PtypObject` arm, so no
embedded-message attachment can be opened. `test_submessage_shows_embedded_
attachment_row` asserts exactly that refusal, so a moved pin that fixes it
fails here and the docs get updated with the recursion the dump already
implements.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from tests.conftest import FIXTURES, REPO, public_fixture_ids, public_fixture_paths
from tests.golden_parsers import parse_node_id

EXAMPLE = "dump_messages"
ALL_STORES = [FIXTURES / "Empty.pst", *public_fixture_paths()]
ALL_IDS = ["Empty", *public_fixture_ids()]
ANSI_STORES = {"pstsdk-sample2", "pstsdk-test_ansi"}

# Counted errors per fixture, with the reason. Everything else is 0.
KNOWN_ERRORS = {
    # One embedded-message attachment; upstream cannot parse PtypObject at this pin.
    "pstsdk-submessage": 1,
    # Two embedded-message attachments (same cause) plus one message in the
    # Contacts folder that upstream refuses for having no sub-node tree.
    "javalibpst-dist-list": 3,
}

_COUNTED_ERROR = re.compile(r"^\s+Error: ")
_BYTES = re.compile(r"^(None|\d+ bytes crc 0x[0-9A-F]{8} type=(String8|Unicode|Binary))$")
_TIME = re.compile(r"^(None|Time\(-?\d+\))$")
_ID_LINE = re.compile(r"^\s*(Folder|Message|Attachment): (NodeId \{.*\})$")


def _store(stem: str) -> Path:
    return next(s for s in ALL_STORES if s.stem == stem)


def _lines(text: str) -> list[str]:
    return text.rstrip("\n").splitlines()


def _values(lines: list[str], label: str) -> list[str]:
    prefix = f"{label}: "
    return [ln.strip()[len(prefix) :] for ln in lines if ln.strip().startswith(prefix)]


# --- every fixture: shape and the Errors trailer ------------------------------


@pytest.mark.parametrize("store", ALL_STORES, ids=ALL_IDS)
def test_errors_trailer_matches_counted_errors_and_exit(store: Path, golden, golden_exit) -> None:
    lines = _lines(golden(store, EXAMPLE))
    assert lines and lines[-1].startswith("Errors: "), f"{store.stem}: no Errors trailer"
    reported = int(lines[-1].removeprefix("Errors: "))
    counted = sum(1 for ln in lines[:-1] if _COUNTED_ERROR.match(ln))
    assert reported == counted, f"{store.stem}: trailer says {reported}, {counted} counted Error: lines"
    assert reported == KNOWN_ERRORS.get(store.stem, 0), f"{store.stem}: unexpected error count"
    assert golden_exit(store, EXAMPLE) == (1 if reported else 0), f"{store.stem}: exit disagrees with trailer"


@pytest.mark.parametrize("store", ALL_STORES, ids=ALL_IDS)
def test_every_golden_starts_at_the_root_folder(store: Path, golden) -> None:
    lines = _lines(golden(store, EXAMPLE))
    assert parse_node_id(lines[0].removeprefix("Folder: ")) == {"type": "NormalFolder", "index": 0x9}, store.stem


@pytest.mark.parametrize("store", ALL_STORES, ids=ALL_IDS)
def test_ids_times_and_byte_summaries_parse(store: Path, golden) -> None:
    lines = _lines(golden(store, EXAMPLE))
    ids = 0
    for ln in lines:
        m = _ID_LINE.match(ln)
        if m:
            parse_node_id(m.group(2))  # raises ValueError on a malformed id
            ids += 1
    assert ids >= 1, store.stem
    for label in ("Body Text", "Body HTML", "Body RTF", "Transport Headers"):
        for value in _values(lines, label):
            assert _BYTES.match(value), f"{store.stem}: {label}: {value!r}"
    for label in ("Delivery Time", "Client Submit Time"):
        for value in _values(lines, label):
            assert _TIME.match(value), f"{store.stem}: {label}: {value!r}"


@pytest.mark.parametrize("store", ALL_STORES, ids=ALL_IDS)
def test_bodies_are_summarised_never_printed(store: Path, golden) -> None:
    # A body line carries a length and a CRC; no line anywhere carries body
    # text. The cheapest tell of a leaked body is an HTML tag on a golden line.
    for ln in _lines(golden(store, EXAMPLE)):
        assert "<html" not in ln.lower() and "{\\rtf" not in ln, f"{store.stem}: body content leaked: {ln[:60]!r}"


# --- what specific fixtures must show -----------------------------------------


def test_submessage_shows_embedded_attachment_row(golden, golden_exit) -> None:
    store = _store("pstsdk-submessage")
    lines = _lines(golden(store, EXAMPLE))
    attachment = next(i for i, ln in enumerate(lines) if ln.strip().startswith("Attachment: "))
    assert lines[attachment].startswith("      Attachment: NodeId { Attachment: 0x401 }")
    # The attachment table row knows it is an embedded message (method 5).
    assert lines[attachment + 1].startswith("        Row: method=5 filename=Unicode(UnicodeValue {")
    # ...and, at this pin, upstream refuses to open it: PtypObject is unparsed
    # and the PC is truncated before PidTagAttachMethod. If this assertion
    # fails after a pin move, the fix landed upstream — update TEST-PLAN T7
    # and this test to assert the embedded `Message:` block instead.
    assert lines[attachment + 2] == "        Error: Custom { kind: InvalidData, error: AttachmentMethodNotFound }"
    assert not any(ln.startswith("        Message: ") for ln in lines), "embedded message now opens — pin moved?"
    assert golden_exit(store, EXAMPLE) == 1


def test_various_body_types_shows_all_three_body_kinds(golden) -> None:
    lines = _lines(golden(_store("tika-variousBodyTypes"), EXAMPLE))
    for label in ("Body Text", "Body HTML", "Body RTF"):
        sizes = [int(v.split(" ", 1)[0]) for v in _values(lines, label) if v != "None"]
        assert sizes and all(n > 0 for n in sizes), f"{label}: {sizes}"
    assert "type=Binary" in " ".join(_values(lines, "Body RTF")), "RTF is stored compressed, as PtypBinary"


def test_dist_list_shows_the_twelve_ipm_folders(golden) -> None:
    lines = _lines(golden(_store("javalibpst-dist-list"), EXAMPLE))
    names = _values(lines, "Name")
    ipm = {
        '"Deleted Items"', '"Inbox"', '"Outbox"', '"Sent Items"', '"Calendar"', '"Contacts"',
        '"Journal"', '"Notes"', '"Tasks"', '"Drafts"', '"RSS Feeds"', '"Junk E-mail"',
    }
    assert ipm <= set(names), sorted(ipm - set(names))
    assert sum(1 for ln in lines if ln.startswith("Folder: ")) >= 12


def test_unicode_fixture_has_posts_without_recipients(golden) -> None:
    # pstsdk's test store holds IPM.Post items: a message with no recipient
    # table is a shape P09 must handle, and this golden pins one.
    lines = _lines(golden(_store("pstsdk-test_unicode"), EXAMPLE))
    assert sum(1 for ln in lines if ln.startswith("  Message: NodeId { NormalMessage: ")) == 2
    assert set(_values(lines, "Class")) == {'"IPM.Post"'}
    assert _values(lines, "Recipients") == ["None", "None"]


def test_various_body_types_has_to_recipients(golden) -> None:
    lines = _lines(golden(_store("tika-variousBodyTypes"), EXAMPLE))
    rows = [ln.strip() for ln in lines if ln.strip().startswith("Recipient: ")]
    assert len(rows) == 4 and all(r.startswith("Recipient: type=1 name=Unicode(") for r in rows), rows


def test_empty_pst_has_no_messages(golden) -> None:
    lines = _lines(golden(_store("Empty"), EXAMPLE))
    assert not any(ln.strip().startswith("Message: ") for ln in lines)
    assert sum(1 for ln in lines if ln.startswith("Folder: ")) == 6


@pytest.mark.parametrize("stem", sorted(ANSI_STORES))
def test_ansi_fixtures_are_read_by_the_oracle(stem: str, golden, golden_exit) -> None:
    # Upstream reads ANSI stores; pypstreader refuses them (ADR-0003). These goldens
    # exist for completeness and are not diffed against.
    lines = _lines(golden(_store(stem), EXAMPLE))
    assert golden_exit(_store(stem), EXAMPLE) == 0
    assert sum(1 for ln in lines if ln.startswith("Folder: ")) >= 2, stem


# --- the live oracle -----------------------------------------------------------


@pytest.mark.oracle
def test_dump_messages_rebuilds_and_matches_golden_on_empty(oracle: Path, empty_pst: Path, golden) -> None:
    assert oracle.is_dir()
    proc = subprocess.run(
        [str(REPO / "scripts" / "oracle.sh"), EXAMPLE, str(empty_pst)],
        capture_output=True,
        text=True,
        timeout=600,  # a cold build of oracle/ compiles the upstream crate once
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert proc.stdout == golden(empty_pst, EXAMPLE)
