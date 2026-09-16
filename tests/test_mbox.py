"""`pypstreader.mbox` — one mbox per folder, and the round trip back through `mailbox`.

The export format the row asked for, and the one every mail tool already
reads. There is no oracle here either (upstream produces no mail at all), so
the evidence is the same three kinds as `tests/test_eml.py`: the synthetic
store's Sent message round-tripping back to the `.eml` it was built from,
every corpus store exported and re-read with the stdlib's own `mailbox.mbox`
to the same counts, and the refusals — including the one property of the
format that bites everybody, a body line that begins with `From `.

Private stores are counted and never quoted.
"""

from __future__ import annotations

import email.parser
import email.policy
import mailbox
import re
import time
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from pypstreader.eml import POLICY, folder_paths, readable_messages
from pypstreader.errors import PstError, PstFormatError
from pypstreader.mbox import (
    INDEX_NAME,
    MAILER_DAEMON,
    MBOX_POLICY,
    export_mbox,
    mbox_name,
)
from pypstreader.messaging.folder import Folder
from pypstreader.messaging.message import Message
from pypstreader.messaging.store import Store
from tests.test_eml import (
    OPENABLE,
    SENT_SOURCE,
    SYNTH,
    UNICODE_IDS,
    UNICODE_STORES,
    _path,
    folders_with_messages,
    openable_messages,
    text_of,
)


def records(path: Path) -> list[Any]:
    """Every message in one mbox, re-parsed with this package's own policy.

    `mailbox.mbox`'s default factory builds a `compat32` message, which has
    no `get_body`; the factory hook hands each record to the same parser
    `tests/test_eml.py` re-reads an `.eml` with, so both round trips are
    compared the same way.
    """
    box = mailbox.mbox(path, factory=lambda f: email.parser.BytesParser(policy=POLICY).parse(f), create=False)
    try:
        return [box[key] for key in box.iterkeys()]
    finally:
        box.close()


def from_lines(path: Path) -> list[str]:
    """The `From ` separator line of every record in one mbox, without the `From `."""
    box = mailbox.mbox(path, create=False)
    try:
        return [box.get_message(key).get_from() for key in box.iterkeys()]
    finally:
        box.close()


def index_of(dest: Path) -> dict[str, str]:
    """`folders.txt` as {file name: folder path}, comment line dropped."""
    lines = (dest / INDEX_NAME).read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("#")
    return {line.split("\t")[0]: line.split("\t")[1] for line in lines[1:]}


def test_the_mbox_policy_is_the_eml_policy_with_unix_line_endings() -> None:
    """RFC 5322 says CRLF and every mbox on earth says LF; the records are the only difference."""
    assert MBOX_POLICY.linesep == "\n"
    assert POLICY.linesep == "\r\n"
    assert MBOX_POLICY.cte_type == POLICY.cte_type == "7bit"


# --- the round trip ---------------------------------------------------------------


def test_synth_basics_sent_round_trips_through_mailbox(tmp_path: Path) -> None:
    """Out through `export_mbox`, back in through `mailbox.mbox`, compared with the source `.eml`."""
    with Store.open(_path(SYNTH)) as store:
        written = export_mbox(store.root_folder, tmp_path)
        message = openable_messages(store)[0]
        (folder,) = folders_with_messages(store)
    assert written == 1
    (back,) = records(tmp_path / mbox_name(folder))
    source = email.parser.BytesParser(policy=POLICY).parsebytes(SENT_SOURCE.read_bytes())
    assert str(back["Subject"]) == str(source["Subject"])
    assert [(a.display_name, a.addr_spec) for a in back["From"].addresses] == [
        (a.display_name, a.addr_spec) for a in source["From"].addresses
    ] == [("Devin Achterberg", "devin@example.test")]
    assert text_of(back) == text_of(source) == "Tuesday at ten works. Tablets acquired.\n\nDevin"
    assert list(back.iter_attachments()) == []
    assert from_lines(tmp_path / mbox_name(folder)) == [
        f"devin@example.test {time.asctime(message.client_submit_time.timetuple())}"
    ]


def test_the_from_line_is_the_sender_and_the_submit_time(tmp_path: Path) -> None:
    """RFC 4155 § 2's `From <addr-spec> <asctime>`, both halves out of the store."""
    with Store.open(_path(SYNTH)) as store:
        export_mbox(store.root_folder, tmp_path)
    raw = next(p for p in tmp_path.glob("*.mbox") if p.stat().st_size).read_bytes()
    assert raw.startswith(b"From devin@example.test Mon Jan  5 12:00:00 2026\n")
    assert re.match(rb"From \S+ [A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \d{4}\n", raw)


def test_a_message_with_no_address_gets_mailer_daemon(tmp_path: Path) -> None:
    none = property(lambda self: None)
    with Store.open(_path(SYNTH)) as store, mock.patch.object(Message, "sender_smtp", none), mock.patch.object(Message, "sender_email", none):
        export_mbox(store.root_folder, tmp_path)
    raw = next(p for p in tmp_path.glob("*.mbox") if p.stat().st_size).read_bytes()
    assert raw.startswith(f"From {MAILER_DAEMON} ".encode("ascii"))


def test_an_x_500_sender_is_not_an_addr_spec_and_does_not_become_one(tmp_path: Path) -> None:
    """`PidTagSenderEmailAddress` on an Exchange message is a distinguished name, not an address."""
    none = property(lambda self: None)
    with Store.open(_path("pstsdk-sample1")) as store, mock.patch.object(Message, "sender_smtp", none):
        message = openable_messages(store)[0]
        assert message.sender_email.startswith("/O=MICROSOFT")
        export_mbox(store.root_folder, tmp_path)
    lines = [line for path in tmp_path.glob("*.mbox") for line in from_lines(path)]
    assert lines and all(line.startswith(f"{MAILER_DAEMON} ") for line in lines)


def test_a_message_with_no_time_gets_the_epoch_not_the_clock(tmp_path: Path) -> None:
    """A clock in the output would make two exports of one store differ, which is the one thing forbidden."""
    none = property(lambda self: None)
    with Store.open(_path(SYNTH)) as store, mock.patch.object(Message, "client_submit_time", none), mock.patch.object(Message, "delivery_time", none):
        export_mbox(store.root_folder, tmp_path)
    raw = next(p for p in tmp_path.glob("*.mbox") if p.stat().st_size).read_bytes()
    assert raw.startswith(b"From devin@example.test Thu Jan  1 00:00:00 1970\n")


# --- every store ------------------------------------------------------------------


@pytest.mark.parametrize("store_path", UNICODE_STORES, ids=UNICODE_IDS)
def test_every_store_exports_every_folder_and_reads_back(store_path: Path, tmp_path: Path) -> None:
    """One file per folder, the store's own message count in it, and `mailbox` agrees."""
    expected: dict[str, int] = {}
    with Store.open(store_path) as store:
        written = export_mbox(store.root_folder, tmp_path)
        for folder, _ in folder_paths(store.root_folder):
            try:
                expected[mbox_name(folder)] = len(list(readable_messages(folder)))
            except PstError:
                expected[mbox_name(folder)] = -1  # the folder's contents table refuses
    assert written == OPENABLE[store_path.stem]
    index = index_of(tmp_path)
    assert set(index) == set(expected), store_path.stem
    for name, count in expected.items():
        if count < 0:
            assert not (tmp_path / name).exists(), f"{store_path.stem} {name}: a refused folder writes no mbox"
            continue
        got = records(tmp_path / name)
        assert len(got) == count, f"{store_path.stem} {name}"
        assert len(from_lines(tmp_path / name)) == count, f"{store_path.stem} {name}"
        for line in from_lines(tmp_path / name):
            assert re.fullmatch(r"\S+ [A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \d{4}", line), line
        for message in got:
            assert message.get_content_type() != ""
    assert sum(max(c, 0) for c in expected.values()) == written


@pytest.mark.parametrize("store_path", UNICODE_STORES, ids=UNICODE_IDS)
def test_two_exports_of_one_store_are_byte_identical(store_path: Path, tmp_path: Path) -> None:
    with Store.open(store_path) as store:
        export_mbox(store.root_folder, tmp_path)
        first = {p.name: p.read_bytes() for p in sorted(tmp_path.iterdir())}
        export_mbox(store.root_folder, tmp_path)
        second = {p.name: p.read_bytes() for p in sorted(tmp_path.iterdir())}
    assert first == second, f"{store_path.stem}: an export that is not reproducible cannot be diffed"
    assert first, store_path.stem


def test_an_existing_mbox_is_replaced_not_appended_to(tmp_path: Path) -> None:
    with Store.open(_path(SYNTH)) as store:
        assert export_mbox(store.root_folder, tmp_path) == 1
        assert export_mbox(store.root_folder, tmp_path) == 1
    assert sum(len(records(p)) for p in tmp_path.glob("*.mbox")) == 1


# --- the format's own trap --------------------------------------------------------


def test_a_body_line_that_begins_with_from_survives_the_round_trip(tmp_path: Path) -> None:
    """The one thing an mbox writer can get wrong: a body line that looks like a separator.

    The stdlib quotes it to `>From ` on write and does not unquote it on
    read (the classic mboxo rule). What must hold — and what this asserts —
    is that the message does not SPLIT: one message in, one message out,
    and the original body one `>` away.
    """
    body = "Tuesday at ten works.\nFrom the desk of Devin\n>From an already-quoted line\nEnd.\n"
    with Store.open(_path(SYNTH)) as store, mock.patch.object(Message, "body_text", property(lambda self: body)):
        assert export_mbox(store.root_folder, tmp_path) == 1
    path = next(p for p in tmp_path.glob("*.mbox") if p.stat().st_size)
    raw = path.read_bytes()
    assert raw.count(b"\nFrom ") == 0, "no body line may look like a record separator"
    assert b"\n>From the desk of Devin\n" in raw
    (back,) = records(path)
    got = text_of(back)
    # What the stdlib implements is mboxo, not mboxrd: a line that was
    # ALREADY quoted is left alone, so `>From ` on the way in and `>From `
    # on the way out are indistinguishable. That ambiguity is the format's,
    # it is recorded in `pypstreader.mbox`'s docstring, and it is pinned here so
    # that a stdlib change is noticed rather than discovered downstream.
    assert got.splitlines() == [
        "Tuesday at ten works.",
        ">From the desk of Devin",
        ">From an already-quoted line",
        "End.",
    ]
    assert body.splitlines()[1] == "From the desk of Devin"


# --- names, and what must never become one ---------------------------------------


def test_files_are_named_from_node_ids_and_display_names_live_in_the_index(tmp_path: Path) -> None:
    with Store.open(_path(SYNTH)) as store:
        export_mbox(store.root_folder, tmp_path)
    for path in tmp_path.glob("*.mbox"):
        assert re.fullmatch(r"[0-9a-f]{8}\.mbox", path.name), path.name
    index = index_of(tmp_path)
    assert "Top of Personal Folders/Top of Personal Folders/Sent" in index.values()
    assert any("Inbox" in value for value in index.values())


def test_a_folder_named_like_a_path_cannot_become_one(tmp_path: Path) -> None:
    renamed = mock.patch.object(Folder, "display_name", property(lambda self: "../../../etc"))
    with Store.open(_path(SYNTH)) as store, renamed:
        export_mbox(store.root_folder, tmp_path, recurse=False)
    assert [p.name for p in tmp_path.glob("*.mbox")] == [f"{0x122:08x}.mbox"]
    assert list(index_of(tmp_path).values()) == ["..\u2215..\u2215..\u2215etc"]
    assert not (tmp_path.parent / "etc").exists()


def test_a_refused_folder_is_recorded_in_the_index_and_strict_propagates(tmp_path: Path) -> None:
    """`synth-basics.pst`'s Inbox: skipped by default, with the reason's TYPE and nothing else."""
    with Store.open(_path(SYNTH)) as store:
        export_mbox(store.root_folder, tmp_path)
        with pytest.raises(PstFormatError, match="cFree"):
            export_mbox(store.root_folder, tmp_path / "strict", strict=True)
    lines = (tmp_path / INDEX_NAME).read_text(encoding="utf-8").splitlines()
    skipped = [line for line in lines if "# skipped:" in line]
    assert len(skipped) == 1 and skipped[0].endswith("# skipped: PstFormatError")
    assert "Inbox" in skipped[0]


def test_export_mbox_refuses_a_non_folder(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="takes a Folder"):
        export_mbox("not a folder", tmp_path)  # type: ignore[arg-type]


# --- private stores: counts only --------------------------------------------------


@pytest.mark.private
def test_private_stores_export_to_mbox_and_nothing_about_them_is_printed(private_stores: list[Path], tmp_path: Path) -> None:
    if not private_stores:
        pytest.skip("no stores in tests/fixtures/private/")
    for index, path in enumerate(private_stores):
        dest = tmp_path / f"store-{index}"
        with Store.open(path) as store:
            written = export_mbox(store.root_folder, dest)
            expected = len(openable_messages(store))
        assert written == expected, f"private store {index}"
        assert sum(len(records(p)) for p in dest.glob("*.mbox")) == written, f"private store {index}"
        for mbox_path in dest.glob("*.mbox"):
            assert re.fullmatch(r"[0-9a-f]{8}\.mbox", mbox_path.name)
        assert (dest / INDEX_NAME).exists(), f"private store {index}"
