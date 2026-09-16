"""`pypstreader.eml` — the `.eml` assembler, its header policy, and the ways it must refuse.

This row has no oracle: upstream ships no export format at all (ten example
binaries that dump layers as text, and nothing that produces mail), so the
evidence here is of three other kinds.

1. **A round trip.** `tests/fixtures/public/synth-basics.pst` was built by
   EMLtoPST from `tests/fixtures/synthetic/basics/**/*.eml`, so for the one
   message of that store this reader can reach — the Sent folder's; the
   Inbox's contents table is refused by this reader and by upstream alike,
   `tests/test_synthetic_content.py` § UNREADABLE_CONTENTS — the source
   `.eml` IS the expected output, and it is compared field by field.
2. **The corpus, swept.** Every openable message of every Unicode store is
   assembled, serialised, re-parsed and compared with itself: same headers,
   same part tree, every payload decodes, and two calls agree byte for byte.
   Counts are pinned per store so a message that stops opening is a failure
   rather than a smaller number.
3. **Denial first.** A ceiling that bites, a mutation family swept through
   the assembler, and the injection cases — a `PidTagAttachMimeTag` with a
   CRLF in it, an attachment filename of `../../etc/passwd` — which is where
   an exporter is actually dangerous, because it is the layer that turns
   attacker-controlled bytes into header text and file names.

Corpus content is public and is asserted on directly. Private stores appear
once, at the bottom, counted and never quoted.
"""

from __future__ import annotations

import dataclasses
import email.parser
import email.policy
import email.utils
import io
import re
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from pypstreader import debug
from pypstreader.eml import (
    BODY_HEADER,
    POLICY,
    SKIPPED_HEADER,
    SYNTHESIZED_HEADER,
    eml_bytes,
    eml_name,
    export_folder,
    folder_paths,
    readable_messages,
    to_eml,
    write_eml,
)
from pypstreader.errors import PstError, PstFormatError, PstLimitError
from pypstreader.limits import DEFAULT_LIMITS
from pypstreader.messaging.attachment import AttachMethod
from pypstreader.messaging.folder import Folder
from pypstreader.messaging.message import Message
from pypstreader.messaging.store import Store
from pypstreader.ndb.ids import NodeId, NodeIdType
from tests import corrupt, corruption_harness
from tests.conftest import FIXTURES, REPO, public_fixture_paths

ANSI_STORES = {"pstsdk-sample2", "pstsdk-test_ansi"}
ALL_STORES = [FIXTURES / "Empty.pst", *public_fixture_paths()]
UNICODE_STORES = [p for p in ALL_STORES if p.stem not in ANSI_STORES]
UNICODE_IDS = [p.stem for p in UNICODE_STORES]

SUBMESSAGE = "pstsdk-submessage"
SAMPLE1 = "pstsdk-sample1"
DIST_LIST = "javalibpst-dist-list"
BODIES = "tika-variousBodyTypes"
SYNTH = "synth-basics"

SENT_SOURCE = REPO / "tests" / "fixtures" / "synthetic" / "basics" / "Sent" / "01-reply.eml"

# Every message this reader can open, per store. Pinned: a store that stops
# yielding one of these has regressed, and a smaller number is not a pass.
# `pstd-inline-cid.pst` has no readable folder below its root (P06/P08), so
# its inline-cid message — which would have been this row's witness for a
# `cid:` reference — is not reachable through EITHER reader, and the inline
# case is built by hand below instead.
OPENABLE = {
    "Empty": 0,
    "javalibpst-dist-list": 3,
    "pstd-inline-cid": 0,
    "pstsdk-sample1": 1,
    "pstsdk-submessage": 1,
    "pstsdk-test_unicode": 2,
    "synth-basics": 1,
    "tika-variousBodyTypes": 4,
}

# P09's measurement, re-taken here through the assembler: 6 of the 12
# openable corpus messages carry `PidTagTransportMessageHeaders` and 6 do not,
# and the split follows the message class rather than the store.
WITH_TRANSPORT_HEADERS = 6


def _path(stem: str) -> Path:
    return next(p for p in ALL_STORES if p.stem == stem)


def _message_nid(index: int) -> NodeId:
    return NodeId.from_parts(NodeIdType.NORMAL_MESSAGE, index)


def openable_messages(store: Store) -> list[Message]:
    """Every message of every folder that opens — the exporters' own view of a store."""
    out: list[Message] = []
    for folder, _ in folder_paths(store.root_folder):
        try:
            out.extend(readable_messages(folder))
        except PstError:  # the folder's contents table; asserted where it belongs
            continue
    return out


def folders_with_messages(store: Store) -> list[Any]:
    """Every folder whose contents table both parses and holds a message that opens."""
    out = []
    for folder, _ in folder_paths(store.root_folder):
        try:
            if list(readable_messages(folder)):
                out.append(folder)
        except PstError:  # the folder's contents table; asserted where it belongs
            continue
    return out


def headers_of(message: Any) -> list[tuple[str, str]]:
    return [(name, str(value)) for name, value in message.items()]


def parts_of(message: Any) -> list[str]:
    return [part.get_content_type() for part in message.walk()]


def reparse(data: bytes) -> Any:
    return email.parser.BytesParser(policy=POLICY).parsebytes(data)


def synthesized(built: Any) -> list[str]:
    value = built[SYNTHESIZED_HEADER]
    return [] if value is None else [name.strip() for name in str(value).split(",")]


def text_of(message: Any) -> str:
    """The plain-text body, newline-normalised: the MIME layer, not this module, picks line endings."""
    part = message.get_body(preferencelist=("plain",))
    assert part is not None
    return part.get_content().replace("\r\n", "\n").rstrip("\n")


# --- the policy, which is a decision and therefore a test --------------------------


def test_the_policy_is_smtp_with_seven_bit_bodies() -> None:
    """CRLF line endings (RFC 5322) and everything transfer-encoded down to ASCII."""
    assert POLICY.linesep == "\r\n"
    assert POLICY.cte_type == "7bit"
    assert POLICY.utf8 is False, "an 8-bit header would not survive every transport"


# --- 1. the round trip against the source the fixture was built from ---------------


@pytest.fixture(scope="module")
def sent_message():
    with Store.open(_path(SYNTH)) as store:
        messages = openable_messages(store)
        assert len(messages) == 1, "synth-basics has exactly one reachable message, the Sent folder's"
        yield messages[0]


def test_synth_basics_sent_round_trips_to_its_source_eml(sent_message: Message) -> None:
    """The one message of the corpus whose expected `.eml` is a file in this repository."""
    source = email.parser.BytesParser(policy=POLICY).parsebytes(SENT_SOURCE.read_bytes())
    built = to_eml(sent_message)

    assert str(built["Subject"]) == str(source["Subject"]) == "Re: Plain text: the kettle schedule"
    for header in ("From", "To"):
        got = [(a.display_name, a.addr_spec) for a in built[header].addresses]
        want = [(a.display_name, a.addr_spec) for a in source[header].addresses]
        assert got == want, header
    assert built["Date"].datetime == source["Date"].datetime, "equal to the second, in UTC"
    assert text_of(built) == text_of(source) == "Tuesday at ten works. Tablets acquired.\n\nDevin"
    assert list(built.iter_attachments()) == list(source.iter_attachments()) == []
    assert built.get_content_type() == source.get_content_type() == "text/plain"


def test_the_round_trip_says_which_headers_it_rebuilt(sent_message: Message) -> None:
    """EMLtoPST keeps no transport headers, so every header here is rebuilt — and says so.

    Each rebuilt header reproduces the source's value (the test above), with
    one exception that the marker exists for: the `Message-ID`. The tool
    wrote neither `PidTagTransportMessageHeaders` nor
    `PidTagInternetMessageId`, so the source's
    `<synth-basics-sent-01@example.test>` is simply not in the store, and
    what comes out is a deterministic id under `pypstreader.invalid` — never the
    source's id, and never presented as original.
    """
    built = to_eml(sent_message)
    assert sent_message.transport_headers is None
    assert synthesized(built) == ["From", "To", "Subject", "Date", "Message-ID"]
    source = email.parser.BytesParser(policy=POLICY).parsebytes(SENT_SOURCE.read_bytes())
    assert str(source["Message-ID"]) == "<synth-basics-sent-01@example.test>"
    assert str(built["Message-ID"]).endswith("@pypstreader.invalid>")
    assert str(built["Message-ID"]) == f"<pypstreader-{sent_message.store.record_key.hex()}-{sent_message.node.raw:08x}@pypstreader.invalid>"


def test_synthesize_missing_false_writes_only_what_the_file_holds(sent_message: Message) -> None:
    built = to_eml(sent_message, synthesize_missing=False)
    assert built["From"] is None and built["Subject"] is None and built["Message-ID"] is None
    assert built[SYNTHESIZED_HEADER] is None
    assert text_of(built).startswith("Tuesday at ten works")


# --- 2. every openable message of every Unicode store -----------------------------


@pytest.mark.parametrize("store_path", UNICODE_STORES, ids=UNICODE_IDS)
def test_every_openable_message_assembles_and_survives_a_reparse(store_path: Path) -> None:
    """Assemble, serialise, re-parse: the same headers, the same parts, every payload decodable."""
    seen = 0
    with Store.open(store_path) as store:
        for message in openable_messages(store):
            seen += 1
            built = to_eml(message)
            data = eml_bytes(message)
            where = f"{store_path.stem} {message.node}"
            assert data.isascii(), f"{where}: the 7-bit policy did not hold"
            assert data.endswith(b"\n") and b"\r\n" in data, where
            assert data == eml_bytes(message), f"{where}: two calls must agree byte for byte"
            back = reparse(data)
            assert headers_of(back) == headers_of(built), where
            assert parts_of(back) == parts_of(built), where
            # RFC 2045 § 4: `MIME-Version` belongs to the message and not to
            # its parts — and an ENCAPSULATED message is a message.
            encapsulated = {id(p.get_payload()[0]) for p in back.walk() if p.get_content_type() == "message/rfc822"}
            for part in back.walk():
                if part is not back and id(part) not in encapsulated:
                    assert part["MIME-Version"] is None, f"{where}: {part.get_content_type()}"
            for part in back.walk():
                if part.is_multipart():  # a multipart, or an encapsulated message: a list, not bytes
                    continue
                assert part.get_payload(decode=True) is not None, f"{where}: {part.get_content_type()}"
    assert seen == OPENABLE[store_path.stem], store_path.stem


def test_the_corpus_holds_twelve_openable_messages() -> None:
    """The denominator every count in this file is a fraction of."""
    assert sum(OPENABLE.values()) == 12


# --- 3. the header policy: pass through, else synthesise and say so ----------------


@pytest.mark.parametrize("store_path", UNICODE_STORES, ids=UNICODE_IDS)
def test_transport_headers_are_passed_through_and_the_rest_is_marked(store_path: Path) -> None:
    """The decision this module is built around, asserted on every message that has one."""
    with Store.open(store_path) as store:
        for message in openable_messages(store):
            built = to_eml(message)
            raw = message.transport_headers
            where = f"{store_path.stem} {message.node}"
            if raw:
                source = email.parser.Parser(policy=POLICY).parsestr(raw, headersonly=True)
                assert str(built["Message-ID"]) == str(source["Message-ID"]), where
                assert "Message-ID" not in synthesized(built), where
                for name, value in source.items():
                    got = [str(v) for v in built.get_all(name, [])]
                    if name.lower() == "mime-version" or not str(value).strip():
                        continue  # "1.0" either way; an empty header carries nothing to pass through
                    if name.lower().startswith("content-"):
                        # The body here is re-assembled, so these describe a
                        # structure that is not the one being written.
                        assert str(value) not in got, f"{where}: {name} describes the ORIGINAL body"
                    else:
                        assert str(value) in got, f"{where}: {name}"
                assert len(built.get_all("Content-Type", [])) == 1, where
                assert len(built.get_all("MIME-Version", [])) == 1, where
                if built.is_multipart():
                    assert built.get_boundary().startswith("----=_pypstreader."), where
            else:
                assert "Message-ID" in synthesized(built), where
                assert str(built["Message-ID"]).endswith("@pypstreader.invalid>"), where


BODY_HEADER_BLOB = (
    "Received: from nowhere.example.test\r\n"
    "Subject: kept\r\n"
    "MIME-Version: 1.0\r\n"
    'Content-Type: multipart/mixed; boundary="the-original-boundary"\r\n'
    "Content-Transfer-Encoding: base64\r\n"
    'Content-Disposition: attachment; filename="the-original.bin"\r\n'
    "Content-ID: <the-original-cid>\r\n"
    "Content-Length: 4096\r\n"
    "X-Kept: yes\r\n"
)


def test_the_original_bodys_headers_are_not_passed_through() -> None:
    """They describe a MIME structure that is not the one being written.

    No corpus store exercises this — Exchange strips the `Content-*` headers
    out of `PidTagTransportMessageHeaders` before it stores them — so the
    blob is written here, with one of each and two headers that must
    survive.
    """
    blob = property(lambda self: BODY_HEADER_BLOB)
    with Store.open(_path(SYNTH)) as store, mock.patch.object(Message, "transport_headers", blob):
        built = to_eml(openable_messages(store)[0])
    assert str(built["Subject"]) == "kept" and str(built["X-Kept"]) == "yes"
    assert str(built["Received"]) == "from nowhere.example.test"
    assert len(built.get_all("MIME-Version", [])) == len(built.get_all("Content-Type", [])) == 1
    assert built["Content-Transfer-Encoding"] == "7bit", "ours, describing the body we wrote"
    assert built["Content-Disposition"] is None and built["Content-ID"] is None
    assert built["Content-Length"] is None
    data = eml_bytes_of(built)
    assert b"the-original-boundary" not in data and b"the-original.bin" not in data
    assert b"the-original-cid" not in data and b"4096" not in data


def eml_bytes_of(built: Any) -> bytes:
    return built.as_bytes(policy=POLICY)


def test_six_of_the_twelve_openable_messages_carry_transport_headers() -> None:
    """P09's measurement, re-taken through the assembler — the number this design rests on."""
    with_headers, without = [], []
    for store_path in UNICODE_STORES:
        with Store.open(store_path) as store:
            for message in openable_messages(store):
                where = f"{store_path.stem}/{message.message_class}"
                (with_headers if message.transport_headers else without).append(where)
    assert len(with_headers) == WITH_TRANSPORT_HEADERS
    assert len(without) == 12 - WITH_TRANSPORT_HEADERS
    assert {w.split("/")[1] for w in with_headers} == {"IPM.Note"}, "delivered IPM.Notes have them"
    assert "IPM.Appointment" in {w.split("/")[1] for w in without}


def test_a_delivered_message_keeps_its_message_id_byte_for_byte() -> None:
    """The one header a threading decision is made from, on a real Exchange message."""
    want = "<B2FDDB8BE384C94794441DB4A7F3D8B804AF79BC@TK5EX14MBXC114.redmond.corp.microsoft.com>"
    with Store.open(_path(SUBMESSAGE)) as store:
        data = eml_bytes(store.open_message(_message_nid(0x10001)))
    assert f"Message-ID: {want}\r\n".encode("ascii") in data
    assert SYNTHESIZED_HEADER.encode() + b": Message-ID" not in data
    assert b"pypstreader.invalid" not in data


def test_a_stored_internet_message_id_is_used_instead_of_an_invented_one() -> None:
    """`PidTagInternetMessageId` is the real id even where the transport headers are gone."""
    with Store.open(_path(SYNTH)) as store:
        message = openable_messages(store)[0]
        with mock.patch.object(Message, "get", lambda self, pid: "<kept@example.test>" if pid == 0x1035 else None):
            built = to_eml(message)
    assert str(built["Message-ID"]) == "<kept@example.test>"
    assert "Message-ID" in synthesized(built), "the HEADER is still ours, and says so"
    assert "pypstreader.invalid" not in str(built["Message-ID"]), "the VALUE is the store's, and is not marked invalid"


# --- 4. the three body kinds ------------------------------------------------------


@pytest.mark.parametrize(
    ("index", "expected"),
    [
        (0x10001, ["multipart/alternative", "text/plain", "text/html"]),
        (0x10002, ["multipart/alternative", "text/plain", "text/html"]),
        (0x10003, ["multipart/alternative", "text/plain", "application/rtf"]),
        (0x10004, ["text/plain"]),
    ],
)
def test_every_body_shape_in_the_corpus_renders_as_documented(index: int, expected: list[str]) -> None:
    """`tika-variousBodyTypes.pst` is the store that has one message per body kind."""
    with Store.open(_path(BODIES)) as store:
        built = to_eml(store.open_message(_message_nid(index)))
    assert parts_of(built) == expected
    assert built[BODY_HEADER] is None, "there is a text body, so nothing to warn about"
    if "application/rtf" in expected:
        rtf = next(p for p in built.walk() if p.get_content_type() == "application/rtf")
        assert rtf.get_payload(decode=True).startswith(b"{\\rtf1")


def test_an_rtf_only_body_is_attached_as_rtf_and_no_text_is_invented() -> None:
    """No corpus message has RTF alone, so the case is made by removing the text body from one that does."""
    with Store.open(_path(BODIES)) as store:
        message = store.open_message(_message_nid(0x10003))
        with mock.patch.object(Message, "body_text", property(lambda self: None)):
            built = to_eml(message)
    assert parts_of(built) == ["application/rtf"]
    assert str(built[BODY_HEADER]) == "rtf-only"
    assert built.get_payload(decode=True).startswith(b"{\\rtf1")


def test_a_message_with_no_body_at_all_says_so() -> None:
    with Store.open(_path(BODIES)) as store:
        message = store.open_message(_message_nid(0x10004))
        with (
            mock.patch.object(Message, "body_text", property(lambda self: None)),
            mock.patch.object(Message, "body_html", property(lambda self: None)),
            mock.patch.object(Message, "body_rtf", property(lambda self: None)),
        ):
            built = to_eml(message)
    assert parts_of(built) == ["text/plain"]
    assert str(built[BODY_HEADER]) == "none"
    assert built.get_content().strip() == ""


def test_the_html_charset_comes_from_the_message_and_the_part_is_utf_eight() -> None:
    """`PidTagInternetCodepage` 20127 is us-ascii; the part is re-encoded, never re-declared."""
    with Store.open(_path(BODIES)) as store:
        message = store.open_message(_message_nid(0x10001))
        assert message.get(0x3FDE) == 20127
        built = to_eml(message)
    html = next(p for p in built.walk() if p.get_content_type() == "text/html")
    assert html.get_content_charset() == "utf-8"
    assert "<html" in html.get_content()


# --- 5. attachments, embedded messages, and the parts they become -----------------


def test_an_unusable_code_page_falls_back_to_utf_eight_rather_than_refusing() -> None:
    """The last fallback in `_charset`: a store opened with a code page Python has no codec for.

    Reachable only this way — `PidTagInternetCodepage` names a real code page
    on every corpus message that has HTML, and `Store`'s own default is
    `cp1252` — and it must not be an exception: the body is bytes either way
    and `errors="replace"` is what a reader wants from a mislabelled one.
    """
    # `PidTagInternetCodepage` names a real code page on this message, so it
    # has to go too before the store's (unusable) one is even consulted.
    no_codepage = mock.patch.object(
        Message, "get", lambda self, pid: None if pid == 0x3FDE else Message.properties.fget(self).get(pid)
    )
    with Store.open(_path(BODIES), codepage="definitely-not-a-codec") as store, no_codepage:
        built = to_eml(store.open_message(_message_nid(0x10001)))
    html = next(p for p in built.walk() if p.get_content_type() == "text/html")
    assert html.get_content_charset() == "utf-8"
    assert "<html" in html.get_content()


def test_a_by_value_attachment_becomes_a_part_with_its_bytes() -> None:
    with Store.open(_path(SAMPLE1)) as store:
        message = store.open_message(_message_nid(0x10001))
        (attachment,) = list(message.attachments())
        name, payload = attachment.long_filename, attachment.data()
        built = to_eml(message)
    (part,) = list(built.iter_attachments())
    assert part.get_filename() == name == "leah_thumper.jpg"
    assert part.get_payload(decode=True) == payload
    assert len(part.get_payload(decode=True)) == 93142
    assert part.get_content_type() == "application/octet-stream", "the store kept no PidTagAttachMimeTag"
    assert part.get_content_disposition() == "attachment"


def test_an_embedded_message_becomes_a_message_rfc822_part() -> None:
    """The divergence P09 landed, carried through to the export: upstream cannot open this at all."""
    with Store.open(_path(SUBMESSAGE)) as store:
        built = to_eml(store.open_message(_message_nid(0x10001)))
    (part,) = [p for p in built.walk() if p.get_content_type() == "message/rfc822"]
    inner = part.get_payload()[0]
    assert str(inner["Subject"]) == "This is an embedded message"
    assert text_of(inner).startswith("This is the body of an embedded message")
    # This embedded message kept transport headers of its OWN, so its
    # Message-ID is passed through like any other delivered message's.
    assert str(inner["Message-ID"]).endswith("@TK5EX14MBXC114.redmond.corp.microsoft.com>")
    assert str(inner["Message-ID"]) != str(built["Message-ID"])
    assert "Message-ID" not in synthesized(inner)


def test_an_encapsulated_message_keeps_its_own_mime_version() -> None:
    """The one `MIME-Version` that is not this message's own is left where it belongs."""
    with Store.open(_path(SUBMESSAGE)) as store:
        built = to_eml(store.open_message(_message_nid(0x10001)))
    assert str(built["MIME-Version"]) == "1.0"
    inner = next(p for p in built.walk() if p.get_content_type() == "message/rfc822").get_payload()[0]
    assert str(inner["MIME-Version"]) == "1.0", "the encapsulated message is a message, not a part"
    assert built.get_payload()[0]["MIME-Version"] is None, "our own multipart is a part, and carries none"


def test_a_non_ascii_body_is_encoded_down_to_seven_bits_and_decodes_back() -> None:
    """The policy's whole point: the bytes on disk are ASCII and the text survives them."""
    text = "Gr\u00fc\u00dfe \u2014 \u30c6\u30b9\u30c8 \u0447\u0430\u0439"
    with Store.open(_path(SYNTH)) as store, mock.patch.object(Message, "body_text", property(lambda self: text)):
        message = openable_messages(store)[0]
        data = eml_bytes(message)
    assert data.isascii(), "a non-ASCII body must not reach the file as 8-bit"
    assert text.encode("utf-8") not in data
    assert text_of(reparse(data)) == text


def test_an_embedded_messages_synthetic_id_is_derived_from_its_carriers() -> None:
    """Sub-node ids repeat between trees, so the carrier's id is what makes the inner one unique.

    The corpus's one embedded message has transport headers of its own, so
    the case where an id must be invented for it is reached by taking them
    away — from carrier and embedded alike, which is the shape every
    locally-composed message has.
    """
    no_headers = mock.patch.object(Message, "transport_headers", property(lambda self: None))
    # This store ALSO keeps `PidTagInternetMessageId`, which is the real id
    # and is preferred over an invented one; a locally-composed message has
    # neither, which is the shape being built here.
    no_stored_id = mock.patch.object(Message, "get", lambda self, pid: None if pid == 0x1035 else Message.properties.fget(self).get(pid))
    with Store.open(_path(SUBMESSAGE)) as store, no_headers, no_stored_id:
        message = store.open_message(_message_nid(0x10001))
        built = to_eml(message)
        (attachment,) = list(message.attachments())
        embedded_nid = attachment.embedded_message().node.raw
    inner = next(p for p in built.walk() if p.get_content_type() == "message/rfc822").get_payload()[0]
    carrier_local = str(built["Message-ID"]).lstrip("<").split("@")[0]
    assert str(built["Message-ID"]).endswith("@pypstreader.invalid>")
    assert str(inner["Message-ID"]) == f"<{carrier_local}.{embedded_nid:08x}@pypstreader.invalid>"


# --- 6. the parts a corpus store cannot witness: inline cid, and injection --------


class FakeAttachment:
    """The attachment shapes no reachable corpus message has — built, not corrupted.

    `pstd-inline-cid.pst` would have been the witness for a `cid:` reference
    and `synth-basics.pst` for a typed attachment, and neither message is
    reachable (see `OPENABLE`). Everything `_add_attachments` asks of an
    attachment is here and nothing else is, so what these exercise is the
    assembler's own branching.
    """

    def __init__(self, method: AttachMethod, *, data: bytes | None = b"x", mime_tag=None, content_id=None, long_filename=None, filename=None) -> None:
        self.method = method
        self._data = data
        self.mime_tag = mime_tag
        self.content_id = content_id
        self.long_filename = long_filename
        self.filename = filename
        self.node = NodeId.from_parts(NodeIdType.ATTACHMENT, 1)

    def data(self) -> bytes | None:
        return self._data


class FakeMessage:
    def __init__(self, attachments: list[FakeAttachment]) -> None:
        self._attachments = attachments

    def attachments(self):
        return iter(self._attachments)


def build_with(attachments: list[FakeAttachment], *, html: str | None = None) -> Any:
    from email.message import EmailMessage

    from pypstreader import eml as eml_mod

    msg = EmailMessage(policy=POLICY)
    msg.set_content("text body")
    if html is not None:
        msg.add_alternative(html, subtype="html")
    eml_mod._add_attachments(msg, FakeMessage(attachments), DEFAULT_LIMITS, depth=0, prefix=None)
    eml_mod._clean_subpart_headers(msg)
    eml_mod._set_boundaries(msg, "fake")
    return msg


def test_an_inline_image_the_html_references_becomes_a_related_part() -> None:
    png = b"\x89PNG\r\n\x1a\nnot really"
    built = build_with(
        [FakeAttachment(AttachMethod.BY_VALUE, data=png, mime_tag="image/png", content_id="<img1>", long_filename="swatch.png")],
        html='<p>see <img src="cid:img1"></p>',
    )
    assert parts_of(built) == ["multipart/alternative", "text/plain", "multipart/related", "text/html", "image/png"]
    part = next(p for p in built.walk() if p.get_content_type() == "image/png")
    assert part.get_content_disposition() == "inline"
    assert part["Content-ID"] == "<img1>"
    assert part.get_payload(decode=True) == png


def test_a_content_id_the_html_does_not_reference_is_an_attachment() -> None:
    built = build_with(
        [FakeAttachment(AttachMethod.BY_VALUE, mime_tag="image/png", content_id="<other>", long_filename="x.png")],
        html="<p>no image here</p>",
    )
    (part,) = list(built.iter_attachments())
    assert part.get_content_disposition() == "attachment"
    assert part["Content-ID"] == "<other>"


@pytest.mark.parametrize(
    "tag",
    [
        "text/plain\r\nBcc: victim@example.test",
        "text/plain\nBcc: victim@example.test",
        "text/plain; charset=\"x\"\r\n\r\nbody",
        "not a type",
        "text/",
        "/plain",
        "",
        "text/plain; charset=utf-8",
    ],
)
def test_a_mime_tag_cannot_inject_a_header(tag: str) -> None:
    """`PidTagAttachMimeTag` is attacker-controlled text that becomes a `Content-Type`."""
    built = build_with([FakeAttachment(AttachMethod.BY_VALUE, mime_tag=tag, long_filename="a.txt")])
    (part,) = list(built.iter_attachments())
    assert part["Bcc"] is None and built["Bcc"] is None
    assert part.get_content_type() in {"application/octet-stream", "text/plain"}
    data = built.as_bytes(policy=POLICY)
    assert b"victim@example.test" not in data
    assert b"\r\n\r\nbody" not in data.split(b"a.txt", 1)[0]


@pytest.mark.parametrize("name", ["../../etc/passwd", "..\\..\\windows\\system32\\x", "a\r\nBcc: victim@example.test", "\x00null"])
def test_an_attachment_filename_is_sanitised_and_never_a_path(name: str, tmp_path: Path) -> None:
    built = build_with([FakeAttachment(AttachMethod.BY_VALUE, long_filename=name)])
    (part,) = list(built.iter_attachments())
    filename = part.get_filename()
    assert "\r" not in filename and "\n" not in filename and "\x00" not in filename
    assert built["Bcc"] is None and part["Bcc"] is None
    data = built.as_bytes(policy=POLICY)
    assert b"\r\nBcc:" not in data, "a header can only be injected by a line break, and there is none"
    assert data.count(b"Content-Disposition:") == 1


@pytest.mark.parametrize("method", [AttachMethod.NONE, AttachMethod.BY_REFERENCE, AttachMethod.BY_REF_RESOLVE, AttachMethod.BY_REF_ONLY])
def test_an_attachment_with_no_bytes_here_is_recorded_not_dropped(method: AttachMethod) -> None:
    built = build_with([FakeAttachment(method, data=None, long_filename="on-the-file-server.docx")])
    assert list(built.iter_attachments()) == []
    assert str(built[SKIPPED_HEADER]) == f"{method.name} on-the-file-server.docx"


def test_the_skipped_header_names_an_unnamed_attachment_too() -> None:
    built = build_with([FakeAttachment(AttachMethod.BY_REFERENCE, data=None)])
    assert str(built[SKIPPED_HEADER]) == "BY_REFERENCE (unnamed)"


def _with_body(html: str) -> Any:
    from email.message import EmailMessage

    from pypstreader import eml as eml_mod

    msg = EmailMessage(policy=POLICY)
    msg.set_content("text body")
    msg.add_alternative(html, subtype="html")
    eml_mod._set_boundaries(msg, "t")
    return msg


def test_a_body_that_contains_the_boundary_pushes_it_aside() -> None:
    """The boundary must not occur in what it delimits, whatever the body says."""
    built = _with_body("<p>----=_pypstreader.t.0 is in the body</p>")
    assert built.get_boundary() == "----=_pypstreader.t.0.1"
    assert built.get_boundary().encode() not in built.get_payload()[1].get_content().encode()


def test_a_body_that_contains_every_counter_is_answered_with_a_hash() -> None:
    """The tag is derived from a node id the FILE chose, so the counter sequence is predictable.

    Counting up for as long as a crafted body wants is a scan of the payload
    per attempt; after `_BOUNDARY_ATTEMPTS` the search ends with a hash of
    the payload, which the payload cannot contain without a preimage.
    """
    from pypstreader import eml as eml_mod

    # Short lines, so the part stays 7-bit and the text reaches the file
    # verbatim: quoted-printable would escape the `=` and collide with
    # nothing, which is itself worth knowing.
    collide = "\n".join(f"----=_pypstreader.t.0.{i}" for i in range(1, eml_mod._BOUNDARY_ATTEMPTS + 4))
    built = _with_body(f"<p>\n----=_pypstreader.t.0\n{collide}\n</p>")
    boundary = built.get_boundary()
    assert re.fullmatch(r"----=_pypstreader\.t\.0\.[0-9a-f]{32}", boundary), boundary
    assert boundary not in built.get_payload()[1].get_content()
    assert boundary.encode() in built.as_bytes(policy=POLICY)


# --- 7. denial --------------------------------------------------------------------


def test_an_attachment_larger_than_max_allocation_is_refused() -> None:
    """The caller's ceiling, not the store's: `data()` already returned the bytes."""
    tight = dataclasses.replace(DEFAULT_LIMITS, max_allocation=1000)
    with Store.open(_path(SAMPLE1)) as store:
        message = store.open_message(_message_nid(0x10001))
        with pytest.raises(PstLimitError, match="exceeds limit 1000"):
            to_eml(message, limits=tight)
        assert to_eml(message, limits=dataclasses.replace(DEFAULT_LIMITS, max_allocation=93142)) is not None


def test_embedding_deeper_than_the_ceiling_is_refused_by_the_exporter() -> None:
    """Counted from `Message.depth`, so a carrier at the ceiling refuses before it recurses."""
    tight = dataclasses.replace(DEFAULT_LIMITS, max_embedded_message_depth=1)
    with Store.open(_path(SUBMESSAGE)) as store:
        deep = Message(store, _message_nid(0x10001), depth=1)
        with pytest.raises(PstLimitError, match="embedded message depth in .eml export"):
            to_eml(deep, limits=tight)
        assert to_eml(store.open_message(_message_nid(0x10001)), limits=tight) is not None


def test_a_message_whose_property_context_refuses_refuses_here() -> None:
    """A `PstError` out of any accessor is a `PstError` out of the assembler."""
    bad_body = mock.patch.object(
        Message, "body_text", property(lambda self: (_ for _ in ()).throw(PstFormatError("bad body")))
    )
    with Store.open(_path(SAMPLE1)) as store, bad_body, pytest.raises(PstFormatError, match="bad body"):
        to_eml(store.open_message(_message_nid(0x10001)))


def test_to_eml_refuses_a_non_message() -> None:
    with pytest.raises(TypeError, match="takes a Message"):
        to_eml("not a message")  # type: ignore[arg-type]
    with Store.open(_path(SAMPLE1)) as store, pytest.raises(TypeError, match="takes a Limits"):
        to_eml(store.open_message(_message_nid(0x10001)), limits=16)  # type: ignore[arg-type]


@pytest.mark.parametrize("family", ["message_lies", "attachment_lies"])
def test_every_mutation_of_a_store_exports_or_raises_a_pst_error(family: str) -> None:
    """The contract, over the two families that aim at this layer: an `.eml` or a `PstError`, nothing else."""
    base = _path(DIST_LIST).read_bytes()
    swept = 0
    for mutation in corrupt.mutations(base, seed=11):
        if not mutation.name.startswith(f"{family}:"):
            continue
        swept += 1
        try:
            corruption_harness.export_eml(io.BytesIO(mutation.data), DEFAULT_LIMITS)
        except PstError:
            continue
        except Exception as exc:  # noqa: BLE001 — the whole point is to classify what escapes
            pytest.fail(f"{mutation.name}: {type(exc).__name__}: {exc}")
    assert swept >= 2, f"{family} produced no mutations over this base"


def test_the_corruption_harness_runs_the_exporter() -> None:
    """`eml.export` is an entry point of the sweep, not only of this file."""
    data = _path(SAMPLE1).read_bytes()
    outcomes = corruption_harness.exercise(data, corruption_harness.BaseShape.of(data))
    names = [o.entry_point for o in outcomes]
    assert "eml.export" in names
    assert all(o.returned for o in outcomes if o.entry_point == "eml.export")


# --- 8. export_folder -------------------------------------------------------------


def test_export_folder_names_files_after_node_ids_and_nothing_else(tmp_path: Path) -> None:
    with Store.open(_path(SYNTH)) as store:
        message = openable_messages(store)[0]
        written = export_folder(store.root_folder, tmp_path)
    assert written == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == [eml_name(message)] == [f"{message.node.raw:08x}.eml"]
    assert re.fullmatch(r"[0-9a-f]{8}\.eml", eml_name(message))
    body = (tmp_path / eml_name(message)).read_bytes()
    assert b"kettle" in body, "the subject is in the FILE"
    assert not any("kettle" in p.name for p in tmp_path.iterdir()), "and never in its NAME"


@pytest.mark.parametrize("store_path", UNICODE_STORES, ids=UNICODE_IDS)
def test_export_folder_writes_every_openable_message(store_path: Path, tmp_path: Path) -> None:
    with Store.open(store_path) as store:
        written = export_folder(store.root_folder, tmp_path)
    assert written == OPENABLE[store_path.stem] == len(list(tmp_path.glob("*.eml")))
    for path in tmp_path.glob("*.eml"):
        assert reparse(path.read_bytes()).get_content_type() != ""


def test_export_folder_is_strict_on_request(tmp_path: Path) -> None:
    """`synth-basics.pst`'s Inbox is the folder no reader can read; `strict` says so out loud."""
    with Store.open(_path(SYNTH)) as store, pytest.raises(PstFormatError, match="cFree"):
        export_folder(store.root_folder, tmp_path, strict=True)


def test_export_folder_is_strict_about_a_message_too(tmp_path: Path) -> None:
    """`javalibpst-dist-list.pst` has one message node with no sub-node tree; `strict` stops at it."""
    with Store.open(_path(DIST_LIST)) as store:
        assert export_folder(store.root_folder, tmp_path) == OPENABLE[DIST_LIST]
        with pytest.raises(PstFormatError, match="missing sub-node tree"):
            export_folder(store.root_folder, tmp_path, strict=True)


def test_export_folder_without_recursion_writes_one_folder(tmp_path: Path) -> None:
    with Store.open(_path(BODIES)) as store:
        assert export_folder(store.root_folder, tmp_path, recurse=False) == 0
        (folder,) = folders_with_messages(store)
        assert export_folder(folder, tmp_path, recurse=False) == 4


def test_write_eml_writes_the_bytes_eml_bytes_returns(tmp_path: Path) -> None:
    with Store.open(_path(SYNTH)) as store:
        message = openable_messages(store)[0]
        path = write_eml(message, tmp_path / "one.eml")
        assert path.read_bytes() == eml_bytes(message)
        assert b"\r\n" in path.read_bytes(), "written binary, so the CRLF endings survive"


def test_folder_paths_and_readable_messages_refuse_a_non_folder() -> None:
    with pytest.raises(TypeError, match="takes a Folder"):
        list(folder_paths("nope"))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="takes a Folder"):
        list(readable_messages("nope"))  # type: ignore[arg-type]


def test_folder_paths_carries_a_display_path_that_is_never_a_path(tmp_path: Path) -> None:
    with Store.open(_path(SYNTH)) as store:
        paths = {path for _, path in folder_paths(store.root_folder)}
    assert "Top of Personal Folders/Top of Personal Folders/Sent" in paths
    renamed = mock.patch.object(Folder, "display_name", property(lambda self: "../../etc"))
    with Store.open(_path(SYNTH)) as store, renamed:
        got = [path for _, path in folder_paths(store.root_folder, recurse=False)]
    assert got == ["..∕..∕etc"], "the separators are replaced, the shape is still legible"


# --- 9. the dumpers ---------------------------------------------------------------


def test_the_eml_dumper_prints_the_message(capsys: pytest.CaptureFixture[str]) -> None:
    with Store.open(_path(SYNTH)) as store:
        message = openable_messages(store)[0]
        expected = eml_bytes(message)
        nid = message.node.raw
    debug.DUMPERS["eml"](_path(SYNTH), f"{nid:x}")
    out = capsys.readouterr().out
    assert out.encode("ascii").replace(b"\r\n", b"\n") == expected.replace(b"\r\n", b"\n")
    assert "Subject: Re: Plain text: the kettle schedule" in out


def test_the_eml_dumper_refuses_a_nid_that_is_not_a_message() -> None:
    with pytest.raises(PstError):
        debug.DUMPERS["eml"](_path(SYNTH), "0x21")
    assert debug.main(["eml", str(_path(SYNTH)), "0x21"]) == 1


def test_the_export_dumper_writes_mboxes_by_default_and_emls_on_request(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    debug.DUMPERS["export"](_path(BODIES), str(tmp_path / "mbox"))
    out = capsys.readouterr().out
    assert "Format: mbox" in out and "Messages: 4" in out and "Folders: 7" in out
    assert sorted(p.suffix for p in (tmp_path / "mbox").iterdir()) == [".mbox"] * 7 + [".txt"]
    debug.DUMPERS["export"](_path(BODIES), str(tmp_path / "eml"), as_eml=True)
    assert "Format: eml" in capsys.readouterr().out
    assert len(list((tmp_path / "eml").glob("*.eml"))) == 4


def test_the_cli_rejects_eml_on_another_layer(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        debug.main(["--eml", "messages", str(_path(SYNTH))])
    assert exc.value.code == 2
    assert debug.main(["export", str(_path(SYNTH)), str(tmp_path)]) == 0


def test_dumper_arguments_counts_positionals_only() -> None:
    assert debug.dumper_arguments(debug.DUMPERS["eml"]) == ["nid"]
    assert debug.dumper_arguments(debug.DUMPERS["export"]) == ["dest"], "`as_eml` is a flag, not an argument"
    assert debug.dumper_arguments(debug.DUMPERS["header"]) == []


# --- 10. private stores: counts only ----------------------------------------------


@pytest.mark.private
def test_private_stores_export_and_nothing_about_them_is_printed(private_stores: list[Path], tmp_path: Path) -> None:
    """Structure only: how many, how many parts, that every marker is well formed. Never a value."""
    if not private_stores:
        pytest.skip("no stores in tests/fixtures/private/")
    marker = re.compile(r"^[A-Za-z0-9 ,.()_-]*$")
    for index, path in enumerate(private_stores):
        dest = tmp_path / f"store-{index}"
        with Store.open(path) as store:
            messages = openable_messages(store)
            parts = 0
            for message in messages:
                built = to_eml(message)
                parts += len(parts_of(built))
                for name in (SYNTHESIZED_HEADER, BODY_HEADER, SKIPPED_HEADER):
                    for value in built.get_all(name, []):
                        assert marker.match(str(value)), f"private store {index}: malformed {name}"
                assert eml_bytes(message).isascii(), f"private store {index}"
            written = export_folder(store.root_folder, dest)
        assert written == len(messages), f"private store {index}"
        assert parts >= len(messages), f"private store {index}"
        assert len(list(dest.glob("*.eml"))) == written, f"private store {index}"
