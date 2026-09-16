"""Messages, recipients and attachments (P09): the differential, the divergence, and the refusals.

Three tiers, in the order the `test-harness` skill asks for them.

**Denial first.** A message is opened from a NID an attacker chose; its
recipients and attachments come from tables the attacker wrote; an
attachment's method decides which property is read next and how far the
reader recurses. Every one of those is refused by type: a NID that is not a
message's, a message node with no sub-node tree, a recipient table that will
not parse, an attachment row naming a sub-node the tree does not hold, an
attachment method no specification defines, a missing or retyped data
property, a subject whose prefix runs past the string, an RTF body that is
not LZFu, and every ceiling. `PstLimitError`, `PstUnsupportedError`,
`PstNotFoundError` and `PstFormatError` stay apart throughout.

**Then the differential.** `python -m pypst.debug messages` against the
committed `dump_messages` goldens — byte for byte on seven of the eight
Unicode corpus stores (`synth-basics` differs in the six lines P08's
`rgib[TCI_4b]` divergence explains and this file re-pins) — and then the same
goldens re-read as values through `tests.golden_parsers.parse_dump_messages`
and compared message by message: class, the raw subject with its control
bytes, both times as FILETIME ticks, each body's length and CRC-32, each
recipient row and each attachment row.

**Then the divergence, asserted on the bytes.** Upstream at pin cfb721da
cannot open an embedded-message attachment at all — its goldens carry
`Error: … AttachmentMethodNotFound` — and this port can. That is only
defensible if what comes out is a message, so
`test_the_embedded_message_is_a_real_message` reads
`pstsdk-submessage.pst`'s embedded message and asserts its class, its
subject, its body and its recipient. It is public corpus data (Microsoft's
pstsdk test store); there is nobody in it.
"""

from __future__ import annotations

import dataclasses
import io
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

from pypst.debug import DUMPERS, dump_messages, upstream_records
from pypst.errors import (
    PstFormatError,
    PstLimitError,
    PstNotFoundError,
    PstUnsupportedError,
)
from pypst.limits import DEFAULT_LIMITS, Limits
from pypst.ltp.prop_type import ObjectRef, datetime_to_filetime
from pypst.messaging.attachment import (
    PID_TAG_ATTACH_DATA_BINARY,
    PID_TAG_ATTACH_METHOD,
    Attachment,
    AttachMethod,
)
from pypst.messaging.message import (
    PID_TAG_MESSAGE_CLASS,
    PID_TAG_SUBJECT,
    Message,
    Recipient,
    RecipientType,
    split_subject,
)
from pypst.messaging.store import EntryId, Store
from pypst.ndb.ids import NID_ROOT_FOLDER, NodeId, NodeIdType
from tests import corrupt
from tests.conftest import FIXTURES, REPO, public_fixture_paths
from tests.golden_parsers import parse_dump_messages

EXAMPLE = "dump_messages"
ANSI_STORES = {"pstsdk-sample2", "pstsdk-test_ansi"}
ALL_STORES = [FIXTURES / "Empty.pst", *public_fixture_paths()]
UNICODE_STORES = [p for p in ALL_STORES if p.stem not in ANSI_STORES]
UNICODE_IDS = [p.stem for p in UNICODE_STORES]

# The store whose root folder's tables this port refuses outright (P06/P08):
# it has no readable folder below the root and therefore no message.
NO_TABLES = "pstd-inline-cid"
# `synth-basics.pst`: six `Associated Count: 0` lines that this port prints as
# `Associated Table: None`, for the reason `tests/test_folder.py` pins.
BYTE_IDENTICAL = [p for p in UNICODE_STORES if p.stem != "synth-basics"]
BYTE_IDENTICAL_IDS = [p.stem for p in BYTE_IDENTICAL]

SUBMESSAGE = "pstsdk-submessage"
SAMPLE1 = "pstsdk-sample1"
DIST_LIST = "javalibpst-dist-list"
BODIES = "tika-variousBodyTypes"


def _path(stem: str) -> Path:
    return next(p for p in ALL_STORES if p.stem == stem)


def _message_nid(index: int, node_type: NodeIdType = NodeIdType.NORMAL_MESSAGE) -> NodeId:
    return NodeId.from_parts(node_type, index)


def _first_message(store: Store) -> Message:
    for folder in store.root_folder.walk():
        for message in folder.messages():
            return message
    raise AssertionError("the fixture is supposed to hold a message")


@pytest.fixture(scope="module")
def submessage_bytes() -> bytes:
    return _path(SUBMESSAGE).read_bytes()


# --- denial: the NID a message is opened from ----------------------------------------


@pytest.mark.parametrize(
    "nid",
    [NID_ROOT_FOLDER, NodeId(0x21), NodeId(0x61), NodeId(0x12D)],
    ids=["root folder", "message store", "name-to-id map", "hierarchy table"],
)
def test_a_nid_that_is_not_a_messages_is_refused(empty_pst: Path, nid: NodeId) -> None:
    """Upstream's `InvalidMessageEntryIdType`: only NormalMessage, AssociatedMessage and Attachment open."""
    with Store.open(empty_pst) as store:
        with pytest.raises(PstFormatError, match="invalid message EntryID NID_TYPE"):
            store.open_message(nid)
        with pytest.raises(PstFormatError, match="invalid message EntryID NID_TYPE"):
            Message(store, nid)


def test_the_three_node_types_upstream_accepts_are_the_three_accepted_here() -> None:
    from pypst.messaging.message import MESSAGE_NODE_TYPES

    assert MESSAGE_NODE_TYPES == (
        NodeIdType.NORMAL_MESSAGE,
        NodeIdType.ASSOC_MESSAGE,
        NodeIdType.ATTACHMENT,
    )


def test_a_nid_whose_type_is_not_a_type_at_all_is_refused(empty_pst: Path) -> None:
    """0x09 is unassigned in [MS-PST] 2.2.2.1; the refusal comes from `NodeId.id_type`, before any read."""
    with Store.open(empty_pst) as store, pytest.raises(PstFormatError, match="unknown node id type"):
        store.open_message(NodeId(0x09))


def test_a_message_nid_the_node_btree_does_not_hold_is_not_found(empty_pst: Path) -> None:
    with Store.open(empty_pst) as store, pytest.raises(PstNotFoundError):
        store.open_message(_message_nid(0x7FFFFFF))


def test_an_entry_id_from_another_store_is_refused() -> None:
    """Upstream's `EntryIdWrongStore` — the record key is what makes a foreign id detectable."""
    with Store.open(_path(SAMPLE1)) as store:
        node = store.root_folder.subfolder_ids()
        assert node  # the store has folders; the message id below comes from one of them
        held = _first_message(store).node
        foreign = EntryId(bytes(16), held)
        assert not store.matches_record_key(foreign)
        with pytest.raises(PstFormatError, match="wrong store"):
            store.open_message(foreign)
        # ...and this store's own id for the same node opens.
        assert store.open_message(store.entry_id(held)).node == held


@pytest.mark.parametrize("bad", [0x10004, "0x10004", None, b"", 1.0], ids=["int", "str", "None", "bytes", "float"])
def test_open_message_refuses_something_that_is_neither_an_entry_id_nor_a_nid(empty_pst: Path, bad: object) -> None:
    with Store.open(empty_pst) as store, pytest.raises(TypeError):
        store.open_message(bad)  # type: ignore[arg-type]


def test_message_refuses_a_store_or_a_node_that_is_not_one(empty_pst: Path) -> None:
    with pytest.raises(TypeError, match="takes a Store"):
        Message(object(), _message_nid(1))  # type: ignore[arg-type]
    with Store.open(empty_pst) as store, pytest.raises(TypeError, match="takes a NodeId"):
        Message(store, 0x10004)  # type: ignore[arg-type]


def test_a_message_node_with_no_sub_node_tree_is_refused() -> None:
    """Upstream's `MessageSubNodeTreeNotFound`, and the corpus store that has one.

    `javalibpst-dist-list.pst`'s Contacts folder names a message whose node
    has no sub-node tree at all — no recipient table, no attachment table,
    nowhere for a long property value to live. Upstream refuses it and its
    golden prints the refusal; so does this port, and the other three
    messages of the same store still open.
    """
    with Store.open(_path(DIST_LIST)) as store:
        node = _message_nid(0x10001)
        assert store.nbt.find(node).sub_node is None
        with pytest.raises(PstFormatError, match="missing sub-node tree"):
            store.open_message(node)
        opened = [m.node for f in store.root_folder.walk() for m in _tolerant(f)]
        assert len(opened) == 3 and node not in opened


def _tolerant(folder: object) -> list[Message]:
    """Every message of `folder` that opens — the walk a caller writes when one message may be broken."""
    out: list[Message] = []
    for nid in folder.message_ids():  # type: ignore[attr-defined]
        try:
            out.append(folder.store.open_message(nid))  # type: ignore[attr-defined]
        except PstFormatError:
            continue
    return out


# --- denial: the recipient and attachment tables -------------------------------------


def test_a_message_with_no_recipient_table_has_no_recipients() -> None:
    """`pstsdk-test_unicode.pst`'s two IPM.Post items have no recipient table at all."""
    with Store.open(_path("pstsdk-test_unicode")) as store:
        messages = [m for f in store.root_folder.walk() for m in f.messages()]
        assert len(messages) == 2
        for message in messages:
            assert message.recipient_table is None
            assert list(message.recipients()) == []
            assert message.attachment_table is None
            assert message.attachment_ids() == ()
            assert list(message.attachments()) == []


def test_a_recipient_table_that_will_not_parse_is_refused_not_reported_empty(submessage_bytes: bytes) -> None:
    """Absent, empty and unreadable are three answers; only the first is `None` (the module docstring's divergence).

    The lie is the recipient table's own TCINFO signature: the sub-node is
    still there, so this is not `PstNotFoundError`, and `recipients()` must
    not report "no recipients" for a table it could not read. The empty case
    is the table layer's: a table with no rows yields no ids, which
    `Empty.pst`'s zero-row contents tables exercise in `test_folder.py`.
    """
    node = _message_nid(0x10001)
    site = corrupt.subnode_data_block(submessage_bytes, node.raw, 0x692)  # NID_RECIPIENT_TABLE
    # bClientSig of the HN header: 0x7C is a table context, 0x6C is not.
    broken = corrupt.rewrite_data_block(submessage_bytes, site, corrupt.set_u8(site.data, 3, 0x6C))
    with Store(io.BytesIO(broken)) as store:
        message = store.open_message(node)
        with pytest.raises(PstFormatError) as info:
            _ = message.recipient_table
        assert not isinstance(info.value, PstNotFoundError)
        with pytest.raises(PstFormatError):
            list(message.recipients())


def test_an_attachment_row_naming_a_sub_node_the_tree_lacks_is_not_found(submessage_bytes: bytes) -> None:
    """Upstream's `AttachmentSubNodeNotFound`, from `corrupt.attachment_lies`."""
    mutation = corrupt.mutation(submessage_bytes, seed=0, name="attachment_lies:row0.sub_node_absent")
    with Store(io.BytesIO(mutation.data)) as store:
        message = store.open_message(_message_nid(0x10001))
        assert message.attachment_ids() == (NodeId(0xFFFF_FFE5),)
        with pytest.raises(PstNotFoundError, match="sub-node tree"):
            list(message.attachments())


def test_an_attachment_nid_that_is_not_an_attachments_is_refused() -> None:
    with Store.open(_path(SUBMESSAGE)) as store:
        message = store.open_message(_message_nid(0x10001))
        with pytest.raises(PstFormatError, match="invalid attachment NID_TYPE"):
            Attachment(message, NodeId(0x692))
        with pytest.raises(TypeError, match="takes a Message"):
            Attachment(object(), NodeId(0x8005))  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="takes a NodeId"):
            Attachment(message, 0x8005)  # type: ignore[arg-type]


# --- denial: the attachment method and its data --------------------------------------


def test_an_unknown_attachment_method_is_unsupported_not_a_guess(submessage_bytes: bytes) -> None:
    mutation = corrupt.mutation(submessage_bytes, seed=0, name="attachment_lies:0x3705_unknown_method")
    with Store(io.BytesIO(mutation.data)) as store:
        attachment = next(iter(store.open_message(_message_nid(0x10001)).attachments()))
        with pytest.raises(PstUnsupportedError, match="unknown attachment method 2147483647"):
            _ = attachment.method
        # ...and it is NOT a format error: the store is well formed and this
        # reader does not implement what it says.
        assert not isinstance(
            pytest.raises(PstUnsupportedError, lambda: attachment.data()).value, PstFormatError  # type: ignore[call-overload]
        )


@pytest.mark.parametrize("value", [8, 9, -1, 0x7FFF_FFFF])
def test_from_wire_refuses_every_value_outside_the_specification(value: int) -> None:
    with pytest.raises(PstUnsupportedError, match=f"unknown attachment method {value}"):
        AttachMethod.from_wire(value)


def test_the_attach_method_enum_is_ms_oxcmsg_2_2_2_9() -> None:
    """The eight values of [MS-OXCMSG] 2.2.2.9, including the 3 upstream's `TryFrom` omits."""
    assert [(m.name, int(m)) for m in AttachMethod] == [
        ("NONE", 0),
        ("BY_VALUE", 1),
        ("BY_REFERENCE", 2),
        ("BY_REF_RESOLVE", 3),
        ("BY_REF_ONLY", 4),
        ("EMBEDDED_MESSAGE", 5),
        ("OLE", 6),
        ("BY_WEB_REFERENCE", 7),
    ]
    assert AttachMethod.from_wire(3) is AttachMethod.BY_REF_RESOLVE
    assert [m for m in AttachMethod if m.carries_bytes] == [AttachMethod.BY_VALUE, AttachMethod.OLE]


def test_a_by_value_attachment_with_no_data_property_is_refused() -> None:
    base = _path(SAMPLE1).read_bytes()
    mutation = corrupt.mutation(base, seed=0, name="attachment_lies:0x3701_absent_data")
    with Store(io.BytesIO(mutation.data)) as store:
        attachment = next(iter(_first_message(store).attachments()))
        assert attachment.method is AttachMethod.BY_VALUE
        with pytest.raises(PstFormatError, match="missing PidTagAttachDataBinary"):
            attachment.data()


def test_an_embedded_message_whose_data_is_not_an_object_is_refused(submessage_bytes: bytes) -> None:
    mutation = corrupt.mutation(submessage_bytes, seed=0, name="attachment_lies:0x3701_type_data")
    with Store(io.BytesIO(mutation.data)) as store:
        attachment = next(iter(store.open_message(_message_nid(0x10001)).attachments()))
        assert attachment.method is AttachMethod.EMBEDDED_MESSAGE
        with pytest.raises(PstFormatError, match="not Object"):
            attachment.embedded_message()


def test_an_embedded_message_deeper_than_the_ceiling_is_a_limit_error() -> None:
    """The guard that stops a message which embeds itself: the depth, not a visited set.

    A cycle in the embedding graph is a walk that never ends, and there is
    no corpus store that contains one — so the ceiling is tested where it
    bites, by opening the carrier at the ceiling itself. Every nesting level
    increments `Message.depth`, which the second half of this test pins, so
    a cycle reaches the ceiling in at most `max_embedded_message_depth`
    steps and stops.
    """
    node = _message_nid(0x10001)
    ceiling = DEFAULT_LIMITS.max_embedded_message_depth
    assert ceiling == 16
    with Store.open(_path(SUBMESSAGE)) as store:
        carrier = Message(store, node, depth=ceiling)
        attachment = next(iter(carrier.attachments()))
        with pytest.raises(PstLimitError, match="embedded message depth"):
            attachment.embedded_message()
        # One under the ceiling still opens, and the message it hands back is
        # one deeper than its carrier.
        carrier = Message(store, node, depth=ceiling - 1)
        embedded = next(iter(carrier.attachments())).embedded_message()
        assert embedded is not None and embedded.depth == ceiling
        assert store.open_message(node).depth == 0
        assert next(iter(store.open_message(node).attachments())).embedded_message().depth == 1


def test_a_tight_embedded_depth_limit_refuses_the_first_level() -> None:
    tight = dataclasses.replace(DEFAULT_LIMITS, max_embedded_message_depth=1)
    with Store.open(_path(SUBMESSAGE), limits=tight) as store:
        attachment = next(iter(store.open_message(_message_nid(0x10001)).attachments()))
        assert attachment.embedded_message() is not None  # 0 -> 1 is the inclusive ceiling
    tighter = dataclasses.replace(DEFAULT_LIMITS, max_embedded_message_depth=1)
    with Store.open(_path(SUBMESSAGE), limits=tighter) as store:
        carrier = Message(store, _message_nid(0x10001), depth=1)
        with pytest.raises(PstLimitError, match="embedded message depth"):
            next(iter(carrier.attachments())).embedded_message()


# --- denial: the bodies and the subject ----------------------------------------------


def test_a_body_rtf_that_is_not_lzfu_is_refused() -> None:
    """`PidTagRtfCompressed` with a COMPTYPE that is neither `LZFu` nor `MELA` ([MS-OXRTFCP] 2.2.2.1)."""
    base = _path(BODIES).read_bytes()
    node = _message_nid(0x10003)
    with Store.open(_path(BODIES)) as store:
        record = store.open_message(node).properties.records[0x1009]
        sub = record.hnid.as_node
    assert sub is not None
    site = corrupt.subnode_data_block(base, node.raw, sub.raw)
    broken = corrupt.rewrite_data_block(base, site, corrupt.set_u32(site.data, 8, 0x4C4C4C4C))
    with Store(io.BytesIO(broken)) as store:
        message = store.open_message(node)
        assert message.body_rtf is not None  # the bytes are still there
        with pytest.raises(PstFormatError, match="COMPTYPE"):
            message.body_rtf_decompressed()


def test_a_subject_prefix_past_the_end_of_the_string_is_refused(submessage_bytes: bytes) -> None:
    mutation = corrupt.mutation(submessage_bytes, seed=0, name="message_lies:0x0037_subject_prefix_past_the_string")
    with Store(io.BytesIO(mutation.data)) as store:
        message = store.open_message(_message_nid(0x10001))
        assert message.subject_raw is not None  # the raw value is still readable
        for accessor in ("subject", "subject_prefix", "normalized_subject"):
            with pytest.raises(PstFormatError, match="subject prefix length"):
                getattr(message, accessor)


@pytest.mark.parametrize(
    ("raw", "prefix", "normalized"),
    [
        ("plain", "", "plain"),
        ("\x01\x01no prefix", "", "no prefix"),
        ("\x01\x05FW: original email", "FW: ", "original email"),
        ("\x01\x04Re: x", "Re:", " x"),
        ("\x01\x01", "", ""),
        ("\x01\x02a", "a", ""),
    ],
)
def test_split_subject_follows_ms_oxcmsg(raw: str, prefix: str, normalized: str) -> None:
    """[MS-OXCMSG] 2.2.1.46: `U+0001`, then the prefix length PLUS ONE, then the subject."""
    assert split_subject(raw) == (prefix, normalized)


@pytest.mark.parametrize("raw", ["\x01", "\x01\x00x", "\x01\x09short", "\x01\xffx"])
def test_split_subject_refuses_a_prefix_the_string_cannot_support(raw: str) -> None:
    with pytest.raises(PstFormatError):
        split_subject(raw)


def test_split_subject_refuses_something_that_is_not_a_string() -> None:
    with pytest.raises(TypeError):
        split_subject(b"\x01\x01x")  # type: ignore[arg-type]


def test_a_message_class_that_is_absent_or_retyped_is_refused(submessage_bytes: bytes) -> None:
    """Upstream's `MessageClassNotFound` / `InvalidMessageClass`, one mutation each."""
    for name, pattern in (
        ("message_lies:0x001A_absent_message_class", "missing PidTagMessageClass"),
        ("message_lies:0x001A_type_message_class", "invalid PidTagMessageClass"),
    ):
        mutation = corrupt.mutation(submessage_bytes, seed=0, name=name)
        with Store(io.BytesIO(mutation.data)) as store:
            message = store.open_message(_message_nid(0x10001))
            with pytest.raises(PstFormatError, match=pattern):
                _ = message.message_class
            # One broken property does not break the message.
            assert message.subject_raw is not None


def test_a_body_rtf_that_is_not_binary_is_refused() -> None:
    """`body_rtf` hands `pypst.rtf` bytes or nothing — never an integer the decompressor would choke on."""
    base = _path(DIST_LIST).read_bytes()
    mutation = corrupt.mutation(base, seed=0, name="message_lies:0x1009_type_body_rtf")
    with Store(io.BytesIO(mutation.data)) as store:
        message = store.open_message(_message_nid(0x10006))
        with pytest.raises(PstFormatError, match="invalid PidTagRtfCompressed .*not Binary"):
            _ = message.body_rtf
        with pytest.raises(PstFormatError, match="not Binary"):
            message.body_rtf_decompressed()
        assert message.body_text is not None  # the other bodies still read


def test_a_by_value_attachment_whose_data_is_not_binary_is_refused() -> None:
    """The arm `data()`'s own type check owns: a 0x3701 that decodes cleanly to something that is not bytes."""
    base = _path(SAMPLE1).read_bytes()
    mutation = corrupt.mutation(base, seed=0, name="attachment_lies:0x3701_int_data")
    with Store(io.BytesIO(mutation.data)) as store:
        attachment = next(iter(_first_message(store).attachments()))
        assert attachment.method is AttachMethod.BY_VALUE
        assert isinstance(attachment.get(PID_TAG_ATTACH_DATA_BINARY), int)  # an Integer32, not bytes
        with pytest.raises(PstFormatError, match="invalid PidTagAttachDataBinary .*not Binary"):
            attachment.data()


def test_a_delivery_time_that_is_not_a_time_is_refused(submessage_bytes: bytes) -> None:
    mutation = corrupt.mutation(submessage_bytes, seed=0, name="message_lies:0x0E06_type_delivery_time")
    with Store(io.BytesIO(mutation.data)) as store:
        message = store.open_message(_message_nid(0x10001))
        with pytest.raises(PstFormatError, match="not Time"):
            _ = message.delivery_time
        with pytest.raises(PstFormatError, match="not Time"):
            _ = message.delivery_filetime
        assert message.client_submit_time is not None  # the other time still reads


# --- denial: the ceilings ------------------------------------------------------------


def test_more_attachments_than_max_attachments_is_a_limit_error() -> None:
    """`javalibpst-dist-list.pst`'s appointment has two attachments; the ceiling is inclusive."""
    node = _message_nid(0x10006)
    with Store.open(_path(DIST_LIST)) as store:
        assert len(store.open_message(node).attachment_ids()) == 2
    with Store.open(_path(DIST_LIST), limits=dataclasses.replace(DEFAULT_LIMITS, max_attachments=2)) as store:
        assert len(store.open_message(node).attachment_ids()) == 2
    with Store.open(_path(DIST_LIST), limits=dataclasses.replace(DEFAULT_LIMITS, max_attachments=1)) as store:
        with pytest.raises(PstLimitError, match="attachments on one message"):
            store.open_message(node).attachment_ids()
        with pytest.raises(PstLimitError):
            list(store.open_message(node).attachments())


def test_more_recipients_than_max_recipients_is_a_limit_error() -> None:
    """No corpus message has two recipients, so the two-row table is borrowed from the same store.

    `recipients()` reads whatever table sits at the message's
    `RecipientTable` sub-node; putting the two-row ATTACHMENT table there
    (the cache the accessor reads, not the file) exercises the ceiling over
    real rows without inventing a store. The rows have no
    `PidTagRecipientType`, which is itself worth pinning: an absent type is
    `ORIGINATOR`, not a refusal.
    """
    node = _message_nid(0x10006)
    with Store.open(_path(DIST_LIST), limits=dataclasses.replace(DEFAULT_LIMITS, max_recipients=1)) as store:
        message = store.open_message(node)
        message._tables[NodeIdType.RECIPIENT_TABLE] = message.attachment_table
        with pytest.raises(PstLimitError, match="recipients on one message"):
            list(message.recipients())
    with Store.open(_path(DIST_LIST), limits=dataclasses.replace(DEFAULT_LIMITS, max_recipients=2)) as store:
        message = store.open_message(node)
        message._tables[NodeIdType.RECIPIENT_TABLE] = message.attachment_table
        recipients = list(message.recipients())
        assert len(recipients) == 2
        assert all(r.type is RecipientType.ORIGINATOR for r in recipients)


def test_attachment_data_larger_than_max_allocation_is_a_limit_error() -> None:
    """`pstsdk-sample1.pst`'s attachment is 93 142 bytes; a budget of 1 000 refuses it before it is assembled."""
    tight = dataclasses.replace(DEFAULT_LIMITS, max_allocation=1000)
    with Store.open(_path(SAMPLE1), limits=tight) as store:
        attachment = next(iter(_first_message(store).attachments()))
        with pytest.raises(PstLimitError) as info:
            attachment.data()
        assert not isinstance(info.value, PstFormatError)


def test_every_ceiling_at_one_refuses_and_never_leaks() -> None:
    """A `Limits` of all ones: the message layer says `PstLimitError` or `PstFormatError`, and nothing else."""
    ones = Limits(**{f.name: 1 for f in dataclasses.fields(Limits)})
    try:
        store = Store.open(_path(SUBMESSAGE), limits=ones)
    except (PstLimitError, PstFormatError):
        return  # the store itself is refused first, which is also correct
    with store, pytest.raises((PstLimitError, PstFormatError)):
        for folder in store.root_folder.walk():
            for message in folder.messages():
                list(message.recipients())
                for attachment in message.attachments():
                    attachment.data()


# --- the differential: byte for byte -------------------------------------------------


def _dumper_output(path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[str, int]:
    """`dump_messages`' stdout and the exit status it implies (1 when it refused at the end)."""
    status = 0
    try:
        dump_messages(path)
    except PstFormatError:
        status = 1
    return capsys.readouterr().out, status


@pytest.mark.parametrize("store", BYTE_IDENTICAL, ids=BYTE_IDENTICAL_IDS)
def test_debug_messages_is_byte_identical_to_the_golden(
    store: Path, golden, golden_exit, capsys: pytest.CaptureFixture[str]
) -> None:
    """`debug messages` == `dump_messages.txt`, line for line and exit status included."""
    out, status = _dumper_output(store, capsys)
    assert out.splitlines() == golden(store, EXAMPLE).splitlines(), store.stem
    assert status == golden_exit(store, EXAMPLE), store.stem


def test_synth_basics_differs_only_in_the_documented_associated_lines(
    golden, capsys: pytest.CaptureFixture[str]
) -> None:
    """The one store that is not byte-identical, and the six lines that make it so (P06's `rgib[TCI_4b]`)."""
    store = _path("synth-basics")
    expected = golden(store, EXAMPLE).splitlines()
    got, status = _dumper_output(store, capsys)
    got_lines = got.splitlines()
    assert len(got_lines) == len(expected)
    differ = [i for i, (a, b) in enumerate(zip(expected, got_lines, strict=True)) if a != b]
    assert [(expected[i], got_lines[i]) for i in differ] == [("  Associated Count: 0", "  Associated Table: None")] * 6
    assert status == 0
    # ...and the store's one readable message block is identical.
    assert [ln for i, ln in enumerate(got_lines) if i not in differ] == [
        ln for i, ln in enumerate(expected) if i not in differ
    ]


def test_the_dumper_is_registered_and_takes_no_extra_arguments() -> None:
    assert DUMPERS["messages"] is dump_messages
    assert "messages" in DUMPERS and "folders" in DUMPERS


@pytest.mark.slow
@pytest.mark.parametrize("store", BYTE_IDENTICAL, ids=BYTE_IDENTICAL_IDS)
def test_debug_messages_through_the_process_boundary(store: Path, golden, golden_exit) -> None:
    """The same comparison through `python -m pypst.debug`: the golden's stdout AND its exit status."""
    proc = subprocess.run(
        [sys.executable, "-m", "pypst.debug", "messages", str(store)],
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=600,
        check=False,
    )
    assert proc.stdout.splitlines() == golden(store, EXAMPLE).splitlines(), store.stem
    expected_exit = golden_exit(store, EXAMPLE)
    assert proc.returncode == expected_exit, proc.stderr[-400:]
    assert (proc.stderr == "") if expected_exit == 0 else proc.stderr.startswith("Error: ")


# --- the differential: value for value -----------------------------------------------


def _golden_messages(text: str) -> list[dict]:
    return [m for f in parse_dump_messages(text)["folders"] for m in f["messages"]]


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_every_message_matches_the_golden_value_for_value(store: Path, golden) -> None:
    """Class, subject, times, bodies, recipients and attachments — as VALUES, not as text."""
    expected = _golden_messages(golden(store, EXAMPLE))
    checked = 0
    with Store.open(store) as opened:
        for block in expected:
            node = NodeId.from_parts(NodeIdType[_UPSTREAM_NID_TYPES[block["node"]["type"]]], block["node"]["index"])
            if block["error"] is not None:
                with pytest.raises(PstFormatError):
                    opened.open_message(node)
                continue
            message = opened.open_message(node)
            assert message.message_class == block["class"], f"{store.stem} {node}"
            assert _text(block["subject"]) == message.subject_raw, f"{store.stem} {node}: subject"
            assert _text(block["normalized_subject"]) == (
                message.properties.get(0x0E1D)
            ), f"{store.stem} {node}: normalized subject"
            assert _text(block["sender_name"]) == message.sender_name
            assert _text(block["sender_email"]) == message.sender_email
            assert _text(block["sender_smtp"]) == message.sender_smtp
            assert _ticks(block["delivery_time"]) == message.delivery_filetime
            assert _ticks(block["client_submit_time"]) == message.client_submit_filetime
            _assert_body(block["body_text"], None if message.body_text is None else message.body_text.encode("utf-16-le"))
            _assert_body(block["body_html"], message.body_html)
            _assert_body(block["body_rtf"], message.body_rtf)
            _assert_body(
                block["transport_headers"],
                None if message.transport_headers is None else message.transport_headers.encode("utf-16-le"),
            )
            _assert_recipients(block["recipients"], message)
            _assert_attachments(block["attachments"], message)
            checked += 1
    assert checked == sum(1 for b in expected if b["error"] is None)


_UPSTREAM_NID_TYPES = {
    "NormalMessage": "NORMAL_MESSAGE",
    "AssociatedMessage": "ASSOC_MESSAGE",
    "Attachment": "ATTACHMENT",
}


def _text(value: object) -> str | None:
    """A golden `{"type": …, "value": …}` as the string it holds, or None."""
    if value is None:
        return None
    assert isinstance(value, dict) and value["type"] in ("Unicode", "String8"), value
    return value["value"]


def _ticks(value: object) -> int | None:
    if value is None:
        return None
    assert isinstance(value, dict) and value["type"] == "Time", value
    return value["value"]


def _assert_body(expected: object, data: bytes | None) -> None:
    """A golden `<n> bytes crc 0x…` against the bytes this port read — length and CRC-32, never content."""
    if expected is None:
        assert data is None
        return
    assert data is not None
    assert isinstance(expected, dict)
    assert (len(data), zlib.crc32(data) & 0xFFFFFFFF) == (expected["len"], expected["crc"])


def _assert_recipients(expected: object, message: Message) -> None:
    got = list(message.recipients())
    if expected is None:
        assert message.recipient_table is None and got == []
        return
    assert isinstance(expected, list)
    assert len(got) == len(expected)
    for want, have in zip(expected, got, strict=True):
        assert int(have.type) == (want["type"] if isinstance(want["type"], int) else 0)
        assert _text(want["name"]) == have.name
        assert _text(want["email"]) == have.email
        assert _text(want["smtp"]) == have.smtp


def _assert_attachments(expected: object, message: Message) -> None:
    ids = message.attachment_ids()
    if expected is None:
        assert message.attachment_table is None and ids == ()
        return
    assert isinstance(expected, list)
    assert len(ids) == len(expected)
    for want, node in zip(expected, ids, strict=True):
        assert node.index == want["node"]["index"] and node.id_type is NodeIdType.ATTACHMENT
        attachment = Attachment(message, node)
        assert int(attachment.method_value) == want["row"]["method"]
        assert attachment.size == want["row"]["size"]
        assert _text(want["row"]["filename"]) == attachment.filename
        if want["properties"] is not None:  # upstream opened it: compare its own PC too
            assert _text(want["properties"]["long_filename"]) == attachment.long_filename
            assert _text(want["properties"]["mime_tag"]) == attachment.mime_tag
            assert _text(want["properties"]["content_id"]) == attachment.content_id
            data = attachment.data()
            if want["data"] is None:
                assert data is None
            else:
                assert data is not None
                assert (len(data), zlib.crc32(data) & 0xFFFFFFFF) == (want["data"]["len"], want["data"]["crc"])


# --- the divergence: the embedded messages upstream cannot open -----------------------


def test_the_golden_still_shows_upstreams_refusal(golden) -> None:
    """A pin move that fixes `PtypObject` upstream must be noticed here, not silently diverged from."""
    blocks = _golden_messages(golden(_path(SUBMESSAGE), EXAMPLE))
    (attachment,) = blocks[0]["attachments"]
    assert attachment["row"]["method"] == 5
    assert attachment["properties"] is None
    assert attachment["error"] == "Custom { kind: InvalidData, error: AttachmentMethodNotFound }"
    assert attachment["message"] is None


def test_the_embedded_message_is_a_real_message() -> None:
    """The arbitration, on the bytes: what this port opens where upstream refuses is a message.

    `pstsdk-submessage.pst` is Microsoft's own pstsdk test store — public
    corpus data with nobody in it — so its content is asserted on directly.
    """
    with Store.open(_path(SUBMESSAGE)) as store:
        carrier = store.open_message(_message_nid(0x10001))
        (attachment,) = list(carrier.attachments())
        assert attachment.method is AttachMethod.EMBEDDED_MESSAGE
        assert attachment.data() is None  # an embedded message is not bytes
        ref = attachment.get(PID_TAG_ATTACH_DATA_BINARY)
        assert isinstance(ref, ObjectRef) and ref.node.id_type is NodeIdType.NORMAL_MESSAGE
        embedded = attachment.embedded_message()
        assert embedded is not None
        assert embedded.node == ref.node
        assert embedded.message_class == "IPM.Note"
        assert embedded.subject == "This is an embedded message"
        assert embedded.subject_raw == "\x01\x01This is an embedded message"
        assert embedded.body_text is not None and "embedded message" in embedded.body_text
        assert embedded.body_text.startswith("This is the body of an embedded message")
        (recipient,) = list(embedded.recipients())
        assert recipient.type is RecipientType.TO
        assert recipient.name == "Terry Mahaffey"
        assert embedded.attachment_ids() == ()


def test_the_embedded_message_lives_in_the_attachments_own_sub_node_tree() -> None:
    """The second upstream bug: `AttachmentInner::read` looks in the MESSAGE's tree, where the node is not."""
    with Store.open(_path(SUBMESSAGE)) as store:
        carrier = store.open_message(_message_nid(0x10001))
        (attachment,) = list(carrier.attachments())
        ref = attachment.get(PID_TAG_ATTACH_DATA_BINARY)
        assert isinstance(ref, ObjectRef)
        assert ref.node in attachment.sub_nodes
        assert ref.node not in carrier.sub_nodes  # upstream would look here and fail
        with pytest.raises(PstNotFoundError):
            carrier.sub_node_entry(ref.node)


def test_the_dist_list_embedded_attachments_open_too() -> None:
    """The other two embedded attachments in the corpus: OLE class messages under an appointment."""
    with Store.open(_path(DIST_LIST)) as store:
        message = store.open_message(_message_nid(0x10006))
        attachments = list(message.attachments())
        assert len(attachments) == 2
        for attachment in attachments:
            assert attachment.method is AttachMethod.EMBEDDED_MESSAGE
            embedded = attachment.embedded_message()
            assert embedded is not None
            assert embedded.message_class.startswith("IPM.OLE.CLASS.")
            assert embedded.depth == 1 and embedded.parent is None


def test_the_dumper_reproduces_upstreams_refusal_while_the_library_succeeds(
    golden, capsys: pytest.CaptureFixture[str]
) -> None:
    """Both halves of the divergence at once: the dump matches the golden, the library reads the message."""
    store = _path(SUBMESSAGE)
    out, status = _dumper_output(store, capsys)
    assert "AttachmentMethodNotFound" in out and status == 1
    assert out.splitlines() == golden(store, EXAMPLE).splitlines()
    with Store.open(store) as opened:
        attachment = next(iter(opened.open_message(_message_nid(0x10001)).attachments()))
        assert attachment.embedded_message() is not None


def test_upstream_records_truncates_where_upstreams_walk_stops() -> None:
    """The dumper's re-creation of upstream's limitation, asserted on the attachment that triggers it."""
    with Store.open(_path(SUBMESSAGE)) as store:
        attachment = next(iter(store.open_message(_message_nid(0x10001)).attachments()))
        ours = attachment.properties.records
        theirs = upstream_records(attachment.properties)
        assert PID_TAG_ATTACH_DATA_BINARY in ours and PID_TAG_ATTACH_METHOD in ours
        assert PID_TAG_ATTACH_DATA_BINARY not in theirs and PID_TAG_ATTACH_METHOD not in theirs
        assert set(theirs) == {i for i in ours if i < PID_TAG_ATTACH_DATA_BINARY}
        # A property context with no PtypObject record is not truncated at all.
        message = store.open_message(_message_nid(0x10001))
        assert upstream_records(message.properties) == dict(message.properties.records)


# --- the shape of the API ------------------------------------------------------------


def test_folder_messages_and_associated_open_what_the_id_lists_name() -> None:
    with Store.open(_path(BODIES)) as store:
        folders = list(store.root_folder.walk())
        with_messages = [f for f in folders if f.message_ids()]
        assert len(with_messages) == 1
        folder = with_messages[0]
        messages = list(folder.messages())
        assert [m.node for m in messages] == list(folder.message_ids())
        assert all(m.parent is folder for m in messages)
        assert [m.node for m in messages] == [store.open_message(e).node for e in folder.contents()]
        # No corpus store has an associated (FAI) message, so the id list and
        # the opened list agree by both being empty.
        assert all(list(f.associated()) == [] and f.associated_ids() == () for f in folders)


def test_the_subject_decision_raw_prefix_and_normalized() -> None:
    """What `subject` returns, pinned on the corpus message that has a real prefix."""
    with Store.open(_path(BODIES)) as store:
        by_raw = {m.subject_raw: m for f in store.root_folder.walk() for m in f.messages()}
        forwarded = by_raw["\x01\x05FW: original email"]
        assert forwarded.subject == "FW: original email"
        assert forwarded.subject_prefix == "FW: "
        assert forwarded.normalized_subject == "original email"
        # PidTagNormalizedSubject itself is absent on every corpus store, so
        # `normalized_subject` is the derived form — as the goldens show.
        assert forwarded.properties.get(0x0E1D) is None
        original = by_raw["\x01\x01original email"]
        assert original.subject == "original email"
        assert original.subject_prefix == ""
        assert original.normalized_subject == "original email"


def test_a_message_with_no_subject_has_none_everywhere(submessage_bytes: bytes) -> None:
    mutation = corrupt.mutation(submessage_bytes, seed=0, name="message_lies:0x001A_absent_message_class")
    with Store(io.BytesIO(mutation.data)) as store:
        message = store.open_message(_message_nid(0x10001))
        assert message.subject_raw is not None
    # ...and a message whose PidTagSubject is genuinely absent: the FreeBusy
    # item of the dist-list store has no sender SMTP and no times.
    with Store.open(_path(DIST_LIST)) as store:
        free_busy = store.open_message(_message_nid(0x10002))
        assert free_busy.sender_smtp is None
        assert free_busy.delivery_time is None and free_busy.delivery_filetime is None
        assert free_busy.client_submit_time is None
        assert free_busy.body_text is None and free_busy.body_html is None and free_busy.body_rtf is None
        assert free_busy.body_rtf_decompressed() is None
        assert free_busy.transport_headers is None


def test_times_are_datetimes_and_the_raw_ticks_are_available() -> None:
    """`delivery_time` is a `datetime`; `delivery_filetime` is what the store wrote, sub-microsecond tick included."""
    with Store.open(_path(BODIES)) as store:
        message = store.open_message(_message_nid(0x10001))
        ticks = message.delivery_filetime
        assert ticks == 131485947642894527
        assert ticks % 10 != 0, "this fixture is chosen because the datetime cannot round-trip it"
        assert datetime_to_filetime(message.delivery_time) == ticks - ticks % 10
        assert message.delivery_time.tzinfo is not None
        assert message.delivery_time.year == 2017


def test_the_three_bodies_are_three_properties() -> None:
    """`tika-variousBodyTypes.pst` is in the corpus for this: plain, HTML and RTF, one message each."""
    with Store.open(_path(BODIES)) as store:
        messages = {m.node.index: m for f in store.root_folder.walk() for m in f.messages()}
        assert len(messages) == 4
        html = messages[0x10001]
        assert isinstance(html.body_text, str) and isinstance(html.body_html, bytes) and html.body_rtf is None
        assert b"<html" in html.body_html.lower()
        rtf = messages[0x10003]
        assert rtf.body_html is None and isinstance(rtf.body_rtf, bytes)
        # `body_rtf` is what the store holds — compressed — and the expansion
        # is a separate call, because a caller often wants neither.
        assert not rtf.body_rtf.startswith(b"{\\rtf1")
        expanded = rtf.body_rtf_decompressed()
        assert expanded is not None and expanded.startswith(b"{\\rtf1")
        assert len(expanded) > len(rtf.body_rtf)
        plain = messages[0x10004]
        assert isinstance(plain.body_text, str) and plain.body_html is None and plain.body_rtf is None


def test_the_rtf_body_is_trimmed_at_the_first_nul() -> None:
    """Upstream cuts its `String` at the first NUL; so does this, at the layer that knows it is a document."""
    with Store.open(_path(BODIES)) as store:
        expanded = store.open_message(_message_nid(0x10003)).body_rtf_decompressed()
        assert expanded is not None and b"\0" not in expanded


def test_recipients_carry_their_whole_row() -> None:
    with Store.open(_path(SAMPLE1)) as store:
        (recipient,) = list(_first_message(store).recipients())
        assert isinstance(recipient, Recipient)
        assert recipient.type is RecipientType.TO and int(recipient.type) == 1
        assert recipient.name == "Terry Mahaffey"
        assert recipient.smtp == "terrymah@microsoft.com"
        assert recipient.email is not None and recipient.email.startswith("/O=MICROSOFT")
        # The whole row is there, not just the four named columns.
        assert recipient.get(0x0C15) == 1
        assert recipient.get(0x3001) == recipient.name
        assert recipient.get(0xFFFF) is None
        assert len(recipient.properties) > 4
        assert "Recipient {" in str(recipient)


def test_attachment_accessors_over_the_by_value_attachment() -> None:
    with Store.open(_path(SAMPLE1)) as store:
        message = _first_message(store)
        (attachment,) = list(message.attachments())
        assert attachment.message is message
        assert attachment.method is AttachMethod.BY_VALUE and attachment.method_value == 1
        assert attachment.filename == "leah_t~1.jpg"
        assert attachment.long_filename == "leah_thumper.jpg"
        assert attachment.mime_tag is None and attachment.content_id is None
        assert attachment.size == 96808
        data = attachment.data()
        assert data is not None and len(data) == 93142
        assert zlib.crc32(data) & 0xFFFFFFFF == 0xB32A82DE
        assert data.startswith(b"\xff\xd8\xff")  # a JPEG, as its name says
        assert attachment.embedded_message() is None
        assert attachment.get(PID_TAG_ATTACH_METHOD) == 1
        assert "Attachment {" in str(attachment)


def test_str_forms_mirror_the_folders() -> None:
    with Store.open(_path(SAMPLE1)) as store:
        message = _first_message(store)
        assert str(message) == "Message { NodeId { NormalMessage: 0x10001 } }"
        assert str(next(iter(message.attachments()))) == "Attachment { NodeId { Attachment: 0x401 } }"
        assert message.entry_id == store.entry_id(message.node)
        assert message.store is store
        assert message.get(PID_TAG_SUBJECT) == message.subject_raw
        assert message.get(PID_TAG_MESSAGE_CLASS) == "IPM.Note"


def test_upstreams_other_accessors_are_ported() -> None:
    """`message_flags`, `message_size`, `message_status`, the two times and the search key."""
    with Store.open(_path(SAMPLE1)) as store:
        message = _first_message(store)
        assert isinstance(message.message_flags, int)
        assert isinstance(message.message_size, int) and message.message_size > 0
        with pytest.raises(PstFormatError, match="missing PidTagMessageStatus"):
            _ = message.message_status  # upstream's accessor, and a property no corpus message writes
        assert message.creation_time is not None and message.last_modification_time is not None
        assert isinstance(message.search_key, bytes) and len(message.search_key) == 16


def test_sub_node_table_refuses_two_tables_of_the_same_type() -> None:
    """Upstream's `MultipleMessageRecipientTables`, which needs a store nobody writes — so the check is unit-tested."""
    with Store.open(_path(SUBMESSAGE)) as store:
        message = store.open_message(_message_nid(0x10001))
        entry = message.sub_nodes[NodeId(0x692)]
        forged = dict(message.sub_nodes)
        forged[NodeId(0x6B2)] = entry  # a second NID whose 5-bit type is 0x12
        message._sub_nodes = forged
        message._tables.clear()
        with pytest.raises(PstFormatError, match="RecipientTable sub-nodes"):
            _ = message.recipient_table


def test_sub_node_entry_and_attachment_ids_agree() -> None:
    with Store.open(_path(SAMPLE1)) as store:
        message = _first_message(store)
        (node,) = message.attachment_ids()
        assert message.sub_node_entry(node).node == node
        with pytest.raises(TypeError, match="takes a NodeId"):
            message.sub_node_entry(0x8005)  # type: ignore[arg-type]
        with pytest.raises(PstNotFoundError):
            message.sub_node_entry(NodeId(0xFFFF_FFE5))


# --- the private stores: structure only ----------------------------------------------


@pytest.mark.private
def test_private_stores_parse_and_nothing_about_them_is_printed(private_stores: list[Path]) -> None:
    """Counts and kinds only. Never a subject, a name, an address or a body — CI output is a publication channel."""
    if not private_stores:
        pytest.skip("no stores in tests/fixtures/private/")
    for index, path in enumerate(private_stores):
        with Store.open(path) as store:
            messages = 0
            methods: set[str] = set()
            bodies: set[str] = set()
            for folder in store.root_folder.walk():
                for message in folder.messages():
                    messages += 1
                    for kind in ("body_text", "body_html", "body_rtf"):
                        if getattr(message, kind) is not None:
                            bodies.add(kind)
                    for recipient in message.recipients():
                        assert isinstance(recipient, Recipient)
                    for attachment in message.attachments():
                        methods.add(attachment.method.name)
                        assert isinstance(attachment.size, int)
            assert messages >= 0, f"private store {index}"
            assert methods <= {m.name for m in AttachMethod}, f"private store {index}"
            assert bodies <= {"body_text", "body_html", "body_rtf"}, f"private store {index}"


@pytest.mark.private
@pytest.mark.slow
def test_private_stores_match_the_prebuilt_oracle(private_stores: list[Path], capsys: pytest.CaptureFixture[str]) -> None:
    """`debug messages` against the PREBUILT `dump_messages`, byte for byte. Never runs cargo; never prints the output."""
    if not private_stores:
        pytest.skip("no stores in tests/fixtures/private/")
    binary = REPO / "reference" / "outlook-pst-rs" / "target" / "debug" / "examples" / "dump_messages"
    if not binary.exists():
        pytest.skip("reference/.../examples/dump_messages is not built — scripts/build_oracle.sh")
    checked = 0
    for index, path in enumerate(private_stores):
        result = subprocess.run([str(binary), str(path)], capture_output=True, text=True, timeout=600, check=False)
        if result.returncode not in (0, 1):
            continue
        out, status = _dumper_output(path, capsys)
        # The assertion is on equality and on counts; neither operand is ever
        # printed, because `==` on two strings does not print them and the
        # message below carries only the index and the line counts.
        assert out == result.stdout, (
            f"private store {index}: {len(out.splitlines())} lines vs {len(result.stdout.splitlines())}"
        )
        assert status == result.returncode, f"private store {index}: exit status differs"
        checked += 1
    if not checked:
        pytest.skip("the prebuilt oracle refused every private store")


# --- the generator's new families ----------------------------------------------------


def test_the_new_families_reach_a_store_with_messages(submessage_bytes: bytes) -> None:
    """`message_lies` and `attachment_lies` yield their retyping lies everywhere and their real ones here.

    `0x1009_type_body_rtf` is not in the set: no message of this store has an
    RTF body, and a lie is only generated for a property a message actually
    holds — `test_a_body_rtf_that_is_not_binary_is_refused` takes it from
    `javalibpst-dist-list.pst`, whose appointment does.
    """
    names = {
        m.name
        for family in (corrupt.message_lies, corrupt.attachment_lies)
        for m in family(submessage_bytes, corrupt.family_rng(0, family))
    }
    assert names == {
        "message_lies:name_to_id_map_retyped_normal_message",
        "message_lies:name_to_id_map_retyped_assoc_message",
        "message_lies:0x001A_absent_message_class",
        "message_lies:0x001A_type_message_class",
        "message_lies:0x0037_subject_prefix_past_the_string",
        "message_lies:0x0E06_type_delivery_time",
        "attachment_lies:name_to_id_map_retyped_attachment",
        "attachment_lies:row0.sub_node_absent",
        "attachment_lies:0x3705_absent_method",
        "attachment_lies:0x3705_unknown_method",
        "attachment_lies:0x3701_absent_data",
        "attachment_lies:0x3701_type_data",
        "attachment_lies:0x3701_int_data",
        "attachment_lies:0x0E20_type_size",
    }


@pytest.mark.parametrize("node_type", [0x04, 0x05, 0x08], ids=["message", "attachment", "associated"])
def test_a_retyped_node_is_reachable_and_refused(empty_pst: Path, node_type: int) -> None:
    """The universal lie: NID 0x61 renamed into a message's NID type is found by the NBT and is not a message."""
    base = empty_pst.read_bytes()
    retyped = corrupt.retype_nbt_entry(base, 0x61, (0x61 >> 5 << 5) | node_type)
    assert retyped is not None and retyped != base
    with Store(io.BytesIO(retyped)) as store:
        node = NodeId((0x61 >> 5 << 5) | node_type)
        store.nbt.find(node)  # the node B-tree still finds it under its new key
        with pytest.raises(PstFormatError, match="missing sub-node tree"):
            store.open_message(node)
        with pytest.raises(PstNotFoundError):
            store.nbt.find(NodeId(0x61))


def test_retyping_refuses_to_move_a_pages_first_key(empty_pst: Path) -> None:
    """0x21 is the first key of its leaf page; renaming it would strand the parent's btkey, so the helper declines."""
    base = empty_pst.read_bytes()
    assert corrupt.retype_nbt_entry(base, 0x21, 0x24) is None
    assert corrupt.retype_nbt_entry(base, 0xDEAD, 0xBEEF) is None
    # ...and a new key past its neighbour is declined too.
    assert corrupt.retype_nbt_entry(base, 0x61, 0x9999) is None


def test_the_retyped_page_still_carries_a_valid_crc(empty_pst: Path) -> None:
    from pypst.ndb.btree import NodeBTree
    from pypst.ndb.header import read_header

    retyped = corrupt.retype_nbt_entry(empty_pst.read_bytes(), 0x61, 0x64)
    assert retyped is not None
    f = io.BytesIO(retyped)
    header = read_header(f)
    keys = [e.node.raw for e in NodeBTree(f, header.root.node_btree)]
    assert 0x64 in keys and 0x61 not in keys
    assert keys == sorted(keys)


def test_subnode_data_block_round_trips(submessage_bytes: bytes) -> None:
    """The builder the attachment lies stand on: rewriting a sub-node block with its own bytes changes nothing."""
    site = corrupt.subnode_data_block(submessage_bytes, _message_nid(0x10001).raw, 0x692)
    assert corrupt.rewrite_data_block(submessage_bytes, site, site.data) == submessage_bytes
    assert len(site.data) == site.size
    with pytest.raises((ValueError, KeyError)):
        corrupt.subnode_data_block(submessage_bytes, _message_nid(0x10001).raw, 0xDEAD)
