"""Messages — a property context, a recipient table, and one sub-node per attachment.

Ported from: crates/pst/src/messaging/message.rs (`MessageProperties`, the read half of
             `MessageInner`/`UnicodeMessage`; the write half and the ANSI arm are not
             ported — ADR-0003)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.4.5 Message Objects, 2.4.5.1 Message object PC, 2.4.5.3 Recipient
             Table, 2.4.6 Attachment Objects, 2.2.2.1 NID; [MS-OXCMSG] 2.2.1 message
             properties, 2.2.3.1 PidTagRecipientType

A message is one node ([MS-PST] 2.4.5): its data is a property context, and
its **sub-node tree** holds everything that is not a scalar —

| sub-node NID type | what |
|---|---|
| `RecipientTable` (0x12) | one row per recipient ([MS-PST] 2.4.5.3) |
| `AttachmentTable` (0x11) | one row per attachment, the row id being the attachment's sub-node NID ([MS-PST] 2.4.6.1) |
| `Attachment` (0x05) | one attachment's own property context ([MS-PST] 2.4.6.2) |
| anything else | a large property value the PC's HNIDs point at |

so a message cannot be read without its sub-node tree, and upstream refuses a
message node that has none (`MessageSubNodeTreeNotFound`). This port refuses
it too: `javalibpst-dist-list.pst` holds exactly one such message
(`NormalMessage: 0x10001`), the oracle prints that refusal, and the two agree.

The accessors are thin: each is one property id from [MS-OXPROPS], read
through the PC on demand. The three body forms are kept apart because they
are three different properties and a caller wants a specific one:
`PidTagBody` (0x1000) is text, `PidTagHtml` (0x1013) is bytes, and
`PidTagRtfCompressed` (0x1009) is LZFu-compressed RTF that `pypstreader.rtf`
(P21) expands.

**The subject prefix, and what `subject` returns.** `PidTagSubject` (0x0037)
may begin with a two-character control prefix: `U+0001`, then a character
whose value is the length of the subject prefix plus one ([MS-OXCMSG]
2.2.1.46 with 2.2.1.9/2.2.1.10 — `PidTagSubjectPrefix` and
`PidTagNormalizedSubject` are the two halves it encodes). Every Outlook-written
message in the corpus carries it: `"\x01\x01This is a message…"` (no prefix)
and `"\x01\x05FW: original email"` (prefix `"FW: "`). Upstream has no subject
accessor at all, so nothing here is transcribed; the oracle prints the raw
property and the goldens show the control characters.

This port hands back **both**, and the plain name is the useful one:

- `subject` — the subject a person would read, with the two control
  characters removed and the prefix text kept (`"FW: original email"`).
  This is what a caller writing a filename, a report or an `.eml` header
  wants, and handing them the raw form means every caller strips it
  themselves, most of them wrongly.
- `subject_raw` — the property exactly as stored, control characters and
  all, which is what the oracle prints and what a differential test needs.
- `subject_prefix` — the prefix alone (`"FW: "`, or `""`).
- `normalized_subject` — `PidTagNormalizedSubject` (0x0E1D) when the store
  holds it, and otherwise the subject with its prefix removed
  (`"original email"`). No corpus store holds 0x0E1D, so on the corpus it is
  always the derived form.

A prefix length that runs past the end of the subject is `PstFormatError`:
the store is making a claim about its own string that the string does not
support, and guessing past it produces a plausible-looking wrong subject,
which is worse than a refusal (CLAUDE.md § "Fail closed on unknown input").

**Deliberate divergences from upstream**, each chosen to fail closed or to
fit Python's conventions:

- **Properties are decoded on demand, and the two tables are read on first
  use.** Upstream's `MessageInner::read` decodes every property and reads
  both tables before it returns, so one undecodable property or one corrupt
  recipient table fails the whole message. Here `Message.properties` is the
  `PropertyContext` and `recipient_table` / `attachment_table` are read when
  they are first asked for — the same choice `Store` and `Folder` made, for
  the same reason: failing at the thing a caller asked for beats failing at
  a thing nobody wanted. It also keeps the three answers "no recipient
  table", "an empty one" and "one that will not parse" distinct, where
  upstream's eager read collapses the last two into a failed open.
- **A table node that exists but is not a readable table context is a
  refusal, not `None`** — as in `folder.py`, and for the same reason.
- **`recipients()` and `attachments()` are bounded.** `limits.max_recipients`
  and `limits.max_attachments` cap the row counts before the rows are built;
  upstream has no ceiling because Rust's allocation failure is survivable and
  a Python one is a swap storm.
- **An embedded message carries its depth.** `Attachment.embedded_message()`
  hands the new `Message` a depth one greater than its own, and
  `limits.max_embedded_message_depth` stops a store whose message embeds
  itself. Upstream cannot reach that code at this pin at all (see
  `attachment.py`'s docstring for the `PtypObject` divergence).
- **`Message.parent` remembers the folder it was opened from** when there
  was one. It is information the caller already had and P10 (`.eml`) needs;
  nothing in the read path depends on it.
- **A recipient type this port does not know is an `int`, not a refusal.**
  `RecipientType` names the four values of [MS-OXCMSG] 2.2.3.1, but that
  section also reserves flag bits (0x10000000, `PidTagRecipientType`'s
  "resend" bit) and permits values this reader has not seen. A recipient
  type is a semantic label rather than a structural field: nothing is parsed
  from it, so an unknown one cannot make the reader read the wrong bytes.
  `AttachMethod` is the opposite case and is refused (see `attachment.py`).

Nothing but `PstError` escapes: an absent node or sub-node is
`PstNotFoundError`, a ceiling is `PstLimitError`, an unknown attachment
method is `PstUnsupportedError`, and everything else about the bytes is
`PstFormatError`.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from typing import TYPE_CHECKING

from pypstreader.errors import PstFormatError, PstNotFoundError
from pypstreader.limits import check_count, check_depth
from pypstreader.ltp.prop_context import PropertyContext, PropertyRecord
from pypstreader.ltp.prop_type import PropType, PropValue, filetime_to_datetime
from pypstreader.ltp.table_context import TableContext, TableRow
from pypstreader.messaging.store import EntryId, Store
from pypstreader.ndb.block import SubNodeLeafEntry
from pypstreader.ndb.ids import NodeId, NodeIdType
from pypstreader.rtf import decompress_rtf

if TYPE_CHECKING:
    from pypstreader.messaging.attachment import Attachment
    from pypstreader.messaging.folder import Folder

__all__ = [
    "MESSAGE_NODE_TYPES",
    "PID_TAG_BODY",
    "PID_TAG_CLIENT_SUBMIT_TIME",
    "PID_TAG_CREATION_TIME",
    "PID_TAG_DISPLAY_NAME",
    "PID_TAG_EMAIL_ADDRESS",
    "PID_TAG_HTML",
    "PID_TAG_LAST_MODIFICATION_TIME",
    "PID_TAG_MESSAGE_CLASS",
    "PID_TAG_MESSAGE_DELIVERY_TIME",
    "PID_TAG_MESSAGE_FLAGS",
    "PID_TAG_MESSAGE_SIZE",
    "PID_TAG_MESSAGE_STATUS",
    "PID_TAG_NORMALIZED_SUBJECT",
    "PID_TAG_RECIPIENT_TYPE",
    "PID_TAG_RTF_COMPRESSED",
    "PID_TAG_SEARCH_KEY",
    "PID_TAG_SENDER_EMAIL_ADDRESS",
    "PID_TAG_SENDER_NAME",
    "PID_TAG_SENDER_SMTP_ADDRESS",
    "PID_TAG_SMTP_ADDRESS",
    "PID_TAG_SUBJECT",
    "PID_TAG_TRANSPORT_MESSAGE_HEADERS",
    "SUBJECT_PREFIX_MARKER",
    "Message",
    "Recipient",
    "RecipientType",
    "split_subject",
]

# [MS-OXPROPS], the property ids this layer reads by name.
PID_TAG_MESSAGE_CLASS = 0x001A
PID_TAG_SUBJECT = 0x0037
PID_TAG_CLIENT_SUBMIT_TIME = 0x0039
PID_TAG_TRANSPORT_MESSAGE_HEADERS = 0x007D
PID_TAG_RECIPIENT_TYPE = 0x0C15
PID_TAG_SENDER_NAME = 0x0C1A
PID_TAG_SENDER_EMAIL_ADDRESS = 0x0C1F
PID_TAG_MESSAGE_DELIVERY_TIME = 0x0E06
PID_TAG_MESSAGE_FLAGS = 0x0E07
PID_TAG_MESSAGE_SIZE = 0x0E08
PID_TAG_NORMALIZED_SUBJECT = 0x0E1D
PID_TAG_MESSAGE_STATUS = 0x0E17
PID_TAG_BODY = 0x1000
PID_TAG_RTF_COMPRESSED = 0x1009
PID_TAG_HTML = 0x1013
PID_TAG_DISPLAY_NAME = 0x3001
PID_TAG_EMAIL_ADDRESS = 0x3003
PID_TAG_CREATION_TIME = 0x3007
PID_TAG_LAST_MODIFICATION_TIME = 0x3008
PID_TAG_SEARCH_KEY = 0x300B
PID_TAG_SMTP_ADDRESS = 0x39FE
PID_TAG_SENDER_SMTP_ADDRESS = 0x5D01

# Upstream's `match node_id_type { NormalMessage | AssociatedMessage | Attachment => {} }`.
MESSAGE_NODE_TYPES = (
    NodeIdType.NORMAL_MESSAGE,
    NodeIdType.ASSOC_MESSAGE,
    NodeIdType.ATTACHMENT,
)

# [MS-OXCMSG] 2.2.1.46: the character that introduces a subject prefix.
SUBJECT_PREFIX_MARKER = "\x01"


class RecipientType(IntEnum):
    """`PidTagRecipientType` ([MS-OXCMSG] 2.2.3.1) — the four values this reader names.

    An unknown value is left as a plain `int` by `Recipient.type` rather
    than refused; the module docstring says why.
    """

    ORIGINATOR = 0x00000000
    TO = 0x00000001
    CC = 0x00000002
    BCC = 0x00000003


def split_subject(raw: str) -> tuple[str, str]:
    """`(prefix, normalized)` for a `PidTagSubject` value — [MS-OXCMSG] 2.2.1.46.

    A subject that does not start with `U+0001` has no prefix and is its own
    normalized form. One that does carries the prefix length **plus one** in
    its second character, and the prefix is that many characters of what
    follows. A length past the end of the string, or a lone `U+0001`, is
    `PstFormatError` (module docstring).
    """
    if not isinstance(raw, str):
        raise TypeError(f"split_subject takes a str, not {type(raw).__name__}")
    if not raw.startswith(SUBJECT_PREFIX_MARKER):
        return "", raw
    if len(raw) < 2:
        raise PstFormatError("invalid subject prefix: a lone U+0001 with no length")
    prefix_len = ord(raw[1]) - 1
    body = raw[2:]
    if prefix_len < 0:
        raise PstFormatError(f"invalid subject prefix length: 0x{ord(raw[1]):04X}")
    if prefix_len > len(body):
        raise PstFormatError(f"subject prefix length {prefix_len} exceeds the {len(body)}-character subject")
    return body[:prefix_len], body[prefix_len:]


@dataclass(frozen=True, slots=True)
class Recipient:
    """One row of a message's recipient table ([MS-PST] 2.4.5.3), read as the four columns that name a person.

    `properties` is the whole row — every column the table declares, by
    property id — so a caller after `PidTagRecipientDisplayName` or an
    address type this class does not name has it without re-reading the
    table.
    """

    type: RecipientType | int
    name: str | None
    email: str | None
    smtp: str | None
    properties: Mapping[int, PropValue]

    def get(self, prop_id: int) -> PropValue | None:
        """One column of this row by property id, or `None` when the row has no value there."""
        return self.properties.get(prop_id)

    def __str__(self) -> str:
        kind = self.type.name if isinstance(self.type, RecipientType) else f"0x{int(self.type):08X}"
        return f"Recipient {{ {kind}: {self.smtp or self.email or self.name or ''} }}"


def _recipient_from_row(row: TableRow) -> Recipient:
    """One `TableRow` of a recipient table as a `Recipient`; a column of the wrong type is `PstFormatError`."""
    kind = row.get(PID_TAG_RECIPIENT_TYPE)
    if kind is None:
        kind_value: RecipientType | int = RecipientType.ORIGINATOR
    elif isinstance(kind, int) and not isinstance(kind, bool):
        try:
            kind_value = RecipientType(kind)
        except ValueError:  # not one of the four; see the module docstring
            kind_value = kind
    else:
        raise PstFormatError(f"invalid PidTagRecipientType on recipient: {type(kind).__name__}, not Integer32")

    def text(prop_id: int, what: str) -> str | None:
        value = row.get(prop_id)
        if value is None:
            return None
        if not isinstance(value, str):
            raise PstFormatError(f"invalid {what} on recipient: {type(value).__name__}, not a string")
        return value

    return Recipient(
        type=kind_value,
        name=text(PID_TAG_DISPLAY_NAME, "PidTagDisplayName"),
        email=text(PID_TAG_EMAIL_ADDRESS, "PidTagEmailAddress"),
        smtp=text(PID_TAG_SMTP_ADDRESS, "PidTagSmtpAddress"),
        properties=row.cells,
    )


class Message:
    """One message: its property context, its recipient table, and its attachments.

    Built from an open `Store` and the message's `NodeId`; `Message.open`
    takes an `EntryId` as well and is what `Store.open_message` calls. An
    *embedded* message is not in the node B-tree at all — it is a sub-node of
    the attachment that carries it — so it is built from that sub-node's
    entry, which is what `entry` and `depth` are for and what upstream's
    `read_embedded` does.
    """

    __slots__ = ("_depth", "_entry", "_node", "_parent", "_properties", "_store", "_sub_nodes", "_tables")

    def __init__(
        self,
        store: Store,
        node: NodeId,
        *,
        entry: SubNodeLeafEntry | None = None,
        parent: Folder | None = None,
        depth: int = 0,
    ) -> None:
        """Open message `node` of `store`; a NID of the wrong type is refused before anything is read.

        `entry` is the node's own B-tree entry, which the caller supplies
        only for an embedded message (whose node lives in an attachment's
        sub-node tree and not in the store's); `depth` is how many
        attachments deep that nesting is, 0 for a message the store holds.
        """
        if not isinstance(store, Store):
            raise TypeError(f"Message takes a Store, not {type(store).__name__}")
        if not isinstance(node, NodeId):
            raise TypeError(f"Message takes a NodeId, not {type(node).__name__}")
        node_type = node.id_type  # an unknown 5-bit type is a PstFormatError here
        if node_type not in MESSAGE_NODE_TYPES:
            raise PstFormatError(f"invalid message EntryID NID_TYPE: {node_type.debug_name}")
        self._store = store
        self._node = node
        self._parent = parent
        self._depth = depth
        self._tables: dict[NodeIdType, TableContext | None] = {}
        self._entry = store.nbt.find(node) if entry is None else entry
        self._properties = PropertyContext.from_node(
            store.reader, self._entry, store.limits, codepage=store.codepage
        )
        sub_node = self._entry.sub_node
        if sub_node is None:
            # Upstream's `MessageSubNodeTreeNotFound`: recipients, attachments
            # and every long property value live there, so a message without
            # one is not a message this reader can answer questions about.
            raise PstFormatError(f"missing sub-node tree on message {node}")
        self._sub_nodes = store.reader.read_subnode_tree(sub_node)

    @classmethod
    def open(cls, store: Store, entry: EntryId | NodeId, *, parent: Folder | None = None) -> Message:
        """Upstream's `UnicodeMessage::read`: an `EntryId` from another store is refused (`EntryIdWrongStore`)."""
        if isinstance(entry, EntryId):
            if not store.matches_record_key(entry):
                raise PstFormatError("EntryID in wrong store")
            node = entry.node
        elif isinstance(entry, NodeId):
            node = entry
        else:
            raise TypeError(f"Message.open takes an EntryId or a NodeId, not {type(entry).__name__}")
        return cls(store, node, parent=parent)

    def __str__(self) -> str:
        return f"Message {{ {self._node} }}"

    # --- identity -------------------------------------------------------------------

    @property
    def store(self) -> Store:
        return self._store

    @property
    def node(self) -> NodeId:
        """The message's own NID — `NormalMessage`, `AssociatedMessage` or (upstream allows it) `Attachment`."""
        return self._node

    @property
    def parent(self) -> Folder | None:
        """The folder this message was opened from, when it was opened from one (module docstring)."""
        return self._parent

    @property
    def depth(self) -> int:
        """0 for a message the store holds; one more than its carrier for an embedded message."""
        return self._depth

    @property
    def entry_id(self) -> EntryId:
        """This message's EntryID. Meaningless for an embedded message, whose NID is not the store's."""
        return self._store.entry_id(self._node)

    @property
    def properties(self) -> PropertyContext:
        """The message's own property context — what the FILE holds, with nothing injected."""
        return self._properties

    @property
    def sub_nodes(self) -> Mapping[NodeId, SubNodeLeafEntry]:
        """The message's sub-node tree: the two tables, every attachment, and every long property value."""
        return self._sub_nodes

    def get(self, prop_id: int) -> PropValue | None:
        """One message property by id, decoded — `None` when it is absent or its HNID is 0."""
        return self._properties.get(prop_id)

    # --- the typed accessors ---------------------------------------------------------

    def _record(self, prop_id: int) -> PropertyRecord | None:
        record = self._properties.records.get(prop_id)
        return None if record is None or record.is_null else record

    def _text(self, prop_id: int, what: str) -> str | None:
        record = self._record(prop_id)
        if record is None:
            return None
        value = self._properties.read(record)
        if not isinstance(value, str):
            raise PstFormatError(f"invalid {what} on message: {record.value_type.debug_name}, not a string")
        return value

    def _int32(self, prop_id: int, what: str) -> int:
        record = self._record(prop_id)
        if record is None:
            raise PstFormatError(f"missing {what} on message")
        value = self._properties.read(record)
        if not isinstance(value, int) or isinstance(value, bool):
            raise PstFormatError(f"invalid {what} on message: {record.value_type.debug_name}, not Integer32")
        return value

    def _filetime(self, prop_id: int, what: str) -> int | None:
        """The raw FILETIME ticks of a `PtypTime` property — what the oracle prints, undivided."""
        record = self._record(prop_id)
        if record is None:
            return None
        if record.prop_type is not PropType.SYSTIME:
            raise PstFormatError(f"invalid {what} on message: {record.value_type.debug_name}, not Time")
        raw = self._properties.heap.get_hnid(record.hnid) if record.hnid is not None else b""
        if len(raw) != 8:
            raise PstFormatError(f"invalid {what} on message: {len(raw)} bytes, not 8")
        return int.from_bytes(raw, "little", signed=True)

    def _time(self, prop_id: int, what: str) -> datetime | None:
        ticks = self._filetime(prop_id, what)
        return None if ticks is None else filetime_to_datetime(ticks)

    @property
    def message_class(self) -> str:
        """`PidTagMessageClass` (0x001A) — `"IPM.Note"`, `"IPM.Appointment"`, … Absent or not a string is a refusal."""
        record = self._record(PID_TAG_MESSAGE_CLASS)
        if record is None:
            raise PstFormatError("missing PidTagMessageClass on message")
        value = self._properties.read(record)
        if not isinstance(value, str):
            raise PstFormatError(f"invalid PidTagMessageClass on message: {record.value_type.debug_name}, not a string")
        return value

    @property
    def subject_raw(self) -> str | None:
        """`PidTagSubject` (0x0037) exactly as stored — the control prefix included (module docstring)."""
        return self._text(PID_TAG_SUBJECT, "PidTagSubject")

    @property
    def subject(self) -> str | None:
        """The subject a person reads: the prefix text kept, the two control characters removed."""
        raw = self.subject_raw
        if raw is None:
            return None
        prefix, normalized = split_subject(raw)
        return prefix + normalized

    @property
    def subject_prefix(self) -> str | None:
        """The `"Re: "` / `"FW: "` the subject's control prefix delimits — `""` when there is none."""
        raw = self.subject_raw
        return None if raw is None else split_subject(raw)[0]

    @property
    def normalized_subject(self) -> str | None:
        """`PidTagNormalizedSubject` (0x0E1D) when the store holds it, else the subject without its prefix."""
        stored = self._text(PID_TAG_NORMALIZED_SUBJECT, "PidTagNormalizedSubject")
        if stored is not None:
            return stored
        raw = self.subject_raw
        return None if raw is None else split_subject(raw)[1]

    @property
    def sender_name(self) -> str | None:
        """`PidTagSenderName` (0x0C1A)."""
        return self._text(PID_TAG_SENDER_NAME, "PidTagSenderName")

    @property
    def sender_email(self) -> str | None:
        """`PidTagSenderEmailAddress` (0x0C1F) — an X.500 address on an Exchange-delivered message."""
        return self._text(PID_TAG_SENDER_EMAIL_ADDRESS, "PidTagSenderEmailAddress")

    @property
    def sender_smtp(self) -> str | None:
        """`PidTagSenderSmtpAddress` (0x5D01), when the store kept one."""
        return self._text(PID_TAG_SENDER_SMTP_ADDRESS, "PidTagSenderSmtpAddress")

    @property
    def delivery_filetime(self) -> int | None:
        """`PidTagMessageDeliveryTime` (0x0E06) as raw FILETIME ticks — what the oracle prints."""
        return self._filetime(PID_TAG_MESSAGE_DELIVERY_TIME, "PidTagMessageDeliveryTime")

    @property
    def delivery_time(self) -> datetime | None:
        """`PidTagMessageDeliveryTime` (0x0E06) as an aware UTC `datetime` (sub-microsecond ticks dropped)."""
        return self._time(PID_TAG_MESSAGE_DELIVERY_TIME, "PidTagMessageDeliveryTime")

    @property
    def client_submit_filetime(self) -> int | None:
        """`PidTagClientSubmitTime` (0x0039) as raw FILETIME ticks."""
        return self._filetime(PID_TAG_CLIENT_SUBMIT_TIME, "PidTagClientSubmitTime")

    @property
    def client_submit_time(self) -> datetime | None:
        """`PidTagClientSubmitTime` (0x0039) as an aware UTC `datetime`."""
        return self._time(PID_TAG_CLIENT_SUBMIT_TIME, "PidTagClientSubmitTime")

    @property
    def creation_time(self) -> datetime | None:
        """`PidTagCreationTime` (0x3007) — upstream's `creation_time`, as a `datetime`."""
        return self._time(PID_TAG_CREATION_TIME, "PidTagCreationTime")

    @property
    def last_modification_time(self) -> datetime | None:
        """`PidTagLastModificationTime` (0x3008) — upstream's `last_modification_time`."""
        return self._time(PID_TAG_LAST_MODIFICATION_TIME, "PidTagLastModificationTime")

    @property
    def message_flags(self) -> int:
        """`PidTagMessageFlags` (0x0E07) — upstream's accessor: absent or not Integer32 is a refusal."""
        return self._int32(PID_TAG_MESSAGE_FLAGS, "PidTagMessageFlags")

    @property
    def message_size(self) -> int:
        """`PidTagMessageSize` (0x0E08) — upstream's accessor."""
        return self._int32(PID_TAG_MESSAGE_SIZE, "PidTagMessageSize")

    @property
    def message_status(self) -> int:
        """`PidTagMessageStatus` (0x0E17) — upstream's accessor."""
        return self._int32(PID_TAG_MESSAGE_STATUS, "PidTagMessageStatus")

    @property
    def search_key(self) -> bytes:
        """`PidTagSearchKey` (0x300B) — upstream's accessor: absent or not Binary is a refusal."""
        record = self._record(PID_TAG_SEARCH_KEY)
        if record is None:
            raise PstFormatError("missing PidTagSearchKey on message")
        value = self._properties.read(record)
        if not isinstance(value, bytes):
            raise PstFormatError(f"invalid PidTagSearchKey on message: {record.value_type.debug_name}, not Binary")
        return value

    # --- the three bodies -------------------------------------------------------------

    @property
    def body_text(self) -> str | None:
        """`PidTagBody` (0x1000) — the plain-text body."""
        return self._text(PID_TAG_BODY, "PidTagBody")

    @property
    def body_html(self) -> bytes | None:
        """`PidTagHtml` (0x1013) as bytes — the HTML's own encoding, which its `<meta>` declares.

        Stores write this as `PtypBinary` (every corpus store does). A store
        that writes a string instead is handed back UTF-8 encoded, so the
        return type does not change with the writer.
        """
        record = self._record(PID_TAG_HTML)
        if record is None:
            return None
        value = self._properties.read(record)
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            return value.encode("utf-8")
        raise PstFormatError(f"invalid PidTagHtml on message: {record.value_type.debug_name}, not Binary")

    @property
    def body_rtf(self) -> bytes | None:
        """`PidTagRtfCompressed` (0x1009) exactly as stored — LZFu-compressed ([MS-OXRTFCP]), not RTF yet."""
        record = self._record(PID_TAG_RTF_COMPRESSED)
        if record is None:
            return None
        value = self._properties.read(record)
        if not isinstance(value, bytes):
            raise PstFormatError(
                f"invalid PidTagRtfCompressed on message: {record.value_type.debug_name}, not Binary"
            )
        return value

    def body_rtf_decompressed(self) -> bytes | None:
        """`body_rtf` expanded by `pypstreader.rtf` — the `{\\rtf1` document — or `None` when there is no RTF body.

        Trimmed at the first NUL, which is what upstream's
        `compressed-rtf` crate does when it turns its output into a `String`
        and what Outlook's own writers expect (an empty RTF body is stored
        as a single NUL). `pypstreader.rtf.decompress_rtf` deliberately does not
        trim — the algorithm's output is the algorithm's output — so the
        trim lives here, at the layer that knows the bytes are a document.
        A body that is not LZFu is `PstFormatError` from `pypstreader.rtf`.
        """
        data = self.body_rtf
        if data is None:
            return None
        return decompress_rtf(data, max_output=self._store.limits.max_allocation).split(b"\0", 1)[0]

    @property
    def transport_headers(self) -> str | None:
        """`PidTagTransportMessageHeaders` (0x007D) — the RFC 822 headers, when the message travelled over SMTP."""
        return self._text(PID_TAG_TRANSPORT_MESSAGE_HEADERS, "PidTagTransportMessageHeaders")

    # --- the sub-node tables -----------------------------------------------------------

    def sub_node_table(self, node_type: NodeIdType) -> TableContext | None:
        """The single sub-node of `node_type` read as a table context, or `None` when there is none.

        Upstream's scan: it filters the sub-node tree by NID *type* rather
        than looking for the well-known NID, and refuses a tree that holds
        two (`MultipleMessageRecipientTables`). Both are mirrored here. A
        sub-node that IS there but is not a readable table propagates its
        refusal (module docstring).
        """
        node_type = NodeIdType(node_type)
        if node_type in self._tables:
            return self._tables[node_type]
        found: list[SubNodeLeafEntry] = []
        for nid, entry in self._sub_nodes.items():
            try:
                if nid.id_type is node_type:
                    found.append(entry)
            except PstFormatError:  # upstream's `node_id.id_type().ok()`: an unknown type is not this table
                continue
        if len(found) > 1:
            raise PstFormatError(f"message {self._node} has {len(found)} {node_type.debug_name} sub-nodes")
        table = (
            None
            if not found
            else TableContext.from_node(
                self._store.reader, found[0], self._store.limits, codepage=self._store.codepage
            )
        )
        self._tables[node_type] = table
        return table

    @property
    def recipient_table(self) -> TableContext | None:
        """[MS-PST] 2.4.5.3 — one row per recipient; `None` when the message has no recipient table."""
        return self.sub_node_table(NodeIdType.RECIPIENT_TABLE)

    @property
    def attachment_table(self) -> TableContext | None:
        """[MS-PST] 2.4.6.1 — one row per attachment; `None` when the message has no attachments."""
        return self.sub_node_table(NodeIdType.ATTACHMENT_TABLE)

    def recipients(self) -> Iterator[Recipient]:
        """Every recipient, in row-matrix order — the order the oracle prints. Empty when there is no table."""
        table = self.recipient_table
        if table is None:
            return
        for index, row in enumerate(table.rows(), start=1):
            check_count(index, self._store.limits.max_recipients, "recipients on one message")
            yield _recipient_from_row(row)

    def attachment_ids(self) -> tuple[NodeId, ...]:
        """The sub-node NIDs the attachment table names, in row-matrix order; `()` when there is no table."""
        table = self.attachment_table
        if table is None:
            return ()
        ids: list[NodeId] = []
        for row in table.rows():
            check_count(len(ids) + 1, self._store.limits.max_attachments, "attachments on one message")
            ids.append(NodeId(row.id))
        return tuple(ids)

    def attachments(self) -> Iterator[Attachment]:
        """Every attachment, in row-matrix order, each opened from its own sub-node.

        Lazy: an attachment whose sub-node the tree does not hold raises
        `PstNotFoundError` when the walk reaches it, and the attachments
        before it have already been yielded.
        """
        from pypstreader.messaging.attachment import (
            Attachment,  # the import cycle, broken at the only point where it does not matter
        )

        for node in self.attachment_ids():
            yield Attachment(self, node)

    def sub_node_entry(self, node: NodeId) -> SubNodeLeafEntry:
        """The sub-node `node` of this message — upstream's `AttachmentSubNodeNotFound` when it is absent."""
        if not isinstance(node, NodeId):
            raise TypeError(f"Message.sub_node_entry takes a NodeId, not {type(node).__name__}")
        entry = self._sub_nodes.get(node)
        if entry is None:
            raise PstNotFoundError(f"sub-node {node} is not in message {self._node}'s sub-node tree")
        return entry

    def check_embedded_depth(self) -> None:
        """Refuse to go one level deeper than `limits.max_embedded_message_depth` (the cycle guard)."""
        check_depth(self._depth + 1, self._store.limits.max_embedded_message_depth, "embedded message depth")
