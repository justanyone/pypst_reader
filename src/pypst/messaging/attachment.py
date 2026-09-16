"""Attachments — one sub-node of a message, holding a property context of its own.

Ported from: crates/pst/src/messaging/attachment.rs (`AttachmentProperties`,
             `AttachmentMethod`, the read half of `AttachmentInner`/`UnicodeAttachment`;
             the write half and the ANSI arm are not ported — ADR-0003)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.4.6 Attachment Objects, 2.4.6.1 Attachment Table, 2.4.6.2
             Attachment object PC, 2.3.3.4 PtypObject; [MS-OXCMSG] 2.2.2.9
             PidTagAttachMethod, 2.2.2.7 PidTagAttachDataBinary, 2.2.2.8
             PidTagAttachDataObject

Each attachment of a message is one sub-node of that message's sub-node tree,
with an `Attachment` (0x05) NID type, and its data is a property context
([MS-PST] 2.4.6.2). The message's attachment table names them: a row per
attachment, the row id being the sub-node's NID. `PidTagAttachMethod`
(0x3705) says where the attachment's content actually is:

| method | [MS-OXCMSG] name | where the content is |
|---|---|---|
| 0 `NONE` | `afNone` | nowhere — the attachment has just been created |
| 1 `BY_VALUE` | `afByValue` | `PidTagAttachDataBinary` (0x3701), as bytes |
| 2 `BY_REFERENCE` | `afByReference` | a path in `PidTagAttachLongPathname` |
| 3 `BY_REF_RESOLVE` | `afByReferenceResolve` | a path, resolved by the server |
| 4 `BY_REF_ONLY` | `afByReferenceOnly` | a path, and only a path |
| 5 `EMBEDDED_MESSAGE` | `afEmbeddedMessage` | `PidTagAttachDataObject` (0x3701) as `PtypObject`: a sub-node that is a whole message |
| 6 `OLE` | `afStorage` | the same, as an OLE storage stream |
| 7 `BY_WEB_REFERENCE` | `afByWebReference` | a URL in `PidTagAttachLongPathname` |

`data()` returns bytes for the two methods that carry them (`BY_VALUE` and
`OLE`) and `None` for the rest — upstream's `Option<AttachmentData>`, with the
same arms. `embedded_message()` returns a `Message` for `EMBEDDED_MESSAGE`
and `None` for the rest.

**The divergence that matters: this port opens embedded messages, and
upstream at this pin cannot.** `PropertyType::try_from(u16)` in
`ltp/prop_type.rs` has no arm for `0x000D` (`PtypObject`) although the enum
declares the variant, and upstream's BTH leaf walk stops silently at the
first record it cannot decode. Every embedded-message attachment carries
`PidTagAttachDataObject` (0x3701) as `PtypObject`, and 0x3701 sorts *before*
`PidTagAttachMethod` (0x3705), so upstream's view of such an attachment's
property context stops before the method: it refuses the attachment with
`AttachmentMethodNotFound` and never reaches its own embedded-message arm.
The goldens record exactly that —

    Attachment: NodeId { Attachment: 0x401 }
      Row: method=5 filename=Unicode(UnicodeValue { "This is an embedded message" }) size=11494
      Error: Custom { kind: InvalidData, error: AttachmentMethodNotFound }

on `pstsdk-submessage.pst`, and twice more on `javalibpst-dist-list.pst`.
This port decodes `PtypObject` (P22/P05) and therefore opens the embedded
message. The arbitration is not "we prefer our answer": [MS-PST] 2.3.3.4
defines the `PtypObject` property-value record as `(NID, size)` and 2.4.6.3
says an `afEmbeddedMessage` attachment's `PidTagAttachDataObject` names a
sub-node holding a message object — and the bytes agree, because the message
that comes out of `pstsdk-submessage.pst` has a sensible message class,
subject and body, all of which the tests assert on (it is public corpus data
with nobody in it). Upstream's own dumper documents the gap in its module
comment. `pypst.debug`'s `messages` dumper reproduces upstream's refusal
line so the golden still matches byte for byte, and
`tests/test_dump_messages_golden.py` pins the golden's `Error:` line so that
a moved pin which fixes upstream is noticed rather than silently diverged
from.

**A second upstream bug, found the same way and fixed here: the embedded
message is in the ATTACHMENT's sub-node tree, not the message's.**
`AttachmentInner::read` resolves `PidTagAttachDataObject`'s NID with
`message.sub_nodes().get(&sub_node)` — the tree of the message that owns the
attachment. The bytes say otherwise. On `pstsdk-submessage.pst` the
attachment `Attachment: 0x401` has a sub-node tree of its own holding
`NormalMessage: 0x10002`, which is the NID its `PidTagAttachDataObject`
names, and the owning message's tree holds no such node at all; the two
embedded attachments of `javalibpst-dist-list.pst` are the same shape
(`NormalMessage: 0x1000C` and `0x1000E`, each under its own attachment).
[MS-PST] 2.4.6.2 puts the embedded message in the subnode of the
*attachment* node, and 2.4.6.3 reads it from there. Upstream never notices
because the `PtypObject` gap above means this code is unreachable at the
pin. So `sub_nodes` here is the attachment's own tree, and
`embedded_message()` and the `OLE` arm of `data()` both resolve into it.

**The other divergences**, each chosen to fail closed or to fit Python:

- **Method 3 (`afByReferenceResolve`) is a known method here.**
  [MS-OXCMSG] 2.2.2.9 defines 0x00000003; upstream's `TryFrom<i32>` has no
  arm for it and rejects it as unknown. Nothing is parsed differently for
  it — like methods 2, 4 and 7 it means "the content is not in this store"
  — so naming it costs nothing and refusing it would refuse a file the
  specification permits.
- **An unknown method is `PstUnsupportedError` naming the value**, where
  upstream returns `UnknownAttachmentMethod(i32)`. Same refusal, this
  port's exception family: "this store uses something this reader does not
  implement" is exactly what `PstUnsupportedError` is for, and it is
  distinguishable from "this store is corrupt".
- **Properties are decoded on demand and `data()` is read when it is
  asked for**, where upstream reads every property and the whole attachment
  payload while opening. A caller listing filenames should not pay for
  ninety megabytes of attachment bytes.
- **`data()` is bounded by `limits.max_allocation`**, by the layer that
  assembles the bytes: `BlockReader.read_data` refuses an `lcbTotal` past
  the ceiling *before* it reads a child block, which is earlier than any
  check here could be. There is deliberately no second ceiling here — it
  would be code no test could reach, and an unreachable check is a comment
  that lints as code.
- **The embedded-message recursion is depth-bounded.** An attachment whose
  embedded message embeds the same node again is a cycle that upstream's
  recursion would follow until the stack ran out; here
  `limits.max_embedded_message_depth` (16) stops it with `PstLimitError`.

Nothing but `PstError` escapes: an absent sub-node is `PstNotFoundError`, a
ceiling is `PstLimitError`, an unknown method is `PstUnsupportedError`, and
everything else about the bytes is `PstFormatError`.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import IntEnum

from pypst.errors import PstFormatError, PstNotFoundError, PstUnsupportedError
from pypst.ltp.prop_context import PropertyContext, PropertyRecord
from pypst.ltp.prop_type import ObjectRef, PropValue
from pypst.messaging.message import Message
from pypst.ndb.block import SubNodeLeafEntry
from pypst.ndb.ids import NodeId, NodeIdType

__all__ = [
    "PID_TAG_ATTACH_CONTENT_ID",
    "PID_TAG_ATTACH_DATA_BINARY",
    "PID_TAG_ATTACH_FILENAME",
    "PID_TAG_ATTACH_LONG_FILENAME",
    "PID_TAG_ATTACH_LONG_PATHNAME",
    "PID_TAG_ATTACH_METHOD",
    "PID_TAG_ATTACH_MIME_TAG",
    "PID_TAG_ATTACH_SIZE",
    "PID_TAG_RENDERING_POSITION",
    "AttachMethod",
    "Attachment",
]

# [MS-OXPROPS], the property ids this layer reads by name.
PID_TAG_ATTACH_SIZE = 0x0E20
PID_TAG_ATTACH_DATA_BINARY = 0x3701  # also PidTagAttachDataObject: the id is shared, the type is not
PID_TAG_ATTACH_FILENAME = 0x3704
PID_TAG_ATTACH_METHOD = 0x3705
PID_TAG_ATTACH_LONG_FILENAME = 0x3707
PID_TAG_ATTACH_PATHNAME = 0x3708
PID_TAG_RENDERING_POSITION = 0x370B
PID_TAG_ATTACH_MIME_TAG = 0x370E
PID_TAG_ATTACH_LONG_PATHNAME = 0x3710
PID_TAG_ATTACH_CONTENT_ID = 0x3712


class AttachMethod(IntEnum):
    """`PidTagAttachMethod` ([MS-OXCMSG] 2.2.2.9) — where an attachment's content is.

    `BY_REF_RESOLVE` (3) is in the specification and not in upstream's
    `TryFrom<i32>`; the module docstring says why it is here. An unknown
    value is `PstUnsupportedError`, never a guess.
    """

    NONE = 0x00000000
    BY_VALUE = 0x00000001
    BY_REFERENCE = 0x00000002
    BY_REF_RESOLVE = 0x00000003
    BY_REF_ONLY = 0x00000004
    EMBEDDED_MESSAGE = 0x00000005
    OLE = 0x00000006
    BY_WEB_REFERENCE = 0x00000007

    @classmethod
    def from_wire(cls, value: int) -> AttachMethod:
        """The `PidTagAttachMethod` value as a method; `PstUnsupportedError` naming any other value."""
        if isinstance(value, bool) or not isinstance(value, int):
            raise PstFormatError(f"PidTagAttachMethod is not an integer: {type(value).__name__}")
        try:
            return cls(value)
        except ValueError:
            raise PstUnsupportedError(f"unknown attachment method {value}") from None

    @property
    def carries_bytes(self) -> bool:
        """True for the two methods whose content is in this store as bytes — upstream's `AttachmentData::Binary` arms."""
        return self in (AttachMethod.BY_VALUE, AttachMethod.OLE)


class Attachment:
    """One attachment of a message: its own property context, and whatever its method points at.

    Built from the `Message` that owns it and the NID of its sub-node — the
    row id of a row of that message's attachment table, which is what
    `Message.attachments()` iterates.
    """

    __slots__ = ("_entry", "_message", "_node", "_properties", "_sub_nodes")

    def __init__(self, message: Message, node: NodeId) -> None:
        """Open sub-node `node` of `message`; a NID that is not an attachment's is refused before anything is read."""
        if not isinstance(message, Message):
            raise TypeError(f"Attachment takes a Message, not {type(message).__name__}")
        if not isinstance(node, NodeId):
            raise TypeError(f"Attachment takes a NodeId, not {type(node).__name__}")
        node_type = node.id_type  # an unknown 5-bit type is a PstFormatError here
        if node_type is not NodeIdType.ATTACHMENT:
            raise PstFormatError(f"invalid attachment NID_TYPE: {node_type.debug_name}")
        self._message = message
        self._node = node
        self._entry = message.sub_node_entry(node)  # PstNotFoundError when the tree does not hold it
        store = message.store
        self._properties = PropertyContext.from_node(
            store.reader, self._entry, store.limits, codepage=store.codepage
        )
        self._sub_nodes: Mapping[NodeId, SubNodeLeafEntry] | None = None

    def __str__(self) -> str:
        return f"Attachment {{ {self._node} }}"

    # --- identity -------------------------------------------------------------------

    @property
    def message(self) -> Message:
        """The message this attachment hangs off — upstream's `Attachment::message`."""
        return self._message

    @property
    def node(self) -> NodeId:
        """The attachment's sub-node NID, which is also its row id in the attachment table."""
        return self._node

    @property
    def properties(self) -> PropertyContext:
        """The attachment's own property context ([MS-PST] 2.4.6.2)."""
        return self._properties

    @property
    def sub_nodes(self) -> Mapping[NodeId, SubNodeLeafEntry]:
        """The attachment's OWN sub-node tree — where an embedded message and an OLE stream live.

        Empty when the attachment node has no sub-node tree, which is the
        normal shape for a by-value attachment small enough to sit in the
        heap. See the module docstring for why this is the tree that is
        searched and upstream searches another.
        """
        if self._sub_nodes is None:
            sub_node = self._entry.sub_node
            self._sub_nodes = (
                {} if sub_node is None else self._message.store.reader.read_subnode_tree(sub_node)
            )
        return self._sub_nodes

    def sub_node_entry(self, node: NodeId) -> SubNodeLeafEntry:
        """The sub-node `node` of this attachment; `PstNotFoundError` when its tree does not hold it."""
        if not isinstance(node, NodeId):
            raise TypeError(f"Attachment.sub_node_entry takes a NodeId, not {type(node).__name__}")
        entry = self.sub_nodes.get(node)
        if entry is None:
            raise PstNotFoundError(f"sub-node {node} is not in attachment {self._node}'s sub-node tree")
        return entry

    def get(self, prop_id: int) -> PropValue | None:
        """One attachment property by id, decoded — `None` when it is absent or its HNID is 0."""
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
            raise PstFormatError(f"invalid {what} on attachment: {record.value_type.debug_name}, not a string")
        return value

    def _int32(self, prop_id: int, what: str) -> int:
        record = self._record(prop_id)
        if record is None:
            raise PstFormatError(f"missing {what} on attachment")
        value = self._properties.read(record)
        if not isinstance(value, int) or isinstance(value, bool):
            raise PstFormatError(f"invalid {what} on attachment: {record.value_type.debug_name}, not Integer32")
        return value

    @property
    def method_value(self) -> int:
        """`PidTagAttachMethod` (0x3705) as the raw i32 — upstream's `attachment_method()`, unvalidated."""
        return self._int32(PID_TAG_ATTACH_METHOD, "PidTagAttachMethod")

    @property
    def method(self) -> AttachMethod:
        """`PidTagAttachMethod` as an `AttachMethod`; an unknown value is `PstUnsupportedError` naming it."""
        return AttachMethod.from_wire(self.method_value)

    @property
    def size(self) -> int:
        """`PidTagAttachSize` (0x0E20) — upstream's `attachment_size()`: absent or not Integer32 is a refusal.

        The store's claim about the attachment's size on disk, which
        includes its properties and is therefore larger than `len(data())`.
        """
        return self._int32(PID_TAG_ATTACH_SIZE, "PidTagAttachSize")

    @property
    def rendering_position(self) -> int:
        """`PidTagRenderingPosition` (0x370B) — upstream's `rendering_position()`."""
        return self._int32(PID_TAG_RENDERING_POSITION, "PidTagRenderingPosition")

    @property
    def filename(self) -> str | None:
        """`PidTagAttachFilename` (0x3704) — the 8.3 name (`"leah_t~1.jpg"`)."""
        return self._text(PID_TAG_ATTACH_FILENAME, "PidTagAttachFilename")

    @property
    def long_filename(self) -> str | None:
        """`PidTagAttachLongFilename` (0x3707) — the name to use (`"leah_thumper.jpg"`)."""
        return self._text(PID_TAG_ATTACH_LONG_FILENAME, "PidTagAttachLongFilename")

    @property
    def pathname(self) -> str | None:
        """`PidTagAttachLongPathname` (0x3710) — where a by-reference attachment's content is."""
        return self._text(PID_TAG_ATTACH_LONG_PATHNAME, "PidTagAttachLongPathname")

    @property
    def mime_tag(self) -> str | None:
        """`PidTagAttachMimeTag` (0x370E) — the MIME type (`"image/png"`)."""
        return self._text(PID_TAG_ATTACH_MIME_TAG, "PidTagAttachMimeTag")

    @property
    def content_id(self) -> str | None:
        """`PidTagAttachContentId` (0x3712) — the `cid:` an HTML body refers to an inline image by."""
        return self._text(PID_TAG_ATTACH_CONTENT_ID, "PidTagAttachContentId")

    # --- what the method points at ----------------------------------------------------

    def _data_record(self) -> PropertyRecord:
        record = self._record(PID_TAG_ATTACH_DATA_BINARY)
        if record is None:
            raise PstFormatError("missing PidTagAttachDataBinary on attachment")
        return record

    def data(self) -> bytes | None:
        """The attachment's bytes, or `None` when its method does not carry any in this store.

        Bytes for `BY_VALUE` (`PidTagAttachDataBinary`) and `OLE`
        (`PidTagAttachDataObject`, whose sub-node holds the storage stream);
        `None` for every other method, including `EMBEDDED_MESSAGE` — that
        one is `embedded_message()`. Upstream's `data()`, with upstream's
        arms. `PstLimitError` when the value is larger than
        `limits.max_allocation`, enforced by the layer that ASSEMBLES the
        bytes: `BlockReader.read_data` refuses an `lcbTotal` past the ceiling
        *before* it reads a child block, which is earlier than any check
        here could be, and `prop_type.decode` bounds a multi-value the same
        way. A second check here would be code no test could reach.
        """
        method = self.method
        if not method.carries_bytes:
            return None
        record = self._data_record()
        if method is AttachMethod.BY_VALUE:
            value = self._properties.read(record)
            if not isinstance(value, bytes):
                raise PstFormatError(
                    f"invalid PidTagAttachDataBinary on attachment: {record.value_type.debug_name}, not Binary"
                )
            return value
        # OLE: the value is a PtypObject naming a sub-node whose DATA TREE is
        # the storage stream — upstream reads the blocks rather than the
        # property, because the object's own `size` is not the block total.
        ref = self._object_ref(record)
        entry = self.sub_node_entry(ref.node)
        return self._message.store.reader.read_data(entry.data)

    def _object_ref(self, record: PropertyRecord) -> ObjectRef:
        value = self._properties.read(record)
        if not isinstance(value, ObjectRef):
            raise PstFormatError(
                f"invalid PidTagAttachDataObject on attachment: {record.value_type.debug_name}, not Object"
            )
        return value

    def embedded_message(self) -> Message | None:
        """The message this attachment carries, or `None` when its method is not `EMBEDDED_MESSAGE`.

        The one place this port sees more than upstream does at the pinned
        revision — the module docstring arbitrates it. `PstFormatError` when
        `PidTagAttachDataObject` is absent or is not a `PtypObject`,
        `PstNotFoundError` when the sub-node it names is not in the owning
        message's sub-node tree, and `PstLimitError` when the nesting is
        deeper than `limits.max_embedded_message_depth` — which is what
        stops a message that embeds itself.
        """
        if self.method is not AttachMethod.EMBEDDED_MESSAGE:
            return None
        ref = self._object_ref(self._data_record())
        self._message.check_embedded_depth()
        entry = self.sub_node_entry(ref.node)
        return Message(
            self._message.store,
            ref.node,
            entry=entry,
            parent=self._message.parent,
            depth=self._message.depth + 1,
        )
