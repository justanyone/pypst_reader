"""The messaging layer — the message store, its folders and its messages.

`store` (P07) is the entry point: `Store.open(path)` reads the header, the
two B-trees and the property context of `NID_MESSAGE_STORE` (0x21), and
gives the display name, the store's record key and the entry ids of the
IPM subtree, the wastebasket and the finder. `named_prop` (P07) reads
`NID_NAME_TO_ID_MAP` (0x61), which translates the 0x8000+ property ids
into (GUID, name-or-number) pairs — without it a reader silently cannot
see any Outlook-specific property.

`folder` (P08) is the tree over it: `Store.root_folder` opens
`NID_ROOT_FOLDER` (0x122) and `Folder.walk()` yields every folder in the
store, pre-order and cycle-guarded, each with its display name, its counts
and the NIDs its three tables name.

`message` and `attachment` (P09) are the leaves: `Folder.messages()` and
`Store.open_message()` give a `Message` — its property context and the thin
accessors over it (class, subject, sender, times, the three body forms,
the transport headers), its `recipients()` from the recipient table in its
sub-node tree, and its `attachments()`, each its own sub-node with its own
property context. An attachment's `data()` is its bytes and its
`embedded_message()` is the whole message it carries, which upstream at the
pinned revision cannot open at all (`attachment.py`'s docstring).
"""

from pypst.messaging.attachment import Attachment, AttachMethod
from pypst.messaging.folder import Folder
from pypst.messaging.message import Message, Recipient, RecipientType
from pypst.messaging.named_prop import NamedPropertyMap
from pypst.messaging.store import EntryId, Store, open_store

__all__ = [
    "AttachMethod",
    "Attachment",
    "EntryId",
    "Folder",
    "Message",
    "NamedPropertyMap",
    "Recipient",
    "RecipientType",
    "Store",
    "open_store",
]
