"""pypstreader — a pure-Python reader for Outlook PST stores.

A port of the READ path of microsoft/outlook-pst-rs (MIT). See NOTICE.

Pure stdlib by design: this package imports nothing outside the standard
library, and that is a load-bearing property rather than a boast — the whole
point of the port is a reader that installs as a plain wheel, is auditable
line by line, and is memory-safe against bytes an attacker chose.

Status: EARLY. The encoding, CRC, id, header, page, B-tree, block, heap,
BTH and property-context layers are ported and tested, and so is the message
store on top of them: `pypstreader.open(path)` returns a `Store` whose name,
record key, entry ids and named-property map can be read, its folder tree
walked (`store.root_folder.walk()` yields every `Folder`), and every
`Message` in a folder opened — its subject, sender, times and bodies, its
`Recipient`s, and its `Attachment`s, embedded messages included. P10 closed
the last promise on the list: `to_eml`/`eml_bytes`/`write_eml` assemble one
message into RFC 5322, `export_folder` writes a directory of `<nid>.eml`
and `export_mbox` writes one mbox per folder, which is the deliverable
everything else exists to enable, and the `pypstreader` command
(`pypstreader.pypstreader`, `python -m pypstreader.pypstreader`) is that
deliverable with a command line on it. See docs/INTERFACES.md
§ "pypstreader — the top level" for the rest of the promise, docs/PORTING-PLAN.md
for the order of work and MasterToDo.md for what is actually next.

`__all__` is the contract, kept sorted and deliberately small: the exception
family every caller catches, the limits a caller tunes, and the readers that
exist today — `open()` and the `Store` it returns, and the `EntryId` its
accessors hand back. `open` shadows the builtin inside this package on
purpose (`pypstreader.open(path)`, like `gzip.open`); it is
`pypstreader.messaging.store.open_store` under a shorter name. `tests/test_contract.py` runs every public callable in
this package — these names and every module's `__all__` — over every
fixture and a corruption corpus, and accepts nothing but a result or a
`PstError`. Internal helpers are not exported here; a name added to this
list joins that contract.
"""

from __future__ import annotations

from pypstreader.eml import eml_bytes, export_folder, to_eml, write_eml
from pypstreader.errors import (
    PstError,
    PstFormatError,
    PstLimitError,
    PstNotFoundError,
    PstUnsupportedError,
)
from pypstreader.limits import DEFAULT_LIMITS, Limits
from pypstreader.mbox import export_mbox
from pypstreader.messaging.attachment import Attachment, AttachMethod
from pypstreader.messaging.folder import Folder
from pypstreader.messaging.message import Message, Recipient, RecipientType
from pypstreader.messaging.store import EntryId, Store
from pypstreader.messaging.store import open_store as open
from pypstreader.ndb.header import Header, read_header

__version__ = "1.0.0"

__all__ = [  # noqa: RUF022 — plain `sorted()`, as the docstring says and test_contract pins
    "AttachMethod",
    "Attachment",
    "DEFAULT_LIMITS",
    "EntryId",
    "Folder",
    "Header",
    "Limits",
    "Message",
    "PstError",
    "PstFormatError",
    "PstLimitError",
    "PstNotFoundError",
    "PstUnsupportedError",
    "Recipient",
    "RecipientType",
    "Store",
    "__version__",
    "eml_bytes",
    "export_folder",
    "export_mbox",
    "open",
    "read_header",
    "to_eml",
    "write_eml",
]
