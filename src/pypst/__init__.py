"""pypst — a pure-Python reader for Outlook PST stores.

A port of the READ path of microsoft/outlook-pst-rs (MIT). See NOTICE.

Pure stdlib by design: this package imports nothing outside the standard
library, and that is a load-bearing property rather than a boast — the whole
point of the port is a reader that installs as a plain wheel, is auditable
line by line, and is memory-safe against bytes an attacker chose.

Status: EARLY. The encoding, CRC, id, header, page, B-tree, block, heap,
BTH and property-context layers are ported and tested, and so is the message
store on top of them: `pypst.open(path)` returns a `Store` whose name,
record key, entry ids and named-property map can be read. Folders (P08) and
messages (P09) are not built yet, so a `Store` cannot yet be walked — see
docs/INTERFACES.md § "pypst — the top level" for the rest of the promise,
docs/PORTING-PLAN.md for the order of work and MasterToDo.md for what is
actually next.

`__all__` is the contract, kept sorted and deliberately small: the exception
family every caller catches, the limits a caller tunes, and the readers that
exist today — `open()` and the `Store` it returns, and the `EntryId` its
accessors hand back. `open` shadows the builtin inside this package on
purpose (`pypst.open(path)`, like `gzip.open`); it is
`pypst.messaging.store.open_store` under a shorter name. `tests/test_contract.py` runs every public callable in
this package — these names and every module's `__all__` — over every
fixture and a corruption corpus, and accepts nothing but a result or a
`PstError`. Internal helpers are not exported here; a name added to this
list joins that contract.
"""

from __future__ import annotations

from pypst.errors import (
    PstError,
    PstFormatError,
    PstLimitError,
    PstNotFoundError,
    PstUnsupportedError,
)
from pypst.limits import DEFAULT_LIMITS, Limits
from pypst.messaging.store import EntryId, Store
from pypst.messaging.store import open_store as open
from pypst.ndb.header import Header, read_header

__version__ = "0.0.1"

__all__ = [
    "DEFAULT_LIMITS",
    "EntryId",
    "Header",
    "Limits",
    "PstError",
    "PstFormatError",
    "PstLimitError",
    "PstNotFoundError",
    "PstUnsupportedError",
    "Store",
    "__version__",
    "open",
    "read_header",
]
