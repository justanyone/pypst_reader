"""pypst — a pure-Python reader for Outlook PST stores.

A port of the READ path of microsoft/outlook-pst-rs (MIT). See NOTICE.

Pure stdlib by design: this package imports nothing outside the standard
library, and that is a load-bearing property rather than a boast — the whole
point of the port is a reader that installs as a plain wheel, is auditable
line by line, and is memory-safe against bytes an attacker chose.

Status: EARLY. The encoding, CRC, id, header, page, B-tree and block layers
are ported and tested; the LTP and messaging layers are not, so `open()` and
`Store` do not exist yet (docs/INTERFACES.md § "pypst — the top level" says
what they will be). See docs/PORTING-PLAN.md for the order of work and
MasterToDo.md for what is actually next.

`__all__` is the contract, kept sorted and deliberately small: the exception
family every caller catches, the limits a caller tunes, and the one reader
that exists today. `tests/test_contract.py` runs every public callable in
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
from pypst.ndb.header import Header, read_header

__version__ = "0.0.1"

__all__ = [
    "DEFAULT_LIMITS",
    "Header",
    "Limits",
    "PstError",
    "PstFormatError",
    "PstLimitError",
    "PstNotFoundError",
    "PstUnsupportedError",
    "__version__",
    "read_header",
]
