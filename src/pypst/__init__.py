"""pypst — a pure-Python reader for Outlook PST stores.

A port of the READ path of microsoft/outlook-pst-rs (MIT). See NOTICE.

Pure stdlib by design: this package imports nothing outside the standard
library, and that is a load-bearing property rather than a boast — the whole
point of the port is a reader that installs as a plain wheel, is auditable
line by line, and is memory-safe against bytes an attacker chose.

Status: EARLY. The encoding and CRC layers are ported and tested; the NDB,
LTP and messaging layers are not. See docs/PORTING-PLAN.md for the order of
work and MasterToDo.md for what is actually next.
"""

from __future__ import annotations

__version__ = "0.0.1"

from pypst.errors import PstError, PstFormatError, PstLimitError, PstUnsupportedError

__all__ = [
    "PstError",
    "PstFormatError",
    "PstLimitError",
    "PstUnsupportedError",
    "__version__",
]
