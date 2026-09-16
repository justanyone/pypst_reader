"""`pstreader` — the shorter name for `pypstreader`, and nothing else.

Ported from: not a port
This distribution has no implementation. It exists because two names lead to
one reader: `pypstreader` is the package, `pstreader` is what a person types
when they do not remember which. Everything here is a re-export, so
`pstreader.open(...)`, `pstreader.Store`, `pstreader.export_mbox` and the
rest are the *same objects* as `pypstreader`'s — not wrappers, not copies —
and an `isinstance` or an `except pstreader.PstError` written against either
name catches what the other raises.

`__version__` is `pypstreader.__version__` for the same reason: there is one
version in this system, the one the real package reports, and this
distribution pins it exactly (`pypstreader==<that version>`) so the two can
never drift apart in an environment.

The console script `pstreader` is `pypstreader.pypstreader:main`, the same
entry point the `pypstreader` command uses. Both run the same code and take
the same options; both announce themselves as `pypstreader`, because that is
the name of the thing, and a `--version` that said `pstreader` would be
claiming a version this distribution does not own.
"""

from __future__ import annotations

from pypstreader import *  # the alias IS the re-export; `pypstreader.__all__` is the contract
from pypstreader import __all__ as _pypstreader_all
from pypstreader import __version__ as __version__  # re-export, not a use

__all__ = list(_pypstreader_all)
