"""Per-layer dump entry point: ``python -m pypst.debug <layer> <file>``.

Ported from: not a port
Harness code with no upstream counterpart: upstream ships one example binary
per layer; here they are one dispatcher so that every ported layer registers
its dumper in ``DUMPERS`` and the goldens in ``tests/golden/`` are compared
by ``tests/golden_parsers.py`` parsing both sides with the same parser.

A dumper is ``Callable[[Path], None]``: it prints upstream's example output
for that layer (``read_header``'s ten lines, and so on) and raises
``PstError`` on refusal, which this module turns into ``Error: …`` on stderr
and exit status 1. Nothing else may escape a dumper: a ``struct.error`` here
is the same bug it would be anywhere in the package.

Registration is one line in the layer's module or here, never in a test:
``DUMPERS["header"] = dump_header``.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from pypst.errors import PstError

DUMPERS: dict[str, Callable[[Path], None]] = {}


def main(argv: list[str] | None = None) -> int:
    names = ", ".join(sorted(DUMPERS)) or "(none registered yet)"
    parser = argparse.ArgumentParser(
        prog="python -m pypst.debug",
        description="Print one layer of a PST in the upstream example's format.",
        epilog=f"registered layers: {names}",
    )
    parser.add_argument("--list", action="store_true", help="print the registered layer names and exit")
    parser.add_argument("layer", nargs="?", help="which layer to dump")
    parser.add_argument("file", nargs="?", type=Path, help="the .pst to read")
    args = parser.parse_args(argv)

    if args.list:
        for name in sorted(DUMPERS):
            print(name)
        return 0
    if args.layer is None or args.file is None:
        parser.error("both <layer> and <file> are required (or use --list)")
    dumper = DUMPERS.get(args.layer)
    if dumper is None:
        parser.error(f"unknown layer {args.layer!r}; registered layers: {names}")
    try:
        dumper(args.file)
    except PstError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
