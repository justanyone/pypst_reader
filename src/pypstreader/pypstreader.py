"""The `pypstreader` command: a PST goes in, mail comes out.

Ported from: not a port
Upstream ships ten example binaries that DUMP a layer apiece and nothing that
produces mail, so there is no command here to port and nothing to diff
against. `pypstreader.debug` is the port of those dumpers, layer by layer,
and stays what it is: a developer's window onto the format. This module is
the other thing — the tool the package exists for, which turns a store into
files a mail client opens.

**The default has to be the useful thing.** `pypstreader store.pst` writes
`store.mbox` in the current directory: every message of every folder, in
walk order, in the one format `mutt`, Thunderbird, `formail`, `readpst`,
Python's own `mailbox` and every e-discovery loader already read (RFC 4155).
No flags, no subcommand, no directory to invent. Everything else this
command does is an option on that sentence.

**The folder survives the flattening.** One mbox for a whole store loses the
tree that `--per-folder` keeps, so every record in it carries
`X-Pypstreader-Folder: <display path>` — the same path `--list` prints and
`--folder` takes — and the tree can be rebuilt from the file alone. It is a
header rather than a naming convention because an mbox has no names in it.
The value is the display path, control characters stripped and `/` inside a
display name replaced (`pypstreader.eml.folder_paths`): a folder called
`../..` is a legal store, and nothing a file chose is allowed to steer a
path or a header.

**Skipping is the default, and it is counted.** A store with one unreadable
message among fifty should still export the other forty-nine — that is what
`export_mbox` and `export_folder` already decided, and this command keeps
it. What it adds is that the skips are never silent: the one-line summary on
stderr says how many messages were written and how many were skipped, and
how many folders refused outright. `--strict` turns the first refusal into
the end of the run, for a caller who would rather have nothing than a
partial export.

**Nothing but `PstError` and `OSError` may reach the user.** A traceback out
of this command is a bug in this package, not a message to the person
holding the PST, so `main` catches those two, prints one line to stderr and
returns 1 — and catches `SystemExit` too, so that `main([...])` called
in-process by a test or another program returns an exit status instead of
raising one. Exit codes: **0** the run finished, **1** the store (or the
filesystem) refused, **2** the command line was wrong.

**What is never printed.** Folder display names are printed, by `--list`, by
`--verbose` and into the mbox header — they are the user's own data, shown
back to the user who named the file on the command line. Message content is
not: `--verbose` reports counts and folder names and stops there. The
summary of a private store is a count, which is the rule the whole test
suite is built around (CLAUDE.md § "Never print, log, or assert on private
store content").

Spec: RFC 4155 (mbox), RFC 5322 (the records themselves).
"""

from __future__ import annotations

import argparse
import codecs
import dataclasses
import mailbox
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from pypstreader import __version__
from pypstreader.eml import export_folder, folder_paths
from pypstreader.errors import PstError, PstNotFoundError
from pypstreader.limits import DEFAULT_LIMITS, Limits
from pypstreader.mbox import INDEX_NAME, export_mbox, mbox_name, mbox_record
from pypstreader.messaging.store import Store

if TYPE_CHECKING:  # pragma: no cover - types only
    from pypstreader.messaging.folder import Folder
    from pypstreader.ndb.ids import NodeId

__all__ = [
    "FOLDER_HEADER",
    "main",
]

PROG = "pypstreader"

# The header that carries the folder into a flattened mbox (module docstring).
FOLDER_HEADER = "X-Pypstreader-Folder"

# A `--verbose` line sink: where a per-folder progress line goes, or nowhere.
Reporter = Callable[[str], None]

# `store.pst` → `store.mbox`, in the current directory. The stem comes from
# the input's file name only; its directory is deliberately not reused, so a
# run over a read-only or shared location writes where the user is standing.
MBOX_SUFFIX = ".mbox"


@dataclasses.dataclass(frozen=True, slots=True)
class Tally:
    """What one run did, and the only thing it reports about the mail itself."""

    folders: int = 0
    written: int = 0
    skipped: int = 0
    folders_skipped: int = 0

    def line(self, destination: Path) -> str:
        parts = [
            f"{self.folders} folder{'' if self.folders == 1 else 's'}",
            f"{self.written} message{'' if self.written == 1 else 's'} written",
            f"{self.skipped} skipped",
        ]
        if self.folders_skipped:
            parts.append(f"{self.folders_skipped} folder(s) unreadable")
        return f"{PROG}: {', '.join(parts)} -> {destination}"


# --- the walk ------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class Selected:
    """One folder the run covers: the folder, its display path, and the messages it names.

    `message_ids` is `None` for a folder whose contents table refuses, which
    is a fact about the folder rather than about any message in it — the
    export skips it and the summary counts it apart.
    """

    folder: Folder
    path: str
    message_ids: tuple[NodeId, ...] | None


def _matches(path: str, wanted: tuple[str, ...]) -> bool:
    """A folder is covered when it IS one of the wanted paths or lives under one.

    Subtree semantics rather than exact match: `--folder 'Top of Personal
    Folders/Inbox'` is read the way a user reads it, as "the Inbox and what
    is filed in it". An empty `wanted` covers the whole store.
    """
    return not wanted or any(path == w or path.startswith(f"{w}/") for w in wanted)


def _select(root: Folder, wanted: tuple[str, ...], *, strict: bool) -> list[Selected]:
    """Every folder of the store the run covers, in walk order, with what each one names.

    Walked once: the `Folder` objects are kept, so the table each one parses
    here is the cached table the export reads afterwards rather than a
    second parse of the same bytes.
    """
    selected: list[Selected] = []
    for folder, path in folder_paths(root, strict=strict):
        if not _matches(path, wanted):
            continue
        try:
            ids: tuple[NodeId, ...] | None = folder.message_ids()
        except PstError:
            if strict:
                raise
            ids = None
        selected.append(Selected(folder, path, ids))
    if wanted and not selected:
        raise PstNotFoundError(f"no folder matches {', '.join(repr(w) for w in wanted)}; try --list")
    return selected


def _tally(selected: list[Selected], written: int) -> Tally:
    """The counts for a finished run: what was named, what was written, the difference."""
    named = sum(len(s.message_ids) for s in selected if s.message_ids is not None)
    refused = sum(1 for s in selected if s.message_ids is None)
    return Tally(folders=len(selected), written=written, skipped=named - written, folders_skipped=refused)


# --- the three outputs ---------------------------------------------------------------


def _write_one_mbox(
    selected: list[Selected],
    destination: Path,
    *,
    strict: bool,
    limits: Limits | None,
    report: Reporter,
) -> int:
    """Every selected folder's messages into ONE mbox; the number of records written.

    The file is replaced rather than appended to — `mailbox.mbox(create=True)`
    appends, and an export that doubled its output on a second run would be a
    trap (the same decision `pypstreader.mbox.export_mbox` made).
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.unlink(missing_ok=True)
    box = mailbox.mbox(destination, create=True)
    written = 0
    try:
        for entry in selected:
            if entry.message_ids is None:
                report(f"  ! {entry.path}: contents table refused")
                continue
            count = 0
            for node in entry.message_ids:
                try:
                    message = entry.folder.store.open_message(node, parent=entry.folder)
                    box.add(mbox_record(message, limits=limits, headers=[(FOLDER_HEADER, entry.path)]))
                except PstError:
                    if strict:
                        raise
                    continue
                count += 1
            written += count
            report(f"  {entry.path}: {count}")
        box.flush()
    finally:
        box.close()
    return written


def _write_per_folder(
    selected: list[Selected],
    destination: Path,
    *,
    strict: bool,
    limits: Limits | None,
    report: Reporter,
) -> int:
    """One `<nid>.mbox` per selected folder into `destination`, plus `folders.txt`.

    `export_mbox` writes each file, one folder at a time (`recurse=False`) so
    that `--folder` selects the same set here as everywhere else. It writes
    an index of its own each time it is called; this function replaces that
    with one index over the whole selection, in the same three-column shape
    and with display names still data rather than paths.
    """
    index: list[str] = []
    written = 0
    for entry in selected:
        name = mbox_name(entry.folder)
        if entry.message_ids is None:
            index.append(f"{name}\t{entry.path}\t# skipped: contents table refused")
            report(f"  ! {entry.path}: contents table refused")
            continue
        count = export_mbox(entry.folder, destination, recurse=False, strict=strict, limits=limits)
        index.append(f"{name}\t{entry.path}\t{count}")
        report(f"  {entry.path}: {count}")
        written += count
    (destination / INDEX_NAME).write_text(
        "# <nid>.mbox\tfolder path\tmessages (display names are data here, never paths)\n"
        + "".join(f"{line}\n" for line in index),
        encoding="utf-8",
    )
    return written


def _write_eml(
    selected: list[Selected],
    destination: Path,
    *,
    strict: bool,
    limits: Limits | None,
    report: Reporter,
) -> int:
    """One `<nid>.eml` per message of every selected folder, into `destination`."""
    written = 0
    for entry in selected:
        if entry.message_ids is None:
            report(f"  ! {entry.path}: contents table refused")
            continue
        count = export_folder(entry.folder, destination, recurse=False, strict=strict, limits=limits)
        report(f"  {entry.path}: {count}")
        written += count
    return written


def _list_folders(selected: list[Selected], out: TextIO) -> None:
    """The folder tree, one line per folder: the message count, then the path `--folder` takes.

    Paths rather than indentation because the path is the thing the next
    command needs, and `pypstreader.eml.folder_paths` has already made it
    safe to print — a `/` inside a display name is replaced, so splitting a
    line on `/` still gives the tree.
    """
    for entry in selected:
        count = "?" if entry.message_ids is None else str(len(entry.message_ids))
        print(f"{count:>7}  {entry.path}", file=out)


# --- the command line ----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """The command's whole surface. Separate from `main` so tests can read it."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Read an Outlook PST and write its mail out as mbox or .eml.",
        epilog=(
            "exit status: 0 the run finished, 1 the store or the filesystem refused, "
            "2 the command line was wrong"
        ),
    )
    parser.add_argument("file", type=Path, help="the .pst to read (Unicode stores only; ANSI is refused)")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="PATH",
        help="the mbox file to write (default: <file>.mbox here); a DIRECTORY for --per-folder and --format eml",
    )
    parser.add_argument(
        "--per-folder",
        action="store_true",
        help="one <nid>.mbox per folder into a directory, plus folders.txt naming them",
    )
    parser.add_argument(
        "--format",
        choices=("mbox", "eml"),
        default="mbox",
        help="mbox (default) or one <nid>.eml per message into a directory",
    )
    parser.add_argument(
        "--folder",
        action="append",
        default=[],
        metavar="PATH",
        dest="folders",
        help="only this folder and what is under it, by the display path --list prints; repeatable",
    )
    parser.add_argument("--list", action="store_true", help="print the folder tree with message counts and exit")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="stop at the first message or folder that refuses, instead of skipping it",
    )
    parser.add_argument("--max-depth", type=int, metavar="N", help="deepest folder nesting to walk")
    parser.add_argument(
        "--max-attachment-bytes", type=int, metavar="N", help="largest single value or attachment to assemble"
    )
    parser.add_argument("--max-embedded-depth", type=int, metavar="N", help="deepest embedded-message nesting")
    parser.add_argument(
        "--codepage",
        default="cp1252",
        metavar="NAME",
        help="the 8-bit code page for strings the store did not write in Unicode (default: cp1252)",
    )
    noise = parser.add_mutually_exclusive_group()
    noise.add_argument("-q", "--quiet", action="store_true", help="no summary line")
    noise.add_argument("-v", "--verbose", action="store_true", help="a line per folder (names and counts, never mail)")
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    return parser


def _limits(parser: argparse.ArgumentParser, args: argparse.Namespace) -> Limits | None:
    """A `Limits` from the three flags, or `None` when none was given.

    A non-positive ceiling is a command-line error, not a `Limits`
    `ValueError`: the value came from the user, and argparse's exit 2 is the
    right currency for it.
    """
    wanted = {
        "max_folder_depth": ("--max-depth", args.max_depth),
        "max_allocation": ("--max-attachment-bytes", args.max_attachment_bytes),
        "max_embedded_message_depth": ("--max-embedded-depth", args.max_embedded_depth),
    }
    given: dict[str, int] = {}
    for field, (flag, value) in wanted.items():
        if value is None:
            continue
        if value <= 0:
            parser.error(f"{flag} must be positive, not {value}")
        given[field] = value
    return dataclasses.replace(DEFAULT_LIMITS, **given) if given else None


def _destination(args: argparse.Namespace) -> Path:
    """Where the run writes: a file for one mbox, a directory for the other two."""
    if args.output is not None:
        return args.output
    if args.per_folder or args.format == "eml":
        return Path.cwd() / args.file.name.removesuffix(".pst")
    return Path.cwd() / (args.file.name.removesuffix(".pst") + MBOX_SUFFIX)


def main(argv: list[str] | None = None) -> int:
    """Run the command; the process exit status. Never raises — see the module docstring."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        if args.per_folder and args.format == "eml":
            parser.error("--per-folder writes mbox files; it cannot be combined with --format eml")
        try:
            codecs.lookup(args.codepage)
        except LookupError:
            parser.error(f"unknown code page {args.codepage!r}")
        limits = _limits(parser, args)
    except SystemExit as exit_:  # argparse: 2 for a usage error, 0 for --help/--version
        return int(exit_.code or 0)

    def report(line: str) -> None:
        if args.verbose:
            print(line, file=sys.stderr)

    destination = _destination(args)
    try:
        with Store.open(args.file, limits=limits or DEFAULT_LIMITS, codepage=args.codepage) as store:
            selected = _select(store.root_folder, tuple(args.folders), strict=args.strict)
            if args.list:
                _list_folders(selected, sys.stdout)
                return 0
            if args.per_folder or args.format == "eml":
                destination.mkdir(parents=True, exist_ok=True)
                writer = _write_per_folder if args.per_folder else _write_eml
            else:
                writer = _write_one_mbox
            written = writer(selected, destination, strict=args.strict, limits=limits, report=report)
        tally = _tally(selected, written)
    except PstError as exc:
        print(f"{PROG}: {args.file}: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:  # the store is not there, the destination is not writable
        print(f"{PROG}: {exc.filename or args.file}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(tally.line(destination), file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover - the module's own entry point
    sys.exit(main())
