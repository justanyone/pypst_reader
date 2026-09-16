"""One folder → one mbox, each record the `.eml` `pypst.eml` assembles.

Ported from: not a port
Upstream ships no export format at all — its ten example binaries DUMP each
layer as text and none of them produces mail — so there is nothing to port
here and nothing to diff against. MBOX is the format asked for because it is
the one every mail tool on the planet already reads (RFC 4155): `mutt`,
Thunderbird, `formail`, `readpst`, Python's own `mailbox`, and every
e-discovery loader. One file per folder keeps the store's shape, which a
directory of per-message `.eml` files loses.

**What is written.** `export_mbox(folder, dest_dir)` writes
`<nid>.mbox` per folder — the folder's node id in hex, never its display
name, which is attacker-chosen text and therefore an attacker-chosen path —
plus `folders.txt`, two tab-separated columns mapping each file to the
folder path a human recognises (`0000156c.mbox` → `Top of Personal
Folders/Sent`). That index is the only place a display name is written, and
it is written as data, never as a path.

**The From_ line.** RFC 4155 § 2 wants `From <addr-spec> <asctime>`. The
address is the sender's SMTP address when the store kept one, else
`MAILER-DAEMON` — the conventional stand-in, and the one thing that can
never be mistaken for a real sender. The timestamp is
`PidTagClientSubmitTime`, else `PidTagMessageDeliveryTime`, else the Unix
epoch, always in UTC and always `time.asctime` spelling. A message with no
time gets the epoch rather than "now" for the same reason the synthetic
`Message-ID` is derived and not random: **two exports of one store must
produce identical bytes**, and a clock in the output makes that impossible.

**Quoting, and the one thing to know about it.** `mailbox.mbox` escapes a
body line that begins with `From ` to `>From ` on write, and does not
unescape anything on read. That is **mboxo**, not the mboxrd variant RFC
4155 § 4 prefers: a line that was ALREADY `>From ` is left alone, so the two
are indistinguishable afterwards. This module does not hand-roll the format
to fix that. The stdlib class is what every consumer of an mbox in Python
will read the file back with, and a file that agrees with the reader
everybody has is worth more than a file that is theoretically reversible and
read wrongly by default. What matters — and what `tests/test_mbox.py` pins,
on a body written to contain the line — is that **no body line can be
mistaken for a record separator**, so the message count survives the round
trip whatever a consumer does with the `>`.

**Line endings.** An `.eml` from `pypst.eml` uses RFC 5322's CRLF. An mbox
record uses LF, which is what the format has meant since it was a Unix
mailbox and what `mailbox.mbox` re-reads without surprises; `MBOX_POLICY` is
`pypst.eml.POLICY` with that one change.

Spec: RFC 4155 (the MIME application/mbox registration, and the only written
      definition of the format), RFC 5322 § 2.1 for the records themselves.
"""

from __future__ import annotations

import mailbox
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from pypst.eml import POLICY, folder_paths, readable_messages, to_eml
from pypst.errors import PstError
from pypst.limits import Limits

if TYPE_CHECKING:  # pragma: no cover - import cycle, types only
    from pypst.messaging.folder import Folder
    from pypst.messaging.message import Message

__all__ = [
    "export_mbox",
    "mbox_name",
]

# `pypst.eml.POLICY` with mbox's line endings (module docstring).
MBOX_POLICY = POLICY.clone(linesep="\n")

INDEX_NAME = "folders.txt"

# The sender an mbox record carries when the message names none.
MAILER_DAEMON = "MAILER-DAEMON"

# The timestamp a message with no time of its own gets: the epoch, in UTC.
# Deterministic by construction — see the module docstring.
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def mbox_name(folder: Folder) -> str:
    """The file name `export_mbox` gives a folder: its node id, and nothing the file chose."""
    return f"{folder.node.raw:08x}.mbox"


def _display_name(folder: Folder) -> str:
    """The folder's name for the index — a placeholder when it refuses, and never a path element.

    Separators are replaced rather than removed so that a display name of
    `../..` is still legible in the index as what it is.
    """
    try:
        name = folder.display_name
    except PstError:
        return f"<{folder.node.raw:08x}>"
    cleaned = "".join(" " if character < " " or character == "\x7f" else character for character in name)
    return cleaned.replace("/", "∕").strip() or f"<{folder.node.raw:08x}>"


def _from_line(message: Message) -> str:
    """`<addr-spec> <asctime>` for the record's From_ line (module docstring)."""
    address = MAILER_DAEMON
    for accessor in ("sender_smtp", "sender_email"):
        try:
            value = getattr(message, accessor)
        except PstError:
            continue
        candidate = "".join(value.split()) if value else ""  # a From_ line is delimited by spaces
        if "@" in candidate:  # an X.500 distinguished name has none, and is not an addr-spec
            address = candidate
            break
    when = None
    try:
        when = message.client_submit_time or message.delivery_time
    except PstError:
        when = None
    stamp = (when or EPOCH).astimezone(UTC)
    return f"{address} {time.asctime(stamp.timetuple())}"


def _record(message: Message, limits: Limits | None) -> mailbox.mboxMessage:
    """One message as an mbox record: the `.eml` `pypst.eml` builds, with a From_ line."""
    record = mailbox.mboxMessage(to_eml(message, limits=limits))
    record.policy = MBOX_POLICY
    record.set_from(_from_line(message))  # never the `time.gmtime()` default the stdlib sets
    return record


def export_mbox(
    folder: Folder,
    dest_dir: str | os.PathLike[str],
    *,
    recurse: bool = True,
    strict: bool = False,
    limits: Limits | None = None,
) -> int:
    """Write one `<nid>.mbox` per folder of the subtree into `dest_dir`; the messages written.

    `recurse=False` writes only this folder's own mbox. `strict=False`, the
    default, **skips a message that refuses** and goes on, as
    `pypst.eml.export_folder` does and for the same reason; `strict=True`
    propagates the first `PstError`. A folder whose contents table will not
    parse refuses either way — that is an answer about the folder, not about
    a message.

    An existing `<nid>.mbox` is replaced, not appended to: an export that
    doubled its output when run twice would be a trap, and
    `mailbox.mbox(create=True)` appends by default.
    """
    from pypst.messaging.folder import Folder as _Folder

    if not isinstance(folder, _Folder):
        raise TypeError(f"export_mbox takes a Folder, not {type(folder).__name__}")
    out = Path(dest_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = 0
    index: list[str] = []
    for current, path in folder_paths(folder, recurse=recurse, strict=strict):
        name = mbox_name(current)
        try:
            count = _write_one(current, out / name, strict=strict, limits=limits)
        except PstError as exc:  # the folder itself: its contents table will not parse
            if strict:
                raise
            index.append(f"{name}\t{path}\t# skipped: {type(exc).__name__}")
            continue
        index.append(f"{name}\t{path}\t{count}")
        written += count
    (out / INDEX_NAME).write_text(
        "# <nid>.mbox\tfolder path\tmessages (display names are data here, never paths)\n"
        + "".join(f"{line}\n" for line in index),
        encoding="utf-8",
    )
    return written


def _write_one(folder: Folder, path: Path, *, strict: bool, limits: Limits | None) -> int:
    """One folder's mbox, replacing whatever was there; the number of records written."""
    messages = readable_messages(folder, strict=strict)
    first = next(messages, None)  # a folder-level refusal, BEFORE the file is created
    path.unlink(missing_ok=True)
    box = mailbox.mbox(path, create=True)
    written = 0
    try:
        for message in ([] if first is None else [first, *messages]):
            try:
                box.add(_record(message, limits))
            except PstError:
                if strict:
                    raise
                continue
            written += 1
        box.flush()
    finally:
        box.close()
    return written
