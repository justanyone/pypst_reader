"""One message → one RFC 5322 `.eml`, assembled from what the store actually holds.

Ported from: not a port
Upstream has no export format at all — `outlook-pst-rs` ships ten example
binaries that DUMP each layer as text and nothing that produces mail — so
there is no oracle for this module and nothing to diff against. It is ours,
and its correctness argument is a round trip instead: `synth-basics.pst` was
built by EMLtoPST from `tests/fixtures/synthetic/basics/**/*.eml`, so for the
one message of that store this reader can reach, the source `.eml` IS the
expected output and `tests/test_eml.py` compares against it.

**The header policy, and the measurement it rests on.** A message that
travelled over SMTP keeps its internet headers in
`PidTagTransportMessageHeaders`; one composed locally never had any. P09
counted: **6 of the 12 openable corpus messages carry the property, and 1 of
the 1 openable private message does**, and the split follows the message
CLASS, not the store — a delivered `IPM.Note` has them, while appointments,
contacts, `IPM.Post` items and anything a tool wrote have none. So this
module does both, and says which:

1. When `transport_headers` is present it is parsed with `email.parser` and
   **passed through**: those headers are the truth about the message that was
   delivered, including the `Message-ID`, `Date`, `Received` chain,
   `In-Reply-To` and `References` that every threading decision downstream is
   made from. Only the headers that describe the ORIGINAL MIME body
   (`Content-*`, `MIME-Version`) are dropped, because the body here is
   re-assembled from MAPI properties and those headers would describe a
   structure that is no longer there.
2. Whatever is then still missing is synthesised from the MAPI properties —
   `From`, `To`/`Cc`/`Bcc`, `Subject`, `Date`, `Message-ID`.
3. **Every header this module added is named in `X-Pypstreader-Synthesized`**, a
   comma-separated list, so a consumer can tell a reconstructed header from a
   delivered one. The header is absent when nothing was added.

A synthesised `Message-ID` is never presented as original. When the store
holds `PidTagInternetMessageId` (0x1035) that value is used — it is the real
id, even though the header is ours, so the header name still appears in
`X-Pypstreader-Synthesized`. When it does not, the id is built from the store's
record key and the message's node id under the reserved domain
`pypstreader.invalid` (RFC 2606), which makes an invented id recognisable by
inspection as well as by the marker: `<pypstreader-<record-key>-<nid>@pypstreader.invalid>`.
It is deterministic — the same store and message give the same id every run —
because an export that threads differently on every run is worse than one
that does not thread at all.

**Bodies.** [MS-OXCMSG] lets a message carry up to three: `PidTagBody`
(text), `PidTagHtml` (bytes) and `PidTagRtfCompressed` (LZFu). They are
emitted as one `multipart/alternative` in increasing fidelity — plain, then
RTF (`application/rtf`), then HTML — which is the order RFC 2046 § 5.1.4
requires. A single representation is emitted as a single part. When RTF is
the ONLY body there is no text part and no HTML part: this module does not
convert RTF to text, and rather than invent a body it says so with
`X-Pypstreader-Body: rtf-only` (`X-Pypstreader-Body: none` when the message has no body
at all). The HTML is decoded with `PidTagInternetCodepage` (0x3FDE) when the
message declares one, else the store's code page, else UTF-8, always with
`errors="replace"`, and re-encoded as UTF-8: a part's declared charset must
match its bytes, and re-encoding to the original charset can fail where
decoding replaced a byte, which would turn a bad byte into an exception.

**Attachments.** `BY_VALUE` and `OLE` become MIME parts; `EMBEDDED_MESSAGE`
becomes a `message/rfc822` part holding the recursion of this function, and
the recursion is bounded by `limits.max_embedded_message_depth`. Every other
method (`BY_REFERENCE`, `BY_REF_RESOLVE`, `BY_REF_ONLY`, `NONE`) has no bytes
in this store to attach, and is recorded as a header —
`X-Pypstreader-Attachment-Skipped: <method> <filename>` — rather than dropped
silently or raised over: an attachment that is a pointer to a file server is
a fact about the message, and losing it quietly is worse than either.

**Deliberate divergences from the rest of the package**, all for the same
reason: this is the layer where attacker-controlled text meets a header
serialiser.

- **Every value that reaches a header is sanitised.** Control characters
  (including CR and LF) are removed from every passed-through header value,
  every filename, every MIME type and every content id before it is set.
  `PidTagAttachMimeTag` is attacker-controlled and `Content-Type: text/plain\\r\\nBcc: …`
  is header injection; `email.policy` refuses a linefeed with `ValueError`,
  which is a refusal in the wrong currency. A MIME type that is not two RFC
  2045 tokens after that becomes `application/octet-stream`.
- **`ValueError` from the `email` package is re-raised as `PstFormatError`**
  (`_guard`). Everything that flows into `email` here came out of the file,
  so its refusals are refusals about file content and a caller must be able
  to catch them with everything else. Nothing else is caught: a `TypeError`
  from this module would be this module's bug.
- **Part boundaries are deterministic.** `email` picks them from
  `random.randrange`, so two `eml_bytes` calls over one message would differ
  in bytes while agreeing in meaning. They are replaced with
  `----=_pypstreader.<nid>.<n>`, extended with a counter if that string occurs in
  the part it delimits.
- **Filenames on disk come from node ids, never from the message.**
  `export_folder` writes `<nid>.eml`. A `PidTagAttachLongFilename` of
  `../../etc/cron.d/x` is a path traversal and a subject is no better; the
  only name here that the file did not choose is its node id.

Spec: RFC 5322 (message format), RFC 2045-2047 (MIME, encoded words),
      RFC 2183 (Content-Disposition), RFC 2392 (`cid:` URLs),
      RFC 2606 (`.invalid`); [MS-OXCMSG] 2.2.1 (the body properties),
      2.2.2.9 (attachment methods), [MS-OXOMSG] 2.2.1.* (the internet
      headers this reads back).
"""

from __future__ import annotations

import codecs
import contextlib
import email.parser
import email.policy
import email.utils
import hashlib
import os
import re
from collections.abc import Iterator
from datetime import UTC
from email.message import EmailMessage
from pathlib import Path
from typing import TYPE_CHECKING

from pypstreader.errors import PstError, PstFormatError
from pypstreader.limits import Limits, VisitedSet, check_allocation, check_depth
from pypstreader.messaging.attachment import AttachMethod

if TYPE_CHECKING:  # pragma: no cover - import cycle, types only
    from pypstreader.messaging.folder import Folder
    from pypstreader.messaging.message import Attachment, Message

__all__ = [
    "eml_bytes",
    "eml_name",
    "export_folder",
    "folder_paths",
    "readable_messages",
    "to_eml",
    "write_eml",
]

# `email.policy.SMTP` is `default` with RFC 5322's CRLF line endings, which is
# what an `.eml` on disk should hold. `cte_type="7bit"` is this module's one
# change to it: every part is transfer-encoded down to 7-bit ASCII and every
# non-ASCII header is RFC 2047 encoded, so `eml_bytes` is pure ASCII and
# survives any transport, any pipe and any terminal. An 8-bit body would be
# smaller and no less correct, but only where everything downstream is 8-bit
# clean, and a reader cannot know that for its caller.
POLICY = email.policy.SMTP.clone(cte_type="7bit")

# `PidTagInternetMessageId` — the delivered Message-ID, kept as a property by
# stores whose transport headers were dropped.
PID_TAG_INTERNET_MESSAGE_ID = 0x1035
# `PidTagInternetCodepage` — the code page the HTML body is written in.
PID_TAG_INTERNET_CODEPAGE = 0x3FDE

SYNTHESIZED_HEADER = "X-Pypstreader-Synthesized"
BODY_HEADER = "X-Pypstreader-Body"
SKIPPED_HEADER = "X-Pypstreader-Attachment-Skipped"

# The domain an invented Message-ID lives under. RFC 2606 § 2 reserves
# `.invalid` for exactly this: a name guaranteed never to resolve.
SYNTHETIC_ID_DOMAIN = "pypstreader.invalid"

# Headers of the ORIGINAL body, which this module re-assembles: passing them
# through would describe a MIME structure that is not the one being written.
_BODY_HEADERS = ("content-type", "content-transfer-encoding", "content-disposition", "content-id", "content-length", "mime-version")

# The order synthesised headers are appended in, so two exports of one
# message agree byte for byte.
_SYNTHESIS_ORDER = ("From", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID")

# RFC 2045 § 5.1: a media type is two tokens separated by "/".
_MIME_TOKEN = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+$")

_FALLBACK_TYPE = ("application", "octet-stream")

# How many times `_set_boundaries` counts up before it stops guessing and
# hashes the payload instead (see the loop for why).
_BOUNDARY_ATTEMPTS = 8

# Control characters have no place in a header value; `str.translate` removes
# them in one pass. CR and LF are the injection vector, the rest are noise.
_CONTROL = {code: None for code in (*range(0x20), 0x7F)}

# Windows code page numbers that are not spelled `cp<n>` in Python's codec
# registry. Anything else is tried as `cp<n>` and falls back to UTF-8.
_CODEPAGE_NAMES = {
    708: "iso8859-6",
    20127: "us-ascii",
    20866: "koi8-r",
    21866: "koi8-u",
    28591: "iso8859-1",
    28592: "iso8859-2",
    28593: "iso8859-3",
    28594: "iso8859-4",
    28595: "iso8859-5",
    28596: "iso8859-6",
    28597: "iso8859-7",
    28598: "iso8859-8",
    28599: "iso8859-9",
    28603: "iso8859-13",
    28605: "iso8859-15",
    50220: "iso2022-jp",
    50225: "iso2022-kr",
    51932: "euc-jp",
    51949: "euc-kr",
    52936: "hz",
    54936: "gb18030",
    65000: "utf-7",
    65001: "utf-8",
}


@contextlib.contextmanager
def _guard(what: str) -> Iterator[None]:
    """Turn the `email` package's `ValueError` into `PstFormatError` (module docstring)."""
    try:
        yield
    except PstError:
        raise
    except (LookupError, ValueError) as exc:  # UnicodeError is a ValueError
        raise PstFormatError(f"{what}: {type(exc).__name__}: {exc}") from exc


def _clean(value: str | None) -> str | None:
    """A header-safe spelling of `value`: control characters removed, ends trimmed."""
    if value is None:
        return None
    return value.translate(_CONTROL).strip()


def _limits_of(message: Message, limits: Limits | None) -> Limits:
    if limits is None:
        return message.store.limits
    if not isinstance(limits, Limits):
        raise TypeError(f"to_eml takes a Limits, not {type(limits).__name__}")
    return limits


# --- headers ---------------------------------------------------------------------


def _transport_headers(message: Message) -> list[tuple[str, str]]:
    """The message's own internet headers, parsed, with the original body's headers dropped.

    `PidTagTransportMessageHeaders` is a blob of RFC 5322 headers the
    transport kept. It is parsed rather than pasted so that a folded header
    arrives as one value and a blob that carries a body by mistake loses it.
    Values are passed through as PARSED values and re-folded by
    `email.policy` on output: an RFC 2047 encoded word is re-encoded
    canonically rather than byte for byte, which preserves what the header
    says, and every ASCII header — `Message-ID` and `References` among them —
    comes out exactly as it went in.
    """
    raw = message.transport_headers
    if not raw:
        return []
    with _guard("parsing PidTagTransportMessageHeaders"):
        parsed = email.parser.Parser(policy=POLICY).parsestr(raw, headersonly=True)
        out: list[tuple[str, str]] = []
        for name, value in parsed.items():
            if name.lower() in _BODY_HEADERS:
                continue
            text = _clean(str(value))
            if text:
                out.append((name, text))
        return out


def _address(name: str | None, smtp: str | None, fallback: str | None) -> str | None:
    """`"Name" <addr>` for one person, or `None` when there is no address at all.

    The address is the SMTP one when the store kept it. When it did not, the
    fallback is whatever address the store DOES hold — on an
    Exchange-delivered message that is an X.500 distinguished name, which is
    not an addr-spec and is written in angle brackets anyway: it is the only
    identifier the file has, and dropping it loses the sender entirely.
    """
    display = _clean(name)
    addr = _clean(smtp) or _clean(fallback)
    if not addr:
        # A name with no address of any kind is not an addressee: there is
        # nothing to write in angle brackets and inventing one would put an
        # address in front of a reader that the message never had.
        return None
    if not display or display == addr:
        return f"<{addr}>"
    return f'"{email.utils.quote(display)}" <{addr}>'


def _sender(message: Message) -> str | None:
    return _address(message.sender_name, message.sender_smtp, message.sender_email)


def _recipient_headers(message: Message) -> dict[str, str]:
    """`To`/`Cc`/`Bcc` from the recipient table, by `PidTagRecipientType`.

    A recipient whose type is not one of the three named ones (an originator,
    or a value [MS-OXCMSG] 2.2.3.1 does not define) is not an addressee and
    is not written: the `From` line is where the originator belongs, and
    inventing a `To` out of an unknown type would put an address in front of
    a reader that the message never addressed.
    """
    from pypstreader.messaging.message import RecipientType

    buckets: dict[str, list[str]] = {"To": [], "Cc": [], "Bcc": []}
    names = {RecipientType.TO: "To", RecipientType.CC: "Cc", RecipientType.BCC: "Bcc"}
    for recipient in message.recipients():
        header = names.get(recipient.type) if isinstance(recipient.type, RecipientType) else None
        if header is None:
            continue
        address = _address(recipient.name, recipient.smtp, recipient.email)
        if address is not None:
            buckets[header].append(address)
    return {header: ", ".join(values) for header, values in buckets.items() if values}


def _date(message: Message) -> str | None:
    """`PidTagClientSubmitTime`, else `PidTagMessageDeliveryTime`, as RFC 5322 date-time in UTC.

    Submit time first because that is when the message was written, which is
    what a `Date` header means; delivery time is the receiving end's clock
    and is the fallback only.
    """
    when = message.client_submit_time or message.delivery_time
    if when is None:
        return None
    with _guard("formatting the message date"):
        return email.utils.format_datetime(when.astimezone(UTC))


def _record_key(message: Message) -> str:
    """The store's record key as hex — the store half of a synthetic Message-ID.

    A store that will not give up its record key (`PidTagRecordKey` absent or
    retyped) still gets an id, under `nokey`: the alternative is refusing to
    export a readable message because of a property nothing in the message
    needs.
    """
    try:
        return message.store.record_key.hex()
    except PstError:
        return "nokey"


def _synthetic_message_id(message: Message, prefix: str | None) -> str:
    """A deterministic id for a message that has none — see the module docstring.

    `prefix` is the carrier's local part for an embedded message, so that an
    embedded message's id is unique even where its node id repeats one the
    store uses at top level (sub-node ids are unique only inside their tree).
    """
    local = f"pypstreader-{_record_key(message)}-{message.node.raw:08x}" if prefix is None else f"{prefix}.{message.node.raw:08x}"
    return f"<{local}@{SYNTHETIC_ID_DOMAIN}>"


def _stored_message_id(message: Message) -> str | None:
    """`PidTagInternetMessageId` (0x1035) — the real id, when the store kept one."""
    value = message.get(PID_TAG_INTERNET_MESSAGE_ID)
    if value is None:
        return None
    if not isinstance(value, str):
        raise PstFormatError(f"invalid PidTagInternetMessageId on message: {type(value).__name__}, not a string")
    text = _clean(value)
    if not text:
        return None
    return text if text.startswith("<") and text.endswith(">") else f"<{text}>"


def _synthesised(message: Message, have: set[str], prefix: str | None) -> list[tuple[str, str]]:
    """Every header the transport headers did not supply, built from MAPI properties."""
    made: dict[str, str] = {}
    sender = _sender(message)
    if "from" not in have and sender is not None:
        made["From"] = sender
    for header, value in _recipient_headers(message).items():
        if header.lower() not in have:
            made[header] = value
    if "subject" not in have:
        subject = _clean(message.subject)
        if subject:  # an empty PidTagSubject is not a Subject header
            made["Subject"] = subject
    if "date" not in have:
        date = _date(message)
        if date is not None:
            made["Date"] = date
    if "message-id" not in have:
        made["Message-ID"] = _stored_message_id(message) or _synthetic_message_id(message, prefix)
    return [(name, made[name]) for name in _SYNTHESIS_ORDER if name in made]


def _message_id_local_part(value: str) -> str:
    """The local part of a `Message-ID`, for prefixing an embedded message's synthetic id."""
    inner = value.strip().lstrip("<").rstrip(">")
    return inner.split("@", 1)[0] or "pypstreader"


# --- bodies ----------------------------------------------------------------------


def _charset(message: Message) -> str:
    """The codec `PidTagHtml`'s bytes are written in (module docstring)."""
    value = message.get(PID_TAG_INTERNET_CODEPAGE)
    candidates: list[str] = []
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        candidates.append(_CODEPAGE_NAMES.get(value, f"cp{value}"))
    candidates.append(message.store.codepage)
    for name in candidates:
        try:
            return codecs.lookup(name).name
        except LookupError:
            continue
    return "utf-8"


def _bodies(message: Message) -> list[tuple[str, object]]:
    """The message's body representations, least faithful first (module docstring)."""
    out: list[tuple[str, object]] = []
    text = message.body_text
    if text:
        out.append(("plain", text))
    rtf = message.body_rtf_decompressed()
    if rtf:
        out.append(("rtf", rtf))
    html = message.body_html
    if html:
        out.append(("html", html.decode(_charset(message), errors="replace")))
    return out


def _set_body(msg: EmailMessage, kind: str, value: object) -> None:
    with _guard(f"building the {kind} body"):
        if kind == "rtf":
            msg.set_content(value, maintype="application", subtype="rtf")
        else:
            msg.set_content(value, subtype=kind, charset="utf-8")


def _add_body(msg: EmailMessage, kind: str, value: object) -> None:
    with _guard(f"building the {kind} body"):
        if kind == "rtf":
            msg.add_alternative(value, maintype="application", subtype="rtf")
        else:
            msg.add_alternative(value, subtype=kind, charset="utf-8")


# --- attachments -----------------------------------------------------------------


def _mime_type(tag: str | None) -> tuple[str, str]:
    """`PidTagAttachMimeTag` as `(maintype, subtype)`, or `application/octet-stream`.

    Parameters are dropped: a `charset=` the store wrote describes bytes this
    module attaches verbatim and may not describe them truthfully, and a
    wrong charset is worse than none. Anything that is not two RFC 2045
    tokens — which is what a header-injection attempt looks like once the
    control characters are gone — is refused into the fallback rather than
    written out.
    """
    text = _clean(tag)
    if not text:
        return _FALLBACK_TYPE
    media = text.split(";", 1)[0].strip()
    if media.count("/") != 1:
        return _FALLBACK_TYPE
    maintype, subtype = media.split("/")
    if not _MIME_TOKEN.match(maintype) or not _MIME_TOKEN.match(subtype):
        return _FALLBACK_TYPE
    return maintype.lower(), subtype.lower()


def _content_id(attachment: Attachment) -> str | None:
    """`PidTagAttachContentId` in the angle brackets RFC 2392 wants, or `None`."""
    text = _clean(attachment.content_id)
    if not text:
        return None
    inner = text.lstrip("<").rstrip(">").strip()
    return f"<{inner}>" if inner else None


def _filename(attachment: Attachment) -> str | None:
    """The long name if the store kept one, else the 8.3 name — sanitised, never a path."""
    return _clean(attachment.long_filename) or _clean(attachment.filename)


def _html_of(msg: EmailMessage) -> EmailMessage | None:
    part = msg.get_body(preferencelist=("html",))
    return part if part is not None and part.get_content_type() == "text/html" else None


def _references(html: str, cid: str) -> bool:
    """Does the HTML body point at this content id with a `cid:` URL (RFC 2392)?"""
    return f"cid:{cid.lstrip('<').rstrip('>').lower()}" in html.lower()


# --- the assembler ---------------------------------------------------------------


def to_eml(
    message: Message,
    *,
    synthesize_missing: bool = True,
    limits: Limits | None = None,
) -> EmailMessage:
    """One `Message` as an `email.message.EmailMessage` — the whole of the module docstring.

    `synthesize_missing=False` writes only what the file itself says: the
    transport headers when there are any and nothing else, so a caller who
    needs to know what a message carried rather than what it probably meant
    can have that. `limits` defaults to the store's; it bounds the bytes of
    one attachment (`max_allocation`) and the depth of embedded-message
    recursion (`max_embedded_message_depth`).

    Raises `PstError` and nothing else: `PstLimitError` past either ceiling,
    `PstFormatError` for a property this layer cannot use (and for the
    `email` package's own refusals, which are refusals about file content —
    module docstring).
    """
    from pypstreader.messaging.message import Message as _Message

    if not isinstance(message, _Message):
        raise TypeError(f"to_eml takes a Message, not {type(message).__name__}")
    # The recursion counter starts at the message's OWN nesting depth, not at
    # zero: a `Message` handed to this function may already be an embedded
    # one (`Message.depth`), and an export of it must respect the same
    # ceiling as an export of whatever carries it.
    return _assemble(message, _limits_of(message, limits), synthesize_missing, depth=message.depth, prefix=None)


def _assemble(message: Message, limits: Limits, synthesize: bool, *, depth: int, prefix: str | None) -> EmailMessage:
    msg = EmailMessage(policy=POLICY)
    passed = _transport_headers(message)
    for name, value in passed:
        with _guard(f"setting header {name}"):
            msg[name] = value
    made: list[tuple[str, str]] = []
    if synthesize:
        made = _synthesised(message, {name.lower() for name, _ in passed}, prefix)
        for name, value in made:
            with _guard(f"setting header {name}"):
                msg[name] = value
    if made:
        msg[SYNTHESIZED_HEADER] = ", ".join(name for name, _ in made)

    bodies = _bodies(message)
    if not bodies:
        _set_body(msg, "plain", "")
        msg[BODY_HEADER] = "none"
    else:
        _set_body(msg, *bodies[0])
        for kind, value in bodies[1:]:
            _add_body(msg, kind, value)
        if [kind for kind, _ in bodies] == ["rtf"]:
            msg[BODY_HEADER] = "rtf-only"

    _add_attachments(msg, message, limits, depth=depth, prefix=prefix)
    _clean_subpart_headers(msg)
    _set_boundaries(msg, f"{message.node.raw:08x}.{depth}")
    return msg


def _add_attachments(msg: EmailMessage, message: Message, limits: Limits, *, depth: int, prefix: str | None) -> None:
    """Every attachment of `message`, as a part or as an `X-Pypstreader-Attachment-Skipped` header."""
    html_part = _html_of(msg)
    html = html_part.get_content() if html_part is not None else ""
    for attachment in message.attachments():
        method = attachment.method  # PstUnsupportedError on a method no specification defines
        name = _filename(attachment)
        if method is AttachMethod.EMBEDDED_MESSAGE:
            _add_embedded(msg, message, attachment, limits, depth=depth, prefix=prefix, name=name)
            continue
        data = attachment.data()
        if data is None:
            msg[SKIPPED_HEADER] = _clean(f"{method.name} {name or '(unnamed)'}") or method.name
            continue
        check_allocation(len(data), limits.max_allocation, f"attachment {name or attachment.node} in one .eml")
        maintype, subtype = _mime_type(attachment.mime_tag)
        cid = _content_id(attachment)
        inline = cid is not None and _references(html, cid)
        with _guard(f"attaching {name or attachment.node}"):
            if inline and html_part is not None:
                html_part.add_related(
                    data, maintype=maintype, subtype=subtype, cid=cid, filename=name, disposition="inline"
                )
            else:
                msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name, cid=cid)


def _add_embedded(
    msg: EmailMessage,
    message: Message,
    attachment: Attachment,
    limits: Limits,
    *,
    depth: int,
    prefix: str | None,
    name: str | None,
) -> None:
    """An `EMBEDDED_MESSAGE` attachment as a `message/rfc822` part, depth-bounded.

    The ceiling is checked HERE as well as in `Attachment.embedded_message`,
    because `to_eml`'s `limits` is the caller's and the store's is the
    store's: an export asked to go no deeper than two levels must stop at
    two even over a store opened with the defaults.
    """
    check_depth(depth + 1, limits.max_embedded_message_depth, "embedded message depth in .eml export")
    embedded = attachment.embedded_message()
    if embedded is None:  # pragma: no cover - `method` said EMBEDDED_MESSAGE
        return
    parent_id = msg["Message-ID"]
    inner = _assemble(
        embedded,
        limits,
        synthesize=True,
        depth=depth + 1,
        prefix=_message_id_local_part(str(parent_id)) if parent_id is not None else prefix,
    )
    with _guard(f"attaching embedded message {embedded.node}"):
        msg.add_attachment(inner, filename=name)


def _own_parts(part: EmailMessage) -> Iterator[EmailMessage]:
    """`part` and its descendants, in pre-order, NOT crossing into an encapsulated message.

    `Message.walk` descends through a `message/rfc822` part into the message
    it carries, which is a different message with its own headers and its
    own boundaries — both already settled by its own `_assemble` call. The
    two helpers below must not touch them, so neither uses `walk`.
    """
    yield part
    if part.get_content_maintype() == "multipart":
        for sub in part.get_payload():
            yield from _own_parts(sub)


def _clean_subpart_headers(msg: EmailMessage) -> None:
    """Drop the `MIME-Version` the content manager writes on sub-parts.

    RFC 2045 § 4 puts it on the message, not on its parts; `set_content`
    adds one wherever it is called, which on a sub-part is noise that every
    reader ignores and one more line to diff. The `MIME-Version` of an
    ENCAPSULATED message is that message's own and is left alone.
    """
    for part in _own_parts(msg):
        if part is not msg:
            del part["MIME-Version"]


def _set_boundaries(msg: EmailMessage, tag: str) -> None:
    """Replace `email`'s random boundaries with deterministic ones (module docstring)."""
    parts = [part for part in _own_parts(msg) if part.get_content_maintype() == "multipart"]
    for index in reversed(range(len(parts))):  # children before their parent
        part = parts[index]
        payload = b"".join(sub.as_bytes(policy=POLICY) for sub in part.get_payload())
        base = f"----=_pypstreader.{tag}.{index}"
        boundary, bump = base, 0
        while boundary.encode("ascii") in payload:
            bump += 1
            if bump > _BOUNDARY_ATTEMPTS:
                # A crafted body can contain every counter this loop would
                # try — the tag is derived from a node id the file chose, so
                # the sequence is predictable to whoever wrote the file, and
                # scanning the payload once per attempt is the denial of
                # service. A body cannot contain its own SHA-256, so one
                # hash ends the search: that is a preimage, not a guess.
                boundary = f"{base}.{hashlib.sha256(payload).hexdigest()[:32]}"
                break
            boundary = f"{base}.{bump}"
        with _guard("setting a MIME boundary"):
            part.set_boundary(boundary)


def eml_bytes(message: Message, *, synthesize_missing: bool = True, limits: Limits | None = None) -> bytes:
    """`to_eml` serialised: RFC 5322 with CRLF line endings, 7-bit clean, and byte-for-byte repeatable."""
    built = to_eml(message, synthesize_missing=synthesize_missing, limits=limits)
    with _guard("serialising the message"):
        return built.as_bytes(policy=POLICY)


def write_eml(
    message: Message,
    path: str | os.PathLike[str],
    *,
    synthesize_missing: bool = True,
    limits: Limits | None = None,
) -> Path:
    """`eml_bytes` written to `path` (binary, so the CRLF endings survive); the path written."""
    target = Path(path)
    data = eml_bytes(message, synthesize_missing=synthesize_missing, limits=limits)
    target.write_bytes(data)
    return target


def eml_name(message: Message) -> str:
    """The file name `export_folder` gives a message: its node id, and nothing the file chose."""
    return f"{message.node.raw:08x}.eml"


def folder_paths(folder: Folder, *, recurse: bool = True, strict: bool = False) -> Iterator[tuple[Folder, str]]:
    """The folders an export covers, each with the display path a human reads it by.

    Pre-order and self first, like `Folder.walk`, with the same ceiling
    (`limits.max_folder_depth`) and the same cycle guard — re-created here
    rather than borrowed because `Folder.walk` cannot carry a path down with
    it: a folder does not know its parent. `recurse=False` yields this
    folder alone.

    `strict=False` treats a folder whose HIERARCHY table refuses as a leaf
    and carries on; `strict=True` propagates. Either way the display path is
    only ever data — `_display_path` replaces the separators and the control
    characters in a display name, because a folder called `../..` is a legal
    store and an illegal path.
    """
    from pypstreader.messaging.folder import Folder as _Folder

    if not isinstance(folder, _Folder):
        raise TypeError(f"folder_paths takes a Folder, not {type(folder).__name__}")
    limits = folder.store.limits
    seen = VisitedSet("folder tree", limits.max_folders)
    stack: list[tuple[Folder, str, int]] = [(folder, _display_path(folder), 0)]
    while stack:
        current, path, depth = stack.pop()
        check_depth(depth, limits.max_folder_depth, "folder tree depth")
        seen.add(current.node)
        yield current, path
        if not recurse:
            return
        try:
            children = list(current.subfolders())
        except PstError:
            if strict:
                raise
            continue
        stack.extend((child, f"{path}/{_display_path(child)}", depth + 1) for child in reversed(children))


def _display_path(folder: Folder) -> str:
    """One folder's display name as an index entry: never a path element, never a control character."""
    try:
        name = folder.display_name
    except PstError:
        return f"<{folder.node.raw:08x}>"
    cleaned = (_clean(name) or "").replace("/", "\u2215").replace("\\", "\u2216")
    return cleaned or f"<{folder.node.raw:08x}>"


def readable_messages(folder: Folder, *, strict: bool = False) -> Iterator[Message]:
    """Every message of one folder that opens, in row-matrix order.

    A folder whose CONTENTS table will not parse refuses here whatever
    `strict` says: that is an answer about the folder, and an exporter has to
    decide what to do with a whole folder it cannot read.
    `synth-basics.pst`'s Inbox is the witness. A single message that refuses
    — `javalibpst-dist-list.pst` has one, a message node with no sub-node
    tree — is skipped unless `strict`.
    """
    from pypstreader.messaging.folder import Folder as _Folder

    if not isinstance(folder, _Folder):
        raise TypeError(f"readable_messages takes a Folder, not {type(folder).__name__}")
    for node in folder.message_ids():
        try:
            yield folder.store.open_message(node, parent=folder)
        except PstError:
            if strict:
                raise
            continue


def export_folder(
    folder: Folder,
    dest_dir: str | os.PathLike[str],
    *,
    recurse: bool = True,
    strict: bool = False,
    limits: Limits | None = None,
) -> int:
    """Write one `<nid>.eml` per message of `folder` into `dest_dir`; the number written.

    `recurse` covers the subtree (`folder_paths`). `strict=False`, the
    default, **skips what refuses** — a message that will not open, and a
    folder whose contents table will not parse — and goes on: a store with
    one unreadable folder among fifty should still export the other
    forty-nine, and `synth-basics.pst` is exactly that store.
    `strict=True` propagates the first `PstError` instead.

    Names are node ids (`eml_name`). Nothing from the message reaches the
    path: `PidTagSubject` and `PidTagAttachLongFilename` are attacker-chosen
    strings and `../` is a legal value for both.
    """
    out = Path(dest_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = 0
    for current, _ in folder_paths(folder, recurse=recurse, strict=strict):
        try:
            for message in readable_messages(current, strict=strict):
                try:
                    write_eml(message, out / eml_name(message), limits=limits)
                except PstError:
                    if strict:
                        raise
                    continue
                written += 1
        except PstError:  # the folder itself: its contents table will not parse
            if strict:
                raise
            continue
    return written
