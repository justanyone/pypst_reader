#!/usr/bin/env python3
"""Regenerate src/pypst/_rtf_dictionary.py from the upstream Rust source.

[MS-OXRTFCP] 2.1.2.1 pre-loads the LZFu dictionary with a 207-byte ASCII
string, and every compressed RTF body in every PST refers back into it. A
mistyped byte would not fail loudly: it would corrupt one character of the
RTF preamble of every message and look like an RTF parser bug two layers up.
So it is never typed. It is read out of `crates/compressed-rtf/src/
dictionary.rs`, decoded from Rust's byte-string escapes, and written here —
and three invariants are proven on the way through: it is exactly 207 bytes,
it equals the string the specification prints (transcribed from the spec
page into SPEC_TEXT below, so the two sources check each other), and its
CRC-32 matches the value pinned when this script was first run.

Usage:  python3 scripts/extract_rtf_dictionary.py [--check]

    --check   verify the committed _rtf_dictionary.py matches the upstream
              source and exit non-zero if it does not (this is what CI runs)
"""

from __future__ import annotations

import re
import subprocess
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
UPSTREAM = REPO / "reference" / "outlook-pst-rs" / "crates" / "compressed-rtf" / "src" / "dictionary.rs"
TARGET = REPO / "src" / "pypst" / "_rtf_dictionary.py"

# [MS-OXRTFCP] 2.1.2.1 "Dictionary", as the specification page prints it,
# with its own <SP>/<CR>/<LF> placeholders. Transcribed from
# https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/4238b0e2-7147-42da-88c9-ea45a1243e67
SPEC_TEXT = (
    r"{\rtf1\ansi\mac\deff0\deftab720{\fonttbl;}{\f0\fnil<SP>\froman<SP>\fswiss<SP>"
    r"\fmodern<SP>\fscript<SP>\fdecor<SP>MS<SP>Sans<SP>SerifSymbolArialTimes<SP>New<SP>"
    r"RomanCourier{\colortbl\red0\green0\blue0<CR><LF>\par<SP>\pard\plain\f0\fs20\b\i\u\tab\tx"
)
SPEC_LENGTH = 207  # 2.1.2.1: the write offset after pre-loading is 207

# zlib.crc32 of the 207 bytes, pinned the first time this script ran so a
# regeneration from the wrong place (or a moved pin that touches the constant)
# is caught even if the other two checks were somehow both fooled.
PINNED_CRC32 = 0x2E98875B

# The Rust byte-string escapes that may appear in a `b"..."` literal.
_RUST_ESCAPES = {"\\": 0x5C, '"': 0x22, "'": 0x27, "n": 0x0A, "r": 0x0D, "t": 0x09, "0": 0x00}


def _pin() -> str:
    """The upstream revision this checkout is parked on, for the header."""
    try:
        out = subprocess.run(
            ["git", "-C", str(UPSTREAM.parents[3]), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip()
    except (subprocess.CalledProcessError, OSError, IndexError):
        return "unknown"


def decode_rust_byte_string(literal: str) -> bytes:
    """Decode the body of a Rust `b"..."` literal (the part between the quotes)."""
    out = bytearray()
    i = 0
    while i < len(literal):
        ch = literal[i]
        if ch != "\\":
            if ord(ch) > 0x7F:
                sys.exit(f"non-ASCII character in the byte-string literal at {i}")
            out.append(ord(ch))
            i += 1
            continue
        nxt = literal[i + 1 : i + 2]
        if nxt == "x":
            out.append(int(literal[i + 2 : i + 4], 16))
            i += 4
        elif nxt in _RUST_ESCAPES:
            out.append(_RUST_ESCAPES[nxt])
            i += 2
        else:
            sys.exit(f"unhandled Rust escape \\{nxt!r} at {i} — extend _RUST_ESCAPES deliberately")
    return bytes(out)


def spec_bytes() -> bytes:
    return SPEC_TEXT.replace("<SP>", " ").replace("<CR>", "\r").replace("<LF>", "\n").encode("ascii")


def extract() -> bytes:
    if not UPSTREAM.exists():
        sys.exit(f"upstream source not found at {UPSTREAM}\nrun scripts/get_rust_source.sh first")
    body = re.search(
        r'const INITIAL_DICTIONARY: &\[u8\] = b"((?:[^"\\]|\\.)*)";', UPSTREAM.read_text()
    )
    if body is None:
        sys.exit(
            "INITIAL_DICTIONARY not found in the upstream file — upstream may have "
            "restructured dictionary.rs; read it before touching this script"
        )
    data = decode_rust_byte_string(body.group(1))

    # Three invariants, checked here rather than trusted.
    if len(data) != SPEC_LENGTH:
        sys.exit(f"expected {SPEC_LENGTH} bytes, extracted {len(data)}")
    if data != spec_bytes():
        sys.exit("upstream's INITIAL_DICTIONARY does not equal the [MS-OXRTFCP] 2.1.2.1 string")
    if zlib.crc32(data) != PINNED_CRC32:
        sys.exit(f"CRC-32 of the dictionary is {zlib.crc32(data):#010x}, pinned {PINNED_CRC32:#010x}")
    return data


def render(data: bytes) -> str:
    rows = "\n".join(
        "        " + " ".join(f"{v}," for v in data[i : i + 12]) for i in range(0, len(data), 12)
    )
    return f'''"""The [MS-OXRTFCP] initial dictionary — mechanically extracted, not transcribed.

Ported from: crates/compressed-rtf/src/dictionary.rs (`INITIAL_DICTIONARY`)
Upstream:    microsoft/outlook-pst-rs @ {_pin()}
Spec:        [MS-OXRTFCP] 2.1.2.1 Dictionary

This file was GENERATED by scripts/extract_rtf_dictionary.py reading the
upstream Rust source directly. Do not hand-edit it: every LZFu-compressed
body refers back into these 207 bytes, so a single wrong byte here corrupts
one character of the RTF preamble of every message and looks like a parser
bug two layers up. Regenerate it instead. The script proves, on the way
through, that the bytes are exactly 207 long, equal the string the
specification prints, and carry the pinned CRC-32; tests/test_rtf.py re-proves
the same three facts against the committed module.
"""

from __future__ import annotations

# Decoded, it reads (with <CR><LF> at offsets 168-169):
#   {{\\rtf1\\ansi\\mac\\deff0\\deftab720{{\\fonttbl;}}{{\\f0\\fnil \\froman \\fswiss \\fmodern
#   \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{{\\colortbl
#   \\red0\\green0\\blue0<CR><LF>\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx
INITIAL_DICTIONARY: bytes = bytes(
    [
{rows}
    ]
)

"""207 bytes: the ASCII string every LZFu dictionary starts life holding."""
'''


def main() -> int:
    data = extract()
    rendered = render(data)
    if "--check" in sys.argv:
        current = TARGET.read_text() if TARGET.exists() else ""

        # Compare the DATA, not the header: the header carries the upstream
        # revision, which legitimately moves when the pin moves.
        def data_only(text: str) -> str:
            return "".join(re.findall(r"^\s+\d+,.*$", text, re.MULTILINE))

        if data_only(current) != data_only(rendered):
            print("_rtf_dictionary.py does not match the upstream source — regenerate it")
            return 1
        print("_rtf_dictionary.py matches upstream")
        return 0
    TARGET.write_text(rendered)
    print(f"wrote {TARGET.relative_to(REPO)} ({len(data)} bytes, 3 invariants proven)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
