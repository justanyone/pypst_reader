"""[MS-OXRTFCP] — the compressed-RTF header, initial dictionary, CRC, and the
section 3 worked examples, typed from the specification pages.

`pypstreader.rtf` is row P21 and may not exist yet. Everything that can be checked
without it (header constants, the dictionary text, the CRC on the examples'
CONTENTS via `pypstreader.crc`) runs unconditionally; the decompression vectors
`importorskip` the module and start biting the moment it lands.
"""

from __future__ import annotations

import struct

import pytest

from pypstreader.crc import compute_crc
from pypstreader.errors import PstFormatError

# --- 2.1.3.1.1 header ----------------------------------------------------------
#
#   Header = COMPSIZE RAWSIZE COMPTYPE CRC     ; 16 bytes, little-endian DWORDs
#   COMPRESSED   = %x4C.5A.46.75 ; Value of 0x75465A4C
#   UNCOMPRESSED = %x4D.45.4C.41 ; Value of 0x414C454D
#   COMPSIZE "the length of the compressed data (the CONTENTS field) in bytes
#             plus 12"; CRC "computed from the CONTENTS field" when COMPRESSED,
#             "MUST be set to %x00.00.00.00" when UNCOMPRESSED.
COMPRESSED = 0x75465A4C
UNCOMPRESSED = 0x414C454D
HEADER = struct.Struct("<IIII")


def test_comptype_constants_are_the_ascii_tags() -> None:
    """[MS-OXRTFCP] 2.1.3.1.1 COMPRESSED and UNCOMPRESSED. Verbatim; the tags are derived from the %x bytes."""
    assert struct.unpack("<I", bytes([0x4C, 0x5A, 0x46, 0x75]))[0] == COMPRESSED
    assert struct.unpack("<I", bytes([0x4D, 0x45, 0x4C, 0x41]))[0] == UNCOMPRESSED
    assert COMPRESSED.to_bytes(4, "little") == b"LZFu"
    assert UNCOMPRESSED.to_bytes(4, "little") == b"MELA"


# --- 2.1.2.1 the initial dictionary --------------------------------------------
#
# Verbatim, with the spec's <SP>/<CR>/<LF> markers substituted as it directs.
SPEC_DICTIONARY_TEXT = (
    r"{\rtf1\ansi\mac\deff0\deftab720{\fonttbl;}{\f0\fnil<SP>\froman<SP>\fswiss<SP>\fmodern<SP>"
    r"\fscript<SP>\fdecor<SP>MS<SP>Sans<SP>SerifSymbolArialTimes<SP>New<SP>RomanCourier"
    r"{\colortbl\red0\green0\blue0<CR><LF>\par<SP>\pard\plain\f0\fs20\b\i\u\tab\tx"
)
DICTIONARY = SPEC_DICTIONARY_TEXT.replace("<SP>", " ").replace("<CR>", "\r").replace("<LF>", "\n").encode("ascii")


def test_initial_dictionary_is_207_bytes() -> None:
    """[MS-OXRTFCP] 2.1.2.1: the write offset after initialisation is 207. Verbatim."""
    assert len(DICTIONARY) == 207


def test_initial_dictionary_agrees_with_the_worked_example_dumps() -> None:
    """[MS-OXRTFCP] 3.1.1.3–3.1.1.6: positions and contents the examples quote. Verbatim.

    3.1.1.3 nonprintables at 168/169 are 0x0d 0x0a; 3.1.1.4 offset 0 length
    12 is "{\\rtf1\\ansi\\" and offset 7 length 4 is "ansi"; 3.1.1.5 offset
    175 length 5 is "\\pard" and offset 144 length 2 is "lo"; 3.1.1.6 offset
    91 length 2 is "or".
    """
    assert DICTIONARY[168:170] == b"\r\n"
    assert DICTIONARY[0:12] == b"{\\rtf1\\ansi\\"
    assert DICTIONARY[7:11] == b"ansi"
    assert DICTIONARY[175:180] == b"\\pard"
    assert DICTIONARY[144:146] == b"lo"
    assert DICTIONARY[91:93] == b"or"


# --- section 3 worked examples -------------------------------------------------
#
# 3.1.1.1 "Simple Compressed RTF" — verbatim hex dump:
#   000000: 2d 00 00 00 2b 00 00 00-4c 5a 46 75 f1 c5 c7 a7
#   000010: 03 00 0a 00 72 63 70 67-31 32 35 42 32 0a f3 20
#   000020: 68 65 6c 09 00 20 62 77-05 b0 6c 64 7d 0a 80 0f
#   000030: a0
# 3.1.1.2: COMPSIZE 0x2d, RAWSIZE 0x2b, COMPTYPE 0x75465a4c, CRC 0xa7c7c5f1
# 3.1.1.6: output "{\rtf1\ansi\ansicpg1252\pard hello world}<CR><LF>"
EXAMPLE_1 = bytes.fromhex(
    "2d0000002b0000004c5a4675f1c5c7a7"
    "03000a007263706731323542320af320"
    "68656c090020627705b06c647d0a800f"
    "a0"
)
EXAMPLE_1_OUTPUT = b"{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n"

# 3.1.2.1 "Reading a Token from the Dictionary that Crosses WritePosition":
#   000000: 1a 00 00 00 1c 00 00 00-4c 5a 46 75 e2 d4 4b 51
#   000010: 41 00 04 20 57 58 59 5a-0d 6e 7d 01 0e b0
# 3.1.2.2: COMPSIZE 0x1a, RAWSIZE 0x1c, COMPTYPE 0x75465a4c, CRC 0x514bd4e2
# 3.1.2.4: output "{\rtf1 WXYZWXYZWXYZWXYZWXYZ}"  (the later dumps in that
#   section print "{\ref1", a typo in the spec: the reference 0004 at offset
#   0 length 6 is "{\rtf1", as 3.1.2.4's own token table says)
EXAMPLE_2 = bytes.fromhex("1a0000001c0000004c5a4675e2d44b51" "41000420" "5758595a" "0d6e7d01" "0eb0")
EXAMPLE_2_OUTPUT = b"{\\rtf1 WXYZWXYZWXYZWXYZWXYZ}"

EXAMPLES = [
    ("3.1.1", EXAMPLE_1, 0x2D, 0x2B, 0xA7C7C5F1, EXAMPLE_1_OUTPUT),
    ("3.1.2", EXAMPLE_2, 0x1A, 0x1C, 0x514BD4E2, EXAMPLE_2_OUTPUT),
]
EXAMPLE_IDS = [e[0] for e in EXAMPLES]


@pytest.mark.parametrize(("section", "data", "compsize", "rawsize", "crc", "output"), EXAMPLES, ids=EXAMPLE_IDS)
def test_example_headers_parse_as_the_spec_says(section: str, data: bytes, compsize: int, rawsize: int, crc: int, output: bytes) -> None:
    """[MS-OXRTFCP] 3.1.1.2 / 3.1.2.2 header fields. Verbatim, plus the 2.1.3.1.1 COMPSIZE rule (derived)."""
    got_compsize, got_rawsize, comptype, got_crc = HEADER.unpack_from(data, 0)
    assert (got_compsize, got_rawsize, comptype, got_crc) == (compsize, rawsize, COMPRESSED, crc), section
    assert compsize == len(data) - 4, "COMPSIZE = CONTENTS length + 12"
    assert rawsize == len(output), "RAWSIZE = uncompressed length"


@pytest.mark.parametrize(("section", "data", "compsize", "rawsize", "crc", "output"), EXAMPLES, ids=EXAMPLE_IDS)
def test_example_crc_is_the_pst_crc_of_the_contents(section: str, data: bytes, compsize: int, rawsize: int, crc: int, output: bytes) -> None:
    """[MS-OXRTFCP] 2.1.3.2 CRC over CONTENTS, seed 0, checked with pypstreader.crc. Verbatim expected value.

    The RTF CRC table (2.1.2.2.1) is the same 0xEDB88320 table as [MS-PST]
    5.3 — its first entries 0x00000000, 0x77073096, 0xee0e612c, 0x990951ba
    are the ones test_ms_pst_crc.py types — and the recurrence in 2.1.3.2
    is the same byte loop, so `compute_crc` is the RTF CRC too.
    """
    assert compute_crc(0, data[16:]) == crc, section


def test_crc_worked_example_first_two_bytes() -> None:
    """[MS-OXRTFCP] 3.3.1.2–3.3.1.4: CRC after 0x03 is 0x990951ba, after 0x03 0x00 is 0x2b2d53c3,
    and over the whole 3.1.1 CONTENTS is 0xA7C7C5F1. Verbatim."""
    assert compute_crc(0, b"\x03") == 0x990951BA
    assert compute_crc(0, b"\x03\x00") == 0x2B2D53C3
    assert compute_crc(0, EXAMPLE_1[16:]) == 0xA7C7C5F1


# --- decompression: needs pypstreader.rtf (row P21) ----------------------------------


@pytest.fixture
def decompress_rtf():
    rtf = pytest.importorskip("pypstreader.rtf", reason="pypstreader.rtf is row P21; these vectors bite when it lands")
    return rtf.decompress_rtf


@pytest.mark.parametrize(("section", "data", "compsize", "rawsize", "crc", "output"), EXAMPLES, ids=EXAMPLE_IDS)
def test_examples_decompress_to_the_spec_output(decompress_rtf, section: str, data: bytes, compsize: int, rawsize: int, crc: int, output: bytes) -> None:
    """[MS-OXRTFCP] 3.1.1.6 / 3.1.2.5 final output. Verbatim."""
    assert decompress_rtf(data) == output, section


# A stream whose output is exactly the initial dictionary: thirteen references
# into the pre-loaded text (12 x 17 bytes + 1 x 3 = 207), then the end marker.
# [MS-OXRTFCP] 2.1.3.1.5: a reference is a big-endian WORD, offset in the
# upper 12 bits, (length - 2) in the lower 4; the end marker is a reference
# whose offset equals the write position (207 + 207 = 414 = 0x19E) with
# length 0. 2.1.3.1.1: CONTROL bytes are read low bit first, 1 = reference,
# so eight references are 0xFF and the trailing six are 0x3F. Derived.
_TOKENS = [((off << 4) | (17 - 2)).to_bytes(2, "big") for off in range(0, 204, 17)]
_TOKENS.append(((204 << 4) | (3 - 2)).to_bytes(2, "big"))
_TOKENS.append(((414 << 4) | 0).to_bytes(2, "big"))
_DUMP_CONTENTS = b"\xff" + b"".join(_TOKENS[:8]) + b"\x3f" + b"".join(_TOKENS[8:])
DICTIONARY_DUMP = HEADER.pack(len(_DUMP_CONTENTS) + 12, 207, COMPRESSED, compute_crc(0, _DUMP_CONTENTS)) + _DUMP_CONTENTS


def test_implementation_dictionary_is_the_spec_dictionary(decompress_rtf) -> None:
    """[MS-OXRTFCP] 2.1.2.1 via a stream that copies the whole pre-loaded dictionary out. Derived."""
    assert decompress_rtf(DICTIONARY_DUMP) == DICTIONARY


def test_uncompressed_is_copied_and_its_crc_is_not_validated(decompress_rtf) -> None:
    """[MS-OXRTFCP] 2.2.3.1: UNCOMPRESSED contents are copied as-is and "The reader MUST NOT validate the value of the CRC field". Verbatim rules."""
    raw = b"{\\rtf1 plain}"
    stream = HEADER.pack(len(raw) + 12, len(raw), UNCOMPRESSED, 0xDEADBEEF) + raw
    assert decompress_rtf(stream) == raw


def test_unknown_comptype_is_corrupt(decompress_rtf) -> None:
    """[MS-OXRTFCP] 2.2.2.1: any COMPTYPE but the two "MUST treat the input stream as corrupt". Denial."""
    bad = bytearray(EXAMPLE_1)
    bad[8:12] = b"LZFX"
    with pytest.raises(PstFormatError):
        decompress_rtf(bytes(bad))


def test_crc_mismatch_is_corrupt(decompress_rtf) -> None:
    """[MS-OXRTFCP] 2.2.3.2: a CRC that does not match "MUST treat the input as corrupt". Denial."""
    bad = bytearray(EXAMPLE_1)
    bad[12] ^= 0x01
    with pytest.raises(PstFormatError):
        decompress_rtf(bytes(bad))


def test_truncated_input_is_corrupt(decompress_rtf) -> None:
    """[MS-OXRTFCP] 2.2.3.2: end of input before the end marker "MUST treat the input as corrupt". Denial."""
    with pytest.raises(PstFormatError):
        decompress_rtf(EXAMPLE_1[:-3])
