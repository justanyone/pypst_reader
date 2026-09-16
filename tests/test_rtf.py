"""The LZFu decompressor: denial cases first, then the spec's vectors, then properties.

Every hex vector in this file is typed from the [MS-OXRTFCP] page cited next
to it — not copied from upstream's test block. That is the point of the
tier: the parity twins in tests/parity/test_rtf_parity.py prove we pass what
upstream passes; these prove the specification's own examples, which is the
one check that could catch a bug upstream and this port share.

Nothing here touches a mail store except the xfail at the bottom, which
waits on the messaging layer and reads a public, licensed fixture.
"""

from __future__ import annotations

import importlib.util
import os
import random
import re
import struct
import sys

import pytest

from pypst._rtf_dictionary import INITIAL_DICTIONARY
from pypst.crc import compute_crc
from pypst.errors import PstError, PstFormatError, PstLimitError
from pypst.rtf import (
    DICTIONARY_SIZE,
    HEADER_SIZE,
    CompressedRtfHeader,
    CompressionType,
    decompress_rtf,
    read_header,
)
from tests.conftest import PUBLIC, REFERENCE, REPO
from tests.rtf_compress import compress_rtf, encode_rtf_uncompressed

# --- Specification vectors -------------------------------------------------
#
# [MS-OXRTFCP] 3.1.1.1 "Compressed RTF Data" (Example 1: Simple Compressed RTF)
SPEC_EXAMPLE_1 = bytes.fromhex(
    "2d 00 00 00 2b 00 00 00 4c 5a 46 75 f1 c5 c7 a7"
    "03 00 0a 00 72 63 70 67 31 32 35 42 32 0a f3 20"
    "68 65 6c 09 00 20 62 77 05 b0 6c 64 7d 0a 80 0f"
    "a0"
)
# [MS-OXRTFCP] 3.2.1 "Example 1: Simple RTF": the text those bytes encode.
SPEC_EXAMPLE_1_TEXT = b"{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n"

# [MS-OXRTFCP] 3.1.2.1 "Compressed RTF" (Example 2: a token crossing WritePosition)
SPEC_EXAMPLE_2 = bytes.fromhex(
    "1a 00 00 00 1c 00 00 00 4c 5a 46 75 e2 d4 4b 51"
    "41 00 04 20 57 58 59 5a 0d 6e 7d 01 0e b0"
)
# [MS-OXRTFCP] 3.2.2 "Example 2: Compressing with Tokens that Cross WritePosition"
SPEC_EXAMPLE_2_TEXT = b"{\\rtf1 WXYZWXYZWXYZWXYZWXYZ}"

# [MS-OXRTFCP] 3.3.1.4: the CRC of Example 1's payload (bytes 0x10 through 0x30).
SPEC_CRC_EXAMPLE = 0xA7C7C5F1

LZFU = CompressionType.COMPRESSED
MELA = CompressionType.UNCOMPRESSED


def _stream(payload: bytes, *, raw_size: int, comp_type: int = LZFU, comp_size: int | None = None, crc: int | None = None) -> bytes:
    """Assemble a PR_RTF_COMPRESSED value, defaulting every header field to the honest value."""
    if comp_size is None:
        comp_size = len(payload) + 12
    if crc is None:
        crc = compute_crc(0, payload)
    return struct.pack("<IIII", comp_size, raw_size, comp_type, crc) + payload


def _reference(offset: int, length: int) -> bytes:
    return ((offset << 4) | (length - 2)).to_bytes(2, "big")


# Where the initial dictionary leaves the write offset ([MS-OXRTFCP] 2.1.2.1).
WRITE0 = len(INITIAL_DICTIONARY)


# --- Denial: the header --------------------------------------------------------


def test_empty_input_is_refused() -> None:
    with pytest.raises(PstFormatError):
        decompress_rtf(b"")


@pytest.mark.parametrize("length", range(1, HEADER_SIZE))
def test_truncated_header_is_refused(length: int) -> None:
    with pytest.raises(PstFormatError):
        decompress_rtf(SPEC_EXAMPLE_1[:length])
    with pytest.raises(PstFormatError):
        read_header(SPEC_EXAMPLE_1[:length])


def test_buffer_longer_than_compsize_is_refused() -> None:
    with pytest.raises(PstFormatError):
        decompress_rtf(SPEC_EXAMPLE_1 + b"\x00")


def test_buffer_shorter_than_compsize_is_refused() -> None:
    """The buffer was cut short: COMPSIZE no longer describes it."""
    with pytest.raises(PstFormatError):
        decompress_rtf(SPEC_EXAMPLE_1[:-1])


@pytest.mark.parametrize("delta", [-1, 1, 0x10000, -0x2D])
def test_compsize_field_disagreeing_with_the_buffer_is_refused(delta: int) -> None:
    comp_size = (0x2D + delta) & 0xFFFFFFFF
    data = struct.pack("<I", comp_size) + SPEC_EXAMPLE_1[4:]
    with pytest.raises(PstFormatError):
        decompress_rtf(data)


@pytest.mark.parametrize("magic", [b"XXXX", b"LZFU", b"lzfu", b"\x00\x00\x00\x00", b"MELa", b"\xff\xff\xff\xff"])
def test_unknown_comptype_is_refused(magic: bytes) -> None:
    """[MS-OXRTFCP] 2.2.2.1: any value other than the two magics is corrupt."""
    data = SPEC_EXAMPLE_1[:8] + magic + SPEC_EXAMPLE_1[12:]
    with pytest.raises(PstFormatError):
        decompress_rtf(data)


def test_header_crc_mismatch_is_refused() -> None:
    corrupted = bytearray(SPEC_EXAMPLE_1)
    corrupted[12] ^= 0x01
    with pytest.raises(PstFormatError):
        decompress_rtf(bytes(corrupted))


@pytest.mark.parametrize("index", [HEADER_SIZE, HEADER_SIZE + 7, len(SPEC_EXAMPLE_1) - 1])
def test_payload_bit_flip_fails_the_crc(index: int) -> None:
    corrupted = bytearray(SPEC_EXAMPLE_1)
    corrupted[index] ^= 0x80
    with pytest.raises(PstFormatError):
        decompress_rtf(bytes(corrupted))


# --- Denial: the token stream (every stream below carries a correct CRC) -------


def test_half_token_is_refused() -> None:
    """Control says 'reference', one byte remains: a truncated big-endian word."""
    with pytest.raises(PstFormatError):
        decompress_rtf(_stream(b"\x01\x0c", raw_size=0))


def test_payload_ending_before_the_terminator_is_refused() -> None:
    """[MS-OXRTFCP] 2.2.3.2: end of input before termination MUST be corrupt.

    Upstream accepts this and returns the eight literals; this port does
    not (see the module docstring). The CRC is correct, so it is the token
    loop and nothing earlier that refuses.
    """
    with pytest.raises(PstFormatError):
        decompress_rtf(_stream(b"\x00" + b"abcdefgh", raw_size=8))


def test_payload_ending_inside_a_run_is_refused() -> None:
    with pytest.raises(PstFormatError):
        decompress_rtf(_stream(b"\x00" + b"abc", raw_size=3))


def test_empty_payload_is_refused() -> None:
    with pytest.raises(PstFormatError):
        decompress_rtf(_stream(b"", raw_size=0))


@pytest.mark.parametrize("offset", [WRITE0 + 1, 300, 4095])
def test_reference_into_unwritten_dictionary_is_refused(offset: int) -> None:
    """Nothing has been written past offset 207 yet; a reference there is not the format.

    The stream is otherwise complete — it ends with a correct terminator —
    so the unwritten-region check is the only thing that can refuse it.
    """
    payload = b"\x03" + _reference(offset, 2) + _reference(WRITE0 + 2, 2)
    with pytest.raises(PstFormatError):
        decompress_rtf(_stream(payload, raw_size=2))


def test_reference_just_below_the_end_offset_is_read() -> None:
    """...whereas the last pre-loaded bytes are fair game (boundary of the previous test)."""
    payload = b"\x03" + _reference(WRITE0 - 2, 2) + _reference(WRITE0 + 2, 2)
    assert decompress_rtf(_stream(payload, raw_size=2)) == INITIAL_DICTIONARY[-2:]


def test_rawsize_above_max_output_is_a_limit_error_not_a_format_error() -> None:
    data = SPEC_EXAMPLE_1[:4] + struct.pack("<I", 0x2C) + SPEC_EXAMPLE_1[8:]
    with pytest.raises(PstLimitError) as excinfo:
        decompress_rtf(data, max_output=0x2B)
    assert not isinstance(excinfo.value, PstFormatError)
    # The honest RAWSIZE at exactly the ceiling is fine.
    assert decompress_rtf(SPEC_EXAMPLE_1, max_output=0x2B) == SPEC_EXAMPLE_1_TEXT


def test_absurd_rawsize_trips_the_default_limit() -> None:
    data = SPEC_EXAMPLE_1[:4] + struct.pack("<I", 0xFFFFFFFF) + SPEC_EXAMPLE_1[8:]
    with pytest.raises(PstLimitError):
        decompress_rtf(data)


def test_output_is_capped_even_when_rawsize_lies_small() -> None:
    """RAWSIZE says 0; the token stream expands to 8 + 17 * 24 bytes."""
    payload = bytearray(b"\x00abc\x00\x00\x00\x00\x00")  # one run of eight literals
    for _ in range(3):  # three runs of eight references, each reading across the write offset
        payload.append(0xFF)
        payload += _reference(WRITE0, 17) * 8
    payload += b"\x01" + _reference(_write_offset_after(bytes(payload)), 2)  # the terminator
    honest = decompress_rtf(_stream(bytes(payload), raw_size=0))
    assert len(honest) == 8 + 17 * 24
    with pytest.raises(PstLimitError):
        decompress_rtf(_stream(bytes(payload), raw_size=0), max_output=100)


def _write_offset_after(payload: bytes) -> int:
    """Where the dictionary's write offset sits after decoding `payload` (no terminator in it)."""
    # Decode by counting: every literal and every referenced byte advances it by one.
    write = WRITE0
    pos = 0
    while pos < len(payload):
        control = payload[pos]
        pos += 1
        for bit in range(8):
            if pos >= len(payload):
                break
            if control & (1 << bit):
                write += (payload[pos + 1] & 0x0F) + 2
                pos += 2
            else:
                write += 1
                pos += 1
    return write & (DICTIONARY_SIZE - 1)


def test_uncompressed_rawsize_past_the_buffer_is_refused() -> None:
    data = struct.pack("<IIII", 5 + 12, 6, MELA, 0) + b"hello"
    with pytest.raises(PstFormatError):
        decompress_rtf(data)


def test_uncompressed_rawsize_above_max_output_is_a_limit_error() -> None:
    with pytest.raises(PstLimitError):
        decompress_rtf(encode_rtf_uncompressed(b"hello"), max_output=4)


def test_only_pst_errors_escape_under_mutation() -> None:
    """The contract: whatever the bytes, the answer is a result or a PstError.

    Seeded so a failure reproduces; every mutation is applied to a valid
    stream, which is how a fuzzer reaches the token loop past the CRC.
    """
    rng = random.Random(20260915)
    seeds = [SPEC_EXAMPLE_1, SPEC_EXAMPLE_2, compress_rtf(b"WXYZ" * 1200), encode_rtf_uncompressed(b"{\\rtf1 x}")]
    for _ in range(1500):
        data = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 4)):
            kind = rng.randint(0, 3)
            if kind == 0 and data:
                data[rng.randrange(len(data))] = rng.randrange(256)
            elif kind == 1:
                del data[rng.randrange(len(data) + 1) :]
            elif kind == 2:
                data += os.urandom(rng.randint(0, 40))
            else:
                # Re-seal the header so the mutation survives the CRC and COMPSIZE gate.
                payload = bytes(data[HEADER_SIZE:])
                data = bytearray(_stream(payload, raw_size=rng.randrange(0, 1 << 20), comp_type=rng.choice([LZFU, MELA])))
        try:
            decompress_rtf(bytes(data), max_output=1 << 16)
        except PstError:
            pass


# --- The specification's worked examples ------------------------------------


def test_spec_example_1_simple_compressed_rtf() -> None:
    """[MS-OXRTFCP] 3.1.1."""
    assert decompress_rtf(SPEC_EXAMPLE_1) == SPEC_EXAMPLE_1_TEXT


def test_spec_example_2_reference_crossing_write_position() -> None:
    """[MS-OXRTFCP] 3.1.2: one reference reads bytes it is itself writing."""
    assert decompress_rtf(SPEC_EXAMPLE_2) == SPEC_EXAMPLE_2_TEXT


def test_spec_example_1_header_fields() -> None:
    """[MS-OXRTFCP] 3.1.1.2 lists the four fields; assert the parsed values, not the text."""
    header = read_header(SPEC_EXAMPLE_1)
    assert header == CompressedRtfHeader(comp_size=0x2D, raw_size=0x2B, comp_type=LZFU, crc=0xA7C7C5F1)
    assert isinstance(header.comp_type, CompressionType)


def test_spec_example_2_header_fields() -> None:
    """[MS-OXRTFCP] 3.1.2.2."""
    assert read_header(SPEC_EXAMPLE_2) == CompressedRtfHeader(comp_size=0x1A, raw_size=0x1C, comp_type=LZFU, crc=0x514BD4E2)


def test_spec_rawsize_equals_the_text_length() -> None:
    assert read_header(SPEC_EXAMPLE_1).raw_size == len(SPEC_EXAMPLE_1_TEXT)
    assert read_header(SPEC_EXAMPLE_2).raw_size == len(SPEC_EXAMPLE_2_TEXT)


def test_spec_compression_example_1() -> None:
    """[MS-OXRTFCP] 3.2.1: compressing the text yields exactly the bytes of 3.1.1.1."""
    assert compress_rtf(SPEC_EXAMPLE_1_TEXT) == SPEC_EXAMPLE_1


def test_spec_compression_example_2() -> None:
    """[MS-OXRTFCP] 3.2.2."""
    assert compress_rtf(SPEC_EXAMPLE_2_TEXT) == SPEC_EXAMPLE_2


def test_spec_repeating_sequence_from_2_3_3_2_1() -> None:
    """[MS-OXRTFCP] 2.3.3.2.1: "XYZXYZXYZXYZ" becomes three literals and one reference.

    The reference the algorithm produces starts where 'X' was written (207)
    and is 9 long; the section's prose quotes 210, which is the write offset
    at that moment rather than the match offset. The bytes below are what
    the pseudocode — and upstream — actually emit, and they round-trip.
    """
    compressed = compress_rtf(b"XYZXYZXYZXYZ")
    assert compressed[HEADER_SIZE:] == b"\x18XYZ" + _reference(WRITE0, 9) + _reference(WRITE0 + 12, 2)
    assert decompress_rtf(compressed) == b"XYZXYZXYZXYZ"


def test_spec_empty_input_quirk_from_2_3_3_2_step_8() -> None:
    """Outlook compresses an empty body as `02 00 0D 00` (a NUL literal, then the terminator).

    Its output is one NUL byte, which upstream's string conversion trims and
    this bytes API keeps (see the module docstring). The pseudocode's own
    form, `01 0C F0`, is the empty output.
    """
    assert decompress_rtf(_stream(bytes.fromhex("02 00 0d 00"), raw_size=0)) == b"\x00"
    assert decompress_rtf(_stream(bytes.fromhex("01 0c f0"), raw_size=0)) == b""


def test_terminator_length_bits_are_ignored() -> None:
    """[MS-OXRTFCP] 2.1.3.1.5: readers SHOULD ignore Length on the terminator."""
    for low in (0x0, 0x7, 0xF):
        token = ((WRITE0 << 4) | low).to_bytes(2, "big")
        assert decompress_rtf(_stream(b"\x01" + token, raw_size=0)) == b""


def test_uncompressed_passthrough_ignores_the_crc() -> None:
    """[MS-OXRTFCP] 2.2.3.1: MELA copies RAWSIZE bytes and MUST NOT validate the CRC."""
    text = b"{\\rtf1\\ansi hello}"
    assert decompress_rtf(encode_rtf_uncompressed(text)) == text
    garbage_crc = _stream(text, raw_size=len(text), comp_type=MELA, crc=0xDEADBEEF)
    assert decompress_rtf(garbage_crc) == text


def test_uncompressed_reads_rawsize_bytes_not_the_whole_payload() -> None:
    data = _stream(b"hello world", raw_size=5, comp_type=MELA, crc=0)
    assert decompress_rtf(data) == b"hello"


def test_nul_bytes_are_returned_not_trimmed() -> None:
    """Documented divergence: the algorithm's output is returned verbatim."""
    text = b"ab\x00cd\x00\x00"
    assert decompress_rtf(compress_rtf(text)) == text


def test_accepts_bytearray_and_memoryview() -> None:
    assert decompress_rtf(bytearray(SPEC_EXAMPLE_1)) == SPEC_EXAMPLE_1_TEXT
    assert decompress_rtf(memoryview(SPEC_EXAMPLE_1)) == SPEC_EXAMPLE_1_TEXT


# --- Round trip against the ported compressor ----------------------------------

_VOCABULARY = [
    b"{\\rtf1", b"\\ansi", b"\\ansicpg1252", b"\\deff0", b"\\pard", b"\\plain", b"\\par", b"\\b", b"\\b0",
    b"\\i", b"\\fs20", b"\\fs24", b"\\f0", b"{", b"}", b" ", b" ", b" ", b"\r\n", b"hello", b"world",
    b"the", b"quick", b"brown", b"fox", b"meeting", b"Regards,", b"\\'e9", b"\\u8212?", b"\\tab",
]


def _rtfish(rng: random.Random, size: int) -> bytes:
    out = bytearray()
    while len(out) < size:
        out += rng.choice(_VOCABULARY)
    return bytes(out[:size])


@pytest.mark.parametrize("size", [0, 1, 2, 3, 16, 17, 18, 100, 1000, 4095, 4096, 4097, 5000, 9000])
def test_round_trip_rtfish_input(size: int) -> None:
    """Sizes straddle a run (8 tokens), a reference (17 bytes) and the dictionary (4096)."""
    rng = random.Random(size)
    for _ in range(3):
        raw = _rtfish(rng, size)
        assert decompress_rtf(compress_rtf(raw)) == raw


@pytest.mark.parametrize(
    "raw",
    [b"WXYZ" * 3000, b"a" * 5000, b"ab" * 2500, bytes(range(256)) * 20, b"\x00" * 4200],
    ids=["WXYZ*3000", "a*5000", "ab*2500", "all-byte-values", "nuls-past-wrap"],
)
def test_round_trip_long_repeats_and_every_byte_value(raw: bytes) -> None:
    compressed = compress_rtf(raw)
    assert decompress_rtf(compressed) == raw
    assert len(compressed) < len(raw) // 4  # and they really did compress


def test_round_trip_incompressible_input() -> None:
    raw = os.urandom(3000)
    assert decompress_rtf(compress_rtf(raw)) == raw


def test_round_trip_random_bytes_seeded() -> None:
    rng = random.Random(7)
    for _ in range(40):
        raw = rng.randbytes(rng.randint(0, 600))
        assert decompress_rtf(compress_rtf(raw)) == raw


def test_compressor_first_byte_skip_is_exactly_the_exhaustive_scan() -> None:
    """The one idiom added to the compressor changes no output — proven, not argued.

    The 4400-byte case fills the dictionary so the wrapped scan range is
    exercised as well as the linear one.
    """
    rng = random.Random(3)
    for size in (0, 1, 50, 300, 700):
        raw = _rtfish(rng, size)
        assert compress_rtf(raw, exhaustive=True) == compress_rtf(raw)
    raw = _rtfish(rng, 4400)
    assert compress_rtf(raw, exhaustive=True) == compress_rtf(raw)


# --- The CRC is zlib's --------------------------------------------------------------


def _standard_table() -> list[int]:
    """The reflected CRC-32 table from polynomial 0xEDB88320."""
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        table.append(c)
    return table


def _spec_crc(crc: int, data: bytes, table: list[int]) -> int:
    """[MS-OXRTFCP] 2.1.3.2, transcribed from the pseudocode (and upstream's crc.rs loop)."""
    for byte in data:
        table_position = (crc ^ byte) & 0xFF
        intermediate = crc >> 8
        crc = table[table_position] ^ intermediate
    return crc


def test_spec_crc_worked_example() -> None:
    """[MS-OXRTFCP] 3.3.1: the CRC of Example 1's payload, by both the spec walk and zlib."""
    payload = SPEC_EXAMPLE_1[HEADER_SIZE:]
    assert _spec_crc(0, payload, _standard_table()) == SPEC_CRC_EXAMPLE
    assert compute_crc(0, payload) == SPEC_CRC_EXAMPLE


def test_zlib_form_matches_the_spec_walk_over_random_input() -> None:
    table = _standard_table()
    rng = random.Random(20260915)
    for _ in range(300):
        data = os.urandom(rng.randint(0, 200))
        assert compute_crc(0, data) == _spec_crc(0, data, table), data.hex()


def test_upstream_crc_table_is_the_standard_crc32_table() -> None:
    """All 256 entries of crc.rs's CRC_LOOKUP_TABLE, parsed from the pinned source.

    Skips when reference/ is absent; the previous two tests carry the claim
    on a fresh clone.
    """
    source = REFERENCE / "crates" / "compressed-rtf" / "src" / "crc.rs"
    if not source.exists():
        pytest.skip("reference/outlook-pst-rs absent — run scripts/get_rust_source.sh")
    body = re.search(r"CRC_LOOKUP_TABLE: &\[u32\] = &\[(.*?)\];", source.read_text(), re.DOTALL)
    assert body is not None, "crc.rs has been restructured upstream"
    upstream = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]{8}", body.group(1))]
    assert upstream == _standard_table()


# --- The initial dictionary ---------------------------------------------------------


def _extraction_script():
    """Import scripts/extract_rtf_dictionary.py so its spec transcription is reused, not retyped."""
    path = REPO / "scripts" / "extract_rtf_dictionary.py"
    spec = importlib.util.spec_from_file_location("extract_rtf_dictionary", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_initial_dictionary_is_207_bytes() -> None:
    assert len(INITIAL_DICTIONARY) == 207
    assert WRITE0 == 207


def test_initial_dictionary_equals_the_spec_string() -> None:
    """[MS-OXRTFCP] 2.1.2.1, via the transcription the generator checks against."""
    script = _extraction_script()
    assert INITIAL_DICTIONARY == script.spec_bytes()
    assert compute_crc(0, INITIAL_DICTIONARY) != 0  # the pinned value is zlib's, checked next


def test_initial_dictionary_crc_is_pinned() -> None:
    import zlib

    assert zlib.crc32(INITIAL_DICTIONARY) == _extraction_script().PINNED_CRC32


def test_initial_dictionary_has_crlf_at_168() -> None:
    """[MS-OXRTFCP] 3.2.1.4 prints the dictionary and notes 0x0d at 168 and 0x0a at 169."""
    assert INITIAL_DICTIONARY[168:170] == b"\r\n"
    assert INITIAL_DICTIONARY.startswith(b"{\\rtf1\\ansi\\mac")
    assert INITIAL_DICTIONARY.endswith(b"\\tab\\tx")


# --- Waits on the messaging layer -----------------------------------------------------


def test_public_fixture_rtf_bodies_decompress_to_rtf() -> None:
    """A licensed public store's RTF bodies begin with `{\\rtf1` once decompressed (P09 landed this).

    `body_rtf` is `PidTagRtfCompressed` exactly as stored — LZFu, not RTF —
    and `body_rtf_decompressed()` is this module over it, so both halves of
    the contract are asserted here.
    """
    from pypst.messaging import Store

    with Store.open(PUBLIC / "tika-variousBodyTypes.pst") as store:
        messages = [m for folder in store.root_folder.walk() for m in folder.messages() if m.body_rtf is not None]
        compressed = [m.body_rtf for m in messages]
        bodies = [m.body_rtf_decompressed() for m in messages]
    assert bodies, "the fixture is chosen because it has an RTF body"
    assert all(not raw.startswith(b"{\\rtf1") for raw in compressed), "the stored form is compressed"
    assert all(body.startswith(b"{\\rtf1") for body in bodies)
    assert all(len(body) > len(raw) for body, raw in zip(bodies, compressed, strict=True))
