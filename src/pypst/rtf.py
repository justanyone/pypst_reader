"""Compressed RTF — the LZFu decompressor behind PR_RTF_COMPRESSED.

Ported from: crates/compressed-rtf/src/lib.rs, crates/compressed-rtf/src/crc.rs
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-OXRTFCP] 2.1 (format, dictionary, CRC), 2.2 (decompression)

An RTF message body is stored in the PST as a small LZ77 variant. A 16-byte
little-endian header (COMPSIZE, RAWSIZE, COMPTYPE, CRC) is followed by runs:
one control byte, then eight tokens, one per control bit starting at 0x01. A
0 bit means the token is one literal byte; a 1 bit means it is a big-endian
16-bit dictionary reference — a 12-bit offset and a 4-bit length-minus-2 —
into a 4096-byte circular dictionary that starts life holding the 207-byte
string in `_rtf_dictionary.py` and receives every output byte as it is
produced. A reference whose offset equals the write offset is the terminator.
COMPTYPE `MELA` marks an uncompressed body: the payload is the RTF.

**Why crc.rs is not ported as a table.** Upstream's `calculate_crc` is the
spec's pseudocode over the spec's 256-entry table, seeded with 0 and with no
final inversion. That table is the standard reflected CRC-32 table (polynomial
0xEDB88320) — the same table as `crates/pst/src/crc.rs`, which `pypst.crc`
already reduced to `zlib.crc32` with the pre- and post-inversion undone. So
the CRC over the compressed payload is `pypst.crc.compute_crc(0, payload)`.
tests/test_rtf.py proves this three ways: the 256 entries in upstream's
crc.rs are the polynomial's table, the spec's own pseudocode walked byte by
byte agrees with the zlib form over random input, and the worked example in
[MS-OXRTFCP] 3.3.1 comes out as 0xA7C7C5F1.

**Deliberate divergences from upstream**, each a fail-closed reading of the
specification where upstream is lenient or where Rust's bounds checks did the
job for it:

- *End of input before the terminator is refused.* Upstream stops quietly
  when the payload runs out mid-run (`let Ok(byte) = ... else break`).
  [MS-OXRTFCP] 2.2.3.2 says a reader "MUST treat the input as corrupt", and
  this port does — a partial body that looks whole is the failure shape this
  project exists to avoid. A half token (one byte where two are needed) is an
  error in both implementations.
- *A reference into the unwritten part of the dictionary is refused.*
  Upstream's buffer is zero-filled, so such a token silently emits NULs (which
  its string conversion then truncates on). The specification never defines
  the contents past the end offset; here it is `PstFormatError`.
- *The output size is capped, not just the RAWSIZE claim.* RAWSIZE is
  attacker-controlled and is not what bounds the output: the token stream is.
  `max_output` is enforced on RAWSIZE up front (`PstLimitError`) and on the
  bytes actually produced while decompressing, so a stream that lies small
  and expands large is stopped at the ceiling.
- *No NUL trimming.* Upstream returns a `String` cut at the first NUL (its
  1.0.1 changelog: "trim trailing null terminators" — Outlook writes one for
  an empty body). This function returns the bytes the algorithm produced,
  verbatim, and leaves the C-string convention to the messaging layer, so the
  round-trip property holds for every byte value and nothing is discarded
  silently at this level.

Wrap-around on the dictionary offsets is masked (`& 0xFFF`) at every
increment; Python ints do not wrap and 4096 is not a byte boundary.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from pypst._rtf_dictionary import INITIAL_DICTIONARY
from pypst.crc import compute_crc
from pypst.errors import PstFormatError, PstLimitError

HEADER_SIZE = 16
_HEADER = struct.Struct("<IIII")  # COMPSIZE, RAWSIZE, COMPTYPE, CRC — [MS-OXRTFCP] 2.1.3.1.1

DICTIONARY_SIZE = 4096  # [MS-OXRTFCP] 2.1.3.1.4: a 4096-byte circular array
_DICTIONARY_MASK = DICTIONARY_SIZE - 1

# The largest run is a control byte plus eight 17-byte references.
_MAX_REFERENCE_LENGTH = 17


class CompressionType(IntEnum):
    """The COMPTYPE field, as the little-endian u32 it is stored as.

    Ported from the `COMPRESSED` / `UNCOMPRESSED` constants in lib.rs. The
    values spell the ASCII magic when read as bytes on the wire.
    """

    COMPRESSED = 0x75465A4C  # b"LZFu"
    UNCOMPRESSED = 0x414C454D  # b"MELA"


@dataclass(frozen=True, slots=True)
class CompressedRtfHeader:
    """The 16-byte header, already checked against the buffer it came from."""

    comp_size: int  # COMPSIZE: bytes of payload + 12, i.e. everything after this field
    raw_size: int  # RAWSIZE: the writer's claim of the uncompressed size
    comp_type: CompressionType
    crc: int  # over the payload for COMPRESSED; must be ignored for UNCOMPRESSED


def read_header(data: bytes) -> CompressedRtfHeader:
    """Parse and validate the header of a PR_RTF_COMPRESSED value.

    Refuses (`PstFormatError`) a buffer shorter than the header, a COMPSIZE
    that does not describe the buffer exactly (upstream's check: COMPSIZE + 4
    must equal the total length), and a COMPTYPE that is neither magic —
    [MS-OXRTFCP] 2.2.2.1 says that last one MUST be treated as corrupt.
    """
    if len(data) < HEADER_SIZE:
        raise PstFormatError(f"compressed RTF header truncated: {len(data)} bytes, need {HEADER_SIZE}")
    comp_size, raw_size, comp_type_value, crc = _HEADER.unpack_from(data)
    if comp_size + 4 != len(data):
        raise PstFormatError(f"COMPSIZE {comp_size} disagrees with a {len(data)}-byte buffer (expected {len(data) - 4})")
    try:
        comp_type = CompressionType(comp_type_value)
    except ValueError:
        raise PstFormatError(f"invalid COMPTYPE {comp_type_value:#010x}") from None
    return CompressedRtfHeader(comp_size, raw_size, comp_type, crc)


def decompress_rtf(data: bytes, *, max_output: int = 256 * 2**20) -> bytes:
    """Decompress a PR_RTF_COMPRESSED value to the RTF bytes it encodes.

    Raises `PstFormatError` for a bad header, a CRC mismatch, a truncated or
    malformed token stream, and `PstLimitError` when RAWSIZE or the produced
    output would exceed `max_output`. Nothing else escapes.
    """
    header = read_header(data)
    if header.raw_size > max_output:
        raise PstLimitError(f"RAWSIZE {header.raw_size} exceeds {max_output}")
    payload = memoryview(data)[HEADER_SIZE:]

    if header.comp_type is CompressionType.UNCOMPRESSED:
        # 2.2.3.1: the reader MAY take RAWSIZE bytes (upstream does) and MUST
        # NOT validate the CRC. A RAWSIZE past the end of the buffer is a lie.
        if header.raw_size > len(payload):
            raise PstFormatError(f"RAWSIZE {header.raw_size} exceeds the {len(payload)}-byte uncompressed payload")
        return bytes(payload[: header.raw_size])

    actual_crc = compute_crc(0, payload)
    if actual_crc != header.crc:
        raise PstFormatError(f"compressed RTF CRC mismatch: header {header.crc:#010x}, payload {actual_crc:#010x}")
    return _decompress_lzfu(payload, max_output)


def _decompress_lzfu(payload: memoryview, max_output: int) -> bytes:
    """The loop of [MS-OXRTFCP] 2.2.3.2 over an already CRC-checked payload."""
    dictionary = bytearray(DICTIONARY_SIZE)
    dictionary[: len(INITIAL_DICTIONARY)] = INITIAL_DICTIONARY
    write = len(INITIAL_DICTIONARY)  # write offset: where the next byte lands
    end = len(INITIAL_DICTIONARY)  # end offset: bytes ever written, saturating at 4096
    output = bytearray()
    pos = 0
    size = len(payload)

    while True:
        if pos >= size:
            raise PstFormatError(f"compressed RTF ends at byte {pos} before its terminator token")
        control = payload[pos]
        pos += 1
        for bit in range(8):
            if not control & (1 << bit):
                # A literal: copy it out and into the dictionary.
                if pos >= size:
                    raise PstFormatError(f"compressed RTF ends at byte {pos} inside a run, expecting a literal")
                if len(output) >= max_output:
                    raise PstLimitError(f"decompressed RTF exceeds {max_output}")
                byte = payload[pos]
                pos += 1
                output.append(byte)
                dictionary[write] = byte
                write = (write + 1) & _DICTIONARY_MASK
                if end < DICTIONARY_SIZE:
                    end += 1
                continue

            # A dictionary reference: big-endian, offset in the top 12 bits,
            # length minus 2 in the low 4 (2.1.3.1.5).
            if pos + 2 > size:
                raise PstFormatError(f"compressed RTF ends at byte {pos} inside a dictionary reference")
            token = (payload[pos] << 8) | payload[pos + 1]
            pos += 2
            offset = token >> 4
            if offset == write:
                return bytes(output)  # the terminator; its length bits are ignored
            if offset >= end:
                raise PstFormatError(f"dictionary reference at byte {pos - 2} reaches offset {offset}, past the {end} bytes written")
            length = (token & 0x0F) + 2
            if len(output) + length > max_output:
                raise PstLimitError(f"decompressed RTF exceeds {max_output}")
            # Byte by byte, on purpose: a reference may run past the write
            # offset and read bytes this same reference just wrote (the
            # spec's "crossing WritePosition" case, example 3.1.2).
            read = offset
            for _ in range(length):
                byte = dictionary[read]
                read = (read + 1) & _DICTIONARY_MASK
                output.append(byte)
                dictionary[write] = byte
                write = (write + 1) & _DICTIONARY_MASK
                if end < DICTIONARY_SIZE:
                    end += 1
