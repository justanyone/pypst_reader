"""Twins of the four `#[test]`s in crates/compressed-rtf/src/lib.rs.

Each test below derives from upstream's test of the same name: the same
constant bytes, the same text, the same assertion. Upstream's decompressor
returns a `String`, so its twin compares against the ASCII encoding of the
text; its compressor takes a `&str`, so its twin passes the same bytes.
Upstream's doc comments cite these as [MS-OXRTFCP] 3.1.1, 3.2.1, 3.1.2 and
3.2.2; tests/test_rtf.py types the same vectors from the specification's
pages independently.
"""

from __future__ import annotations

from pypst.rtf import decompress_rtf
from tests.parity import upstream_test
from tests.rtf_compress import compress_rtf

# `COMPRESSED_SIMPLE_RTF` / `UNCOMPRESSED_SIMPLE_RTF` in upstream's test module.
COMPRESSED_SIMPLE_RTF = bytes(
    [
        0x2D, 0x00, 0x00, 0x00, 0x2B, 0x00, 0x00, 0x00, 0x4C, 0x5A, 0x46, 0x75, 0xF1, 0xC5, 0xC7,
        0xA7, 0x03, 0x00, 0x0A, 0x00, 0x72, 0x63, 0x70, 0x67, 0x31, 0x32, 0x35, 0x42, 0x32, 0x0A,
        0xF3, 0x20, 0x68, 0x65, 0x6C, 0x09, 0x00, 0x20, 0x62, 0x77, 0x05, 0xB0, 0x6C, 0x64, 0x7D,
        0x0A, 0x80, 0x0F, 0xA0,
    ]
)
UNCOMPRESSED_SIMPLE_RTF = b"{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n"

# `COMPRESSED_CROSSING_WRITE_RTF` / `UNCOMPRESSED_CROSSING_WRITE_RTF` upstream.
COMPRESSED_CROSSING_WRITE_RTF = bytes(
    [
        0x1A, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x4C, 0x5A, 0x46, 0x75, 0xE2, 0xD4, 0x4B,
        0x51, 0x41, 0x00, 0x04, 0x20, 0x57, 0x58, 0x59, 0x5A, 0x0D, 0x6E, 0x7D, 0x01, 0x0E, 0xB0,
    ]
)
UNCOMPRESSED_CROSSING_WRITE_RTF = b"{\\rtf1 WXYZWXYZWXYZWXYZWXYZ}"


@upstream_test("crates/compressed-rtf/src/lib.rs::test_decompress_simple_rtf")
def test_decompress_simple_rtf() -> None:
    # Derived from upstream's test_decompress_simple_rtf ([MS-OXRTFCP] 3.1.1).
    assert decompress_rtf(COMPRESSED_SIMPLE_RTF) == UNCOMPRESSED_SIMPLE_RTF


@upstream_test("crates/compressed-rtf/src/lib.rs::test_compress_simple_rtf")
def test_compress_simple_rtf() -> None:
    # Derived from upstream's test_compress_simple_rtf ([MS-OXRTFCP] 3.2.1).
    assert compress_rtf(UNCOMPRESSED_SIMPLE_RTF) == COMPRESSED_SIMPLE_RTF


@upstream_test("crates/compressed-rtf/src/lib.rs::test_decompress_crossing_write_rtf")
def test_decompress_crossing_write_rtf() -> None:
    # Derived from upstream's test_decompress_crossing_write_rtf ([MS-OXRTFCP] 3.1.2).
    assert decompress_rtf(COMPRESSED_CROSSING_WRITE_RTF) == UNCOMPRESSED_CROSSING_WRITE_RTF


@upstream_test("crates/compressed-rtf/src/lib.rs::test_compress_crossing_write_rtf")
def test_compress_crossing_write_rtf() -> None:
    # Derived from upstream's test_compress_crossing_write_rtf ([MS-OXRTFCP] 3.2.2).
    assert compress_rtf(UNCOMPRESSED_CROSSING_WRITE_RTF) == COMPRESSED_CROSSING_WRITE_RTF
