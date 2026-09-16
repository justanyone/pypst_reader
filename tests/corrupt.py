"""Byte-level mutations of a corpus store, for the denial tests.

Every corrupt input in this suite is made here, in memory, from a licensed
corpus store: no corrupt binary is ever committed, and a new denial case is
a new mutation rather than a new file. Seeded by P01 for the header; **P12
(the corruption generator) extends this module** with the structure-aware
mutations — a B-tree page that points at itself, a length larger than the
file, an allocation claim of gigabytes — and keeps these primitives.

Two kinds of helper:

- **Blind mutations** (`flip_byte`, `set_bytes`, `truncate`) change bytes and
  nothing else. Used when the CRC is what should catch the change.
- **Resealing** (`reseal_header`) recomputes the header's two CRCs over the
  mutated bytes so that a test can reach the check *behind* the CRC: a
  `wVer` from the future is only seen as such once the CRC passes.

All helpers return a new `bytes`; the input is never modified.
"""

from __future__ import annotations

import struct

from pypst.crc import compute_crc

# [MS-PST] 2.2.2.6, Unicode layout. These duplicate the private constants
# in pypst.ndb.header on purpose: a test that imported the module's idea of
# where the CRC lives could not catch the module being wrong about it.
HEADER_SIZE = 564
CRC_PARTIAL_OFFSET = 4
CRC_FULL_OFFSET = 524
CRC_START = 8
CRC_PARTIAL_END = CRC_START + 471
CRC_FULL_END = CRC_START + 516

MAGIC_OFFSET = 0
MAGIC_CLIENT_OFFSET = 8
VERSION_OFFSET = 10
CLIENT_VERSION_OFFSET = 12
PLATFORM_CREATE_OFFSET = 14
PLATFORM_ACCESS_OFFSET = 15
RGNID_OFFSET = 44
ROOT_OFFSET = 180
AMAP_VALID_OFFSET = ROOT_OFFSET + 68
ALIGN_OFFSET = 252
FREE_PAGE_MAP_OFFSET = 384
SENTINEL_OFFSET = 512
CRYPT_METHOD_OFFSET = 513
RESERVED_OFFSET = 514


def flip_byte(data: bytes, offset: int, mask: int = 0xFF) -> bytes:
    """XOR one byte. With the default mask every bit changes, so it is never a no-op."""
    if not 0 <= offset < len(data):
        raise ValueError(f"offset {offset} outside {len(data)} bytes")
    out = bytearray(data)
    out[offset] ^= mask
    return bytes(out)


def set_bytes(data: bytes, offset: int, replacement: bytes) -> bytes:
    """Overwrite `len(replacement)` bytes at `offset`."""
    end = offset + len(replacement)
    if not 0 <= offset <= end <= len(data):
        raise ValueError(f"[{offset}, {end}) outside {len(data)} bytes")
    out = bytearray(data)
    out[offset:end] = replacement
    return bytes(out)


def set_u8(data: bytes, offset: int, value: int) -> bytes:
    return set_bytes(data, offset, struct.pack("<B", value))


def set_u16(data: bytes, offset: int, value: int) -> bytes:
    return set_bytes(data, offset, struct.pack("<H", value))


def set_u32(data: bytes, offset: int, value: int) -> bytes:
    return set_bytes(data, offset, struct.pack("<I", value))


def truncate(data: bytes, length: int) -> bytes:
    """The first `length` bytes — a file cut short."""
    if not 0 <= length <= len(data):
        raise ValueError(f"length {length} outside {len(data)} bytes")
    return data[:length]


def reseal_header(data: bytes) -> bytes:
    """Recompute `dwCRCPartial` and `dwCRCFull` over the (mutated) Unicode header.

    Only the Unicode layout is sealed: the ANSI header has no full CRC and
    this project never reads one past its version field.
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(f"need at least {HEADER_SIZE} bytes, got {len(data)}")
    partial = compute_crc(0, data[CRC_START:CRC_PARTIAL_END])
    data = set_u32(data, CRC_PARTIAL_OFFSET, partial)
    full = compute_crc(0, data[CRC_START:CRC_FULL_END])
    return set_u32(data, CRC_FULL_OFFSET, full)
