"""The PST HEADER — the 564 bytes at offset 0 that everything else hangs from.

Ported from: crates/pst/src/ndb/header.rs (the `UnicodeHeader` read arm)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.2.2.6 HEADER, 5.3 CRC Calculation

The header names the file's format version, how its data blocks are
encoded, the two allocation counters, and — through the embedded ROOT
(`pypstreader.ndb.root`) — the pages the node and block B-trees start from. It is
the first thing read and the smallest thing the oracle can contradict,
which is why it is the first NDB module ported.

**Unicode arm only (ADR-0003).** The ANSI header is 512 bytes with a
different field order; it is recognised by `wVer` and refused with
`PstUnsupportedError` before anything past `wVer` is interpreted.

**What is validated — exactly what upstream validates.** `dwMagic`,
`wMagicClient`, `wVer`, `dwCRCPartial` (the 471 bytes from offset 8),
`dwCRCFull` (the 516 bytes from offset 8), `wVerClient` (must be 19),
`bPlatformCreate` and `bPlatformAccess` (must be 1), `dwAlign` (must be 0),
`bSentinel` (must be 0x80), `bCryptMethod`, and `rgbReserved` (must be 0).

**What is read but not validated — also as upstream.** `dwReserved1`,
`dwReserved2`, `bidUnused`, `qwUnused`, `rgbFM`, `rgbFP`, `rgbReserved2`,
`bReserved` and `rgbReserved3` are covered by the CRCs but their values are
not checked. The specification says `qwUnused` MUST be zero and the two maps
MUST be 0xFF-filled; real stores in the corpus violate both, upstream does
not check them, and a check upstream lacks would refuse files upstream
reads. `rgnid` (the 32 per-type NID allocation counters) is likewise read
and not kept: nothing on the read path consults it. None of these is a
field of `Header`.

**Divergence: the version check comes before the CRC checks.** Upstream
verifies `dwCRCPartial` before it looks at `wVer`. Here `wVer` is examined
first, so that an ANSI store is reported as an ANSI store rather than as
whatever else may be wrong with it. This is safe because `wMagicClient` and
`wVer` sit at the same offsets in both layouts ([MS-PST] 2.2.2.6, both
tables), and it changes nothing for a Unicode store: every check upstream
makes is still made, in an order that differs only in which of two
refusals a doubly-bad file receives. The one consequence worth knowing: a
Unicode store whose `wVer` bytes themselves are corrupted is refused as
"ANSI" or "unknown version" rather than as "bad CRC".

**Divergence: `wVer` 36 and 37 raise `PstUnsupportedError`, not
`PstFormatError`.** Upstream's `NdbVersion::try_from` accepts only 14, 15
and 23 and reports the rest as `InvalidNdbVersion`. The specification
names 36/37 as Unicode stores from newer Outlook (37: written with Windows
Information Protection), and other readers document them as the 4 KB-page
layout. They are a recognised format this port does not handle, which is
what `PstUnsupportedError` means (`pypstreader.errors`); parsing them with the
512-byte-page assumptions of the rest of this package would be the
plausible-garbage outcome the threat model forbids. The docs/INTERFACES.md
draft had them parsed as Unicode; that was wrong for the same reason.

**`bCryptMethod` 0x10 (`NDB_CRYPT_EDPCRYPTED`, Windows Information
Protection) is `PstUnsupportedError`.** Upstream has no variant for it and
refuses it as unknown; the specification names it, so it is refused by name.
Any other unknown value is `PstFormatError`. `CryptMethod` itself lives in
`pypstreader.encode`, where the decoders are; it is re-exported here.

Nothing but `PstError` subclasses escapes `Header.parse` or `read_header`
for any input bytes. An `OSError` from the file object in `read_header` is
the environment's, not the file's, and is not caught.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import BinaryIO, ClassVar

from pypstreader.crc import compute_crc
from pypstreader.encode import CryptMethod
from pypstreader.errors import PstFormatError, PstUnsupportedError
from pypstreader.ndb.ids import BlockId, PageId
from pypstreader.ndb.root import Root

__all__ = [
    "CRYPT_METHOD_EDPCRYPTED",
    "HEADER_MAGIC",
    "HEADER_MAGIC_CLIENT",
    "CryptMethod",
    "Header",
    "Version",
    "read_header",
]

# `dwMagic` is the bytes "!BDN"; read little-endian they are this u32, which
# is how upstream (and its test_magic_values) spells it. `wMagicClient` is
# "SM" the same way.
HEADER_MAGIC = 0x4E444221
HEADER_MAGIC_CLIENT = 0x4D53

# The values upstream requires of the fixed fields ([MS-PST] 2.2.2.6).
CLIENT_VERSION = 19
PLATFORM_CREATE = 0x01
PLATFORM_ACCESS = 0x01
SENTINEL = 0x80
CRYPT_METHOD_EDPCRYPTED = 0x10  # the spec's NDB_CRYPT_EDPCRYPTED; refused by name

# [MS-PST] 2.2.2.6, Unicode layout, as three struct formats around the two
# regions this module does not unpack field by field (rgnid and the ROOT).
#
#   dwMagic, dwCRCPartial, wMagicClient, wVer, wVerClient, bPlatformCreate,
#   bPlatformAccess, dwReserved1, dwReserved2, bidUnused, bidNextP, dwUnique
_LEAD_FORMAT = "<IIHHHBBIIQQI"
_NID_COUNT = 32  # rgnid: one u32 per 5-bit NID type
_NIDS_FORMAT = f"<{_NID_COUNT}I"
#   qwUnused
_UNUSED_FORMAT = "<Q"
#   dwAlign, rgbFM, rgbFP, bSentinel, bCryptMethod, rgbReserved, bidNextB,
#   dwCRCFull, rgbReserved2 + bReserved + rgbReserved3
_TAIL_FORMAT = "<I128s128sBBHQI36s"

_LEAD_SIZE = struct.calcsize(_LEAD_FORMAT)
_NIDS_OFFSET = _LEAD_SIZE
_UNUSED_OFFSET = _NIDS_OFFSET + struct.calcsize(_NIDS_FORMAT)
_ROOT_OFFSET = _UNUSED_OFFSET + struct.calcsize(_UNUSED_FORMAT)
_TAIL_OFFSET = _ROOT_OFFSET + Root.SIZE
HEADER_SIZE = _TAIL_OFFSET + struct.calcsize(_TAIL_FORMAT)

# Both CRCs start at wMagicClient (offset 8). The partial one covers 471
# bytes, the full one 516 — the whole header up to and including bidNextB.
# [MS-PST] 2.2.2.6 dwCRCPartial / dwCRCFull; header.rs reads the same counts.
_CRC_START = 8
_CRC_PARTIAL_LEN = 471
_CRC_FULL_LEN = 516
_CRC_PARTIAL_END = _CRC_START + _CRC_PARTIAL_LEN
_CRC_FULL_END = _CRC_START + _CRC_FULL_LEN

# Only the fields needed to recognise the layout sit before wVer, and they
# sit at the same offsets in both layouts. Everything past here is
# Unicode-only.
_MAGIC_CLIENT_OFFSET = 8
_VERSION_OFFSET = 10
_VERSION_FORMAT = "<H"


class Version(IntEnum):
    """`wVer` — [MS-PST] 2.2.2.6. Only `UNICODE` is ever held by a `Header`."""

    ANSI_14 = 14
    ANSI_15 = 15
    UNICODE = 23
    UNICODE_4K_36 = 36
    UNICODE_4K_37 = 37

    @property
    def is_ansi(self) -> bool:
        return self in (Version.ANSI_14, Version.ANSI_15)

    @property
    def debug_name(self) -> str:
        """Upstream's `NdbVersion` variant name: `Ansi` or `Unicode`."""
        return "Ansi" if self.is_ansi else "Unicode"

    def __str__(self) -> str:
        return self.debug_name


def _check_version(raw: int) -> Version:
    """Turn `wVer` into the one member this port reads, or refuse by kind."""
    try:
        version = Version(raw)
    except ValueError:
        raise PstFormatError(f"unknown PST version wVer={raw}") from None
    if version.is_ansi:
        raise PstUnsupportedError(
            f"ANSI (pre-2003) store, wVer={raw}; pypstreader reads Unicode stores only — see pypstreader_nu"
        )
    if version is not Version.UNICODE:
        raise PstUnsupportedError(
            f"wVer={raw} (4 KB-page Unicode store) is not supported; pypstreader reads wVer 23 stores only"
        )
    return version


def _check_crypt_method(raw: int) -> CryptMethod:
    if raw == CRYPT_METHOD_EDPCRYPTED:
        raise PstUnsupportedError(
            f"bCryptMethod=0x{raw:02X} (NDB_CRYPT_EDPCRYPTED, Windows Information Protection) is not supported"
        )
    try:
        return CryptMethod(raw)
    except ValueError:
        raise PstFormatError(f"unknown bCryptMethod 0x{raw:02X}") from None


@dataclass(frozen=True, slots=True)
class Header:
    """HEADER — [MS-PST] 2.2.2.6, Unicode layout, 564 bytes."""

    version: Version
    client_version: int
    crypt_method: CryptMethod
    next_block: BlockId
    next_page: PageId
    unique_value: int
    root: Root

    SIZE: ClassVar[int] = HEADER_SIZE

    @classmethod
    def parse(cls, buf: bytes | bytearray | memoryview) -> Header:
        """Parse a header from its first `SIZE` bytes.

        Raises `PstUnsupportedError` for an ANSI store, a 4 KB-page store,
        or WIP-encrypted blocks; `PstFormatError` for everything else that
        is wrong, a short buffer included.
        """
        if len(buf) < HEADER_SIZE:
            raise PstFormatError(f"header is {len(buf)} bytes; a Unicode PST header is {HEADER_SIZE}")

        # The layout is decided by three fields at fixed offsets shared by
        # both layouts; nothing else is interpreted until they pass.
        (magic,) = struct.unpack_from("<I", buf, 0)
        if magic != HEADER_MAGIC:
            raise PstFormatError(f"bad dwMagic 0x{magic:08X}; not a PST file")
        (magic_client,) = struct.unpack_from("<H", buf, _MAGIC_CLIENT_OFFSET)
        if magic_client != HEADER_MAGIC_CLIENT:
            raise PstFormatError(f"bad wMagicClient 0x{magic_client:04X}")
        (raw_version,) = struct.unpack_from(_VERSION_FORMAT, buf, _VERSION_OFFSET)
        version = _check_version(raw_version)

        (
            _magic,
            crc_partial,
            _magic_client,
            _version,
            client_version,
            platform_create,
            platform_access,
            _reserved1,
            _reserved2,
            _unused_bid,
            next_page,
            unique,
        ) = struct.unpack_from(_LEAD_FORMAT, buf, 0)
        (
            align,
            _free_map,
            _free_page_map,
            sentinel,
            raw_crypt_method,
            reserved,
            next_block,
            crc_full,
            _reserved3,
        ) = struct.unpack_from(_TAIL_FORMAT, buf, _TAIL_OFFSET)

        if crc_partial != compute_crc(0, bytes(buf[_CRC_START:_CRC_PARTIAL_END])):
            raise PstFormatError(f"header partial CRC mismatch (dwCRCPartial=0x{crc_partial:08X})")
        if crc_full != compute_crc(0, bytes(buf[_CRC_START:_CRC_FULL_END])):
            raise PstFormatError(f"header full CRC mismatch (dwCRCFull=0x{crc_full:08X})")

        if client_version != CLIENT_VERSION:
            raise PstFormatError(f"wVerClient={client_version}; expected {CLIENT_VERSION}")
        if platform_create != PLATFORM_CREATE:
            raise PstFormatError(f"bPlatformCreate=0x{platform_create:02X}; expected 0x{PLATFORM_CREATE:02X}")
        if platform_access != PLATFORM_ACCESS:
            raise PstFormatError(f"bPlatformAccess=0x{platform_access:02X}; expected 0x{PLATFORM_ACCESS:02X}")
        if align != 0:
            raise PstFormatError(f"dwAlign=0x{align:08X}; expected 0")
        if sentinel != SENTINEL:
            raise PstFormatError(f"bSentinel=0x{sentinel:02X}; expected 0x{SENTINEL:02X}")
        crypt_method = _check_crypt_method(raw_crypt_method)
        if reserved != 0:
            raise PstFormatError(f"rgbReserved=0x{reserved:04X}; expected 0")

        return cls(
            version=version,
            client_version=client_version,
            crypt_method=crypt_method,
            next_block=BlockId(next_block),
            next_page=PageId(next_page),
            unique_value=unique,
            root=Root.unpack_from(buf, _ROOT_OFFSET),
        )


def read_header(f: BinaryIO) -> Header:
    """Read and parse the header from the start of an open binary file.

    Seeks to offset 0 first. A file shorter than `Header.SIZE` is a
    `PstFormatError`; the parse errors are `Header.parse`'s.
    """
    f.seek(0)
    data = f.read(HEADER_SIZE)
    return Header.parse(data)
