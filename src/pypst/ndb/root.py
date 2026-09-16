"""The ROOT structure — the file's current state, embedded in the header.

Ported from: crates/pst/src/ndb/root.rs (the Unicode arm) and the
             `RootReadWrite::read` default in crates/pst/src/ndb/read_write.rs
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 2.2.2.5 ROOT

ROOT is 72 bytes at offset 180 of the Unicode header. It carries the file
size, the position of the last allocation-map page, the two free-space
totals, the BREFs of the node and block B-tree root pages — the two values
everything above this layer starts from — and the AMap validity flag.

**Unicode arm only (ADR-0003).** Upstream's `AnsiRoot` (40 bytes, 32-bit
indices) is not ported.

**What is read but not validated, as upstream.** `dwReserved`, `bReserved`
and `wReserved` are read and discarded: the specification says readers
SHOULD ignore them, upstream keeps them only so that it can write them back
unchanged, and this port never writes. They are not fields of `Root`.

**Unknown `fAMapValid` values become `INVALID`, as upstream.** Upstream's
read maps any byte outside 0x00–0x02 to `AmapStatus::Invalid`
(read_write.rs, `AmapStatus::try_from(..).unwrap_or(AmapStatus::Invalid)`)
rather than failing. That is followed here deliberately: the flag only says
whether the allocation maps may be trusted, which a reader never consults,
and "invalid" is the conservative reading of a value that means nothing.
It is the one place in this layer where an unknown byte is not a refusal,
and `tests/test_header.py` pins the behaviour so that it cannot drift
either way unnoticed. `AmapStatus.from_byte` is the strict form.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar

from pypst.errors import PstFormatError
from pypst.ndb.ids import ByteIndex, PageId, PageRef, _unpack

# [MS-PST] 2.2.2.5, Unicode layout: dwReserved, ibFileEof, ibAMapLast,
# cbAMapFree, cbPMapFree, BREFNBT (bid, ib), BREFBBT (bid, ib), fAMapValid,
# bReserved, wReserved. Little-endian throughout.
ROOT_FORMAT = "<IQQQQQQQQBBH"


class AmapStatus(IntEnum):
    """`fAMapValid` — [MS-PST] 2.2.2.5. Whether the allocation maps are trustworthy."""

    INVALID = 0x00
    VALID1 = 0x01  # deprecated by the spec; still "valid"
    VALID2 = 0x02

    @property
    def debug_name(self) -> str:
        """The variant name upstream's `Debug` prints, which the goldens contain."""
        return _DEBUG_NAMES[self]

    @classmethod
    def from_byte(cls, value: int) -> AmapStatus:
        """The strict conversion: a value outside the table is refused."""
        try:
            return cls(value)
        except ValueError:
            raise PstFormatError(f"unknown fAMapValid value 0x{value:02X}") from None

    @classmethod
    def from_byte_lenient(cls, value: int) -> AmapStatus:
        """Upstream's read: anything unknown is `INVALID`. See the module docstring."""
        try:
            return cls(value)
        except ValueError:
            return cls.INVALID

    def __str__(self) -> str:
        return self.debug_name


_DEBUG_NAMES: dict[AmapStatus, str] = {
    AmapStatus.INVALID: "Invalid",
    AmapStatus.VALID1: "Valid1",
    AmapStatus.VALID2: "Valid2",
}


@dataclass(frozen=True, slots=True)
class Root:
    """ROOT — [MS-PST] 2.2.2.5, Unicode layout, 72 bytes."""

    file_eof_index: ByteIndex
    amap_last_index: ByteIndex
    amap_free_size: ByteIndex
    pmap_free_size: ByteIndex
    node_btree: PageRef
    block_btree: PageRef
    amap_is_valid: AmapStatus

    SIZE: ClassVar[int] = struct.calcsize(ROOT_FORMAT)

    @classmethod
    def unpack_from(cls, buf: bytes | bytearray | memoryview, offset: int = 0) -> Root:
        """Read a ROOT from `buf` at `offset`. Short buffer or bad offset → PstFormatError."""
        (
            _reserved,
            file_eof,
            amap_last,
            amap_free,
            pmap_free,
            nbt_page,
            nbt_index,
            bbt_page,
            bbt_index,
            amap_valid,
            _reserved2,
            _reserved3,
        ) = _unpack(ROOT_FORMAT, buf, offset, "Root")
        return cls(
            file_eof_index=ByteIndex(file_eof),
            amap_last_index=ByteIndex(amap_last),
            amap_free_size=ByteIndex(amap_free),
            pmap_free_size=ByteIndex(pmap_free),
            node_btree=PageRef(PageId(nbt_page), ByteIndex(nbt_index)),
            block_btree=PageRef(PageId(bbt_page), ByteIndex(bbt_index)),
            amap_is_valid=AmapStatus.from_byte_lenient(amap_valid),
        )
