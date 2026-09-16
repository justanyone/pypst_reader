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


# --- pages (P02) -------------------------------------------------------------
#
# [MS-PST] 2.2.2.7 and 2.2.2.7.7. As above, these duplicate the constants in
# pypst.ndb.page on purpose.

PAGE_SIZE = 512
PAGE_DATA_SIZE = 496
PAGE_TRAILER_OFFSET = 496
BTREE_HEADER_OFFSET = 488  # cEnt, cEntMax, cbEnt, cLevel, dwPadding
PTYPE_BBT = 0x80
PTYPE_NBT = 0x81
PTYPE_DL = 0x86
DENSITY_LIST_OFFSET = 0x4200

# The Unicode entry sizes: BTENTRY, BBTENTRY, NBTENTRY.
BTENTRY_SIZE = 24
BBTENTRY_SIZE = 24
NBTENTRY_SIZE = 32


def page_sig(index: int, page_id: int) -> int:
    """[MS-PST] 5.5, on the low 32 bits of each input, as upstream's `PageType::signature`."""
    value = (index & 0xFFFFFFFF) ^ (page_id & 0xFFFFFFFF)
    return ((value >> 16) ^ value) & 0xFFFF


def reseal_page(data: bytes, page_offset: int, *, signature: bool = False) -> bytes:
    """Recompute the trailer CRC of the page at `page_offset` over its 496 data bytes.

    With `signature=True` the trailer's `wSig` is also recomputed from the
    offset and the trailer's own `bid`, so a test can build a page whose
    signature is right for where it sits. The default leaves it alone: the
    reader does not check it (as upstream), and a test that wants to prove
    that must be able to keep a wrong one.
    """
    end = page_offset + PAGE_SIZE
    if not 0 <= page_offset <= end <= len(data):
        raise ValueError(f"page [{page_offset}, {end}) outside {len(data)} bytes")
    trailer = page_offset + PAGE_TRAILER_OFFSET
    if signature:
        page_id = int.from_bytes(data[trailer + 8 : trailer + 16], "little")
        data = set_u16(data, trailer + 2, page_sig(page_offset, page_id))
    crc = compute_crc(0, data[page_offset : page_offset + PAGE_DATA_SIZE])
    return set_u32(data, trailer + 4, crc)


def page_trailer(page_type: int, page_id: int, index: int, crc: int, *, signature: int | None = None) -> bytes:
    """A 16-byte Unicode PAGETRAILER: ptype, ptypeRepeat, wSig, dwCRC, bid."""
    sig = page_sig(index, page_id) if signature is None else signature
    return struct.pack("<BBHIQ", page_type, page_type, sig, crc, page_id)


def btree_page(
    page_type: int,
    level: int,
    entries: list[bytes],
    page_id: int,
    index: int,
    *,
    entry_size: int | None = None,
    max_entries: int | None = None,
    padding: int = 0,
    count: int | None = None,
    ptype_repeat: int | None = None,
) -> bytes:
    """A whole 512-byte BTPAGE with a correct CRC and signature, built from packed entries.

    Every field a test may want wrong is a keyword: `entry_size` (cbEnt),
    `max_entries` (cEntMax), `padding` (dwPadding), `count` (cEnt, default
    the number of entries), `ptype_repeat`. All entries must be the same
    length, which is the default `cbEnt`.
    """
    sizes = {len(e) for e in entries}
    if len(sizes) > 1:
        raise ValueError(f"entries of mixed sizes: {sorted(sizes)}")
    size = entry_size if entry_size is not None else (sizes.pop() if sizes else BTENTRY_SIZE)
    if max_entries is None:
        max_entries = BTREE_HEADER_OFFSET // size if size else 0
    body = b"".join(entries)
    if len(body) > BTREE_HEADER_OFFSET:
        raise ValueError(f"{len(body)} bytes of entries do not fit in {BTREE_HEADER_OFFSET}")
    data = bytearray(PAGE_DATA_SIZE)
    data[: len(body)] = body
    n = len(entries) if count is None else count
    data[BTREE_HEADER_OFFSET:PAGE_DATA_SIZE] = struct.pack("<BBBBI", n, max_entries, size, level, padding)
    crc = compute_crc(0, bytes(data))
    trailer = bytearray(page_trailer(page_type, page_id, index, crc))
    if ptype_repeat is not None:
        trailer[1] = ptype_repeat
    return bytes(data) + bytes(trailer)


def bt_entry(key: int, page_id: int, index: int) -> bytes:
    """A Unicode BTENTRY: btkey, BREF."""
    return struct.pack("<QQQ", key, page_id, index)


def bbt_entry(block_id: int, index: int, size: int, ref_count: int = 1, padding: int = 0) -> bytes:
    """A Unicode BBTENTRY: BREF, cb, cRef, dwPadding."""
    return struct.pack("<QQHHI", block_id, index, size, ref_count, padding)


def nbt_entry(nid: int, data: int, sub_node: int = 0, parent: int = 0, padding: int = 0) -> bytes:
    """A Unicode NBTENTRY: nid (u64), bidData, bidSub, nidParent, dwPadding."""
    return struct.pack("<QQQII", nid, data, sub_node, parent, padding)


def density_list_page(
    entries: list[int],
    page_id: int,
    *,
    backfill_complete: bool = False,
    current_page: int = 0,
    count: int | None = None,
    padding: int = 0,
    tail: bytes = bytes(12),
) -> bytes:
    """A whole 512-byte DLISTPAGE for the fixed offset 0x4200, CRC and signature correct."""
    if len(entries) > 119:
        raise ValueError(f"{len(entries)} entries; a DLISTPAGE holds 119")
    n = len(entries) if count is None else count
    data = bytearray(PAGE_DATA_SIZE)
    data[0:8] = struct.pack("<BBHI", 0x01 if backfill_complete else 0, n, padding, current_page)
    data[8 : 8 + 4 * len(entries)] = struct.pack(f"<{len(entries)}I", *entries)
    if len(tail) != 12:
        raise ValueError("rgPadding is 12 bytes")
    data[484:496] = tail
    crc = compute_crc(0, bytes(data))
    return bytes(data) + page_trailer(PTYPE_DL, page_id, DENSITY_LIST_OFFSET, crc)


def file_with_pages(pages: dict[int, bytes], size: int | None = None) -> bytes:
    """An in-memory file holding each page at its offset, zero elsewhere.

    The B-tree walk takes its root as a `PageRef`, so a synthetic tree needs
    no header: only the pages, at the offsets the refs name.
    """
    end = max((offset + len(page) for offset, page in pages.items()), default=0)
    if size is None:
        size = end
    if size < end:
        raise ValueError(f"size {size} cannot hold a page ending at {end}")
    out = bytearray(size)
    for offset, page in pages.items():
        out[offset : offset + len(page)] = page
    return bytes(out)
