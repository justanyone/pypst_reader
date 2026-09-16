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
- **Resealing** (`reseal_header`, `reseal_page`) recomputes the CRCs over
  the mutated bytes so that a test can reach the check *behind* the CRC: a
  `wVer` from the future is only seen as such once the CRC passes.

On top of those, page and entry builders (`btree_page`, `bt_entry`, …,
`file_with_pages`, `append_pages`, `btree_chain`) for synthetic trees, and
the **mutation generator** (P12): `mutations(store_bytes, seed=…)` yields a
`Mutation` (name, bytes, the `PstError` kind expected, whether a refusal is
required) from each family in `FAMILIES`. `tests/test_corruption.py` sweeps
it through every landed entry point; the contract harness (P24) consumes
the same stream. A new denial case is a new mutation in an existing family,
or a new family appended to `FAMILIES` (the `test-harness` skill says how).

All helpers return a new `bytes`; the input is never modified.
"""

from __future__ import annotations

import io
import itertools
import random
import struct
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from pypst.crc import compute_crc
from pypst.errors import (
    PstError,
    PstFormatError,
    PstLimitError,
    PstNotFoundError,
    PstUnsupportedError,
)
from pypst.limits import DEFAULT_LIMITS

# The struct formats the landed modules parse with. `field_lies` derives every
# field's offset and width from these, so a field added to a format is a field
# mutated here without anyone typing an offset. The root/page/entry formats
# are public; the header's lead/tail and the BTPAGE header are the modules'
# own (underscored) names, imported deliberately for the same reason. (The
# offsets below stay hand-typed for the reason the docstring gives: the
# generator tests cross-check the two against each other.)
from pypst.ndb.header import _LEAD_FORMAT, _TAIL_FORMAT, _TAIL_OFFSET
from pypst.ndb.page import (
    _BTREE_HEADER_FORMAT,
    BLOCK_ENTRY_FORMAT,
    INTERMEDIATE_ENTRY_FORMAT,
    NODE_ENTRY_FORMAT,
    PAGE_TRAILER_FORMAT,
)
from pypst.ndb.root import ROOT_FORMAT

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


# --- blocks (P03) ------------------------------------------------------------
#
# [MS-PST] 2.2.2.8. As above, these duplicate the constants in pypst.ndb.block
# on purpose. Every builder returns the WHOLE 64-byte-aligned allocation —
# data, padding, 16-byte trailer — ready to drop into `file_with_blocks` at
# the offset a BBT entry names. P12 (the corruption generator) imports them;
# keep the signatures simple.

BLOCK_TRAILER_SIZE = 16
MAX_BLOCK_DATA_SIZE = 8192 - BLOCK_TRAILER_SIZE
BTYPE_DATA_TREE = 0x01
BTYPE_SUBNODE = 0x02
BID_INTERNAL = 0x2  # bit 1 of a BID: XBLOCK/XXBLOCK/SLBLOCK/SIBLOCK


def block_alloc_size(cb: int) -> int:
    """[MS-PST] 2.2.2.8: the smallest multiple of 64 holding `cb` data bytes plus the trailer."""
    total = cb + BLOCK_TRAILER_SIZE
    return -(-total // 64) * 64


def block_sig(index: int, block_id: int) -> int:
    """[MS-PST] 5.5 for a block: the same fold as `page_sig`."""
    return page_sig(index, block_id)


def block_trailer(cb: int, block_id: int, index: int, crc: int, *, signature: int | None = None) -> bytes:
    """A 16-byte Unicode BLOCKTRAILER: cb, wSig, dwCRC, bid. `signature` defaults to the correct one."""
    sig = block_sig(index, block_id) if signature is None else signature
    return struct.pack("<HHIQ", cb, sig, crc, block_id)


def _sealed_block(
    body: bytes,
    block_id: int,
    index: int,
    *,
    cb: int | None = None,
    crc: int | None = None,
    trailer_bid: int | None = None,
    signature: int | None = None,
    trailer_offset: int | None = None,
) -> bytes:
    """`body` padded to its allocation with the trailer last (or at `trailer_offset`)."""
    n = len(body) if cb is None else cb
    alloc = block_alloc_size(len(body))
    out = bytearray(alloc)
    out[: len(body)] = body
    crc_value = compute_crc(0, body) if crc is None else crc
    bid = block_id if trailer_bid is None else trailer_bid
    at = alloc - BLOCK_TRAILER_SIZE if trailer_offset is None else trailer_offset
    out[at : at + BLOCK_TRAILER_SIZE] = block_trailer(n, bid, index, crc_value, signature=signature)
    return bytes(out)


def data_block(
    payload: bytes,
    block_id: int,
    index: int,
    *,
    cb: int | None = None,
    crc: int | None = None,
    trailer_bid: int | None = None,
    signature: int | None = None,
) -> bytes:
    """A whole data block: `payload` (already encoded, if the store encodes), padding, trailer.

    `cb` overrides the trailer's count (default `len(payload)`), `crc` the
    trailer's CRC (default the correct one over `payload`), `trailer_bid`
    the trailer's bid (default `block_id`), `signature` the wSig (default
    the correct one for `index`). The BBT entry that names this block
    should carry `len(payload)` as its cb and `block_id` as its bid.
    """
    if not 1 <= len(payload) <= MAX_BLOCK_DATA_SIZE:
        raise ValueError(f"a data block holds 1..{MAX_BLOCK_DATA_SIZE} bytes, not {len(payload)}")
    return _sealed_block(payload, block_id, index, cb=cb, crc=crc, trailer_bid=trailer_bid, signature=signature)


def xblock(
    entries: list[int],
    block_id: int,
    index: int,
    *,
    level: int = 1,
    total_size: int = 0,
    count: int | None = None,
    btype: int = BTYPE_DATA_TREE,
    cb: int | None = None,
    crc: int | None = None,
    trailer_bid: int | None = None,
) -> bytes:
    """A whole XBLOCK (`level` 1) or XXBLOCK (`level` 2): btype, cLevel, cEnt, lcbTotal, rgbid, padding, trailer.

    `entries` are raw BIDs. `count` overrides cEnt (default `len(entries)`);
    `cb` overrides the trailer's cb (default the header + entries size).
    The block's own `block_id` should have the internal bit (`BID_INTERNAL`)
    set, as should the BBT entry's; `trailer_bid` can disagree on purpose.
    """
    n = len(entries) if count is None else count
    body = struct.pack("<BBHI", btype, level, n, total_size) + struct.pack(f"<{len(entries)}Q", *entries)
    return _sealed_block(body, block_id, index, cb=cb, crc=crc, trailer_bid=trailer_bid)


def slblock(
    entries: list[tuple[int, int, int]],
    block_id: int,
    index: int,
    *,
    level: int = 0,
    count: int | None = None,
    padding: int = 0,
    btype: int = BTYPE_SUBNODE,
    cb: int | None = None,
    crc: int | None = None,
    trailer_bid: int | None = None,
) -> bytes:
    """A whole SLBLOCK: btype, cLevel 0, cEnt, dwPadding, then (nid, bidData, bidSub) SLENTRYs of 24 bytes."""
    n = len(entries) if count is None else count
    body = struct.pack("<BBHI", btype, level, n, padding) + b"".join(struct.pack("<QQQ", *e) for e in entries)
    return _sealed_block(body, block_id, index, cb=cb, crc=crc, trailer_bid=trailer_bid)


def siblock(
    entries: list[tuple[int, int]],
    block_id: int,
    index: int,
    *,
    level: int = 1,
    count: int | None = None,
    padding: int = 0,
    btype: int = BTYPE_SUBNODE,
    cb: int | None = None,
    crc: int | None = None,
    trailer_bid: int | None = None,
) -> bytes:
    """A whole SIBLOCK: btype, cLevel 1, cEnt, dwPadding, then (nid, bidNextLevel) SIENTRYs of 16 bytes."""
    n = len(entries) if count is None else count
    body = struct.pack("<BBHI", btype, level, n, padding) + b"".join(struct.pack("<QQ", *e) for e in entries)
    return _sealed_block(body, block_id, index, cb=cb, crc=crc, trailer_bid=trailer_bid)


def file_with_blocks(blocks: dict[int, bytes], size: int | None = None) -> bytes:
    """An in-memory file holding each block (or page) at its offset, zero elsewhere.

    The same shape as `file_with_pages`: a synthetic store for the block
    reader is a BBT leaf page (`btree_page(PTYPE_BBT, 0, [bbt_entry(...)],
    …)`) plus the blocks its entries name, and no header — `BlockReader`
    takes the crypt method from a `Header` the test supplies.
    """
    return file_with_pages(blocks, size)

# --- the mutation generator (P12) -------------------------------------------------
#
# Everything below turns one *good* Unicode store into a stream of bad ones.
# Each family is a named generator so that a sweep can report by family and
# a parametrize id can read `bit_flips` rather than `case_37`; `mutations`
# runs every family. The rows above this one (P01, P02) wrote the specific
# denial tests; these are the systematic ones — every boundary, every field,
# every value class — and the contract harness (P24) consumes the same stream.
#
# Determinism: a family gets its own `random.Random` seeded from the sweep
# seed AND its name, so adding a mutation to one family never changes what
# another produces for the same seed.
#
# `expect` is the strongest claim a mutation can make about how the landed
# layers must refuse it. `None` means "any PstError, or success — but never
# anything else"; a class or tuple means every PstError raised by any entry
# point must be an instance of it. Keep expectations honest rather than
# tight: a resealed bit flip can land anywhere and produce a cycle
# (`PstLimitError`) as easily as a bad field (`PstFormatError`).

UNICODE_VERSION = 23
MAX_BTREE_LEVEL = 8  # cLevel's ceiling (page.py); bounds the leaf search below


@dataclass(frozen=True, slots=True)
class Mutation:
    """One corrupt store and the refusal it must draw.

    `expect=None`: success or any `PstError` is acceptable; a non-`PstError`
    exception or a hang is the failure. A class or tuple of classes: every
    `PstError` raised must be an instance of it.

    `must_raise`: at least one entry point must refuse the store (with a
    `PstError`, of `expect`'s kind when set). Without it a reader that
    silently walked a nine-deep chain or a self-pointing root would pass;
    with it, "nothing was raised" is its own failure. Left `False` where an
    entry point may legitimately not notice — a raw bit flip in a page's
    unchecked `wSig`, a lie in a field nothing reads yet.
    """

    name: str
    data: bytes
    expect: type[PstError] | tuple[type[PstError], ...] | None = None
    must_raise: bool = False


@dataclass(frozen=True, slots=True)
class Field:
    """One integer field of a struct: where it sits in the file and how wide it is."""

    name: str
    offset: int
    fmt: str  # the single struct code, e.g. "<H"

    @property
    def size(self) -> int:
        return struct.calcsize(self.fmt)

    @property
    def max(self) -> int:
        return (1 << (8 * self.size)) - 1

    def read(self, data: bytes) -> int:
        (value,) = struct.unpack_from(self.fmt, data, self.offset)
        return value

    def write(self, data: bytes, value: int) -> bytes:
        return set_bytes(data, self.offset, struct.pack(self.fmt, value))


def struct_fields(fmt: str, names: list[str], base_offset: int = 0) -> list[Field]:
    """The integer fields of a little-endian struct format, with absolute offsets.

    `names` names every item in `fmt` in order, byte-string items (`Ns`)
    included; those are skipped in the result because a lie in a reserved
    byte string is a CRC test, not a field test.
    """
    if not fmt.startswith("<"):
        raise ValueError(f"only little-endian formats are handled: {fmt!r}")
    fields: list[Field] = []
    offset = base_offset
    index = 0
    count = ""
    for code in fmt[1:]:
        if code.isdigit():
            count += code
            continue
        repeat = int(count) if count else 1
        count = ""
        if code == "s":
            offset += repeat
            index += 1
            continue
        for _ in range(repeat):
            fields.append(Field(names[index], offset, f"<{code}"))
            offset += struct.calcsize(f"<{code}")
            index += 1
    if index != len(names):
        raise ValueError(f"{fmt!r} has {index} items, {len(names)} names given")
    return fields


# Field names, in format order ([MS-PST] 2.2.2.6 / 2.2.2.5 / 2.2.2.7.x).
_LEAD_NAMES = [
    "dwMagic", "dwCRCPartial", "wMagicClient", "wVer", "wVerClient", "bPlatformCreate",
    "bPlatformAccess", "dwReserved1", "dwReserved2", "bidUnused", "bidNextP", "dwUnique",
]  # fmt: skip
_TAIL_NAMES = [
    "dwAlign", "rgbFM", "rgbFP", "bSentinel", "bCryptMethod", "rgbReserved", "bidNextB",
    "dwCRCFull", "rgbReserved2",
]  # fmt: skip
_ROOT_NAMES = [
    "dwReserved", "ibFileEof", "ibAMapLast", "cbAMapFree", "cbPMapFree", "BREFNBT.bid",
    "BREFNBT.ib", "BREFBBT.bid", "BREFBBT.ib", "fAMapValid", "bReserved", "wReserved",
]  # fmt: skip
_BTREE_HEADER_NAMES = ["cEnt", "cEntMax", "cbEnt", "cLevel", "dwPadding"]
_TRAILER_NAMES = ["ptype", "ptypeRepeat", "wSig", "dwCRC", "bid"]
_BTENTRY_NAMES = ["btkey", "BREF.bid", "BREF.ib"]
_BBTENTRY_NAMES = ["BREF.bid", "BREF.ib", "cb", "cRef", "dwPadding"]
_NBTENTRY_NAMES = ["nid", "bidData", "bidSub", "nidParent", "dwPadding"]

# The header fields upstream validates against a fixed value: any lie is a
# PstFormatError (the CRC fields are excluded because every lie is resealed).
_HEADER_FIXED_FIELDS = frozenset(
    {"dwMagic", "wMagicClient", "wVer", "wVerClient", "bPlatformCreate", "bPlatformAccess", "dwAlign", "bSentinel", "rgbReserved"}
)
# The ROOT's two byte indices: a lie is a page the file does not hold.
_ROOT_INDEX_FIELDS = frozenset({"BREFNBT.ib", "BREFBBT.ib"})
# Page fields whose every lie upstream refuses as a format error.
_PAGE_FIXED_FIELDS = frozenset({"ptype", "ptypeRepeat", "dwPadding"})
_CRC_FIELDS = frozenset({"dwCRCPartial", "dwCRCFull", "dwCRC"})


def header_fields() -> list[Field]:
    """Every integer field of the Unicode header, ROOT included, CRCs excluded."""
    fields = struct_fields(_LEAD_FORMAT, _LEAD_NAMES)
    fields += struct_fields(ROOT_FORMAT, _ROOT_NAMES, ROOT_OFFSET)
    fields += struct_fields(_TAIL_FORMAT, _TAIL_NAMES, _TAIL_OFFSET)
    return [f for f in fields if f.name not in _CRC_FIELDS]


def page_fields(data: bytes, page_offset: int) -> list[Field]:
    """The BTPAGE header, the trailer (CRC excluded) and the first entry of the page at `page_offset`."""
    _count, _max, entry_size, level, _padding = _btree_header(data, page_offset)
    fields = struct_fields(_BTREE_HEADER_FORMAT, _BTREE_HEADER_NAMES, page_offset + BTREE_HEADER_OFFSET)
    fields += struct_fields(PAGE_TRAILER_FORMAT, _TRAILER_NAMES, page_offset + PAGE_TRAILER_OFFSET)
    ptype = data[page_offset + PAGE_TRAILER_OFFSET]
    if level > 0:
        entry_fmt, names = INTERMEDIATE_ENTRY_FORMAT, _BTENTRY_NAMES
    elif ptype == PTYPE_NBT:
        entry_fmt, names = NODE_ENTRY_FORMAT, _NBTENTRY_NAMES
    else:
        entry_fmt, names = BLOCK_ENTRY_FORMAT, _BBTENTRY_NAMES
    if entry_size >= struct.calcsize(entry_fmt):
        fields += [Field(f"entry0.{f.name}", f.offset, f.fmt) for f in struct_fields(entry_fmt, names, page_offset)]
    return [f for f in fields if f.name not in _CRC_FIELDS]


# --- reading the base store's shape ----------------------------------------------


def check_unicode_base(data: bytes) -> None:
    """Refuse a base that is not a Unicode store: mutating one is not a test of anything."""
    if len(data) < HEADER_SIZE or data[:4] != b"!BDN":
        raise ValueError("base store is not a PST")
    (version,) = struct.unpack_from("<H", data, VERSION_OFFSET)
    if version != UNICODE_VERSION:
        raise ValueError(f"base store has wVer={version}; the generator mutates Unicode (23) stores only")


def root_refs(data: bytes) -> tuple[tuple[int, int], tuple[int, int]]:
    """`((nbt_page_id, nbt_offset), (bbt_page_id, bbt_offset))` from the header's ROOT, read raw."""
    values = struct.unpack_from(ROOT_FORMAT, data, ROOT_OFFSET)
    return (values[5], values[6]), (values[7], values[8])


def _btree_header(data: bytes, page_offset: int) -> tuple[int, int, int, int, int]:
    """`(cEnt, cEntMax, cbEnt, cLevel, dwPadding)` of the page at `page_offset`."""
    return struct.unpack_from(_BTREE_HEADER_FORMAT, data, page_offset + BTREE_HEADER_OFFSET)


def first_child(data: bytes, page_offset: int) -> tuple[int, int]:
    """`(page_id, offset)` of the first BTENTRY of the intermediate page at `page_offset`."""
    _key, page_id, index = struct.unpack_from(INTERMEDIATE_ENTRY_FORMAT, data, page_offset)
    return page_id, index


def leaf_page(data: bytes, root_offset: int) -> int:
    """The offset of the leftmost leaf under `root_offset` (the root itself if it is one)."""
    offset = root_offset
    for _ in range(MAX_BTREE_LEVEL + 1):
        _count, _max, _size, level, _padding = _btree_header(data, offset)
        if level == 0:
            return offset
        _page_id, offset = first_child(data, offset)
    raise ValueError("no leaf within the level bound; the base store is not well formed")


def first_leaf_key(data: bytes, root_offset: int) -> int:
    """The first key of the leftmost leaf: a key `find` must reach on the unmutated base."""
    leaf = leaf_page(data, root_offset)
    (key,) = struct.unpack_from("<Q", data, leaf)
    return key


def tree_pages(data: bytes, root_offset: int) -> list[int]:
    """Every page offset of the B-tree rooted at `root_offset`, read raw, pre-order.

    Bounded by `MAX_BTREE_LEVEL` and a visited set so that a malformed base
    cannot loop it; it exists to say which bytes of the base a reader
    visits, so that a mutation can know whether it touched any of them.
    """
    seen: list[int] = []
    stack = [(root_offset, 0)]
    while stack:
        offset, depth = stack.pop()
        if offset in seen or depth > MAX_BTREE_LEVEL or offset + PAGE_SIZE > len(data):
            continue
        seen.append(offset)
        count, _max, entry_size, level, _padding = _btree_header(data, offset)
        if level == 0 or entry_size < BTENTRY_SIZE:
            continue
        for i in reversed(range(count)):
            if (i + 1) * entry_size > BTREE_HEADER_OFFSET:
                break
            _key, _page_id, child = struct.unpack_from(INTERMEDIATE_ENTRY_FORMAT, data, offset + i * entry_size)
            stack.append((child, depth + 1))
    return seen


def pages_read(data: bytes) -> list[int]:
    """The page offsets the landed entry points visit: both trees and the density list page, when present."""
    (_, nbt), (_, bbt) = root_refs(data)
    pages = tree_pages(data, nbt) + [p for p in tree_pages(data, bbt) if p not in tree_pages(data, nbt)]
    dl = DENSITY_LIST_OFFSET
    if dl + PAGE_SIZE <= len(data) and data[dl + PAGE_TRAILER_OFFSET] == PTYPE_DL:
        pages.append(dl)
    return pages


def interesting_pages(data: bytes) -> list[tuple[str, int]]:
    """`(what, offset)` for the NBT root, the BBT root, and the NBT's leftmost leaf when it is a separate page."""
    (_, nbt), (_, bbt) = root_refs(data)
    pages = [("nbt_root", nbt), ("bbt_root", bbt)]
    leaf = leaf_page(data, nbt)
    if leaf != nbt:
        pages.append(("nbt_leaf", leaf))
    return pages


# --- builders the families share --------------------------------------------------


def append_pages(data: bytes, pages: dict[int, bytes]) -> bytes:
    """`data` extended so that each page sits at its (absolute, past-the-end) offset."""
    for offset in pages:
        if offset < len(data):
            raise ValueError(f"page offset 0x{offset:X} is inside the {len(data)}-byte base")
    return data + file_with_pages({offset - len(data): page for offset, page in pages.items()})


def btree_chain(
    length: int, *, start: int, page_type: int = PTYPE_NBT, key: int = 0, first_page_id: int = 0x1000
) -> tuple[dict[int, bytes], tuple[int, int]]:
    """`length` intermediate pages each naming the next, then one leaf; returns `(pages, (root_id, root_offset))`.

    Every entry carries `key` (default 0, so that a `find` for any key
    descends the chain rather than stopping at "below the first key"). The
    pages are laid out contiguously from `start`.
    """
    pages: dict[int, bytes] = {}
    for i in range(length):
        offset, child = start + PAGE_SIZE * i, start + PAGE_SIZE * (i + 1)
        page_id, child_id = first_page_id + i, first_page_id + i + 1
        pages[offset] = btree_page(page_type, 1, [bt_entry(key, child_id, child)], page_id, offset)
    leaf_offset = start + PAGE_SIZE * length
    leaf_id = first_page_id + length
    entry = nbt_entry(0x21, 0x4) if page_type == PTYPE_NBT else bbt_entry(0x4, leaf_offset, 0)
    pages[leaf_offset] = btree_page(page_type, 0, [entry], leaf_id, leaf_offset)
    return pages, (first_page_id, start)


def replace_page(data: bytes, offset: int, page: bytes) -> bytes:
    """`data` with the 512 bytes at `offset` replaced by `page` (already sealed)."""
    if len(page) != PAGE_SIZE:
        raise ValueError(f"a page is {PAGE_SIZE} bytes, got {len(page)}")
    return set_bytes(data, offset, page)


# --- the families -----------------------------------------------------------------

Family = Callable[[bytes, random.Random], Iterator[Mutation]]

# Where a truncation inside the header lands: every structure boundary of
# [MS-PST] 2.2.2.6 (each field start) plus the last byte.
_HEADER_BOUNDARIES = sorted(
    {f.offset for f in struct_fields(_LEAD_FORMAT, _LEAD_NAMES)}
    | {RGNID_OFFSET}
    | {f.offset for f in struct_fields(ROOT_FORMAT, _ROOT_NAMES, ROOT_OFFSET)}
    | {f.offset for f in struct_fields(_TAIL_FORMAT, _TAIL_NAMES, _TAIL_OFFSET)}
    | {ALIGN_OFFSET, FREE_PAGE_MAP_OFFSET, SENTINEL_OFFSET, CRYPT_METHOD_OFFSET, RESERVED_OFFSET, HEADER_SIZE - 1}
)
TRUNCATION_PAGES = 16  # every page boundary of the first N pages
FINAL_PAGE_STEP = 64


def truncations(base: bytes, rng: random.Random) -> Iterator[Mutation]:
    """The file cut short at every structure boundary, page boundary, and 64-byte step of the last page."""
    lengths: set[int] = set(_HEADER_BOUNDARIES)
    lengths |= {PAGE_SIZE * i for i in range(1, TRUNCATION_PAGES + 1)}
    (_, nbt), (_, bbt) = root_refs(base)
    lengths |= {nbt, nbt + 1, nbt + PAGE_SIZE - 1, bbt, bbt + 1, bbt + PAGE_SIZE - 1}
    last_page = (len(base) - 1) // PAGE_SIZE * PAGE_SIZE
    lengths |= {last_page + step for step in range(0, PAGE_SIZE, FINAL_PAGE_STEP)}
    # A cut that removes bytes of a page the reader visits must be refused;
    # one that only removes pages nothing reads yet (Empty.pst ends in an
    # allocation map) may pass today and will be refused by a later layer.
    read_end = max((p + PAGE_SIZE for p in pages_read(base)), default=HEADER_SIZE)
    for length in sorted(lengths):
        if 0 <= length < len(base):
            data = truncate(base, length)
            yield Mutation(f"truncations:len=0x{length:X}", data, PstFormatError, must_raise=length < read_end)


FLIPS_PER_REGION = 12


def _flip_region(base: bytes, rng: random.Random, what: str, start: int, end: int, *, reseal: Callable[[bytes], bytes] | None) -> Iterator[Mutation]:
    kind = "resealed" if reseal else "raw"
    for _ in range(FLIPS_PER_REGION):
        offset = rng.randrange(start, end)
        bit = rng.randrange(8)
        data = flip_byte(base, offset, 1 << bit)
        if reseal:
            data = reseal(data)
        # Raw: the CRC (or a fixed field) catches it, so only PstFormatError
        # may come out. Resealed: the parser sees the value, and a flipped
        # page reference can as easily make a cycle as a bad field.
        yield Mutation(f"bit_flips:{what}:{kind}:0x{offset:X}b{bit}", data, PstFormatError if not reseal else None)


def bit_flips(base: bytes, rng: random.Random) -> Iterator[Mutation]:
    """Seeded single-bit flips over the header, the two root pages and a leaf, raw and resealed."""
    # Raw header flips: anywhere the CRCs cover, or the CRC fields themselves.
    yield from _flip_region(base, rng, "header", 0, CRC_FULL_OFFSET + 4, reseal=None)
    # Resealed header flips: inside the CRC-covered span but not the CRC
    # fields (a reseal would undo those and the mutation would equal the base).
    yield from _flip_region(base, rng, "header", CRC_START, CRC_FULL_OFFSET, reseal=reseal_header)
    for what, offset in interesting_pages(base):
        yield from _flip_region(base, rng, what, offset, offset + PAGE_SIZE, reseal=None)
        yield from _flip_region(base, rng, what, offset, offset + PAGE_DATA_SIZE, reseal=lambda d, o=offset: reseal_page(d, o))


def _lie_values(field: Field, current: int, past_eof: int) -> list[tuple[str, int]]:
    """0, 1, max, max-1 and a value past EOF — each once, and never the current value."""
    candidates = [("0", 0), ("1", 1), ("max", field.max), ("max-1", field.max - 1), ("past_eof", min(past_eof, field.max))]
    seen: set[int] = {current}
    out: list[tuple[str, int]] = []
    for label, value in candidates:
        if value not in seen:
            seen.add(value)
            out.append((label, value))
    return out


def _header_expect(field: Field) -> type[PstError] | None:
    if field.name in _HEADER_FIXED_FIELDS or field.name in _ROOT_INDEX_FIELDS:
        return PstFormatError
    if field.name == "bCryptMethod":
        # 0/1 are real methods (success); 0xFF, 0xFE and the clipped past-EOF
        # value are unknown; 0x10 is not among the lie values.
        return PstFormatError
    return None


def field_lies(base: bytes, rng: random.Random) -> Iterator[Mutation]:
    """Every integer field of the header, ROOT, root pages, a leaf and their first entries, set to each value class, resealed."""
    past_eof = len(base) + PAGE_SIZE
    for field in header_fields():
        current = field.read(base)
        for label, value in _lie_values(field, current, past_eof):
            data = reseal_header(field.write(base, value))
            expect = _header_expect(field)
            # A lie in a validated field is always refused; bCryptMethod 0/1
            # are real methods, so only its unknown values are.
            required = field.name in _HEADER_FIXED_FIELDS or field.name in _ROOT_INDEX_FIELDS or (
                field.name == "bCryptMethod" and value > 2
            )
            yield Mutation(f"field_lies:header.{field.name}={label}", data, expect, must_raise=required)
    for what, offset in interesting_pages(base):
        for field in page_fields(base, offset):
            current = field.read(base)
            for label, value in _lie_values(field, current, past_eof):
                data = reseal_page(field.write(base, value), offset)
                expect = PstFormatError if field.name in _PAGE_FIXED_FIELDS else None
                yield Mutation(f"field_lies:{what}.{field.name}={label}", data, expect, must_raise=expect is not None)


def pointer_cycles(base: bytes, rng: random.Random) -> Iterator[Mutation]:
    """Root → itself (both trees), a two-page cycle, an intermediate naming the root, a leaf claiming a level."""
    (nbt_id, nbt), (bbt_id, bbt) = root_refs(base)
    for what, page_id, offset, ptype in (("nbt", nbt_id, nbt, PTYPE_NBT), ("bbt", bbt_id, bbt, PTYPE_BBT)):
        page = btree_page(ptype, 1, [bt_entry(0, page_id, offset)], page_id, offset)
        yield Mutation(f"pointer_cycles:{what}_root_to_itself", replace_page(base, offset, page), PstLimitError, must_raise=True)
    # NBT root → BBT root's slot → NBT root: both walks enter the loop.
    a = btree_page(PTYPE_NBT, 1, [bt_entry(0, bbt_id, bbt)], nbt_id, nbt)
    b = btree_page(PTYPE_NBT, 1, [bt_entry(0, nbt_id, nbt)], bbt_id, bbt)
    yield Mutation("pointer_cycles:two_page_cycle", replace_page(replace_page(base, nbt, a), bbt, b), PstLimitError, must_raise=True)
    # Root (level 2) → intermediate (level 1) → back at the root.
    a = btree_page(PTYPE_NBT, 2, [bt_entry(0, bbt_id, bbt)], nbt_id, nbt)
    b = btree_page(PTYPE_NBT, 1, [bt_entry(0, nbt_id, nbt)], bbt_id, bbt)
    yield Mutation("pointer_cycles:intermediate_back_to_root", replace_page(replace_page(base, nbt, a), bbt, b), PstLimitError, must_raise=True)
    # A leaf whose header claims level 1: its entries are read as BTENTRYs and
    # their "byte indices" (bidSub, usually 0) are followed as pages. Where
    # those land is not a page, so the walk refuses; nothing may leak.
    leaf = leaf_page(base, nbt)
    lifted = reseal_page(set_u8(base, leaf + BTREE_HEADER_OFFSET + 3, 1), leaf)
    yield Mutation("pointer_cycles:leaf_claims_level_1", lifted, (PstFormatError, PstLimitError), must_raise=True)
    # A root that names the other tree's root: intermediate pages of either
    # type are accepted, so the walk proceeds until a leaf of the wrong kind.
    page = btree_page(PTYPE_NBT, 1, [bt_entry(0, bbt_id, bbt)], nbt_id, nbt)
    yield Mutation("pointer_cycles:nbt_root_into_bbt", replace_page(base, nbt, page), (PstFormatError, PstLimitError), must_raise=True)


def depth_bombs(base: bytes, rng: random.Random) -> Iterator[Mutation]:
    """Chains of intermediate pages one deeper than `limits.max_btree_depth`, appended past the base's end."""
    (nbt_id, nbt), (bbt_id, bbt) = root_refs(base)
    start = (len(base) + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE
    depth = DEFAULT_LIMITS.max_btree_depth
    for what, page_id, offset, ptype, length in (
        ("nbt", nbt_id, nbt, PTYPE_NBT, depth + 1),
        ("bbt", bbt_id, bbt, PTYPE_BBT, depth + 1),
        ("nbt_x4", nbt_id, nbt, PTYPE_NBT, 4 * (depth + 1)),
    ):
        pages, (chain_id, chain_offset) = btree_chain(length, start=start, page_type=ptype)
        root = btree_page(ptype, 1, [bt_entry(0, chain_id, chain_offset)], page_id, offset)
        data = append_pages(replace_page(base, offset, root), pages)
        yield Mutation(f"depth_bombs:{what}_chain_{length}", data, PstLimitError, must_raise=True)


FUTURE_VERSIONS = (24, 35, 38, 0xFFFF)
CRYPT_SAMPLES = 12


def future_versions(base: bytes, rng: random.Random) -> Iterator[Mutation]:
    """`wVer` values from the future and `bCryptMethod` values this port does not know, resealed."""
    for version in FUTURE_VERSIONS:
        data = reseal_header(set_u16(base, VERSION_OFFSET, version))
        yield Mutation(f"future_versions:wVer={version}", data, PstFormatError, must_raise=True)
    methods = {0x10, *rng.sample(range(3, 0x100), CRYPT_SAMPLES)}
    for method in sorted(methods):
        data = reseal_header(set_u8(base, CRYPT_METHOD_OFFSET, method))
        expect = PstUnsupportedError if method == 0x10 else PstFormatError
        yield Mutation(f"future_versions:bCryptMethod=0x{method:02X}", data, expect, must_raise=True)


def zero_files(base: bytes, rng: random.Random) -> Iterator[Mutation]:
    """Files with no structure at all: empty, one byte, a page, one short of a header, a header, all-0xFF."""
    for length in (0, 1, PAGE_SIZE, HEADER_SIZE - 1, HEADER_SIZE):
        yield Mutation(f"zero_files:zeros_{length}", bytes(length), PstFormatError, must_raise=True)
    yield Mutation("zero_files:ff_header_and_page", b"\xff" * (HEADER_SIZE + PAGE_SIZE), PstFormatError, must_raise=True)


def magic_only(base: bytes, rng: random.Random) -> Iterator[Mutation]:
    """`!BDN` and then nothing, or zeros: the file starts like a PST and stops."""
    yield Mutation("magic_only:nothing", b"!BDN", PstFormatError, must_raise=True)
    yield Mutation("magic_only:zeros_to_header", b"!BDN" + bytes(HEADER_SIZE - 4), PstFormatError, must_raise=True)
    yield Mutation("magic_only:zeros_to_page_past_header", b"!BDN" + bytes(HEADER_SIZE + PAGE_SIZE - 4), PstFormatError, must_raise=True)


# P03 landed? add: `block_lies` — a BBTENTRY `cb` larger than the file, an
# XXBLOCK tree 10,000 deep (`limits.max_xblock_depth` + 1 is enough, 10,000
# proves the bound is not a stack), an XBLOCK `lcbTotal` of 4 GB in a 29 KB
# file (must be `PstLimitError` before any allocation), and a subnode tree
# whose SIBLOCK names its own block (cycle → `PstLimitError`). Build them
# with the block builders P03 adds here (`data_block`, `xblock`, `slblock`,
# `siblock`, `file_with_blocks`) and register the family in FAMILIES. The
# stub tests in tests/test_corruption.py (`test_p03_*`) are the place they
# are asserted; they skip until `pypst.ndb.block` imports.
#
# --- P04: heap-on-node and BTree-on-heap builders --------------------------------
#
# Synthetic heaps for tests/test_heap.py and tests/test_tree.py, and the
# `heap_lies` family below. A heap here is ONE block's worth of bytes (the
# HNHDR, the items back to back, the HNPAGEMAP), exactly what
# `HeapNode([bytes])` takes; a multi-block heap is a list of `heap_block`s.
# Every builder takes overrides for the fields a denial test lies about.

HEAP_SIGNATURE = 0xEC
HEAP_HEADER_FORMAT = "<HBBII"
BTH_HEADER_FORMAT = "<BBBBI"
CLIENT_SIG_PC = 0xBC
CLIENT_SIG_TC = 0x7C
CLIENT_SIG_BTH = 0xB5


def hid(index: int, block: int = 0) -> int:
    """A raw HID ([MS-PST] 2.3.1.1): type 0, the 1-based `index` (11 bits), the block index (16 bits)."""
    return (block << 16) | (index << 5)


def heap_header(
    page_map_offset: int = 0,
    *,
    client_sig: int = CLIENT_SIG_PC,
    user_root: int = hid(1),
    fill_levels: int = 0,
    signature: int = HEAP_SIGNATURE,
) -> bytes:
    """A 12-byte HNHDR ([MS-PST] 2.3.1.2). `page_map_offset` is patched by `heap_block`."""
    return struct.pack(HEAP_HEADER_FORMAT, page_map_offset, signature, client_sig, user_root, fill_levels)


def page_header(page_map_offset: int = 0) -> bytes:
    """A 2-byte HNPAGEHDR ([MS-PST] 2.3.1.3)."""
    return struct.pack("<H", page_map_offset)


def bitmap_header(page_map_offset: int = 0, fill_levels: bytes = bytes(64)) -> bytes:
    """A 66-byte HNBITMAPHDR ([MS-PST] 2.3.1.4)."""
    return struct.pack("<H", page_map_offset) + fill_levels


def page_map(offsets: Sequence[int], *, count: int | None = None, free: int | None = None) -> bytes:
    """An HNPAGEMAP ([MS-PST] 2.3.1.5): cAlloc (len - 1 unless lied), cFree (the zero steps unless lied), rgibAlloc."""
    n = len(offsets) - 1 if count is None else count
    zero_steps = sum(1 for a, b in itertools.pairwise(offsets) if a == b)
    f = zero_steps if free is None else free
    return struct.pack(f"<HH{len(offsets)}H", n, f, *offsets)


def heap_block(
    items: Sequence[bytes],
    *,
    header: bytes | None = None,
    offsets: Sequence[int] | None = None,
    page_map_offset: int | None = None,
    count: int | None = None,
    free: int | None = None,
    pad: int = 0,
) -> bytes:
    """One heap block: `header` (an HNHDR by default), the items, `pad` bytes, then the page map.

    The header's first two bytes are set to the page map's offset unless
    `page_map_offset` lies; `offsets` replaces the computed rgibAlloc.
    """
    head = heap_header() if header is None else header
    body = bytearray(head)
    computed = [len(body)]
    for item in items:
        body += item
        computed.append(len(body))
    body += bytes(pad)
    ib = len(body) if page_map_offset is None else page_map_offset
    body[0:2] = struct.pack("<H", ib)
    return bytes(body) + page_map(computed if offsets is None else list(offsets), count=count, free=free)


def heap_node(items: Sequence[bytes], **header_kwargs: Any) -> bytes:
    """A single-block heap whose HNHDR takes `heap_header`'s keyword overrides; item 1 is `items[0]`."""
    return heap_block(items, header=heap_header(**header_kwargs))


def bth_header(key_size: int = 2, entry_size: int = 6, levels: int = 0, root: int = 0, *, btype: int = CLIENT_SIG_BTH) -> bytes:
    """An 8-byte BTHHEADER ([MS-PST] 2.3.2.1); `root` is a raw HID (0 = empty tree)."""
    return struct.pack(BTH_HEADER_FORMAT, btype, key_size, entry_size, levels, root)


def bth_leaf(pairs: Sequence[tuple[bytes, bytes]]) -> bytes:
    """A leaf page ([MS-PST] 2.3.2.3): the key/value records back to back, as given."""
    return b"".join(k + v for k, v in pairs)


def bth_index(records: Sequence[tuple[bytes, int]]) -> bytes:
    """An index page ([MS-PST] 2.3.2.2): (first key, raw HID of the next level) records back to back."""
    return b"".join(k + struct.pack("<I", h) for k, h in records)


def _chunks(seq: Sequence[Any], size: int) -> list[list[Any]]:
    return [list(seq[i : i + size]) for i in range(0, len(seq), size)] or [[]]


def bth_heap(
    pairs: Sequence[tuple[bytes, bytes]],
    *,
    key_size: int = 2,
    entry_size: int = 6,
    levels: int = 0,
    fanout: int = 2,
    client_sig: int = CLIENT_SIG_PC,
    header_root: int | None = None,
) -> bytes:
    """A single-block heap holding a well-formed BTH over `pairs` (already in key order).

    Item 1 is the BTHHEADER (the heap's user root); the leaf pages follow,
    `fanout` records each when `levels` > 0, then each index level, the
    top one a single page. `header_root` replaces `hidRoot` for a lie.
    With no pairs the tree is empty (hidRoot 0), whatever `levels` says.
    """
    items: list[bytes] = [b""]  # placeholder for the header, item 1
    if not pairs:
        root = 0
    else:
        leaf_pages = _chunks(pairs, fanout) if levels else [list(pairs)]
        page_hids: list[tuple[bytes, int]] = []
        for page in leaf_pages:
            items.append(bth_leaf(page))
            page_hids.append((page[0][0], hid(len(items))))
        for level in range(levels):
            groups = _chunks(page_hids, fanout) if level < levels - 1 else [page_hids]
            page_hids = []
            for group in groups:
                items.append(bth_index(group))
                page_hids.append((group[0][0], hid(len(items))))
        root = page_hids[0][1]
    items[0] = bth_header(key_size, entry_size, levels, root if header_root is None else header_root)
    return heap_node(items, client_sig=client_sig)


def pc_record(prop_type: int, hnid: int) -> bytes:
    """A 6-byte PC BTH value ([MS-PST] 2.3.3.3): wPropType, dwValueHnid — the `entry_size` 6 of every PC."""
    return struct.pack("<HI", prop_type, hnid)


# --- P06: table-context builders ---------------------------------------------------
#
# A TC's heap holds a TCINFO at its user root ([MS-PST] 2.3.4.1), a BTH for
# the row index ([MS-PST] 2.3.4.3) and — usually — the row matrix as another
# heap item. These build each piece; `tests/test_table_context.py` assembles
# them with `heap_node`, and `tc_lies` below rewrites a real one in place.

TCINFO_FORMAT = "<BBHHHHIII"
TCOLDESC_FORMAT = "<HHHBB"


def tcoldesc(prop_type: int, prop_id: int, offset: int, size: int, bit: int) -> bytes:
    """An 8-byte TCOLDESC ([MS-PST] 2.3.4.2): the property tag, the cell's offset and width, the existence bit."""
    return struct.pack(TCOLDESC_FORMAT, prop_type, prop_id, offset, size, bit)


def tcinfo(
    columns: Sequence[bytes],
    rgib: Sequence[int],
    *,
    row_index: int = 0,
    rows: int = 0,
    btype: int = CLIENT_SIG_TC,
    count: int | None = None,
    deprecated_index: int = 0,
) -> bytes:
    """A TCINFO ([MS-PST] 2.3.4.1): bType, cCols, the four rgib offsets, hidRowIndex, hnidRows, hidIndex, rgTCOLDESC.

    `count` lies about cCols; `rgib` is the four end offsets in order
    (TCI_4b, TCI_2b, TCI_1b, TCI_bm).
    """
    head = struct.pack(
        TCINFO_FORMAT,
        btype,
        len(columns) if count is None else count,
        *rgib,
        row_index,
        rows,
        deprecated_index,
    )
    return head + b"".join(columns)


def tcrowid(row_id: int, index: int) -> tuple[bytes, bytes]:
    """One TCROWID ([MS-PST] 2.3.4.3.1) as the (key, value) pair a Unicode row-index BTH holds."""
    return struct.pack("<I", row_id), struct.pack("<I", index)


def tc_row(row_id: int, unique: int, cells: bytes, bitmap: bytes) -> bytes:
    """One row of a row matrix ([MS-PST] 2.3.4.4.1): dwRowID, rgdwData[0], the cell bytes from offset 8, rgbCEB."""
    return struct.pack("<II", row_id, unique) + cells + bitmap


# --- heap_lies: the message-store PC of a real store, lied about in place ----------
#
# The store PC (NID 0x21) is a single data block in every corpus store, so
# each lie is a rewrite of that block's decoded bytes, re-encoded by the
# header's method and re-CRC'd, and the whole file is otherwise the base.
# The landed NDB layers locate the block; a lie the NDB refuses would be
# the NDB's test, not the heap's, so the trailer is always made consistent.

NID_MESSAGE_STORE = 0x21
NID_NAME_TO_ID_MAP = 0x61
_HNID_BEARING_TYPES = frozenset({0x001E, 0x001F, 0x0102})


@dataclass(frozen=True)
class _DataBlockSite:
    offset: int
    size: int
    cyclic_key: int
    crypt: int
    data: bytes  # decoded


def node_data_block(base: bytes, nid: int) -> _DataBlockSite:
    """Where one node's single data block is, and its decoded bytes.

    The lie families rewrite a real structure in place, which needs the
    node's data to be ONE block: a multi-block node would have to be
    re-encoded block by block with each one's own key. Every node these
    families aim at (the store PC, the root folder's hierarchy table) is a
    single block in every base they are pinned for.
    """
    from pypst.encode import decode_block
    from pypst.ndb.block import BlockReader
    from pypst.ndb.btree import BlockBTree, NodeBTree
    from pypst.ndb.header import read_header
    from pypst.ndb.ids import NodeId

    f = io.BytesIO(base)
    header = read_header(f)
    bbt = BlockBTree(f, header.root.block_btree)
    entry = NodeBTree(f, header.root.node_btree).find(NodeId(nid))
    block = bbt.find(entry.data)
    if block.block.block.is_internal:
        raise ValueError(f"node 0x{nid:X} is not a single data block; the lie families need one")
    offset, size = block.block.index.value, block.size
    key = block.block.block.search_key & 0xFFFFFFFF
    raw = base[offset : offset + size]
    reader = BlockReader(f, header, bbt)
    assert reader.node_data(entry) == decode_block(raw, header.crypt_method, key)
    return _DataBlockSite(offset, size, key, int(header.crypt_method), decode_block(raw, header.crypt_method, key))


def store_pc_block(base: bytes) -> _DataBlockSite:
    """Where the message store's PC data block is, and its decoded bytes."""
    return node_data_block(base, NID_MESSAGE_STORE)


node_pc_block = node_data_block  # P07's name for the same helper; both rows generalized `store_pc_block`


def rewrite_data_block(base: bytes, site: _DataBlockSite, data: bytes) -> bytes:
    """`base` with the block at `site` holding `data` (same length), encoded and CRC'd as the header says."""
    from pypst.encode import CryptMethod, encode_decode_cyclic, encode_permute

    assert len(data) == site.size
    method = CryptMethod(site.crypt)
    if method is CryptMethod.PERMUTE:
        encoded = encode_permute(data)
    elif method is CryptMethod.CYCLIC:
        encoded = encode_decode_cyclic(data, site.cyclic_key)
    else:
        encoded = data
    out = bytearray(base)
    out[site.offset : site.offset + site.size] = encoded
    trailer = site.offset + block_alloc_size(site.size) - BLOCK_TRAILER_SIZE
    out[trailer + 4 : trailer + 8] = struct.pack("<I", compute_crc(0, encoded))
    return bytes(out)


def _heap_shape(data: bytes) -> dict[str, Any]:
    """The offsets inside a decoded PC heap block that the lies below rewrite."""
    ib, _sig, _client, user_root, _fill = struct.unpack_from(HEAP_HEADER_FORMAT, data, 0)
    count, _free = struct.unpack_from("<HH", data, ib)
    offsets = struct.unpack_from(f"<{count + 1}H", data, ib + 4)
    root_index = (user_root >> 5) & 0x7FF
    bth_at = offsets[root_index - 1]
    _btype, key_size, entry_size, _levels, bth_root = struct.unpack_from(BTH_HEADER_FORMAT, data, bth_at)
    page_index = (bth_root >> 5) & 0x7FF
    page_at, page_end = offsets[page_index - 1], offsets[page_index]
    return {
        "ib": ib,
        "count": count,
        "rgib": ib + 4,
        "bth": bth_at,
        "page": page_at,
        "page_end": page_end,
        "stride": key_size + entry_size,
        "root_hid": bth_root,
        "offsets": offsets,
        "sizes": tuple(b - a for a, b in itertools.pairwise(offsets)),
    }


def _first_hnid_record(data: bytes, shape: dict[str, int]) -> int | None:
    """The offset of the first root-page record whose value is a heap HNID of a variable-size type."""
    for at in range(shape["page"], shape["page_end"], shape["stride"]):
        prop_type, hnid = struct.unpack_from("<HI", data, at + 2)
        if prop_type in _HNID_BEARING_TYPES and hnid & 0x1F == 0 and hnid != 0:
            return at
    return None


def heap_lies(base: bytes, rng: random.Random) -> Iterator[Mutation]:
    """The store PC's heap and BTH lied about in place: header, page map, user root, BTH header, root page."""
    site = store_pc_block(base)
    data = site.data
    shape = _heap_shape(data)
    ib, rgib, bth = shape["ib"], shape["rgib"], shape["bth"]

    def lie(name: str, edited: bytes, expect: type[PstError]) -> Mutation:
        return Mutation(f"heap_lies:{name}", rewrite_data_block(base, site, edited), expect, must_raise=True)

    yield lie("bSig=0x00", set_u8(data, 2, 0x00), PstFormatError)
    yield lie("bClientSig=0x00", set_u8(data, 3, 0x00), PstFormatError)
    yield lie("ibHnpm=0xFFFF", set_u16(data, 0, 0xFFFF), PstFormatError)
    yield lie("ibHnpm=odd_past_end", set_u16(data, 0, len(data) - 1), PstFormatError)
    yield lie("cAlloc=0xFFFF", set_u16(data, ib, 0xFFFF), PstFormatError)
    yield lie("cFree=cAlloc", set_u16(data, ib + 2, shape["count"]), PstFormatError)
    yield lie("rgibAlloc_decreasing", set_u16(data, rgib + 4, 0), PstFormatError)
    yield lie("rgibAlloc_past_block", set_u16(data, rgib + 2 * shape["count"], 0xFFFF), PstFormatError)
    yield lie("hidUserRoot=0", set_u32(data, 4, 0), PstFormatError)
    yield lie("hidUserRoot_type_bits", set_u32(data, 4, hid(1) | 0x01), PstFormatError)
    yield lie("hidUserRoot_past_cAlloc", set_u32(data, 4, hid(0x7FF)), PstFormatError)
    yield lie("hidUserRoot_block_1", set_u32(data, 4, hid(1, block=1)), PstFormatError)
    yield lie("bth.bType=bTypePC", set_u8(data, bth, CLIENT_SIG_PC), PstFormatError)
    yield lie("bth.cbKey=3", set_u8(data, bth + 1, 3), PstFormatError)
    yield lie("bth.cbEnt=0", set_u8(data, bth + 2, 0), PstFormatError)
    yield lie("bth.cbEnt=33", set_u8(data, bth + 2, 33), PstFormatError)
    yield lie("bth.bIdxLevels=0xFF", set_u8(data, bth + 3, 0xFF), PstLimitError)
    yield lie("bth.hidRoot_past_cAlloc", set_u32(data, bth + 4, hid(0x7FF)), PstFormatError)
    # The root page not a whole number of records — a cbEnt the page length
    # does not divide by: upstream's `while let Ok` would drop the tail
    # silently; this port refuses.
    page_len = shape["page_end"] - shape["page"]
    ragged_ent = next(e for e in (7, 5, 9, 11, 13) if page_len % (2 + e))
    yield lie(f"bth.cbEnt={ragged_ent}_ragged", set_u8(data, bth + 2, ragged_ent), PstFormatError)
    # A cycle: one index level whose root page is an item filled with
    # records naming that same item. Any item whose length is a whole
    # number of 6-byte index records will do; its bytes are overwritten.
    cyclic_item = next((i for i, size in enumerate(shape["sizes"], start=1) if size and size % 6 == 0), None)
    if cyclic_item is not None:
        at, size = shape["offsets"][cyclic_item - 1], shape["sizes"][cyclic_item - 1]
        cyclic = set_u8(data, bth + 3, 1)
        cyclic = set_u32(cyclic, bth + 4, hid(cyclic_item))
        cyclic = set_bytes(cyclic, at, (b"\x00\x00" + struct.pack("<I", hid(cyclic_item))) * (size // 6))
        yield lie("bth.root_cycle", cyclic, PstLimitError)
    record = _first_hnid_record(data, shape)
    if record is not None:
        yield lie("record.hnid_past_cAlloc", set_u32(data, record + 4, hid(0x7FF)), PstFormatError)
        yield lie("record.hnid_subnode_absent", set_u32(data, record + 4, 0x4000_0001), PstNotFoundError)


# --- pc_lies: the same store PC, lied about one PROPERTY RECORD at a time ----------
#
# `heap_lies` breaks the container — the HNHDR, the page map, the BTH
# header, the root page's shape. `pc_lies` leaves all of that valid and
# breaks what P05 reads: the client signature a PC insists on, the
# key/record widths a PC BTH must have, and the `wPropType` /
# `dwValueHnid` pair of one record ([MS-PST] 2.3.3.3). Every lie here is
# invisible to `pypst.ltp.heap` and `pypst.ltp.tree` and must be refused by
# `pypst.ltp.prop_context`.


def _pc_records(data: bytes, shape: dict[str, Any]) -> list[tuple[int, int, int, int]]:
    """Every root-page record as `(offset, prop_id, wPropType, dwValueHnid)`."""
    out = []
    for at in range(shape["page"], shape["page_end"], shape["stride"]):
        prop_id, prop_type, hnid = struct.unpack_from("<HHI", data, at)
        out.append((at, prop_id, prop_type, hnid))
    return out


def _heap_item(shape: dict[str, Any], hnid: int) -> tuple[int, int] | None:
    """`(offset, size)` of the heap item an HNID names, or None when it is not a resolvable HID in block 0."""
    if hnid == 0 or hnid & 0x1F or (hnid >> 16) & 0xFFFF:
        return None
    index = (hnid >> 5) & 0x7FF
    if not 0 < index <= shape["count"]:
        return None
    return shape["offsets"][index - 1], shape["sizes"][index - 1]


def pc_lies(base: bytes, rng: random.Random) -> Iterator[Mutation]:
    """The store PC's client signature, BTH widths and property records lied about, the heap left valid."""
    site = store_pc_block(base)
    data = site.data
    shape = _heap_shape(data)
    bth = shape["bth"]
    records = _pc_records(data, shape)

    def lie(name: str, edited: bytes, expect: type[PstError] | None, *, must_raise: bool = True) -> Mutation:
        return Mutation(f"pc_lies:{name}", rewrite_data_block(base, site, edited), expect, must_raise=must_raise)

    # A signature the heap accepts and a PC does not: a TC's heap is a heap.
    yield lie("bClientSig=bTypeTC", set_u8(data, 3, CLIENT_SIG_TC), PstFormatError)
    # Widths the BTH accepts (cbKey in KEY_SIZES, cbEnt in 1..=32, and the
    # page still a whole number of 8-byte records) but a PC record is not.
    widened = set_u8(set_u8(data, bth + 1, 4), bth + 2, 4)
    yield lie("bth.cbKey=4_cbEnt=4", widened, PstFormatError)

    # One record's wPropType, for the three shapes of "not a type this port reads".
    at = records[0][0]
    yield lie("record.wPropType=0x0000", set_u16(data, at + 2, 0x0000), PstUnsupportedError)
    yield lie("record.wPropType=0x0009", set_u16(data, at + 2, 0x0009), PstUnsupportedError)
    yield lie("record.wPropType=0x1234", set_u16(data, at + 2, 0x1234), PstUnsupportedError)

    # Two leaves with the same key: upstream's BTreeMap keeps the last, this port refuses.
    if len(records) > 1:
        yield lie("record.duplicate_prop_id", set_u16(data, records[1][0], records[0][1]), PstFormatError)

    # A heap item whose length no fixed-size type can be, retyped to each of
    # them: the 16-byte Guid, the 8-byte Integer64, and PtypObject (the
    # documented divergence — upstream cannot read it at all).
    odd_sized = next(
        (r for r in records if (item := _heap_item(shape, r[3])) is not None and item[1] not in (8, 16)),
        None,
    )
    if odd_sized is not None:
        at, _prop_id, _prop_type, hnid = odd_sized
        item_at, item_size = _heap_item(shape, hnid)
        yield lie("record.type=Guid_over_wrong_length", set_u16(data, at + 2, 0x0048), PstFormatError)
        yield lie("record.type=Integer64_over_wrong_length", set_u16(data, at + 2, 0x0014), PstFormatError)
        yield lie("record.type=Object_over_wrong_length", set_u16(data, at + 2, 0x000D), PstFormatError)
        # An 8/16-byte scalar is always a HID ([MS-PST] 2.3.3.3); type bits
        # on one are read past by upstream and refused here.
        yield lie("record.type=Guid_hnid_type_bits", set_u16(set_u32(data, at + 4, 0x4000_0001), at + 2, 0x0048), PstFormatError)
        # A count-prefixed multi-value claiming 4 billion items.
        if item_size >= 4:
            bomb = set_u16(data, at + 2, 0x101F)
            bomb = set_u32(bomb, item_at, 0xFFFF_FFFF)
            yield lie("record.type=MultipleUnicode_count=0xFFFFFFFF", bomb, PstLimitError)
        # An HNID of 0 on a variable-size type is upstream's Null, not an
        # error: the reader must return, not refuse (module docstring).
        yield lie("record.hnid=0_is_null", set_u32(data, at + 4, 0), None, must_raise=False)

    # An odd-length PtypUnicode value: the item's end offset pulled back one
    # byte, which leaves both spans non-empty and the heap valid.
    unicode_rec = next(
        (r for r in records if r[2] == 0x001F and (item := _heap_item(shape, r[3])) is not None and item[1] > 1),
        None,
    )
    if unicode_rec is not None:
        index = (unicode_rec[3] >> 5) & 0x7FF
        if index < shape["count"] and shape["sizes"][index] >= 2:
            yield lie(
                "record.unicode_value_odd_length",
                set_u16(data, shape["rgib"] + 2 * index, shape["offsets"][index] - 1),
                PstFormatError,
            )

    # PtypBoolean inline: P22 takes the spec's strict reading (0 or 1) where
    # upstream's PC arm is `value & 0xFF != 0`.
    boolean = next((r for r in records if r[2] == 0x000B), None)
    if boolean is not None:
        yield lie("record.boolean=0x02", set_u32(data, boolean[0] + 4, 0x02), PstFormatError)


# --- tc_lies: the root folder's hierarchy table, lied about in place ---------------
#
# The third structure built on a heap, after the BTH (`heap_lies`) and the
# PC (`pc_lies`): a table context ([MS-PST] 2.3.4). Every store has one at
# NID 0x12D — the root folder's hierarchy table — and in every base pinned
# here it is a single data block, so the lies are rewrites of that block.
# What they break is what P06 reads and P04 cannot see: the TCINFO's
# signature, its four rgib offsets, its hidRowIndex and hnidRows, one
# TCOLDESC, the row index's key/entry widths, a row index entry that names
# a row the matrix does not have, and one row's existence bitmap.

NID_ROOT_HIERARCHY_TABLE = 0x12D


def _tc_shape(data: bytes) -> dict[str, Any]:
    """The offsets inside a decoded TC heap block that the lies below rewrite."""
    ib, _sig, _client, user_root, _fill = struct.unpack_from(HEAP_HEADER_FORMAT, data, 0)
    count, _free = struct.unpack_from("<HH", data, ib)
    offsets = struct.unpack_from(f"<{count + 1}H", data, ib + 4)
    sizes = tuple(b - a for a, b in itertools.pairwise(offsets))

    def item(raw_hid: int) -> tuple[int, int] | None:
        """`(offset, size)` of the heap item an HID in block 0 names, or None."""
        if raw_hid == 0 or raw_hid & 0x1F or (raw_hid >> 16) & 0xFFFF:
            return None
        index = (raw_hid >> 5) & 0x7FF
        if not 0 < index <= count:
            return None
        return offsets[index - 1], sizes[index - 1]

    root_item = item(user_root)
    if root_item is None:
        raise ValueError("the TC heap's user root is not an item of block 0; tc_lies needs one")
    tcinfo_at = root_item[0]
    rgib = struct.unpack_from("<4H", data, tcinfo_at + 2)
    row_index_hid, rows_hnid, _deprecated = struct.unpack_from("<III", data, tcinfo_at + 10)
    row_index_item = item(row_index_hid)
    if row_index_item is None:
        raise ValueError("the TC's hidRowIndex is not an item of block 0; tc_lies needs one")
    bth_at = row_index_item[0]
    bth_root = struct.unpack_from(BTH_HEADER_FORMAT, data, bth_at)[4]
    page = item(bth_root)
    matrix = item(rows_hnid)
    return {
        "ib": ib,
        "count": count,
        "rgib_at": ib + 4,
        "offsets": offsets,
        "sizes": sizes,
        "tcinfo": tcinfo_at,
        "columns": tcinfo_at + 22,
        "column_count": data[tcinfo_at + 1],
        "rgib": rgib,
        "bth": bth_at,
        "page": None if page is None else page[0],
        "page_end": None if page is None else page[0] + page[1],
        "matrix": None if matrix is None else matrix[0],
        "matrix_size": None if matrix is None else matrix[1],
    }


def _tc_opens(base: bytes) -> bool:
    """Whether the base's OWN root hierarchy table parses — pstd-inline-cid's does not.

    A lie is only evidence when the unmutated structure was readable. Over
    a base whose TC this port already refuses (pstd-inline-cid writes a
    five-byte existence bitmap for five columns, which upstream refuses
    too — its `read_root_folder` golden is empty with exit 1), the family
    still yields the same mutations, but with no `expect` and no
    `must_raise`: they prove nothing and must not be scored as if they did.
    """
    from pypst.errors import PstError
    from pypst.ltp.table_context import TableContext
    from pypst.ndb.block import BlockReader
    from pypst.ndb.btree import BlockBTree, NodeBTree
    from pypst.ndb.header import read_header
    from pypst.ndb.ids import NodeId

    f = io.BytesIO(base)
    try:
        header = read_header(f)
        bbt = BlockBTree(f, header.root.block_btree)
        entry = NodeBTree(f, header.root.node_btree).find(NodeId(NID_ROOT_HIERARCHY_TABLE))
        tc = TableContext.from_node(BlockReader(f, header, bbt), entry)
        for row in tc.rows():
            _ = row.cells
        return bool(tc.row_index)
    except PstError:
        return False


def tc_lies(base: bytes, rng: random.Random) -> Iterator[Mutation]:
    """The root hierarchy table's TCINFO, columns, row index and row matrix lied about, the heap left valid."""
    site = node_data_block(base, NID_ROOT_HIERARCHY_TABLE)
    data = site.data
    shape = _tc_shape(data)
    tc, col, bth = shape["tcinfo"], shape["columns"], shape["bth"]
    rgib = shape["rgib"]
    usable = _tc_opens(base)

    def lie(name: str, edited: bytes, expect: type[PstError] | None, *, must_raise: bool = True) -> Mutation:
        return Mutation(
            f"tc_lies:{name}",
            rewrite_data_block(base, site, edited),
            expect if usable else None,
            must_raise=must_raise and usable,
        )

    # The container: a heap the heap layer accepts and a TC does not.
    yield lie("bClientSig=bTypePC", set_u8(data, 3, CLIENT_SIG_PC), PstFormatError)
    yield lie("tcinfo.bType=bTypePC", set_u8(data, tc, CLIENT_SIG_PC), PstFormatError)

    # cCols against the rgib offsets: the existence bitmap's width is
    # `ceil(cCols / 8)` and rgib[TCI_bm] - rgib[TCI_1b] must equal it.
    yield lie("tcinfo.cCols=0", set_u8(data, tc + 1, 0), PstFormatError)
    yield lie("tcinfo.cCols=0xFF", set_u8(data, tc + 1, 0xFF), PstFormatError)

    # The four rgib end offsets, each broken the way [MS-PST] 2.3.4.1 forbids.
    yield lie("rgib[TCI_4b]_unaligned", set_u16(data, tc + 2, rgib[0] + 1), PstFormatError)
    yield lie("rgib[TCI_4b]=4_inside_row_header", set_u16(data, tc + 2, 4), PstFormatError)
    yield lie("rgib[TCI_2b]=0", set_u16(data, tc + 4, 0), PstFormatError)
    yield lie("rgib[TCI_1b]=0", set_u16(data, tc + 6, 0), PstFormatError)
    yield lie("rgib[TCI_bm]+1", set_u16(data, tc + 8, rgib[3] + 1), PstFormatError)

    # hidRowIndex and hnidRows.
    yield lie("tcinfo.hidRowIndex=0", set_u32(data, tc + 10, 0), PstFormatError)
    yield lie("tcinfo.hidRowIndex_past_cAlloc", set_u32(data, tc + 10, hid(0x7FF)), PstFormatError)
    yield lie("tcinfo.hnidRows_past_cAlloc", set_u32(data, tc + 14, hid(0x7FF)), PstFormatError)
    yield lie("tcinfo.hnidRows_subnode_absent", set_u32(data, tc + 14, 0x4000_0001), PstNotFoundError)
    # An empty matrix is legal shape-wise; the row index then names rows that
    # are not there, which `find_row` refuses. Either answer is honest.
    yield lie("tcinfo.hnidRows=0_empty_matrix", set_u32(data, tc + 14, 0), None, must_raise=False)

    # One TCOLDESC ([MS-PST] 2.3.4.2), which the heap layer never looks at.
    yield lie("column0.wPropType=0x1234", set_u16(data, col, 0x1234), PstUnsupportedError)
    yield lie("column0.wPropType=PtypNull", set_u16(data, col, 0x0001), PstFormatError)
    yield lie("column0.ibData_past_rgib", set_u16(data, col + 4, 0xFFF0), PstFormatError)
    yield lie("column0.cbData=7", set_u8(data, col + 6, 7), PstFormatError)
    yield lie("column0.iBit=0xFF", set_u8(data, col + 7, 0xFF), PstFormatError)

    # The row index BTH: a TC's is keyed by 4 bytes with 4-byte entries.
    yield lie("rowindex.bType=bTypeTC", set_u8(data, bth, CLIENT_SIG_TC), PstFormatError)
    yield lie("rowindex.cbKey=2", set_u8(data, bth + 1, 2), PstFormatError)
    yield lie("rowindex.cbEnt=2", set_u8(data, bth + 2, 2), PstFormatError)

    # A TCROWID whose dwRowIndex is past the end of the matrix.
    if shape["page"] is not None:
        yield lie("rowindex.row_past_matrix", set_u32(data, shape["page"] + 4, 0xFFFF), PstFormatError)

    # The row matrix itself. Clearing a row's existence bitmap makes every
    # column absent, which is legal; changing its dwRowID desynchronises it
    # from the index, which is a lie no reader can detect. Neither may crash.
    if shape["matrix"] is not None:
        row_width = rgib[3]
        bitmap_at = shape["matrix"] + rgib[2]
        bitmap_len = row_width - rgib[2]
        if bitmap_len > 0 and row_width <= shape["matrix_size"]:
            yield lie(
                "row0.existence_bitmap=0",
                set_bytes(data, bitmap_at, bytes(bitmap_len)),
                None,
                must_raise=False,
            )
            yield lie("row0.dwRowID=0xFFFFFFFF", set_u32(data, shape["matrix"], 0xFFFFFFFF), None, must_raise=False)
# --- store_lies: the five message-store properties the P07 accessors read by name ----
#
# `pc_lies` breaks what a property context reads; these break what the
# MESSAGE STORE reads out of one that is perfectly valid. Every lie here is
# invisible to `pypst.ltp.prop_context` — the record decodes, the value
# decodes — and must be refused by `pypst.messaging.store`. Two of them
# must NOT be refused: an absent `PidTagIpmWastebasketEntryId` or
# `PidTagFinderEntryId` is tolerated on purpose (P07's decision, recorded in
# that module's docstring and pinned here so that "fixing" it back is red).

PID_TAG_RECORD_KEY = 0x0FF9
PID_TAG_DISPLAY_NAME = 0x3001
PID_TAG_IPM_SUB_TREE_ENTRY_ID = 0x35E0
PID_TAG_IPM_WASTEBASKET_ENTRY_ID = 0x35E3
PID_TAG_FINDER_ENTRY_ID = 0x35E7
ENTRY_ID_SIZE = 24


def _record_by_id(records: Sequence[tuple[int, int, int, int]], prop_id: int) -> tuple[int, int, int, int] | None:
    """The `(offset, prop_id, wPropType, dwValueHnid)` of one property, or None when the PC has no such record."""
    return next((r for r in records if r[1] == prop_id), None)


def _can_shrink(shape: dict[str, Any], hid_index: int) -> bool:
    """True when item `hid_index` (1-based) has a byte to spare and its end offset is in the page map."""
    return 0 < hid_index <= shape["count"] and shape["sizes"][hid_index - 1] > 1


def _shrink_item(data: bytes, shape: dict[str, Any], hid_index: int) -> bytes:
    """Pull the END of heap item `hid_index` (1-based) back one byte: the item shortens, the heap stays valid."""
    return set_u16(data, shape["rgib"] + 2 * hid_index, shape["offsets"][hid_index] - 1)


def _hid_index(hnid: int) -> int:
    return (hnid >> 5) & 0x7FF


def store_lies(base: bytes, rng: random.Random) -> Iterator[Mutation]:
    """The message store's own properties: renamed, retyped, and the wrong length."""
    site = store_pc_block(base)
    data = site.data
    shape = _heap_shape(data)
    records = _pc_records(data, shape)
    held = {r[1] for r in records}

    def lie(name: str, edited: bytes, expect: type[PstError] | None, *, must_raise: bool = True) -> Mutation:
        return Mutation(f"store_lies:{name}", rewrite_data_block(base, site, edited), expect, must_raise=must_raise)

    # Each by-name property renamed one id up, which is "absent" as far as
    # the store is concerned. The last two are the tolerated absences.
    for prop_id, what, expect, must_raise in (
        (PID_TAG_RECORD_KEY, "record_key", PstFormatError, True),
        (PID_TAG_DISPLAY_NAME, "display_name", PstFormatError, True),
        (PID_TAG_IPM_SUB_TREE_ENTRY_ID, "ipm_subtree", PstFormatError, True),
        (PID_TAG_IPM_WASTEBASKET_ENTRY_ID, "wastebasket_is_None", None, False),
        (PID_TAG_FINDER_ENTRY_ID, "finder_is_None", None, False),
    ):
        record = _record_by_id(records, prop_id)
        if record is None or prop_id + 1 in held:
            continue
        yield lie(f"0x{prop_id:04X}_absent_{what}", set_u16(data, record[0], prop_id + 1), expect, must_raise=must_raise)

    display = _record_by_id(records, PID_TAG_DISPLAY_NAME)
    if display is not None:
        # A display name that is not a string: upstream's `invalid` arm.
        yield lie("0x3001_type=Binary", set_u16(data, display[0] + 2, 0x0102), PstFormatError)

    key = _record_by_id(records, PID_TAG_RECORD_KEY)
    if key is not None:
        # An inline 4-byte type where the store wants 16 bytes of Binary.
        yield lie("0x0FF9_type=Integer32", set_u16(data, key[0] + 2, 0x0003), PstFormatError)
        if _heap_item(shape, key[3]) is not None and _can_shrink(shape, _hid_index(key[3])):
            yield lie("0x0FF9_15_bytes", _shrink_item(data, shape, _hid_index(key[3])), PstFormatError)

    ipm = _record_by_id(records, PID_TAG_IPM_SUB_TREE_ENTRY_ID)
    if ipm is not None:
        yield lie("0x35E0_type=Unicode", set_u16(data, ipm[0] + 2, 0x001F), PstFormatError)
        item = _heap_item(shape, ipm[3])
        if item is not None:
            # rgbFlags must be zero ([MS-PST] 2.4.3.2), and the id is 24 bytes.
            yield lie("0x35E0_rgbFlags=1", set_u32(data, item[0], 1), PstFormatError)
            if item[1] == ENTRY_ID_SIZE and _can_shrink(shape, _hid_index(ipm[3])):
                yield lie("0x35E0_23_bytes", _shrink_item(data, shape, _hid_index(ipm[3])), PstFormatError)


# --- named_prop_lies: the name-to-id map's four streams (NID 0x61) -------------------
#
# The same technique one node over. The heap of NID 0x61 is a single data
# block in every Unicode fixture, so its PC records can be rewritten in
# place; the stream VALUES are heap items on the small stores and sub-nodes
# on the large ones, so every lie that edits a stream's bytes is emitted
# only when that stream is a heap item here.

PID_TAG_NAMEID_BUCKET_COUNT = 0x0001
PID_TAG_NAMEID_STREAM_GUID = 0x0002
PID_TAG_NAMEID_STREAM_ENTRY = 0x0003
PID_TAG_NAMEID_STREAM_STRING = 0x0004
NAME_ID_SIZE = 8


def named_prop_shape(base: bytes) -> dict[str, Any]:
    """What the base's named property map holds, read with the landed reader — so the lies below can be honest."""
    from pypst.messaging.store import Store

    with Store(io.BytesIO(base)) as store:
        named = store.named_properties
        strings = [e for e in named.entries if e.is_string]
        return {
            "count": len(named.entries),
            "has_string": bool(strings),
            "first_string_offset": strings[0].name_id if strings else None,
            "has_buckets": any(prop_id >= 0x1000 for prop_id in named.properties.records),
        }


def named_prop_lies(base: bytes, rng: random.Random) -> Iterator[Mutation]:
    """The name-to-id map's bucket count and its three streams, lied about in the 0x61 heap."""
    site = node_pc_block(base, NID_NAME_TO_ID_MAP)
    data = site.data
    shape = _heap_shape(data)
    records = _pc_records(data, shape)
    held = {r[1] for r in records}
    known = named_prop_shape(base)

    def lie(name: str, edited: bytes, expect: type[PstError] | None, *, must_raise: bool = True) -> Mutation:
        return Mutation(f"named_prop_lies:{name}", rewrite_data_block(base, site, edited), expect, must_raise=must_raise)

    bucket = _record_by_id(records, PID_TAG_NAMEID_BUCKET_COUNT)
    if bucket is not None:
        if 0x0005 not in held:
            yield lie("bucket_count_absent", set_u16(data, bucket[0], 0x0005), PstFormatError)
        yield lie("bucket_count_type=Unicode", set_u16(data, bucket[0] + 2, 0x001F), PstFormatError)
        # Upstream computes `hash_value % bucket_count`; zero is a division by zero there.
        yield lie("bucket_count=0", set_u32(data, bucket[0] + 4, 0), PstFormatError)
        # `0x1000 + count` must stay a u16 (upstream's own guard).
        yield lie("bucket_count=0xF000", set_u32(data, bucket[0] + 4, 0xF000), PstFormatError)
        if known["has_buckets"]:
            # A count that does not describe the buckets the map actually has.
            yield lie("bucket_count=1_below_its_buckets", set_u32(data, bucket[0] + 4, 1), PstFormatError)

    for prop_id, what, present in (
        (PID_TAG_NAMEID_STREAM_GUID, "guid_stream", True),
        (PID_TAG_NAMEID_STREAM_ENTRY, "entry_stream", True),
        (PID_TAG_NAMEID_STREAM_STRING, "string_stream", known["has_string"]),
    ):
        record = _record_by_id(records, prop_id)
        if record is None or not present or prop_id + 0x10 in held:
            continue
        yield lie(f"{what}_absent", set_u16(data, record[0], prop_id + 0x10), PstFormatError)

    entry_stream = _record_by_id(records, PID_TAG_NAMEID_STREAM_ENTRY)
    if entry_stream is not None:
        yield lie("entry_stream_type=Integer32", set_u16(data, entry_stream[0] + 2, 0x0003), PstFormatError)
        item = _heap_item(shape, entry_stream[3])
        if item is not None:
            at, size = item
            if _can_shrink(shape, _hid_index(entry_stream[3])):
                # Not a whole number of NAMEIDs: upstream drops the tail silently.
                yield lie("entry_stream_ragged", _shrink_item(data, shape, _hid_index(entry_stream[3])), PstFormatError)
            if size >= NAME_ID_SIZE:
                yield lie("entry.wPropIdx=0x8000", set_u16(data, at + 6, 0x8000), PstFormatError)
                yield lie("entry.wGuid_index_past_the_stream", set_u16(data, at + 4, 0xFFFE), PstFormatError)
                (guid_field,) = struct.unpack_from("<H", data, at + 4)
                as_string = set_u32(set_u16(data, at + 4, guid_field | 0x0001), at, 0xFFFFFFF0)
                yield lie("entry.string_offset_past_the_stream", as_string, PstFormatError)
            if size >= 2 * NAME_ID_SIZE:
                (first,) = struct.unpack_from("<H", data, at + 6)
                yield lie("entry.duplicate_wPropIdx", set_u16(data, at + NAME_ID_SIZE + 6, first), PstFormatError)

    guid_stream = _record_by_id(records, PID_TAG_NAMEID_STREAM_GUID)
    if guid_stream is not None and _heap_item(shape, guid_stream[3]) is not None and _can_shrink(shape, _hid_index(guid_stream[3])):
        yield lie("guid_stream_ragged", _shrink_item(data, shape, _hid_index(guid_stream[3])), PstFormatError)

    string_stream = _record_by_id(records, PID_TAG_NAMEID_STREAM_STRING)
    offset = known["first_string_offset"]
    if string_stream is not None and offset is not None:
        item = _heap_item(shape, string_stream[3])
        if item is not None and offset + 4 <= item[1]:
            (length,) = struct.unpack_from("<I", data, item[0] + offset)
            yield lie("string.odd_length", set_u32(data, item[0] + offset, length | 1), PstFormatError)


FAMILIES: tuple[Family, ...] = (
    truncations,
    bit_flips,
    field_lies,
    pointer_cycles,
    depth_bombs,
    future_versions,
    zero_files,
    magic_only,
    heap_lies,
    pc_lies,
    tc_lies,
    store_lies,
    named_prop_lies,
)


def family_names() -> list[str]:
    return [family.__name__ for family in FAMILIES]


def family_rng(seed: int, family: Family) -> random.Random:
    """The generator a family draws from: the seed and the family's name, so families are independent."""
    return random.Random(f"{seed}:{family.__name__}")


def mutations(store_bytes: bytes, *, seed: int, families: tuple[Family, ...] = FAMILIES) -> Iterator[Mutation]:
    """Every mutation of every family over `store_bytes` (a Unicode store), deterministic for `seed`.

    Lazy on purpose: a 265 KB base times several hundred mutations is not a
    list anyone wants in memory. Names are unique across families.
    """
    check_unicode_base(store_bytes)
    for family in families:
        yield from family(store_bytes, family_rng(seed, family))


def mutation(store_bytes: bytes, *, seed: int, name: str) -> Mutation:
    """One mutation by name — to reproduce a sweep failure in isolation."""
    for m in mutations(store_bytes, seed=seed):
        if m.name == name:
            return m
    raise KeyError(name)
