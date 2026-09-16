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

import random
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from pypst.crc import compute_crc
from pypst.errors import PstError, PstFormatError, PstLimitError, PstUnsupportedError
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
# P04 landed? add: `heap_lies` — a BTH whose child pointer names its own
# HID (cycle), a heap index past the block, a freed (zero-length) item
# referenced by the user root. See `test_p04_*` in tests/test_corruption.py.

FAMILIES: tuple[Family, ...] = (
    truncations,
    bit_flips,
    field_lies,
    pointer_cycles,
    depth_bombs,
    future_versions,
    zero_files,
    magic_only,
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
