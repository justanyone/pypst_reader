"""[MS-PST] page and block trailers on real stores, read at the spec's offsets.

The strongest vector available: Outlook (and two other writers) laid these
structures down by the specification, and never saw this code. The walk here
uses NO pypstreader parsing above `compute_crc` / `compute_sig` — every offset is
summed from the field widths the spec lists, so a bug in a future B-tree
module cannot hide a bug in the primitives.

Sections and the derived offsets:

  2.2.2.6 HEADER (Unicode) ... root at 0xB4 (see test_ms_pst_layout.py)
  2.2.2.5 ROOT ............... BREFBBT at root+52 = 0xE8: bid u64, ib u64
  2.2.2.7.7.1 BTPAGE ......... 512 bytes: rgentries 488 | cEnt cEntMax cbEnt
                               cLevel at 488..491 | dwPadding 492 | trailer 496
  2.2.2.7.1 PAGETRAILER ...... ptype u8, ptypeRepeat u8, wSig u16, dwCRC u32,
                               bid u64 (16 bytes); ptypeBBT = 0x80;
                               wSig "Block or page signature (section 5.5)";
                               dwCRC "of the page data, excluding the page trailer"
  2.2.2.7.7.2 BTENTRY ........ btkey u64, BREF (bid u64, ib u64); cbEnt 24
  2.2.2.7.7.3 BBTENTRY ....... BREF, cb u16, cRef u16, dwPadding u32; cbEnt 24
  2.2.2.8.1 BLOCKTRAILER ..... cb u16, wSig u16, dwCRC u32, bid u64 (16 bytes)
  2.2.2.8.2 Anatomy .......... block size = smallest multiple of 64 holding
                               cb + 16; trailer is the LAST 16 bytes; the CRC
                               "MUST NOT include" the padding between them
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from pypstreader.block_sig import compute_sig
from pypstreader.crc import compute_crc
from tests.conftest import FIXTURES, public_fixture_ids, public_fixture_paths

PTYPE_BBT = 0x80
PAGE_SIZE = 512
PAGE_DATA = 496
TRAILER = 16
MAX_PAGES = 10_000  # a cycle in a corrupt B-tree must end the test, not the run

# Writers that ignore [MS-PST] 5.5 and store wSig = 0 on every page and block
# (spec: "For BBT, NBT, and DList pages, a page / block signature is computed").
# The store still opens in Outlook, so a reader cannot treat a zero signature
# as fatal; the test pins the deviation so it is known rather than ignored.
ZERO_SIG_WRITERS = {
    "pstd-inline-cid": "EMLtoPST (PSTD fixture)",
    "synth-basics": "EMLtoPST (our P20 fixture; the conformance patch does not yet compute wSig)",
}


@dataclass
class Tally:
    pages: int = 0
    blocks: int = 0
    sig_values: set[int] = field(default_factory=set)
    sig_ok: int = 0
    crc_ok: int = 0
    bid_ok: int = 0
    cb_ok: int = 0


def _walk_bbt(data: bytes, ib: int, bid: int, tally: Tally) -> None:
    if tally.pages >= MAX_PAGES:
        pytest.fail("BBT walk exceeded MAX_PAGES — a cycle or a corrupt fixture")
    page = data[ib : ib + PAGE_SIZE]
    assert len(page) == PAGE_SIZE, f"page at 0x{ib:X} runs past EOF"
    c_ent, _c_ent_max, cb_ent, c_level = struct.unpack_from("<BBBB", page, 488)
    ptype, ptype_repeat, w_sig, dw_crc, page_bid = struct.unpack_from("<BBHIQ", page, PAGE_DATA)
    assert ptype == ptype_repeat == PTYPE_BBT, f"page at 0x{ib:X} is not a BBT page"
    assert cb_ent == 24, "BTENTRY and BBTENTRY are both 24 bytes in a Unicode store"
    tally.pages += 1
    tally.sig_values.add(w_sig)
    tally.sig_ok += w_sig == compute_sig(ib, bid)
    tally.crc_ok += dw_crc == compute_crc(0, page[:PAGE_DATA])
    tally.bid_ok += page_bid == bid
    for i in range(c_ent):
        entry = i * cb_ent
        if c_level > 0:
            _btkey, child_bid, child_ib = struct.unpack_from("<QQQ", page, entry)
            _walk_bbt(data, child_ib, child_bid, tally)
            continue
        blk_bid, blk_ib, cb, _c_ref = struct.unpack_from("<QQHH", page, entry)
        size = -(-(cb + TRAILER) // 64) * 64
        block = data[blk_ib : blk_ib + size]
        assert len(block) == size, f"block at 0x{blk_ib:X} runs past EOF"
        t_cb, t_sig, t_crc, t_bid = struct.unpack_from("<HHIQ", block, size - TRAILER)
        tally.blocks += 1
        tally.sig_values.add(t_sig)
        tally.cb_ok += t_cb == cb
        tally.sig_ok += t_sig == compute_sig(blk_ib, blk_bid)
        tally.crc_ok += t_crc == compute_crc(0, block[:cb])
        tally.bid_ok += t_bid == blk_bid


def _unicode_stores() -> list[tuple[str, Path]]:
    out = []
    for name, path in zip(["Empty", *public_fixture_ids()], [FIXTURES / "Empty.pst", *public_fixture_paths()]):
        (w_ver,) = struct.unpack_from("<H", path.read_bytes()[:12], 10)
        if w_ver >= 23:
            out.append((name, path))
    return out


@pytest.mark.parametrize(("name", "store"), _unicode_stores(), ids=[n for n, _ in _unicode_stores()])
def test_every_bbt_page_and_block_trailer_obeys_the_spec(name: str, store: Path) -> None:
    """[MS-PST] 2.2.2.7.1, 2.2.2.8.1, 2.2.2.8.2 with 5.3 and 5.5, on real bytes. Derived.

    For every page of the block B-tree and every block it lists: the trailer's
    bid is the entry's bid, cb is the entry's cb, dwCRC is the seed-0 CRC of
    exactly cb bytes, and wSig is ComputeSig(ib, bid) — except for the writer
    named in ZERO_SIG_WRITERS, whose signatures must all be zero.
    """
    data = store.read_bytes()
    bbt_bid, bbt_ib = struct.unpack_from("<QQ", data, 0xE8)
    tally = Tally()
    _walk_bbt(data, bbt_ib, bbt_bid, tally)
    total = tally.pages + tally.blocks
    assert tally.pages >= 1 and tally.blocks >= 1, f"{name}: nothing walked"
    assert tally.bid_ok == total, f"{name}: trailer bid != B-tree bid on {total - tally.bid_ok}/{total}"
    assert tally.cb_ok == tally.blocks, f"{name}: trailer cb != BBTENTRY cb"
    assert tally.crc_ok == total, f"{name}: dwCRC mismatch on {total - tally.crc_ok}/{total}"
    if name in ZERO_SIG_WRITERS:
        assert tally.sig_values == {0}, f"{name}: {ZERO_SIG_WRITERS[name]} was pinned as writing wSig=0"
    else:
        assert tally.sig_ok == total, f"{name}: wSig mismatch on {total - tally.sig_ok}/{total}"


def test_a_crc_over_the_padding_would_fail() -> None:
    """[MS-PST] 2.2.2.8.2: "implementers MUST NOT include unused data in CRC calculations".

    Derived. On Empty.pst, find a leaf block whose cb is not a multiple of 64
    (so padding exists) and show the stored dwCRC matches the CRC of cb bytes
    and NOT the CRC of the padded data region.
    """
    data = (FIXTURES / "Empty.pst").read_bytes()
    _bbt_bid, bbt_ib = struct.unpack_from("<QQ", data, 0xE8)
    page = data[bbt_ib : bbt_ib + PAGE_SIZE]
    c_ent, _, cb_ent, c_level = struct.unpack_from("<BBBB", page, 488)
    while c_level > 0:  # descend the first BTENTRY (2.2.2.7.7.2) to a leaf page
        _btkey, _child_bid, child_ib = struct.unpack_from("<QQQ", page, 0)
        page = data[child_ib : child_ib + PAGE_SIZE]
        c_ent, _, cb_ent, c_level = struct.unpack_from("<BBBB", page, 488)
    checked = 0
    for i in range(c_ent):
        _bid, ib, cb, _ = struct.unpack_from("<QQHH", page, i * cb_ent)
        size = -(-(cb + TRAILER) // 64) * 64
        padding = size - TRAILER - cb
        if padding == 0:
            continue
        block = data[ib : ib + size]
        _, _, stored, _ = struct.unpack_from("<HHIQ", block, size - TRAILER)
        assert compute_crc(0, block[:cb]) == stored
        assert compute_crc(0, block[: cb + padding]) != stored
        checked += 1
    assert checked > 0, "no padded block found — the vector proved nothing"
