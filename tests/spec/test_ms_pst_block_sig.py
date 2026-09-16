"""[MS-PST] 5.5 Block Signature — the spec's ComputeSig, traced by hand.

    WORD ComputeSig(IB ib, BID bid)
    {
       ib ^= bid;
       return(WORD(WORD(ib >> 16) ^ WORD(ib)));
    }

with the prose: "the DWORD XOR result between the absolute file offset of the
block and its BID", then "the XOR result between the higher and lower 16 bits
of the DWORD". Signatures on real pages and blocks are checked in
test_ms_pst_trailers.py; this file is the arithmetic alone.
"""

from __future__ import annotations

import pytest

from pypst.block_sig import compute_sig

# Derived: each row is one hand evaluation of the spec's three lines.
#
#   ib=0x5000 (the block offset [MS-PST] 2.2.2.8.2 uses), bid=0x124:
#     ib ^ bid = 0x5124;  WORD(0x5124 >> 16) = 0x0000;  WORD(0x5124) = 0x5124
#     0x0000 ^ 0x5124 = 0x5124
#
#   ib=0x12000, bid=0x30004:
#     ib ^ bid = 0x22004;  WORD(0x22004 >> 16) = 0x0002;  WORD(0x22004) = 0x2004
#     0x0002 ^ 0x2004 = 0x2006
#
#   ib=0x0001_0000_5000, bid=0x0002_0000_0124 (64-bit Unicode values):
#     ib ^ bid = 0x0003_0000_5124;  WORD(... >> 16) = WORD(0x0003_0000) = 0x0000
#     WORD(0x0003_0000_5124) = 0x5124;  0x0000 ^ 0x5124 = 0x5124
#     — bits 32 and up never reach a WORD, which is why upstream's `as u32`
#       truncation of the 64-bit inputs is harmless.
HAND_TRACES = [
    (0x5000, 0x124, 0x5124),
    (0x12000, 0x30004, 0x2006),
    (0x0001_0000_5000, 0x0002_0000_0124, 0x5124),
]


@pytest.mark.parametrize(("ib", "bid", "expected"), HAND_TRACES)
def test_compute_sig_matches_the_hand_trace(ib: int, bid: int, expected: int) -> None:
    """[MS-PST] 5.5 ComputeSig(ib, bid). Derived (traces above)."""
    assert compute_sig(ib, bid) == expected


def test_sig_is_a_word() -> None:
    """[MS-PST] 5.5 returns a WORD: 16 bits, whatever the inputs. Derived."""
    assert compute_sig(0xFFFF_FFFF_FFFF_FFFF, 0) == 0x0000  # 0xFFFF ^ 0xFFFF
    assert compute_sig(0xFFFF_FFFF, 0xFFFF_0000) == 0xFFFF  # 0x0000 ^ 0xFFFF
