"""The block signature — the 16-bit check stored in every block trailer.

Ported from: crates/pst/src/block_sig.rs (32 lines)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 5.5 Block Signature

A block's trailer ([MS-PST] 2.2.2.8.1) records a signature derived from the
block's byte offset and its block id. It is not a checksum of the data (that
is the CRC, `pypst.crc`); it is a cheap check that the block sitting at this
offset is the block the B-tree said would be here — a misdirected read is
caught before its bytes are trusted.

Upstream's signature takes two `u32`s; the callers hand it a 64-bit byte
index and a 64-bit block id truncated with `as u32`. Python ints do not
truncate on their own, so the masks are applied here, at the boundary, where
a reader of the call site can see that the wide values were meant to lose
their high halves. The input masks are, strictly, redundant: the final
16-bit fold only ever sees bits 0-31 of the XOR, so bits above 31 could not
reach the result anyway. They stay because they are the visible record of
the `as u32` that upstream's call sites perform, and tests/test_block_sig.py
pins the behaviour either way.
"""

from __future__ import annotations

_U32 = 0xFFFFFFFF
_U16 = 0xFFFF


def compute_sig(index: int, block_id: int) -> int:
    """The signature of the block at byte offset `index` with id `block_id`.

    Both inputs are taken modulo 2**32, as upstream's `as u32` does; the
    result is the XOR of the two 16-bit halves of their XOR, and so fits in
    16 bits.
    """
    value = (index & _U32) ^ (block_id & _U32)
    return ((value >> 16) ^ value) & _U16
