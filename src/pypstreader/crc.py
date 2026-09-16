"""MS-PST's CRC — which is plain CRC-32, and therefore one line of Python.

Ported from: crates/pst/src/crc.rs (335 lines)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 5.3 CRC Calculation

**Why this file is 20 lines and the Rust is 335.** Upstream implements the
slicing-by-8 CRC from the specification verbatim: nine 256-entry tables, an
alignment prologue, an 8-byte main loop and an epilogue. That is the right
thing to do in Rust, where the alternative is a byte-at-a-time loop.

In Python the byte-at-a-time loop is unthinkable (~100x slower than the file
read itself), and the nine tables would not help, because the loop driving
them would still be interpreted. So the port goes the other way: MS-PST's CRC
is the standard reflected CRC-32 (polynomial 0xEDB88320 — its table is byte-
for-byte `CRC_TABLE_OFFSET32` in crc.rs) computed WITHOUT the pre- and post-
inversion that zlib applies. Undo the inversion on the way in and out and
`zlib.crc32` — C, vectorised, already in every Python — computes it exactly.

This identity is not assumed. tests/test_crc.py re-derives the table from the
polynomial, checks it against the upstream constant, and then proves the zlib
form equals the naive table walk over hundreds of random (crc, data) pairs.
If upstream ever changes the polynomial, that test fails loudly.
"""

from __future__ import annotations

import zlib

_MASK = 0xFFFFFFFF


def compute_crc(crc: int, data: bytes) -> int:
    """Continue a running MS-PST CRC over `data`.

    `crc` is the running value (0 to start a fresh computation), matching
    upstream's `compute_crc(crc: u32, data: &[u8]) -> u32` signature so that
    call sites port across unchanged.
    """
    return zlib.crc32(data, (crc ^ _MASK) & _MASK) ^ _MASK
