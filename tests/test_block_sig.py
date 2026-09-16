"""The block signature: a 16-bit fold, with the masks that make it one.

Upstream's two `#[test]`s are twinned in tests/parity/. What is here is the
property they leave implicit — that the wide inputs a caller actually holds
(a 64-bit byte index, a 64-bit block id) are truncated the way Rust's
`as u32` truncates them, and that the result never leaves 16 bits.
"""

from __future__ import annotations

import random

from pypst.block_sig import compute_sig


def _reference(index: int, block_id: int) -> int:
    """The specification's arithmetic, written the slow obvious way."""
    ib = index % 2**32
    bid = block_id % 2**32
    value = ib ^ bid
    return ((value >> 16) ^ (value & 0xFFFF)) & 0xFFFF


def test_high_halves_of_wide_inputs_are_dropped() -> None:
    """A 64-bit byte index and block id contribute only their low 32 bits."""
    assert compute_sig(0x1_0000_0000, 0) == 0
    assert compute_sig(0, 0xABCD_0000_0000_0000) == 0
    assert compute_sig(0x1_0001_0000, 0) == 0x0001
    assert compute_sig(0xFFFF_FFFF_0000_0001, 0xFFFF_FFFF_0000_0000) == 0x0001


def test_result_is_the_xor_of_the_two_halves() -> None:
    assert compute_sig(0x12345678, 0) == 0x1234 ^ 0x5678
    assert compute_sig(0, 0xDEADBEEF) == 0xDEAD ^ 0xBEEF
    assert compute_sig(0x12340000, 0x00005678) == 0x1234 ^ 0x5678


def test_symmetric_in_its_arguments() -> None:
    rng = random.Random(55)
    for _ in range(200):
        a, b = rng.getrandbits(64), rng.getrandbits(64)
        assert compute_sig(a, b) == compute_sig(b, a)


def test_matches_the_reference_arithmetic_and_fits_16_bits() -> None:
    rng = random.Random(20260915)
    for _ in range(1000):
        a, b = rng.getrandbits(64), rng.getrandbits(64)
        sig = compute_sig(a, b)
        assert 0 <= sig <= 0xFFFF
        assert sig == _reference(a, b), (hex(a), hex(b))
