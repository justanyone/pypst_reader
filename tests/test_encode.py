"""Block encodings, against upstream's own test vectors.

`SAMPLE` and `KEY` are lifted from the `#[cfg(test)]` blocks in
crates/pst/src/encode/{permute,cyclic}.rs so that a divergence shows up as a
failure here rather than as unreadable mail four layers up.
"""

from __future__ import annotations

import os

import pytest

from pypst.encode import (
    CryptMethod,
    decode_block,
    decode_permute,
    encode_decode_cyclic,
    encode_permute,
)

SAMPLE = b"Hello, World!"
KEY = 0x12345678


def test_permute_round_trips() -> None:
    assert decode_permute(encode_permute(SAMPLE)) == SAMPLE


def test_permute_actually_changes_the_data() -> None:
    """Upstream's `test_encode_block` assertion — a no-op table would pass
    the round-trip test and fail every real file."""
    assert encode_permute(SAMPLE) != SAMPLE


def test_permute_round_trips_over_random_buffers() -> None:
    for size in (0, 1, 255, 256, 257, 4096):
        data = os.urandom(size)
        assert decode_permute(encode_permute(data)) == data


def test_cyclic_is_its_own_inverse() -> None:
    """Upstream's `test_decode_block`: applying it twice restores the input."""
    once = encode_decode_cyclic(SAMPLE, KEY)
    assert encode_decode_cyclic(once, KEY) == SAMPLE


def test_cyclic_actually_changes_the_data() -> None:
    assert encode_decode_cyclic(SAMPLE, KEY) != SAMPLE


def test_cyclic_key_is_folded_to_16_bits() -> None:
    """`key ^ (key >> 16)` collapses distinct 32-bit keys onto one 16-bit key.

    0x00001234 folds to 0x1234, and so does 0x12340000 (0x12340000 ^ 0x1234
    keeps 0x1234 in the low half). Two genuinely different 32-bit keys, one
    output — which is the property, and a port that dropped the fold would
    pass every round-trip test and fail this one.
    """
    assert encode_decode_cyclic(SAMPLE, 0x0000_1234) == encode_decode_cyclic(
        SAMPLE, 0x1234_0000
    )


def test_cyclic_differs_between_keys() -> None:
    assert encode_decode_cyclic(SAMPLE, 1) != encode_decode_cyclic(SAMPLE, 2)


def test_decode_block_dispatches_on_method() -> None:
    assert decode_block(SAMPLE, CryptMethod.NONE) == SAMPLE
    assert decode_block(encode_permute(SAMPLE), CryptMethod.PERMUTE) == SAMPLE
    assert (
        decode_block(encode_decode_cyclic(SAMPLE, KEY), CryptMethod.CYCLIC, KEY) == SAMPLE
    )


def test_unknown_method_refuses_rather_than_passing_bytes_through() -> None:
    """Fail-closed: a store declaring an encoding we do not know must NOT be
    read as plaintext. Plausible garbage is worse than a refusal."""
    with pytest.raises(ValueError):
        decode_block(SAMPLE, 0x7F)  # type: ignore[arg-type]


def test_negative_key_is_refused() -> None:
    with pytest.raises(ValueError):
        encode_decode_cyclic(SAMPLE, -1)
