"""Block encodings — permutative and cyclic.

Ported from: crates/pst/src/encode/{mod,permute,cyclic}.rs
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-PST] 5.1 Permutative Encoding, 5.2 Cyclic Encoding

A PST's data blocks may be stored obfuscated. This is NOT encryption and must
never be described as such anywhere in this project or its output: the tables
are published in the specification and the key for cyclic encoding is derived
from the block id, which is in the file. It is a speed bump against a hex
editor. Treat a decoded block as exactly as sensitive as an encoded one.

**The performance note that shaped this file.** Permutative decoding is a
256-byte substitution applied to every byte of every block — the single
hottest loop in a PST reader, and in Rust it is a three-line `for`. Python
cannot afford that loop, and does not need it: a 256-byte substitution over a
buffer is precisely `bytes.translate()`, which is C. The result is faster than
the "obvious" Rust-shaped port by two orders of magnitude and is also shorter.

Cyclic encoding gets no such reprieve — its key advances per byte, so the loop
is real. It is also rare (it appears in OST files and in PSTs configured for
it), so it stays a readable byte loop until a profile says otherwise. The
place to look first, if that day comes, is a per-key precomputed table.
"""

from __future__ import annotations

from enum import IntEnum

from pypstreader._tables import KEY_DATA_I, KEY_DATA_R, KEY_DATA_S

# `bytes.translate` wants a 256-byte table, which is exactly what these are.
_DECODE_TABLE = KEY_DATA_I
_ENCODE_TABLE = KEY_DATA_R


class CryptMethod(IntEnum):
    """How a data block's bytes are stored.

    Ported from `NdbCryptMethod` in crates/pst/src/ndb/mod.rs. Values are the
    `bCryptMethod` field of the PST header ([MS-PST] 2.2.2.6).
    """

    NONE = 0x00
    PERMUTE = 0x01
    CYCLIC = 0x02


def decode_permute(data: bytes) -> bytes:
    """Decode a permutatively-encoded block. Inverse of `encode_permute`."""
    return data.translate(_DECODE_TABLE)


def encode_permute(data: bytes) -> bytes:
    """Encode a block permutatively.

    Present because the inverse is what proves the decode: a round-trip test
    needs both directions. Nothing in the read path calls it.
    """
    return data.translate(_ENCODE_TABLE)


def encode_decode_cyclic(data: bytes, key: int) -> bytes:
    """Apply the cyclic transform, which is its own inverse.

    `key` is the low 32 bits of the block id. Upstream folds it to 16 bits
    with `key ^ (key >> 16)` and then advances it once per byte, wrapping.

    Self-inverse is a property of the algorithm, not an accident of this
    port, and tests/test_encode.py asserts it against upstream's own test
    vector (`b"Hello, World!"`, key 0x12345678).
    """
    if key < 0:
        raise ValueError("key must be a non-negative 32-bit value")
    k = (key ^ (key >> 16)) & 0xFFFF
    out = bytearray(len(data))
    r, s, i = KEY_DATA_R, KEY_DATA_S, KEY_DATA_I
    for index, byte in enumerate(data):
        low = k & 0xFF
        high = (k >> 8) & 0xFF
        b = (byte + low) & 0xFF
        b = r[b]
        b = (b + high) & 0xFF
        b = s[b]
        b = (b - high) & 0xFF
        b = i[b]
        b = (b - low) & 0xFF
        out[index] = b
        k = (k + 1) & 0xFFFF
    return bytes(out)


def decode_block(data: bytes, method: CryptMethod, key: int = 0) -> bytes:
    """Decode a data block by whichever method the header declared.

    Fail-closed on an unknown method: a store that declares an encoding this
    reader does not know is not silently read as plaintext, because the
    plausible-looking garbage that produces is worse than a refusal.
    """
    if method == CryptMethod.NONE:
        return data
    if method == CryptMethod.PERMUTE:
        return decode_permute(data)
    if method == CryptMethod.CYCLIC:
        return encode_decode_cyclic(data, key)
    raise ValueError(f"unknown crypt method: {method!r}")
