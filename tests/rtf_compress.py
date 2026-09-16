"""Upstream's LZFu COMPRESSOR, ported so the decompressor can be tested against it.

Ported from: crates/compressed-rtf/src/lib.rs (`compress_rtf`, `encode_rtf`),
             crates/compressed-rtf/src/dictionary.rs (`TokenDictionary`)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d
Spec:        [MS-OXRTFCP] 2.3.3.2 (the run loop), 2.3.3.2.1 (finding the longest match)

This lives under tests/ and not src/ on purpose: a reader never compresses,
and the package's public surface must not grow a writer. It exists because
upstream's four `#[test]`s are two decompress vectors and two compress
vectors (parity, tests/parity/test_rtf_parity.py), and because
`decompress(compress(x)) == x` over random input is the property that finds
token-boundary and dictionary-wrap bugs that fixed vectors never reach.

The match search follows the spec's pseudocode exactly, including the part
that matters: a byte is appended to the dictionary the moment it extends the
best match so far, which is what lets a reference run past the write offset.
One Python idiom is added on top — see `_next_candidate` — that skips
positions where the first byte cannot match; it changes nothing observable
and `exhaustive=True` turns it off so a test can prove that.
"""

from __future__ import annotations

import struct

from pypst._rtf_dictionary import INITIAL_DICTIONARY
from pypst.crc import compute_crc
from pypst.rtf import DICTIONARY_SIZE, HEADER_SIZE, CompressionType

_MASK = DICTIONARY_SIZE - 1
_MAX_MATCH = 17  # a 4-bit length field plus 2


class _Dictionary:
    """The circular dictionary of [MS-OXRTFCP] 2.1.3.1.4, writer's side."""

    __slots__ = ("buffer", "end", "write")

    def __init__(self) -> None:
        self.buffer = bytearray(DICTIONARY_SIZE)
        self.buffer[: len(INITIAL_DICTIONARY)] = INITIAL_DICTIONARY
        self.write = len(INITIAL_DICTIONARY)
        self.end = len(INITIAL_DICTIONARY)

    def add(self, byte: int) -> None:
        """AddByteToDictionary in the spec's pseudocode."""
        self.buffer[self.write] = byte
        if self.end < DICTIONARY_SIZE:
            self.end += 1
        self.write = (self.write + 1) & _MASK

    def find_longest_match(self, data: bytes, cursor: int, *, exhaustive: bool = False) -> tuple[int, int]:
        """FindLongestMatch: the (offset, length) of the best match for data[cursor:].

        Length 0 means no match, and in that case the literal has already
        been added to the dictionary, as the spec requires. A length of 1 is
        reported too (the caller emits a literal for it) and that byte was
        likewise added during the scan.
        """
        final = self.write
        offset = 0 if self.end != DICTIONARY_SIZE else (self.write + 1) & _MASK
        best_offset, best_length = 0, 0
        first = data[cursor]
        while True:
            length = self._try_match(data, cursor, offset, best_length)
            if length > best_length:
                best_offset, best_length = offset, length
            offset = (offset + 1) & _MASK
            if offset == final or best_length == _MAX_MATCH:
                break
            if not exhaustive:
                candidate = self._next_candidate(first, offset, final)
                if candidate is None:
                    break
                offset = candidate
        if best_length == 0:
            self.add(data[cursor])
        return best_offset, best_length

    def _try_match(self, data: bytes, cursor: int, offset: int, best_length: int) -> int:
        """TryMatch: how many bytes of data[cursor:] match at dictionary offset."""
        max_length = min(_MAX_MATCH, len(data) - cursor)
        length = 0
        position = offset
        while length < max_length and self.buffer[position] == data[cursor + length]:
            length += 1
            if length > best_length:
                self.add(data[cursor + length - 1])
            position = (position + 1) & _MASK
        return length

    def _next_candidate(self, first: int, offset: int, final: int) -> int | None:
        """The next scan position at or after `offset` (circularly, before `final`) holding `first`.

        Equivalent to the spec's one-step advance because a TryMatch whose
        first comparison fails returns 0 and adds nothing to the dictionary,
        so skipping those positions leaves both the state and the result
        unchanged; the stop conditions are still tested after every real try.
        `bytearray.find` reads the live buffer, so bytes written by an earlier
        try in this same scan are seen exactly as the step-by-step scan sees them.
        """
        if offset < final:
            found = self.buffer.find(first, offset, final)
            return None if found < 0 else found
        found = self.buffer.find(first, offset, DICTIONARY_SIZE)
        if found >= 0:
            return found
        found = self.buffer.find(first, 0, final)
        return None if found < 0 else found


def _reference(offset: int, length_minus_2: int) -> bytes:
    """A dictionary reference as it goes on the wire: big-endian, offset << 4 | length-2."""
    return ((offset << 4) | length_minus_2).to_bytes(2, "big")


def compress_rtf(raw: bytes, *, exhaustive: bool = False) -> bytes:
    """Compress `raw` as COMPTYPE COMPRESSED, byte for byte as upstream does.

    Upstream takes a `&str` and refuses characters above 0xFF; this takes
    bytes, which is the same domain without the detour through UTF-16.
    """
    dictionary = _Dictionary()
    out = bytearray(HEADER_SIZE)  # the header is filled in last (2.3.3.2.2)
    cursor = 0
    while True:
        # One run per iteration: steps 1-9 of [MS-OXRTFCP] 2.3.3.2.
        control = 0
        tokens = bytearray()
        finished = False
        for bit in range(8):
            if cursor >= len(raw):
                # Step 8: the terminator is a reference to the write offset, length 0.
                tokens += _reference(dictionary.write, 0)
                control |= 1 << bit
                finished = True
                break
            offset, length = dictionary.find_longest_match(raw, cursor, exhaustive=exhaustive)
            if length >= 2:
                tokens += _reference(offset, length - 2)
                control |= 1 << bit
                cursor += length
            else:
                tokens.append(raw[cursor])
                cursor += 1
        out.append(control)
        out += tokens
        if finished:
            break
    struct.pack_into(
        "<IIII", out, 0, len(out) - 4, len(raw), CompressionType.COMPRESSED, compute_crc(0, out[HEADER_SIZE:])
    )
    return bytes(out)


def encode_rtf_uncompressed(raw: bytes) -> bytes:
    """Wrap `raw` as COMPTYPE UNCOMPRESSED (upstream's `encode_rtf`): CRC is zero by rule."""
    return struct.pack("<IIII", len(raw) + 12, len(raw), CompressionType.UNCOMPRESSED, 0) + raw
