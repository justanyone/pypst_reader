"""The zlib shortcut really is MS-PST's CRC.

crc.py replaces 335 lines of upstream slicing-by-8 with one `zlib.crc32`
call. That is a claim about an algorithm, so it is proven three ways here
rather than asserted in a comment: the polynomial produces upstream's table,
the naive table walk matches zlib over random input, and the running-CRC form
composes the way a chunked caller will use it.
"""

from __future__ import annotations

import os
import random

from pypst.crc import compute_crc

# The first four entries of `CRC_TABLE_OFFSET32` in crates/pst/src/crc.rs.
UPSTREAM_TABLE_HEAD = (0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA)


def _standard_table() -> list[int]:
    """Rebuild the reflected CRC-32 table from polynomial 0xEDB88320."""
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        table.append(c)
    return table


def _naive_crc(crc: int, data: bytes) -> int:
    """Upstream's algorithm, transcribed byte-at-a-time from crc.rs.

    Deliberately the slow, obvious form: it is the reference, so it must be
    readable rather than fast.
    """
    table = _standard_table()
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


def test_upstream_table_is_the_standard_crc32_table() -> None:
    assert tuple(_standard_table()[:4]) == UPSTREAM_TABLE_HEAD


def test_zlib_form_matches_the_naive_walk() -> None:
    rng = random.Random(20260915)
    for _ in range(400):
        data = os.urandom(rng.randint(0, 137))
        crc = rng.getrandbits(32)
        assert compute_crc(crc, data) == _naive_crc(crc, data), (crc, data.hex())


def test_empty_input_is_the_identity() -> None:
    assert compute_crc(0, b"") == 0
    assert compute_crc(0xDEADBEEF, b"") == 0xDEADBEEF


def test_running_crc_composes_over_chunks() -> None:
    """A caller CRCs a header in pieces; the pieces must equal the whole."""
    data = os.urandom(1024)
    whole = compute_crc(0, data)
    running = 0
    for start in range(0, len(data), 97):
        running = compute_crc(running, data[start : start + 97])
    assert running == whole


def test_result_stays_in_32_bits() -> None:
    for _ in range(50):
        assert 0 <= compute_crc(random.getrandbits(32), os.urandom(64)) <= 0xFFFFFFFF
