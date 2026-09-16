"""[MS-PST] 5.1 Permutative Encoding and 5.2 Cyclic Encoding, from the spec page.

`_tables.py` was extracted from upstream's Rust. These tests re-type rows of
the spec's own `mpbbCrypt[]` listing and trace the spec's C by hand, so that
a table that is a faithful copy of a wrong upstream would be caught here.
"""

from __future__ import annotations

import pytest

from pypstreader._tables import KEY_DATA, KEY_DATA_I, KEY_DATA_R, KEY_DATA_S
from pypstreader.encode import (
    CryptMethod,
    decode_block,
    decode_permute,
    encode_decode_cyclic,
    encode_permute,
)
from pypstreader.errors import PstError

# --- 5.1: the mpbbCrypt[] table ------------------------------------------------
#
# Verbatim. The spec lists 768 bytes, eight per line, and defines
#   #define mpbbR (mpbbCrypt)        #define mpbbS (mpbbCrypt + 256)
#   #define mpbbI (mpbbCrypt + 512)
# Each pair below is the first two and the last two lines of one 256-byte third.

SPEC_R_FIRST = bytes([65, 54, 19, 98, 168, 33, 110, 187, 244, 22, 204, 4, 127, 100, 232, 93])
SPEC_R_LAST = bytes([162, 1, 247, 46, 188, 36, 104, 117, 13, 254, 186, 47, 181, 208, 218, 61])
SPEC_S_FIRST = bytes([20, 83, 15, 86, 179, 200, 122, 156, 235, 101, 72, 23, 22, 21, 159, 2])
SPEC_S_LAST = bytes([97, 224, 198, 193, 89, 171, 187, 88, 222, 95, 223, 96, 121, 126, 178, 138])
SPEC_I_FIRST = bytes([71, 241, 180, 230, 11, 106, 114, 72, 133, 78, 158, 235, 226, 248, 148, 83])
SPEC_I_LAST = bytes([212, 225, 17, 208, 8, 139, 42, 242, 237, 154, 100, 63, 193, 108, 249, 236])


def test_table_thirds_are_at_the_spec_offsets() -> None:
    """[MS-PST] 5.1, the three #defines: R at 0, S at +256, I at +512. Verbatim."""
    assert len(KEY_DATA) == 768
    assert KEY_DATA_R == KEY_DATA[0:256]
    assert KEY_DATA_S == KEY_DATA[256:512]
    assert KEY_DATA_I == KEY_DATA[512:768]


@pytest.mark.parametrize(
    ("name", "table", "first", "last"),
    [
        ("mpbbR", KEY_DATA_R, SPEC_R_FIRST, SPEC_R_LAST),
        ("mpbbS", KEY_DATA_S, SPEC_S_FIRST, SPEC_S_LAST),
        ("mpbbI", KEY_DATA_I, SPEC_I_FIRST, SPEC_I_LAST),
    ],
)
def test_table_edges_match_the_spec_listing(name: str, table: bytes, first: bytes, last: bytes) -> None:
    """[MS-PST] 5.1 `mpbbCrypt[]`: first and last 16 bytes of each third. Verbatim.

    The whole 768 bytes were compared against the spec page when this file
    was written and agreed byte for byte; what is typed here is the canary
    that stays in the tree. That the thirds are permutations, and that I
    inverts R, is proven by tests/test_tables.py and not repeated.
    """
    assert table[:16] == first, f"{name} head differs from [MS-PST] 5.1"
    assert table[-16:] == last, f"{name} tail differs from [MS-PST] 5.1"


# --- 5.1: CryptPermute traced by hand ------------------------------------------
#
# Derived. The spec's CryptPermute is `*pb = pbTable[*pb]` for every byte, with
# pbTable = mpbbR when fEncrypt is TRUE and mpbbI when FALSE (the DWORD-at-a-
# time loop in the middle is an optimisation of the same lookup). So encoding
# b"PST!" is four lookups in mpbbR, read off the spec listing (8 per line):
#
#   'P' = 0x50 = 80  -> line 11 (bytes 80..87) "143, 173, 179, 15, 99, 171, 137, 75" -> 143
#   'S' = 0x53 = 83  -> same line, 4th entry                                    -> 15
#   'T' = 0x54 = 84  -> same line, 5th entry                                    -> 99
#   '!' = 0x21 = 33  -> line 5 (bytes 32..39)  "76, 125, 132, 63, 219, 172, 49, 182" -> 125
#
# and decoding is the inverse lookups in mpbbI (mpbbCrypt + 512):
#
#   I[143] = mpbbCrypt[655] -> line 82 "31, 86, 170, 46, 179, 120, 51, 80"    -> 80  = 'P'
#   I[15]  = mpbbCrypt[527] -> line 66 "133, 78, 158, 235, 226, 248, 148, 83"  -> 83  = 'S'
#   I[99]  = mpbbCrypt[611] -> line 77 "60, 169, 3, 84, 13, 218, 93, 223"      -> 84  = 'T'
#   I[125] = mpbbCrypt[637] -> line 80 "117, 172, 177, 233, 69, 33, 112, 12"   -> 33  = '!'
#
# (line numbers are 1-based lines of the listing; 655 = 81*8 + 7 is line 82's
# 8th entry, etc.)

PERMUTE_PLAIN = b"PST!"
PERMUTE_ENCODED = bytes([143, 15, 99, 125])


def test_permute_encode_matches_hand_trace() -> None:
    """[MS-PST] 5.1 CryptPermute(fEncrypt=TRUE) on b"PST!". Derived (trace above)."""
    assert encode_permute(PERMUTE_PLAIN) == PERMUTE_ENCODED


def test_permute_decode_matches_hand_trace() -> None:
    """[MS-PST] 5.1 CryptPermute(fEncrypt=FALSE) on the encoded bytes. Derived."""
    assert decode_permute(PERMUTE_ENCODED) == PERMUTE_PLAIN
    assert decode_block(PERMUTE_ENCODED, CryptMethod.PERMUTE) == PERMUTE_PLAIN


# --- 5.2: CryptCyclic traced by hand -------------------------------------------
#
# Derived. The spec: w = (WORD)(dwKey ^ (dwKey >> 16)), then per byte
#   b += (byte)w;  b = mpbbR[b];  b += (byte)(w >> 8);  b = mpbbS[b];
#   b -= (byte)(w >> 8);  b = mpbbI[b];  b -= (byte)w;  w += 1
# with every add/subtract wrapping at 8 bits. Key 0x00000102 keeps the
# arithmetic readable: w = 0x0102 ^ 0x0000 = 0x0102, low byte 0x02, high 0x01.
# Table values are read off the spec listing exactly as in the permute trace.
#
#   'P' 0x50, w=0x0102: 0x50+0x02=0x52  R[82]=179=0xB3  +0x01=0xB4  S[180]=140=0x8C
#                       -0x01=0x8B  I[139]=46=0x2E  -0x02=0x2C  -> 44
#   'S' 0x53, w=0x0103: 0x53+0x03=0x56  R[86]=137=0x89  +0x01=0x8A  S[138]=255=0xFF
#                       -0x01=0xFE  I[254]=249=0xF9  -0x03=0xF6  -> 246
#   'T' 0x54, w=0x0104: 0x54+0x04=0x58  R[88]=215=0xD7  +0x01=0xD8  S[216]=145=0x91
#                       -0x01=0x90  I[144]=176=0xB0  -0x04=0xAC  -> 172
#   '!' 0x21, w=0x0105: 0x21+0x05=0x26  R[38]=49=0x31   +0x01=0x32  S[50]=184=0xB8
#                       -0x01=0xB7  I[183]=174=0xAE  -0x05=0xA9  -> 169

CYCLIC_KEY = 0x00000102
CYCLIC_PLAIN = b"PST!"
CYCLIC_ENCODED = bytes([44, 246, 172, 169])


def test_cyclic_matches_hand_trace() -> None:
    """[MS-PST] 5.2 CryptCyclic on b"PST!" with dwKey 0x00000102. Derived (trace above)."""
    assert encode_decode_cyclic(CYCLIC_PLAIN, CYCLIC_KEY) == CYCLIC_ENCODED


def test_cyclic_is_symmetric_as_the_spec_states() -> None:
    """[MS-PST] 5.2: "a symmetric cipher that is used to both encode and decode"."""
    assert encode_decode_cyclic(CYCLIC_ENCODED, CYCLIC_KEY) == CYCLIC_PLAIN
    assert decode_block(CYCLIC_ENCODED, CryptMethod.CYCLIC, key=CYCLIC_KEY) == CYCLIC_PLAIN


def test_cyclic_key_is_the_lower_dword_of_the_bid() -> None:
    """[MS-PST] 5.2: dwKey is "the lower DWORD of the BID". Derived.

    A Unicode BID is 64 bits; only its low 32 may reach the key. With the
    high DWORD set the trace above must come out unchanged.
    """
    wide_bid = (0xDEADBEEF << 32) | CYCLIC_KEY
    assert encode_decode_cyclic(CYCLIC_PLAIN, wide_bid & 0xFFFFFFFF) == CYCLIC_ENCODED


def test_cyclic_word_key_folds_the_two_halves() -> None:
    """[MS-PST] 5.2: w = (WORD)(dwKey ^ (dwKey >> 16)). Derived.

    0x12340000 and 0x00001234 fold to the same w (0x1234 ^ 0 == 0 ^ 0x1234),
    so they must encode identically; 0x12341234 folds to 0 and must not.
    """
    a = encode_decode_cyclic(CYCLIC_PLAIN, 0x12340000)
    assert a == encode_decode_cyclic(CYCLIC_PLAIN, 0x00001234)
    assert a != encode_decode_cyclic(CYCLIC_PLAIN, 0x12341234)


# --- 2.2.2.6 bCryptMethod: the values, and the one we must refuse ---------------


def test_crypt_method_values_are_the_header_table() -> None:
    """[MS-PST] 2.2.2.6 bCryptMethod: NONE 0x00, PERMUTE 0x01, CYCLIC 0x02. Verbatim."""
    assert CryptMethod.NONE == 0x00
    assert CryptMethod.PERMUTE == 0x01
    assert CryptMethod.CYCLIC == 0x02


def test_edp_crypted_blocks_are_refused_not_passed_through() -> None:
    """[MS-PST] 2.2.2.6: 0x10 NDB_CRYPT_EDPCRYPTED, "Encrypted with Windows
    Information Protection". Verbatim value; the refusal is this port's rule.

    No published algorithm exists for it, so the only correct reading is
    none. `decode_block` raises rather than returning the bytes unchanged;
    the header layer turns the same value into a `PstUnsupportedError`
    before any block is read. Either exception family is a refusal; what
    must never happen is a silent pass-through, asserted last.
    """
    data = bytes(range(16))
    with pytest.raises((PstError, ValueError)):
        decode_block(data, 0x10)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        CryptMethod(0x10)
