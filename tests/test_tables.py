"""The key tables are structurally sound — proven here, not trusted.

If any of these fail, nothing else in the port is worth debugging: every
decoded block would be wrong in a way that looks like a structural bug.
"""

from __future__ import annotations

from pypstreader._tables import KEY_DATA, KEY_DATA_I, KEY_DATA_R, KEY_DATA_S
from tests.parity import upstream_test


# Twin of upstream's encode/mod.rs `test_key_data` — derived from Microsoft's MIT-licensed test code.
@upstream_test("crates/pst/src/encode/mod.rs::test_key_data")
def test_key_data_is_768_bytes() -> None:
    """Upstream asserts each of R, S, I is 256 entries; the 768 total is ours."""
    assert len(KEY_DATA) == 768
    assert len(KEY_DATA_R) == len(KEY_DATA_S) == len(KEY_DATA_I) == 256


def test_each_table_is_a_permutation() -> None:
    for name, table in (("R", KEY_DATA_R), ("S", KEY_DATA_S), ("I", KEY_DATA_I)):
        assert sorted(table) == list(range(256)), f"table {name} is not a permutation"


def test_i_inverts_r() -> None:
    """The property permutative DECODING rests on."""
    assert all(KEY_DATA_I[KEY_DATA_R[b]] == b for b in range(256))
    assert all(KEY_DATA_R[KEY_DATA_I[b]] == b for b in range(256))


def test_first_bytes_match_the_specification() -> None:
    """A cheap canary against a regenerated-from-the-wrong-place table."""
    assert KEY_DATA[:6] == bytes([65, 54, 19, 98, 168, 33])
