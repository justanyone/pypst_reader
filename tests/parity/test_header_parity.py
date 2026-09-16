"""Twin of upstream's header test (T0, docs/TEST-PLAN.md)."""

from __future__ import annotations

from pypst.ndb.header import HEADER_MAGIC, HEADER_MAGIC_CLIENT
from tests.parity import upstream_test


@upstream_test("crates/pst/src/ndb/header.rs::test_magic_values")
def test_magic_values() -> None:
    # Derived from upstream's test_magic_values — Microsoft's MIT-licensed test code.
    assert HEADER_MAGIC == 0x4E444221
    assert HEADER_MAGIC_CLIENT == 0x4D53
    # And what the constants mean: the bytes "!BDN" and "SM" read little-endian.
    assert HEADER_MAGIC.to_bytes(4, "little") == b"!BDN"
    assert HEADER_MAGIC_CLIENT.to_bytes(2, "little") == b"SM"
