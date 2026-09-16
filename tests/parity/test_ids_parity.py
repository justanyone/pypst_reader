"""Twins of upstream's id and block-signature tests (T0, docs/TEST-PLAN.md).

Each carries the same assertions as the `#[test]` it is named for. Where
upstream matches an error variant carrying the offending value, the twin
asserts the exception type and that the value appears in its message.
"""

from __future__ import annotations

import pytest

from pypstreader.block_sig import compute_sig
from pypstreader.errors import PstFormatError
from pypstreader.ndb.ids import (
    MAX_BLOCK_INDEX,
    MAX_NODE_INDEX,
    BlockId,
    NodeId,
    NodeIdType,
)
from tests.parity import upstream_test


@upstream_test("crates/pst/src/ndb/block_id.rs::test_unicode_bid_index_overflow")
def test_unicode_bid_index_overflow() -> None:
    # Derived from upstream's test_unicode_bid_index_overflow.
    with pytest.raises(PstFormatError) as info:
        BlockId.from_parts(False, MAX_BLOCK_INDEX + 1)
    assert str(MAX_BLOCK_INDEX + 1) in str(info.value)


@upstream_test("crates/pst/src/ndb/node_id.rs::test_nid_index_overflow")
def test_nid_index_overflow() -> None:
    # Derived from upstream's test_nid_index_overflow.
    with pytest.raises(PstFormatError) as info:
        NodeId.from_parts(NodeIdType.HID, MAX_NODE_INDEX + 1)
    assert str(MAX_NODE_INDEX + 1) in str(info.value)


@upstream_test("crates/pst/src/block_sig.rs::test_compute_sig")
def test_compute_sig() -> None:
    # Derived from upstream's test_compute_sig.
    assert compute_sig(0x00000000, 0x00000000) == 0x0000
    assert compute_sig(0x00000000, 0x00000001) == 0x0001
    assert compute_sig(0x00000001, 0x00000000) == 0x0001
    assert compute_sig(0x00000001, 0x00000001) == 0x0000
    assert compute_sig(0x00000000, 0x00000002) == 0x0002
    assert compute_sig(0x00000002, 0x00000000) == 0x0002
    assert compute_sig(0x00000002, 0x00000002) == 0x0000


@upstream_test("crates/pst/src/block_sig.rs::test_overflow")
def test_overflow() -> None:
    # Derived from upstream's test_overflow.
    assert compute_sig(0x00000000, 0x00010000) == 0x0001
    assert compute_sig(0x00010000, 0x00000000) == 0x0001
    assert compute_sig(0x00010000, 0x00010000) == 0x0000
