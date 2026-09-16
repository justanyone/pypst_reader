"""The ceilings, denial first: each helper refuses one over and passes at the ceiling.

`pypst.limits` is the one module whose whole job is to say no, so every test
here is a boundary: the ceiling passes (inclusive, as the module docstring
says), one over raises `PstLimitError` naming the walk, and that error is
never a `PstFormatError` — "too big" and "corrupt" must stay distinguishable
because a caller retries one and discards the other (docs/TEST-PLAN.md T6).
"""

from __future__ import annotations

import dataclasses

import pytest

from pypst import limits
from pypst.errors import PstError, PstFormatError, PstLimitError
from pypst.limits import (
    DEFAULT_LIMITS,
    MAX_ITEMS,
    MAX_MV_ITEMS,
    Limits,
    VisitedSet,
    check_allocation,
    check_count,
    check_depth,
)
from pypst.ltp import prop_type
from pypst.ndb.ids import MAX_NODE_INDEX

CHECKS = [check_depth, check_count, check_allocation]
CHECK_IDS = [fn.__name__ for fn in CHECKS]


# --- the exception family ---------------------------------------------------


def test_limit_and_format_errors_are_distinguishable() -> None:
    assert not issubclass(PstLimitError, PstFormatError)
    assert not issubclass(PstFormatError, PstLimitError)
    assert issubclass(PstLimitError, PstError)
    assert issubclass(PstFormatError, PstError)


# --- the check helpers ------------------------------------------------------


@pytest.mark.parametrize("check", CHECKS, ids=CHECK_IDS)
def test_one_over_the_ceiling_is_a_limit_error_naming_the_walk(check) -> None:
    with pytest.raises(PstLimitError) as info:
        check(9, 8, "NBT depth")
    assert str(info.value) == "NBT depth: 9 exceeds limit 8"
    assert not isinstance(info.value, PstFormatError)


@pytest.mark.parametrize("check", CHECKS, ids=CHECK_IDS)
def test_at_the_ceiling_passes(check) -> None:
    check(8, 8, "NBT depth")  # inclusive: MAX_ means maximum, not first refused


@pytest.mark.parametrize("check", CHECKS, ids=CHECK_IDS)
def test_one_under_the_ceiling_passes(check) -> None:
    check(7, 8, "NBT depth")


@pytest.mark.parametrize("check", CHECKS, ids=CHECK_IDS)
def test_zero_passes(check) -> None:
    check(0, 1, "anything")


def test_check_allocation_refuses_a_block_claiming_more_than_the_budget() -> None:
    # The motivating case: a block claiming 4 GiB inside a small file must be
    # refused before bytearray(n), and the message carries the claimed size.
    with pytest.raises(PstLimitError, match=r"data tree: 4294967295 exceeds limit"):
        check_allocation(2**32 - 1, DEFAULT_LIMITS.max_allocation, "data tree")


# --- the constants ----------------------------------------------------------


def _constants() -> dict[str, int]:
    return {name: getattr(limits, name) for name in limits.__all__ if name.startswith("MAX_")}


def test_every_constant_is_a_positive_int() -> None:
    constants = _constants()
    assert constants, "no MAX_ constants exported"
    for name, value in constants.items():
        assert type(value) is int, name
        assert value > 0, name


def test_every_limits_field_defaults_to_its_constant() -> None:
    # Introspected, so a constant added without a field (or a field whose
    # default drifted from its constant) fails here rather than going unnoticed.
    constants = _constants()
    field_names = {f.name for f in dataclasses.fields(Limits)}
    assert field_names == {name.lower() for name in constants}
    for f in dataclasses.fields(Limits):
        assert f.default == constants[f.name.upper()], f.name
        assert getattr(DEFAULT_LIMITS, f.name) == constants[f.name.upper()], f.name


def test_the_format_bounds_the_defaults_cite_are_the_ones_in_the_code() -> None:
    # The comments in limits.py derive these from other modules' facts; pin
    # the arithmetic so the comment cannot silently go stale.
    assert MAX_ITEMS == MAX_NODE_INDEX + 1  # 27-bit nidIndex
    assert MAX_ITEMS == limits.MAX_FILE_SIZE // 512  # pages in a max-size file
    assert limits.MAX_HEAP_ITEMS == (1 << 16) * ((1 << 11) - 1)  # HID: 16-bit block, 11-bit index, 0 reserved
    assert limits.MAX_ATTACHMENTS == ((8192 - 8 - 16) // 16) * ((8192 - 8 - 16) // 24)  # SIBLOCK × SLBLOCK
    assert limits.MAX_XBLOCK_DEPTH == 2 and limits.MAX_SUBNODE_DEPTH == 2  # two-level structures
    assert limits.MAX_PROPERTY_COUNT == 1 << 16  # u16 property id
    assert limits.MAX_MV_ITEMS <= limits.MAX_ALLOCATION // 4  # offsets alone must fit one allocation


def test_prop_type_default_max_items_is_the_named_constant() -> None:
    assert prop_type.DEFAULT_MAX_ITEMS is MAX_MV_ITEMS
    assert prop_type.DEFAULT_MAX_ITEMS == 1_000_000  # P22's landed default, unchanged


# --- Limits, the caller's configuration ------------------------------------


def test_limits_is_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        DEFAULT_LIMITS.max_btree_depth = 1  # type: ignore[misc]


def test_limits_is_overridable_per_field() -> None:
    custom = Limits(max_btree_depth=3)
    assert custom.max_btree_depth == 3
    assert custom.max_xblock_depth == DEFAULT_LIMITS.max_xblock_depth
    assert dataclasses.replace(DEFAULT_LIMITS, max_items=10).max_items == 10


@pytest.mark.parametrize("bad", [0, -1], ids=["zero", "negative"])
def test_limits_refuses_a_non_positive_ceiling_with_value_error(bad: int) -> None:
    # Caller configuration, not file input: ValueError (TypeError for a wrong
    # type, per Python convention), and never a PstError.
    with pytest.raises(ValueError, match="max_btree_depth must be positive"):
        Limits(max_btree_depth=bad)


@pytest.mark.parametrize("bad", [1.5, "8", None, True], ids=["float", "str", "None", "bool"])
def test_limits_refuses_a_non_int_ceiling_with_type_error(bad: object) -> None:
    with pytest.raises(TypeError, match="max_items must be an int"):
        Limits(max_items=bad)  # type: ignore[arg-type]


def test_limits_checks_every_field_not_just_the_first() -> None:
    last = dataclasses.fields(Limits)[-1].name
    with pytest.raises(ValueError, match=f"{last} must be positive"):
        Limits(**{last: 0})


# --- VisitedSet, the cycle guard -------------------------------------------


def test_visited_set_refuses_a_revisit_naming_the_key() -> None:
    seen = VisitedSet("BBT pages")
    seen.add(0x1234)
    with pytest.raises(PstLimitError, match=r"BBT pages: cycle at 4660") as info:
        seen.add(0x1234)
    assert not isinstance(info.value, PstFormatError)


def test_visited_set_accepts_distinct_keys_and_reports_membership() -> None:
    seen = VisitedSet("walk")
    for key in (1, 2, (3, 4), "five"):
        seen.add(key)
    assert len(seen) == 4
    assert (3, 4) in seen
    assert 5 not in seen


def test_visited_set_bounds_its_own_size() -> None:
    seen = VisitedSet("walk", ceiling=3)
    for key in (1, 2, 3):  # at the ceiling passes
        seen.add(key)
    with pytest.raises(PstLimitError, match=r"walk: 4 exceeds limit 3"):
        seen.add(4)
    assert 4 not in seen
    assert len(seen) == 3


def test_visited_set_defaults_to_max_items() -> None:
    assert VisitedSet("walk")._ceiling == MAX_ITEMS


def test_visited_set_reports_a_cycle_before_a_full_set() -> None:
    # A revisit is a cycle whatever the fill level; the message must say so.
    seen = VisitedSet("walk", ceiling=1)
    seen.add("a")
    with pytest.raises(PstLimitError, match="cycle at 'a'"):
        seen.add("a")
