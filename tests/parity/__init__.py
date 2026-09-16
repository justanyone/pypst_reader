"""Twins of upstream's `#[test]` functions, tagged so scripts/check_upstream_parity.py can match them."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

F = TypeVar("F", bound=Callable[..., object])


def upstream_test(ref: str) -> Callable[[F], F]:
    """Tag a test as the twin of upstream's `<crate-relative path>::<fn name>`."""

    def decorate(fn: F) -> F:
        fn.__upstream_test__ = ref  # type: ignore[attr-defined]
        return fn

    return decorate
