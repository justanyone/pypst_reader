"""The exception hierarchy — one place, so a caller can catch one thing.

Ported from: the `thiserror` enums spread across the upstream crate
             (`crates/pst/src/lib.rs`, `ndb/mod.rs`, `ltp/mod.rs`, …)
Upstream:    microsoft/outlook-pst-rs @ cfb721daee538acc50d2bad6faac5ce724f6037d

Rust spells a fallible read `Result<T, NdbError>` and makes the compiler
enforce the handling. Python cannot, so the discipline moves here: every
public entry point raises one of these and NOTHING else. A `struct.error`,
an `IndexError` or a `MemoryError` escaping this package is a bug in the
package, not a property of the input — because every one of those can be
provoked by a malformed file, and a caller cannot be asked to catch them.
"""

from __future__ import annotations


class PstError(Exception):
    """Base class for everything this package raises deliberately."""


class PstFormatError(PstError):
    """The bytes are not a valid PST, or not valid at the point we reached.

    Raised for a bad signature, a failed CRC, an impossible offset, a block
    that claims a size the file cannot contain. It means *this file*, not
    *this reader*.
    """


class PstUnsupportedError(PstError):
    """The file is valid but uses something this port does not implement yet.

    Kept separate from PstFormatError on purpose: "I cannot read this" and
    "this is corrupt" are different answers, and conflating them is how a
    reader ends up blaming a customer's file for its own gap.
    """


class PstLimitError(PstError):
    """A safety limit was hit before the work completed.

    Recursion depth, total allocation, item count. A malicious store can
    claim enormous structures; refusing is the correct outcome, and it must
    be distinguishable from corruption so that a legitimate large file can
    be retried with a higher limit.
    """


class PstNotFoundError(PstFormatError):
    """A B-tree lookup for a key the tree does not hold (upstream's `BTreePageNotFound`).

    A `PstFormatError`, because a store whose node points at a block the
    block B-tree does not list is corrupt by any reading — but its own
    class, because a caller probing for an optional node (a folder's
    contents table, a named-property map) wants to tell "absent" from
    "the bytes are wrong" without parsing a message. Added by P02.
    """
