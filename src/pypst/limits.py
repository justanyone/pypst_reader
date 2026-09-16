"""The ceilings: every walk over attacker-controlled structure stops somewhere.

Ported from: not a port
This module is a deliberate divergence — upstream has no equivalent. Rust's
bounds checks make a runaway walk end in a survivable panic; in Python an
unbounded loop over a self-referential B-tree is a hang, and a `bytearray(n)`
for an `n` the file chose is a swap storm. Both are denial of service from a
crafted file, which is the whole threat model (CLAUDE.md § "Untrusted input").
So the limits live here, named, with the reason for each default written next
to it, and every walk that follows an offset, a count or a child pointer
checks one of them BEFORE doing the work.

**What a limit is, and is not.** A limit is a ceiling on work this reader is
willing to do, not a statement about the format. Tripping one raises
`PstLimitError`, which is deliberately NOT a `PstFormatError`: "too big for
the configured budget" and "corrupt" are different answers, and a caller
retries the first with a larger `Limits` and discards the second. The one
exception in this module is a revisited key in a `VisitedSet`, which is a
cycle — corruption by any reading — but is raised as `PstLimitError` because
that is what `docs/INTERFACES.md` promised every walk's callers, and because
the walk has by then done bounded work and must stop for the same reason a
depth trip stops it.

**Inclusive ceilings.** Every helper here treats the ceiling as the largest
value that PASSES: `check_depth(8, 8, …)` is fine and `check_depth(9, 8, …)`
raises. "MAX_" means maximum, not "first refused". The same convention holds
in `pypst.ltp.prop_type` (`count > max_items` raises), and the tests pin both
sides of every boundary.

**Where the defaults come from.** Each constant cites the [MS-PST] section,
the upstream check, or the arithmetic that bounds it. A ceiling equal to the
format's own bound still earns its place: the u32 or u16 that carries a count
can name a value the format could never fill, and the check turns that into
a refusal instead of an allocation. Where no format bound exists (embedded
message nesting, recipients) the default is a stated practical number and the
comment says so — a caller with a real store that trips one raises it via
`Limits(...)`.

**`ValueError`, once.** `Limits.__post_init__` refuses a non-positive field
with `ValueError` (and a non-int one with `TypeError`, as Python convention
has it). That is the one place in this package where either is the right
exception: the value came from the caller's code, not from a file, and it is
a programming error rather than an input property. Nothing that reads bytes
raises them; a caller never needs to catch them alongside `PstError`.
"""

from __future__ import annotations

from collections.abc import Hashable
from dataclasses import dataclass, fields

from pypst.errors import PstLimitError

# --- Depths ------------------------------------------------------------------

# [MS-PST] 2.2.2.7.7.1 BTPAGE: `cLevel` is one byte, 0 for a leaf. Upstream's
# `UnicodeBTreeEntryPage::new` (ndb/page.rs) refuses an intermediate page whose
# level is outside 1..=8, so 8 is the deepest tree the oracle will open. It is
# also far more than a real tree needs: a 496-byte page holds 20 Unicode
# NBT/BBT entries, so 8 levels index 20**8 ≈ 2.6e10 records against a 27-bit
# node index — real stores are 2 to 4 levels deep.
MAX_BTREE_DEPTH = 8

# [MS-PST] 2.2.2.8.3.2: a data tree is at most XXBLOCK (cLevel 2) → XBLOCK
# (cLevel 1) → data block (level 0). Anything deeper is not the format.
MAX_XBLOCK_DEPTH = 2

# [MS-PST] 2.2.2.8.3.3: a subnode BTree is at most SIBLOCK (cLevel 1) → SLBLOCK
# (cLevel 0). A subnode's OWN subnode tree (bidSub of an SLENTRY) is a new
# tree and a new node, and is bounded by MAX_EMBEDDED_MESSAGE_DEPTH, not here.
MAX_SUBNODE_DEPTH = 2

# [MS-PST] 2.3.2.1 BTHHEADER: `bIdxLevels` is one byte. Upstream (ltp/tree.rs)
# walks whatever it says. Arithmetic: a heap allocation is at most 3580 bytes
# ([MS-PST] 2.3.1.2) and an index record is key (≤ 16 bytes) + HID (4), so
# every index node fans out ≥ 179 ways; 179**4 ≈ 1.0e9 exceeds MAX_HEAP_ITEMS,
# so a well-formed BTH never needs more than 4 index levels. 8 is double that.
MAX_HEAP_TREE_DEPTH = 8

# No format bound: an attachment's embedded message is a subnode with its own
# subnode tree, recursively. Practical: a forwarded-forwarded-forwarded chain
# is 3–4 deep; 16 refuses only a store built to recurse.
MAX_EMBEDDED_MESSAGE_DEPTH = 16

# --- Sizes -------------------------------------------------------------------

# The largest single `bytes` a walk may assemble (one node's data, one
# property value, one decompressed RTF body). The format's own bound is the
# u32 `cbTotal` of an XBLOCK ([MS-PST] 2.2.2.8.3.2), i.e. 4 GiB; Outlook
# never writes a value near it (its default attachment cap is 20 MB, Exchange's
# largest documented is 150 MB). 2**28 leaves an order of magnitude over that.
MAX_ALLOCATION = 256 * 2**20

# Refuse to map or walk a file whose header claims an EOF beyond this.
# [MS-PST] 2.2.2.5 ROOT: `ibFileEof` is a u64 for a Unicode store, so the
# format itself bounds nothing. Outlook's own cap is the `MaxLargeFileSize`
# registry default of 51 200 MB (50 GiB); 2**36 is the next power of two above
# it. (An ANSI store is a u32, 4 GiB, and is refused elsewhere anyway.)
MAX_FILE_SIZE = 64 * 2**30

# --- Counts ------------------------------------------------------------------

# Entries in one tree, rows in one table, keys in one VisitedSet.
# [MS-PST] 2.2.2.1 NID: `nidIndex` is 27 bits (`pypst.ndb.ids.MAX_NODE_INDEX`
# is 2**27 - 1), so no tree or table can name more than 2**27 distinct nodes.
# The same number bounds the page walk from the other side: MAX_FILE_SIZE
# divided by the 512-byte page ([MS-PST] 2.2.2.7) is exactly 2**27 pages.
MAX_ITEMS = 1 << 27

# Allocations in one heap node. [MS-PST] 2.3.1.1 HID: `hidBlockIndex` is 16
# bits and `hidIndex` is 11 bits with 0 reserved, so a heap can address at
# most 65 536 blocks × 2 047 allocations.
MAX_HEAP_ITEMS = 65_536 * 2_047

# Properties in one property context. [MS-PST] 2.3.3.3: the PC is a BTH keyed
# by the u16 property id, so 65 536 keys is the most it can hold.
MAX_PROPERTY_COUNT = 1 << 16

# Rows in one recipient table. No format bound tighter than the u32 row id
# ([MS-PST] 2.3.4.3.1 TCROWID). Practical: Exchange's MaxRecipientEnvelopeLimit
# defaults to 500 and Outlook.com caps a message at 500; 2**16 is 130× that.
MAX_RECIPIENTS = 1 << 16

# Attachments on one message. Each attachment is one subnode of the message,
# and [MS-PST] 2.2.2.8.3.3 bounds a subnode tree to one SIBLOCK of SLBLOCKs:
# a block is ≤ 8 192 bytes (upstream `MAX_BLOCK_SIZE`), minus the 8-byte
# header and 16-byte trailer leaves 8 168, which holds 510 16-byte SIENTRYs or
# 340 24-byte SLENTRYs — 173 400 subnodes, so never more attachments than that.
MAX_ATTACHMENTS = 510 * 340

# Folders in a store, and messages in a store. Every folder and every message
# is a node, and the 27-bit `nidIndex` ([MS-PST] 2.2.2.1) is shared by all
# node types, so neither count can exceed 2**27. Outlook's guidance is far
# lower (100 000 items per folder before performance degrades), but that is
# advice to users, not a bound on what a store may contain.
MAX_FOLDERS = 1 << 27
MAX_MESSAGES = 1 << 27

# Elements in one multi-valued property (`pypst.ltp.prop_type.decode`'s
# `max_items` default). A counted multi-value carries a u32 `ulCount`
# ([MS-PST] 2.3.3.4.2), so the field can claim 4 G; the value must fit one
# allocation and each element costs a 4-byte offset, so MAX_ALLOCATION / 4 is
# the arithmetic bound. 1 000 000 is P22's landed default: 4 MiB of offsets,
# and no MAPI client writes a multi-value of more than a few hundred entries.
MAX_MV_ITEMS = 1_000_000


@dataclass(frozen=True, slots=True)
class Limits:
    """The caller's budget for one open store — one field per constant above.

    Frozen: a `Limits` is threaded through every reader from `open()` down,
    and a walk that could mutate it could also loosen it. Construct another
    one instead.
    """

    max_btree_depth: int = MAX_BTREE_DEPTH
    max_xblock_depth: int = MAX_XBLOCK_DEPTH
    max_subnode_depth: int = MAX_SUBNODE_DEPTH
    max_heap_tree_depth: int = MAX_HEAP_TREE_DEPTH
    max_embedded_message_depth: int = MAX_EMBEDDED_MESSAGE_DEPTH
    max_allocation: int = MAX_ALLOCATION
    max_file_size: int = MAX_FILE_SIZE
    max_items: int = MAX_ITEMS
    max_heap_items: int = MAX_HEAP_ITEMS
    max_property_count: int = MAX_PROPERTY_COUNT
    max_recipients: int = MAX_RECIPIENTS
    max_attachments: int = MAX_ATTACHMENTS
    max_folders: int = MAX_FOLDERS
    max_messages: int = MAX_MESSAGES
    max_mv_items: int = MAX_MV_ITEMS

    def __post_init__(self) -> None:
        # Caller configuration, not file input: ValueError/TypeError are right
        # here and nowhere else in the package. `bool` is an int in Python and
        # a limit of `True` is a bug, so it is refused by name.
        for field in fields(self):
            value = getattr(self, field.name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"Limits.{field.name} must be an int, not {type(value).__name__}")
            if value <= 0:
                raise ValueError(f"Limits.{field.name} must be positive, not {value}")


DEFAULT_LIMITS = Limits()


def _refuse(what: str, value: int, ceiling: int) -> PstLimitError:
    return PstLimitError(f"{what}: {value} exceeds limit {ceiling}")


def check_depth(depth: int, ceiling: int, what: str) -> None:
    """Raise `PstLimitError` if `depth > ceiling` (the ceiling itself passes)."""
    if depth > ceiling:
        raise _refuse(what, depth, ceiling)


def check_count(count: int, ceiling: int, what: str) -> None:
    """Raise `PstLimitError` if `count > ceiling` — before anything is allocated for it."""
    if count > ceiling:
        raise _refuse(what, count, ceiling)


def check_allocation(nbytes: int, ceiling: int, what: str) -> None:
    """Raise `PstLimitError` if `nbytes > ceiling` — before `bytearray(nbytes)`, never after."""
    if nbytes > ceiling:
        raise _refuse(what, nbytes, ceiling)


class VisitedSet:
    """Cycle guard for a graph walk: `add(key)` refuses a key it has seen.

    A B-tree page that names itself, an XBLOCK that lists its parent, a
    subnode whose data block is its own SIBLOCK — every one is a walk that
    never ends unless something remembers where it has been. This does, and
    it bounds its own size (`ceiling`, default `MAX_ITEMS`) so that the
    memory of the walk cannot itself be what the file exhausts.

    Keys are whatever identifies a visit uniquely — a `BlockId`, a byte
    offset, a `NodeId` — as long as they hash. One set per walk; a set
    shared across walks would call a legitimate second read a cycle.
    """

    __slots__ = ("_ceiling", "_seen", "_what")

    def __init__(self, what: str, ceiling: int = MAX_ITEMS) -> None:
        self._what = what
        self._ceiling = ceiling
        self._seen: set[Hashable] = set()

    def add(self, key: Hashable) -> None:
        """Record a visit; `PstLimitError` on a revisit or once the set is full."""
        if key in self._seen:
            raise PstLimitError(f"{self._what}: cycle at {key!r}")
        if len(self._seen) >= self._ceiling:
            raise _refuse(self._what, len(self._seen) + 1, self._ceiling)
        self._seen.add(key)

    def __contains__(self, key: object) -> bool:
        return key in self._seen

    def __len__(self) -> int:
        return len(self._seen)


__all__ = [
    "DEFAULT_LIMITS",
    "MAX_ALLOCATION",
    "MAX_ATTACHMENTS",
    "MAX_BTREE_DEPTH",
    "MAX_EMBEDDED_MESSAGE_DEPTH",
    "MAX_FILE_SIZE",
    "MAX_FOLDERS",
    "MAX_HEAP_ITEMS",
    "MAX_HEAP_TREE_DEPTH",
    "MAX_ITEMS",
    "MAX_MESSAGES",
    "MAX_MV_ITEMS",
    "MAX_PROPERTY_COUNT",
    "MAX_RECIPIENTS",
    "MAX_SUBNODE_DEPTH",
    "MAX_XBLOCK_DEPTH",
    "Limits",
    "VisitedSet",
    "check_allocation",
    "check_count",
    "check_depth",
]
