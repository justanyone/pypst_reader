# ADR-0003: Unicode stores only; ANSI is refused, and belongs to a sibling library

- **Status:** accepted 2026-09-15, before the first NDB module
- **Relates to:** ADR-0001 (the port), row P01-HEADER (where this bites first)
- **Closes:** row P13-ANSI; opens row P27-NU

## Context

[MS-PST] defines two on-disk layouts distinguished by `wVer` in the header:
**ANSI** (`wVer` 14 or 15; 32-bit byte indices, block ids and node ids; 2 GB
ceiling; written by Outlook 97–2002) and **Unicode** (`wVer` 23, and 36/37 for
the 4 KB-page variant; 64-bit indices; written by Outlook 2003 and every
release since, and by Exchange/Purview exports).

Upstream carries both behind a `PstFile` trait with two implementations. That
axis touches ~480 sites across `ndb/` and `ltp/` — every struct that holds an
offset has two widths, every parser two format strings, every BTree page two
entry sizes. Upstream's own example binaries are not uniformly generic:
`read_btrees` panics on an ANSI store.

What we have to test against: all three private stores and 6 of the 8 public
corpus stores are Unicode. Two ANSI stores exist in the corpus (Microsoft's
pstsdk `test_ansi.pst` and `sample2.pst`).

## Decision

**`pypst` reads Unicode stores only.** A header with `wVer` 14 or 15 raises
`PstUnsupportedError` naming the version and pointing at the sibling library.
It is never parsed further, never guessed at, and never silently read with
the wrong field widths.

**ANSI support, if wanted, is a separate package — `pypst_reader_nu`** ("nu",
non-Unicode) — ported from the ANSI arms of the same upstream, against the two
ANSI corpus stores as its oracle fixtures. It is recorded as backlog row
**P27-NU** and is not started until this reader reads Unicode stores end to
end.

The two ANSI fixtures stay in the corpus for two reasons: to test the
refusal path here, and to be the fixtures there.

## Consequences

- Every `ndb/` and `ltp/` module has **one** struct format per structure and
  no variant axis. Estimated saving: a third of the NDB port, and every
  future reader of the code is spared a generic parameter that does nothing
  for them.
- A private store older than Outlook 2003 cannot be read by this package. In
  2026 that is a store that has survived 23 years without Outlook upgrading
  it, which Outlook does on first open; we accept the gap and name it in the
  README.
- The refusal is **tested**, on real ANSI bytes, not just on a synthetic
  header: `tests/test_header.py::test_ansi_store_is_refused` parametrised over
  the two ANSI fixtures.
- Retrofitting ANSI into this package later would be the expensive path P13
  warned about. That is why it is a sibling, not a flag: the sibling can copy
  freely from here and swap the format table, and neither package pays for
  the other's axis.
- Interface consequence: nothing in `pypst`'s public API mentions a variant.
  `open(path)` either returns a Unicode store or raises.

## Rejected

- **Both variants via a format-table parameter** (the P01 alternative). It is
  cheap at the header and expensive by the table context, where upstream's
  generic code is at its densest; and we would be shipping an ANSI path that
  two fixtures cannot adequately test.
- **Both, tested only on synthetic headers.** An untested ANSI path is worse
  than an honest refusal; a wrong-width parse of a real ANSI store produces
  plausible garbage, which the project's threat model treats as the worst
  outcome.
