---
name: rust-port
description: Port a module from the upstream Rust PST implementation to Python — the differential-oracle method, the Rust→Python idiom table, when to diverge deliberately, and the ways this method can fool you. Load FIRST before touching any module in src/pypstreader/.
---

# Porting a module from Rust

## The method, in one line

**Port a layer, run both implementations over the same bytes, diff the output.**

Not "read the Rust and write Python". The Rust is not documentation to be
paraphrased; it is a working oracle that will tell you, in seconds, that your
B-tree walk is off by one page.

## Before you write anything

1. **Read the upstream module end to end.** Not skimmed — every branch.
   `reference/outlook-pst-rs/crates/pst/src/<path>`.
2. **Read the spec section it links to.** Every upstream file has
   `learn.microsoft.com` deep links in its doc comments; 27 of 31 modules do.
   The spec explains *why* a field exists, which the Rust cannot.
3. **Run the oracle on the fixtures and save the output.** This is your target:
   ```bash
   scripts/oracle.sh read_header tests/fixtures/Empty.pst > /tmp/rust-header-empty.txt
   scripts/oracle.sh read_header tests/fixtures/private/throwaway.pst > /tmp/rust-header-throw.txt
   ```
4. **Decide what your Python will print** so the two are diffable. A small
   `pypstreader.debug` entry point per layer, mirroring the oracle's format, is worth
   the half hour every single time.

## The three ways this method fools you

Read these before you trust a green diff.

- **`Empty.pst` proves almost nothing above the BTree layer.** It has a header,
  pages and a root folder, and no mail. A messaging-layer diff that passes on
  `Empty.pst` alone has tested that your code does not crash. Always diff
  against a populated private store too — and say which fixture in the row.
- **Matching the oracle is not matching the spec.** If your port and upstream
  agree because you transcribed upstream's bug, the diff is empty and you are
  both wrong. When a field's handling looks strange, check the spec before
  copying it — and if upstream and the spec genuinely disagree, **follow
  upstream** (it is the implementation that opens real files) and write a
  comment naming the disagreement.
- **A diff of formatted output hides type errors.** `42` prints the same
  whether it is an `int`, a `bool`, or an enum member whose `__str__` you got
  lucky with. Assert on parsed values in tests, not only on printed text.

## Rust → Python idioms

| upstream | here | note |
|---|---|---|
| `byteorder::ReadBytesExt` | `struct.unpack_from` | one format string per structure, module-level constant |
| `#[derive(Debug)] struct` | `@dataclass(frozen=True, slots=True)` | frozen: parsed structures are facts, not scratch space |
| `thiserror` enum | a `PstError` subclass | see `src/pypstreader/errors.py`; never let `struct.error` escape |
| `Result<T, E>` | raise | Rust makes the compiler enforce handling; here the discipline is "one exception family, always" |
| `impl PstFile for {Unicode,Ansi}` | a struct-format table, or drop ANSI | see row P13 — do NOT reproduce the trait-generic axis literally |
| `&[u8]` slices | `memoryview` | avoids copying on every block read; slice it, do not `bytes()` it until you must |
| a 256-byte table + `for` loop | `bytes.translate` | already done in `encode.py`; the pattern generalises |
| a table-driven CRC | `zlib.crc32` | already done in `crc.py` |
| `u32` arithmetic | `& 0xFFFFFFFF` | Python ints do not wrap — every `+`, `-`, `<<` on a fixed-width value needs the mask |
| `as u8` truncation | `& 0xFF` | same trap, smaller |
| `usize` indexing | bounds-check yourself | Rust panics; Python returns something from the wrong place or raises `IndexError` far away |

**The wrapping-arithmetic row is the one that bites.** Rust's `wrapping_add` is
explicit; Python's `+` silently grows. A missing mask produces correct output
on small inputs and garbage on large ones, which is the worst failure shape
there is.

## Where to diverge deliberately

Four sanctioned divergences (see `docs/PORTING-PLAN.md`):

1. C-speed stdlib primitives instead of hand-rolled loops.
2. Explicit limits and cycle guards (row P11) — Rust's bounds checks make a
   panic survivable; an unbounded Python loop is a hang.
3. Possibly no ANSI support (row P13).
4. Pythonic naming where mirroring would be noise.

**Every divergence gets a paragraph in the module docstring saying what and
why.** An unexplained divergence reads as a porting bug to the next person, who
will then "fix" it back.

## Finishing a module

- [ ] `Ported from:` / `Upstream:` headers present (`scripts/check_provenance.py`)
- [ ] Diffs clean against the oracle on `Empty.pst` **and** a populated store
- [ ] Denial cases tested: truncated, lying length, bad CRC, cycle
- [ ] No `struct.error` / `IndexError` / `MemoryError` escapes — only `PstError`
- [ ] Wrapping arithmetic masked everywhere a fixed-width value is computed
- [ ] `uv run pytest -q` green; `scripts/check_quality_ratchet.py` green
- [ ] The `todo/` block's `status:` updated **with the evidence** — which
      fixture, which oracle command, how many tests

## Lessons learned

Append here as the port teaches you things. Two from the scaffold:

- **Never transcribe a table by hand.** `_tables.py` is generated by
  `scripts/extract_key_data.py`, which proves three invariants on the way
  through (each table a permutation; I inverts R). A mistyped byte would
  corrupt one byte in 256 of every block and look like a structural bug.
- **Check whether a 300-line upstream file is a stdlib one-liner first.**
  `crc.rs` is 335 lines of slicing-by-8 that `zlib.crc32` computes exactly,
  once the missing pre/post inversion is undone. Ask that question of every
  file before starting: upstream optimised for Rust's constraints, not ours.
- **Clear `__pycache__` before a mutation pass.** "Break the code once and watch
  it go red" is defeated by a same-size edit restored within the same second:
  the stale `.pyc` stays valid and the tests run against code no longer on
  disk. P23's first pass was contaminated this way. `find . -name __pycache__
  -exec rm -r {} +` between mutations, or run with `PYTHONDONTWRITEBYTECODE=1`.
