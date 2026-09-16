# ADR-0004: A hash-pinned public fixture corpus, and what may enter it

- **Status:** accepted 2026-09-15
- **Supersedes:** the "exactly one committed store" rule in the P00 scaffold
  (NOTICE, CLAUDE.md, the pre-commit hook and CI as first written)
- **Relates to:** ADR-0002 (attribution), row P00-FIXTURES

## Context

The scaffold allowed one mail store in the repository — Microsoft's MIT
`Empty.pst` — and it holds no mail, so CI could prove the header and BTree
layers and nothing above them. Everything from the heap up was going to be
provable only on a developer's machine, against private stores whose content
no test may print. That was recorded in PORTING-PLAN as "a real limitation,
not a temporary one".

It is temporary. Several permissively licensed, small, populated test stores
exist, published by projects that needed exactly what we need:

| source | licence | stores |
|---|---|---|
| Microsoft PST SDK (pstsdk, via the enrondata mirror) | Apache-2.0 | 3 Unicode + 2 ANSI, 265 KB each, incl. an embedded-message case |
| PSTD (andrew3stedall) | MIT | a 29 KB synthetic store, generated from authored EML by an MIT tool, hash-pinned upstream |
| Apache Tika | Apache-2.0 | a 265 KB store with plain, HTML and RTF bodies |
| java-libpst | Apache-2.0 / LGPL dual | a 265 KB store with 12 folders and a distribution list |

Not everything found was acceptable: a fixture with no licence at all
(mcp-pst), a fixture whose authors did not write it and did not say where it
came from (PSTD's `sample.pst`), copyleft test data (libpff, libpst), a
project that has since gone AGPL/commercial (go-pst), and the Enron corpora
(real people's mail, tens of MB per custodian).

## Decision

**1. A committed store must satisfy three conditions, and a fourth makes them
checkable.**

1. A permissive licence, established from the source repository's LICENSE
   file. MIT, BSD, Apache-2.0, or public domain. **Copyleft is refused
   regardless of size or usefulness.**
2. No real correspondence: synthetic, or a vendor's own test store.
3. Small. The corpus today is nine files and ~2.2 MB; a fixture over ~1 MB
   needs a reason written in the README row.
4. **SHA-256 pinned** in `tests/fixtures/public/MANIFEST.sha256`, with a
   README row naming source repository, path, commit, licence, and what it
   exercises.

**2. The guards check the manifest, not a name.** The pre-commit hook allows
a `tests/fixtures/public/*.pst` only if its staged content's SHA-256 appears
in the (staged or committed) manifest; CI runs `sha256sum -c --strict` and
refuses any `.pst` present but unlisted; `tests/test_fixtures.py` asserts the
tracked set equals the manifest. `.gitignore` still ignores `*.pst` by default;
the exemption is the one directory, and the hook is what makes the exemption
safe. `Empty.pst` keeps its original place and its md5 check unchanged.

**3. Apache-2.0 fixtures are acceptable in this MIT project.** Apache-2.0 §4
requires that redistribution carry the licence text and attribution; MIT
requires the attribution already. The text lives at
`tests/fixtures/public/LICENSES/Apache-2.0.txt` and NOTICE names each source.
This does not change the licence of `pypstreader` — test data is not the package —
and no Apache-2.0 file is included in the wheel.

**4. Tests may print corpus content.** The content-silence rule exists to
protect people; there is nobody in these files. The rule stays absolute for
`tests/fixtures/private/`.

**5. Oracle output over the corpus is committed** (`tests/golden/`, produced by
`scripts/capture_oracle.py`). It is derived from public data by MIT code, so
it is redistributable, and it is what lets the differential suite run in CI
without a Rust toolchain. The `oracle`-marked tests re-derive it when cargo is
present and fail on drift.

## Consequences

- CI can now prove every layer up to and including messages, attachments and
  embedded messages, on public data — PORTING-PLAN § "What we do not have" is
  rewritten.
- The corpus includes two ANSI stores that this package will refuse
  (ADR-0003). They are there to test the refusal and to seed
  `pypstreader_nu`.
- Adding a fixture is a documented five-step procedure in the corpus README
  and cannot be done by `git add -f` alone.
- The wheel excludes `tests/`; nothing here ships to PyPI.
- One of the fixtures (`pstd-inline-cid.pst`) is rejected by upstream's own
  store layer for a missing property. That is deliberate: it is what a PST
  written by something other than Outlook looks like, and the port's
  behaviour on it (refuse with a named `PstFormatError`, or tolerate with a
  documented divergence) is a decision row P07 must make explicitly.
