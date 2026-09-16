---
name: test-harness
description: pytest conventions for this port — the fixture policy that keeps real mail out of the repository, differential tests against the Rust oracle, and denial-first testing. Use when writing any test.
---

# Test conventions

## The fixture policy — read this first

| fixture | where | may a test print its content? |
|---|---|---|
| `Empty.pst` | `tests/fixtures/` (committed) | **yes** — Microsoft's, MIT, holds no mail |
| the public corpus | `tests/fixtures/public/` (committed, SHA-256 pinned) | **yes** — licensed vendor/synthetic test data; see its README for what each exercises |
| oracle goldens | `tests/golden/<fixture>/<example>.txt` | yes — derived from the corpus; never hand-edit, regenerate with `scripts/capture_oracle.py` |
| real stores | `tests/fixtures/private/` (gitignored) | **no** — structure only, never content |
| large stores | outside the repo entirely | no; absolute path, profiling only |

Parametrise over the corpus so a failure names the store:

```python
from tests.conftest import public_fixture_ids, public_fixture_paths

@pytest.mark.parametrize("store", public_fixture_paths(), ids=public_fixture_ids())
def test_header_matches_golden(store): ...
```

A test may assert that a private store **parses**. It may never assert, print,
or log **what it says** — not a subject, not an address, not a body. A failing
assertion prints its operands and CI output is a publication channel.

Three guards, and none of them may be weakened:

- `.gitignore` ignores every `*.pst` except `Empty.pst` and `tests/fixtures/public/*.pst`
- `scripts/git-hooks/pre-commit` blocks a staged store unless it is `Empty.pst`
  (by md5) or its SHA-256 is in `tests/fixtures/public/MANIFEST.sha256`
- CI's `no-mail-stores` job re-checks the manifest, which `--no-verify` cannot bypass

Adding a store is the five-step procedure in `tests/fixtures/public/README.md`
(licence from the LICENSE file, no real mail, oracle-vetted, manifest, NOTICE).

## Markers

| marker | meaning | skips when |
|---|---|---|
| `oracle` | differential test against the built Rust | `reference/` absent or no `cargo` |
| `private` | needs a real store | `tests/fixtures/private/` empty |
| `slow` | full-file walk rather than a unit check | never (deselect with `-m "not slow"`) |

Every marked test must **skip cleanly**, never fail, when its precondition is
missing. A contributor with a fresh clone runs `uv run pytest` and gets green.

## Denial-first

For every layer, the refusal cases are written **before** the success cases,
because they are the ones a port silently gets wrong:

- truncated input at every structure boundary
- a length field larger than the file
- a CRC that does not match
- a cycle in any walked structure
- an unknown enum value — version, crypt method, node type

Assert the **exception type**, not merely that something raised.
`pytest.raises(PstFormatError)` — never bare `Exception`, which passes on the
`AttributeError` your refactor introduced.

`PstLimitError` and `PstFormatError` must stay distinguishable: "too big" and
"corrupt" are different answers and a caller acts on them differently.

## Differential tests

Two forms. The everyday one reads a **committed golden** and needs no Rust:

```python
from tests.golden_parsers import parse_read_header   # P29
from tests.conftest import public_fixture_ids, public_fixture_paths

@pytest.mark.parametrize("store", public_fixture_paths(), ids=public_fixture_ids())
def test_header_matches_golden(store, golden):
    expected = parse_read_header(golden(store, "read_header"))
    ...
```

The `oracle`-marked one runs the Rust live (`run_oracle` in conftest) and is
for private stores, and for the drift check that the goldens still match the
built oracle (`scripts/capture_oracle.py --check`).

Parse the oracle's text into values and compare **values**, not strings:
formatting is upstream's choice and will change under you, while the facts will
not. And name the fixture in the assertion message — "matches the oracle" is
not a claim until you say on what.

The tiers — parity, spec vectors, goldens, denial, the contract harness,
limits, property tests — are in `docs/TEST-PLAN.md`. A layer is done when it
has tests in every tier that applies.

## Upstream parity

Tier T0 says this port passes every test upstream passes, and
`scripts/check_upstream_parity.py` checks it: every `#[test]` in the pinned
Rust source must have **exactly one** Python twin, tagged with the decorator
from `tests/parity`:

```python
from tests.parity import upstream_test

# Twin of upstream's permute.rs `test_decode_block` — derived from Microsoft's MIT-licensed test code.
@upstream_test("crates/pst/src/encode/permute.rs::test_decode_block")
def test_permute_round_trips() -> None: ...
```

The ref is the path relative to `reference/outlook-pst-rs` plus `::` and the
Rust fn name; read the Rust first and assert what it asserts (a superset is
fine). A twin lives wherever the layer's tests live — `tests/parity/` for a
file that is nothing but twins, or in place next to the layer's other tests.
Twins derive from Microsoft's MIT test code, so each carries the one-line
comment above. When your row's twin cannot land yet because the layer does
not exist, add `<ref>  <ROW-ID>` to `scripts/parity-pending.txt`; the lint
fails the moment the twin appears with the line still present, so the row
that writes the twin deletes the line in the same commit. The lint skips
when `reference/` is absent (CI's lint job) and bites in the nightly job.

## Corruption suite

`tests/corrupt.py` is the only source of corrupt input: no bad binary is
ever committed. `mutations(store_bytes, seed=…)` yields a `Mutation` —
`name` (`family:detail`, unique), `data`, `expect` (the `PstError` kind any
refusal must be, or `None` for "any"), `must_raise` (at least one entry
point must refuse it) — from every family in `FAMILIES`, each family drawing
from its own seeded `random.Random` so that adding a mutation to one never
moves another. `tests/corruption_harness.py` runs the landed entry points
over a mutation under a thread watchdog and classifies the result as clean,
`LEAK` (a non-`PstError` escaped), `TYPE` (the wrong `PstError`), `SILENT`
(`must_raise` and nothing refused) or `HANG`; `tests/test_corruption.py`
sweeps one seed over `pstd-inline-cid.pst` and `Empty.pst`, and
`scripts/fuzz_sweep.py --seeds N` is the slow path over every Unicode
fixture. Reproduce a finding with `corrupt.mutation(base, seed=S, name=N)`.

To add a family: write `def my_family(base: bytes, rng: random.Random) ->
Iterator[Mutation]` in `corrupt.py` yielding names prefixed `my_family:`,
append it to `FAMILIES`, add its name to `EXPECTED_FAMILIES` in
`test_corruption.py` and its counts to `PINNED` in
`test_corrupt_generator.py` (both are deliberate pins: a family that
vanishes must be red). Set `expect` only as tight as is honest — a resealed
flip can make a cycle as easily as a bad field — and `must_raise` only where
a refusal is certain. Build the bytes with the existing builders
(`btree_page`, `btree_chain`, `append_pages`, `replace_page`, the `Field`
writers) rather than hand-typed offsets. When a layer lands, add its entry
points to `exercise()` in the harness in the same row.

Stubs waiting for their layer, each `pytest.importorskip`-guarded in
`test_corruption.py`: P03 (`pypst.ndb.block`) — a leaf BBTENTRY `cb`
larger than the file, a leaf data block past EOF, an XXBLOCK chain 10 000
deep, an XBLOCK `lcbTotal` of 4 GB, a subnode tree cycle; P04
(`pypst.ltp.heap`) — a BTH cycle, an HID past the block. The
`P03 landed? add:` note in `corrupt.py` names the family (`block_lies`,
`heap_lies`) and the builders each row is expected to add.

## What "done" means for a test

Not that it passes. That it would **fail** if the code were wrong. When you
write a test, break the code deliberately once and watch it go red. A test that
has never been seen to fail is a comment with a slow runtime.
