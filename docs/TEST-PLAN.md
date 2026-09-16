# The test plan

The goal, stated by the project owner: **a very, very complete test suite —
better than upstream's.** This document says what that means concretely, so
that "complete" is a checklist and not a feeling.

Upstream's bar is low in one dimension and high in another. It has **15 unit
tests** (`grep -r '#\[test\]'` over the crate): key-table sizes, two encoding
round-trips, block-signature arithmetic, three id-overflow checks, one magic
constant, and four compressed-RTF vectors from [MS-OXRTFCP]. What it has
instead is the compiler, and ten example binaries that its authors ran over
real stores. We do not have the compiler. We have the binaries, and we have
turned them into data.

## The tiers

Every tier below has a row in `MasterToDo.md`; the tier is the *what*, the
row is the *when*. A layer is not done until it has tests in every tier that
applies to it.

### T0 — upstream parity: we pass the tests upstream passes

Every upstream `#[test]` is ported one-for-one into `tests/parity/`, and a
lint (`scripts/check_upstream_parity.py`, row P18) enumerates upstream's test
functions from the pinned source and fails if any lacks a Python counterpart
tagged `@upstream_test("crates/pst/src/encode/permute.rs::test_decode_block")`.
This is what makes "passes the same tests as upstream" a checked claim rather
than a hope, and it is how a moved pin tells us upstream added a test.

Today: 15 tests. Some are near-trivial (table length is 256) and stay anyway:
parity is the property.

### T1 — specification vectors

[MS-PST] and [MS-OXRTFCP] contain worked examples with bytes: the permutative
and cyclic key tables, the CRC of sample data, the RTF compression examples,
the header field layout with offsets. Each becomes a test that reads the bytes
from the spec, not from upstream — the one tier that can catch a bug upstream
and we share. Row P28.

### T2 — differential goldens, over the public corpus, no Rust required

For every fixture in `tests/fixtures/public/` (plus `Empty.pst`) and every
non-interactive upstream example, the oracle's exact output is committed under
`tests/golden/<fixture>/<example>.txt` (row P17, `scripts/capture_oracle.py`).

Each ported layer ships a `pypst.debug <layer>` dumper whose output is
*parsed*, as the golden is parsed, into values — and the values are compared.
Not strings: upstream's `Debug` formatting is theirs to change. A parser per
example lives in `tests/golden_parsers.py`, written once, used by every layer.

Parametrised over the corpus: `@pytest.mark.parametrize("store", public_fixture_paths(), ids=...)`
so a failure names the fixture. Nine fixtures × eight examples = 72 diffs per
layer that runs on every push, with no toolchain.

The `oracle` marker keeps the goldens honest: when cargo is present,
`capture_oracle.py --check` re-derives them and fails on drift. That
re-derivation is scheduled: `.github/workflows/nightly-oracle.yml` builds the
oracle at the pin once a night and runs it (with the T0 parity lint, the T8
fixture regeneration, and the `oracle`/`slow` tests) through
`scripts/nightly_oracle_local.sh`, the same script a developer runs locally.

### T3 — private-store differential, structure only, local only

The same dumpers run over `tests/fixtures/private/` when present, comparing
against a *fresh* oracle run (never a committed golden — the oracle's output
over private mail is the mail). Assertions are on counts, ids, sizes, types,
and on equality between the two outputs; never on a value that is content.
Marker `private`; skips cleanly elsewhere.

### T4 — denial: the corruption suite

Every input here is bytes we write ourselves by mutating a corpus store
(`tests/corrupt.py`, row P12), so it needs no licence and grows by adding a
mutation, not a binary:

truncation at every structure boundary · a length larger than the file · a
CRC that does not match · a byte index past EOF · an NBT root that points at
itself · a BTH cycle · an XBLOCK tree deeper than any real one · a `wVer` from
the future · an unknown crypt method · an unknown property type · a 4 GB
allocation claim in a 265 KB file.

Each asserts the **exception type** — `PstFormatError`, `PstLimitError`,
`PstUnsupportedError` — never bare `Exception`. Written before the success
cases of the layer they target (the `test-harness` skill).

### T5 — the contract harness: `PstError` or nothing

A single generic test (row P24) that runs **every public entry point** over
**every file in the corruption corpus and every fixture**, and asserts that
whatever comes out is either a result or a `PstError` subclass. `struct.error`,
`IndexError`, `KeyError`, `MemoryError`, `RecursionError`, `UnicodeDecodeError`
escaping is a failure regardless of which layer leaked it. This is the test
that catches the bug nobody wrote a specific test for.

Built (P24): `tests/contract.py` **discovers** the entry points — `pkgutil`
over the package, each module's `__all__` (else its public top-level
callables), every public classmethod and method along the class's MRO —
and `tests/test_contract.py` runs them over every fixture (default limits;
every ceiling at 1, which must trip only `PstLimitError`/`PstFormatError`;
every ceiling at `sys.maxsize`, which must reproduce the default outcomes
reader for reader) and over P12's mutation corpus (one seed, one base in the
suite; three seeds over every Unicode base, and the `python -m pypst.debug`
process boundary, under `slow`). **How a new layer joins:** it does not
opt in — its public callables are discovered the moment the module exists,
and `test_every_public_callable_has_an_adapter_or_a_reason` fails, naming
each one, until the row that lands it adds either an `ADAPTERS` entry (a
builder that, given a `Store`, yields the argument tuples: the bytes, the
file, the parsed header/B-tree/reader, the NBT entries, the heap over a
node, the BTH over that heap and the property context over it, a nid…) or a
`NOT_STORE_INPUT` entry with the reason it takes no store-derived input.
Exception types, enums and dataclass constructors are excluded by rule;
a dumper registered in `pypst.debug.DUMPERS` is adapted automatically
(an extra positional parameter must be named in `EXTRA_ARGS`). A leak the
harness finds is pinned `xfail(strict=True, reason="<module>: <exception>
on <mutation>")` by the row that finds it and fixed by the row that owns
the module.

### T6 — limits

For each ceiling in `limits.py` (row P11): a test that a structure one under
the ceiling is read, one over it raises `PstLimitError`, and that the error is
not a `PstFormatError` — the two must stay distinguishable because a caller
retries one and discards the other.

### T7 — message-level oracle

Upstream's message-level example is a TUI (`browse_pst`). Row P19 adds a
small Rust example of our own, compiled against the pinned crate, that dumps
every folder, message, recipient and attachment non-interactively. It lives in
`oracle/` (not `src/`; Rust is the oracle, not the product), its output is
captured into goldens like any other example, and it is what P08–P09 diff
against.

Built (P19): `oracle/Cargo.toml` + `oracle/examples/dump_messages.rs`, a
`[workspace]`-less crate with `outlook-pst` as a path dependency, sharing the
reference checkout's debug `target/` via `oracle/.cargo/config.toml`.
`scripts/oracle.sh dump_messages <pst>` runs it (`cargo build --example
dump_messages` inside `oracle/` builds it by hand; a few seconds once the
upstream examples are built). It walks pre-order from `NID_ROOT_FOLDER`,
prints folders, messages (ids, class, subjects, sender, times as raw FILETIME integers,
body kinds as byte length + CRC-32, recipient and attachment rows) and ends
with `Errors: n`; a per-item failure never aborts the walk. Goldens live at
`tests/golden/<fixture>/dump_messages.txt`, tested by
`tests/test_dump_messages_golden.py`. Known ceiling at pin `cfb721da`:
upstream's `PropertyType::try_from` lacks `PtypObject` (0x000D), so it cannot
open any embedded-message attachment; the dump records the attachment-table
row (`method=5`) and the refusal, and the recursion into the embedded
message is written but unreachable until the pin moves.

### T8 — synthetic fixtures with known content

`pstd-inline-cid.pst` was generated from authored EML files by EMLtoPST, a
pure-Python MIT writer of Unicode PSTs. Row P20 pins that tool and adds a
`scripts/make_fixture.py` that turns `tests/fixtures/synthetic/<name>/*.eml`
into a PST whose hash is recorded. Because *we wrote the mail*, tests can
assert on content — "the subject of the second message is X" — which no
vendor fixture allows. Caveat, recorded in the ADR: EMLtoPST is not Outlook,
and upstream refuses one of its outputs; a synthetic fixture is admitted to
the corpus only after the oracle reads it, or with its oracle refusal
documented as the point.

### T9 — property-based

For every pure function — encodings, CRC, id packing, FILETIME conversion,
RTF decompression against RTF compression — a `hypothesis` test of the
round-trip or the invariant, dev-dependency only (row P25). Where the
function has an upstream counterpart with different code shape (`bytes.translate`
vs a loop), the property test compares the two shapes over random input, as
`test_crc.py` already does with the naive table walk.

### T10 — coverage as a ratchet, not a target

`pytest-cov` with a recorded floor in `scripts/coverage-baseline.txt`,
enforced the way `check_quality_ratchet.py` enforces ruff findings: the number
may not go down. A coverage percentage is not evidence of correctness and the
ratchet must never be cited as such; it exists to catch a module that landed
with its tests forgotten. Row P26.

### The discipline that makes any of this mean something

From the `test-harness` skill, and repeated because it is the one that gets
skipped: **a test that has never been seen to fail is a comment with a slow
runtime.** When you write one, break the code once and watch it go red. For a
differential test, corrupt one byte of the golden and watch it go red.

## How this beats upstream, and where it cannot

| | upstream | here |
|---|---|---|
| unit tests | 15 | those 15, plus T1/T4/T6/T9 |
| differential against another implementation | none (it *is* the implementation) | 72+ goldens per layer, on every push |
| corruption / adversarial input | none | T4 + T5 |
| message-level automated check | none (TUI) | T7 |
| content assertions on known mail | none | T8 |
| what it has that we do not | **the compiler** | tier-1 ruff rules (F821 etc.) catch the porting slip that a type checker would; consider `mypy --strict` as a row once the API settles |

"Better than upstream" is achievable on every row but the last, and the last
is why the differential tiers exist: what the compiler proved for them, the
oracle proves for us.
