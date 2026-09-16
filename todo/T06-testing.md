# T06 — the test infrastructure that makes "better than upstream" checkable

The tiers are defined in `docs/TEST-PLAN.md`; these are the rows that build
them. Every row here is a leaf — none touches `src/pypst/ndb/`, `ltp/` or
`messaging/` — so all of them can run beside lane A.

### P17-GOLDEN
status: ✅ 2026-09-15 — `scripts/capture_oracle.py`; 72 goldens (9 fixtures × 8 examples) under `tests/golden/`; `--check` clean on an independent second run
upstream: the eight non-interactive examples in `crates/pst/examples/`
oracle:   `python3 scripts/capture_oracle.py --check`
blocked on: none

Captured. Two things the goldens record that a reader should know: ANSI
fixtures get exit 101 from `read_btrees` (upstream's own panic — that example
is Unicode-only), and `pstd-inline-cid.pst` gets exit 1 from every
store-level example (missing `PidTagIpmWastebasketEntryId`). Both are kept
as goldens: the port must refuse the same inputs, in its own vocabulary.

### P29-GOLDEN-HARNESS
status: ✗ not started
upstream: none
oracle:   `tests/golden/`
blocked on: none — **lane C starts here**

Three pieces, each small:

1. `src/pypst/debug.py` — `python -m pypst.debug <layer> <file>`, a
   dispatcher with no layers yet. Each layer row registers its dumper here.
   `Ported from: not a port`.
2. `tests/golden_parsers.py` — one parser per oracle example, turning the
   Rust `Debug` text into plain Python values (ints, tuples, lists of
   dicts). Write `parse_read_header` now against the 9 committed goldens,
   including the two exit-101 empties; leave a `NotImplementedError` stub
   with the golden's shape described for the other seven, so each layer row
   fills in one. Test the parser itself: it must parse all 9 goldens and
   must reject a truncated one.
3. `tests/test_golden_drift.py` — `@pytest.mark.oracle`: runs
   `capture_oracle.py --check`, skips without cargo. This is what makes a
   moved pin visible.

**Done means:** 9/9 `read_header` goldens parse into values with the field
names `docs/INTERFACES.md` § header uses (so P01 can compare directly), and
the drift test is seen to fail when one golden byte is changed.

### P18-PARITY
status: ✗ not started
upstream: every `#[test]` in the pinned source (15 today)
oracle:   `python3 scripts/check_upstream_parity.py`
blocked on: none

`scripts/check_upstream_parity.py` walks `reference/outlook-pst-rs` for
`#[test]\nfn <name>` (with its file), and walks `tests/parity/` for functions
decorated `@upstream_test("<crate-relative path>::<name>")`. Every upstream
test must have exactly one twin; the lint lists the missing ones and fails.
Skips (does not fail) when `reference/` is absent, like the `oracle` marker.

Port the 15 now: the encode and CRC ones already exist in `tests/test_encode.py`
/ `test_crc.py` — move or tag them; the block_sig/id/header-magic ones land as
`xfail(reason="P23")` / `"P01"` until those rows land, and RTF as `"P21"`.
An `xfail` twin satisfies the lint; an absent one does not.

**Done means:** the lint passes with 15/15 twins and is wired into CI's lint
job; a deleted twin is seen to fail it.

### P19-ORACLE-DUMP
status: ✗ not started
upstream: `crates/pst/examples/browse_pst.rs` (the TUI — what to dump, not how)
oracle:   this row *builds* the oracle for P08/P09
blocked on: none (needs someone comfortable writing ~200 lines of Rust)

`oracle/Cargo.toml` + `oracle/examples/dump_messages.rs`: a crate that
depends on `outlook-pst = { path = "../reference/outlook-pst-rs/crates/pst" }`
and walks the store from the IPM subtree, printing — deterministically, in
folder-then-row order — every folder (id, name, counts), every message (id,
class, subject, sender, dates, body kinds and byte lengths, recipient rows,
attachment rows), and recursing into embedded messages. Debug-format values
like the other examples do, so P29's parser style applies.

Extend `scripts/oracle.sh` to find it, add it to `capture_oracle.py`'s
example list, capture goldens for all 9 fixtures (it will fail on the ANSI
pair and on `pstd-inline-cid` like the others — record the exits).

**Done means:** goldens for `dump_messages` on 9/9 fixtures, determinism
confirmed by `--check`, and `pstsdk-submessage`'s golden shows the embedded
message one level down.

### P20-SYNTH
status: ✗ not started
upstream: none — EMLtoPST is `igrbtn/EMLtoPST` (MIT, pure Python) @ `6fe9025390a96fe0095457b56f12ce241ee4ba53`, the commit PSTD generated `inline-cid.pst` with
oracle:   `scripts/oracle.sh read_ipm_subtree <generated>.pst` must succeed before a synthetic store enters the corpus
blocked on: none

`scripts/make_fixture.py <name>`: clones EMLtoPST at the pin into
`reference/` (gitignored, like the Rust), runs it over
`tests/fixtures/synthetic/<name>/**/*.eml` (which **we author**, with
`example.test` addresses and nothing real), writes
`tests/fixtures/public/synth-<name>.pst`, and prints the hash for the
manifest. Fixed timestamps and store keys so the output is reproducible
byte-for-byte; the corpus README row records the recipe.

First fixture: `synth-basics` — six messages exercising a plain body, an
HTML body, a UTF-8 subject with non-Latin characters, a message with two
attachments, a message with CC and BCC, and an empty subject.

Then the thing this row exists for: `tests/test_synthetic_content.py`
asserting **what the messages say**, which no vendor fixture permits.

**The caveat, in the row so it is not forgotten:** EMLtoPST is not Outlook.
`pstd-inline-cid.pst` is refused by upstream's store layer. A synthetic store
that the oracle refuses is not admitted unless the refusal is the point.

### P24-CONTRACT
status: ✗ not started
upstream: none
oracle:   none
blocked on: P12 (the corruption corpus), P01 (the first entry point)

`tests/test_contract.py`: for every public callable in `pypst.__all__`, for
every file in the corruption corpus and the fixture corpus, call it; accept a
return value or a `PstError` subclass; **fail on anything else** — name the
exception type and the file. Generic on purpose: the layer-specific tests say
what should happen; this says what must never happen. Add a timeout per call
(a hang is a failure, not a wait).

### P25-HYPOTHESIS
status: ✗ not started
upstream: none
oracle:   none
blocked on: none

Decide, in a paragraph appended to ADR-0004's neighbour (or a new ADR-0005
"dev-only dependencies"), that `hypothesis` is admitted to the `dev` group
and the runtime stays at zero. Then the first property tests: encode/decode
round-trips for both encodings over arbitrary bytes and keys; `zlib.crc32`
against the naive walk; P23's pack/unpack; FILETIME → datetime → FILETIME.

### P26-COVERAGE
status: ✗ not started
upstream: none
oracle:   none
blocked on: none

`pytest-cov` in the dev group, `--cov=pypst --cov-report=term-missing`, and
`scripts/check_coverage_ratchet.py` with `scripts/coverage-baseline.txt`
modelled exactly on the ruff ratchet: fails if the percentage drops below
the recorded floor; raising the floor is a chore, lowering it is a decision.
Wire into CI's test job. Never cite it as evidence of correctness.

### P28-SPEC-VECTORS
status: ✗ not started
upstream: none — the vectors come from the specification, not the crate
oracle:   none
blocked on: none

`tests/spec/`: every worked byte example in [MS-PST] (the key tables in §5.1,
the CRC in §5.3, the header layout in §2.2.2.6, the block trailer in §2.2.2.8)
and [MS-OXRTFCP] (§4.1–4.2, the RTF examples, which upstream also uses —
type them from the spec anyway). Each test names the spec section. This is
the one tier where our implementation and upstream can be wrong together and
still get caught.

### P31-MYPY
status: ✗ blocked on P06
upstream: rustc
oracle:   none
blocked on: P06 (the API needs to stop moving first)

`mypy --strict src/` as a CI lint. The closest we can get to what upstream's
compiler gave it. Not before the LTP surface settles, because strict typing
on a moving API is a tax with no payer.
