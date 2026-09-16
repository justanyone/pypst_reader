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
status: ✅ 2026-09-15 — `parse_read_header` parses 9/9 read_header goldens (Empty + 8 corpus; 2 ANSI
        → version "Ansi", prefix stripped); 84 tests added in test_golden_parsers.py (83) +
        test_golden_drift.py (1), suite 125 passed; `--check` drift test seen red on one flipped byte
        (named Empty/read_header), parser seen red on a flipped value and on truncation at each
        of the 10 line boundaries; 7 stubs raise NotImplementedError describing their golden's shape;
        `python -m pypst.debug --list` runs with an empty registry
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
status: ✅ 2026-09-15 — `scripts/check_upstream_parity.py` reports `parity: 15 upstream tests — 5 twinned, 10 pending (P01-HEADER ×1, P21-RTF ×4, P23-IDS ×5), 0 missing`, exit 0; the 5 encode/key-table twins tagged in place (tests/test_encode.py ×4, tests/test_tables.py ×1 — upstream has no CRC tests); `scripts/parity-pending.txt` carries the 10 owed by P23/P21/P01 rather than xfail stubs, so those rows' real twins merge without a collision; 12 tests in tests/test_parity_lint.py, each seen red once (9 lint mutations + a deleted twin); wired into CI's lint job (skips there, bites nightly)
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
status: ✅ 2026-09-15 — built, captured, tested; one "done means" clause blocked by an upstream bug at the pin (below)
evidence:
- `oracle/Cargo.toml` (+ `Cargo.lock`, `.cargo/config.toml` sharing reference's debug `target/`) and
  `oracle/examples/dump_messages.rs` (475 lines incl. doc comment). Debug profile, first build 7.3 s (-j 4, deps
  already cached), incremental 0.24 s. `scripts/oracle.sh dump_messages <pst>` runs it;
  `capture_oracle.py` lists it (a filtered capture no longer rewrites MANIFEST).
- Goldens 9/9: Empty 39 lines exit 0 · javalibpst-dist-list 210 exit 1 · pstd-inline-cid 9 exit 0 ·
  pstsdk-sample1 72 · pstsdk-sample2 72 · pstsdk-submessage 58 exit 1 · pstsdk-test_ansi 54 ·
  pstsdk-test_unicode 69 · tika-variousBodyTypes 109 (all exit 0 unless stated).
  `--check --example dump_messages` twice: identical. A full re-capture left the other 72 goldens
  byte-identical (only MANIFEST gained the example).
- Exits explained: upstream reads BOTH ANSI stores (they did not "error at open"; pypst still refuses
  them, ADR-0003). pstd-inline-cid opens (the dump never asks for the wastebasket id) but its IPM
  subtree is the root folder with no hierarchy/contents tables → 9 lines. pstsdk-submessage: 1 error;
  javalibpst-dist-list: 3 (two the same cause, one `MessageSubNodeTreeNotFound` on message 0x10001 in
  Contacts — upstream requires a sub-node tree on every message).
- **Upstream bug at pin cfb721da** (found by differential probing, reproduced in a scratch copy, never
  in reference/): `crates/pst/src/ltp/prop_type.rs` `PropertyType::try_from(u16)` has no `0x000D`
  (`PtypObject`) arm although the enum declares `Object = 0x000D`, and `HeapTreeInner::entries` stops
  at the first undecodable leaf record (`while let Ok`). Every embedded-message attachment carries
  `PidTagAttachDataObject` (0x3701) as PtypObject, so the attachment PC is truncated before 0x3705 and
  `UnicodeAttachment::read` fails with `AttachmentMethodNotFound`. Consequence: the "embedded message
  one level down" clause cannot be met through this oracle; the golden shows the attachment-table row
  (`Row: method=5 filename=… size=11494`) then the refusal, and `dump_messages.rs` already implements
  the recursion for a fixed pin. `tests/test_dump_messages_golden.py::test_submessage_shows_embedded_
  attachment_row` asserts the refusal explicitly so a pin move that fixes it fails loudly.
- Also unreachable through upstream's public API: attachments *of* an embedded message (it is
  `Rc<dyn Message>`; `sub_nodes()` is crate-private) — the dump prints their `Row:` only.
- Tests: `tests/test_dump_messages_golden.py`, 45 (44 golden, no Rust needed; 1 `oracle`-marked
  rebuild-and-compare on Empty.pst). Each of the 12 test functions shown red once by mutating the
  goldens, then restored by re-capture. Suite 900 passed / 6 skipped / 2 xfailed; ruff, provenance,
  quality ratchet, parity all green. `parse_dump_messages` stub registered in `golden_parsers.PARSERS`.
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
status: ✅ 2026-09-15 — `synth-basics.pst` (35,840 bytes, sha256 `07f0d7f7…0595982`) is in the corpus as a first-class fixture. Oracle over it: `read_header` 0, `read_btrees` 0, `read_density_list` 0, `read_store_props` 0, `read_named_props` 0, `read_root_folder` 0, `read_ipm_subtree` 0; `read_search_updates` 1 (no NID 0x1E1 search-management queue — documented in the README row). Reproducible: yes, byte-for-byte (`make_fixture.py --check`, and `tests/test_synthetic_content.py` runs it). EMLtoPST needed patching to get there — `scripts/patches/emltopst-oracle-conformance.patch`, 5 files, +80/−27: TCINFO `rgib` were start offsets not end offsets and booleans were 4-byte cells (upstream: `InvalidTableContextBitmaskOffset`), no wastebasket/finder entry ids (`Missing PidTagIpmWastebasketEntryId`), `os.urandom` record key, wall-clock timestamps, "(No Subject)" substituted for a missing subject, RFC 2047 subjects stored as encoded-word literals. Licence note: EMLtoPST states MIT in its README only; no LICENSE file at the pin (`docs/FIXTURE-TOOLS.txt`). Tests: 44 in `test_synthetic_content.py` — 36 pass (policy, goldens, byte-level content on the unencrypted store, regeneration), 8 skip until P07–P09 land (reader tier against INTERFACES § messaging). Goldens captured in `tests/golden/synth-basics/`.
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

**Follow-up (P20b, optional):** EMLtoPST writes `wSig = 0` on every page and
block trailer; upstream does not enforce it, so the store reads, but it is a
spec MUST violation pinned in `tests/spec/test_ms_pst_trailers.py`
(`ZERO_SIG_WRITERS`). Adding `ComputeSig` to the conformance patch would make
`synth-basics` a fully conformant store and let that pin be removed.


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
status: ✅ 2026-09-15 — `tests/spec/` (7 modules, 56 test functions, 128 items: 118 pass, 9 skip on `importorskip("pypst.rtf")` + 2 ANSI dwCRCFull, 1 strict xfail). ≈120 values typed verbatim from the spec pages and ≈60 derived checks with the arithmetic in comments. Sections: [MS-PST] 2.2.2.1–2.2.2.6, 2.2.2.7.1, 2.2.2.7.2, 2.2.2.7.7.1–3, 2.2.2.8.1–2, 2.3.3.4.1–2, 2.4.1, 5.1, 5.2, 5.3, 5.5; [MS-OXCDATA] 2.11.1; [MS-DTYP] 2.3.4.2; [MS-OXRTFCP] 2.1.2.1, 2.1.2.2.1, 2.1.3.1.1, 2.1.3.1.5, 2.1.3.2, 2.2.2.1, 2.2.3.1–2, 3.1.1, 3.1.2, 3.3.1. Off-line, the full 768-byte mpbbCrypt and both 256-entry CRC tables were compared to the pages: byte-for-byte equal to `_tables.py` and to the 0xEDB88320 table. Real-store vectors: dwCRCPartial matches on 9/9 corpus stores, dwCRCFull on 7/7 Unicode; every BBT page and block trailer (436 blocks, 40 pages across 7 Unicode stores) has the spec's CRC and bid. Every test broken once and seen red (24 mutations, code- and test-side, `__pycache__` cleared). **Disagreements found:** (1) spec vs upstream — PtypMultipleGuid: [MS-PST] 2.3.3.4.1 makes it a packed fixed-size array, upstream reads a u32 count; the port follows upstream, pinned as `xfail(strict=True)`. (2) spec vs real files — `pstd-inline-cid.pst` (EMLtoPST) writes wSig=0 on every BBT page/block (2.2.2.7.1 says a 5.5 signature); `javalibpst-dist-list.pst` has non-zero qwUnused (MUST be zero); three corpus stores do not 0xFF-fill rgbFM/rgbFP. P01/P02 must not enforce those MUSTs. (3) spec wording — HEADER (ANSI) sums to 512 bytes; wMagicClient `{0x53,0x4D}` is the LE WORD 0x4D53, not 0x534D; rgnid[] holds bare nidIndex counters, not NIDs. (4) spec typo — [MS-OXRTFCP] 3.1.2.4 later dumps print `{\ref1` for `{\rtf1`. No spec-vs-our-code disagreement found. Nothing failed to fetch.
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
