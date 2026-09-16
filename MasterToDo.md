# pypst — MasterToDo

Unfinished work only. Resume: read this, `git log --oneline -15`, then the
`todo/` file the top unblocked row links to. Landing check before touching a
row: `git log --oneline | grep -i <ID>`. **Working beside other agents: read
[`docs/AGENTS.md`](docs/AGENTS.md) first — claim the row before starting.**

| | |
|---|---|
| How to port (read FIRST) | `.claude/skills/rust-port/SKILL.md` |
| Multi-agent protocol | [`docs/AGENTS.md`](docs/AGENTS.md) |
| Layer contracts (code against these) | [`docs/INTERFACES.md`](docs/INTERFACES.md) |
| What "tested" means here | [`docs/TEST-PLAN.md`](docs/TEST-PLAN.md) |
| Layer order and costs | [`docs/PORTING-PLAN.md`](docs/PORTING-PLAN.md) |
| Task files | [`todo/`](todo/) — rules + one file per cluster |
| Binding decisions | [`docs/adr/`](docs/adr/) |
| Upstream pin | [`docs/UPSTREAM.txt`](docs/UPSTREAM.txt) |

Branch `main`. One commit per row, message starts with the id; done ONLY with
verification recorded on the row (a test count, an oracle diff, a sha); ✗ cases
before ✓ cases; mail stores only via the manifest (ADR-0004); zero runtime
dependencies; fail closed; Unicode only (ADR-0003); `git commit -F msg -- <paths>`.

## Priority key

1–2 high · 5 medium · 10 low · 11 backlog (do not start; revisit later).
A row is sized for ONE opus sub-agent session. Rows too big for that say so and
name their split.

## Lanes — what can run at the same time

| lane | rows, in order | touches |
|---|---|---|
| **A · the port** (serial) | P23 → P01 → P02 (+P11) → P03 → P04 → P05 ∥ P06 → P07 → P08 → P09 → P10 | `src/pypst/ndb/`, `ltp/`, `messaging/` |
| **B · leaf modules** (each independent, run beside A) | P21 RTF · P22 property-type decoders · P28 spec vectors | `src/pypst/rtf.py`, `ltp/prop_type.py`, `tests/spec/` |
| **C · test infrastructure** (independent, run beside A) | P29 golden harness · P18 parity lint · P19 Rust message dumper · P20 synthetic fixtures · P25 property tests · P26 coverage ratchet; then P12 after P01, P24 after P12 | `tests/`, `scripts/`, `oracle/` |
| **D · later** | P14 · P31 · P15 · P16 · P27 | CI, typing, perf, release, the sibling library |

Two agents never hold the same module. Lane A's next row and any lane B/C row
can start today.

## Open

| Id | Pri | State | One line | Work |
|---|---|---|---|---|
| P25-HYPOTHESIS | 5 | ✗ not started | Decide (ADR paragraph) and add `hypothesis` as a dev-only dependency; first property tests over encode/crc/ids. | [`todo/T06-testing.md`](todo/T06-testing.md#p25-hypothesis) |
| P26-COVERAGE | 5 | ✗ not started | `pytest-cov` + a coverage floor ratchet beside the ruff ratchet. A number that may not go down, never cited as evidence of correctness. | [`todo/T06-testing.md`](todo/T06-testing.md#p26-coverage) |
| P10-EML | 5 | ⏳ in flight — agent/p10-eml 2026-09-16 | The RFC-822 assembler: one message → one `.eml`. **The actual deliverable.** Measure header survival first. | [`todo/T03-messaging.md`](todo/T03-messaging.md#p10-eml) |
| P31-MYPY | 10 | ready (P06 done) — deferred until P09 lands so strict typing is not applied to a moving messaging API; needs `mypy` as a dev dependency (user's call, with hypothesis/pytest-cov) | `mypy --strict` over `src/` once the LTP API has settled — the closest thing to the compiler upstream had. | [`todo/T06-testing.md`](todo/T06-testing.md#p31-mypy) |
| P15-PERF | 11 | ✗ backlog | Profile against a large store (outside the repo). Not before P10. | [`todo/T05-infra.md`](todo/T05-infra.md#p15-perf) |
| P16-PUBLISH | 11 | ✗ backlog | PyPI release. Not before P10. | [`todo/T05-infra.md`](todo/T05-infra.md#p16-publish) |
| P27-NU | 11 | ✗ backlog | `pypst_reader_nu` — a sibling package for ANSI (pre-2003) stores, ported from upstream's ANSI arms against `pstsdk-test_ansi.pst` and `pstsdk-sample2.pst`. Not before this package reads Unicode end to end. | [`todo/T05-infra.md`](todo/T05-infra.md#p27-nu) |

## Done

| Id | State | One line |
|---|---|---|
| P00-SCAFFOLD | ✅ 2026-09-15 | Repo scaffold: uv env, pytest, ruff ratchet, provenance lint, fixture policy + pre-commit guard, pinned upstream fetch + oracle scripts, CI, ADRs 0001–0002, skills. 23 tests green. |
| P00-ENCODE | ✅ 2026-09-15 | `encode.py` + `_tables.py` — permutative (via `bytes.translate`) and cyclic encodings, key table mechanically extracted with three invariants proven, upstream's own test vectors reproduced. |
| P00-CRC | ✅ 2026-09-15 | `crc.py` — 335 upstream lines reduced to one `zlib.crc32` call, proven equal to the naive table walk over 400 random pairs. |
| P00-FIXTURES | ✅ 2026-09-15 | Public corpus: 8 stores (6 Unicode, 2 ANSI; 29 KB–265 KB; Apache-2.0 ×7, MIT ×1) from Microsoft pstsdk, PSTD, Tika, java-libpst — every one opened by the oracle, SHA-256 pinned in `MANIFEST.sha256`; hook, CI and `test_fixtures.py` check the manifest. ADR-0004. 41 tests green. |
| P17-GOLDEN | ✅ 2026-09-15 | `scripts/capture_oracle.py`: 72 oracle goldens (9 fixtures × 8 examples) under `tests/golden/`, `--check` clean on a second independent run. |
| P13-ANSI | ✅ 2026-09-15 decided | Unicode only; ANSI refused with `PstUnsupportedError`; ANSI work is the sibling library, row P27-NU. ADR-0003. |
| P00-PLAN | ✅ 2026-09-15 | ADR-0003/0004, `docs/TEST-PLAN.md` (ten tiers), `docs/AGENTS.md` (multi-agent protocol), `docs/INTERFACES.md` (layer contracts), rows P17–P31, lane table. |
| P29-GOLDEN-HARNESS | ✅ 2026-09-15 | `pypst.debug` dispatcher, `tests/golden_parsers.py` (`parse_read_header` complete, 9/9 goldens; six value parsers; seven described stubs), `golden`/`golden_exit` fixtures, oracle drift test. 84 tests added, 125 passing; each seen red once. |
| P18-PARITY | ✅ 2026-09-15 | `scripts/check_upstream_parity.py` + `scripts/parity-pending.txt`: 15 upstream tests — 5 twinned in place (encode ×4, tables ×1; upstream has no CRC tests), 10 pending by row; 12 lint tests each seen red; wired into CI lint (skips without `reference/`, bites nightly). |
| P23-IDS | ✅ 2026-09-15 | `ndb/ids.py` + `block_sig.py` (Unicode arms only): NodeId/NodeIdType + 14 NID_* constants, BlockId, PageId, ByteIndex, BlockRef, PageRef, `compute_sig`. Header ids unpacked from the fixtures' own bytes reproduce the goldens on 7/7 Unicode stores; every NodeId/BlockRef in `read_btrees` goldens rebuilt on 7/7; 4/4 upstream twins; 103 tests, 18/19 mutants caught. |
| P22-PROPTYPE | ✅ 2026-09-15 | `ltp/prop_type.py`: 30 PropType members checked against [MS-OXCDATA] 2.11.1, table-driven `decode` per type incl. all MV_* forms, FILETIME/GUID edge cases pinned, `max_items` → PstLimitError. 225 tests, 20/20 mutants caught. Six documented divergences (strict widths, strict UTF-16, named codepage). MV_GUID follows upstream's count prefix against the spec — flagged to P05. |
| P21-RTF | ✅ 2026-09-15 | `rtf.py` + generated `_rtf_dictionary.py` (207 bytes, three invariants incl. the spec's own string): LZFu/MELA decompression; upstream's CRC proven to be zlib's three ways; 4/4 spec vectors, 4/4 upstream twins, round-trip over 42 size×seed cases, 1500-mutation fuzz leaks only PstError; 17/17 mutants caught. Four documented divergences, two of them where the spec says MUST and upstream is lenient. |
| P01-HEADER | ✅ 2026-09-15 | `ndb/header.py` + `ndb/root.py`, `debug header` dumper, `tests/corrupt.py` seed. Goldens 7/7 Unicode stores (text and values), ANSI refused 2/2 on real bytes, private stores match the live oracle 2/2 (structure only), 110 denial cases incl. truncation at every 8-byte boundary, 30/30 mutants caught; upstream's magic twin landed. Validates exactly upstream's set; wVer 36/37 (4 KB pages) refused as unsupported. |
| P11-LIMITS | ✅ 2026-09-15 | `limits.py`: 15 ceilings each justified from [MS-PST] field widths or Outlook's documented caps (MAX_ITEMS raised to 2^27 = the 27-bit node index — a 50 GiB store's BBT alone exceeds the draft's 1e6), frozen `Limits`, `check_depth/count/allocation`, bounded `VisitedSet`; PstLimitError proven disjoint from PstFormatError; 32 tests, 18/18 mutants caught. Not yet wired into any walk — that is P02+. |
| P28-SPEC-VECTORS | ✅ 2026-09-15 | `tests/spec/`: 7 modules, 128 items, ~120 values typed verbatim from [MS-PST]/[MS-OXRTFCP]/[MS-OXCDATA]/[MS-DTYP] and ~60 derived; full key and CRC tables compared byte-for-byte; 24/24 mutants caught. Found: MV_GUID spec-vs-upstream (pinned xfail); corpus stores violate spec MUSTs upstream ignores (wSig=0 in pstd-inline-cid, qwUnused, rgbFM fill) — pinned as known deviations so P01/P02 do not enforce them. |
| P20-SYNTH | ✅ 2026-09-15 | `scripts/get_fixture_tools.sh` + `make_fixture.py` over pinned EMLtoPST with a conformance patch (its TCINFO offsets and booleans were wrong — the same defect that makes upstream refuse `pstd-inline-cid`); `synth-basics.pst` (35 KB, 7 authored messages, byte-reproducible) is read by the oracle through `read_ipm_subtree` (only `read_search_updates` refuses: no search queue node); goldens captured; 44 content tests (8 wait on P08/P09), 8/8 mutants caught. |
| P02-BTREE | ✅ 2026-09-15 | `ndb/page.py` + `ndb/btree.py` incl. the density list; bounded iterative walks (VisitedSet, depth, counts) — first consumer of `limits.py`. `read_btrees` block tree byte-identical 7/7, node tree parsed-equal 7/7, DL 5/5 (+2 refused where upstream errors), private 2/2 live; 204 tests, 29/31 mutants red (2 equivalent). Checks exactly upstream's set (no signature/bid enforcement — pstd/synth stores write wSig=0); 4 documented divergences. |
| P14-CI-ORACLE | 🔶 2026-09-15 | `.github/workflows/nightly-oracle.yml` + `scripts/nightly_oracle_local.sh` (single source of truth: fetch, build, parity, goldens `--check`, dump_messages when present, synthetic-fixture regen, live-oracle tests; failure-only artifact of the golden diff). Local `SKIP_RUST=1` run green; 7 tests. **Unproven until the first scheduled/dispatched run** (cargo on the runner, cache ordering, 45-min budget). |
| P19-ORACLE-DUMP | ✅ 2026-09-15 | `oracle/` crate + `dump_messages` example (links the pinned crate, copies nothing): folders, messages, recipients, attachments, body lengths+CRCs, embedded-message recursion; goldens 10/10 fixtures, deterministic; 45 tests. **Found an upstream bug at the pin:** `PropertyType::try_from` lacks `PtypObject` (0x000D), so upstream cannot open any embedded-message attachment — the oracle cannot arbitrate that case (see P09). Also: upstream reads both ANSI stores and opens `pstd-inline-cid` at message level. |
| P12-FUZZ | ✅ 2026-09-16 | `tests/corrupt.py` mutation generator (8 families, ~400–470 mutations per base store, seeded, deterministic) + `corruption_harness.py` (LEAK/TYPE/SILENT/HANG verdicts, watchdog) + `scripts/fuzz_sweep.py`. 18,527 mutations × header/BTree/DL entry points: **0 leaks, 0 hangs, 0 wrong types.** 67 tests (+~5 s); P03/P04 mutation stubs importorskip-guarded. |
| P03-BLOCK | ✅ 2026-09-16 | `ndb/block.py`: data blocks, XBLOCK/XXBLOCK trees, SLBLOCK/SIBLOCK sub-node trees, `BlockReader.node_data` — the first real bytes out of a real file; `debug btrees` now prints the full upstream output, `debug node` gives length+CRC without content. Goldens **byte-identical 8/8**, private 2/2 per node live, ~45 denial cases incl. the size-boundary trap and 4 GiB lcbTotal refused before any read, 33/35 mutants red. Matches exactly upstream's trailer checks (no wSig). P12's block stubs now live. |
| P04-HEAP | ✅ 2026-09-16 | `ltp/heap.py` (`HeapId`/`HeapNodeId` distinct types, `HeapNode.from_node`, `get`/`get_hnid` incl. the sub-node arm) + `ltp/tree.py` (`HeapTree` iteration/`find`); `BlockReader.read_data_blocks`; `debug heap`, `debug bth`. Store-PC BTH == `read_store_props` key-for-key on 7/7 goldens, every heap-borne value decodes to the golden's value; row-index keys == golden `Row:` ids; NID 0x61 entry stream 8× the golden count on 8/8; private 2/2 structure-only. 261 tests, 27 mutants all red after one boundary test was added; `heap_lies` family (22 lies) in the corruption sweep; P12's P04 stubs live. Divergences documented: undecodable BTH tail/typed record HID → `PstFormatError` (the P19 upstream bug), offsets past the block and freed items refused. |
| P05-PC | ✅ 2026-09-16 | `ltp/prop_context.py`: `PropertyRecord`, `PropertyContext` (`records`, `get`, `__iter__`, `from_node`), `debug pc`; `ObjectRef.node` is a `NodeId`; golden parsers for `read_store_props`/`read_named_props`/root+IPM PCs complete. `read_store_props` **byte-identical 7/7** complete goldens (pstd-inline-cid: oracle exits before printing, ours reads all 12); named props value-for-value 8/8 (964 entries, exercises the sub-node HNID arm); private 2/2 structure-only, 98 PCs surveyed with no non-`PstError` escape. MV_GUID settled: none in corpus or private stores, upstream's count-prefixed reading and P22's pin stand, with a standing survey test. 116 tests, `pc_lies` family (14/13 lies), 26 mutants 24 red (2 equivalent, named). PtypNull→None, PtypObject decoded (documented divergence), repeated prop id and typed fixed-width HNID refused. |
| P24-CONTRACT | ✅ 2026-09-16 | `tests/contract.py` + `tests/test_contract.py`: the `PstError`-or-nothing harness discovers every public entry point by `pkgutil` walk + `__all__` + public methods along the MRO (**155 entry points / 17 modules: 85 adapters, 26 named exclusions, 44 by rule**; anything unplaced turns the suite red, which is how P04's and P05's points were caught on rebase). Swept: corpus × default limits, every ceiling = 1, `max_file_size` = 1, every ceiling = `sys.maxsize` (must equal default reader-for-reader), 433 mutations non-slow, **11,971 mutations × 85 adapters** slow, 7 dumpers × 15 stores as subprocesses. **0 leaks, 0 hangs**, no xfail pinned. `pypst.__all__` sorted and asserted. 47 tests; 7 deliberate breakages confirmed red. |
| P06-TC | ✅ 2026-09-16 | `ltp/table_context.py`: TCINFO, `ColumnDescriptor`, row index, row matrix (heap and **sub-node** arms; javalibpst-dist-list is the sub-node witness), existence bitmap (absent ≠ None), `TableContext`/`TableRow`, `debug tc`; `HeapNode.get_hnid_blocks`. `debug tc` **byte-identical to both table goldens on 8/8** Unicode stores (16 tables); pstd-inline-cid is refusal parity (oracle and port both refuse its TCINFO's 5-byte bitmap at the same check, exit 1); private 2/2 structure-only (100 TCs, 398 cells, prebuilt oracle agrees on ids/columns/absent cells). 151 tests, `tc_lies` (25/base), 32 mutants 29 red (3 equivalent, named). Divergences: `rgib[TCI_4b]` ≥ 8 (upstream underflows), zero cell HNID → None (upstream kills the table), duplicate row id / index past matrix refused; a partial trailing row is padding and dropped per spec. Harness: 176 entry points / 18 modules, 101 adapters, 12,571 mutations × 101 adapters, 0 leaks. |
| P07-STORE | ✅ 2026-09-16 | `messaging/store.py` (`EntryId`, `Store.open`/borrowing ctor, `display_name`, `ipm_subtree`, `wastebasket`/`finder` as `EntryId \| None`, `named_properties`, `get`, `entry_id`, `matches_record_key`) + `messaging/named_prop.py` (`NamedPropertyMap`, `NameIdEntry`, `NamedPropertyGuid`, `lookup`/`resolve`/`hash_entry`/`hash_bucket`), `pypst.open`/`Store` exported, `debug store`, `debug named_props`. **Decision:** an absent wastebasket/finder entry id is tolerated (upstream's *library* opens pstd-inline-cid; only its examples refuse), pinned from both sides. **Upstream bug found:** `hash_entry` clears `wGuid`, mis-bucketing every string-named property; the port keeps it and all 964 corpus entries land in their written bucket. Dumpers byte-identical incl. exit status on 8/8 Unicode stores; private 2/2 structure-only (419 named props). 194 cases, `store_lies` (9–11) + `named_prop_lies` (12–16), 30/30 mutants red; harness +20 adapters, 0 leaks. |
| P08-FOLDER | ✅ 2026-09-16 | `messaging/folder.py`: `Folder` (own PC, hierarchy/contents/associated tables derived from the NID, `display_name` refusing a null name for parity, `entry_id`/`folder_type`, `subfolders()`, `message_ids()`/`associated_ids()`/`contents()`, iterative `walk()` bounded by new `limits.max_folder_depth` 64 + `VisitedSet`), `Store.root_folder`/`open_folder`, `debug folders`, `parse_dump_messages` folder blocks. `debug folders` **byte-identical 7/8** to the folder blocks of `dump_messages.txt` (63 folders; synth-basics differs on 6 `Associated Count` lines → P06b-EMPTY-TC), value-for-value 8/8 incl. contents-row ids vs the golden's `Message:` blocks; private 2/2 byte-identical to the prebuilt oracle (50 folders, structure only). 152 cases, `folder_lies` (12/base), **32/32 mutants red**; harness +14 adapters, entry points `folder.walk` + `folder.tables`, 0 leaks. Divergence: a table node that exists but will not parse is a refusal, not `None`. |
| P06b-EMPTY-TC | ✅ 2026-09-16 | `TableContextInfo.check_row_header_fits()` now runs only when the row matrix has rows (synth-basics' empty associated table has one column and `hnidRows = 0`); refusal still pinned for a non-empty matrix, acceptance pinned for an empty one, `tc_lies` unaffected. P08's folder dump is **byte-identical 8/8**. |
| P09-MESSAGE | ✅ 2026-09-16 | `messaging/message.py` (`Message`: class, `subject`/`subject_raw`/`subject_prefix`/`normalized_subject` with `split_subject`, sender name/email/SMTP, times as FILETIME + `datetime`, the three bodies + RTF decompression via P21, `transport_headers`, `recipients()`, `attachments()`), `messaging/attachment.py` (`Attachment`, `AttachMethod`, `data()`, `embedded_message()` depth-bounded), `Store.open_message`, `Folder.messages()`/`associated()`, `debug messages`, full `parse_dump_messages`. `debug messages` **byte-identical incl. exit status on 8/8** Unicode stores (after P06b) and 2/2 private (prebuilt oracle, structure only); 13 message blocks value-for-value. **Divergence:** embedded messages open here (3/3 in corpus; submessage's is an `IPM.Note` with the expected subject/body) where upstream refuses — and a **second upstream bug**: the embedded message lives in the *attachment's* sub-node tree, not the owning message's where `AttachmentInner::read` looks. 107 cases, `message_lies`/`attachment_lies`, **41/41 mutants red**, harness 0 leaks. Transport headers (for P10): 6/12 openable corpus messages, 1/1 private — by class (delivered `IPM.Note`s have them). synth-basics' Inbox is unreadable by both readers (EMLtoPST HNPAGEMAP `cFree` bug → P20 fixture follow-up, 6 strict xfails). |

## Still the user's call

- **Scope of P10.** EML per message is the assumed deliverable. If the real
  target is MBOX (one file per folder) or JSON, say so before P09 — it changes
  what P09 must extract, not just how it is formatted.
- **Apache-2.0 fixtures.** ADR-0004 admits them (7 of the 8 corpus stores).
  If the corpus must be MIT/public-domain only, the pstsdk, Tika and
  java-libpst stores come out and P20 (synthetic fixtures) becomes priority 1.
- **An upstream issue?** P19 found that `microsoft/outlook-pst-rs` at the pin
  cannot open embedded-message attachments (`PtypObject` missing from
  `PropertyType::try_from`, and `HeapTreeInner::entries` stops silently at the
  first undecodable record). Filing that upstream is outward-facing and yours
  to decide; the port will support PT_OBJECT regardless, as a documented
  divergence arbitrated by the spec and `pstsdk-submessage.pst`.
- **The EMLtoPST patch.** `scripts/patches/emltopst-oracle-conformance.patch`
  necessarily contains fragments of EMLtoPST's source. That project says MIT
  in its README but ships no LICENSE file (checked at the pin and at every
  commit). The generated store is our own work and the tool is never
  redistributed; the patch is the only thing that carries its text. If that
  is not comfortable, the alternative is to upstream the patch to EMLtoPST
  and pin the merged commit, or to rewrite the generator ourselves (P20b).
- **Dev-only dependencies** (P25, P26): `hypothesis`, `pytest-cov`. Runtime
  stays at zero either way.
