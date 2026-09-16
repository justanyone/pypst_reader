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
| P23-IDS | 1 | ⏳ in flight — agent/p23-ids 2026-09-15 | `ndb/ids.py` + `block_sig.py` — the packed value types every layer above uses: `NodeId` (type + index), `BlockId` (internal bit + index), `ByteIndex`, `PageId`, `BlockRef`/`PageRef`, and `compute_sig`. Small, has 4 upstream tests, unblocks P01 and P02. | [`todo/T00-foundation.md`](todo/T00-foundation.md#p23-ids) |
| P01-HEADER | 1 | ✗ blocked on P23 | `ndb/header.py` + `ndb/root.py` — parse the Unicode PST header, CRC-verified; **refuse ANSI** with `PstUnsupportedError` (ADR-0003). Done = `read_header` goldens match on 7/7 Unicode fixtures, 2/2 ANSI refused, corrupted copies refused. | [`todo/T01-ndb.md`](todo/T01-ndb.md#p01-header) |
| P02-BTREE | 1 | ✗ blocked on P01 | `ndb/page.py` + `ndb/btree.py` — the node and block B-trees, with a depth limit and a cycle guard that upstream does not need. | [`todo/T01-ndb.md`](todo/T01-ndb.md#p02-btree) |
| P11-LIMITS | 2 | ✗ not started — land WITH P02 | `limits.py`: recursion depth, allocation ceiling, item counts, `PstLimitError` everywhere they bite. Deliberate divergence — CLAUDE.md § untrusted input. | [`todo/T04-hardening.md`](todo/T04-hardening.md#p11-limits) |
| P03-BLOCK | 2 | ✗ blocked on P02 | `ndb/block.py` — data blocks, XBLOCK/XXBLOCK trees, subnode BTrees; wire in `encode.py` and `crc.py`. First point at which real bytes come out of a real file. | [`todo/T01-ndb.md`](todo/T01-ndb.md#p03-block) |
| P21-RTF | 2 | ⏳ in flight — agent/p21-rtf 2026-09-15 | `rtf.py` — port `crates/compressed-rtf` (LZFu decompression; 207-entry dictionary transcribed mechanically). 4 upstream tests + [MS-OXRTFCP] vectors. Needed by P09, independent of everything. | [`todo/T03-messaging.md`](todo/T03-messaging.md#p21-rtf) |
| P22-PROPTYPE | 2 | ⏳ in flight — agent/p22-proptype 2026-09-15 | `ltp/prop_type.py` — the MAPI property-type decoders as pure functions over bytes: PT_LONG…PT_SYSTIME (FILETIME→UTC datetime), PT_GUID, PT_UNICODE/STRING8, PT_BINARY, PT_MV_*. Unknown type → `PstUnsupportedError`. Split out of P05 so it can run now. | [`todo/T02-ltp.md`](todo/T02-ltp.md#p22-proptype) |
| P19-ORACLE-DUMP | 2 | ✗ not started | `oracle/dump_messages.rs` — our own non-interactive Rust example against the pinned crate: every folder, message, recipient, attachment, embedded message. Captured to goldens like the others. Replaces the `browse_pst` TUI as P08/P09's oracle. | [`todo/T06-testing.md`](todo/T06-testing.md#p19-oracle-dump) |
| P04-HEAP | 2 | ✗ blocked on P03 | `ltp/heap.py` + `ltp/tree.py` — heap-on-node and the BTree-on-heap. | [`todo/T02-ltp.md`](todo/T02-ltp.md#p04-heap) |
| P05-PC | 2 | ✗ blocked on P04, P22 | `ltp/prop_context.py` — property contexts over the P22 decoders. | [`todo/T02-ltp.md`](todo/T02-ltp.md#p05-pc) |
| P06-TC | 2 | ✗ blocked on P04 | `ltp/table_context.py` — table contexts. Largest LTP file; split if it overruns. | [`todo/T02-ltp.md`](todo/T02-ltp.md#p06-tc) |
| P12-FUZZ | 2 | ✗ blocked on P01 (grows with each layer) | `tests/corrupt.py` mutation generator + the corruption suite: truncation, lying lengths, cyclic BTrees, bad CRCs, a 4 GB claim in a 265 KB file. Denial-first. | [`todo/T04-hardening.md`](todo/T04-hardening.md#p12-fuzz) |
| P24-CONTRACT | 2 | ✗ blocked on P12 | The `PstError`-or-nothing harness: every public entry point × every corrupt file × every fixture; any other exception type is a failure. | [`todo/T06-testing.md`](todo/T06-testing.md#p24-contract) |
| P28-SPEC-VECTORS | 5 | ✗ not started (leaf) | `tests/spec/`: the worked byte examples in [MS-PST] and [MS-OXRTFCP], typed in from the spec rather than from upstream — the one tier that can catch a shared bug. | [`todo/T06-testing.md`](todo/T06-testing.md#p28-spec-vectors) |
| P20-SYNTH | 5 | ✗ not started | `scripts/make_fixture.py` over a pinned EMLtoPST (MIT, pure Python): authored `.eml` → hash-recorded PST with **known content**, so tests can assert what a message says. Admitted to the corpus only once the oracle reads it. | [`todo/T06-testing.md`](todo/T06-testing.md#p20-synth) |
| P25-HYPOTHESIS | 5 | ✗ not started | Decide (ADR paragraph) and add `hypothesis` as a dev-only dependency; first property tests over encode/crc/ids. | [`todo/T06-testing.md`](todo/T06-testing.md#p25-hypothesis) |
| P26-COVERAGE | 5 | ✗ not started | `pytest-cov` + a coverage floor ratchet beside the ruff ratchet. A number that may not go down, never cited as evidence of correctness. | [`todo/T06-testing.md`](todo/T06-testing.md#p26-coverage) |
| P07-STORE | 5 | ✗ blocked on P05 | `messaging/store.py` + `messaging/named_prop.py` — the store object and the named-property map. **Must decide** what to do with `pstd-inline-cid.pst`, which upstream refuses for a missing property. | [`todo/T03-messaging.md`](todo/T03-messaging.md#p07-store) |
| P08-FOLDER | 5 | ✗ blocked on P06, P07, P19 | `messaging/folder.py` — the folder hierarchy and its contents tables. First "open a PST and list the mail". | [`todo/T03-messaging.md`](todo/T03-messaging.md#p08-folder) |
| P09-MESSAGE | 5 | ✗ blocked on P08, P21 | `messaging/message.py` + `attachment.py` — properties, bodies (plain/HTML/RTF via P21), recipients, attachments, embedded messages (`pstsdk-submessage.pst`). | [`todo/T03-messaging.md`](todo/T03-messaging.md#p09-message) |
| P10-EML | 5 | ✗ blocked on P09 | The RFC-822 assembler: one message → one `.eml`. **The actual deliverable.** Measure header survival first. | [`todo/T03-messaging.md`](todo/T03-messaging.md#p10-eml) |
| P14-CI-ORACLE | 10 | ✗ not started | Nightly CI job: build the Rust oracle, run `capture_oracle.py --check` and the `oracle`-marked tests. Every-push CI stays Rust-free thanks to the goldens. | [`todo/T05-infra.md`](todo/T05-infra.md#p14-ci-oracle) |
| P31-MYPY | 10 | ✗ blocked on P06 | `mypy --strict` over `src/` once the LTP API has settled — the closest thing to the compiler upstream had. | [`todo/T06-testing.md`](todo/T06-testing.md#p31-mypy) |
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

## Still the user's call

- **Scope of P10.** EML per message is the assumed deliverable. If the real
  target is MBOX (one file per folder) or JSON, say so before P09 — it changes
  what P09 must extract, not just how it is formatted.
- **Apache-2.0 fixtures.** ADR-0004 admits them (7 of the 8 corpus stores).
  If the corpus must be MIT/public-domain only, the pstsdk, Tika and
  java-libpst stores come out and P20 (synthetic fixtures) becomes priority 1.
- **Dev-only dependencies** (P25, P26): `hypothesis`, `pytest-cov`. Runtime
  stays at zero either way.
