# pypst — MasterToDo

Unfinished work only. Resume: read this, `git log --oneline -15`, then the
`todo/` file the top unblocked row links to. Landing check before touching a
row: `git log --oneline | grep -i <ID>`.

| | |
|---|---|
| How to port (read FIRST) | `.claude/skills/rust-port/SKILL.md` |
| Layer order and costs | [`docs/PORTING-PLAN.md`](docs/PORTING-PLAN.md) |
| Task files | [`todo/`](todo/) — rules + one file per cluster |
| Binding decisions | [`docs/adr/`](docs/adr/) |
| Upstream pin | [`docs/UPSTREAM.txt`](docs/UPSTREAM.txt) |

Branch `main`. One commit per row, message starts with the id; done ONLY with
verification recorded on the row (a test count, an oracle diff, a sha); ✗ cases
before ✓ cases; mail stores never committed; zero runtime dependencies;
fail closed; `git commit -F msg -- <paths>`.

## Priority key

1–2 high · 5 medium · 10 low · 11 backlog (do not start; revisit later).
A row is sized for ONE opus sub-agent session. Rows too big for that say so and
name their split.

## Open

| Id | Pri | State | One line | Work |
|---|---|---|---|---|
| P01-HEADER | 1 | ✗ not started | `ndb/header.py` — parse the PST header, both ANSI and Unicode, CRC-verified. The first layer the oracle can contradict, and the decision point for the ANSI/Unicode strategy. | [`todo/T01-ndb.md`](todo/T01-ndb.md#p01-header) |
| P02-BTREE | 1 | ✗ blocked on P01 | `ndb/page.py` + `ndb/btree.py` — the node and block B-trees, with a depth limit and a cycle guard that upstream does not need. | [`todo/T01-ndb.md`](todo/T01-ndb.md#p02-btree) |
| P03-BLOCK | 2 | ✗ blocked on P02 | `ndb/block.py` — data blocks, XBLOCK/XXBLOCK trees, subnode BTrees; wire in the already-ported `encode.py` and `crc.py`. First point at which real bytes come out of a real file. | [`todo/T01-ndb.md`](todo/T01-ndb.md#p03-block) |
| P04-HEAP | 2 | ✗ blocked on P03 | `ltp/heap.py` + `ltp/tree.py` — heap-on-node and the BTree-on-heap. | [`todo/T02-ltp.md`](todo/T02-ltp.md#p04-heap) |
| P05-PC | 2 | ✗ blocked on P04 | `ltp/prop_context.py` + `ltp/prop_type.py` — property contexts and the MAPI property-type decoders (the long tail: PT_UNICODE, PT_BINARY, PT_MV_*, PT_SYSTIME). | [`todo/T02-ltp.md`](todo/T02-ltp.md#p05-pc) |
| P06-TC | 2 | ✗ blocked on P04 | `ltp/table_context.py` — table contexts. The largest single upstream file (1,158 lines) and the one most worth splitting if it overruns a session. | [`todo/T02-ltp.md`](todo/T02-ltp.md#p06-tc) |
| P07-STORE | 5 | ✗ blocked on P05 | `messaging/store.py` + `messaging/named_prop.py` — the message store and the named-property map. | [`todo/T03-messaging.md`](todo/T03-messaging.md#p07-store) |
| P08-FOLDER | 5 | ✗ blocked on P06,P07 | `messaging/folder.py` — the folder hierarchy and its contents tables. First point at which "open a PST and list the mail" works end to end. | [`todo/T03-messaging.md`](todo/T03-messaging.md#p08-folder) |
| P09-MESSAGE | 5 | ✗ blocked on P08 | `messaging/message.py` + `attachment.py` — message properties, bodies, recipients, attachments. | [`todo/T03-messaging.md`](todo/T03-messaging.md#p09-message) |
| P10-EML | 5 | ✗ blocked on P09 | The RFC-822 assembler: one message → one `.eml` via `email.message.EmailMessage`. **The actual deliverable** — everything above it is plumbing. Measure header survival before designing it (see the row's note on `InternetHeaders`). | [`todo/T03-messaging.md`](todo/T03-messaging.md#p10-eml) |
| P11-LIMITS | 2 | ✗ not started, do alongside P02 | The limits module: recursion depth, allocation ceiling, item counts, and `PstLimitError` everywhere they bite. A deliberate divergence from upstream — see CLAUDE.md § untrusted input. | [`todo/T04-hardening.md`](todo/T04-hardening.md#p11-limits) |
| P12-FUZZ | 5 | ✗ blocked on P03 | Corruption suite: truncated files, lying lengths, cyclic BTrees, bad CRCs, a 4 GB claim in a 265 KB file. Denial-first, built from bytes we write ourselves — needs no licensable PST. | [`todo/T04-hardening.md`](todo/T04-hardening.md#p12-fuzz) |
| P13-ANSI | 10 | ✗ deferred, decided at P01 | Whether ANSI (pre-2003) stores are supported at all. Dropping them removes ~480 upstream references and a whole generic axis; supporting them is cheap only if decided at P01, expensive if retrofitted. | [`todo/T01-ndb.md`](todo/T01-ndb.md#p13-ansi) |
| P14-CI-ORACLE | 10 | ✗ not started | Teach CI to build the Rust oracle and run the differential suite on a schedule (it is too slow for every push). | [`todo/T05-infra.md`](todo/T05-infra.md#p14-ci-oracle) |
| P15-PERF | 11 | ✗ backlog | Profile against a large store (the 140 MB and 179 MB ones, kept outside the repo). Do not optimise before P10 works. | [`todo/T05-infra.md`](todo/T05-infra.md#p15-perf) |
| P16-PUBLISH | 11 | ✗ backlog | PyPI release: name check, trove classifiers, wheel build, and a README that does not overclaim what is implemented. | [`todo/T05-infra.md`](todo/T05-infra.md#p16-publish) |

## Done

| Id | State | One line |
|---|---|---|
| P00-SCAFFOLD | ✅ 2026-09-15 | Repo scaffold: uv env, pytest, ruff ratchet, provenance lint, fixture policy + pre-commit guard, pinned upstream fetch + oracle scripts, CI, ADRs 0001–0002, skills. 23 tests green. |
| P00-ENCODE | ✅ 2026-09-15 | `encode.py` + `_tables.py` — permutative (via `bytes.translate`) and cyclic encodings, key table mechanically extracted with three invariants proven, upstream's own test vectors reproduced. |
| P00-CRC | ✅ 2026-09-15 | `crc.py` — 335 upstream lines reduced to one `zlib.crc32` call, proven equal to the naive table walk over 400 random pairs. |

## Still the user's call

- **P13-ANSI.** Support pre-2003 ANSI stores, or Unicode only? Unicode-only is
  materially less work and covers every store Outlook has written since 2003.
  Decide at P01; retrofitting later is the expensive path.
- **Scope of P10.** EML per message is the assumed deliverable. If the real
  target is MBOX (one file per folder) or JSON, say so before P09 — it changes
  what P09 must extract, not just how it is formatted.
