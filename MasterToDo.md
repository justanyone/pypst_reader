# pypstreader — MasterToDo

Unfinished work only. Everything that has landed is in
[`DoneFeatures.md`](DoneFeatures.md) — the build record, with the verification
that closed each row. Resume: read this, `git log --oneline -15`, then the
`todo/` file the top unblocked row links to. Landing check before touching a
row: `git log --oneline | grep -i <ID>`. **Working beside other agents: read
[`docs/AGENTS.md`](docs/AGENTS.md) first — claim the row before starting.**

| | |
|---|---|
| What has landed | [`DoneFeatures.md`](DoneFeatures.md) |
| How to port (read FIRST) | `.claude/skills/rust-port/SKILL.md` |
| Multi-agent protocol | [`docs/AGENTS.md`](docs/AGENTS.md) |
| Layer contracts (code against these) | [`docs/INTERFACES.md`](docs/INTERFACES.md) |
| What "tested" means here | [`docs/TEST-PLAN.md`](docs/TEST-PLAN.md) |
| Layer order and costs | [`docs/PORTING-PLAN.md`](docs/PORTING-PLAN.md) |
| Task files | [`todo/`](todo/) — rules + one file per cluster |
| Binding decisions | [`docs/adr/`](docs/adr/) |
| Upstream pin | [`docs/UPSTREAM.txt`](docs/UPSTREAM.txt) |

Branch `main`. One commit per row, message starts with the id; done ONLY with
verification recorded on the row (a test count, an oracle diff, a sha), then
the row moves to `DoneFeatures.md`; ✗ cases before ✓ cases; mail stores only
via the manifest (ADR-0004); zero runtime dependencies; fail closed; Unicode
only (ADR-0003); `git commit -F msg -- <paths>`.

## Where the project stands

**1.0.0 — production, released.** The read path is complete and every row that
built it is in [`DoneFeatures.md`](DoneFeatures.md). Nothing below blocks a
user: the rows that remain are developer tooling and future scope.

The port's own lanes (A the port, B leaf modules, C test infrastructure) are
closed. What is left does not need a lane table — the rows are independent and
none of them touches `src/pypstreader/`, except P31, which only annotates it.

## Priority key

1–2 high · 5 medium · 10 low · 11 backlog (do not start; revisit later).
A row is sized for ONE opus sub-agent session. Rows too big for that say so and
name their split.

## Open

| Id | Pri | State | One line | Work |
|---|---|---|---|---|
| P25-HYPOTHESIS | 5 | ✗ not started | Decide (ADR paragraph) and add `hypothesis` as a dev-only dependency; first property tests over encode/crc/ids. | [`todo/T06-testing.md`](todo/T06-testing.md#p25-hypothesis) |
| P26-COVERAGE | 5 | ✗ not started | `pytest-cov` + a coverage floor ratchet beside the ruff ratchet. A number that may not go down, never cited as evidence of correctness. | [`todo/T06-testing.md`](todo/T06-testing.md#p26-coverage) |
| P31-MYPY | 10 | ✗ unblocked — the messaging API it was waiting on settled at 1.0 and is now stable, so strict typing is no longer chasing a moving target; needs `mypy` as a dev dependency (user's call, with hypothesis/pytest-cov) | `mypy --strict` over `src/` once the LTP API has settled — the closest thing to the compiler upstream had. | [`todo/T06-testing.md`](todo/T06-testing.md#p31-mypy) |
| P15-PERF | 11 | ✗ backlog — unblocked (P10 landed) | Profile against a large store (outside the repo). | [`todo/T05-infra.md`](todo/T05-infra.md#p15-perf) |
| P27-NU | 11 | ✗ backlog | `pypstreader_nu` — a sibling package for ANSI (pre-2003) stores, ported from upstream's ANSI arms against `pstsdk-test_ansi.pst` and `pstsdk-sample2.pst`. Not before this package reads Unicode end to end. | [`todo/T05-infra.md`](todo/T05-infra.md#p27-nu) |

## Still the user's call

- **Scope of P10 — decided 2026-09-16.** Kevin: the main output format is the same as upstream's (upstream has none beyond its text dumps, which the port reproduces) with a slight preference for MBOX. P10 writes one mbox per folder, with per-message EML as the building block.
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
