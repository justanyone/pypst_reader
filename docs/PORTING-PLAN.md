# The porting plan

What is being ported, in what order, and what each layer costs. Measured
against `microsoft/outlook-pst-rs` at the pin in [UPSTREAM.txt](UPSTREAM.txt).

## What we are porting

The **read path only**. Upstream is explicit that it does not implement PST
modification, and we do not want it: 106 `fn write` against 180 `fn read` in
the crate, and the write halves are serialization traits a reader never calls.

## The size of the job, measured

| upstream | lines | character | rows |
|---|---|---|---|
| `ndb/` — pages, blocks, header, BTrees | ~6,600 | bulk; mechanical; struct-shaped | P01–P03 |
| `ltp/` — heap, tree, property & table contexts | ~3,700 | fiddly; where subtle wrongness lives | P04–P06 |
| `messaging/` — store, folder, message, attachment | ~3,300 | thin; the layer you actually want | P07–P09 |
| `crc.rs` + `encode/` | ~500 | **done** — collapsed to ~120 lines of Python | ✅ |
| `compressed-rtf` (separate crate) | 508 | needed for RTF bodies | P09 |
| **total** | **~15,400** | read path is roughly two thirds | |

Python is denser, and two of the hottest modules collapse rather than
translate. Realistic target: **5,000–7,000 lines of Python.**

## Why this order

Bottom-up, because each layer is only testable once the one below it works, and
because **each layer has an oracle binary that contradicts it**:

```
ids ──► header ──► BTrees ──► blocks ──► heap/BTH ──► PC/TC ──► store ──► folder ──► message ──► EML
P23   P01        P02        P03        P04        P05/06     P07       P08        P09       P10
read_header  read_btrees  read_density  read_root  read_store  read_named  read_ipm  browse_pst
```

The one row that does **not** wait for its predecessor is P11 (limits): it
lands alongside P02, because a cycle guard retrofitted onto a finished walk is
a rewrite of that walk.

## The method

Not "read the Rust and write Python". **Port a layer, run both over the same
bytes, diff.** The protocol, including the ways it can fool you, is in
`.claude/skills/rust-port/SKILL.md`. In short:

```bash
scripts/oracle.sh read_header tests/fixtures/Empty.pst > /tmp/rust.txt
python -m pypst.debug header tests/fixtures/Empty.pst > /tmp/py.txt   # you write this
diff /tmp/rust.txt /tmp/py.txt
```

## Where the port deliberately differs from upstream

Four places, each for a reason that does not apply to Rust:

1. **`bytes.translate` instead of a byte loop** for permutative decoding
   (already landed). Two orders of magnitude, and shorter.
2. **`zlib.crc32` instead of slicing-by-8** (already landed). 335 lines → 1.
3. **Explicit limits and cycle guards** (P11). Rust's bounds checks make a
   panic survivable; an unbounded Python loop is a hang.
4. **No ANSI support** (ADR-0003). Upstream carries a whole generic axis
   for pre-2003 stores; this package refuses them and a sibling
   `pypst_reader_nu` (P27) would carry that axis instead.

Every divergence is recorded in the diverging module's docstring. An
unexplained one reads as a porting bug to the next person.

## What we test against

The **public corpus** (`tests/fixtures/public/`, ADR-0004): eight licensed,
hash-pinned stores — Microsoft's PST SDK samples (including an embedded
message and two ANSI stores kept for the refusal test), Tika's three-body-type
store, java-libpst's twelve-folder store, and a 29 KB synthetic MIT one — plus
`Empty.pst`. The Rust oracle's output over each is committed as goldens
(`tests/golden/`), so **every layer up to messages is provable in CI with no
Rust toolchain.** The private stores in `tests/fixtures/private/` add
structure-only coverage of real Outlook output, locally.

What the corpus does not cover, and what fills it: content assertions on
known mail (P20, synthetic fixtures we author); a non-interactive
message-level oracle (P19, since upstream's is a TUI); hostile input (P12,
built from bytes we mutate ourselves). The tiers are in `docs/TEST-PLAN.md`.
