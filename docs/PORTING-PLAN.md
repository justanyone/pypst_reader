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
header ──► BTrees ──► blocks ──► heap/BTH ──► PC/TC ──► store ──► folder ──► message ──► EML
  P01        P02        P03        P04        P05/06     P07       P08        P09       P10
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
4. **Possibly no ANSI support** (P13). Upstream carries a whole generic axis
   for pre-2003 stores. Decide at P01.

Every divergence is recorded in the diverging module's docstring. An
unexplained one reads as a porting bug to the next person.

## What we do not have

**A rich test corpus.** `Empty.pst` is MIT and redistributable but holds no
mail, so it exercises the header and the BTrees and almost nothing above them.
The private stores in `tests/fixtures/private/` fill that gap locally and
cannot be shared, which means **CI can never prove the messaging layer** — only
a developer's machine can.

That is a real limitation, not a temporary one, and the mitigation is P12: the
corruption suite is built from bytes we write ourselves, so the *denial* half of
the test story runs everywhere even though the *success* half does not.
