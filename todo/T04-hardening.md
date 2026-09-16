# T04 — hardening, because the input is hostile

A PST arrives from a laptop image, a discovery production, an adversary. Every
offset, length and count in it is attacker-controlled. Python removes memory
corruption from the risk list and removes nothing else.

**This cluster is where the port deliberately diverges from upstream.** Say so
in each module's docstring, with the reason — an unexplained divergence reads
as a porting bug.

### P11-LIMITS
status: ✗ not started — land it WITH P02, not after
upstream: no direct equivalent (Rust's bounds checks make a panic survivable)
oracle:   none
blocked on: none, but meaningless before P02

A `limits.py` carrying the ceilings, and `PstLimitError` raised at each:

- **BTree depth** — a self-referential BTree must terminate, not hang.
- **Visited-node set** — cycle detection on every graph walk (NBT, BBT, BTH,
  subnode trees, embedded messages).
- **Total allocation** — a block claiming 4 GB inside a 265 KB file is refused
  before `bytearray(n)` is called, not after the machine swaps.
- **Item counts** — folders, messages, attachments, recipients.
- **Embedded-message depth** — an attachment containing a message containing an
  attachment, forever.

Every ceiling is a named constant with a default, overridable by the caller.
Refusal must be distinguishable from corruption: `PstLimitError`, never
`PstFormatError`, so a legitimately enormous store can be retried.

### P12-FUZZ
status: ✗ not started
upstream: none
oracle:   none — these files are not valid, so the oracle's behaviour on them
          is interesting but not authoritative
blocked on: P01 for the generator and the header mutations; each later layer adds its own mutations in its own row

The corruption suite. **Every input here is bytes we write ourselves**, which
is why this row needs no licensable PST and can be built the day P03 lands:

- `!BDN` magic and then nothing
- a valid header with a CRC that does not match
- a byte index pointing past EOF
- a block declaring a size larger than the file
- an NBT whose root page points at itself
- a BTH with a cycle
- an XXBLOCK tree 10,000 deep
- a `wVer` from the future

Each must raise a `PstError` subclass — named, specific, and *not* a
`struct.error`, `IndexError`, `MemoryError` or hang. Assert the exception type,
not just that something was raised.

Build these as a generator (`tests/corrupt.py`) that mutates a corpus store
(default `pstd-inline-cid.pst`, the smallest populated one; parametrise over
the Unicode corpus where cheap), so the suite grows by adding a mutation
rather than by checking in more binaries. P24 consumes the same generator.
