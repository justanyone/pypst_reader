# T03 — the messaging layer, and the thing we are actually building

~3,300 upstream lines, and the thinnest of the three clusters: by the time LTP
works, a message is mostly a property context with well-known property ids.

### P07-STORE
status: ✗ not started
upstream: `crates/pst/src/messaging/store.rs` (602), `messaging/named_prop.rs` (599)
oracle:   `scripts/oracle.sh read_store_props`, `scripts/oracle.sh read_named_props`
blocked on: P05

**A decision this row must make explicitly:** `pstd-inline-cid.pst` (a
Unicode store written by EMLtoPST, not Outlook) has no
`PidTagIpmWastebasketEntryId`, and upstream refuses the whole store for it
(see its goldens: exit 1 on every store-level example). Refuse identically
with a named `PstFormatError`, or read it and report the gap? Either is
defensible; write the choice in the module docstring as a divergence if it
is the second, and test it either way.

The message store object (the PST's root properties, including the display name
and the IPM subtree entry id) and the named-property map that translates
GUID+name pairs into property ids in the 0x8000+ range.

**Why named properties matter more than they look:** every interesting
Outlook-specific property (conversation index, internet headers on some stores)
lives behind this map. A reader without it silently cannot see them.

### P08-FOLDER
status: ✗ not started
upstream: `crates/pst/src/messaging/folder.rs` (371)
oracle:   `scripts/oracle.sh read_ipm_subtree tests/fixtures/Empty.pst`
blocked on: P06, P07, P19 (its oracle)

The folder hierarchy: a folder is a PC for its own properties plus three TCs
(hierarchy, contents, associated contents). Walk from the IPM subtree.

**Done means:** your folder walk matches P19's `dump_messages` goldens on
every corpus fixture the oracle reads (folder ids, names, counts, order). This is the first
end-to-end "it reads PSTs" moment.

### P09-MESSAGE
status: ✗ not started
upstream: `crates/pst/src/messaging/message.rs` (480), `messaging/attachment.rs` (427)
oracle:   P19's `dump_messages` goldens; `pstsdk-submessage.pst` for the embedded case, `tika-variousBodyTypes.pst` for the three body kinds
blocked on: P08, P21 (RTF bodies)

Message properties (subject, sender, times, body in plain/HTML/RTF form),
recipients (a TC on a subnode), and attachments (each its own subnode with its
own PC, possibly containing an embedded message).

**The oracle cannot see embedded messages — P19's finding.** Upstream at the
pin has no `PtypObject` arm in `PropertyType::try_from`, and its BTH walk
stops silently at the first undecodable record, so every embedded-message
attachment (`PidTagAttachDataObject`, 0x3701) fails upstream with
`AttachmentMethodNotFound`; `dump_messages` goldens carry the attachment
row (`method=5 … size=11494` on `pstsdk-submessage`) and then an `Error:`.
This row supports PT_OBJECT (P22 decodes it) as a **documented divergence**,
arbitrated by [MS-PST] 2.3.3.4 + 2.4.6.3 and by the bytes of
`pstsdk-submessage.pst` (the embedded message's own subject and body must
decode to sensible text — assert on it, it is public). Pin a test that the
golden shows upstream's refusal so a fixed pin is noticed.

**Two traps worth knowing before you start:**
- **Compressed RTF.** Bodies are often stored as RTF compressed with the LZFu
  scheme. That is P21 (`rtf.py`), a leaf row that lands before this one; here
  you only call it.
- **Subject prefixes.** PR_SUBJECT carries a control-character prefix encoding
  where the "Re:"/"Fw:" ends. Strip it deliberately or subjects come out with a
  stray `\x01`.

### P10-EML
status: ✗ not started
upstream: nothing — **this is ours**, and the module docstring must say `not a port`
oracle:   none; this is where we stop having one
blocked on: P09

One message → one RFC-822 `.eml`, via `email.message.EmailMessage` from the
standard library. The deliverable everything else exists to enable.

**Measure before you design.** The header question decides the shape of this
module: a message that travelled over SMTP has its internet headers
(`Message-ID`, `In-Reply-To`, `References`) retained as a property; one composed
in Outlook and never sent may have none. Before writing the assembler, count —
over the private stores — how many messages carry real internet headers.

- If most do: pass them through, and synthesise only what is missing.
- If few do: synthesise from the MAPI properties (`PR_INTERNET_MESSAGE_ID`, the
  conversation properties) and **say in the output that they were synthesised**.
  A reconstructed `Message-ID` that is presented as original corrupts every
  downstream threading decision made from it.

Record the measurement in the row. It is the one number that makes this module
designable.

### P21-RTF
status: ✅ 2026-09-15 — `src/pypst/rtf.py` + generated `_rtf_dictionary.py` (207 bytes, extracted by `scripts/extract_rtf_dictionary.py`, three invariants: length, equals the [MS-OXRTFCP] 2.1.2.1 string, CRC-32 0x2E98875B; `--check` green). 51 new test functions / 94 cases, all green (+1 strict xfail waiting on P09): 4/4 upstream parity twins in `tests/parity/test_rtf_parity.py`; [MS-OXRTFCP] 3.1.1, 3.1.2, 3.2.1, 3.2.2 vectors typed from the spec pages match 4/4 (decompress and byte-exact compress); spec CRC example 3.3.1 = 0xA7C7C5F1 by both the spec walk and `zlib.crc32`; all 256 entries of upstream's crc.rs table = the CRC-32 polynomial table; round trip `decompress(compress(x)) == x` over 14 sizes × 3 seeds (0–9000 bytes, across the 4096 wrap) plus long repeats, every byte value and random bytes; 1500-mutation fuzz leaks nothing but `PstError`. Denial cases asserted by type: truncated header (15 lengths), COMPSIZE mismatch (6), unknown COMPTYPE (6), CRC mismatch (4), half token, missing terminator, reference into unwritten dictionary (3), RAWSIZE > limit and output > limit as `PstLimitError` not `PstFormatError`. Every test seen red under 17 deliberate single-point bugs, then restored. Deliberate divergences from upstream (all in the module docstring): end of payload before the terminator is refused (spec 2.2.3.2 MUST), reference into unwritten dictionary is refused, output size capped not just RAWSIZE, no NUL trimming.
upstream: `crates/compressed-rtf/src/lib.rs` (245), `dictionary.rs` (215), `crc.rs` (48 — a plain CRC32, `zlib.crc32` again)
oracle:   the four `#[test]` vectors in `lib.rs`, which are [MS-OXRTFCP] §4's worked examples
blocked on: none

`rtf.py`: `decompress_rtf(data: bytes) -> bytes` for the LZFu scheme
([MS-OXRTFCP]): the 16-byte header (`COMPSIZE`, `RAWSIZE`, `COMPTYPE` =
`LZFu`/`MELA`, `CRC`), the 4096-byte circular dictionary pre-loaded with the
207-byte initial string (transcribe it **mechanically** from upstream's
`dictionary.rs` with a script that asserts its length and CRC, the way
`_tables.py` was made), the control-byte/token loop, and the CRC check over
the compressed payload. `MELA` (uncompressed) is the trivial case. A CRC
mismatch, a `RAWSIZE` larger than the limit, or a token reaching outside the
dictionary is `PstFormatError` / `PstLimitError`, never an `IndexError`.

Compression is not needed by a reader — **but port it anyway** into a
`tests/`-only helper: upstream's compress tests are parity tests (P18), and
`decompress(compress(x)) == x` over random RTF-ish input is the property test
that actually finds the token-boundary bugs.

**Done means:** the 4 upstream vectors pass as parity twins; the same vectors
typed from [MS-OXRTFCP] §4 pass (P28's tier); the round-trip property holds;
and a body from `tika-variousBodyTypes.pst` decompresses to text that starts
with `{\\rtf1` once P09 can hand it over (leave that test `xfail(reason="P09")`).
