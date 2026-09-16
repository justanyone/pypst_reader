# T03 — the messaging layer, and the thing we are actually building

~3,300 upstream lines, and the thinnest of the three clusters: by the time LTP
works, a message is mostly a property context with well-known property ids.

### P07-STORE
status: ✗ not started
upstream: `crates/pst/src/messaging/store.rs` (602), `messaging/named_prop.rs` (599)
oracle:   `scripts/oracle.sh read_store_props`, `scripts/oracle.sh read_named_props`
blocked on: P05

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
blocked on: P06, P07

The folder hierarchy: a folder is a PC for its own properties plus three TCs
(hierarchy, contents, associated contents). Walk from the IPM subtree.

**Done means:** you can print the folder tree of a real store with the same
names and message counts the oracle's `browse_pst` TUI shows. This is the first
end-to-end "it reads PSTs" moment.

### P09-MESSAGE
status: ✗ not started
upstream: `crates/pst/src/messaging/message.rs` (480), `messaging/attachment.rs` (427)
oracle:   `scripts/oracle.sh browse_pst <store>` (interactive — compare by hand)
blocked on: P08

Message properties (subject, sender, times, body in plain/HTML/RTF form),
recipients (a TC on a subnode), and attachments (each its own subnode with its
own PC, possibly containing an embedded message).

**Two traps worth knowing before you start:**
- **Compressed RTF.** Bodies are often stored as RTF compressed with the LZFu
  scheme. Upstream has a whole second crate for it (`crates/compressed-rtf`,
  508 lines) — port it here, not earlier; it has a 207-entry static dictionary
  that must be transcribed mechanically, like `_tables.py` was.
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
