# T03 — the messaging layer, and the thing we are actually building

~3,300 upstream lines, and the thinnest of the three clusters: by the time LTP
works, a message is mostly a property context with well-known property ids.

### P07-STORE
status: ✅ 2026-09-16 — `src/pypstreader/messaging/{__init__,store,named_prop}.py`; `pypstreader.open`, `pypstreader.Store` and `pypstreader.EntryId` exported. **Differential: byte-identical on 8/8 Unicode corpus stores, both examples.** `python -m pypstreader.debug store` == `read_store_props.txt` and `debug named_props` == `read_named_props.txt` for Empty, javalibpst-dist-list, pstd-inline-cid, pstsdk-sample1, pstsdk-submessage, pstsdk-test_unicode, synth-basics, tika-variousBodyTypes — stdout AND exit status, the exit-1 golden included. The same goldens re-read as values through `parse_read_store_props` / `parse_read_named_props`: every property id, display name, entry-id node, and all **964 named properties** (GUID, number-or-name, string/number split) over the 8 stores, which also equal P05's independent hand-rolled reconstruction entry for entry. Private stores (structure only, prebuilt binaries, no `cargo`): 2/2 agree with the live `read_store_props` and `read_named_props` on property ids, entry-id node types and 419 named properties. **70 new test functions / 194 cases**: `tests/test_store.py` (31 functions, 107 cases) and `tests/test_named_prop.py` (39 / 87), plus the harness work below. Whole suite `-m "not slow"`: 2053 passed, 20 skipped, 2 xfailed; slow lane (`-m "slow and not oracle"`, so no `cargo`): 4 passed in 11m38s. **30/30 deliberate single-point bugs seen red** (`PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider`, `__pycache__` cleared between mutants); the first pass left 2 survivors — an EntryID property *longer* than 24 bytes, and `Store.open` leaking its handle on refusal — and both now have a test that fails without the check. Denial by type: ANSI refused at `open` (2/2), empty file, every header field boundary (24 lengths), a renamed 0x21 node (`PstNotFoundError`), 0x21 pointed at a table context, every ceiling at 1 (`PstLimitError`, never `PstFormatError`), every EntryID shorter than 24 bytes (24 cases), non-zero `rgbFlags` (4), a record key that is not 16 bytes, a bucket count absent / not Integer32 / 0 with entries / past 0xEFFF / below its own buckets, ragged GUID and entry streams, `wPropIdx >= 0x8000`, duplicate `wPropIdx`, a GUID index past the stream, a string offset past the stream, an odd string length, a hash bucket the map does not hold (`PstNotFoundError`). `tests/corrupt.py` gained `store_lies` (9 on pstd-inline-cid, 11 on Empty) and `named_prop_lies` (12 / 16), and the corruption harness two entry points; `tests/contract.py` gained 20 adapters and one `NOT_STORE_INPUT` reason, 0 uncovered. Upstream has **no `#[test]` in either file**, so parity is 0 missing by construction (`check_upstream_parity.py`: 15 upstream tests, 14 twinned, 1 pending P27-NU, 0 missing).

**The decision, made: tolerate absence, and reproduce the example's refusal
in the dumper.** `pstd-inline-cid.pst` has no `PidTagIpmWastebasketEntryId`
and no `PidTagFinderEntryId`. The deciding evidence is that upstream's own
*library* opens it — `read_named_props` exits 0 on that store, only the
store-level examples exit 1 — so the refusal belongs to the example's
accessors, not to `open_store`. [MS-PST] 2.4.3.1 requires neither property.
So `Store.open` succeeds, `wastebasket` and `finder` are `EntryId | None`
(as `docs/INTERFACES.md` already typed them), `ipm_subtree` stays mandatory,
and `python -m pypstreader.debug store` refuses at exactly the point the example
does, so the golden's two lines and its exit 1 both reproduce. Written up as
a divergence in `pypstreader/messaging/store.py`'s docstring and pinned by
`test_the_pstd_inline_cid_decision_is_pinned`, by the byte-for-byte dumper
test, and by two `store_lies` mutations whose contract is that **nothing**
refuses them.

**An upstream bug found by the differential, and fixed here.**
`NamedPropertyMapProperties::hash_entry` rebuilds a string-named NAMEID as
`NameIdEntry::new(StringOffset(crc), NamedPropertyGuid::None, prop_index)`
— clearing `wGuid`. With it cleared, every string-named property hashes to
a bucket that does not hold it: 9 of Empty's 35 entries, 34 of
tika-variousBodyTypes' 56. Keeping `wGuid` puts all 964 entries of all 8
Unicode stores in the bucket the store actually wrote them to. Upstream
never notices because nothing in its read path calls `hash_entry`.
Divergence documented in `named_prop.py` and pinned by
`test_hash_entry_keeps_the_guid_where_upstream_clears_it` and
`test_every_entry_is_in_the_bucket_its_hash_names`.

Other divergences, each in its module docstring: an EntryID property must be
exactly 24 bytes (upstream ignores trailing bytes); store property values are
decoded on demand, not all at open; `Store.open` lets `OSError` through
(opening the *path* is the OS's business — the bytes are always a
`PstError`); a GUID or entry stream that is not a whole number of records is
refused where upstream's `while let Ok` silently drops the tail; a duplicate
`wPropIdx` is refused; a bucket count of 0 with entries (upstream divides by
it) or one smaller than the buckets present is refused; `stream_string()` is
not ported — its walk skips every other entry and nothing reads it.

Left for the rows above: `root_folder` / `open_folder` (P08) and
`open_message` (P09) are named in a comment in `Store` and are not stubbed.

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
status: ✅ 2026-09-16 — `src/pypstreader/messaging/folder.py`; `Store.root_folder` / `Store.open_folder`; `pypstreader.Folder` and `pypstreader.messaging.__all__` exported; `python -m pypstreader.debug folders`. **Differential: byte-identical on 7/8 Unicode corpus stores, and on 2/2 private stores.** `debug folders` == the folder blocks of `tests/golden/<fixture>/dump_messages.txt`, line for line — Empty (6 folders, 38 lines), javalibpst-dist-list (24/156), pstd-inline-cid (1/8), pstsdk-sample1 (7/46), pstsdk-submessage (6/38), pstsdk-test_unicode (6/38), tika-variousBodyTypes (7/44) — both in-process and through `python -m pypstreader.debug` (exit 0, empty stderr, the slow lane). The same goldens re-read as VALUES through the new `parse_dump_messages`: the walk's order and every node id (8/8 stores, 63 folders), every display name, content count, unread count and sub-folder flag (including the seven `Error: … InvalidFolderDisplayName(Null)` root folders, asserted as refusals), every `Associated Count:` and both `… Table: None` lines (7/8), and every contents-table row id against the `Message:` blocks the oracle printed under that folder (8/8, 14 messages). **synth-basics differed in exactly 6 lines and no others at landing time**, all `Associated Count: 0` → `Associated Table: None`; the cause was P06's `rgib[TCI_4b] >= 8` divergence meeting an EMPTY associated-contents table whose TCINFO says 4 (upstream accepts it because it never reads a row; P06 refused it when the TCINFO was parsed). **P06b closed this** (2026-09-16): the check is now deferred to `TableContext`'s first matrix read and fires only for a non-empty matrix, so `debug folders` is byte-identical on 8/8 Unicode corpus stores, pinned by `test_synth_basics_associated_table_is_byte_identical`. Private stores (structure only, the PREBUILT `reference/.../target/debug/examples/dump_messages`, no `cargo`): 2/2 byte-identical, 20 folders / 130 lines and 30 folders / 210 lines, NID types `{NormalFolder, SearchFolder}` only; nothing about their content printed or asserted. **47 new test functions / 152 cases**: `tests/test_folder.py` (41 functions, 123 cases) and 6 functions / 29 cases for `parse_dump_messages` in `tests/test_golden_parsers.py`. Whole suite `-m "not slow"`: 2352 passed, 22 skipped, 2 xfailed; slow lane (`-m "slow and not oracle"`, no `cargo`): 11 passed in 17m21s. **32/32 deliberate single-point bugs seen red** (`PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider`, `__pycache__` cleared between mutants), covering every accessor, the walk's order/depth/cycle guard, the three table derivations, the dumper's line order and error text, the golden filter and the parser. Denial by type: a NID that is not a folder's (4 kinds) and one whose 5-bit type is unassigned, a folder NID the NBT does not hold (`PstNotFoundError`), an EntryID from another store, a non-EntryId/non-NodeId argument (5), a table node absent (→ `None`, `()`) vs present-and-unreadable (→ `PstFormatError`, told apart deliberately), a hierarchy row naming a node that is not there / the folder itself (`PstLimitError`, "cycle") / the message store / an unassigned NID type, each of the four required properties absent and retyped (8 cases), `max_depth` past the tree (2) and of the wrong type (3), `max_folders` and `max_messages` at 1 (`PstLimitError`, never `PstFormatError`), every ceiling at 1 at once, and ANSI refused before any folder (2/2). `tests/corrupt.py` gained `folder_lies` (12 mutations on each of the 8 Unicode bases, 96 in all) and the corruption harness two entry points (`folder.walk`, `folder.tables` — kept apart so a contents table this port refuses cannot hide the rest of the walk); `tests/contract.py` gained 14 adapters, `"Store"`/`"Folder"` in `READER_TYPES` and a `folders`/`folder_nids` section, 0 uncovered, 0 stale. Upstream has **no `#[test]` in `folder.rs`**, so parity is 0 missing by construction (`check_upstream_parity.py`: 15 upstream tests, 14 twinned, 1 pending P27-NU, 0 missing).

**The display-name decision, made: refuse, as upstream does.** Six of the
eight Unicode corpus stores have a root folder whose `PidTagDisplayName`
record has a zero HNID, and the oracle prints `Name: Error: Custom { kind:
InvalidData, error: InvalidFolderDisplayName(Null) }` in place of the value.
`Folder.display_name` raises `PstFormatError` at exactly that point rather
than returning `None`: [MS-PST] 2.4.4.1 makes the property required, and a
caller handed `None` writes it into a path or a report as the empty string.
The lenient reading stays one call away (`folder.properties.get(0x3001)`),
and `debug folders` reproduces the golden's line by catching the refusal and
re-rendering upstream's variant name from the record's own type — which is
why `folder_accessor` exists and why a mutant that drops the variant is red.

Deliberate divergences, each a paragraph in `folder.py`'s docstring: **a
table node that exists but will not parse is a refusal, not `None`**
(upstream's `read_table(..).ok()?` reports every error as "absent", which is
how `dump_messages` prints `Hierarchy Table: None` for `pstd-inline-cid`;
a caller cannot tell "no sub-folders" from "sub-folder list unreadable", and
the two lead to opposite actions — `pypstreader.debug.folder_table` re-creates the
swallow so the dumper still matches, and that is the only place it happens);
**the two properties upstream injects into its property map**
(`PidTagEntryId` 0x0FFF, `PidTagFolderType` 0x3601) **are attributes here**,
so `Folder.properties` is what the file holds; **`walk()` is iterative,
depth-bounded and cycle-guarded**, where upstream has no walk at all —
`pypstreader.limits` gained `MAX_FOLDER_DEPTH` / `Limits.max_folder_depth` (64, the
same ceiling `oracle/examples/dump_messages.rs` uses), additive.

**Left for P09.** `Folder.messages()` and `associated()` are not here: they
need `Message`, so this row lands `message_ids()`, `associated_ids()` and
`contents()` (the same rows as NIDs and as EntryIDs) and `parse_dump_messages`
keeps each `Message:` block as raw lines for P09 to parse. `tests/test_rtf.py`'s
P09 xfail changed from `raises=ImportError` to `raises=AttributeError` — the
import it was waiting on now works, and `Folder.messages()` is what is
missing. (The `rgib[TCI_4b] = 4` finding above was the P06b follow-up row;
see its status block for the close-out.)

upstream: `crates/pst/src/messaging/folder.rs` (371)
oracle:   P19's `dump_messages` goldens (`tests/golden/<fixture>/dump_messages.txt`), folder blocks
blocked on: P06, P07, P19 (its oracle)

The folder hierarchy: a folder is a PC for its own properties plus three TCs
(hierarchy, contents, associated contents). Walk from the IPM subtree.

**Done means:** your folder walk matches P19's `dump_messages` goldens on
every corpus fixture the oracle reads (folder ids, names, counts, order). This is the first
end-to-end "it reads PSTs" moment.

### P09-MESSAGE
status: ✅ 2026-09-16 — `src/pypstreader/messaging/{message,attachment}.py`; `Store.open_message`, `Folder.messages()` / `Folder.associated()`; `Message`, `Recipient`, `RecipientType`, `Attachment`, `AttachMethod` exported from `pypstreader.messaging.__all__` and `pypstreader.__all__`; `python -m pypstreader.debug messages`. **Differential: byte-identical on 7/8 Unicode corpus stores and on 2/2 private stores, stdout AND exit status.** `debug messages` == `tests/golden/<fixture>/dump_messages.txt` for Empty (38 lines, exit 0), javalibpst-dist-list (156 folder lines + 4 message blocks, exit 1 — its `Errors: 3` trailer reproduced), pstd-inline-cid (8, exit 0), pstsdk-sample1 (46 + 1 message with its by-value attachment), pstsdk-submessage (38 + 1, exit 1), pstsdk-test_unicode (38 + 2) and tika-variousBodyTypes (44 + 4), both in-process and through `python -m pypstreader.debug` (the slow lane; stderr empty on exit 0, `Error: …` on exit 1). **synth-basics differs in exactly 6 lines and no others**, the same `Associated Count: 0` → `Associated Table: None` lines P08 documented (P06's `rgib[TCI_4b] >= 8` divergence); its one readable message block is identical, pinned by `test_synth_basics_differs_only_in_the_documented_associated_lines`. The same goldens re-read as VALUES through the new `parse_message_block`: all 13 message blocks of the 6 readable Unicode stores — message class, the raw subject with its `\u{1}\u{1}` bytes, both times as FILETIME ticks (including the three that end in a non-zero digit a `datetime` cannot round-trip), each body's LENGTH and CRC-32, all 7 recipient rows and all 4 attachment rows — plus the one block that is an `Error:` line, asserted as a refusal. Private stores (structure only, the PREBUILT `reference/.../target/debug/examples/dump_messages`, never `cargo`): 2/2 byte-identical, 147 and 211 lines; nothing about their content printed or asserted. **68 new test functions / 107 cases**: `tests/test_message.py` (62 functions, 101 cases) and 6 functions / 6 cases for `parse_message_block` in `tests/test_golden_parsers.py`, plus `tests/test_synthetic_content.py`'s reader tier going live and `tests/test_rtf.py`'s P09 xfail closing. Whole suite `-m "not slow"`: 2480 passed, 14 skipped, 7 xfailed (the six Inbox messages of `synth-basics`, below, and P27-NU's); slow lane (`-m "slow and not oracle"`, so no `cargo`): 19 passed in 34m12s — the corruption sweep and the contract harness both grew with the layer, and `tests/test_nightly_script.py`'s subprocess timeout went 900 s → 1800 s because the script's `tests` step IS that lane (it is a hang guard, not a performance budget; the run it now covers takes 1072 s). `tests/corruption_harness.py` caps the sweep at 16 messages and 4 attachments per store for the same reason — the message cap has to clear the FOURTH message of `javalibpst-dist-list.pst`, which is the one that carries attachments, and a tighter cap turns `attachment_lies:row0.sub_node_absent` SILENT. **41/41 deliberate single-point bugs seen red** (`PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider`, `__pycache__` cleared between mutants), covering every accessor and refusal of both modules, the dumper's five re-created upstream behaviours, the two new corruption families and the new parser. The first pass left 5 survivors and each was closed by making the code or the test say what it meant: two new `corrupt` mutations (`0x1009_type_body_rtf`, `0x3701_int_data`) with the tests they feed, a sharper mangle in the parser test, a mutant that was masked by an overlapping guard replaced with one that is not, and **two ceilings removed from `Attachment.data()` because no test could reach them** — `BlockReader.read_data` refuses an `lcbTotal` past `max_allocation` before it reads a child block, which is earlier than any check there could be. Denial by type: a NID that is not a message's (4 kinds) and one whose 5-bit type is unassigned, a message NID the NBT does not hold (`PstNotFoundError`), an EntryID from another store, a non-EntryId/non-NodeId argument (5), a message node with no sub-node tree, a recipient table present-and-unreadable (told apart from absent), an attachment row naming a sub-node the tree lacks (`PstNotFoundError`), an attachment NID that is not one, an attachment method no specification defines (`PstUnsupportedError`, 4 values, never `PstFormatError`), `PidTagAttachDataBinary` absent / retyped to Object / retyped to Integer32, an embedded message whose 0x3701 is not `PtypObject`, the embedding ceiling at the boundary and one under it, an RTF body that is not LZFu and one that is not Binary, a subject prefix past the string (4 hand vectors and one on real bytes), a message class absent and retyped, a delivery time retyped, `max_attachments` at 1 and 2, `max_recipients` at 1 and 2 over a real two-row table, `max_allocation` at 1000 against a 93 KB attachment, and every ceiling at 1 at once. `tests/corrupt.py` gained `message_lies` (2 mutations on each pinned base, 6-7 on a store with messages) and `attachment_lies` (1 / 2-8), with `retype_nbt_entry` and `subnode_data_block` as their builders, and the corruption harness two entry points (`message.open`, `message.attachments`, kept apart so a refused attachment cannot hide the messages); `tests/contract.py` gained 24 adapters, `"Message"`/`"Attachment"` in `READER_TYPES` and a `messages`/`message_nids`/`attachments`/`subjects` section, 0 uncovered, 0 stale. Upstream has **no `#[test]` in either file**, so parity is 0 missing by construction (`check_upstream_parity.py`: 15 upstream tests, 14 twinned, 1 pending P27-NU, 0 missing).

**One corpus folder's messages are unreachable, by this reader and by
upstream alike.** `synth-basics.pst`'s Inbox holds six of the seven authored
messages and its contents table's HNPAGEMAP says `cFree` 0 while the page
holds one zero-length allocation ([MS-PST] 2.3.1.5) — a check P04 ported
from upstream's `HeapNodePageMap::try_from`, so the oracle prints
`Contents Table: None` for that folder and dumps none of its messages
either. `tests/test_synthetic_content.py`'s reader tier is live and green
with those six parametrised cases `xfail(strict=True)` and the refusal
itself pinned on both sides
(`test_the_inbox_contents_table_is_refused_by_this_reader_and_by_upstream`);
the Sent folder's message is read back in full against its `.eml` source —
subject, sender, body, recipients. Fixing it is the fixture's job (a
P20-SYNTH follow-up), not a reader's.

**The subject decision, made: `subject` is the readable form and `subject_raw` is the file's, and both are exported.** `PidTagSubject` carries the [MS-OXCMSG] 2.2.1.46 control prefix — `U+0001`, then the prefix length PLUS ONE — on every Outlook-written message in the corpus (`"\x01\x01Test appointment"`, `"\x01\x05FW: original email"`). `subject` removes the two control characters and keeps the prefix TEXT (`"FW: original email"`), because that is what a caller writes into a filename, a report or an `.eml` and handing them the raw form means every caller strips it themselves, most of them wrongly; `subject_raw` is the value verbatim (what the oracle prints, and what the differential above compares); `subject_prefix` is `"FW: "` and `normalized_subject` is `"original email"` — `PidTagNormalizedSubject` (0x0E1D) when the store holds it, which no corpus store does, else derived. A prefix length past the end of the string is `PstFormatError`, never a slice: `split_subject` is public, has six worked vectors and four refusals, and `message_lies:0x0037_subject_prefix_past_the_string` proves it on real bytes.

**The documented divergence, arbitrated by the bytes: this port opens embedded messages and upstream cannot.** At pin cfb721da `PropertyType::try_from` has no `PtypObject` arm and the BTH walk stops at the first record it cannot decode, so an embedded-message attachment's PC is truncated before `PidTagAttachMethod` (0x3701 sorts before 0x3705) and upstream refuses it with `AttachmentMethodNotFound`. This port reads all 3 embedded attachments in the corpus: `pstsdk-submessage.pst`'s is an `IPM.Note` whose subject is `"This is an embedded message"`, whose body starts `"This is the body of an embedded message"` and which has one `To` recipient — all asserted on directly (public corpus data), and `javalibpst-dist-list.pst`'s two are `IPM.OLE.CLASS.{00061055-…}` items under an appointment. `test_the_golden_still_shows_upstreams_refusal` pins the golden's `Error:` line so a fixed pin is noticed. **A second upstream bug found the same way and fixed here:** `AttachmentInner::read` resolves `PidTagAttachDataObject`'s NID in the owning MESSAGE's sub-node tree, and the node is in the ATTACHMENT's own tree (`NormalMessage: 0x10002` under `Attachment: 0x401`; the message's tree holds no such node), which [MS-PST] 2.4.6.2/2.4.6.3 agree with — pinned by `test_the_embedded_message_lives_in_the_attachments_own_sub_node_tree`. The `messages` dumper re-creates upstream's truncation in `debug.upstream_records` — the only place it happens, as `folder_table` is for P08's `.ok()?` — so the golden still matches byte for byte while the library succeeds.

Other divergences, each in its module docstring: a message node with **no sub-node tree is refused** as upstream refuses it (`javalibpst-dist-list.pst` has exactly one, and its golden prints the refusal); properties are decoded on demand and the two sub-node tables are read on first use, where upstream reads everything at open — which is what keeps "no recipient table", "an empty one" and "one that will not parse" three answers instead of two; a table node that exists but will not parse is a refusal, not `None`; `recipients()`, `attachment_ids()` and `data()` are bounded by `limits`; the embedded recursion is bounded by `limits.max_embedded_message_depth` (16), which is what stops a message that embeds itself; an unknown **recipient** type stays an `int` ([MS-OXCMSG] 2.2.3.1 reserves flag bits and nothing is parsed from it) while an unknown **attachment method** is `PstUnsupportedError`; `AttachMethod` names 3 (`afByReferenceResolve`), which the specification defines and upstream's `TryFrom<i32>` rejects; `body_rtf` is the value AS STORED and `body_rtf_decompressed()` is `pypstreader.rtf` over it, trimmed at the first NUL as upstream trims.

**The measurement P10 asked for, taken: 6 of the 12 openable corpus messages
carry `PidTagTransportMessageHeaders`, and 1 of the 1 openable private
message does.** Public, by store: pstsdk-sample1 1/1, pstsdk-submessage 1/1,
tika-variousBodyTypes 4/4 — every message that arrived over SMTP has them —
and javalibpst-dist-list 0/3, pstsdk-test_unicode 0/2, synth-basics 0/1:
the appointment, the contact, the free/busy item, the two `IPM.Post` items
and the EMLtoPST-written message have none. Private stores, counts only: 2
stores, 50 folders, 1 openable message, 1 with headers, 0 attachments. The
corpus is too small to decide P10's design on its own, and what it does say
is that the split follows the message CLASS rather than the store: an
`IPM.Note` that was delivered has real headers, and everything composed
locally or synthesised has none. P10 should pass them through where they
are and synthesise-and-mark where they are not, and it should re-take this
count over a larger private corpus before it settles the shape.

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
status: ✅ 2026-09-16 — `src/pypstreader/eml.py` (`to_eml`, `eml_bytes`, `write_eml`, `eml_name`, `folder_paths`, `readable_messages`, `export_folder`) and `src/pypstreader/mbox.py` (`export_mbox`, `mbox_name`), both `Ported from: not a port`; `to_eml`/`eml_bytes`/`write_eml`/`export_folder`/`export_mbox` exported from `pypstreader.__all__`; `python -m pypstreader.debug eml <file> <nid-hex>` and `python -m pypstreader.debug export <file> <dir> [--eml]`. **EVIDENCE BELOW.**
upstream: nothing — **this is ours**, and both module docstrings say `not a port`
oracle:   none; this is where we stop having one
blocked on: P09

**The deliverable, as shipped: MBOX first, EML as the building block.**
Upstream ships **no export format at all** — ten example binaries that dump
each layer as text and nothing that produces mail — which is why the format
was the user's choice rather than a port's: MBOX (RFC 4155), one file per
folder, because it is what mutt, Thunderbird, `formail`, `readpst`, every
e-discovery loader and Python's own `mailbox` already read, and because one
file per folder keeps the store's shape that a directory of loose `.eml`
files loses. Per-message `.eml` is what each mbox record contains, and is
available on its own (`export_folder`, `--eml`).

**The header policy, as implemented, and the measurement it rests on.** P09
counted: **6 of the 12 openable corpus messages carry
`PidTagTransportMessageHeaders`, and 1 of the 1 openable private message
does**, and the split follows the message CLASS, not the store — every
delivered `IPM.Note` has them; the appointment, the free/busy item, the two
`IPM.Post`s and the EMLtoPST-written message have none. So the module does
both and says which: transport headers are **parsed and passed through**
(minus `Content-*`/`MIME-Version`, which describe the ORIGINAL body and would
mislabel the one being re-assembled), what is then missing is **synthesised
from MAPI**, and **every header added is named in `X-Pypstreader-Synthesized`**
(absent when nothing was added, so its presence is the signal). A
`Message-ID` is `PidTagInternetMessageId` when the store kept one — a real id
under an added header — else invented deterministically from the store record
key and the node id under `@pypstreader.invalid` (RFC 2606), so a reconstructed id
is recognisable by inspection as well as by the marker and is never presented
as original. The measurement is re-taken by the test suite
(`test_six_of_the_twelve_openable_messages_carry_transport_headers`), so it
cannot silently stop being true. It is still a small corpus: **re-take it
over a larger private corpus before anything downstream threads on it.**

**Round trip: the one message of the corpus whose expected output is a file
in this repository.** `synth-basics.pst` was built by EMLtoPST from
`tests/fixtures/synthetic/basics/**/*.eml`, and its Sent folder's message
(`NormalMessage: 0x2B`; the Inbox's six are unreachable by this reader and
upstream alike, P09's `UNREADABLE_CONTENTS`) comes back out equal to
`Sent/01-reply.eml` in `Subject`, `From` and `To` (display name and
addr-spec), `Date` to the second, decoded text body, content type and
attachment list (none, on both sides) — and equal again after a round trip
through `mailbox.mbox`. Every header of it is synthesised (`From, To,
Subject, Date, Message-ID`) because EMLtoPST stores neither transport headers
nor `PidTagInternetMessageId`, and each reproduces the source's value except
the `Message-ID`, which the store simply does not contain and which therefore
comes out under `pypstreader.invalid` — which is the case the marker exists for,
pinned as such.

**Per-store export counts, 12/12 openable messages, all 8 Unicode stores:**
Empty 0, javalibpst-dist-list 3 (of 4 message nodes — the fourth has no
sub-node tree and is skipped, or refused under `strict=True`), pstd-inline-cid
0 (no readable folder below its root, P06/P08 — so its inline-`cid:` message
is NOT this row's witness and the inline case is built in the test file
instead), pstsdk-sample1 1, pstsdk-submessage 1, pstsdk-test_unicode 2,
synth-basics 1 (of 7 authored — the Inbox contents table is refused),
tika-variousBodyTypes 4. Every one assembles, serialises to **pure ASCII with
CRLF**, re-parses to the same headers and the same part tree with every
payload decodable, and **two `eml_bytes` calls agree byte for byte** (MIME
boundaries are `----=_pypstreader.<nid>.<n>` precisely because `email` draws them
from `random`; a body that contains its own boundary pushes it aside, and one
that contains every counter the search would try — the tag comes from a node
id the FILE chose, so the sequence is predictable — ends the search with a
SHA-256 of the payload, which the payload cannot contain). `export_mbox` over each store writes one `<nid>.mbox` per
folder plus `folders.txt`, `mailbox.mbox` reads back exactly the count
`readable_messages` yielded for that folder, and two exports of one store are
byte-identical (no clock anywhere: a message with no time gets the epoch).
Private stores, structure only: both export, counts and part counts only, no
header value or body asserted, printed or logged.

**The body shapes, from `tika-variousBodyTypes.pst`, one message per kind:**
0x10001 and 0x10002 → `multipart/alternative` [`text/plain`, `text/html`],
0x10003 → [`text/plain`, `application/rtf`] (the RTF decompressed by P21 and
starting `{\rtf1`), 0x10004 → `text/plain` alone. Least faithful first, as
RFC 2046 § 5.1.4 requires. RTF alone (no corpus witness; built by removing
the text body from 0x10003) is `application/rtf` plus `X-Pypstreader-Body:
rtf-only` and **no invented text**; no body at all is an empty `text/plain`
plus `X-Pypstreader-Body: none`. HTML is decoded with `PidTagInternetCodepage`
(0x3FDE — 20127/us-ascii on every corpus message that has HTML), else the
store's code page, else UTF-8, always `errors="replace"`, and re-encoded as
UTF-8 because a part's declared charset must match its bytes and re-encoding
to the original can fail where decoding replaced.

**Attachments and embedded messages.** `pstsdk-sample1.pst`'s
`leah_thumper.jpg` becomes a part with its 93 142 bytes verbatim, named from
`PidTagAttachLongFilename`, typed `application/octet-stream` because the
store kept no `PidTagAttachMimeTag`. `pstsdk-submessage.pst`'s embedded
message becomes a `message/rfc822` part whose inner `Subject` is `"This is an
embedded message"` and whose body starts `"This is the body of an embedded
message"` — **the P09 divergence carried through to the export: upstream at
the pin cannot open this attachment at all**. That embedded message kept
transport headers of its own, so its `Message-ID` is passed through; with
them removed (and `PidTagInternetMessageId` with them) its synthetic id is
prefixed with its carrier's, because sub-node ids are unique only inside
their own tree. An attachment whose method carries no bytes in this store
(`NONE`, `BY_REFERENCE`, `BY_REF_RESOLVE`, `BY_REF_ONLY`) is recorded as
`X-Pypstreader-Attachment-Skipped: <METHOD> <filename>` — never dropped silently,
never an exception.

**Denial, and the injection cases, which is where an exporter is actually
dangerous.** An attachment over the CALLER's `max_allocation` is
`PstLimitError` (the store's limits let `data()` return; `to_eml`'s own
`limits` is checked after, and the boundary value passes); embedding deeper
than `max_embedded_message_depth` counted **from `Message.depth`** is
`PstLimitError` from the exporter's own check, and a carrier one under the
ceiling still exports; an accessor that refuses propagates its
`PstFormatError`; a non-`Message` or non-`Limits` argument is `TypeError`.
**Every value that reaches a header is stripped of control characters
first** — `email.policy` answers a linefeed with `ValueError`, which is a
refusal in the wrong currency, and `PidTagAttachMimeTag` of
`"text/plain\r\nBcc: victim@example.test"` is header injection: 8 mime-tag
vectors and 4 filename vectors (`../../etc/passwd`, `..\..\windows\...`, a
CRLF, a NUL) produce no `Bcc`, no `\r\nBcc:` sequence and no second
`Content-Disposition`. A `mime_tag` that is not two RFC 2045 tokens becomes
`application/octet-stream`. **Nothing from a message ever reaches a path**:
`.eml` files are `<nid>.eml`, mboxes are `<nid>.mbox`, display names appear
only inside `folders.txt` with `/` and `\` replaced, and a folder renamed
`../../../etc` writes neither a directory nor a file outside `dest_dir`.
`ValueError`/`LookupError` from the `email` package is re-raised as
`PstFormatError` (documented divergence): everything that flows into it came
out of the file. The corruption harness gained an `eml.export` entry point
(bounded by `EML_BYTES_PER_SWEEP` = 256 KiB of output per store so the sweep
does not pay a base64 of a 93 KB attachment per mutation), and every mutation
of the `message_lies` and `attachment_lies` families over
`javalibpst-dist-list.pst` yields an `.eml` or a `PstError` and nothing else.

**Tests: 116 new cases in `tests/test_eml.py` (49 functions) and
`tests/test_mbox.py` (15 functions).** Whole suite `-m "not slow"`: **2600
passed, 14 skipped, 7 xfailed** (2480 before this row); slow lane
(`-m "slow and not oracle"`, so no `cargo`): **21 passed in 37m34**. Two slow
tests had to be told about this row: `test_debug_cli_never_tracebacks` counts
a dumper's arguments with `debug.dumper_arguments` now, because `export`'s
`as_eml` is a FLAG and not a positional argument (it was passing two `21`s
and getting argparse's exit 2), and `test_nightly_script.py`'s subprocess
guard went 1800 s → 2400 s: the nightly script's `tests` step IS this lane,
and this row added an entry point to the corruption sweep, nine adapters
(two of which write files) to the contract sweep and two dumpers to the CLI
sweep. It is a hang guard, not a performance budget. `tests/contract.py`
gained nine adapters (`to_eml`, `eml_bytes`, `write_eml`, `eml_name`,
`folder_paths`, `readable_messages`, `export_folder`, `export_mbox`,
`mbox_name`), a `workdir` on its fixture object, an `EXTRA_ARGS["dest"]`, and
`debug.dumper_arguments` in `NOT_STORE_INPUT`; `uncovered()` and `stale()`
are both empty. `scripts/check_provenance.py` (27 modules), 
`check_quality_ratchet.py`, `check_upstream_parity.py` (15 upstream tests, 14
twinned, 1 pending P27-NU, 0 missing) and `ruff check src tests scripts` all
exit 0. **31/31 deliberate single-point bugs seen red**
(`PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider`, `__pycache__` cleared
between mutants): the 7-bit policy, the control-character strip, the dropped
body headers, the synthesis order, the marker itself, the stored id, the
invalid domain, the embedded id prefix, the body order, the rtf-only marker,
the charset fallback, the mime-type validation, the content-id brackets, the
`cid:` match, both ceilings, the deterministic boundaries, the sub-part
`MIME-Version` strip, the walk that must not cross into an encapsulated
message, the `.eml` name, `strict`, the display-path replacement, the mbox
From_ line (address, clock, and the stdlib default), the mbox file name, the
mbox line endings, the replace-not-append, the X.500 sender, `dumper_arguments`, and both halves of the boundary search
(the counter, and the hash that ends it). The first pass left three survivors and each was closed by
a test that reaches the branch rather than by weakening the code: the
`_charset` fallback needed a message with NO `PidTagInternetCodepage` AND a
store code page Python has no codec for; `strict` needed a store with an
unreadable MESSAGE (`javalibpst-dist-list.pst`) and not only an unreadable
FOLDER; and the X.500 From_ fallback needed a sender with an X.500 address
and no SMTP one. Two more cases had no corpus witness at all and are built in
the test file with a stated reason: the original body's `Content-*` headers
(Exchange strips them before storing) and an inline `cid:` image
(`pstd-inline-cid.pst`'s message is unreachable through either reader).

**Divergences and decisions, each also in its module docstring:** the policy
is `email.policy.SMTP` with `cte_type="7bit"` (RFC 5322 CRLF, and every part
encoded down to ASCII so an `.eml` survives any transport — an 8-bit body is
no less correct but only where everything downstream is 8-bit clean, and a
reader cannot know that for its caller); mbox records are LF, which is what
the format has meant since it was a Unix mailbox and what `mailbox.mbox`
re-reads without surprises; the stdlib quotes a body line beginning `From ` to
`>From ` and does not unquote on read, which is **mboxo, not the mboxrd RFC
4155 § 4 prefers** — the ambiguity is the format's, it is pinned by a test on
a body written to contain the line, and what is guaranteed is that no body
line can be mistaken for a record separator; `export_folder` and
`export_mbox` skip what refuses by default (`strict=True` propagates) because
a store with one unreadable folder among fifty should still export the other
forty-nine, and the mbox index records the refusal by exception TYPE; an
existing `<nid>.mbox` is replaced rather than appended to, so a second run is
not a trap.

**Left undone, deliberately:** no `multipart/report`/DSN handling, no TNEF
(`winmail.dat`) expansion, no `PidTagMessageClass`-specific rendering
(an appointment exports as its properties, not as an iCalendar part), and no
`.mbx`/Maildir writer. `folders.txt` is this module's own index format, not a
standard one. And the header measurement wants re-taking over a corpus larger
than twelve messages before anything downstream relies on the 50/50 split.

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
status: ✅ 2026-09-15 — `src/pypstreader/rtf.py` + generated `_rtf_dictionary.py` (207 bytes, extracted by `scripts/extract_rtf_dictionary.py`, three invariants: length, equals the [MS-OXRTFCP] 2.1.2.1 string, CRC-32 0x2E98875B; `--check` green). 51 new test functions / 94 cases, all green (+1 strict xfail waiting on P09): 4/4 upstream parity twins in `tests/parity/test_rtf_parity.py`; [MS-OXRTFCP] 3.1.1, 3.1.2, 3.2.1, 3.2.2 vectors typed from the spec pages match 4/4 (decompress and byte-exact compress); spec CRC example 3.3.1 = 0xA7C7C5F1 by both the spec walk and `zlib.crc32`; all 256 entries of upstream's crc.rs table = the CRC-32 polynomial table; round trip `decompress(compress(x)) == x` over 14 sizes × 3 seeds (0–9000 bytes, across the 4096 wrap) plus long repeats, every byte value and random bytes; 1500-mutation fuzz leaks nothing but `PstError`. Denial cases asserted by type: truncated header (15 lengths), COMPSIZE mismatch (6), unknown COMPTYPE (6), CRC mismatch (4), half token, missing terminator, reference into unwritten dictionary (3), RAWSIZE > limit and output > limit as `PstLimitError` not `PstFormatError`. Every test seen red under 17 deliberate single-point bugs, then restored. Deliberate divergences from upstream (all in the module docstring): end of payload before the terminator is refused (spec 2.2.3.2 MUST), reference into unwritten dictionary is refused, output size capped not just RAWSIZE, no NUL trimming.
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
