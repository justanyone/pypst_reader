# pypstreader — a pure-Python reader for Outlook PST stores

A port of the **read path** of [microsoft/outlook-pst-rs](https://github.com/microsoft/outlook-pst-rs)
(MIT) into Python, with no dependencies outside the standard library — and a
command that turns a PST into mail your tools already read.

> **Status: 1.0.0 — production.** The read path is complete and verified
> against the Rust oracle byte for byte on every fixture: `pypstreader.open()`
> opens a Unicode PST and walks folders, messages, recipients and attachments —
> and exports them as `.eml` files or as **mbox**, which is what the reader is
> for. The public API above is stable; it follows semantic versioning from here,
> and a breaking change means 2.0. Unicode (Outlook 2003 and later) stores only;
> an ANSI store is refused, never guessed at.

## Install

```bash
pip install pypstreader          # the library and the command
uv tool install pypstreader      # just the command, in its own environment
```

Nothing comes with it: the package imports the standard library and nothing
else, on any platform, with no compiler and no network.

`pip install pstreader` installs the same thing under
[an alias name](alias/pstreader/README.md), for people who reach for the
shorter one.

## The command

```bash
pypstreader store.pst                      # -> store.mbox, every folder, every message
pypstreader store.pst -o mail.mbox         # somewhere else
pypstreader --list store.pst               # the folder tree, with message counts
pypstreader --per-folder store.pst -o out/ # one <nid>.mbox per folder, plus folders.txt
pypstreader --format eml store.pst -o out/ # one <nid>.eml per message
pypstreader --folder 'Top of Personal Folders/Inbox' store.pst
```

The default writes **one mbox** — the format `mutt`, Thunderbird, `formail`,
`readpst`, Python's own `mailbox` and every e-discovery loader read as-is
(RFC 4155) — with every message stamped `X-Pypstreader-Folder: <display
path>`, so flattening the store does not lose the tree. `--folder` takes
exactly the path `--list` prints, and covers that folder and everything under
it.

A message that will not open is **skipped and counted**, not fatal: the
summary line on stderr says how many were written and how many were skipped,
and `--strict` turns the first refusal into the end of the run instead.
Limits are on the command line too — `--max-depth`, `--max-attachment-bytes`,
`--max-embedded-depth` — because the file being read is not trusted.

Exit status is **0** when the run finished, **1** when the store or the
filesystem refused (one line on stderr, never a traceback), **2** when the
command line was wrong.

```
$ pypstreader --list mail.pst
      0  Top of Personal Folders
      4  Top of Personal Folders/Inbox
      1  Top of Personal Folders/Sent
$ pypstreader mail.pst
pypstreader: 3 folders, 5 messages written, 0 skipped -> mail.mbox
```

## The library

```python
import pypstreader

with pypstreader.open("store.pst") as store:
    for folder in store.root_folder.walk():
        print(folder.display_name, folder.content_count)
        for message in folder.messages():
            print("  ", message.subject, "from", message.sender_name)

    # One mbox per folder (`<nid>.mbox`, plus `folders.txt` naming them):
    pypstreader.export_mbox(store.root_folder, "out/")

    # ...or one RFC 5322 `.eml` per message, named by node id:
    pypstreader.export_folder(store.root_folder, "out-eml/")

    # ...or one message at a time, as an `email.message.EmailMessage`:
    message = next(iter(store.root_folder.messages()))
    eml = pypstreader.to_eml(message)           # headers, bodies, attachments
    pypstreader.write_eml(message, "one.eml")   # or pypstreader.eml_bytes(message)
```

Everything that can fail raises a `PstError` — `PstFormatError`,
`PstUnsupportedError`, `PstLimitError`, `PstNotFoundError` — and nothing
else: a `struct.error` or an `IndexError` out of this package is a bug, and
the test suite sweeps every public entry point over thousands of deliberately
corrupted stores to keep that true.

There is a second command for reading the *format* rather than the mail,
which prints one layer of a store in the upstream Rust example's own
wording:

```bash
python -m pypstreader.debug messages store.pst   # what the oracle prints
python -m pypstreader.debug eml store.pst 10001  # one message, on stdout
python -m pypstreader.debug --list               # every layer it can dump
```

**Where the headers come from.** A message that arrived over SMTP keeps its
internet headers in a MAPI property, and those are passed through verbatim —
`Message-ID`, `Date`, the `Received` chain, `In-Reply-To`, `References`.
A message composed locally has none, so `From`, `To`/`Cc`/`Bcc`, `Subject`,
`Date` and `Message-ID` are rebuilt from MAPI properties, and **every header
that was rebuilt is listed in `X-Pypstreader-Synthesized:`**. An invented
`Message-ID` lives under `@pypstreader.invalid` and is deterministic, so a
reconstructed thread is never mistaken for a delivered one. (In the test
corpus the split is 6 messages of 12 either way, and it follows the message
class: delivered `IPM.Note`s have headers, appointments and locally-composed
items do not.)

## Why this exists

Every existing way to read a PST from Python goes through `libpff` — a C
library under LGPL-3, reached via a compiled extension. That is three problems
in one dependency: a copyleft obligation on anything that ships it, a native
build in every install, and a large C parser being fed bytes an attacker chose.

There is no pure-Python PST reader. This is an attempt at one:

- **MIT**, like the Rust it is ported from — no copyleft obligation to convey.
- **Pure stdlib**, so it installs as a plain wheel, air-gapped, on any platform.
- **Memory-safe** by construction, which matters when the input is a mail store
  from a hostile source.
- **Auditable** — a few thousand lines of Python you can actually read, each
  module naming the upstream file it came from.

## Develop

```bash
git clone <this repo> && cd pypstreader
scripts/setup.sh          # venv, git hooks, Rust oracle, test run
```

`scripts/setup.sh --no-rust` skips the oracle if you only want the Python side.

### The differential oracle

The porting method is not "read the Rust and write Python". It is: port a
layer, then run **both implementations over the same bytes and diff the
output**. The upstream repository ships ten example binaries that dump each
layer — headers, B-trees, the named-property map, the root folder — and those
are the ground truth.

```bash
scripts/get_rust_source.sh                          # pinned clone into reference/
scripts/build_oracle.sh                             # ~2 min, ~270 MB
scripts/oracle.sh read_header tests/fixtures/Empty.pst
scripts/oracle.sh --list                            # what else it can dump
```

The Rust is **fetched, never vendored** — it is the oracle, not the product.
The pin lives in [docs/UPSTREAM.txt](docs/UPSTREAM.txt).

The oracle's output over every public fixture is committed as goldens under
`tests/golden/`, which is why every-push CI stays Rust-free: the differential
tests diff Python against the *file*. A nightly job,
[`.github/workflows/nightly-oracle.yml`](.github/workflows/nightly-oracle.yml),
is what proves the file still agrees with the Rust. It fetches upstream at the
pin, builds the example binaries, and checks that every upstream test has a
Python twin, that the goldens are what the oracle emits today, that the
synthetic fixture regenerates byte-for-byte, and that the `oracle`-marked
tests pass live. Every one of those checks is a call into
`scripts/nightly_oracle_local.sh`, so the same run works on a laptop
(`SKIP_RUST=1` for the Python-only half).
Upstream's only message-level example is an interactive TUI, so `oracle/`
holds a small Rust crate of our own (MIT; it links the pinned upstream crate
as a path dependency and copies nothing in) with the examples upstream does
not ship. `dump_messages` walks every folder, message, recipient and
attachment non-interactively and prints them in upstream's `Debug` style —
body *lengths and CRC-32s*, never body text — and is captured into
`tests/golden/` like the other eight. `scripts/oracle.sh` finds it by name:

```bash
scripts/oracle.sh dump_messages tests/fixtures/public/pstsdk-test_unicode.pst
cd oracle && cargo build --example dump_messages     # or let oracle.sh build it
```

It builds into the reference checkout's `target/` (debug profile, the one
`oracle.sh` already uses), so nothing is compiled twice.

### Test

```bash
uv run pytest                    # everything
uv run pytest -m "not oracle"    # skip differential tests (no Rust needed)
```

## Mail stores in the repository

Two kinds, both pinned by hash, nothing else:

- `tests/fixtures/Empty.pst` — Microsoft's MIT-licensed empty store.
- `tests/fixtures/public/` — a small corpus of **licensed test stores**
  (Microsoft's PST SDK samples, Apache Tika's, java-libpst's, and a synthetic
  MIT one), 29 KB–265 KB each, every one listed with its SHA-256, source
  commit and licence in [that directory's README](tests/fixtures/public/README.md).
  The Rust oracle's output over each is captured in `tests/golden/`, so the
  differential tests run without a Rust toolchain.

Real stores live in `tests/fixtures/private/`, which is gitignored, and a
`pre-commit` hook (and CI) refuses any commit containing a store that is not
in the manifest. A PST is somebody's correspondence; a public repository that
has ever held one has published it.

Tests may assert that a private store *parses*. They may not assert, print, or
log what it *says* — a CI log is a publication channel.

**Unicode stores only.** Stores written by Outlook 97–2002 (ANSI format) are
refused with `PstUnsupportedError`; see ADR-0003.

## Licence and attribution

MIT. Portions are derived from microsoft/outlook-pst-rs, Copyright (c)
Microsoft Corporation, also MIT. **See [NOTICE](NOTICE)** — it carries the
attribution the MIT licence requires, the trademark position (this project is
not affiliated with or endorsed by Microsoft), and the patent posture of every
open PST implementation, which this one inherits and does not change.

The format itself is documented by Microsoft as the open specification
[[MS-PST]](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/141923d5-15ab-4ef1-a524-6dce75aae546),
whose IP notice expressly permits copying it in order to build implementations.
