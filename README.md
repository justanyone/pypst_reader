# pypst — a pure-Python reader for Outlook PST stores

A port of the **read path** of [microsoft/outlook-pst-rs](https://github.com/microsoft/outlook-pst-rs)
(MIT) into Python, with no dependencies outside the standard library.

> **Status: early.** The encoding and CRC layers are ported and tested. The
> NDB, LTP and messaging layers are not. It cannot open a PST yet. See
> [docs/PORTING-PLAN.md](docs/PORTING-PLAN.md).

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

## Install

Nothing to install yet. When there is:

```bash
pip install pypst
```

## Develop

```bash
git clone <this repo> && cd pypst_reader
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

### Test

```bash
uv run pytest                    # everything
uv run pytest -m "not oracle"    # skip differential tests (no Rust needed)
```

## Mail stores are never committed

`tests/fixtures/Empty.pst` — Microsoft's MIT-licensed empty store — is the only
mail store in this repository and the only one that may ever be committed.
Real stores live in `tests/fixtures/private/`, which is gitignored, and a
`pre-commit` hook refuses any commit containing one. A PST is somebody's
correspondence; a public repository that has ever held one has published it.

Tests may assert that a private store *parses*. They may not assert, print, or
log what it *says* — a CI log is a publication channel.

## Licence and attribution

MIT. Portions are derived from microsoft/outlook-pst-rs, Copyright (c)
Microsoft Corporation, also MIT. **See [NOTICE](NOTICE)** — it carries the
attribution the MIT licence requires, the trademark position (this project is
not affiliated with or endorsed by Microsoft), and the patent posture of every
open PST implementation, which this one inherits and does not change.

The format itself is documented by Microsoft as the open specification
[[MS-PST]](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/141923d5-15ab-4ef1-a524-6dce75aae546),
whose IP notice expressly permits copying it in order to build implementations.
