# pypstreader — agent guide

A pure-Python reader for Outlook PST stores, ported from the **read path** of
[microsoft/outlook-pst-rs](https://github.com/microsoft/outlook-pst-rs) (MIT).
No write support: this reads mail stores, it never produces one.

## Resume protocol

1. `MasterToDo.md` — the one ranked list of unfinished work
   (`DoneFeatures.md` is what has already landed, and why it counts as done)
2. `docs/AGENTS.md` — the multi-agent protocol: **claim the row before starting**
3. `git log --oneline -15`
4. `docs/INTERFACES.md` — the layer contracts you code against
5. `docs/PORTING-PLAN.md` — the layer order and why it is that order
6. The `rust-port` skill, before touching any ported module

## Repo state

Every layer of the read path is ported and green (`uv run pytest`): NDB
(header, pages, B-trees, blocks), LTP (heap, BTH, property and table
contexts), and messaging (store, named properties, folders, messages,
recipients, attachments, embedded messages). `pypstreader.open()` opens a Unicode
PST and walks it; `python -m pypstreader.debug messages <file>` reproduces the
Rust oracle's dump byte for byte on every corpus store. P10 landed the export
(`to_eml`, `export_folder`, `export_mbox`) and P16 the command on top of it —
`pypstreader store.pst` writes `store.mbox` — plus the rename from `pypst`
(taken on PyPI) and the `pstreader` alias distribution in `alias/pstreader/`.

**1.0.0 is released and production-marked.** The public API is stable and
follows semantic versioning: a breaking change to the names in
`docs/INTERFACES.md` means 2.0, not a minor bump. The build record — every row
that landed, with the verification that closed it — is `DoneFeatures.md`;
`MasterToDo.md` carries only what is still open, which is developer tooling
and future scope, none of it blocking a user.

One standing trap, learned the hard way in CI: **do not compare a parsed email
header value against a constructed one without normalising it.** CPython
changed whether `email` keeps the whitespace after a header's colon between
3.12.3 and 3.12.13, so an exact comparison passes on a developer box and fails
on the runner. The bytes written are identical either way; use
`tests/test_eml.py`'s `header_value()`.

Two decisions are already made and are not re-litigated in a row:
**Unicode stores only** (ADR-0003; ANSI is refused and belongs to a sibling
`pypstreader_nu`), and a **hash-pinned public fixture corpus** with captured
oracle goldens (ADR-0004), so the differential suite runs in CI without Rust.

## The method: differential porting, not translation

This is the single most important thing in this file.

**Do not read the Rust and write Python from memory.** Port a layer, then run
the upstream binary and your Python over the same bytes and diff the output:

```bash
scripts/oracle.sh read_header tests/fixtures/Empty.pst
```

Upstream ships ten example binaries (`scripts/oracle.sh --list`) that dump each
layer. They are ground truth. A ported layer is not done when it runs; it is
done when it agrees with the oracle byte for byte on every fixture available.

Full protocol, including how to avoid fooling yourself with it: the
**`rust-port`** skill.

## Non-negotiable build standards

- **Mail stores are committed only through the manifest.** `Empty.pst` (MIT,
  Microsoft, by md5) and `tests/fixtures/public/*.pst` — licensed, synthetic
  or vendor test data, every one SHA-256 pinned in `MANIFEST.sha256` with a
  provenance row in that directory's README (ADR-0004). Real stores live in
  `tests/fixtures/private/`, gitignored, hook-blocked. Never weaken
  `.gitignore`, `scripts/git-hooks/pre-commit` or CI's `no-mail-stores`; the
  manifest procedure is the only way in.
- **Never print, log, or assert on private-store content.** Structure only.
  A CI log is a publication channel and a failing assert prints its operands.
  Corpus content may be printed and asserted on freely — there is nobody in it.
- **Unicode only.** `wVer` 14/15 raises `PstUnsupportedError`; no variant axis
  anywhere in the code (ADR-0003).
- **Every ported module records its origin** — `Ported from:` / `Upstream:` in
  the module docstring. `scripts/check_provenance.py` enforces it; NOTICE
  depends on it being true.
- **Zero runtime dependencies.** The package imports stdlib only. Adding one is
  an ADR-sized decision, not a convenience.
- **Fail closed on unknown input.** An unrecognised crypt method, version, or
  node type raises — it is never read as plaintext, never guessed past. The
  plausible-looking garbage that guessing produces is worse than a refusal.
- **`PstError` or nothing.** No `struct.error`, `IndexError` or `MemoryError`
  may escape a public entry point: every one is reachable from a malformed
  file, and a caller cannot be asked to catch them. See `src/pypstreader/errors.py`.
- **Limits are explicit.** Recursion depth, allocation size, item counts. A
  malicious store claims enormous structures; refusing is correct, and
  `PstLimitError` must stay distinguishable from `PstFormatError`.
- **Every change lands with tests, and denial cases are tested too** — not just
  that a good file parses, but that a bad one is refused.

## Untrusted input is the whole threat model

A PST arrives from a laptop image, a discovery production, an adversary. Every
offset, length and count in it is attacker-controlled. Python removes memory
corruption from the risk list; it does not remove resource exhaustion, infinite
recursion, or cycles in a B-tree that a naive walk follows forever. Those are
this port's job, and they are the places where **this reader should deliberately
diverge from upstream**: Rust's bounds checks make a panic survivable in a way
an unbounded Python loop is not.

When you diverge from upstream, say so in the module docstring, with the
reason. An unexplained divergence looks like a porting bug to the next reader.

## Layout

| path | what |
|---|---|
| `src/pypstreader/` | the library — stdlib only; `pypstreader.py` is the command |
| `alias/pstreader/` | the `pstreader` alias distribution: a re-export and a pin, no code |
| `tests/` | pytest; markers `oracle`, `private`, `slow` |
| `tests/fixtures/Empty.pst` | Microsoft's MIT empty store |
| `tests/fixtures/public/` | the licensed corpus, SHA-256 pinned; README has provenance |
| `tests/golden/` | the Rust oracle's output over the corpus, captured by `scripts/capture_oracle.py` |
| `tests/fixtures/private/` | real mail, gitignored, never referenced in output |
| `reference/outlook-pst-rs` | pinned upstream clone — the oracle, gitignored |
| `scripts/` | setup, oracle, and the standing lints |
| `docs/adr/` | binding decisions and the research behind them |
| `docs/TEST-PLAN.md`, `docs/AGENTS.md`, `docs/INTERFACES.md` | the test tiers, the multi-agent protocol, the layer contracts |
| `MasterToDo.md`, `DoneFeatures.md` | what is open · what has landed, with its proof |
| `docs/UPSTREAM.txt` | the upstream revision this port is verified against |

## Skills in this repo

- `rust-port` — **load FIRST when porting any module**: the differential
  method, the layer order, Rust→Python idiom table, what to do when upstream
  and the specification disagree
- `test-harness` — pytest conventions, the fixture policy, denial-first testing
- `rtk` — token-compressed command output
- `codegraph` — query the code graph instead of repo-wide greps (needs indexing)
- `grabchat` — export the session transcript

## Conventions

- Python 3.12+, `uv` for the environment, `ruff` pinned, `pytest` for tests.
- Module and function names **mirror upstream's** where a reader would benefit
  from the correspondence (`compute_crc`, `decode_block`), and diverge where
  Python has a better idiom (`bytes.translate` over a hand-rolled loop).
  Mirroring is for navigability, not for its own sake.
- Commit messages: plain and descriptive, matching existing history style.
