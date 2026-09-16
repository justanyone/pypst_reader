# pypst — agent guide

A pure-Python reader for Outlook PST stores, ported from the **read path** of
[microsoft/outlook-pst-rs](https://github.com/microsoft/outlook-pst-rs) (MIT).
No write support: this reads mail stores, it never produces one.

## Resume protocol

1. `MasterToDo.md` — the one ranked list of unfinished work
2. `git log --oneline -15`
3. `docs/PORTING-PLAN.md` — the layer order and why it is that order
4. The `rust-port` skill, before touching any ported module

## Repo state

The encoding and CRC layers are ported, tested, and green (`uv run pytest`).
Nothing above them exists yet: **this package cannot open a PST**. The next
move is `ndb/header.py`, and it is deliberately the first because it is the
smallest thing the oracle can contradict.

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

- **Mail stores are never committed.** One exception, by name and by content
  hash: `tests/fixtures/Empty.pst` (Microsoft's MIT empty store). Real stores
  live in `tests/fixtures/private/`, gitignored, hook-blocked. Never weaken
  `.gitignore` or `scripts/git-hooks/pre-commit`.
- **Never print, log, or assert on private-store content.** Structure only.
  A CI log is a publication channel and a failing assert prints its operands.
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
  file, and a caller cannot be asked to catch them. See `src/pypst/errors.py`.
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
| `src/pypst/` | the library — stdlib only |
| `tests/` | pytest; markers `oracle`, `private`, `slow` |
| `tests/fixtures/Empty.pst` | the one committed store (MIT, Microsoft) |
| `tests/fixtures/private/` | real mail, gitignored, never referenced in output |
| `reference/outlook-pst-rs` | pinned upstream clone — the oracle, gitignored |
| `scripts/` | setup, oracle, and the standing lints |
| `docs/adr/` | binding decisions and the research behind them |
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
