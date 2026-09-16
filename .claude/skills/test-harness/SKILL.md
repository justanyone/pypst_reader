---
name: test-harness
description: pytest conventions for this port — the fixture policy that keeps real mail out of the repository, differential tests against the Rust oracle, and denial-first testing. Use when writing any test.
---

# Test conventions

## The fixture policy — read this first

| fixture | where | may a test print its content? |
|---|---|---|
| `Empty.pst` | `tests/fixtures/` (committed) | **yes** — Microsoft's, MIT, holds no mail |
| real stores | `tests/fixtures/private/` (gitignored) | **no** — structure only, never content |
| large stores | outside the repo entirely | no; absolute path, profiling only |

A test may assert that a private store **parses**. It may never assert, print,
or log **what it says** — not a subject, not an address, not a body. A failing
assertion prints its operands and CI output is a publication channel.

Three guards, and none of them may be weakened:

- `.gitignore` ignores every `*.pst` except `tests/fixtures/Empty.pst` by name
- `scripts/git-hooks/pre-commit` blocks a staged store, and checks the exempt
  fixture's md5 so the exemption cannot be used as a smuggling slot
- CI's `no-mail-stores` job, which `--no-verify` cannot bypass

## Markers

| marker | meaning | skips when |
|---|---|---|
| `oracle` | differential test against the built Rust | `reference/` absent or no `cargo` |
| `private` | needs a real store | `tests/fixtures/private/` empty |
| `slow` | full-file walk rather than a unit check | never (deselect with `-m "not slow"`) |

Every marked test must **skip cleanly**, never fail, when its precondition is
missing. A contributor with a fresh clone runs `uv run pytest` and gets green.

## Denial-first

For every layer, the refusal cases are written **before** the success cases,
because they are the ones a port silently gets wrong:

- truncated input at every structure boundary
- a length field larger than the file
- a CRC that does not match
- a cycle in any walked structure
- an unknown enum value — version, crypt method, node type

Assert the **exception type**, not merely that something raised.
`pytest.raises(PstFormatError)` — never bare `Exception`, which passes on the
`AttributeError` your refactor introduced.

`PstLimitError` and `PstFormatError` must stay distinguishable: "too big" and
"corrupt" are different answers and a caller acts on them differently.

## Differential tests

```python
from tests.conftest import run_oracle

@pytest.mark.oracle
def test_header_matches_upstream(oracle, empty_pst):
    expected = run_oracle(oracle, "read_header", str(empty_pst))
    ...
```

Parse the oracle's text into values and compare **values**, not strings:
formatting is upstream's choice and will change under you, while the facts will
not. And name the fixture in the assertion message — "matches the oracle" is
not a claim until you say on what.

## What "done" means for a test

Not that it passes. That it would **fail** if the code were wrong. When you
write a test, break the code deliberately once and watch it go red. A test that
has never been seen to fail is a comment with a slow runtime.
