# `todo/` — itemised task files

One file per cluster; every task sized for ONE opus sub-agent session working
from the block alone, with no further context than the repo provides.

## Rules

- **Check the tree before you believe a status.** `git log --oneline --grep "<ID>"`
  and `ls src/pypstreader/`. A block whose work has landed is done whatever its
  `status:` says; "landed" means **committed on a ref**, never a decision line.
- **Status changes ONLY with verification recorded on the block** — a test
  count, an oracle diff that came out empty, a sha. Never from another document.
- **Keep a measured number with the conditions that make it mean anything.**
  "agrees with the oracle" without naming which fixture is worse than no claim:
  `Empty.pst` exercises almost no message code.
- **A block heading is a link target.** `MasterToDo.md` links in by anchor —
  never rename or delete a heading without updating the row.
- **`MasterToDo.md` keeps ONE ranked line per live row**, pointing here. The row
  is the state; the file is the work.
- **Every block starts with the oracle command** that proves it. If you cannot
  write that line, the block is not ready to be worked.

## Block shape

```
### P0n-NAME
status: ✗ not started | ⏳ in flight | ✅ <date> <evidence>
upstream: crates/pst/src/<file>.rs (<n> lines)
oracle:   scripts/oracle.sh <example> tests/fixtures/Empty.pst
blocked on: <row ids, or none>

<what to build, in prose. What "done" means. The traps.>
```
