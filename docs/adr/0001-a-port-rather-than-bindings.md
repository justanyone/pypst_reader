# ADR-0001: A port rather than bindings — what pure Python buys, and what it costs

- **Status:** accepted 2026-09-15, at project inception
- **Supersedes:** nothing

## Context

Reading a PST from Python today means `libpff`: a C library under LGPL-3,
reached through a compiled extension (`pypff` / `libpff-python`). Every
existing Python route — `libratom` included, MIT though it is — has `libpff`
underneath it.

Two other routes exist and were considered rather than assumed away:

1. **PyO3 bindings over `microsoft/outlook-pst-rs`.** Days of work, not weeks.
   MIT throughout. Keeps upstream's correctness and inherits its fixes.
2. **A subprocess boundary** around an existing engine (`pffexport`,
   `readpst`), which is how a vault-style product would isolate a C parser
   fed attacker-chosen bytes.

## Decision

**Port the read path to pure Python.**

## Consequences

**What it buys, in the order the reasons actually weigh:**

- **No native build.** A plain wheel, installable air-gapped, on any platform
  Python runs on, with no toolchain and no per-platform artifacts.
- **No copyleft conveyance obligation.** MIT in, MIT out. The LGPL-3 source
  offer that follows `libpff` into every distribution simply is not there.
- **Auditability.** A few thousand lines of readable Python that a reviewer can
  follow end to end, versus a C library plus a binding layer.
- **Memory safety against hostile input** — which for a mail-store parser is
  the substantive security property, not a nicety.

**What it costs, stated plainly:**

- **Weeks, not days**, against the bindings alternative.
- **We own the correctness.** Upstream's fixes do not flow to us; each one is a
  re-port. The pin in `docs/UPSTREAM.txt` is how we at least know what we are
  behind.
- **It will be slower than the Rust.** Acceptable because the two hottest loops
  are C in Python anyway (`bytes.translate`, `zlib.crc32`), and the rest is
  per-item work.
- **CI cannot prove the messaging layer**, because the only redistributable
  fixture holds no mail. See PORTING-PLAN § "What we do not have".

**Why bindings were rejected despite being cheaper:** they reintroduce the
native build, which is half of what makes the `libpff` route unpleasant. A
project whose entire value proposition is "installs anywhere, reads anywhere,
audit it yourself" cannot ship a compiled extension and still make the claim.

**The escape hatch, recorded so it is a decision and not a discovery:** if the
port stalls in the LTP layer, PyO3 bindings remain available, MIT, and a week's
work. Choosing them later is a retreat, not a failure — but it is an ADR, not a
quiet pivot.
