# ADR-0002: Attribution is mechanical, and the patent posture is inherited rather than created

- **Status:** accepted 2026-09-15, at project inception
- **Relates to:** ADR-0001 (the decision to port at all)

## Context

This project is a derivative work of MIT-licensed code. That is a licence
question with an easy answer and a discipline question with a harder one, and
they get conflated: "we said so in NOTICE" is not the same as "a reader can
check that we said something true".

Separately, PST implementations sit under a patent posture that people
discover late and then over-react to.

## Decision

**1. Attribution is enforced by a lint, not by good intentions.**

Every module in `src/pypst/` carries, in its docstring:

```
Ported from: crates/pst/src/<file>.rs
Upstream:    microsoft/outlook-pst-rs @ <40-char sha>
```

`scripts/check_provenance.py` fails the build otherwise, and checks the sha
against `docs/UPSTREAM.txt`. A module that is genuinely ours writes
`Ported from: not a port` — a sentence somebody must choose to write.

NOTICE and LICENSE carry Microsoft's copyright line. Neither may be removed,
and the per-module headers are how a reader verifies they are honest.

**2. The name is `pypst`, and nothing implies Microsoft endorsement.**

Upstream's README reserves Microsoft's trademarks. Any user-visible string
suggesting Microsoft authorship or sponsorship is a bug.

**3. The patent posture is recorded once, here, and not re-litigated.**

[MS-PST]'s IP notice is explicit: *"Microsoft has patents that might cover your
implementations… Neither this notice nor Microsoft's delivery of this
documentation grants any licenses under those patents"*, pointing to the Open
Specification Promise and the Microsoft Community Promise as what may cover a
given document. MIT grants copyright permissions and, unlike Apache-2.0,
contains no express patent grant.

**This project neither improves nor worsens that posture.** It is identical to
the one under which `libpff` has operated since 2008, and `java-libpst`,
`go-pst`, and Microsoft's own Rust crate operate today. It is inherited from
the format, not created by the port.

The same notice **expressly permits** copying the documentation "in order to
develop implementations of the technologies that are described in this
documentation", which is exactly what porting against the spec is.

## Consequences

- A new module cannot land without recording where it came from. That is the
  point: the cost is one docstring, and the thing it buys is that NOTICE stays
  true as the tree grows.
- Moving the upstream pin is a deliberate act: change `docs/UPSTREAM.txt`,
  re-run `scripts/get_rust_source.sh`, regenerate `_tables.py`, re-run the
  suite, and update the headers of modules you actually re-verified — not all
  of them reflexively, because a header claiming verification that did not
  happen is worse than a stale one.
- **If this is ever commercialised**, the patent question is a lawyer's to
  answer against Microsoft's Patent Map, not an engineer's to answer from this
  file. Recorded here so that conversation starts from facts.
