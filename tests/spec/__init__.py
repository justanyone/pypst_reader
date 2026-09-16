"""Tier T1 — vectors typed from the published specifications, not from upstream.

Every other tier in docs/TEST-PLAN.md ultimately trusts microsoft/outlook-pst-rs:
the parity twins re-run its tests, the goldens are its output, the oracle IS it.
If upstream and this port share a bug, all of those tiers agree and all of
them are wrong. This package is the one place that can notice.

The rule for a file in here: an expected value comes from [MS-PST],
[MS-OXCDATA], [MS-DTYP] or [MS-OXRTFCP] — a table row, a worked example, a
field offset summed from the widths the spec lists — and never from
`reference/`, never from a golden, and never from running our own code and
pasting what it printed. Each test's docstring names the spec and section and
says whether the value is *verbatim* (copied from the page) or *derived* (and
shows the arithmetic). A reader who suspects a vector should be able to open
the cited section and check it in a minute.

Where the spec gives only prose, the smallest independent check is used: the
CRC table is rebuilt from its polynomial; header offsets are summed from the
field widths; a real store written by Outlook (`tests/fixtures/Empty.pst` and
the public corpus) is read at those offsets and the fields the spec calls
MUST are asserted. Real bytes are the strongest vector of all: Outlook wrote
them by the spec, and it has never read our code.

Where the spec and upstream disagree, the test says so rather than quietly
following either — see the `xfail(strict=True)` cases. Making the
disagreement visible in every test run is the whole reason this tier exists.
"""
