# Decision records

Binding decisions **and the research behind them**. Search here before
researching anything externally — the licence analysis, the rejected
alternatives and the reasoning are recorded, not just the outcome.

Add a numbered ADR for any decision of that weight. A decision that changes
what the code must do, or that somebody will otherwise re-litigate in six
weeks, is that weight.

| # | Status | Decision |
|---|---|---|
| [0001](0001-a-port-rather-than-bindings.md) | accepted | A port rather than bindings — what pure Python buys, and what it costs |
| [0002](0002-attribution-and-patent-posture.md) | accepted | Attribution is mechanical, and the patent posture is inherited rather than created |
| [0003](0003-unicode-only.md) | accepted | Unicode stores only; ANSI is refused here and belongs to a sibling `pypst_reader_nu` |
| [0004](0004-public-fixture-corpus.md) | accepted | A hash-pinned public fixture corpus — what may enter it, and why Apache-2.0 test data is fine |

## Expected next

- **The output contract** (row P10). EML per message is assumed; MBOX or JSON
  would change what the messaging layer must extract.
- **Dev-only dependencies for testing** (row P25): `hypothesis` and
  `pytest-cov` are dev-group candidates. The zero-runtime-dependency rule is
  untouched by them, but the first non-pytest dev dependency deserves a
  paragraph.
- **Tolerating non-Outlook writers** (row P07): whether a store missing a
  property upstream requires is refused or read with the gap reported.
