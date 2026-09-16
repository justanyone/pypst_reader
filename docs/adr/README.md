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

## Expected next

- **ANSI or Unicode only** (row P13, decided at P01). Whichever way it goes, it
  is an ADR: it changes the shape of every module in `ndb/` and `ltp/`.
- **The output contract** (row P10). EML per message is assumed; MBOX or JSON
  would change what the messaging layer must extract.
