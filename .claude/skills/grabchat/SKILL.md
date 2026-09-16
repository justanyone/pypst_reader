---
name: grabchat
description: >-
  Export the current Claude Code session transcript to a Markdown file in
  .chat_history/. Optional arg: output filename (default extension .md). If no
  path is given, file lands in .chat_history/. Use /grabchat --help for usage.
---

# grabchat — Export session transcript to Markdown

Converts the current (or a selected) Claude Code session transcript into a
readable Markdown file. (Imported from https://github.com/justanyone/grabchat;
the implementation lives at `.claude/scripts/grabchat.py`, configuration at
`.chat_history/grabchat.ini`.)

## If `args` is `--help`, `help`, or `-h`

Run `pwd` to get the absolute project root, then print this help to the user
(substituting the real absolute path for `<ROOT>`):

```
grabchat — export a Claude Code session transcript to Markdown

Usage:
  /grabchat                   export the latest session (auto-named)
  /grabchat myfile            save to .chat_history/myfile.md
  /grabchat myfile.md         same (extension kept as-is)
  /grabchat path/to/file.md   save to an explicit path
  /grabchat --list            pick from the 5 most recent sessions
  /grabchat --list 10         pick from the 10 most recent sessions

Default output directory:
  <ROOT>/.chat_history/

Open the output directory:
  In Chrome   →  file://<ROOT>/.chat_history/
  In VSCode   →  [.chat_history/](.chat_history/)
                 (click the link in the VSCode Simple Browser or Explorer)

File names follow the pattern:
  chat_<session-start>_exp_<export-time>.md
```

## Otherwise — run the export

Resolve the output path from `args`:

| `args` value | `-o` flag value passed to script |
|---|---|
| empty / absent | (omit `-o`; script auto-names the file) |
| bare name with no extension, e.g. `myfile` | `.chat_history/myfile.md` |
| bare name with extension, e.g. `myfile.md` | `.chat_history/myfile.md` |
| path containing `/`, e.g. `path/to/out.md` | `path/to/out.md` (used as-is) |
| `--list` | pass `--list` to the script instead of `-o` |
| `--list N` | pass `--list N` to the script |

Run the script from the repository root:

```bash
python3 .claude/scripts/grabchat.py [--list [N] | -o <resolved-path>]
```

By default the script also launches the exported file in a real browser
itself (direct `google-chrome`/`chromium` binary launch, non-blocking,
best-effort — falls back to `xdg-open` only if no browser binary is found).
Note: `xdg-open`/`gio open` alone is *not* enough here, since on this desktop
`.md` files are file-type-associated with a text editor, not the browser —
launching the browser binary directly bypasses that association. This chat
UI's webview also blocks navigation on `file://` markdown links, so a
clickable link in the chat text does **not** open the browser either; the
script's direct launch is the only reliable path. Pass `--no-open` to skip
this, or set `auto_open_browser = false` in `.chat_history/grabchat.ini`.

After the script exits successfully, print the output file path to the user
as both a plain path and a clickable VSCode-friendly markdown link (this one
works, since it's a relative in-workspace link, not `file://`), e.g.:
```
Exported to: .chat_history/chat_20260703_175255_exp_20260703_192115.md
Open in VSCode: [.chat_history/…](.chat_history/chat_20260703_175255_exp_20260703_192115.md)
Opened automatically in your default browser.
```
Do not claim a `file://` markdown link is clickable — it isn't, in this UI.
