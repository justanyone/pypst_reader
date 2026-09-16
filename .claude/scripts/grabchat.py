#!/usr/bin/env python3
"""
grabchat.py — Convert a Claude Code session transcript to readable Markdown.

Usage:
    python3 scripts/grabchat.py                     # export the latest session
    python3 scripts/grabchat.py path/to/file.jsonl  # export a specific file
    python3 scripts/grabchat.py -o out.md           # custom output path
    python3 scripts/grabchat.py --list              # list 5 recent sessions, prompt to export
    python3 scripts/grabchat.py --list 10           # list 10 recent sessions

Output goes to .chat_history/ with a name derived from the session start time and
the export time, so re-running never clobbers a previous export of the same session:

    .chat_history/chat_20260703_175255_exp_20260703_192115.md
                        ↑ session start          ↑ export time
"""

import argparse
import configparser
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


_CLAUDE_PROJECTS = Path.home() / ".claude" / "projects"
_CHAT_HISTORY = Path(".chat_history")

# ---------------------------------------------------------------------------
# Configuration — .chat_history/grabchat.ini overrides these defaults.
# ---------------------------------------------------------------------------
_INI_PATH = _CHAT_HISTORY / "grabchat.ini"

_DEFAULTS: dict[str, str] = {
    # Timestamp style: A=sub B=bold C=code D=color E=mark F=pill
    "timestamp_style": "F",
    # Keep only the latest N chat_*_exp_*.md files; move older ones to /tmp (0=disabled)
    "keep_latest_exports": "10",
    # When true, output is saved_chatlog_YYYYMMDD_HHMM.md instead of the default name
    "preserve_latest": "false",
    # Default N for --list when no number is given
    "list_count": "5",
    # Launch the exported file in the default browser after writing it
    "auto_open_browser": "true",
}


def _load_config() -> dict[str, str]:
    """Read grabchat.ini and return settings merged over _DEFAULTS."""
    cfg = dict(_DEFAULTS)
    if _INI_PATH.exists():
        cp = configparser.ConfigParser()
        cp.read(_INI_PATH)
        if "grabchat" in cp:
            for key in _DEFAULTS:
                if key in cp["grabchat"]:
                    cfg[key] = cp["grabchat"][key].strip()
    return cfg


# IDE / system noise tags to strip from human turns
_STRIP_TAGS = re.compile(
    r"<(system-reminder|ide_opened_file|ide_selection|ide_context"
    r"|local-command-stdout|task-notification|user-prompt-submit-hook)"
    r">.*?</\1>",
    re.DOTALL,
)

# Slash-command invocation stub, e.g. the literal turn Claude Code inserts
# when a user runs /grabchat: "<command-message>grabchat</command-message>
# <command-name>/grabchat</command-name>". The skill body that Claude Code
# injects as the *next* user turn (same promptId) is the "how to run this
# skill" text — also not something the human wrote — and is skipped alongside it.
_COMMAND_STUB = re.compile(
    r"^\s*<command-message>.*?</command-message>\s*"
    r"<command-name>.*?</command-name>\s*"
    r"(?:<command-args>.*?</command-args>\s*)?$",
    re.DOTALL,
)

# Key input field to surface per tool name (everything else gets a generic summary)
_TOOL_KEY = {
    "Read": "file_path",
    "Edit": "file_path",
    "Write": "file_path",
    "Bash": "command",
    "Agent": "description",
    "Workflow": "description",
    "WebFetch": "url",
    "WebSearch": "query",
    "Skill": "skill",
    "Artifact": "file_path",
    "SendMessage": "to",
    "TodoWrite": None,
}


# ---------------------------------------------------------------------------
# Directory / file helpers
# ---------------------------------------------------------------------------

def _find_project_dir(cwd: Path = Path.cwd()) -> Path:
    """
    Locate the Claude Code project directory for this repo.

    Claude encodes the working directory as a hyphen-joined path, e.g.
    /home/alice/code/yourProject  →  -home-alice-code-yourProject

    We look for any subdirectory of ~/.claude/projects/ whose name ends with
    the repo's directory name (last component of cwd), preceded by a hyphen.
    If more than one match exists we pick the one modified most recently.
    """
    repo_name = cwd.name
    suffix = f"-{repo_name}"

    if not _CLAUDE_PROJECTS.exists():
        sys.exit(f"Claude projects directory not found: {_CLAUDE_PROJECTS}")

    candidates = [
        p for p in _CLAUDE_PROJECTS.iterdir()
        if p.is_dir() and p.name.endswith(suffix)
    ]

    if not candidates:
        sys.exit(
            f"No Claude project directory ending in '{suffix}' found under:\n"
            f"  {_CLAUDE_PROJECTS}\n"
            f"Available: {[p.name for p in _CLAUDE_PROJECTS.iterdir() if p.is_dir()]}"
        )

    return max(candidates, key=lambda p: p.stat().st_mtime)


def _find_latest(directory: Path) -> Path:
    files = sorted(directory.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
    if not files:
        sys.exit(f"No .jsonl files found in {directory}")
    return files[-1]


def _list_sessions(directory: Path, n: int) -> list[Path]:
    """Return the n most-recently-modified .jsonl files, newest first."""
    files = sorted(directory.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[:n]


# ---------------------------------------------------------------------------
# Per-session metadata helpers
# ---------------------------------------------------------------------------

def _session_start(src: Path) -> str:
    """Return 'YYYYMMDD_HHMMSS' (UTC) of the first timestamped entry."""
    with src.open(encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            ts = obj.get("timestamp", "")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    return dt.strftime("%Y%m%d_%H%M%S")
                except Exception:
                    pass
    return "unknown"


def _key_to_dt(key: str) -> datetime:
    """Parse a session key back to a UTC-aware datetime."""
    try:
        return datetime.strptime(key, "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _first_question(src: Path, max_chars: int = 30) -> str:
    """Return the first ≤max_chars of the first human question in the transcript."""
    with src.open(encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "user" or obj.get("isSidechain"):
                continue
            content = obj.get("message", {}).get("content", [])
            if isinstance(content, str):
                content = [{"type": "text", "text": content}]
            for block in content:
                if block.get("type") == "text":
                    text = re.sub(_STRIP_TAGS, "", block.get("text", "")).strip()
                    text = text.replace("\n", " ")
                    if text:
                        return text[:max_chars] + ("…" if len(text) > max_chars else "")
    return "(empty)"


def _is_exported(session_key: str) -> bool:
    """True if at least one export of this session exists in .chat_history/."""
    return any(_CHAT_HISTORY.glob(f"chat_{session_key}_exp_*.md"))


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _time_ago(dt: datetime) -> str:
    secs = int((datetime.now(timezone.utc) - dt).total_seconds())
    if secs < 60:
        return f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    if secs < 86400 * 7:
        return f"{secs // 86400}d ago"
    if secs < 86400 * 30:
        return f"{secs // (86400 * 7)}w ago"
    return f"{secs // (86400 * 30)}mo ago"


# ---------------------------------------------------------------------------
# --list interactive flow
# ---------------------------------------------------------------------------

def list_and_prompt(n: int) -> Path:
    """Print a table of the n most recent sessions and return the user's choice."""
    project_dir = _find_project_dir()
    sessions = _list_sessions(project_dir, n)

    if not sessions:
        sys.exit("No chat sessions found.")

    # Gather metadata for all sessions (one pass each, but only first lines for speed)
    rows = []
    for path in sessions:
        key = _session_start(path)
        start_dt = _key_to_dt(key)
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        size = _human_size(path.stat().st_size)
        question = _first_question(path)
        exported = "✓" if _is_exported(key) else ""
        rows.append((path, key, start_dt, mtime, size, question, exported))

    # Column widths
    started_w = 16   # "2026-07-03 17:52"
    updated_w = 10   # "2h ago"
    size_w = 8       # "145.0 KB"
    exp_w = 3        # "✓" or ""

    header = (
        f"  {'#':>2}  {'Started':<{started_w}}  {'Updated':>{updated_w}}"
        f"  {'Size':>{size_w}}  {'Exp':<{exp_w}}  {'First question'}"
    )
    print(f"\nAvailable sessions ({len(rows)} most recent):\n")
    print(header)
    print("  " + "-" * (len(header) - 2))

    for i, (path, key, start_dt, mtime, size, question, exported) in enumerate(rows, 1):
        started = start_dt.strftime("%Y-%m-%d %H:%M")
        updated = _time_ago(mtime)
        print(
            f"  {i:>2}  {started:<{started_w}}  {updated:>{updated_w}}"
            f"  {size:>{size_w}}  {exported:<{exp_w}}  {question}"
        )

    print()
    try:
        raw = input(f"Export which? [1–{len(rows)}, default 1]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

    if not raw:
        idx = 0
    else:
        try:
            idx = int(raw) - 1
        except ValueError:
            sys.exit(f"Invalid choice: {raw!r}")
        if not 0 <= idx < len(rows):
            sys.exit(f"Choice out of range: {raw}")

    return rows[idx][0]


# ---------------------------------------------------------------------------
# Transcript parsing
# ---------------------------------------------------------------------------

def _tool_summary(name: str, inp: dict) -> str:
    field = _TOOL_KEY.get(name, next(iter(inp), None))
    if field is None:
        return ""
    val = str(inp.get(field, "")).strip().replace("\n", " ")
    if len(val) > 100:
        val = val[:97] + "…"
    return f"`{val}`" if val else ""


def _render_assistant(blocks: list) -> str:
    """Render assistant content blocks: text + brief tool stubs; skip thinking."""
    parts = []
    for block in blocks:
        btype = block.get("type", "")
        if btype == "text":
            t = block.get("text", "").strip()
            if t:
                parts.append(t)
        elif btype == "tool_use":
            name = block.get("name", "?")
            summary = _tool_summary(name, block.get("input", {}))
            stub = f"> `[{name}]`"
            if summary:
                stub += f" {summary}"
            parts.append(stub)
    return "\n\n".join(parts)


def _render_human(blocks: list) -> str:
    """Render human content blocks: text only, strip system noise."""
    texts = []
    for block in blocks:
        if block.get("type") == "text":
            t = re.sub(_STRIP_TAGS, "", block.get("text", "")).strip()
            if t:
                texts.append(t)
    return "\n\n".join(texts)


def parse_transcript(path: Path) -> list[dict]:
    """
    Walk a .jsonl transcript and return a flat list of conversation turns.
    Each turn: {"role": "human"|"assistant", "text": str, "ts": str}
    Side-chain messages (subagent transcripts) are skipped.
    """
    turns = []
    skip_prompt_ids: set[str] = set()
    with path.open(encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue

            if obj.get("type") not in ("user", "assistant"):
                continue
            if obj.get("isSidechain"):
                continue

            msg = obj.get("message", {})
            role = msg.get("role")
            content = msg.get("content", [])
            ts = obj.get("timestamp", "")
            prompt_id = obj.get("promptId")

            if isinstance(content, str):
                content = [{"type": "text", "text": content}]

            if role == "user":
                text_blocks = [b for b in content if b.get("type") == "text"]
                is_stub = (
                    len(text_blocks) == 1
                    and len(content) == 1
                    and _COMMAND_STUB.match(text_blocks[0].get("text", "") or "")
                )
                if is_stub or (prompt_id and prompt_id in skip_prompt_ids):
                    if prompt_id:
                        skip_prompt_ids.add(prompt_id)
                    continue
                if not text_blocks:
                    continue
                text = _render_human(content)
                if text:
                    turns.append({"role": "human", "text": text, "ts": ts})

            elif role == "assistant":
                text = _render_assistant(content)
                if text:
                    turns.append({"role": "assistant", "text": text, "ts": ts})

    return turns


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def _fmt_ts(ts: str) -> str:
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone()
        return dt.strftime("%H:%M:%S %Z")
    except Exception:
        return ts


def _style_ts(ts: str, style: str) -> str:
    """Wrap a formatted timestamp string according to the chosen style letter."""
    if not ts:
        return ""
    s = style.upper()
    if s == "A":
        return f"<sub>{ts}</sub>"
    if s == "B":
        return f"**{ts}**"
    if s == "C":
        return f"`{ts}`"
    if s == "D":
        return f'<span style="color:#6ea8d8">{ts}</span>'
    if s == "E":
        return f"<mark>{ts}</mark>"
    # F — inverted pill (default)
    return (
        f'<span style="background:#c8cfe0;color:#0f1117;padding:1px 6px;'
        f'border-radius:3px;font-size:.82em;font-weight:600;'
        f'letter-spacing:.02em;font-family:monospace">{ts}</span>'
    )


def render_markdown(turns: list[dict], src: Path, style: str = "F") -> str:
    lines = [
        "# Claude Code Session Transcript",
        "",
        f"**Source:** `{src}`  ",
        f"**Exported:** {datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M %Z')}  ",
        f"**Turns:** {len(turns)}",
        "",
        "---",
        "",
    ]

    # Group consecutive same-role turns into one section each
    groups: list[dict] = []
    for turn in turns:
        if groups and groups[-1]["role"] == turn["role"]:
            groups[-1]["entries"].append(turn)
        else:
            groups.append({"role": turn["role"], "entries": [turn]})

    for group in groups:
        label = "Human" if group["role"] == "human" else "Assistant"
        lines.append(f"## {label}")
        for i, entry in enumerate(group["entries"]):
            ts = _fmt_ts(entry["ts"])
            text = entry["text"].strip()
            if i > 0:
                lines.append("")
            text_lines = text.split("\n")
            prefix = (_style_ts(ts, style) + " ") if ts else ""
            lines.append(f"{prefix}{text_lines[0]}")
            for tl in text_lines[1:]:
                lines.append(tl)
        lines += ["", "---", ""]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Default output path
# ---------------------------------------------------------------------------

def _default_output(src: Path) -> Path:
    """Build a timestamped output path unique per session and per export run."""
    session = _session_start(src)
    export = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return _CHAT_HISTORY / f"chat_{session}_exp_{export}.md"


# ---------------------------------------------------------------------------
# Export pruning
# ---------------------------------------------------------------------------

def _prune_exports(keep: int) -> None:
    """Move all but the latest `keep` chat_*_exp_*.md files to /tmp."""
    if keep <= 0:
        return
    exports = sorted(_CHAT_HISTORY.glob("chat_*_exp_*.md"))
    to_move = exports[:-keep] if keep < len(exports) else []
    for f in to_move:
        dest = Path("/tmp") / f.name
        shutil.move(str(f), str(dest))
        print(f"Pruned: {f.name} → /tmp", file=sys.stderr)


# ---------------------------------------------------------------------------
# Browser launch
# ---------------------------------------------------------------------------

_BROWSER_BINARIES = [
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
]


def _open_in_browser(path: Path) -> None:
    """
    Best-effort launch of a real browser on the exported file. Never fatal.

    xdg-open/gio dispatch .md files to the desktop's registered file-type
    handler (a text editor on GNOME), not the default *browser* — so we
    launch a known browser binary directly instead. Falls back to xdg-open
    only if no browser binary is found.
    """
    uri = path.resolve().as_uri()
    for binary in _BROWSER_BINARIES:
        if shutil.which(binary):
            try:
                subprocess.Popen(
                    [binary, uri],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return
            except OSError:
                continue
    try:
        subprocess.Popen(
            ["xdg-open", uri],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, FileNotFoundError) as exc:
        print(f"Could not auto-open browser ({exc}); open manually: {uri}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    cfg = _load_config()

    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "input", nargs="?",
        help="Path to .jsonl file (default: latest in the auto-detected project dir)",
    )
    ap.add_argument(
        "-o", "--output", default=None,
        help="Output .md path (default: .chat_history/chat_<session>_exp_<now>.md)",
    )
    ap.add_argument(
        "--list", nargs="?", const=int(cfg["list_count"]), type=int, metavar="N",
        dest="list_n",
        help="List the N most recent sessions and prompt for which to export"
             f" (default N={cfg['list_count']})",
    )
    ap.add_argument(
        "--no-open", action="store_true",
        help="Don't launch the default browser on the exported file"
             " (overrides auto_open_browser in grabchat.ini)",
    )
    args = ap.parse_args()

    # Resolve source file
    if args.list_n is not None:
        src = list_and_prompt(args.list_n)
        print(f"Source: {src}", file=sys.stderr)
    elif args.input:
        src = Path(args.input)
        if not src.exists():
            sys.exit(f"File not found: {src}")
    else:
        project_dir = _find_project_dir()
        src = _find_latest(project_dir)
        print(f"Source: {src}", file=sys.stderr)

    # Parse and render
    turns = parse_transcript(src)
    if not turns:
        sys.exit("No conversation turns found in transcript.")

    md = render_markdown(turns, src, cfg["timestamp_style"])

    # Determine output path
    if args.output:
        out = Path(args.output)
    elif cfg["preserve_latest"].lower() in ("1", "true", "yes"):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
        out = _CHAT_HISTORY / f"saved_chatlog_{stamp}.md"
    else:
        out = _default_output(src)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print(f"Written: {out}  ({len(turns)} turns, {len(md):,} chars)", file=sys.stderr)
    print(out)

    if not args.no_open and cfg["auto_open_browser"].lower() in ("1", "true", "yes"):
        _open_in_browser(out)

    # Prune old exports (skips saved_chatlog_* files — only touches chat_*_exp_*.md)
    _prune_exports(int(cfg["keep_latest_exports"]))


if __name__ == "__main__":
    main()
