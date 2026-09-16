#!/usr/bin/env python3
"""Capture the Rust oracle's output over the public corpus into tests/golden/.

Why goldens exist at all: the differential method ("run both implementations
over the same bytes, diff") needs the Rust built, which CI does not do on every
push and a contributor may never do. But the public corpus is redistributable,
so the oracle's output over it is too. Capturing it once and committing it
means every differential test runs everywhere, Rust or no Rust — and the
`oracle` marker tests re-capture when cargo IS present and fail if the goldens
drifted, which is how a moved upstream pin announces itself.

Layout:  tests/golden/<fixture-stem>/<example>.txt
         tests/golden/<fixture-stem>/<example>.exit     (only when non-zero)
         tests/golden/MANIFEST.txt                       (which pin produced them)

Never captured:
  browse_pst    — a TUI, not a dump
  rebuild_amap  — MODIFIES the file it is given; must never touch a fixture

Private stores are never captured: their oracle output is their content.

Usage: python3 scripts/capture_oracle.py [--check] [--fixture NAME ...] [--example NAME ...]
  --check   re-run and diff against the committed goldens instead of writing
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"
PUBLIC = FIXTURES / "public"
GOLDEN = REPO / "tests" / "golden"
ORACLE = REPO / "scripts" / "oracle.sh"
PIN = REPO / "docs" / "UPSTREAM.txt"

EXAMPLES = [
    "read_header",
    "read_btrees",
    "read_density_list",
    "read_store_props",
    "read_named_props",
    "read_root_folder",
    "read_ipm_subtree",
    "read_search_updates",
]
FORBIDDEN = {"browse_pst", "rebuild_amap"}

# Rust's Debug formatting of a `Box<dyn Error>` or a pointer can carry an
# address; nothing in these examples does today, but strip it if it appears
# so a golden never depends on ASLR.
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{12,16}(?![0-9a-fA-F])")


def fixtures() -> list[Path]:
    stores = [FIXTURES / "Empty.pst"]
    manifest = PUBLIC / "MANIFEST.sha256"
    if manifest.exists():
        for line in manifest.read_text().splitlines():
            if "  " in line:
                stores.append(PUBLIC / line.split("  ", 1)[1].strip())
    return stores


def pinned_rev() -> str:
    match = re.search(r"^REV=([0-9a-f]{40})$", PIN.read_text(), re.MULTILINE)
    return match.group(1) if match else "unknown"


def run(example: str, store: Path) -> tuple[str, int]:
    assert example not in FORBIDDEN, example
    proc = subprocess.run(
        [str(ORACLE), example, str(store)],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
        timeout=600,
    )
    # cargo's own chatter goes to stderr; the example's Error: lines go to
    # stdout in every example here. Keep stdout only.
    return _ADDRESS.sub("<addr>", proc.stdout), proc.returncode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--fixture", action="append", default=None, help="fixture stem(s) to limit to")
    ap.add_argument("--example", action="append", default=None, help="example(s) to limit to")
    args = ap.parse_args()

    examples = args.example or EXAMPLES
    bad = FORBIDDEN & set(examples)
    if bad:
        print(f"refusing to capture {sorted(bad)}: see the module docstring", file=sys.stderr)
        return 2

    stores = [s for s in fixtures() if not args.fixture or s.stem in args.fixture]
    drift: list[str] = []
    for store in stores:
        out_dir = GOLDEN / store.stem
        for example in examples:
            text, code = run(example, store)
            txt = out_dir / f"{example}.txt"
            exit_file = out_dir / f"{example}.exit"
            if args.check:
                want = txt.read_text() if txt.exists() else None
                want_code = int(exit_file.read_text()) if exit_file.exists() else 0
                if want != text or want_code != code:
                    drift.append(f"{store.stem}/{example}")
                continue
            out_dir.mkdir(parents=True, exist_ok=True)
            txt.write_text(text)
            if code:
                exit_file.write_text(f"{code}\n")
            elif exit_file.exists():
                exit_file.unlink()
            print(f"{store.stem:28s} {example:20s} {len(text.splitlines()):5d} lines  exit {code}")

    if args.check:
        if drift:
            print("goldens drifted from the oracle:")
            for d in drift:
                print(f"  {d}")
            return 1
        print(f"goldens match the oracle for {len(stores)} fixture(s)")
        return 0

    (GOLDEN / "MANIFEST.txt").write_text(
        "# Oracle goldens. Regenerate with scripts/capture_oracle.py; verify with --check.\n"
        f"UPSTREAM_REV={pinned_rev()}\n"
        f"EXAMPLES={','.join(examples)}\n"
        f"FIXTURES={','.join(s.stem for s in stores)}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
