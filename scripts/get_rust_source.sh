#!/usr/bin/env bash
# get_rust_source.sh — fetch the upstream Rust implementation into reference/.
#
# The Rust is NOT vendored into this repository. It is fetched, pinned to the
# revision in docs/UPSTREAM.txt, and gitignored. Three reasons, in order:
#
#   1. It is the ORACLE, not the product. Differential tests run it; nothing
#      ships it. Vendoring would put 15k lines of someone else's code in every
#      clone and every diff of this project.
#   2. A pin in a text file is auditable. A vendored copy drifts silently.
#   3. The MIT licence requires attribution where the code is DISTRIBUTED
#      (see NOTICE, which covers the port itself). Not re-distributing the
#      Rust keeps that obligation simple and single-sited.
#
# Usage: scripts/get_rust_source.sh [--update]
#
#   --update   move to the pinned revision even if the checkout is dirty

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PIN_FILE="docs/UPSTREAM.txt"
[[ -f $PIN_FILE ]] || { echo "get_rust_source.sh: $PIN_FILE not found" >&2; exit 1; }

URL="$(grep -E '^URL=' "$PIN_FILE" | cut -d= -f2-)"
REV="$(grep -E '^REV=' "$PIN_FILE" | cut -d= -f2-)"
DEST="reference/outlook-pst-rs"

command -v git >/dev/null || { echo "git is required" >&2; exit 1; }

if [[ ! -d $DEST/.git ]]; then
    echo "cloning $URL -> $DEST"
    mkdir -p reference
    git clone --quiet "$URL" "$DEST"
else
    echo "fetching updates in $DEST"
    git -C "$DEST" fetch --quiet origin
fi

if [[ -n "$(git -C "$DEST" status --porcelain)" && ${1:-} != "--update" ]]; then
    echo "get_rust_source.sh: $DEST has local modifications; refusing to move it." >&2
    echo "Inspect them (they are probably experiments), then re-run with --update." >&2
    exit 1
fi

git -C "$DEST" checkout --quiet "$REV"
echo "reference/outlook-pst-rs is at $(git -C "$DEST" rev-parse --short HEAD) (pinned $REV)"
echo
echo "Next:"
echo "  scripts/build_oracle.sh          # compile the example binaries (~3 min first time)"
echo "  python3 scripts/extract_key_data.py --check"
