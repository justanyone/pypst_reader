#!/usr/bin/env bash
# get_fixture_tools.sh — fetch the tools that GENERATE fixtures into reference/.
#
# Modelled on get_rust_source.sh, for the same reasons: a fixture generator is
# not the product and is not a dependency of it. It is fetched, pinned to the
# revision in docs/FIXTURE-TOOLS.txt, gitignored, and never vendored. What is
# committed is the pin, the patch we apply on top of it, the EML sources we
# author, and the store the tool wrote from them — hash-pinned like every
# other corpus member (ADR-0004).
#
# The tool is patched after checkout (PATCH= in the pin file), because at the
# pinned revision its output is refused by the upstream oracle. The patched
# checkout is therefore always "dirty" in git's eyes; this script recognises
# exactly that state (the working-tree diff reverse-applies to the patch) and
# refuses any other modification, so an experiment left in the checkout cannot
# silently become part of a fixture.
#
# Usage: scripts/get_fixture_tools.sh [--update]
#
#   --update   discard local modifications, re-pin, and re-apply the patch

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PIN_FILE="docs/FIXTURE-TOOLS.txt"
[[ -f $PIN_FILE ]] || { echo "get_fixture_tools.sh: $PIN_FILE not found" >&2; exit 1; }

NAME="$(grep -E '^NAME=' "$PIN_FILE" | cut -d= -f2-)"
URL="$(grep -E '^URL=' "$PIN_FILE" | cut -d= -f2-)"
REV="$(grep -E '^REV=' "$PIN_FILE" | cut -d= -f2-)"
PATCH="$(grep -E '^PATCH=' "$PIN_FILE" | cut -d= -f2- || true)"
DEST="reference/$NAME"

command -v git >/dev/null || { echo "git is required" >&2; exit 1; }
[[ -n $PATCH && ! -f $PATCH ]] && { echo "get_fixture_tools.sh: $PATCH not found" >&2; exit 1; }

if [[ ! -d $DEST/.git ]]; then
    echo "cloning $URL -> $DEST"
    mkdir -p reference
    git clone --quiet "$URL" "$DEST"
else
    echo "fetching updates in $DEST"
    git -C "$DEST" fetch --quiet origin
fi

patched() {
    # True when the checkout's modification IS our patch, exactly. A reverse
    # `--check` alone would only prove the patch's hunks are present; this
    # stages the working tree, reverses the patch in the index, and demands
    # that nothing remains — so a stray edit next to the patch is refused too.
    [[ -n $PATCH ]] || return 1
    git -C "$DEST" diff --quiet -- . && return 1
    local exact=1
    if git -C "$DEST" add -u -- . \
        && git -C "$DEST" apply --reverse --cached "$REPO_ROOT/$PATCH" 2>/dev/null \
        && git -C "$DEST" diff --cached --quiet HEAD -- .; then
        exact=0
    fi
    git -C "$DEST" reset -q -- .
    return $exact
}

if [[ ${1:-} == "--update" ]]; then
    git -C "$DEST" checkout --quiet -- .
elif ! git -C "$DEST" diff --quiet -- .; then
    if patched && [[ "$(git -C "$DEST" rev-parse HEAD)" == "$REV" ]]; then
        echo "$DEST is at $(git -C "$DEST" rev-parse --short HEAD) (pinned $REV), patch applied"
        exit 0
    fi
    echo "get_fixture_tools.sh: $DEST has local modifications that are not $PATCH; refusing to move it." >&2
    echo "Inspect them (git -C $DEST diff), then re-run with --update to discard them." >&2
    exit 1
fi

git -C "$DEST" checkout --quiet "$REV"
if [[ -n $PATCH ]]; then
    git -C "$DEST" apply "$REPO_ROOT/$PATCH"
    echo "applied $PATCH"
fi
echo "$DEST is at $(git -C "$DEST" rev-parse --short HEAD) (pinned $REV)"
echo
echo "Next:"
echo "  uv run python scripts/make_fixture.py --check basics   # the committed store still regenerates"
