#!/usr/bin/env bash
# oracle.sh — run one upstream example against a PST and print its output.
#
# This is the single most useful command in the project while porting: it is
# the ground truth you diff your Python against. Capture it, port a layer,
# compare, repeat.
#
# Usage: scripts/oracle.sh <example> <pst-path> [args...]
#        scripts/oracle.sh --list
#
# Examples:
#   scripts/oracle.sh read_header tests/fixtures/Empty.pst
#   scripts/oracle.sh read_btrees tests/fixtures/private/throwaway.pst
#   scripts/oracle.sh browse_pst  tests/fixtures/private/throwaway.pst   # TUI
#
# NOTE: output from a private store is somebody's mail. Do not paste it into
# an issue, a commit message, or a chat transcript.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DEST="reference/outlook-pst-rs"
[[ -d $DEST ]] || { echo "run scripts/get_rust_source.sh first" >&2; exit 1; }
command -v cargo >/dev/null || export PATH="$HOME/.cargo/bin:$PATH"

# Our own examples (oracle/, compiled against the same pinned crate) fill the
# gaps upstream leaves — today `dump_messages`, the message-level dump that
# upstream only offers as a TUI. Same output conventions, same goldens.
OURS="oracle"

if [[ ${1:-} == "--list" || $# -lt 1 ]]; then
    echo "examples:"
    ls "$DEST/crates/pst/examples"/*.rs | xargs -n1 basename | sed 's/\.rs$//' | sed 's/^/  /'
    echo "examples (ours, $OURS/):"
    ls "$OURS/examples"/*.rs | xargs -n1 basename | sed 's/\.rs$//' | sed 's/^/  /'
    exit 0
fi

EXAMPLE="$1"; shift
[[ $# -ge 1 ]] || { echo "usage: scripts/oracle.sh <example> <pst-path> [args...]" >&2; exit 1; }

# Resolve the PST to an absolute path: cargo runs from the crate directory,
# so a relative path would resolve against the wrong root and produce a
# confusing "file not found" three layers into someone else's code.
PST="$(cd "$(dirname -- "$1")" && pwd)/$(basename -- "$1")"; shift
[[ -f $PST ]] || { echo "oracle.sh: no such file: $PST" >&2; exit 1; }

if [[ -f "$DEST/crates/pst/examples/$EXAMPLE.rs" ]]; then
    cd "$DEST/crates/pst"
    exec cargo run --quiet --example "$EXAMPLE" -- "$PST" "$@"
elif [[ -f "$OURS/examples/$EXAMPLE.rs" ]]; then
    # cd, not --manifest-path: cargo finds oracle/.cargo/config.toml (the
    # shared target dir) from the working directory, not from the manifest.
    cd "$OURS"
    exec cargo run --quiet --example "$EXAMPLE" -- "$PST" "$@"
else
    echo "oracle.sh: no example named '$EXAMPLE' (see --list)" >&2
    exit 1
fi
