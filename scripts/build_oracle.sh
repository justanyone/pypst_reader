#!/usr/bin/env bash
# build_oracle.sh — compile the upstream example binaries used as the oracle.
#
# Rust has no virtualenv. The equivalent isolation is that cargo keeps every
# dependency and build artifact inside the checkout's own `target/` directory
# and installs nothing globally, so this is self-contained and deleting
# reference/ removes all of it. `~/.cargo` and `~/.rustup` (the toolchain
# itself) are the only things outside the tree, and rustup installed those.
#
# Footprint: roughly 270 MB in reference/outlook-pst-rs (measured 2026-09-15: source + debug target).
#
# Usage: scripts/build_oracle.sh [--release]

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DEST="reference/outlook-pst-rs"
[[ -d $DEST ]] || { echo "run scripts/get_rust_source.sh first" >&2; exit 1; }

if ! command -v cargo >/dev/null; then
    if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    else
        echo "cargo not found — run scripts/setup.sh, or see https://rustup.rs" >&2
        exit 1
    fi
fi

PROFILE=()
[[ ${1:-} == "--release" ]] && PROFILE=(--release)

echo "building upstream examples (first run downloads crates and takes a few minutes)"
cd "$DEST/crates/pst"
cargo build --examples "${PROFILE[@]}"

echo
echo "oracle ready. Available example binaries:"
ls examples/*.rs | xargs -n1 basename | sed 's/\.rs$//' | sed 's/^/  /'
echo
echo "Run one:  scripts/oracle.sh read_header tests/fixtures/Empty.pst"
