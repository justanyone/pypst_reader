#!/usr/bin/env bash
# setup.sh — make a fresh checkout ready to work in.
#
# Idempotent: safe to re-run. Does five things, in this order, and tells you
# what it did rather than assuming you watched.
#
#   1. Python environment (.venv) via uv, with dev dependencies
#   2. The git pre-commit hook that refuses to commit mail stores
#   3. The Rust toolchain check (the ORACLE needs it; the library does not)
#   4. The upstream Rust source, pinned, into reference/
#   5. A verification run of the test suite
#
# Usage: scripts/setup.sh [--no-rust]
#
#   --no-rust   skip steps 3 and 4. The pure-Python package and its unit
#               tests work fine without them; only differential tests skip.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

say() { printf '\n=== %s\n' "$*"; }
warn() { printf 'setup.sh: %s\n' "$*" >&2; }

WANT_RUST=1
[[ ${1:-} == "--no-rust" ]] && WANT_RUST=0

# ---------------------------------------------------------------- 1. Python
say "Python environment"
if ! command -v uv >/dev/null; then
    if [[ -x "$HOME/.local/bin/uv" ]]; then
        export PATH="$HOME/.local/bin:$PATH"
    else
        warn "uv not found. Install it: curl -LsSf https://astral.sh/uv/install.sh | sh"
        warn "(or use a plain venv: python3 -m venv .venv && .venv/bin/pip install -e '.[dev]')"
        exit 1
    fi
fi
uv sync
echo "  .venv ready — $(.venv/bin/python -V)"
echo "  activate with:  source .venv/bin/activate"

# ------------------------------------------------------------------ 2. Hook
say "git pre-commit hook (refuses to commit mail stores)"
if [[ -d .git ]]; then
    HOOK_DIR="$(git rev-parse --git-path hooks)"
    mkdir -p "$HOOK_DIR"
    # A symlink, not a copy: the hook then tracks the version-controlled file
    # instead of going stale the first time it is improved.
    ln -sf "$REPO_ROOT/scripts/git-hooks/pre-commit" "$HOOK_DIR/pre-commit"
    echo "  installed: $HOOK_DIR/pre-commit -> scripts/git-hooks/pre-commit"
else
    warn "not a git repository yet — run 'git init' then re-run this script"
fi

# ------------------------------------------------------------------ 3. Rust
if (( WANT_RUST )); then
    say "Rust toolchain (needed only for the differential oracle)"
    if ! command -v cargo >/dev/null; then
        if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
            export PATH="$HOME/.cargo/bin:$PATH"
            echo "  found ~/.cargo/bin/cargo — add it to PATH in your shell profile:"
            echo '    export PATH="$HOME/.cargo/bin:$PATH"'
        else
            warn "cargo not found. Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal"
            warn "continuing without the oracle; differential tests will skip"
            WANT_RUST=0
        fi
    fi
    [[ $WANT_RUST == 1 ]] && echo "  $(cargo --version)"
fi

# -------------------------------------------------------------- 4. Upstream
if (( WANT_RUST )); then
    say "upstream Rust source (the oracle)"
    scripts/get_rust_source.sh
    echo
    echo "  NOT built yet — that takes a couple of minutes and ~270 MB."
    echo "  Build it when you need it:  scripts/build_oracle.sh"
fi

# ------------------------------------------------------------------ 5. Test
say "verification"
uv run pytest -q
echo
say "ready"
echo "Read, in this order:"
echo "  CLAUDE.md             — how to work in this repo (agents and humans both)"
echo "  docs/PORTING-PLAN.md  — the layer order and what each one costs"
echo "  MasterToDo.md         — what is actually next"
