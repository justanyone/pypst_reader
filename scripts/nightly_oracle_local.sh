#!/usr/bin/env bash
# nightly_oracle_local.sh — the nightly oracle job, runnable on a laptop.
#
# .github/workflows/nightly-oracle.yml installs toolchains and restores caches;
# every CHECK it runs is one call into this script, so the workflow and the
# local run cannot drift: what the nightly proves is exactly what this proves.
#
# The steps, in the order the nightly runs them:
#
#   fetch          scripts/get_rust_source.sh — upstream at docs/UPSTREAM.txt's pin
#   build          scripts/build_oracle.sh    — the example binaries (cargo)
#   parity         scripts/check_upstream_parity.py, and it must NOT skip: on
#                  every-push CI there is no reference/ and the lint exits 0
#                  without looking; here reference/ exists and a skip is a bug
#   goldens        scripts/capture_oracle.py --check — the committed goldens
#                  are what the oracle emits today (the drift detector)
#   dump-messages  the same for row P19's `dump_messages` example, guarded on
#                  oracle/Cargo.toml so this works before and after P19 lands
#   fixture        scripts/get_fixture_tools.sh + make_fixture.py --check basics
#                  — the synthetic store regenerates byte-for-byte
#   tests          uv run pytest -m "oracle or slow" — the live-oracle tests
#
# Usage: scripts/nightly_oracle_local.sh [STEP ...]     (no argument: all, in order)
#
# Environment:
#   SKIP_RUST=1    skip fetch, build, goldens and dump-messages (everything that
#                  runs cargo) and run the tests as `slow and not oracle`. For a
#                  machine that must not build Rust; the Python half still runs.
#   NIGHTLY_OUT=D  on golden drift, regenerate tests/golden/ and write the
#                  `git diff` under D for the workflow to upload. Unset locally,
#                  so a local run never modifies the working tree. Goldens are
#                  the oracle's output over the PUBLIC corpus; nothing private
#                  can be in that diff (and nothing private exists on a runner).
#
# Exit status: 0 only when every requested step passed (set -e; each step is a
# command that fails loudly). 2 for a usage error.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

STEPS=(fetch build parity goldens dump-messages fixture tests)
REFERENCE="reference/outlook-pst-rs"

say()  { printf '\n==> %s\n' "$*"; }
skip() { printf '    (skipped: %s)\n' "$*"; }
die()  { echo "nightly_oracle_local.sh: $*" >&2; exit 2; }

# The parity lint and the tests need reference/ to mean anything; refuse to
# report a green run that silently checked nothing.
need_reference() {
    [[ -d $REFERENCE/crates ]] || die "$REFERENCE is absent — run scripts/get_rust_source.sh (or this script's 'fetch' step)"
}

# capture_oracle.py --check prints only fixture/example NAMES on drift. When
# NIGHTLY_OUT is set, turn that into the actual diff for the upload: regenerate
# the goldens in place and let git show what moved.
golden_check() {
    local label="$1"; shift
    local log=/dev/null
    if [[ -n ${NIGHTLY_OUT:-} ]]; then
        mkdir -p "$NIGHTLY_OUT"
        log="$NIGHTLY_OUT/$label-check.txt"
    fi
    if python3 scripts/capture_oracle.py --check "$@" | tee "$log"; then
        return 0
    fi
    if [[ -n ${NIGHTLY_OUT:-} ]]; then
        echo "    regenerating goldens to produce $NIGHTLY_OUT/$label-drift.diff"
        python3 scripts/capture_oracle.py "$@" >/dev/null
        git status --porcelain -- tests/golden > "$NIGHTLY_OUT/$label-drift.status"
        git diff --no-color -- tests/golden > "$NIGHTLY_OUT/$label-drift.diff"
    fi
    return 1
}

step_fetch() {
    say "fetch: upstream Rust at the pin in docs/UPSTREAM.txt"
    if [[ ${SKIP_RUST:-} == 1 ]]; then skip "SKIP_RUST=1"; return; fi
    scripts/get_rust_source.sh
}

step_build() {
    say "build: the upstream example binaries"
    if [[ ${SKIP_RUST:-} == 1 ]]; then skip "SKIP_RUST=1"; return; fi
    scripts/build_oracle.sh
}

step_parity() {
    say "parity: every upstream #[test] has exactly one Python twin (must not skip here)"
    need_reference
    local out
    out="$(mktemp)"
    uv run python scripts/check_upstream_parity.py | tee "$out"
    if grep -q "skipped" "$out"; then
        rm -f "$out"
        die "the parity lint skipped although $REFERENCE exists — it checked nothing"
    fi
    rm -f "$out"
}

step_goldens() {
    say "goldens: tests/golden/ is what the oracle emits today"
    if [[ ${SKIP_RUST:-} == 1 ]]; then skip "SKIP_RUST=1"; return; fi
    need_reference
    golden_check goldens
}

step_dump_messages() {
    say "dump-messages: row P19's example over the corpus (guarded on oracle/Cargo.toml)"
    if [[ ${SKIP_RUST:-} == 1 ]]; then skip "SKIP_RUST=1"; return; fi
    if [[ ! -f oracle/Cargo.toml ]]; then
        skip "oracle/Cargo.toml absent — row P19 has not landed on this branch"
        return
    fi
    need_reference
    golden_check dump-messages --example dump_messages
}

step_fixture() {
    say "fixture: synth-basics.pst regenerates byte-for-byte from its sources"
    scripts/get_fixture_tools.sh
    uv run python scripts/make_fixture.py --check basics
}

step_tests() {
    say "tests: the live-oracle and slow tests"
    need_reference
    # A CI runner holds only Empty.pst and the manifest-pinned corpus (the
    # no-mail-stores job proves it), so `private` tests skip there. If a
    # private store were ever present under CI, the log would be a
    # publication channel: refuse to run rather than find out.
    if [[ -n ${CI:-} ]] && compgen -G "tests/fixtures/private/*.pst" >/dev/null; then
        die "a private store is present on a CI runner; refusing to run"
    fi
    # tests/test_nightly_script.py runs THIS script; this variable is how its
    # self-run test knows not to recurse.
    export PYPST_NIGHTLY_INNER=1
    if [[ ${SKIP_RUST:-} == 1 ]]; then
        # pytest exits 5 when the marker selects nothing. Under SKIP_RUST that
        # is "no Rust-free slow tests on this branch", not a failure; in the
        # real nightly an empty selection would mean the oracle suite vanished
        # and is left to fail.
        uv run pytest -q -m "slow and not oracle" || { rc=$?; [[ $rc -eq 5 ]] && skip "no tests selected" || exit "$rc"; }
    else
        uv run pytest -q -m "oracle or slow"
    fi
}

run_step() {
    case "$1" in
        fetch)         step_fetch ;;
        build)         step_build ;;
        parity)        step_parity ;;
        goldens)       step_goldens ;;
        dump-messages) step_dump_messages ;;
        fixture)       step_fixture ;;
        tests)         step_tests ;;
        *) die "unknown step '$1' (steps: ${STEPS[*]})" ;;
    esac
}

if [[ $# -eq 0 ]]; then
    set -- "${STEPS[@]}"
fi
for step in "$@"; do
    run_step "$step"
done
say "nightly oracle: all requested steps passed ($*)"
