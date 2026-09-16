"""The nightly oracle job is runnable, and its Python half runs green here.

`.github/workflows/nightly-oracle.yml` runs no check of its own: every step
is one call into `scripts/nightly_oracle_local.sh`, so that a developer can
run the nightly on a laptop and so that the workflow and the local run cannot
drift. These tests pin that arrangement from the Python side, without a YAML
parser (none in the stdlib, and the workflow is plain enough to check as
text): the script exists, is executable, parses, refuses an unknown step,
and every step the script knows is a named step in the workflow.

The slow test runs the script with SKIP_RUST=1 — the parity lint, the
synthetic-fixture regeneration, and the Rust-free slow tests. Nothing here
builds or runs cargo; the cargo half is only proven by the scheduled run.
"""

from __future__ import annotations

import os
import re
import subprocess

import pytest

from tests.conftest import REFERENCE, REPO

SCRIPT = REPO / "scripts" / "nightly_oracle_local.sh"
WORKFLOW = REPO / ".github" / "workflows" / "nightly-oracle.yml"

# The steps, in the order the nightly runs them. Mirrors STEPS= in the script.
STEPS = ["fetch", "build", "parity", "goldens", "dump-messages", "fixture", "tests"]


def test_script_exists_and_is_executable() -> None:
    assert SCRIPT.is_file(), SCRIPT
    assert os.access(SCRIPT, os.X_OK), f"{SCRIPT.name} is not executable (chmod +x)"


def test_script_parses() -> None:
    proc = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr


def test_script_declares_the_steps_the_workflow_calls() -> None:
    match = re.search(r"^STEPS=\(([^)]*)\)", SCRIPT.read_text(), re.MULTILINE)
    assert match, "the script has no STEPS=(...) line"
    assert match.group(1).split() == STEPS


def test_unknown_step_is_refused() -> None:
    """A typo in a workflow step must fail the job, not silently pass."""
    proc = subprocess.run(
        [str(SCRIPT), "no-such-step"],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO,
        env={**os.environ, "SKIP_RUST": "1"},
    )
    assert proc.returncode == 2, (proc.returncode, proc.stderr)
    assert "unknown step" in proc.stderr


def test_workflow_calls_the_script_for_every_step() -> None:
    text = WORKFLOW.read_text()
    for step in STEPS:
        assert f"scripts/nightly_oracle_local.sh {step}\n" in text, f"workflow has no step calling `{step}`"
    # And, in that order: the checks must come after the build.
    positions = [text.index(f"scripts/nightly_oracle_local.sh {step}\n") for step in STEPS]
    assert positions == sorted(positions), "workflow steps are not in the script's order"


def test_workflow_is_scheduled_and_cache_is_keyed_on_the_pin() -> None:
    text = WORKFLOW.read_text()
    assert "schedule:" in text and "cron:" in text
    assert "workflow_dispatch:" in text
    assert "hashFiles('docs/UPSTREAM.txt')" in text, "the oracle cache must be invalidated by a pin change"
    assert "reference/outlook-pst-rs/target" in text
    # Nothing is pushed and nothing is written back.
    assert "contents: read" in text
    assert "if: failure()" in text, "the drift artifact uploads only on failure"


@pytest.mark.slow
def test_python_half_runs_green_with_rust_skipped() -> None:
    """`SKIP_RUST=1 scripts/nightly_oracle_local.sh` exits 0.

    Runs the parity lint, the fixture regeneration, and (nested) the Rust-free
    slow tests. Skips when reference/ is absent — the script refuses to report
    a green parity lint that checked nothing — and inside its own nested run,
    which the script marks with PYPST_NIGHTLY_INNER.
    """
    if os.environ.get("PYPST_NIGHTLY_INNER"):
        pytest.skip("inside the script's own pytest run")
    if not REFERENCE.is_dir():
        pytest.skip("reference/outlook-pst-rs absent — run scripts/get_rust_source.sh")
    proc = subprocess.run(
        [str(SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO,
        env={**os.environ, "SKIP_RUST": "1"},
        # The script's `tests` step is the whole Rust-free slow lane, which
        # grows with the package: at P09 it is ~16 minutes on this box, and
        # the parity/goldens/fixture steps run before it. The timeout is a
        # hang guard, not a performance budget — it is raised when a layer
        # lands, and the row that raises it says so.
        timeout=1800,
    )
    # The script's output is lint summaries, the fixture byte count, and a
    # pytest tail: nothing from a private store is ever printed by any step.
    assert proc.returncode == 0, f"exit {proc.returncode}\n{proc.stdout[-3000:]}\n{proc.stderr[-2000:]}"
    assert "all requested steps passed" in proc.stdout
