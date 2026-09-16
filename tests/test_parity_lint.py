"""scripts/check_upstream_parity.py, exercised on synthetic inputs.

The lint is the thing that makes tier T0 ("we pass the tests upstream
passes") a checked claim, so it gets the same treatment as any other code:
each way it must FAIL is shown to fail, on a tiny fake `reference/` and a
tiny fake `tests/` built in a temp dir. The last test runs the real lint over
the real repo and expects green.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "check_upstream_parity.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_upstream_parity", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lint = _load()

RUST = """\
pub fn compute(x: u32) -> u32 { x }

#[cfg(test)]
mod tests {
    use super::*;

    fn helper() {}          // not a test: no attribute

    #[test]
    fn test_alpha() {
        assert_eq!(compute(1), 1);
    }

    #[test]
    #[should_panic]
    fn test_beta() {
        panic!();
    }
}
"""

ALPHA = "crates/pst/src/thing.rs::test_alpha"
BETA = "crates/pst/src/thing.rs::test_beta"


def _fake_repo(
    tmp_path: Path,
    tests_py: str,
    pending: str = "",
    *,
    with_reference: bool = True,
) -> tuple[Path, Path, Path]:
    reference = tmp_path / "reference"
    if with_reference:
        rs = reference / "crates" / "pst" / "src" / "thing.rs"
        rs.parent.mkdir(parents=True)
        rs.write_text(RUST)
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_thing.py").write_text(tests_py)
    pending_path = tmp_path / "parity-pending.txt"
    pending_path.write_text(pending)
    return reference, tests, pending_path


BOTH_TWINNED = f'''\
from tests.parity import upstream_test
import tests.parity as parity

@upstream_test("{ALPHA}")
def test_alpha_twin(): ...

@parity.upstream_test("{BETA}")
def test_beta_twin(): ...

def test_not_a_twin(): ...
'''


# --- the collectors --------------------------------------------------------


def test_collects_upstream_tests_through_a_second_attribute(tmp_path: Path) -> None:
    reference, _, _ = _fake_repo(tmp_path, "")
    assert lint.collect_upstream_tests(reference) == [ALPHA, BETA]


def test_collects_twins_by_decorator_name_under_any_alias(tmp_path: Path) -> None:
    _, tests, _ = _fake_repo(tmp_path, BOTH_TWINNED)
    twins = lint.collect_twins(tests)
    assert twins == {
        ALPHA: ["test_thing.py::test_alpha_twin"],
        BETA: ["test_thing.py::test_beta_twin"],
    }


def test_pending_file_parses_and_rejects_malformed_lines(tmp_path: Path) -> None:
    path = tmp_path / "pending.txt"
    path.write_text(f"# header\n\n{ALPHA}  P99-ROW\nnot a ref  P99-ROW\n")
    pending, problems = lint.read_pending(path)
    assert pending == {ALPHA: "P99-ROW"}
    assert len(problems) == 1 and "pending.txt:4" in problems[0]


# --- the verdicts ----------------------------------------------------------


def test_clean_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert lint.run(*_fake_repo(tmp_path, BOTH_TWINNED)) == 0
    assert "parity: 2 upstream tests — 2 twinned, 0 pending, 0 missing" in capsys.readouterr().out


def test_pending_twin_passes_and_is_counted_by_row(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    only_alpha = BOTH_TWINNED.replace(f'@parity.upstream_test("{BETA}")\n', "")
    assert lint.run(*_fake_repo(tmp_path, only_alpha, f"{BETA}  P99-ROW\n")) == 0
    assert "1 twinned, 1 pending (P99-ROW ×1), 0 missing" in capsys.readouterr().out


def test_missing_twin_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    only_alpha = BOTH_TWINNED.replace(f'@parity.upstream_test("{BETA}")\n', "")
    assert lint.run(*_fake_repo(tmp_path, only_alpha)) == 1
    out = capsys.readouterr().out
    assert f"{BETA} has no twin" in out and "1 missing" in out


def test_duplicate_twin_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    doubled = BOTH_TWINNED + f'\n@upstream_test("{ALPHA}")\ndef test_alpha_again(): ...\n'
    assert lint.run(*_fake_repo(tmp_path, doubled)) == 1
    assert f"{ALPHA} has 2 twins" in capsys.readouterr().out


def test_unknown_ref_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    typo = BOTH_TWINNED.replace(BETA, BETA + "_typo")
    assert lint.run(*_fake_repo(tmp_path, typo)) == 1
    out = capsys.readouterr().out
    assert f"claims upstream {BETA}_typo, which does not exist" in out
    assert f"{BETA} has no twin" in out


def test_stale_pending_entry_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert lint.run(*_fake_repo(tmp_path, BOTH_TWINNED, f"{BETA}  P99-ROW\n")) == 1
    out = capsys.readouterr().out
    assert "stale pending entry" in out and "P99-ROW landed" in out


def test_pending_entry_for_a_vanished_upstream_test_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    gone = "crates/pst/src/thing.rs::test_gone"
    assert lint.run(*_fake_repo(tmp_path, BOTH_TWINNED, f"{gone}  P99-ROW\n")) == 1
    assert f"pending entry {gone} (P99-ROW) names no upstream test" in capsys.readouterr().out


def test_absent_reference_skips_with_exit_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Untwinned upstream tests would fail if the lint ran — the point is that
    # it must not run, and must say where it does.
    assert lint.run(*_fake_repo(tmp_path, "", with_reference=False)) == 0
    out = capsys.readouterr().out
    assert "skipped" in out and "P14-CI-ORACLE" in out


# --- the real thing --------------------------------------------------------


def test_real_lint_is_green_over_this_repo() -> None:
    if not (REPO / "reference" / "outlook-pst-rs" / "crates").is_dir():
        pytest.skip("reference/outlook-pst-rs absent — run scripts/get_rust_source.sh")
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=REPO, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.startswith("parity: "), result.stdout
