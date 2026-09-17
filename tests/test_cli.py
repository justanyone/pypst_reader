"""The `pypstreader` command — every option, and the promise that only a status comes out.

This is the entry point a person types, so it is tested the way a person
reaches it: through `subprocess`, as `python -m pypstreader.pypstreader` and
(when the package is installed, which `uv run pytest` makes true) as the
`pypstreader` console script, with the exit status and the streams compared
rather than a return value. The in-process `main()` is used only where the
process boundary would cost more than it proves: the corruption sweep, which
runs hundreds of mutated stores through the command and asks for nothing but
`0` or `1`.

Three things are pinned here that no other test file can pin:

- **the counts are the library's counts.** What the command writes into an
  mbox is the number of messages `readable_messages` yields over the same
  walk, which is `tests/test_eml.py`'s `OPENABLE` table, which is in turn
  what the Rust oracle's `dump_messages` golden holds. The command is not
  allowed to invent or lose a message, and the summary line on stderr has to
  agree with the file on disk and with `Folder.message_ids()`.
- **skipping is counted, and `--strict` refuses.** `javalibpst-dist-list.pst`
  has a message node with no sub-node tree; by default it is skipped, counted
  and the run still exits 0, and with `--strict` the run exits 1 having said
  why.
- **nothing but an exit status escapes.** Every mutation of a corpus store
  through `main()` returns 0 or 1. A traceback here is a bug in the package,
  not a message to somebody holding a PST.

The version is pinned in three places that have to agree — the package, the
distribution and the alias's dependency pin — so a release cannot ship a
`pstreader` that installs a `pypstreader` it was never built against.

Private stores: exit status and counts, never a subject, a name or a path
out of the store (CLAUDE.md § "Never print, log, or assert on private-store
content"). The mbox they produce is written into `tmp_path` and only its
record count is looked at.
"""

from __future__ import annotations

import contextlib
import io
import mailbox
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import pypstreader
from pypstreader import pypstreader as cli
from tests import corrupt
from tests.conftest import PUBLIC, REPO
from tests.test_eml import (
    ANSI_STORES,
    DIST_LIST,
    OPENABLE,
    SYNTH,
    UNICODE_IDS,
    UNICODE_STORES,
    _path,
)

VERSION = "1.0.0"
ALIAS = REPO / "alias" / "pstreader"
TIMEOUT = 300

# The store `--strict` is tested on: its fourth message is a message node
# with no sub-node tree, which the default run skips and counts.
DIST_LIST_WRITTEN = OPENABLE[DIST_LIST]
DIST_LIST_SKIPPED = 1

# The corruption sweep's bases. The cheap one is swept whole in the fast
# lane; the one with mail in it costs ~30 ms a mutation (every message
# assembled, every attachment base64'd), so the fast lane takes a regular
# sample of it and the slow lane takes all of it.
SWEEP_BASE = PUBLIC / "pstd-inline-cid.pst"
SWEEP_MAIL_BASE = PUBLIC / "tika-variousBodyTypes.pst"
SWEEP_MAIL_STRIDE = 8
SWEEP_SEED = 0


# --- running it --------------------------------------------------------------------


def run(*args: str, cwd: Path, script: Path | None = None) -> subprocess.CompletedProcess[str]:
    """The command, as a process. `script` runs the installed console script instead of `-m`."""
    argv = [str(script)] if script is not None else [sys.executable, "-m", "pypstreader.pypstreader"]
    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(
        [*argv, *args], capture_output=True, text=True, check=False, cwd=cwd, env=env, timeout=TIMEOUT
    )


def in_process(*args: str) -> tuple[int, str, str]:
    """`main(argv)` with both streams captured: the status, stdout, stderr. Never raises."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = cli.main(list(args))
    return status, out.getvalue(), err.getvalue()


def records(path: Path) -> list[object]:
    """Every record of an mbox, through the stdlib reader every consumer uses."""
    box = mailbox.mbox(path, create=False)
    try:
        return list(box)
    finally:
        box.close()


def listed(stdout: str) -> list[tuple[str, str]]:
    """`--list`'s lines as (count, path). The count is right-aligned, so split on whitespace once."""
    return [(line.split(maxsplit=1)[0], line.split(maxsplit=1)[1]) for line in stdout.splitlines() if line.strip()]


def summary(stderr: str) -> dict[str, int]:
    """The three numbers out of the one-line summary: folders, written, skipped."""
    line = next(ln for ln in stderr.splitlines() if ln.startswith("pypstreader: ") and " -> " in ln)
    body = line.removeprefix("pypstreader: ").split(" -> ")[0]
    parts = [p.strip().split(" ", 1) for p in body.split(",")]
    return {parts[0][1].rstrip("s"): int(parts[0][0]), "written": int(parts[1][0]), "skipped": int(parts[2][0])}


@pytest.fixture(scope="session")
def console_script() -> Path:
    """The installed `pypstreader` entry point, beside the interpreter running the tests."""
    for name in ("pypstreader", "pypstreader.exe"):
        candidate = Path(sys.executable).parent / name
        if candidate.exists():
            return candidate
    pytest.skip("pypstreader is not installed in this environment (`uv run pytest` installs it)")
    raise AssertionError  # pragma: no cover - pytest.skip does not return


# --- the version, in the three places that must agree ---------------------------------


def test_the_package_version_is_the_release() -> None:
    assert pypstreader.__version__ == VERSION


def test_pyproject_agrees_with_the_package() -> None:
    """A wheel whose metadata disagrees with `__version__` is a wheel nobody can pin."""
    meta = tomllib.loads((REPO / "pyproject.toml").read_bytes().decode())["project"]
    assert meta["version"] == pypstreader.__version__
    assert meta["name"] == "pypstreader"
    assert meta["scripts"] == {"pypstreader": "pypstreader.pypstreader:main"}
    assert meta["requires-python"] == ">=3.12"


def test_the_alias_pins_this_exact_version() -> None:
    """`pstreader` may never install a `pypstreader` it was not built against."""
    meta = tomllib.loads((ALIAS / "pyproject.toml").read_bytes().decode())["project"]
    assert meta["name"] == "pstreader"
    assert meta["version"] == VERSION
    assert meta["dependencies"] == [f"pypstreader=={VERSION}"]
    assert meta["scripts"] == {"pstreader": "pypstreader.pypstreader:main"}


def test_both_distributions_declare_production_status() -> None:
    """1.0.0 says production in the metadata, or it does not say it at all.

    `Development Status` is the one classifier a packaging index shows as a
    promise about stability. It is asserted here because the README and the
    changelog make the same claim in prose, and prose is not checkable.
    """
    for path in (REPO / "pyproject.toml", ALIAS / "pyproject.toml"):
        classifiers = tomllib.loads(path.read_bytes().decode())["project"]["classifiers"]
        status = [c for c in classifiers if c.startswith("Development Status ::")]
        assert status == ["Development Status :: 5 - Production/Stable"], path


def test_the_alias_re_exports_the_package(monkeypatch: pytest.MonkeyPatch) -> None:
    """`import pstreader` gives the same objects, not copies of them."""
    monkeypatch.syspath_prepend(str(ALIAS / "src"))
    monkeypatch.delitem(sys.modules, "pstreader", raising=False)
    import pstreader  # the path is only right inside this test

    assert pstreader.__version__ == pypstreader.__version__
    assert pstreader.open is pypstreader.open
    assert pstreader.PstError is pypstreader.PstError
    assert sorted(pstreader.__all__) == sorted(pypstreader.__all__)


def test_version_flag_prints_the_release(tmp_path: Path) -> None:
    done = run("--version", cwd=tmp_path)
    assert done.returncode == 0
    assert done.stdout.strip() == f"pypstreader {VERSION}"


def test_the_installed_console_script_is_the_same_command(console_script: Path, tmp_path: Path) -> None:
    done = run("--version", cwd=tmp_path, script=console_script)
    assert (done.returncode, done.stdout.strip()) == (0, f"pypstreader {VERSION}")


# --- the default: one mbox, the right number of messages ------------------------------


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_default_writes_one_mbox_beside_the_caller(store: Path, tmp_path: Path) -> None:
    """`pypstreader IN.pst` writes `IN.mbox` in the current directory, and exits 0."""
    done = run(str(store), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    written = tmp_path / f"{store.stem}.mbox"
    assert written.exists()
    assert len(records(written)) == OPENABLE[store.stem]
    assert done.stdout == ""  # the mail goes in the file; stdout is for --list


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_the_summary_is_the_file_and_the_store(store: Path, tmp_path: Path) -> None:
    """written + skipped is what `Folder.message_ids()` named, and written is what landed."""
    done = run(str(store), "-o", str(tmp_path / "out.mbox"), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    counts = summary(done.stderr)
    assert counts["written"] == len(records(tmp_path / "out.mbox")) == OPENABLE[store.stem]
    named = run("--list", str(store), cwd=tmp_path)
    assert named.returncode == 0
    # Every message the store NAMES was either written or counted as skipped;
    # a `?` is a folder whose contents table refused, counted apart.
    assert counts["written"] + counts["skipped"] == sum(int(c) for c, _ in listed(named.stdout) if c.isdigit())


def test_empty_store_writes_an_empty_mbox(tmp_path: Path) -> None:
    """Zero messages is a successful run with an empty file, not a refusal and not no file."""
    done = run(str(REPO / "tests" / "fixtures" / "Empty.pst"), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    written = tmp_path / "Empty.mbox"
    assert written.exists() and written.read_bytes() == b""
    assert records(written) == []


def test_output_names_the_file(tmp_path: Path) -> None:
    target = tmp_path / "deep" / "mail.mbox"
    done = run(str(_path("tika-variousBodyTypes")), "-o", str(target), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    assert len(records(target)) == 4
    assert not (tmp_path / "tika-variousBodyTypes.mbox").exists()


def test_a_second_run_replaces_rather_than_appends(tmp_path: Path) -> None:
    """An export that doubled its output on a second run would be a trap."""
    store = str(_path("tika-variousBodyTypes"))
    first = run(store, cwd=tmp_path)
    second = run(store, cwd=tmp_path)
    assert (first.returncode, second.returncode) == (0, 0)
    assert len(records(tmp_path / "tika-variousBodyTypes.mbox")) == 4


def test_every_record_names_its_folder(tmp_path: Path) -> None:
    """The tree survives the flattening: `X-Pypstreader-Folder` on every record."""
    done = run(str(_path("javalibpst-dist-list")), "-o", str(tmp_path / "o.mbox"), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    folders = [record[cli.FOLDER_HEADER] for record in records(tmp_path / "o.mbox")]
    assert len(folders) == DIST_LIST_WRITTEN
    assert all(value for value in folders)
    assert "Contacts" in " ".join(folders)
    tree = run("--list", str(_path("javalibpst-dist-list")), cwd=tmp_path).stdout
    assert set(folders) <= {path for _, path in listed(tree)}, "a record names a folder --list does not print"


# --- --list ---------------------------------------------------------------------------


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_list_prints_the_tree_and_writes_nothing(store: Path, tmp_path: Path) -> None:
    done = run("--list", str(store), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    assert list(tmp_path.iterdir()) == []
    rows = listed(done.stdout)
    assert rows, "every store has at least a root folder"
    assert all(count == "?" or count.isdigit() for count, _ in rows)
    assert sum(int(c) for c, _ in rows if c.isdigit()) >= OPENABLE[store.stem]


def test_list_paths_are_what_folder_takes(tmp_path: Path) -> None:
    store = str(_path("tika-variousBodyTypes"))
    rows = [(int(c), path) for c, path in listed(run("--list", store, cwd=tmp_path).stdout) if c.isdigit()]
    _, path = max(rows)
    done = run("--folder", path, store, "-o", str(tmp_path / "one.mbox"), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    assert len(records(tmp_path / "one.mbox")) == 4


# --- --per-folder and --format eml -----------------------------------------------------


def test_per_folder_writes_one_mbox_each_and_an_index(tmp_path: Path) -> None:
    out = tmp_path / "out"
    done = run("--per-folder", str(_path("tika-variousBodyTypes")), "-o", str(out), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    index = out / "folders.txt"
    assert index.exists()
    rows = [line.split("\t") for line in index.read_text(encoding="utf-8").splitlines() if not line.startswith("#")]
    assert len(rows) == summary(done.stderr)["folder"]
    assert sum(int(row[2]) for row in rows if row[2].isdigit()) == 4
    boxes = sorted(p for p in out.glob("*.mbox"))
    assert len(boxes) == len(rows)
    assert sum(len(records(p)) for p in boxes) == 4
    for row in rows:
        assert (out / row[0]).exists(), f"folders.txt names {row[0]}, which is not there"


def test_format_eml_writes_one_file_per_message(tmp_path: Path) -> None:
    out = tmp_path / "eml"
    done = run("--format", "eml", str(_path("tika-variousBodyTypes")), "-o", str(out), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    written = sorted(out.glob("*.eml"))
    assert len(written) == 4
    assert all(len(p.stem) == 8 and int(p.stem, 16) for p in written), "named by node id, never by the message"
    assert all(p.read_bytes().startswith(b"X-") or b"\r\n" in p.read_bytes()[:200] for p in written)


def test_per_folder_and_eml_together_is_a_usage_error(tmp_path: Path) -> None:
    done = run("--per-folder", "--format", "eml", str(_path("synth-basics")), "-o", str(tmp_path / "x"), cwd=tmp_path)
    assert done.returncode == 2
    assert "--per-folder" in done.stderr


# --- --folder ---------------------------------------------------------------------------


def test_folder_restricts_the_run_to_a_subtree(tmp_path: Path) -> None:
    store = str(_path("tika-variousBodyTypes"))
    inbox = next(path for _, path in listed(run("--list", store, cwd=tmp_path).stdout) if path.endswith("/Inbox"))
    done = run("--folder", inbox, store, "-o", str(tmp_path / "inbox.mbox"), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    counts = summary(done.stderr)
    assert counts["folder"] == 2, "the Inbox and the `tmp` folder under it"
    assert counts["written"] == len(records(tmp_path / "inbox.mbox")) == 4


def test_folder_is_repeatable(tmp_path: Path) -> None:
    store = str(_path("javalibpst-dist-list"))
    tree = listed(run("--list", store, cwd=tmp_path).stdout)
    named = [path for _, path in tree if path.endswith(("/Contacts", "/Calendar"))]
    assert len(named) == 2
    done = run("--folder", named[0], "--folder", named[1], store, "-o", str(tmp_path / "two.mbox"), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    counts = summary(done.stderr)
    # Three messages are named between the two folders; one of them is the
    # message node with no sub-node tree, skipped and counted as always.
    assert counts["folder"] == 2
    assert (counts["written"], counts["skipped"]) == (2, 1)
    assert len(records(tmp_path / "two.mbox")) == 2


def test_folder_that_names_nothing_is_a_refusal(tmp_path: Path) -> None:
    done = run("--folder", "no/such/folder", str(_path("synth-basics")), "-o", str(tmp_path / "x.mbox"), cwd=tmp_path)
    assert done.returncode == 1
    assert "no folder matches" in done.stderr
    assert "Traceback" not in done.stderr
    assert not (tmp_path / "x.mbox").exists()


# --- skipping, and --strict -------------------------------------------------------------


def test_an_unreadable_message_is_skipped_and_counted(tmp_path: Path) -> None:
    """`javalibpst-dist-list.pst`: one message node has no sub-node tree."""
    done = run(str(_path(DIST_LIST)), "-o", str(tmp_path / "o.mbox"), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    counts = summary(done.stderr)
    assert (counts["written"], counts["skipped"]) == (DIST_LIST_WRITTEN, DIST_LIST_SKIPPED)
    assert len(records(tmp_path / "o.mbox")) == DIST_LIST_WRITTEN


def test_strict_refuses_the_whole_run_on_that_message(tmp_path: Path) -> None:
    done = run("--strict", str(_path(DIST_LIST)), "-o", str(tmp_path / "o.mbox"), cwd=tmp_path)
    assert done.returncode == 1
    assert "sub-node" in done.stderr
    assert "Traceback" not in done.stderr


def test_strict_refuses_a_folder_whose_contents_table_will_not_parse(tmp_path: Path) -> None:
    """`synth-basics.pst`'s Inbox: default skips the folder and counts it, `--strict` stops."""
    relaxed = run(str(_path(SYNTH)), "-o", str(tmp_path / "a.mbox"), cwd=tmp_path)
    assert relaxed.returncode == 0, relaxed.stderr
    assert "unreadable" in relaxed.stderr
    assert len(records(tmp_path / "a.mbox")) == OPENABLE[SYNTH]
    strict = run("--strict", str(_path(SYNTH)), "-o", str(tmp_path / "b.mbox"), cwd=tmp_path)
    assert strict.returncode == 1
    assert "Traceback" not in strict.stderr


# --- the limits --------------------------------------------------------------------------


def test_max_depth_stops_the_folder_walk(tmp_path: Path) -> None:
    done = run("--max-depth", "1", str(_path("tika-variousBodyTypes")), "-o", str(tmp_path / "o.mbox"), cwd=tmp_path)
    assert done.returncode == 1
    assert "folder tree depth" in done.stderr
    assert "Traceback" not in done.stderr


def test_max_attachment_bytes_bites(tmp_path: Path) -> None:
    """A one-byte allocation ceiling cannot assemble anything; the run refuses or writes nothing."""
    done = run(
        "--max-attachment-bytes", "1", str(_path("tika-variousBodyTypes")), "-o", str(tmp_path / "o.mbox"), cwd=tmp_path
    )
    assert done.returncode in (0, 1)
    if done.returncode == 0:
        assert summary(done.stderr)["written"] == 0
    assert "Traceback" not in done.stderr


def test_max_embedded_depth_is_accepted_and_carried(tmp_path: Path) -> None:
    done = run(
        "--max-embedded-depth", "1", str(_path("pstsdk-submessage")), "-o", str(tmp_path / "o.mbox"), cwd=tmp_path
    )
    assert done.returncode in (0, 1)
    assert "Traceback" not in done.stderr


@pytest.mark.parametrize("flag", ["--max-depth", "--max-attachment-bytes", "--max-embedded-depth"])
@pytest.mark.parametrize("value", ["0", "-1"])
def test_a_non_positive_ceiling_is_a_usage_error(flag: str, value: str, tmp_path: Path) -> None:
    done = run(flag, value, str(_path("synth-basics")), "-o", str(tmp_path / "o.mbox"), cwd=tmp_path)
    assert done.returncode == 2
    assert "must be positive" in done.stderr


@pytest.mark.parametrize("flag", ["--max-depth", "--max-attachment-bytes", "--max-embedded-depth"])
def test_a_non_numeric_ceiling_is_a_usage_error(flag: str, tmp_path: Path) -> None:
    done = run(flag, "lots", str(_path("synth-basics")), "-o", str(tmp_path / "o.mbox"), cwd=tmp_path)
    assert done.returncode == 2


# --- --codepage, -q, -v --------------------------------------------------------------------


def test_an_unknown_codepage_is_a_usage_error(tmp_path: Path) -> None:
    done = run("--codepage", "not-a-codec", str(_path("synth-basics")), "-o", str(tmp_path / "o.mbox"), cwd=tmp_path)
    assert done.returncode == 2
    assert "code page" in done.stderr


def test_a_known_codepage_is_carried_into_the_store(tmp_path: Path) -> None:
    done = run("--codepage", "utf-8", str(_path("tika-variousBodyTypes")), "-o", str(tmp_path / "o.mbox"), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    assert len(records(tmp_path / "o.mbox")) == 4


def test_quiet_says_nothing(tmp_path: Path) -> None:
    done = run("-q", str(_path("tika-variousBodyTypes")), "-o", str(tmp_path / "o.mbox"), cwd=tmp_path)
    assert (done.returncode, done.stdout, done.stderr) == (0, "", "")


def test_verbose_reports_folders_and_counts_and_no_mail(tmp_path: Path) -> None:
    done = run("-v", str(_path("tika-variousBodyTypes")), "-o", str(tmp_path / "o.mbox"), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    lines = done.stderr.splitlines()
    folder_lines = [ln for ln in lines if ln.startswith("  ")]
    assert len(folder_lines) == summary(done.stderr)["folder"]
    assert all(ln.rsplit(": ", 1)[1].isdigit() for ln in folder_lines)
    # Nothing else is on stderr: a folder line per folder, and the summary.
    # `--verbose` reports counts and folder names and stops there, so no
    # subject, sender or body can be in this stream whatever the store says.
    assert len(lines) == len(folder_lines) + 1


def test_quiet_and_verbose_together_is_a_usage_error(tmp_path: Path) -> None:
    done = run("-q", "-v", str(_path("synth-basics")), "-o", str(tmp_path / "o.mbox"), cwd=tmp_path)
    assert done.returncode == 2


# --- the refusals -------------------------------------------------------------------------


@pytest.mark.parametrize("stem", sorted(ANSI_STORES))
def test_an_ansi_store_is_refused_by_name(stem: str, tmp_path: Path) -> None:
    """ADR-0003: `wVer` 14/15 is refused, never guessed at, and the message says where to look."""
    done = run(str(_path(stem)), "-o", str(tmp_path / "o.mbox"), cwd=tmp_path)
    assert done.returncode == 1
    assert "ANSI" in done.stderr and "pypstreader_nu" in done.stderr
    assert "Traceback" not in done.stderr
    assert not (tmp_path / "o.mbox").exists()


def test_a_missing_file_is_one_line_and_exit_one(tmp_path: Path) -> None:
    done = run(str(tmp_path / "absent.pst"), cwd=tmp_path)
    assert done.returncode == 1
    assert len(done.stderr.strip().splitlines()) == 1
    assert "Traceback" not in done.stderr


def test_a_directory_is_not_a_store(tmp_path: Path) -> None:
    done = run(str(tmp_path), cwd=tmp_path)
    assert done.returncode == 1
    assert "Traceback" not in done.stderr


def test_an_empty_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / "empty.pst").write_bytes(b"")
    done = run(str(tmp_path / "empty.pst"), cwd=tmp_path)
    assert done.returncode == 1
    assert "Traceback" not in done.stderr


def test_no_arguments_is_a_usage_error(tmp_path: Path) -> None:
    done = run(cwd=tmp_path)
    assert done.returncode == 2
    assert "usage:" in done.stderr


def test_an_unknown_option_is_a_usage_error(tmp_path: Path) -> None:
    done = run("--decrypt-everything", str(_path("synth-basics")), cwd=tmp_path)
    assert done.returncode == 2


def test_help_exits_zero(tmp_path: Path) -> None:
    done = run("--help", cwd=tmp_path)
    assert done.returncode == 0
    assert "--per-folder" in done.stdout and "--strict" in done.stdout


# --- the contract: nothing but a status --------------------------------------------------


def sweep(base: Path, out: Path, *, stride: int = 1) -> tuple[int, list[str]]:
    """Every (stride-th) mutation of `base` through `main()`; the count and what misbehaved."""
    data = base.read_bytes()
    store = out / "store.pst"
    bad: list[str] = []
    swept = 0
    for index, mutation in enumerate(corrupt.mutations(data, seed=SWEEP_SEED)):
        if index % stride:
            continue
        swept += 1
        store.write_bytes(mutation.data)
        try:
            status, _, _ = in_process(str(store), "--quiet", "-o", str(out / "o.mbox"))
        except BaseException as exc:  # noqa: BLE001 — classifying, not handling, is the point
            bad.append(f"LEAK  {mutation.name} :: {type(exc).__name__}: {exc!s:.100}")
            continue
        if status not in (0, 1):
            bad.append(f"STATUS {mutation.name} :: main returned {status}")
    return swept, bad


def test_no_mutation_makes_the_command_raise(tmp_path: Path) -> None:
    """Every mutation of a corpus store, exported through `main()`: 0 or 1, never a traceback."""
    swept, bad = sweep(SWEEP_BASE, tmp_path)
    assert swept > 100, "the mutation generator produced almost nothing; the sweep proves little"
    assert not bad, f"{len(bad)} of {swept} mutations:\n  " + "\n  ".join(bad[:20])


def test_no_mutation_of_a_store_with_mail_makes_the_command_raise(tmp_path: Path) -> None:
    """The same, over a store whose messages and attachments are actually assembled."""
    swept, bad = sweep(SWEEP_MAIL_BASE, tmp_path, stride=SWEEP_MAIL_STRIDE)
    assert swept > 20
    assert not bad, f"{len(bad)} of {swept} mutations:\n  " + "\n  ".join(bad[:20])


@pytest.mark.slow
def test_no_mutation_of_a_store_with_mail_makes_the_command_raise_whole(tmp_path: Path) -> None:
    swept, bad = sweep(SWEEP_MAIL_BASE, tmp_path)
    assert swept > 500
    assert not bad, f"{len(bad)} of {swept} mutations:\n  " + "\n  ".join(bad[:20])


def test_main_returns_rather_than_exits(tmp_path: Path) -> None:
    """`--version` and a usage error are `SystemExit` inside argparse; `main` turns both into a status."""
    assert in_process("--version")[0] == 0
    assert in_process("--nope", str(_path("synth-basics")))[0] == 2
    assert in_process(str(tmp_path / "absent.pst"))[0] == 1


# --- private stores: the status and the counts, and nothing else ----------------------------


@pytest.mark.private
def test_private_stores_export_and_are_never_quoted(private_stores: list[Path], tmp_path: Path) -> None:
    """Structure only: an exit status and a record count. Nothing from the store is printed."""
    if not private_stores:
        pytest.skip("no private stores present")
    for index, store in enumerate(private_stores):
        target = tmp_path / f"private-{index}.mbox"
        status, _, _ = in_process(str(store), "--quiet", "-o", str(target))
        assert status == 0
        assert len(records(target)) >= 0
