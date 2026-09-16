"""The folder tree (P08): the differential against `dump_messages`, and the refusals.

Three tiers, in the order the `test-harness` skill asks for them.

**Denial first.** A folder is opened from a NID an attacker chose, and its
children are NIDs a table the attacker wrote names. Every one of those is
refused by type: a NID that is not a folder's, a NID the node B-tree does not
hold, an EntryID from another store, a hierarchy table that will not parse, a
child that is its own parent, a tree deeper than the ceiling, a required
property that is absent or the wrong type. `PstLimitError` and
`PstFormatError` stay apart throughout.

**Then the differential.** `python -m pypstreader.debug folders` against the folder
blocks of the committed `dump_messages` goldens — byte for byte, and then the
same goldens re-read as values through `tests.golden_parsers.parse_dump_messages`
and compared against `Folder.walk()` id by id, name by name, count by count.
All eight Unicode corpus stores match byte for byte, including `synth-basics`
(`test_synth_basics_associated_table_is_byte_identical`), whose empty
associated-contents table used to be this file's one documented divergence
until P06b closed it (`pypstreader.ltp.table_context`'s module docstring).

**Then the shape of the API**: the walk's order, the three tables, the
computed `entry_id` and `folder_type`, and the decision about a null display
name.
"""

from __future__ import annotations

import dataclasses
import io
import subprocess
import sys
from pathlib import Path

import pytest

from pypstreader.debug import DUMPERS, dump_folders
from pypstreader.errors import PstFormatError, PstLimitError, PstNotFoundError
from pypstreader.limits import DEFAULT_LIMITS, Limits
from pypstreader.ltp.table_context import TableContext
from pypstreader.messaging.folder import (
    PID_TAG_CONTENT_COUNT,
    PID_TAG_CONTENT_UNREAD_COUNT,
    PID_TAG_DISPLAY_NAME,
    PID_TAG_SUBFOLDERS,
    Folder,
)
from pypstreader.messaging.store import EntryId, Store
from pypstreader.ndb.ids import NID_MESSAGE_STORE, NID_ROOT_FOLDER, NodeId, NodeIdType
from tests import corrupt
from tests.conftest import FIXTURES, REPO, public_fixture_paths
from tests.golden_parsers import dump_messages_folder_lines, parse_dump_messages

EXAMPLE = "dump_messages"
ANSI_STORES = {"pstsdk-sample2", "pstsdk-test_ansi"}
ALL_STORES = [FIXTURES / "Empty.pst", *public_fixture_paths()]
UNICODE_STORES = [p for p in ALL_STORES if p.stem not in ANSI_STORES]
UNICODE_IDS = [p.stem for p in UNICODE_STORES]

# `synth-basics.pst`'s root folder writes an EMPTY associated-contents table
# whose TCINFO says `rgib[TCI_4b] = 4`. [MS-PST] 2.3.4.4 puts dwRowID and
# dwRowVer in the first 8 bytes of every row, so 4 is impossible for a row
# that exists — and the table has none. P06 used to refuse it when the
# TCINFO was parsed, before the table's (empty) row count was even known;
# P06b (`pypstreader.ltp.table_context`'s module docstring) narrowed that check to
# a non-empty matrix, matching upstream's own `rows_matrix()`, which never
# reads a row of an empty table and never trips. All eight Unicode corpus
# stores are now byte identical to the golden.
BYTE_IDENTICAL = UNICODE_STORES
BYTE_IDENTICAL_IDS = UNICODE_IDS

# `pstd-inline-cid.pst`'s root folder has all three tables in the node B-tree
# and none of them parses (five bitmap bytes for five columns, and the same
# `rgib[TCI_4b]` lie): its golden is one folder and nothing under it.
NO_TABLES = "pstd-inline-cid"


def _store(path: Path, **kw: object) -> Store:
    return Store.open(path, **kw)  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def empty_bytes() -> bytes:
    return (FIXTURES / "Empty.pst").read_bytes()


# --- denial: the NID a folder is opened from -----------------------------------------


@pytest.mark.parametrize(
    "nid",
    [NID_MESSAGE_STORE, NodeId(0x12D), NodeId(0x61), NodeId(0x10004)],
    ids=["message store", "hierarchy table", "name-to-id map", "message"],
)
def test_a_nid_that_is_not_a_folders_is_refused(empty_pst: Path, nid: NodeId) -> None:
    """Upstream's `InvalidFolderEntryIdType`: only NormalFolder and SearchFolder open."""
    with _store(empty_pst) as store:
        with pytest.raises(PstFormatError, match="invalid folder EntryID NID_TYPE"):
            store.open_folder(nid)
        with pytest.raises(PstFormatError, match="invalid folder EntryID NID_TYPE"):
            Folder(store, nid)


def test_a_nid_whose_type_is_not_a_type_at_all_is_refused(empty_pst: Path) -> None:
    """0x09 is unassigned in [MS-PST] 2.2.2.1; the refusal comes from `NodeId.id_type`, before any read."""
    with _store(empty_pst) as store, pytest.raises(PstFormatError, match="unknown node id type"):
        store.open_folder(NodeId(0x09))


def test_a_folder_nid_the_node_btree_does_not_hold_is_not_found(empty_pst: Path) -> None:
    with _store(empty_pst) as store, pytest.raises(PstNotFoundError):
        store.open_folder(NodeId(0xFFFF_FFE2))


def test_an_entry_id_from_another_store_is_refused(empty_pst: Path) -> None:
    """Upstream's `EntryIdWrongStore` — the record key is what makes a foreign id detectable."""
    with _store(empty_pst) as store:
        foreign = EntryId(bytes(16), NID_ROOT_FOLDER)
        assert not store.matches_record_key(foreign)
        with pytest.raises(PstFormatError, match="wrong store"):
            store.open_folder(foreign)
        # ...and this store's own id for the same node opens.
        assert store.open_folder(store.entry_id(NID_ROOT_FOLDER)).node == NID_ROOT_FOLDER


@pytest.mark.parametrize("bad", [0x122, "0x122", None, b"", 1.0], ids=["int", "str", "None", "bytes", "float"])
def test_open_folder_refuses_something_that_is_neither_an_entry_id_nor_a_nid(empty_pst: Path, bad: object) -> None:
    with _store(empty_pst) as store, pytest.raises(TypeError):
        store.open_folder(bad)  # type: ignore[arg-type]


def test_folder_refuses_a_store_that_is_not_one(empty_pst: Path) -> None:
    with pytest.raises(TypeError, match="takes a Store"):
        Folder(object(), NID_ROOT_FOLDER)  # type: ignore[arg-type]
    with _store(empty_pst) as store, pytest.raises(TypeError, match="takes a NodeId"):
        Folder(store, 0x122)  # type: ignore[arg-type]


# --- denial: the tables --------------------------------------------------------------


def test_an_absent_table_is_none_and_names_nothing(empty_pst: Path) -> None:
    """`Empty.pst`'s search folder has no hierarchy, contents or associated node at all."""
    with _store(empty_pst) as store:
        search = next(f for f in store.root_folder.walk() if f.node.id_type is NodeIdType.SEARCH_FOLDER)
        assert (search.hierarchy_table, search.contents_table, search.associated_table) == (None, None, None)
        assert (search.subfolder_ids(), search.message_ids(), search.associated_ids()) == ((), (), ())
        assert search.contents() == ()
        assert list(search.walk()) == [search]


def test_a_table_node_that_will_not_parse_is_refused_not_reported_absent() -> None:
    """The divergence from upstream's `.ok()?`: present-and-corrupt is not the same answer as absent."""
    with _store(next(p for p in UNICODE_STORES if p.stem == NO_TABLES)) as store:
        root = store.root_folder
        # The nodes ARE there — this is not `PstNotFoundError`.
        for node_type in (NodeIdType.HIERARCHY_TABLE, NodeIdType.CONTENTS_TABLE, NodeIdType.ASSOC_CONTENTS_TABLE):
            store.nbt.find(NodeId.from_parts(node_type, root.node.index))
            with pytest.raises(PstFormatError) as info:
                root.table(node_type)
            assert not isinstance(info.value, PstNotFoundError)
        with pytest.raises(PstFormatError):
            root.subfolder_ids()
        with pytest.raises(PstFormatError):
            list(root.walk())


@pytest.mark.parametrize(
    "node_type",
    [NodeIdType.NORMAL_FOLDER, NodeIdType.INTERNAL, NodeIdType.LTP],
    ids=lambda t: t.name,
)
def test_asking_for_a_table_at_a_type_that_is_not_one_refuses_or_says_absent(empty_pst: Path, node_type: NodeIdType) -> None:
    """`table()` derives a NID and reads it as a TC; a node that is not one is a PstError, never a wrong object."""
    with _store(empty_pst) as store:
        try:
            result = store.root_folder.table(node_type)
        except PstFormatError:
            return
        assert result is None or isinstance(result, TableContext)


def test_table_refuses_a_node_type_that_is_not_one(empty_pst: Path) -> None:
    with _store(empty_pst) as store, pytest.raises(ValueError, match="not a valid NodeIdType"):
        store.root_folder.table(0x1234)  # type: ignore[arg-type]


# --- denial: the children a hierarchy table names ------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("row0.child_absent", PstNotFoundError),
        ("row0.child_is_the_root_folder", PstLimitError),
        ("row0.child_is_the_message_store", PstFormatError),
        ("row0.child_type_unassigned", PstFormatError),
    ],
)
def test_a_lying_hierarchy_row_is_refused_by_type(empty_bytes: bytes, name: str, expected: type[Exception]) -> None:
    """`folder_lies` rewrites the root hierarchy table's first row id; the walk must refuse each lie as its own kind."""
    mutation = corrupt.mutation(empty_bytes, seed=0, name=f"folder_lies:{name}")
    with Store(io.BytesIO(mutation.data)) as store, pytest.raises(expected) as info:
        list(store.root_folder.walk())
    if expected is PstFormatError:
        # "corrupt" and "absent" are different answers and must stay apart.
        assert not isinstance(info.value, PstNotFoundError)
    if expected is PstLimitError:
        assert "cycle" in str(info.value)


def test_a_folder_that_is_its_own_child_is_a_cycle_not_a_hang(empty_bytes: bytes) -> None:
    mutation = corrupt.mutation(empty_bytes, seed=0, name="folder_lies:row0.child_is_the_root_folder")
    with Store(io.BytesIO(mutation.data)) as store:
        walk = store.root_folder.walk()
        assert next(walk).node == NID_ROOT_FOLDER  # the root is yielded before the cycle is seen
        with pytest.raises(PstLimitError, match="folder tree: cycle at"):
            list(walk)


# --- denial: the four required properties --------------------------------------------


@pytest.mark.parametrize("prop_id", [PID_TAG_DISPLAY_NAME, PID_TAG_CONTENT_COUNT, PID_TAG_CONTENT_UNREAD_COUNT, PID_TAG_SUBFOLDERS])
@pytest.mark.parametrize("how", ["absent", "type"])
def test_a_required_property_that_is_absent_or_retyped_is_refused(empty_bytes: bytes, prop_id: int, how: str) -> None:
    """Upstream's `Folder…NotFound` / `InvalidFolder…` arms, one mutation each, asserted by type."""
    what = {
        PID_TAG_DISPLAY_NAME: ("display_name", "display_name"),
        PID_TAG_CONTENT_COUNT: ("content_count", "content_count"),
        PID_TAG_CONTENT_UNREAD_COUNT: ("unread_count", "unread_count"),
        PID_TAG_SUBFOLDERS: ("has_subfolders", "has_subfolders"),
    }[prop_id][0]
    mutation = corrupt.mutation(empty_bytes, seed=0, name=f"folder_lies:0x{prop_id:04X}_{how}_{what}")
    with Store(io.BytesIO(mutation.data)) as store:
        root = store.root_folder
        with pytest.raises(PstFormatError) as info:
            getattr(root, what)
        if how == "absent":
            assert "missing PidTag" in str(info.value)
        else:
            # Retyping a 4-byte scalar to a variable-length type turns its
            # inline value into an HNID, so the refusal can come from the heap
            # ("not in the node's sub-node tree") as easily as from the
            # accessor's own type check. Both are `PstFormatError`, which is
            # the claim; which layer notices is not.
            assert isinstance(info.value, PstFormatError)
        # The other three still read: one broken property does not break the folder.
        for other in ("display_name", "content_count", "unread_count", "has_subfolders"):
            if other == what:
                continue
            try:
                getattr(root, other)
            except PstFormatError as exc:  # Empty.pst's own root name is PtypNull
                assert other == "display_name", exc


def test_the_root_folders_null_display_name_is_a_refusal_not_none(empty_pst: Path) -> None:
    """The display-name decision, pinned: parity with upstream's `InvalidFolderDisplayName(Null)`.

    The record IS present and its HNID is 0, so this is not "missing" — and
    `properties.get` is the lenient reading a caller can still ask for.
    """
    with _store(empty_pst) as store:
        root = store.root_folder
        record = root.properties.records[PID_TAG_DISPLAY_NAME]
        assert record.is_null and record.value_type.debug_name == "Null"
        with pytest.raises(PstFormatError, match="invalid PidTagDisplayName on folder: Null"):
            _ = root.display_name
        assert root.properties.get(PID_TAG_DISPLAY_NAME) is None
        assert root.get(PID_TAG_DISPLAY_NAME) is None
        # ...and every other folder in the store does have a name.
        named = [f for f in root.walk() if f.node != NID_ROOT_FOLDER]
        assert named and all(isinstance(f.display_name, str) and f.display_name for f in named)


# --- denial: the ceilings ------------------------------------------------------------


def test_a_walk_deeper_than_max_depth_is_a_limit_error(empty_pst: Path) -> None:
    with _store(empty_pst) as store:
        root = store.root_folder
        # Empty.pst's tree is two deep: the root, its three children, and a
        # grandchild under two of them.
        assert len(list(root.walk())) == 6
        assert [f.node for f in root.walk(max_depth=2)] == [f.node for f in root.walk()]  # inclusive ceiling
        for tight in (1, 0):
            with pytest.raises(PstLimitError, match="folder tree depth"):
                list(root.walk(max_depth=tight))
        # ...and the folders shallower than the ceiling are yielded first.
        walk = root.walk(max_depth=1)
        assert [next(walk).node for _ in range(2)] == [NID_ROOT_FOLDER, root.subfolder_ids()[0]]


def test_max_folder_depth_is_the_default_and_bites(empty_pst: Path) -> None:
    assert DEFAULT_LIMITS.max_folder_depth == 64
    tight = dataclasses.replace(DEFAULT_LIMITS, max_folder_depth=1)
    with _store(empty_pst, limits=tight) as store, pytest.raises(PstLimitError, match="folder tree depth"):
        list(store.root_folder.walk())


def test_more_folders_than_max_folders_is_a_limit_error(empty_pst: Path) -> None:
    tight = dataclasses.replace(DEFAULT_LIMITS, max_folders=1)
    with _store(empty_pst, limits=tight) as store:
        with pytest.raises(PstLimitError) as info:
            store.root_folder.subfolder_ids()
        assert "hierarchy table" in str(info.value)
        with pytest.raises(PstLimitError):
            list(store.root_folder.walk())


def test_more_messages_than_max_messages_is_a_limit_error() -> None:
    tight = dataclasses.replace(DEFAULT_LIMITS, max_messages=1)
    store_path = next(p for p in UNICODE_STORES if p.stem == "tika-variousBodyTypes")
    with _store(store_path, limits=tight) as store:
        crowded = [f for f in store.root_folder.walk() if len(f.contents_table or ()) > 1]
        assert crowded, "the fixture is supposed to have a folder with more than one message"
        with pytest.raises(PstLimitError, match="contents table"):
            crowded[0].message_ids()


@pytest.mark.parametrize("bad", ["4", 1.5, True], ids=["str", "float", "bool"])
def test_walk_refuses_a_max_depth_that_is_not_an_int(empty_pst: Path, bad: object) -> None:
    with _store(empty_pst) as store, pytest.raises(TypeError, match="max_depth"):
        list(store.root_folder.walk(max_depth=bad))  # type: ignore[arg-type]


def test_every_ceiling_at_one_refuses_and_never_leaks(empty_pst: Path) -> None:
    """A `Limits` of all ones: the folder layer says `PstLimitError` or `PstFormatError`, and nothing else."""
    ones = Limits(**{f.name: 1 for f in dataclasses.fields(Limits)})
    try:
        store = _store(empty_pst, limits=ones)
    except (PstLimitError, PstFormatError):
        return  # the store itself is refused first, which is also correct
    with store, pytest.raises((PstLimitError, PstFormatError)):
        list(store.root_folder.walk())


# --- the differential: byte for byte -------------------------------------------------


def _dumper_output(path: Path, capsys: pytest.CaptureFixture[str]) -> str:
    dump_folders(path)
    return capsys.readouterr().out


@pytest.mark.parametrize("store", BYTE_IDENTICAL, ids=BYTE_IDENTICAL_IDS)
def test_debug_folders_is_byte_identical_to_the_golden(store: Path, golden, capsys: pytest.CaptureFixture[str]) -> None:
    """`debug folders` == the folder blocks of `dump_messages.txt`, line for line, on every store but one."""
    expected = dump_messages_folder_lines(golden(store, EXAMPLE))
    assert expected, f"{store.stem}: the golden has no folder blocks"
    assert _dumper_output(store, capsys).splitlines() == expected, store.stem


def test_synth_basics_associated_table_is_byte_identical(golden, capsys: pytest.CaptureFixture[str]) -> None:
    """P06b closed the one documented divergence: `debug folders` now matches the golden 8/8, byte for byte.

    `synth-basics.pst`'s root folder's empty associated-contents table
    carries `rgib[TCI_4b] = 4` — too small for the 8-byte row header, but
    the table has no row for it to misread (`pypstreader.ltp.table_context`'s
    module docstring). Where this used to be refused at TCINFO parse time
    (six `Associated Table: None` lines against the golden's `Associated
    Count: 0`), the table now opens and reports zero rows, exactly as
    upstream's `rows_matrix()` does.
    """
    store = next(p for p in UNICODE_STORES if p.stem == "synth-basics")
    expected = dump_messages_folder_lines(golden(store, EXAMPLE))
    got = _dumper_output(store, capsys).splitlines()
    assert got == expected
    # ...and the cause is `TableContext`'s row count, not anything in this layer.
    with _store(store) as opened:
        table = opened.root_folder.associated_table
        assert table is not None
        assert len(table) == 0
        assert opened.root_folder.associated_ids() == ()


def test_the_dumper_starts_at_the_root_folder_not_the_ipm_subtree(empty_pst: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """NID_ROOT_FOLDER (0x122) — starting at `ipm_subtree` would drop the wastebasket and the search folders."""
    lines = _dumper_output(empty_pst, capsys).splitlines()
    assert lines[0] == f"Folder: {NID_ROOT_FOLDER}"
    with _store(empty_pst) as store:
        assert store.ipm_subtree.node != NID_ROOT_FOLDER
        assert f"Folder: {store.ipm_subtree.node}" in lines


def test_the_dumper_is_registered_and_takes_no_extra_arguments() -> None:
    assert DUMPERS["folders"] is dump_folders


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_debug_folders_output_reparses_as_the_goldens_shape(store: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Our own output goes back through `parse_dump_messages`, so the two sides share one grammar."""
    parsed = parse_dump_messages(_dumper_output(store, capsys))
    assert parsed["errors"] is None  # the dumper prints no `Errors:` trailer
    assert parsed["folders"]
    assert all(f["messages"] == [] for f in parsed["folders"])


@pytest.mark.slow
@pytest.mark.parametrize("store", BYTE_IDENTICAL, ids=BYTE_IDENTICAL_IDS)
def test_debug_folders_through_the_process_boundary(store: Path, golden) -> None:
    """The same comparison through `python -m pypstreader.debug`: exit 0, nothing on stderr."""
    proc = subprocess.run(
        [sys.executable, "-m", "pypstreader.debug", "folders", str(store)],
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=300,
        check=False,
    )
    assert (proc.returncode, proc.stderr) == (0, "")
    assert proc.stdout.splitlines() == dump_messages_folder_lines(golden(store, EXAMPLE))


# --- the differential: value for value -----------------------------------------------


def _golden_folders(text: str) -> list[dict]:
    return parse_dump_messages(text)["folders"]


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_walk_matches_the_golden_id_for_id(store: Path, golden) -> None:
    """The walk's order and nodes, read as VALUES out of the golden rather than as text."""
    expected = [f["node"] for f in _golden_folders(golden(store, EXAMPLE))]
    with _store(store) as opened:
        walked = []
        try:
            for folder in opened.root_folder.walk():
                walked.append({"type": folder.node.id_type.debug_name, "index": folder.node.index})
        except PstFormatError:
            # pstd-inline-cid: the hierarchy table will not parse, and the
            # golden is the one folder the walk did produce.
            assert store.stem == NO_TABLES
        assert walked == expected, store.stem


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_every_folders_name_and_counts_match_the_golden(store: Path, golden) -> None:
    """Name, content count, unread count and sub-folder flag, per folder, against the oracle's values."""
    expected = _golden_folders(golden(store, EXAMPLE))
    checked = 0
    with _store(store, codepage="latin-1") as opened:
        for folder, want in zip(_walked(opened), expected, strict=False):
            for key, attr in (
                ("name", "display_name"),
                ("content_count", "content_count"),
                ("unread_count", "unread_count"),
                ("has_subfolders", "has_subfolders"),
            ):
                if isinstance(want[key], dict):  # the oracle printed `Error: …` in place of the value
                    with pytest.raises(PstFormatError):
                        getattr(folder, attr)
                else:
                    assert getattr(folder, attr) == want[key], f"{store.stem} {folder.node} {key}"
            checked += 1
    assert checked == len(expected), store.stem


@pytest.mark.parametrize("store", BYTE_IDENTICAL, ids=BYTE_IDENTICAL_IDS)
def test_every_folders_table_counts_match_the_golden(store: Path, golden) -> None:
    """`Associated Count:`, and the `… Table: None` lines, as the oracle's `.ok()?` sees them."""
    from pypstreader.debug import folder_table

    expected = _golden_folders(golden(store, EXAMPLE))
    with _store(store, codepage="latin-1") as opened:
        for folder, want in zip(_walked(opened), expected, strict=False):
            associated = folder_table(folder, NodeIdType.ASSOC_CONTENTS_TABLE)
            assert (None if associated is None else len(associated)) == want["associated_count"], folder.node
            assert (folder_table(folder, NodeIdType.CONTENTS_TABLE) is not None) == want["contents_table"]
            assert (folder_table(folder, NodeIdType.HIERARCHY_TABLE) is not None) == want["hierarchy_table"]


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_message_ids_match_the_goldens_message_blocks(store: Path, golden) -> None:
    """The contents table's row ids are exactly the `Message:` nodes the oracle printed under that folder."""
    expected = _golden_folders(golden(store, EXAMPLE))
    total = 0
    with _store(store) as opened:
        for folder, want in zip(_walked(opened), expected, strict=False):
            if not want["contents_table"]:
                # The oracle printed `Contents Table: None`: either the node
                # is absent (`Empty.pst`'s search folder) or it is there and
                # will not parse (`synth-basics`' Inbox, `pstd-inline-cid`'s
                # root folder). Either way, no messages are named — which is
                # the claim, and the two are told apart deliberately by
                # `test_a_table_node_that_will_not_parse_is_refused_not_reported_absent`.
                assert want["messages"] == []
                try:
                    assert folder.message_ids() == (), folder.node  # the node is absent
                except PstFormatError:
                    pass  # ...or it is there and unreadable, which this port says out loud
                continue
            got = [{"type": n.id_type.debug_name, "index": n.index} for n in folder.message_ids()]
            assert got == [m["node"] for m in want["messages"]], f"{store.stem} {folder.node}"
            total += len(got)
    assert total == sum(len(f["messages"]) for f in expected)


def _walked(store: Store) -> list[Folder]:
    """The walk, or as much of it as the store allows — `pstd-inline-cid` stops at the root."""
    out: list[Folder] = []
    try:
        out.extend(store.root_folder.walk())
    except PstFormatError:
        pass
    return out


# --- the shape of the API ------------------------------------------------------------


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_walk_is_pre_order_self_first_and_matches_the_dumper(store: Path, capsys: pytest.CaptureFixture[str]) -> None:
    printed = [ln.removeprefix("Folder: ") for ln in _dumper_output(store, capsys).splitlines() if ln.startswith("Folder: ")]
    with _store(store) as opened:
        assert [str(f.node) for f in _walked(opened)] == printed, store.stem


def test_walk_yields_self_first_even_with_no_children(empty_pst: Path) -> None:
    with _store(empty_pst) as store:
        leaf = next(f for f in store.root_folder.walk() if not f.subfolder_ids())
        assert [f.node for f in leaf.walk()] == [leaf.node]


def test_subfolders_opens_each_child_in_matrix_order(empty_pst: Path) -> None:
    with _store(empty_pst) as store:
        root = store.root_folder
        assert [f.node for f in root.subfolders()] == list(root.subfolder_ids())
        assert list(root.subfolder_ids()) == [NodeId(row.id) for row in root.hierarchy_table.rows()]


def test_contents_are_this_stores_entry_ids(empty_pst: Path) -> None:
    store_path = next(p for p in UNICODE_STORES if p.stem == "pstsdk-sample1")
    with _store(store_path) as store:
        folder = next(f for f in store.root_folder.walk() if f.message_ids())
        ids = folder.contents()
        assert [e.node for e in ids] == list(folder.message_ids())
        assert all(isinstance(e, EntryId) and store.matches_record_key(e) for e in ids)


def test_entry_id_and_folder_type_are_upstreams_computed_properties(empty_pst: Path) -> None:
    """The two values upstream injects into its property map; here they are attributes (module docstring)."""
    with _store(empty_pst) as store:
        folders = {f.node: f for f in store.root_folder.walk()}
        root = folders[NID_ROOT_FOLDER]
        assert root.folder_type == 0
        assert root.entry_id == store.entry_id(NID_ROOT_FOLDER)
        search = next(f for f in folders.values() if f.node.id_type is NodeIdType.SEARCH_FOLDER)
        assert search.folder_type == 2
        ordinary = next(f for f in folders.values() if f.node not in (NID_ROOT_FOLDER, search.node))
        assert ordinary.folder_type == 1
        # ...and the property context is the FILE's: neither id is in it.
        assert 0x0FFF not in root.properties.records
        assert 0x3601 not in root.properties.records


def test_the_three_tables_are_read_once_and_kept(empty_pst: Path) -> None:
    with _store(empty_pst) as store:
        root = store.root_folder
        assert root.hierarchy_table is root.hierarchy_table
        assert root.contents_table is root.contents_table
        assert root.associated_table is root.associated_table


def test_a_folder_knows_its_store_and_prints_its_node(empty_pst: Path) -> None:
    with _store(empty_pst) as store:
        root = store.root_folder
        assert root.store is store
        assert str(root) == f"Folder {{ {NID_ROOT_FOLDER} }}"


def test_the_root_folder_is_the_same_folder_open_folder_gives(empty_pst: Path) -> None:
    with _store(empty_pst) as store:
        assert store.root_folder.node == store.open_folder(NID_ROOT_FOLDER).node == NID_ROOT_FOLDER


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_every_unicode_store_opens_its_root_folder(store: Path) -> None:
    """The one claim that holds on all eight, `pstd-inline-cid` included: 0x122 is a readable property context."""
    with _store(store) as opened:
        assert opened.root_folder.node == NID_ROOT_FOLDER
        assert len(opened.root_folder.properties) > 0


@pytest.mark.parametrize("store", [p for p in ALL_STORES if p.stem in ANSI_STORES], ids=sorted(ANSI_STORES))
def test_an_ansi_store_is_refused_before_any_folder(store: Path) -> None:
    """ADR-0003: the refusal is the header's, and the folder layer is never reached."""
    from pypstreader.errors import PstUnsupportedError

    with pytest.raises(PstUnsupportedError):
        Store.open(store)


# --- private stores: structure only, never content -----------------------------------


@pytest.mark.private
def test_private_stores_walk_and_are_never_described(private_stores: list[Path]) -> None:
    """A real store's folder tree parses. Structure only: counts, depths and NID types — never a name.

    Nothing printed or asserted here can carry content: `display_name` is
    read and discarded (the assertion is on its TYPE), and the numbers are
    folder counts and tree depths, which are structure. CLAUDE.md § "Never
    print, log, or assert on private-store content".
    """
    if not private_stores:
        pytest.skip("no private stores in tests/fixtures/private/")
    for path in private_stores:
        with Store.open(path) as store:
            depths: dict[NodeId, int] = {NID_ROOT_FOLDER: 0}
            types: set[str] = set()
            count = 0
            for folder in store.root_folder.walk():
                count += 1
                types.add(folder.node.id_type.debug_name)
                for child in folder.subfolder_ids():
                    depths[child] = depths[folder.node] + 1
                try:
                    assert isinstance(folder.display_name, str)
                except PstFormatError:
                    pass  # a null name is a fact about the store, not a failure
                assert isinstance(folder.message_ids(), tuple)
            assert count >= 1
            assert types <= {"NormalFolder", "SearchFolder"}
            assert max(depths.values()) < DEFAULT_LIMITS.max_folder_depth
