"""The message store: refused when the file, the node or a property lies; exact against the goldens when they do not.

Denial first. `EntryId` is 24 bytes and nothing else: every short length, a
negative offset, a non-zero `rgbFlags`, a record key that is not 16 bytes,
a node that is not a `NodeId`. `Store.open` is refused for an ANSI store
(`PstUnsupportedError`), an empty file, a file truncated at every header
field boundary, a store whose `NID_MESSAGE_STORE` or `NID_NAME_TO_ID_MAP`
node has been renamed out of the node B-tree (`PstNotFoundError`), and a
store read under a ceiling of 1 (`PstLimitError`, kept apart from
`PstFormatError`). `OSError` is deliberately NOT wrapped — a missing path
and a directory raise `FileNotFoundError` and `IsADirectoryError`, which is
the one thing in this package that is not a `PstError` and is tested as
such.

Then the differential claim: `python -m pypstreader.debug store <fixture>` is
compared with `read_store_props`'s golden line for line, byte for byte, on
every Unicode corpus store, and the same goldens are compared again as
values through `tests/golden_parsers.parse_read_store_props` so that a
formatting accident cannot hide a typed one.

`pstd-inline-cid.pst` is the row's decision, pinned from both sides: the
oracle exits 1 on it after two lines (it has no
`PidTagIpmWastebasketEntryId` and no `PidTagFinderEntryId`), the dumper
reproduces that exactly, and `Store.open` nevertheless succeeds with
`wastebasket is None` and `finder is None` — which is what upstream's own
library does, since `read_named_props` exits 0 on the same file.

Private stores are STRUCTURE ONLY: property ids, counts, types and
booleans. No display name, no record key and no property value from a
private store is printed, logged or asserted on (CLAUDE.md).
"""

from __future__ import annotations

import io
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

import pypstreader
from pypstreader import debug
from pypstreader.errors import (
    PstError,
    PstFormatError,
    PstLimitError,
    PstNotFoundError,
    PstUnsupportedError,
)
from pypstreader.limits import DEFAULT_LIMITS, Limits
from pypstreader.ltp.prop_context import PropertyContext
from pypstreader.messaging.store import (
    ENTRY_ID_SIZE,
    PID_TAG_DISPLAY_NAME,
    PID_TAG_FINDER_ENTRY_ID,
    PID_TAG_IPM_SUB_TREE_ENTRY_ID,
    PID_TAG_IPM_WASTEBASKET_ENTRY_ID,
    PID_TAG_RECORD_KEY,
    RECORD_KEY_SIZE,
    EntryId,
    Store,
    open_store,
)
from pypstreader.ndb.ids import NodeId, NodeIdType
from tests import corrupt
from tests.conftest import FIXTURES, REPO, public_fixture_paths
from tests.golden_parsers import parse_read_store_props
from tests.test_prop_context import make_pc, utf16, value_hnid

ALL_STORES = [FIXTURES / "Empty.pst", *public_fixture_paths()]
ANSI_STEMS = {"pstsdk-sample2", "pstsdk-test_ansi"}
ANSI_STORES = [p for p in ALL_STORES if p.stem in ANSI_STEMS]
UNICODE_STORES = [p for p in ALL_STORES if p.stem not in ANSI_STEMS]
UNICODE_IDS = [p.stem for p in UNICODE_STORES]

# The oracle's own failure, not ours (see the module docstring).
PARTIAL_STORE_PROPS = {"pstd-inline-cid"}

ORACLE_BIN = REPO / "reference" / "outlook-pst-rs" / "target" / "debug" / "examples"

RECORD_KEY = bytes(range(16))
# NID_TYPE_NORMAL_FOLDER with index 0x401 — the shape `read_store_props`
# prints for an IPM subtree, so `__str__` can be compared with a golden line.
IPM_LIKE_NID = (0x401 << 5) | int(NodeIdType.NORMAL_FOLDER)


def entry_id_bytes(record_key: bytes = RECORD_KEY, nid: int = IPM_LIKE_NID, flags: int = 0) -> bytes:
    return struct.pack("<I16sI", flags, record_key, nid)


# --- denial: EntryId ------------------------------------------------------------------


def test_entry_id_round_trips() -> None:
    """24 bytes in, the same 24 bytes out — the inverse pair the rest of the tests lean on."""
    raw = entry_id_bytes()
    entry = EntryId.unpack_from(raw)
    assert entry.record_key == RECORD_KEY
    assert entry.node == NodeId(IPM_LIKE_NID)
    assert entry.pack() == raw
    assert EntryId.SIZE == ENTRY_ID_SIZE == 24


def test_entry_id_debug_form_is_upstreams() -> None:
    """`__str__` is what the goldens print; `parse_entry_id` reads it back."""
    entry = EntryId.unpack_from(entry_id_bytes())
    assert str(entry) == (
        "EntryId { record_key: 00-01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F, "
        "node_id: NodeId { NormalFolder: 0x401 } }"
    )
    # The same shape the Empty.pst golden prints, so the two are comparable.
    golden_line = (REPO / "tests" / "golden" / "Empty" / "read_store_props.txt").read_text().splitlines()[1]
    assert golden_line.startswith("IPM Subtree: EntryId { record_key: ")
    assert golden_line.endswith("node_id: NodeId { NormalFolder: 0x401 } }")


@pytest.mark.parametrize("length", range(ENTRY_ID_SIZE))
def test_entry_id_shorter_than_24_bytes_is_refused(length: int) -> None:
    with pytest.raises(PstFormatError):
        EntryId.unpack_from(entry_id_bytes()[:length])


def test_entry_id_at_an_offset_and_past_the_end() -> None:
    """Straddling the end, at the end and past it — and a negative offset, which struct would count backwards."""
    buf = b"\xaa" * 3 + entry_id_bytes()
    assert EntryId.unpack_from(buf, 3).node == NodeId(IPM_LIKE_NID)
    for offset in (1, 2, 4, len(buf), len(buf) + 1, -1, -24):
        with pytest.raises(PstFormatError):
            EntryId.unpack_from(buf, offset)


@pytest.mark.parametrize("flags", [1, 0x80000000, 0xFFFFFFFF, 0x4E444221])
def test_entry_id_with_non_zero_flags_is_refused(flags: int) -> None:
    """[MS-PST] 2.4.3.2 `rgbFlags` is reserved and zero; upstream's `InvalidEntryIdFlags`."""
    with pytest.raises(PstFormatError, match="rgbFlags"):
        EntryId.unpack_from(entry_id_bytes(flags=flags))


@pytest.mark.parametrize(
    "record_key",
    [b"", b"\x00" * 15, b"\x00" * 17, "not bytes", None],
)
def test_entry_id_record_key_must_be_16_bytes(record_key: object) -> None:
    with pytest.raises(PstFormatError):
        EntryId(record_key, NodeId(0x21))  # type: ignore[arg-type]


@pytest.mark.parametrize("node", [0x21, "0x21", None, NodeIdType.NORMAL_FOLDER])
def test_entry_id_node_must_be_a_node_id(node: object) -> None:
    with pytest.raises(PstFormatError):
        EntryId(RECORD_KEY, node)  # type: ignore[arg-type]


def test_entry_id_is_frozen_and_copies_its_key() -> None:
    """A parsed structure is a fact: a bytearray handed in cannot be mutated underneath it."""
    key = bytearray(RECORD_KEY)
    entry = EntryId(key, NodeId(0x21))
    key[0] = 0xFF
    assert entry.record_key == RECORD_KEY
    assert entry == EntryId(RECORD_KEY, NodeId(0x21))
    with pytest.raises(AttributeError):
        entry.node = NodeId(0x22)  # type: ignore[misc]


# --- denial: opening ------------------------------------------------------------------


@pytest.mark.parametrize("store", ANSI_STORES, ids=[p.stem for p in ANSI_STORES])
def test_ansi_store_is_refused_at_open(store: Path) -> None:
    """ADR-0003: the ANSI arm is not ported, and the refusal happens before any node is read."""
    with pytest.raises(PstUnsupportedError):
        Store.open(store)
    with pytest.raises(PstUnsupportedError):
        pypstreader.open(store)


def test_empty_file_is_a_format_error(tmp_path: Path) -> None:
    path = tmp_path / "empty.pst"
    path.write_bytes(b"")
    with pytest.raises(PstFormatError):
        Store.open(path)


def test_truncated_at_every_header_field_boundary(tmp_path: Path) -> None:
    """Every field boundary of the header, and the header's own length: refused, and only ever as a `PstError`."""
    base = (FIXTURES / "Empty.pst").read_bytes()
    lengths = sorted({0, 1, 4, *[f.offset for f in corrupt.header_fields()], corrupt.HEADER_SIZE - 1})
    path = tmp_path / "short.pst"
    for length in lengths:
        path.write_bytes(base[:length])
        with pytest.raises(PstError) as info:
            Store.open(path)
        assert isinstance(info.value, (PstFormatError, PstUnsupportedError)), f"{length} bytes: {info.value!r}"
    # The whole header and nothing after it: the header parses, the B-tree does not.
    path.write_bytes(base[: corrupt.HEADER_SIZE])
    with pytest.raises(PstFormatError):
        Store.open(path)


def test_a_path_that_is_not_a_file_raises_oserror(tmp_path: Path) -> None:
    """The one deliberate exception to "PstError or nothing": opening the PATH is the OS's business.

    A caller handling paths catches `OSError` by name and expects
    `FileNotFoundError` to survive. Everything about the BYTES of a file
    that did open is a `PstError` — see the module docstring of
    `pypstreader.messaging.store`.
    """
    with pytest.raises(FileNotFoundError):
        Store.open(tmp_path / "no-such-file.pst")
    with pytest.raises(IsADirectoryError):
        Store.open(tmp_path)
    with pytest.raises(FileNotFoundError):
        pypstreader.open(tmp_path / "no-such-file.pst")


def rename_node(data: bytes, nid: int, new_nid: int) -> bytes:
    """`data` with the node B-tree's leaf entry for `nid` renamed, so the node is absent from the tree.

    The new id is chosen one above the old one by every caller, which keeps
    the leaf's keys in order; only the key changes, so the page reseals to a
    perfectly valid tree that simply does not hold `nid`.
    """
    (_page_id, nbt), _bbt = corrupt.root_refs(data)
    for page in corrupt.tree_pages(data, nbt):
        count, _max, entry_size, level, _padding = corrupt._btree_header(data, page)
        if level != 0:
            continue
        for i in range(count):
            at = page + i * entry_size
            (key,) = struct.unpack_from("<Q", data, at)
            if key == nid:
                return corrupt.reseal_page(corrupt.set_u32(data, at, new_nid), page)
    raise AssertionError(f"no NBT entry for node 0x{nid:X}")


def test_a_store_without_its_message_store_node_is_not_found(tmp_path: Path) -> None:
    """NID 0x21 renamed out of the node B-tree: `PstNotFoundError`, not a crash and not a silent empty store."""
    data = rename_node((FIXTURES / "Empty.pst").read_bytes(), 0x21, 0x22)
    with pytest.raises(PstNotFoundError):
        Store(io.BytesIO(data))
    path = tmp_path / "no-store-node.pst"
    path.write_bytes(data)
    with pytest.raises(PstNotFoundError):
        Store.open(path)


def leaf_nids(data: bytes) -> list[int]:
    """Every NID the node B-tree's leaves hold, read raw — the base's shape, not the reader's view of it."""
    (_page_id, nbt), _bbt = corrupt.root_refs(data)
    out: list[int] = []
    for page in corrupt.tree_pages(data, nbt):
        count, _max, entry_size, level, _padding = corrupt._btree_header(data, page)
        if level != 0:
            continue
        out += [struct.unpack_from("<Q", data, page + i * entry_size)[0] for i in range(count)]
    return out


def test_a_store_whose_message_store_node_is_not_a_property_context() -> None:
    """NID 0x21 pointed at a hierarchy table instead: the heap opens, its client signature is bTypeTC, a PC refuses it."""
    data = (FIXTURES / "Empty.pst").read_bytes()
    table = next(nid for nid in leaf_nids(data) if nid & 0x1F == int(NodeIdType.HIERARCHY_TABLE))
    swapped = rename_node(rename_node(data, 0x21, 0x22), table, 0x21)
    with pytest.raises(PstFormatError, match="bTypePC"):
        Store(io.BytesIO(swapped))


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_a_ceiling_of_one_is_a_limit_error_not_a_format_error(store: Path) -> None:
    """`PstLimitError` and `PstFormatError` stay distinguishable: "too big" and "corrupt" are different answers."""
    with pytest.raises(PstLimitError):
        Store.open(store, limits=Limits(max_property_count=1))
    with pytest.raises(PstLimitError):
        Store.open(store, limits=Limits(max_items=1))


# --- the file handle ------------------------------------------------------------------


def test_open_owns_its_file_and_close_is_idempotent() -> None:
    store = Store.open(FIXTURES / "Empty.pst")
    handle = store._f
    assert not handle.closed
    store.close()
    assert handle.closed
    store.close()  # idempotent


def test_context_manager_closes_on_the_way_out_and_on_an_exception() -> None:
    with Store.open(FIXTURES / "Empty.pst") as store:
        assert store.display_name == "Empty"
    assert store._f.closed

    store = Store.open(FIXTURES / "Empty.pst")
    with pytest.raises(ZeroDivisionError), store:
        _ = 1 / 0
    assert store._f.closed


def test_a_caller_supplied_file_object_is_left_open() -> None:
    """`Store(f)` borrows; only `Store.open` owns."""
    f = io.BytesIO((FIXTURES / "Empty.pst").read_bytes())
    store = Store(f)
    store.close()
    assert not f.closed
    assert store.path is None


def test_open_closes_the_file_when_the_store_refuses(tmp_path: Path) -> None:
    """A refusal must not leak a descriptor: the file is closed before the `PstError` propagates.

    Refcounting would close it eventually anyway, which is exactly why this
    asks the question directly: the traceback still holds `Store.open`'s
    frame, so the file object it opened can be reached and interrogated.
    """
    path = tmp_path / "bad.pst"
    path.write_bytes(b"!BDN" + bytes(100))
    with pytest.raises(PstFormatError) as info:
        Store.open(path)
    handles = []
    tb = info.value.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        if frame.f_code.co_qualname == "Store.open" and isinstance(frame.f_locals.get("f"), io.IOBase):
            handles.append(frame.f_locals["f"])
        tb = tb.tb_next
    assert handles, "Store.open's frame is not in the traceback; this test cannot see what it opened"
    assert all(h.closed for h in handles), "Store.open leaked its file handle when the store refused"

    if Path("/proc/self/fd").is_dir():  # the gross check too, over many refusals
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(64):
            with pytest.raises(PstFormatError):
                Store.open(path)
        assert len(os.listdir("/proc/self/fd")) == before, "Store.open leaked a file descriptor on refusal"


# --- the corpus, as values -------------------------------------------------------------


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_every_unicode_store_opens_and_agrees_with_its_golden(store: Path, golden, golden_exit) -> None:
    """Display name, record key and the three entry ids, value for value against `read_store_props`."""
    expected = parse_read_store_props(golden(store, "read_store_props"))
    with Store.open(store, codepage=debug.DUMP_CODEPAGE) as opened:
        assert opened.display_name == expected["display_name"], store.stem
        assert len(opened.record_key) == RECORD_KEY_SIZE
        assert opened.ipm_subtree.record_key == opened.record_key, store.stem
        assert _node(expected["ipm_subtree"]) == opened.ipm_subtree.node, store.stem
        if store.stem in PARTIAL_STORE_PROPS:
            assert golden_exit(store, "read_store_props") == 1
            assert expected["deleted_items"] is None and expected["finder"] is None
            assert opened.wastebasket is None and opened.finder is None
            return
        assert golden_exit(store, "read_store_props") == 0
        assert opened.wastebasket is not None and opened.finder is not None
        assert _node(expected["deleted_items"]) == opened.wastebasket.node, store.stem
        assert _node(expected["finder"]) == opened.finder.node, store.stem
        assert opened.wastebasket.record_key == opened.record_key
        assert opened.finder.record_key == opened.record_key
        assert [g["id"] for g in expected["properties"]] == list(opened.properties.records), store.stem


def _node(parsed: dict[str, object]) -> NodeId:
    """A `parse_entry_id` node dict as a `NodeId` — the type name and index the golden printed."""
    node_id = parsed["node_id"]
    assert isinstance(node_id, dict)
    return NodeId.from_parts(NodeIdType.from_debug_name(str(node_id["type"])), int(node_id["index"]))  # type: ignore[arg-type]


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_dump_store_reproduces_read_store_props_byte_for_byte(store: Path, golden, golden_exit) -> None:
    """The whole claim of this row's first half: same bytes in, same characters out, same exit status."""
    expected = golden(store, "read_store_props")
    text, refused = _dump(debug.dump_store, store)
    assert text == expected, f"{store.stem}: `debug store` differs from read_store_props"
    assert refused == bool(golden_exit(store, "read_store_props")), store.stem


def _dump(dumper, store: Path) -> tuple[str, bool]:
    """A dumper's stdout, and whether it refused. Nothing but a `PstError` may come out of it."""
    out = io.StringIO()
    stdout, sys.stdout = sys.stdout, out
    refused = False
    try:
        dumper(store)
    except PstError:
        refused = True
    finally:
        sys.stdout = stdout
    return out.getvalue(), refused


def test_the_pstd_inline_cid_decision_is_pinned() -> None:
    """P07's decision, from both sides at once, so that changing it is a red test.

    The oracle refuses the whole example (`read_store_props` exits 1 after
    two lines) because the store has no `PidTagIpmWastebasketEntryId`; the
    upstream *library* does not (`read_named_props` exits 0 on the same
    file). This port follows the library: the store opens, and the two
    optional entry ids are `None`.
    """
    store = FIXTURES / "public" / "pstd-inline-cid.pst"
    golden_dir = REPO / "tests" / "golden" / "pstd-inline-cid"
    assert (golden_dir / "read_store_props.exit").read_text().strip() == "1"
    assert not (golden_dir / "read_named_props.exit").exists(), "the oracle opens this store; only the example fails"
    assert len((golden_dir / "read_store_props.txt").read_text().splitlines()) == 2

    with Store.open(store) as opened:
        assert opened.wastebasket is None
        assert opened.finder is None
        assert opened.ipm_subtree.node == NodeId.from_parts(NodeIdType.NORMAL_FOLDER, 0x9)
        assert PID_TAG_IPM_WASTEBASKET_ENTRY_ID not in opened.properties
        assert PID_TAG_FINDER_ENTRY_ID not in opened.properties
        assert len(opened.named_properties.entries) == 1  # and the named map reads, as upstream's does


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_the_named_properties_the_store_reads_by_name_are_all_present(store: Path) -> None:
    """The three required ones on every Unicode store; the two optional ones only where the store has them."""
    with Store.open(store) as opened:
        records = opened.properties.records
        for prop_id in (PID_TAG_RECORD_KEY, PID_TAG_DISPLAY_NAME, PID_TAG_IPM_SUB_TREE_ENTRY_ID):
            assert prop_id in records, f"{store.stem}: missing 0x{prop_id:04X}"
        for prop_id, value in (
            (PID_TAG_IPM_WASTEBASKET_ENTRY_ID, opened.wastebasket),
            (PID_TAG_FINDER_ENTRY_ID, opened.finder),
        ):
            assert (prop_id in records) == (value is not None), f"{store.stem}: 0x{prop_id:04X}"


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_entry_id_and_matches_record_key(store: Path) -> None:
    """`entry_id` mints this store's ids and `matches_record_key` tells them from another store's."""
    with Store.open(store) as opened:
        minted = opened.entry_id(NodeId(0x122))
        assert minted.node == NodeId(0x122)
        assert opened.matches_record_key(minted)
        assert opened.matches_record_key(opened.ipm_subtree)
        assert not opened.matches_record_key(EntryId(bytes(RECORD_KEY_SIZE), NodeId(0x122)))
        assert minted.pack() == EntryId.unpack_from(minted.pack()).pack()
        with pytest.raises(TypeError):
            opened.entry_id(0x122)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            opened.matches_record_key(minted.pack())  # type: ignore[arg-type]


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_the_store_exposes_the_layers_underneath(store: Path) -> None:
    """`header`, `reader`, `nbt`, `bbt`, `properties` are the objects P08 and P09 will build on."""
    with Store.open(store) as opened:
        assert opened.header.version.is_ansi is False
        assert opened.limits is DEFAULT_LIMITS
        assert opened.codepage == "cp1252"
        assert opened.path == store
        assert isinstance(opened.properties, PropertyContext)
        assert opened.reader.limits is DEFAULT_LIMITS
        assert opened.nbt.find(NodeId(0x21)).node == NodeId(0x21)
        assert opened.bbt.find(opened.nbt.find(NodeId(0x21)).data).size > 0
        assert opened.get(PID_TAG_DISPLAY_NAME) == opened.display_name
        assert opened.get(0xFFFF) is None


def test_open_store_and_pypstreader_open_are_the_same_reader() -> None:
    """`pypstreader.open` is the module-level function, not a second implementation."""
    assert pypstreader.open is open_store
    assert pypstreader.Store is Store
    assert pypstreader.EntryId is EntryId
    with pypstreader.open(FIXTURES / "Empty.pst") as store:
        assert store.display_name == "Empty"


def test_a_missing_or_wrongly_typed_store_property_is_refused() -> None:
    """The accessors' own arms, on a store PC built by hand rather than by a mutation."""
    # Nothing at all: every required accessor refuses, both optional ones are None.
    pc = make_pc([(0x0001, 0x0003, 7)])
    store = _store_over(pc)
    for accessor in ("record_key", "display_name", "ipm_subtree"):
        with pytest.raises(PstFormatError, match="missing"):
            getattr(store, accessor)
    assert store.wastebasket is None and store.finder is None

    # A display name that is Binary, a record key that is inline, an entry id
    # of the wrong length, and an entry id that is not Binary at all.
    pc = make_pc(
        [
            (PID_TAG_RECORD_KEY, 0x0003, 0x1234),
            (PID_TAG_DISPLAY_NAME, 0x0102, value_hnid(0)),
            (PID_TAG_IPM_SUB_TREE_ENTRY_ID, 0x0102, value_hnid(1)),
            (PID_TAG_FINDER_ENTRY_ID, 0x001F, value_hnid(2)),
        ],
        [b"\x01\x02\x03\x04", entry_id_bytes()[:23], utf16("nope")],
    )
    store = _store_over(pc)
    with pytest.raises(PstFormatError, match="not Binary"):
        _ = store.record_key
    with pytest.raises(PstFormatError, match="not a string"):
        _ = store.display_name
    with pytest.raises(PstFormatError, match="23 bytes"):
        _ = store.ipm_subtree
    with pytest.raises(PstFormatError, match="not Binary"):
        _ = store.finder


def test_an_entry_id_property_of_the_wrong_length_is_refused() -> None:
    """A documented divergence: upstream reads 24 bytes out of the value and ignores whatever follows.

    Both directions matter — a 23-byte value is short for the record and a
    25-byte one is not, so only the explicit length check catches the second.
    """
    for length, blob in ((25, entry_id_bytes() + b"\x00"), (23, entry_id_bytes()[:23]), (0 + 48, entry_id_bytes() * 2)):
        pc = make_pc([(PID_TAG_IPM_SUB_TREE_ENTRY_ID, 0x0102, value_hnid(0))], [blob])
        with pytest.raises(PstFormatError, match=f"{length} bytes"):
            _ = _store_over(pc).ipm_subtree
    pc = make_pc([(PID_TAG_IPM_SUB_TREE_ENTRY_ID, 0x0102, value_hnid(0))], [entry_id_bytes()])
    assert _store_over(pc).ipm_subtree.node == NodeId(IPM_LIKE_NID)
    # The two optional ones go through the same check, absence aside.
    pc = make_pc([(PID_TAG_FINDER_ENTRY_ID, 0x0102, value_hnid(0))], [entry_id_bytes() + b"\x00"])
    with pytest.raises(PstFormatError, match="25 bytes"):
        _ = _store_over(pc).finder


def test_a_record_key_of_the_wrong_size_is_refused() -> None:
    pc = make_pc([(PID_TAG_RECORD_KEY, 0x0102, value_hnid(0))], [b"\x00" * 15])
    with pytest.raises(PstFormatError, match="size"):
        _ = _store_over(pc).record_key


def _store_over(pc: PropertyContext) -> Store:
    """A `Store` whose properties are `pc` — the accessors under test without a file behind them.

    Built by hand because the arms below are reachable only from a store PC
    no writer produces; every other test in this module goes through
    `Store.open`.
    """
    store = Store.__new__(Store)
    store._properties = pc
    store._named = None
    store._limits = DEFAULT_LIMITS
    store._codepage = "cp1252"
    store._owns_file = False
    store._path = None
    return store


# --- private stores: structure only ------------------------------------------------------


@pytest.mark.private
def test_private_stores_open_structure_only(private_stores: list[Path]) -> None:
    """Every private store opens and its ids are self-consistent. Counts and booleans — never a value."""
    if not private_stores:
        pytest.skip("no private stores present (this is a normal clean checkout)")
    for index, path in enumerate(private_stores):
        with Store.open(path) as store:
            assert type(store.display_name) is str, f"private store {index}: display name is not a string"
            assert len(store.record_key) == RECORD_KEY_SIZE, f"private store {index}: record key size"
            assert len(store.properties) > 0, f"private store {index}: empty store PC"
            assert store.matches_record_key(store.ipm_subtree), f"private store {index}: ipm subtree is another store's"
            assert store.ipm_subtree.node.id_type is NodeIdType.NORMAL_FOLDER, f"private store {index}"
            for optional in (store.wastebasket, store.finder):
                assert optional is None or store.matches_record_key(optional), f"private store {index}"


@pytest.mark.private
@pytest.mark.oracle
def test_private_store_structure_matches_the_prebuilt_oracle(private_stores: list[Path]) -> None:
    """The property ids and the entry ids' node types, from the oracle and from this port. No values (CLAUDE.md).

    Runs the example binary that is already built; it never invokes `cargo`,
    so a box that has not built the oracle simply skips.
    """
    if not private_stores:
        pytest.skip("no private stores present (this is a normal clean checkout)")
    binary = ORACLE_BIN / "read_store_props"
    if not binary.exists():
        pytest.skip("reference/.../examples/read_store_props is not built — scripts/build_oracle.sh")
    checked = 0
    for index, path in enumerate(private_stores):
        result = subprocess.run([str(binary), str(path)], capture_output=True, text=True, timeout=300, check=False)
        if result.returncode != 0:
            continue  # the oracle refuses this store; a structure claim needs both sides
        expected = parse_read_store_props(result.stdout)
        with Store.open(path, codepage=debug.DUMP_CODEPAGE) as store:
            assert list(store.properties.records) == [g["id"] for g in expected["properties"]], f"private store {index}"
            assert store.ipm_subtree.node == _node(expected["ipm_subtree"]), f"private store {index}"
            assert (store.wastebasket is None) == (expected["deleted_items"] is None), f"private store {index}"
            assert (store.finder is None) == (expected["finder"] is None), f"private store {index}"
            assert store.display_name == expected["display_name"], f"private store {index}: display name differs"
        checked += 1
    if not checked:
        pytest.skip("the oracle refused every private store")
