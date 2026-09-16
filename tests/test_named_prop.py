"""The named property lookup map: refused when a stream lies, exact against `read_named_props` when it does not.

Denial first, on maps built from `tests/corrupt.py`'s heap and BTH builders
so that every lie is invisible to the layers underneath: a missing or
wrongly typed `PidTagNameidBucketCount`, a count of zero on a map that has
entries, a count past `0xEFFF`, a count smaller than the hash buckets the
map actually carries, a GUID stream that is not a whole number of GUIDs, an
entry stream that is not a whole number of NAMEIDs, a `wPropIdx` of 0x8000,
two NAMEIDs claiming one property id, a `wGuid` naming a GUID past the
stream, a string offset past the string stream, a string of odd length, and
a stream longer than `limits.max_items` — each the right `PstError`
subclass, with `PstLimitError` kept apart from `PstFormatError`.

Then the differential claim. `python -m pypst.debug named_props <fixture>`
is compared with `read_named_props`'s golden byte for byte on every Unicode
corpus store, and the same goldens are compared again as values through
`tests/golden_parsers.parse_read_named_props`: 964 named properties over 8
stores, each with its GUID and its name or number. P05 rebuilt the same 964
from the raw streams by hand (`tests/test_prop_context.named_properties_from_pc`);
that reconstruction stays, as an independent second reading, and this
module must agree with it entry for entry.

Private stores are STRUCTURE ONLY: counts, property ids, GUID indices and
booleans. No property NAME from a private store is printed, logged or
asserted on — a custom field's name is content (CLAUDE.md).
"""

from __future__ import annotations

import io
import struct
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from pypst import debug
from pypst.errors import PstError, PstFormatError, PstLimitError, PstNotFoundError
from pypst.limits import DEFAULT_LIMITS, Limits
from pypst.messaging.named_prop import (
    GUID_SIZE,
    NAME_ID_SIZE,
    PID_TAG_NAMEID_BUCKET_BASE,
    PS_MAPI,
    PS_PUBLIC_STRINGS,
    NamedProperty,
    NamedPropertyGuid,
    NamedPropertyMap,
    NameIdEntry,
)
from pypst.messaging.store import Store
from tests.conftest import FIXTURES, REPO, public_fixture_paths
from tests.golden_parsers import parse_read_named_props
from tests.test_prop_context import (
    make_pc,
    named_properties_from_pc,
    store_pc,
    value_hnid,
)

ALL_STORES = [FIXTURES / "Empty.pst", *public_fixture_paths()]
ANSI_STEMS = {"pstsdk-sample2", "pstsdk-test_ansi"}
UNICODE_STORES = [p for p in ALL_STORES if p.stem not in ANSI_STEMS]
UNICODE_IDS = [p.stem for p in UNICODE_STORES]

ORACLE_BIN = REPO / "reference" / "outlook-pst-rs" / "target" / "debug" / "examples"

NID_NAME_TO_ID_MAP = 0x61

GUID_A = uuid.UUID("00062002-0000-0000-c000-000000000046")
GUID_B = uuid.UUID("00062008-0000-0000-c000-000000000046")
TWO_GUIDS = GUID_A.bytes_le + GUID_B.bytes_le


# --- building a map by hand ---------------------------------------------------------


def nameid(name_id: int, guid_raw: int = 3, prop_index: int = 0, *, string: bool = False) -> bytes:
    """One NAMEID ([MS-PST] 2.4.7.1); `guid_raw` is `wGuid >> 1`, so 3 is the first GUID of the stream."""
    return struct.pack("<IHH", name_id, (guid_raw << 1) | int(string), prop_index)


def string_entry(text: str) -> bytes:
    """One string-stream entry: a u32 byte length, the UTF-16LE name, and padding to a 4-byte boundary."""
    body = text.encode("utf-16-le")
    blob = struct.pack("<I", len(body)) + body
    return blob + bytes(-len(blob) % 4)


def make_map(
    *,
    bucket_count: int | None = 251,
    guids: bytes | None = TWO_GUIDS,
    entries: bytes | None = nameid(0x8201, 3, 0),
    strings: bytes | None = b"\x00\x00\x00\x00",
    buckets: tuple[tuple[int, bytes], ...] = (),
    map_limits: Limits | None = None,
) -> NamedPropertyMap:
    """A `NamedPropertyMap` over a synthetic 0x61 property context; `None` leaves a stream property out.

    The heap refuses a zero-length item, so a stream is either absent or has
    at least one byte — which is also true of every real store (the smallest
    corpus map has a 4-byte string stream holding nothing).
    """
    records: list[tuple[int, int, int]] = []
    values: list[bytes] = []

    def add(prop_id: int, blob: bytes) -> None:
        records.append((prop_id, 0x0102, value_hnid(len(values))))
        values.append(blob)

    if bucket_count is not None:
        records.append((0x0001, 0x0003, bucket_count))
    if guids is not None:
        add(0x0002, guids)
    if entries is not None:
        add(0x0003, entries)
    if strings is not None:
        add(0x0004, strings)
    for prop_id, blob in buckets:
        add(prop_id, blob)
    return NamedPropertyMap(make_pc(sorted(records), values), map_limits)


# --- the happy path, by hand ---------------------------------------------------------


def test_a_hand_built_map_reads_its_streams() -> None:
    named = make_map(entries=nameid(0x8201, 3, 0) + nameid(0, 4, 1, string=True), strings=string_entry("Keywords"))
    assert named.bucket_count == 251
    assert named.guids == (GUID_A, GUID_B)
    assert len(named.entries) == len(named) == 2
    assert named.entries[0] == NameIdEntry(0x8201, NamedPropertyGuid(3), 0, False)
    assert named.entries[1] == NameIdEntry(0, NamedPropertyGuid(4), 1, True)
    assert [e.prop_id for e in named.entries] == [0x8000, 0x8001]
    assert named.lookup(0x8000) == NamedProperty(GUID_A, 0x8201)
    assert named.lookup(0x8001) == NamedProperty(GUID_B, "Keywords")
    assert named.lookup(0x8002) is None
    assert named.resolve(GUID_A, 0x8201) == 0x8000
    assert named.resolve(GUID_B, "Keywords") == 0x8001
    assert named.resolve(GUID_A, "Keywords") is None
    assert named.lookup(0x8001).is_string and not named.lookup(0x8000).is_string
    assert named.limits is DEFAULT_LIMITS
    assert named.lookup_string(0) == "Keywords"


def test_the_two_well_known_guids_are_named_not_stored() -> None:
    """[MS-OXPROPS] 1.3.2: `wGuid >> 1` of 1 and 2 are PS_MAPI and PS_PUBLIC_STRINGS, which no stream holds."""
    named = make_map(entries=nameid(0x1234, 1, 0) + nameid(0x5678, 2, 1) + nameid(0x9ABC, 0, 2))
    assert [str(e.guid) for e in named.entries] == ["Mapi", "PublicStrings", "None"]
    assert named.guid_of(named.entries[0]) == PS_MAPI
    assert named.guid_of(named.entries[1]) == PS_PUBLIC_STRINGS
    # `wGuid >> 1 == 0` names no GUID at all; upstream prints `None` and looks nothing up.
    assert named.guid_of(named.entries[2]) == uuid.UUID(int=0)
    assert named.entries[2].guid.index is None and named.entries[2].guid.well_known is None


def test_named_property_guid_debug_forms_and_bounds() -> None:
    """The `GUID Index:` line the goldens print, and upstream's `TryFrom<u16>` refusal above 0x7FFF."""
    assert [str(NamedPropertyGuid.from_wire(v)) for v in (0, 1, 2, 3, 4)] == [
        "None",
        "Mapi",
        "PublicStrings",
        "GuidIndex(0)",
        "GuidIndex(1)",
    ]
    assert NamedPropertyGuid(3).index == 0 and NamedPropertyGuid(3).is_index
    assert NamedPropertyGuid(0x7FFF).index == 0x7FFC
    for bad in (0x8000, 0xFFFF, -1, 1.0, True, "3"):
        with pytest.raises(PstFormatError):
            NamedPropertyGuid.from_wire(bad)  # type: ignore[arg-type]


def test_name_id_entry_fields_and_hash_value() -> None:
    """Upstream's `hash_value`: `dwPropertyID ^ (wGuid << 1 | string flag)`, masked to a u32."""
    number = NameIdEntry.unpack_from(nameid(0x8201, 3, 7))
    text = NameIdEntry.unpack_from(nameid(0x40, 4, 8, string=True))
    assert number.prop_id == 0x8007 and text.prop_id == 0x8008
    assert number.hash_value == 0x8201 ^ (3 << 1)
    assert text.hash_value == 0x40 ^ ((4 << 1) | 1)
    assert NameIdEntry.unpack_from(nameid(0xFFFFFFFF, 0x7FFF, 0)).hash_value <= 0xFFFFFFFF
    assert NameIdEntry.SIZE == NAME_ID_SIZE == 8


@pytest.mark.parametrize("length", range(NAME_ID_SIZE))
def test_name_id_entry_shorter_than_eight_bytes_is_refused(length: int) -> None:
    with pytest.raises(PstFormatError):
        NameIdEntry.unpack_from(nameid(1, 3, 0)[:length])


def test_name_id_entry_prop_index_past_the_named_range_is_refused() -> None:
    """Upstream's `NamedPropertyIndex::try_from` refuses >= 0x8000 — and then swallows the error."""
    with pytest.raises(PstFormatError, match="wPropIdx"):
        NameIdEntry.unpack_from(nameid(1, 3, 0x8000))
    with pytest.raises(PstFormatError, match="wPropIdx"):
        NameIdEntry.unpack_from(nameid(1, 3, 0xFFFF))


# --- denial: the bucket count ---------------------------------------------------------


def test_bucket_count_absent_is_refused() -> None:
    with pytest.raises(PstFormatError, match="missing PidTagNameidBucketCount"):
        _ = make_map(bucket_count=None).bucket_count


def test_bucket_count_of_the_wrong_type_is_refused() -> None:
    """Upstream's `invalid` arm: the count must be `PtypInteger32`, not a binary blob."""
    named = NamedPropertyMap(
        make_pc(
            [(0x0001, 0x0102, value_hnid(0)), (0x0002, 0x0102, value_hnid(1)), (0x0003, 0x0102, value_hnid(2))],
            [b"\xfb\x00\x00\x00", TWO_GUIDS, nameid(1, 3, 0)],
        )
    )
    with pytest.raises(PstFormatError, match="not Integer32"):
        _ = named.bucket_count


def test_bucket_count_of_zero_with_entries_is_refused() -> None:
    """Upstream computes `hash_value % bucket_count` on this and divides by zero."""
    with pytest.raises(PstFormatError, match="is 0 on a Named Property Lookup Map with 1 entries"):
        _ = make_map(bucket_count=0).bucket_count


def test_bucket_count_past_its_upper_bound_is_refused() -> None:
    """`0x1000 + count` must stay a u16 — upstream's own guard."""
    with pytest.raises(PstFormatError, match="out of bounds"):
        _ = make_map(bucket_count=0xF000).bucket_count
    with pytest.raises(PstFormatError, match="out of bounds"):
        _ = make_map(bucket_count=0xFFFFFFFF).bucket_count
    assert make_map(bucket_count=0xEFFF).bucket_count == 0xEFFF


def test_a_bucket_count_smaller_than_the_map_s_buckets_is_refused() -> None:
    """A count that does not describe the hash table it is in ([MS-PST] 2.4.7.5)."""
    buckets = ((PID_TAG_NAMEID_BUCKET_BASE + 40, nameid(1, 3, 0)),)
    assert make_map(bucket_count=41, buckets=buckets).bucket_count == 41
    with pytest.raises(PstFormatError, match="hash bucket 0x1028"):
        _ = make_map(bucket_count=40, buckets=buckets).bucket_count


# --- denial: the streams ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"guids": None}, "missing PidTagNameidStreamGuid"),
        ({"entries": None}, "missing PidTagNameidStreamEntry"),
    ],
)
def test_a_missing_stream_is_refused(kwargs: dict[str, None], match: str) -> None:
    named = make_map(**kwargs)  # type: ignore[arg-type]
    with pytest.raises(PstFormatError, match=match):
        _ = (named.guids, named.entries)


def test_a_missing_string_stream_is_refused_only_when_a_name_needs_it() -> None:
    named = make_map(entries=nameid(0x8201, 3, 0), strings=None)
    assert named.name_of(named.entries[0]) == 0x8201  # a number needs no string stream
    with_string = make_map(entries=nameid(0, 3, 0, string=True), strings=None)
    with pytest.raises(PstFormatError, match="missing PidTagNameidStreamString"):
        with_string.name_of(with_string.entries[0])


@pytest.mark.parametrize("extra", [1, 15, 17, 31])
def test_a_guid_stream_that_is_not_a_whole_number_of_guids_is_refused(extra: int) -> None:
    """Upstream's `while let Ok` drops the tail silently; this port refuses (module docstring)."""
    with pytest.raises(PstFormatError, match="not a whole number of 16-byte GUIDs"):
        _ = make_map(guids=TWO_GUIDS + bytes(extra)).guids
    assert len(make_map(guids=TWO_GUIDS + bytes(GUID_SIZE)).guids) == 3


@pytest.mark.parametrize("extra", [1, 3, 7])
def test_an_entry_stream_that_is_not_a_whole_number_of_nameids_is_refused(extra: int) -> None:
    with pytest.raises(PstFormatError, match="not a whole number of 8-byte NAMEIDs"):
        _ = make_map(entries=nameid(1, 3, 0) + bytes(extra)).entries


def test_an_entry_whose_guid_index_is_past_the_stream_is_refused() -> None:
    named = make_map(entries=nameid(0x8201, 5, 0))  # index 2 of a two-GUID stream
    with pytest.raises(PstFormatError, match="past the 2-GUID stream"):
        named.guid_of(named.entries[0])
    assert make_map(entries=nameid(0x8201, 4, 0)).guid_of(make_map(entries=nameid(0x8201, 4, 0)).entries[0]) == GUID_B


def test_two_entries_claiming_one_property_id_are_refused() -> None:
    """A divergence: upstream never indexes the entries by id, so it has no opinion."""
    named = make_map(entries=nameid(0x8201, 3, 4) + nameid(0x8202, 4, 4))
    assert len(named.entries) == 2  # the stream itself is well formed
    with pytest.raises(PstFormatError, match="0x8004 appears twice"):
        named.lookup(0x8004)


# --- denial: the string stream ------------------------------------------------------------


def test_a_string_offset_past_the_stream_is_refused() -> None:
    named = make_map(entries=nameid(0x40, 3, 0, string=True), strings=string_entry("Keywords"))
    with pytest.raises(PstFormatError):
        named.name_of(named.entries[0])
    for offset in (len(string_entry("Keywords")), 0xFFFFFFF0, 0x7FFFFFFF):
        with pytest.raises(PstFormatError):
            named.lookup_string(offset)


def test_a_string_of_odd_length_is_refused() -> None:
    """UTF-16 is two bytes a code unit; upstream refuses an odd `size` too (`InvalidNamedPropertyMapStreamString`)."""
    odd = struct.pack("<I", 7) + b"abcdefg" + b"\x00"
    with pytest.raises(PstFormatError, match="odd length 7"):
        make_map(strings=odd).lookup_string(0)


def test_a_string_claiming_more_bytes_than_the_stream_holds_is_refused() -> None:
    short = struct.pack("<I", 64) + "Keywords".encode("utf-16-le")
    with pytest.raises(PstFormatError, match="past the"):
        make_map(strings=short).lookup_string(0)


def test_a_truncated_string_length_field_is_refused() -> None:
    with pytest.raises(PstFormatError):
        make_map(strings=b"\x08\x00\x00").lookup_string(0)


def test_a_lone_surrogate_in_a_name_is_replaced_not_raised() -> None:
    """Upstream's `from_utf16_lossy`; a name is a label, and refusing the whole map over one is worse."""
    body = b"\x00\xd8" + "ok".encode("utf-16-le")
    blob = struct.pack("<I", len(body)) + body
    assert make_map(strings=blob).lookup_string(0) == "�ok"


# --- denial: the hash buckets --------------------------------------------------------------


def test_hash_bucket_reads_the_bucket_an_entry_hashes_to() -> None:
    entry = NameIdEntry.unpack_from(nameid(0x8201, 3, 0))
    offset = entry.hash_value % 251
    held = nameid(0x8201, 3, 0) + nameid(0x8202, 3, 1)
    named = make_map(buckets=((PID_TAG_NAMEID_BUCKET_BASE + offset, held),), bucket_count=251)
    assert named.hash_bucket(entry) == tuple(NameIdEntry.unpack_from(held, at) for at in (0, 8))


def test_a_hash_bucket_the_map_does_not_hold_is_not_found() -> None:
    entry = NameIdEntry.unpack_from(nameid(0x8201, 3, 0))
    with pytest.raises(PstNotFoundError, match="PidTagNameidBucketBase"):
        make_map().hash_bucket(entry)


def test_a_ragged_hash_bucket_is_refused() -> None:
    entry = NameIdEntry.unpack_from(nameid(0x8201, 3, 0))
    offset = entry.hash_value % 251
    named = make_map(buckets=((PID_TAG_NAMEID_BUCKET_BASE + offset, nameid(1, 3, 0) + b"\x00"),))
    with pytest.raises(PstFormatError, match="not a whole number"):
        named.hash_bucket(entry)


def test_hash_entry_keeps_the_guid_where_upstream_clears_it() -> None:
    """The divergence, pinned from both sides: upstream's form misses the bucket a real store put the name in.

    If someone "fixes" `hash_entry` back to upstream's
    `NamedPropertyGuid::None`, the first assertion still passes and the
    last one goes red — which is the point of computing both here.
    """
    with Store.open(FIXTURES / "Empty.pst") as opened:
        named = opened.named_properties
        entry = next(e for e in named.entries if e.is_string)
        hashed = named.hash_entry(entry)
        assert hashed.guid == entry.guid, "the property set is part of the key"
        assert hashed.name_id != entry.name_id and hashed.is_string
        assert any(b.prop_id == entry.prop_id for b in named.hash_bucket(entry))
        upstream_form = NameIdEntry(hashed.name_id, NamedPropertyGuid(0), entry.prop_index, True)
        assert upstream_form.hash_value % named.bucket_count != hashed.hash_value % named.bucket_count
        # A numeric name is unchanged by `hash_entry`, as upstream leaves it.
        number = next(e for e in named.entries if not e.is_string)
        assert named.hash_entry(number) is number


def test_string_bytes_is_the_raw_name_and_lookup_string_decodes_it() -> None:
    named = make_map(entries=nameid(0, 3, 0, string=True), strings=string_entry("Keywords"))
    assert named.string_bytes(0) == "Keywords".encode("utf-16-le")
    assert named.lookup_string(0) == "Keywords"
    with pytest.raises(TypeError):
        named.string_bytes("0")  # type: ignore[arg-type]


# --- limits --------------------------------------------------------------------------------


def test_counts_over_the_ceiling_are_limit_errors_not_format_errors() -> None:
    """`PstLimitError` before anything is allocated, and distinguishable from corruption."""
    entries = nameid(1, 3, 0) + nameid(2, 3, 1)
    tight = make_map(entries=entries, map_limits=Limits(max_items=1))
    with pytest.raises(PstLimitError):
        _ = tight.entries
    with pytest.raises(PstLimitError):
        _ = make_map(guids=TWO_GUIDS, map_limits=Limits(max_items=1)).guids
    assert len(make_map(entries=entries, map_limits=Limits(max_items=2)).entries) == 2


# --- argument types -------------------------------------------------------------------------


def test_the_public_methods_refuse_arguments_of_the_wrong_type() -> None:
    """A caller error is a `TypeError`; only the file's bytes are a `PstError`."""
    named = make_map()
    entry = named.entries[0]
    for call, arg in (
        (named.lookup, "0x8000"),
        (named.lookup_string, "0"),
        (named.guid_of, 0),
        (named.name_of, 0),
        (named.hash_bucket, 0),
    ):
        with pytest.raises(TypeError):
            call(arg)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        named.resolve("not a uuid", 1)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        named.resolve(GUID_A, 1.5)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        NamedPropertyMap(entry)  # type: ignore[arg-type]
    assert named.resolve(GUID_A, entry.name_id) == entry.prop_id


def test_a_property_context_that_is_not_a_map_refuses_every_stream() -> None:
    """The store PC of a real store is a perfectly good PC and a hopeless named property map."""
    with store_pc(FIXTURES / "Empty.pst") as pc:
        named = NamedPropertyMap(pc)
        for what in ("bucket_count", "guids", "entries"):
            with pytest.raises(PstFormatError, match="missing"):
                getattr(named, what)


# --- the corpus, byte for byte and value for value --------------------------------------------


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_dump_named_props_reproduces_read_named_props_byte_for_byte(store: Path, golden, golden_exit) -> None:
    """The whole claim of this row's second half: same bytes in, same characters out."""
    assert golden_exit(store, "read_named_props") == 0
    expected = golden(store, "read_named_props")
    out = io.StringIO()
    stdout, sys.stdout = sys.stdout, out
    try:
        debug.dump_named_props(store)
    finally:
        sys.stdout = stdout
    assert out.getvalue() == expected, f"{store.stem}: `debug named_props` differs from read_named_props"


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_named_properties_equal_the_golden_values(store: Path, golden) -> None:
    """The same goldens read as data: every prop id, GUID index, GUID, number and name."""
    expected = parse_read_named_props(golden(store, "read_named_props"))
    with Store.open(store) as opened:
        named = opened.named_properties
        assert [e.prop_id for e in named.entries] == [g["prop_id"] for g in expected], store.stem
        for entry, group in zip(named.entries, expected, strict=True):
            where = f"{store.stem} 0x{entry.prop_id:04X}"
            index = group["guid_index"]
            assert str(entry.guid) == ("None" if index is None else index if isinstance(index, str) else f"GuidIndex({index})"), where
            wanted_guid = group["guid"] if group["guid"] is not None else uuid.UUID(int=0)
            assert named.guid_of(entry) == wanted_guid, where
            assert named.name_of(entry) == (group["name"] if group["name"] is not None else group["number"]), where
            assert entry.is_string == (group["name"] is not None), where
            assert named.lookup(entry.prop_id) == NamedProperty(wanted_guid, named.name_of(entry)), where
        assert len(expected) >= 1, store.stem


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_the_module_agrees_with_p05_s_hand_rolled_reconstruction(store: Path) -> None:
    """Two independent readings of the same three streams must agree; P05's is the control."""
    with store_pc(store, __import__("pypst.ndb.ids", fromlist=["NodeId"]).NodeId(NID_NAME_TO_ID_MAP)) as pc:
        control = named_properties_from_pc(pc)
        named = NamedPropertyMap(pc)
        ours = [
            {
                "prop_id": e.prop_id,
                "guid_index": None if e.guid.raw == 0 else (e.guid.index if e.guid.is_index else str(e.guid)),
                "guid": None if e.guid.raw == 0 else named.guid_of(e),
                "number": None if e.is_string else e.name_id,
                "string_offset": e.name_id if e.is_string else None,
                "name": named.name_of(e) if e.is_string else None,
            }
            for e in named.entries
        ]
    assert ours == control, f"{store.stem}: {len(ours)} entries vs P05's {len(control)}"


def test_the_corpus_named_property_count_is_pinned() -> None:
    """964 named properties over the 8 Unicode stores — the number P05 measured, now read through this module."""
    total = 0
    for store in UNICODE_STORES:
        with Store.open(store) as opened:
            total += len(opened.named_properties)
    assert total == 964, f"the corpus now holds {total} named properties, not 964"


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_resolve_inverts_lookup_on_every_corpus_store(store: Path) -> None:
    """Round trip through the map: every id it holds resolves back to itself."""
    with Store.open(store) as opened:
        named = opened.named_properties
        for entry in named.entries:
            found = named.lookup(entry.prop_id)
            assert found is not None
            assert named.resolve(found.guid, found.name) == entry.prop_id, f"{store.stem} 0x{entry.prop_id:04X}"
        assert named.lookup(0x7FFF) is None and named.lookup(0xFFFF) is None
        assert named.resolve(uuid.UUID(int=0), "no such name") is None


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_every_entry_is_in_the_bucket_its_hash_names(store: Path) -> None:
    """[MS-PST] 2.4.7.5, on real stores: the hash table and the entry stream describe the same map.

    Upstream never checks this — `hash_bucket` is how it looks a property
    up — so it is worth pinning that the corpus agrees, and that a store
    with no hash buckets at all (the two EMLtoPST-written ones) says so as
    `PstNotFoundError` rather than pretending.
    """
    with Store.open(store) as opened:
        named = opened.named_properties
        missing = 0
        for entry in named.entries:
            try:
                bucket = named.hash_bucket(entry)
            except PstNotFoundError:
                missing += 1
                continue
            assert any(b.prop_id == entry.prop_id for b in bucket), f"{store.stem} 0x{entry.prop_id:04X}"
        has_buckets = any(prop_id >= PID_TAG_NAMEID_BUCKET_BASE for prop_id in named.properties.records)
        assert (missing == 0) if has_buckets else (missing == len(named.entries)), store.stem


# --- private stores: structure only ---------------------------------------------------------


@pytest.mark.private
def test_private_named_maps_read_structure_only(private_stores: list[Path]) -> None:
    """Counts, ids and booleans. A named property's NAME is content and is never asserted on."""
    if not private_stores:
        pytest.skip("no private stores present (this is a normal clean checkout)")
    for index, path in enumerate(private_stores):
        with Store.open(path) as store:
            named = store.named_properties
            assert named.bucket_count > 0, f"private store {index}: no hash buckets"
            ids = [e.prop_id for e in named.entries]
            assert len(ids) == len(set(ids)), f"private store {index}: a duplicate named property id"
            assert all(0x8000 <= i <= 0xFFFF for i in ids), f"private store {index}: an id outside the named range"
            for entry in named.entries:
                assert type(named.guid_of(entry)) is uuid.UUID, f"private store {index}"
                assert type(named.name_of(entry)) in (str, int), f"private store {index}"


@pytest.mark.private
@pytest.mark.oracle
def test_private_named_maps_match_the_prebuilt_oracle(private_stores: list[Path]) -> None:
    """Ids, GUID indices and the string/number split, from the oracle and from this port — never a name.

    Runs the already-built example binary; never `cargo`, so a box that has
    not built the oracle skips.
    """
    if not private_stores:
        pytest.skip("no private stores present (this is a normal clean checkout)")
    binary = ORACLE_BIN / "read_named_props"
    if not binary.exists():
        pytest.skip("reference/.../examples/read_named_props is not built — scripts/build_oracle.sh")
    checked = 0
    for index, path in enumerate(private_stores):
        result = subprocess.run([str(binary), str(path)], capture_output=True, text=True, timeout=300, check=False)
        if result.returncode != 0:
            continue
        expected = parse_read_named_props(result.stdout)
        with Store.open(path) as store:
            named = store.named_properties
            mine = [(e.prop_id, str(e.guid), e.is_string) for e in named.entries]
            theirs = [
                (
                    g["prop_id"],
                    "None" if g["guid_index"] is None else (g["guid_index"] if isinstance(g["guid_index"], str) else f"GuidIndex({g['guid_index']})"),
                    g["name"] is not None,
                )
                for g in expected
            ]
            assert mine == theirs, f"private store {index}: {len(mine)} named properties vs the oracle's {len(theirs)}"
            same_names = [named.name_of(e) for e in named.entries] == [
                g["name"] if g["name"] is not None else g["number"] for g in expected
            ]
            assert same_names, f"private store {index}: a name or number differs from the oracle's"
            same_guids = [named.guid_of(e) for e in named.entries] == [
                g["guid"] if g["guid"] is not None else uuid.UUID(int=0) for g in expected
            ]
            assert same_guids, f"private store {index}: a GUID differs from the oracle's"
        checked += 1
    if not checked:
        pytest.skip("the oracle refused every private store")


def test_nothing_but_pst_errors_escape_a_hand_built_map() -> None:
    """The family guard: every accessor over a deliberately broken map raises a `PstError` and nothing else."""
    broken = [
        make_map(bucket_count=None),
        make_map(guids=b"\x01"),
        make_map(entries=b"\x01"),
        make_map(entries=nameid(0xFFFFFFF0, 3, 0, string=True)),
        make_map(strings=b"\xff\xff\xff\xff"),
    ]
    for index, named in enumerate(broken):
        for probe in (
            lambda m: m.bucket_count,
            lambda m: m.guids,
            lambda m: m.entries,
            lambda m: [m.guid_of(e) for e in m.entries],
            lambda m: [m.name_of(e) for e in m.entries],
            lambda m: m.lookup(0x8000),
            lambda m: m.resolve(GUID_A, 1),
        ):
            try:
                probe(named)
            except PstError:
                pass
            except Exception as exc:  # classifying, not handling, is the point
                raise AssertionError(f"map {index}: {type(exc).__name__} escaped: {exc}") from exc
