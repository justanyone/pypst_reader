"""The mutation generator is itself under test.

A generator that quietly produced nothing, or the same bytes as the base,
or a "truncation" no shorter than the file, would make the whole
corruption sweep a comment with a slow runtime. So: deterministic for a
seed, every mutation differs from its base, names unique, truncations
strictly shorter, resealed flips carry valid CRCs, every family non-empty,
and the total count pinned per base so that a family silently vanishing
is a red test rather than a smaller number nobody reads.
"""

from __future__ import annotations

import io
import struct
from collections import Counter
from pathlib import Path

import pytest

from pypst.crc import compute_crc
from pypst.errors import PstError, PstFormatError, PstLimitError
from pypst.limits import DEFAULT_LIMITS
from pypst.ndb.btree import BlockBTree, NodeBTree
from pypst.ndb.header import HEADER_SIZE, Header
from pypst.ndb.ids import ByteIndex, PageId, PageRef
from pypst.ndb.page import BTreePage, PageType
from tests import corrupt
from tests.conftest import FIXTURES, PUBLIC

SEED = 20260915
BASES = [PUBLIC / "pstd-inline-cid.pst", FIXTURES / "Empty.pst"]
BASE_IDS = [p.stem for p in BASES]

# Pinned totals per base and family. A change here is a deliberate change
# to the generator, made in the same commit that explains it.
PC_LIES_INLINE_CID = 13  # pstd-inline-cid's store PC has no PtypBoolean record
PC_LIES_EMPTY = 14
# Every tc_lies mutation is unconditional over both bases; pstd-inline-cid's
# own root hierarchy table is unreadable (see `corrupt._tc_opens`), so its 25
# carry no `expect` and no `must_raise`.
TC_LIES = 25

PINNED = {
    "pstd-inline-cid": {
        "truncations": 61,
        "bit_flips": 72,
        "field_lies": 230,
        "pointer_cycles": 6,
        "depth_bombs": 3,
        "future_versions": 17,
        "zero_files": 6,
        "magic_only": 3,
        "heap_lies": 22,
        "pc_lies": PC_LIES_INLINE_CID,
        "tc_lies": TC_LIES,
        "store_lies": 9,
        "named_prop_lies": 12,
    },
    "Empty": {
        "truncations": 62,
        "bit_flips": 96,
        "field_lies": 279,
        "pointer_cycles": 6,
        "depth_bombs": 3,
        "future_versions": 17,
        "zero_files": 6,
        "magic_only": 3,
        "heap_lies": 22,
        "pc_lies": PC_LIES_EMPTY,
        "tc_lies": TC_LIES,
        "store_lies": 11,
        "named_prop_lies": 16,
    },
}

_CACHE: dict[Path, tuple[bytes, list[corrupt.Mutation]]] = {}


def _all(path: Path) -> tuple[bytes, list[corrupt.Mutation]]:
    if path not in _CACHE:
        base = path.read_bytes()
        _CACHE[path] = (base, list(corrupt.mutations(base, seed=SEED)))
    return _CACHE[path]


def _family(name: str) -> corrupt.Family:
    return next(f for f in corrupt.FAMILIES if f.__name__ == name)


# --- the stream as a whole -------------------------------------------------------------


@pytest.mark.parametrize("path", BASES, ids=BASE_IDS)
def test_deterministic_for_a_seed(path: Path) -> None:
    base, first = _all(path)
    second = list(corrupt.mutations(base, seed=SEED))
    assert [(m.name, m.data, m.expect) for m in first] == [(m.name, m.data, m.expect) for m in second]


def test_another_seed_moves_the_random_families_and_only_those() -> None:
    base = BASES[0].read_bytes()
    a = {m.name: m.data for m in corrupt.mutations(base, seed=1)}
    b = {m.name: m.data for m in corrupt.mutations(base, seed=2)}
    # bit_flips names carry the offset, so a different seed gives different names.
    assert {n for n in a if n.startswith("bit_flips:")} != {n for n in b if n.startswith("bit_flips:")}
    # The deterministic families are identical byte for byte.
    for family in ("truncations", "field_lies", "pointer_cycles", "depth_bombs", "zero_files", "magic_only", "heap_lies", "pc_lies"):
        assert {n: d for n, d in a.items() if n.startswith(family)} == {n: d for n, d in b.items() if n.startswith(family)}


def test_family_rng_is_independent_of_family_order() -> None:
    """A family draws from its own stream: adding a mutation elsewhere cannot move its output."""
    base = BASES[0].read_bytes()
    alone = list(corrupt.bit_flips(base, corrupt.family_rng(SEED, corrupt.bit_flips)))
    within = [m for m in corrupt.mutations(base, seed=SEED) if m.name.startswith("bit_flips:")]
    assert [(m.name, m.data) for m in alone] == [(m.name, m.data) for m in within]


@pytest.mark.parametrize("path", BASES, ids=BASE_IDS)
def test_every_mutation_differs_from_the_base(path: Path) -> None:
    base, ms = _all(path)
    same = [m.name for m in ms if m.data == base]
    assert not same, f"identical to the base: {same}"


@pytest.mark.parametrize("path", BASES, ids=BASE_IDS)
def test_names_are_unique_and_prefixed_by_family(path: Path) -> None:
    _, ms = _all(path)
    names = [m.name for m in ms]
    dups = [n for n, c in Counter(names).items() if c > 1]
    assert not dups, dups
    families = set(corrupt.family_names())
    assert all(n.split(":", 1)[0] in families for n in names)


@pytest.mark.parametrize("path", BASES, ids=BASE_IDS)
def test_expectations_are_pst_error_classes(path: Path) -> None:
    _, ms = _all(path)
    for m in ms:
        if m.expect is None:
            continue
        kinds = (m.expect,) if isinstance(m.expect, type) else m.expect
        assert all(issubclass(k, PstError) for k in kinds), m.name


@pytest.mark.parametrize("path", BASES, ids=BASE_IDS)
def test_counts_are_pinned(path: Path) -> None:
    _, ms = _all(path)
    counts = Counter(m.name.split(":", 1)[0] for m in ms)
    assert dict(counts) == PINNED[path.stem]
    assert all(counts[f] > 0 for f in corrupt.family_names())


# --- per family ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", BASES, ids=BASE_IDS)
def test_truncations_are_strictly_shorter_and_prefixes(path: Path) -> None:
    base, ms = _all(path)
    ts = [m for m in ms if m.name.startswith("truncations:")]
    assert all(len(m.data) < len(base) and base.startswith(m.data) for m in ts)
    lengths = [len(m.data) for m in ts]
    assert lengths == sorted(lengths)
    # The header boundaries, the first pages, the roots and the final page are all represented.
    assert {0, 4, 8, 10, corrupt.ROOT_OFFSET, corrupt.HEADER_SIZE - 1, 512, 1024} <= set(lengths)
    (_, nbt), (_, bbt) = corrupt.root_refs(base)
    assert {nbt, nbt + 1, bbt + 511} <= set(lengths)
    last = (len(base) - 1) // 512 * 512
    assert {last + 64 * k for k in range(8) if last + 64 * k < len(base)} <= set(lengths)


def _header_crcs_valid(data: bytes) -> bool:
    partial = compute_crc(0, data[corrupt.CRC_START : corrupt.CRC_PARTIAL_END])
    full = compute_crc(0, data[corrupt.CRC_START : corrupt.CRC_FULL_END])
    return struct.unpack_from("<I", data, corrupt.CRC_PARTIAL_OFFSET)[0] == partial and (
        struct.unpack_from("<I", data, corrupt.CRC_FULL_OFFSET)[0] == full
    )


def _page_crc_valid(data: bytes, offset: int) -> bool:
    crc = compute_crc(0, data[offset : offset + corrupt.PAGE_DATA_SIZE])
    return struct.unpack_from("<I", data, offset + corrupt.PAGE_TRAILER_OFFSET + 4)[0] == crc


@pytest.mark.parametrize("path", BASES, ids=BASE_IDS)
def test_bit_flips_flip_exactly_one_bit_and_reseal_when_they_say_so(path: Path) -> None:
    base, ms = _all(path)
    pages = dict(corrupt.interesting_pages(base))
    for m in (m for m in ms if m.name.startswith("bit_flips:")):
        _, what, kind, where = m.name.split(":")
        offset, bit = where.split("b")
        offset, bit = int(offset, 16), int(bit)
        assert len(m.data) == len(base)
        assert m.data[offset] == base[offset] ^ (1 << bit), m.name
        if kind == "raw":
            assert m.data[:offset] == base[:offset] and m.data[offset + 1 :] == base[offset + 1 :], m.name
            assert m.expect is PstFormatError
        else:
            assert m.expect is None
            if what == "header":
                assert _header_crcs_valid(m.data), m.name
            else:
                assert _page_crc_valid(m.data, pages[what]), m.name


@pytest.mark.parametrize("path", BASES, ids=BASE_IDS)
def test_bit_flips_cover_every_region_both_ways(path: Path) -> None:
    _, ms = _all(path)
    seen = Counter(tuple(m.name.split(":")[1:3]) for m in ms if m.name.startswith("bit_flips:"))
    regions = ["header", "nbt_root", "bbt_root"]
    if path.stem == "Empty":
        regions.append("nbt_leaf")
    for region in regions:
        assert seen[(region, "raw")] == corrupt.FLIPS_PER_REGION
        assert seen[(region, "resealed")] == corrupt.FLIPS_PER_REGION


def test_field_lies_cover_every_header_and_root_field() -> None:
    _, ms = _all(BASES[0])
    lied = {m.name.split(":")[1].split("=")[0] for m in ms if m.name.startswith("field_lies:header.")}
    expected = {f"header.{f.name}" for f in corrupt.header_fields()}
    assert lied == expected
    assert {"header.wVer", "header.bCryptMethod", "header.BREFNBT.ib", "header.ibFileEof", "header.bidNextB"} <= lied
    assert "header.dwCRCPartial" not in lied and "header.dwCRCFull" not in lied


def test_field_lies_are_resealed_and_value_classes_are_right() -> None:
    base, ms = _all(BASES[0])
    fields = {f.name: f for f in corrupt.header_fields()}
    for m in (m for m in ms if m.name.startswith("field_lies:header.")):
        name, label = m.name.split(":")[1].removeprefix("header.").split("=")
        field = fields[name]
        value = field.read(m.data)
        assert _header_crcs_valid(m.data), m.name
        assert value != field.read(base), m.name
        assert {"0": 0, "1": 1, "max": field.max, "max-1": field.max - 1, "past_eof": min(len(base) + 512, field.max)}[label] == value


def test_header_fields_agree_with_the_hand_typed_offsets() -> None:
    """The formats come from the modules, the offsets in corrupt.py are typed by hand: they must meet."""
    by_name = {f.name: f for f in corrupt.header_fields()}
    assert by_name["dwMagic"].offset == corrupt.MAGIC_OFFSET
    assert by_name["wMagicClient"].offset == corrupt.MAGIC_CLIENT_OFFSET
    assert by_name["wVer"].offset == corrupt.VERSION_OFFSET
    assert by_name["wVerClient"].offset == corrupt.CLIENT_VERSION_OFFSET
    assert by_name["bPlatformCreate"].offset == corrupt.PLATFORM_CREATE_OFFSET
    assert by_name["bPlatformAccess"].offset == corrupt.PLATFORM_ACCESS_OFFSET
    assert by_name["dwReserved"].offset == corrupt.ROOT_OFFSET
    assert by_name["fAMapValid"].offset == corrupt.AMAP_VALID_OFFSET
    assert by_name["dwAlign"].offset == corrupt.ALIGN_OFFSET
    assert by_name["bSentinel"].offset == corrupt.SENTINEL_OFFSET
    assert by_name["bCryptMethod"].offset == corrupt.CRYPT_METHOD_OFFSET
    assert by_name["rgbReserved"].offset == corrupt.RESERVED_OFFSET
    assert by_name["bidNextB"].offset + 8 == corrupt.CRC_FULL_OFFSET
    assert HEADER_SIZE == corrupt.HEADER_SIZE


def test_struct_fields_walks_repeats_and_skips_byte_strings() -> None:
    fields = corrupt.struct_fields("<I2H4sQ", ["a", "b", "c", "s", "d"], 100)
    assert [(f.name, f.offset, f.size) for f in fields] == [("a", 100, 4), ("b", 104, 2), ("c", 106, 2), ("d", 112, 8)]
    with pytest.raises(ValueError):
        corrupt.struct_fields("<I", ["a", "b"])
    with pytest.raises(ValueError):
        corrupt.struct_fields(">I", ["a"])


def test_page_fields_follow_the_page_kind() -> None:
    base = BASES[1].read_bytes()  # Empty.pst: intermediate roots, a separate leaf
    pages = dict(corrupt.interesting_pages(base))
    root_names = {f.name for f in corrupt.page_fields(base, pages["nbt_root"])}
    assert "entry0.btkey" in root_names and "entry0.nid" not in root_names
    leaf_names = {f.name for f in corrupt.page_fields(base, pages["nbt_leaf"])}
    assert "entry0.nid" in leaf_names and "entry0.bidSub" in leaf_names
    assert "dwCRC" not in root_names
    assert {"cEnt", "cEntMax", "cbEnt", "cLevel", "dwPadding", "ptype", "ptypeRepeat", "wSig", "bid"} <= root_names


@pytest.mark.parametrize("path", BASES, ids=BASE_IDS)
def test_pointer_cycles_and_depth_bombs_expect_limit_errors(path: Path) -> None:
    _, ms = _all(path)
    for m in ms:
        if m.name.startswith("depth_bombs:") or m.name.endswith(("_to_itself", "two_page_cycle", "intermediate_back_to_root")):
            assert m.expect is PstLimitError, m.name


def test_depth_bomb_chain_is_sound_at_the_ceiling() -> None:
    """The builder's chain is walkable at the depth ceiling — so one deeper fails for depth, not for a broken page."""
    depth = DEFAULT_LIMITS.max_btree_depth
    pages, (root_id, root_offset) = corrupt.btree_chain(depth, start=0x1000)
    tree = NodeBTree(io.BytesIO(corrupt.file_with_pages(pages)), PageRef(PageId(root_id), ByteIndex(root_offset)))
    assert [e.key for e in tree] == [0x21]
    assert tree.find(0x21).key == 0x21
    deeper, (root_id, root_offset) = corrupt.btree_chain(depth + 1, start=0x1000)
    tree = NodeBTree(io.BytesIO(corrupt.file_with_pages(deeper)), PageRef(PageId(root_id), ByteIndex(root_offset)))
    with pytest.raises(PstLimitError):
        list(tree)


def test_depth_bombs_keep_the_base_intact_below_the_appended_pages() -> None:
    base, ms = _all(BASES[0])
    bombs = [m for m in ms if m.name.startswith("depth_bombs:")]
    (_, nbt), _ = corrupt.root_refs(base)
    for m in bombs:
        assert len(m.data) > len(base)
        assert m.data[:nbt] == base[:nbt]
        # The appended pages are sealed pages that parse on their own.
        start = (len(base) + 511) // 512 * 512
        page = BTreePage.parse(m.data[start : start + 512], PageType.NBT, ByteIndex(start))
        assert page.level == 1


def test_future_versions_name_the_values_and_types() -> None:
    _, ms = _all(BASES[0])
    versions = {m.name: m for m in ms if m.name.startswith("future_versions:wVer=")}
    assert set(versions) == {f"future_versions:wVer={v}" for v in corrupt.FUTURE_VERSIONS}
    for m in versions.values():
        assert struct.unpack_from("<H", m.data, corrupt.VERSION_OFFSET)[0] == int(m.name.split("=")[1])
        assert _header_crcs_valid(m.data)
    methods = [m for m in ms if m.name.startswith("future_versions:bCryptMethod=")]
    assert len(methods) == 1 + corrupt.CRYPT_SAMPLES
    edp = next(m for m in methods if m.name.endswith("0x10"))
    assert edp.expect.__name__ == "PstUnsupportedError"
    assert all(m.expect is PstFormatError for m in methods if m is not edp)
    assert all(3 <= m.data[corrupt.CRYPT_METHOD_OFFSET] <= 0xFF for m in methods)


def test_zero_and_magic_files_have_the_named_lengths() -> None:
    _, ms = _all(BASES[0])
    lengths = {m.name: len(m.data) for m in ms if m.name.startswith(("zero_files:", "magic_only:"))}
    assert lengths == {
        "zero_files:zeros_0": 0,
        "zero_files:zeros_1": 1,
        "zero_files:zeros_512": 512,
        "zero_files:zeros_563": 563,
        "zero_files:zeros_564": 564,
        "zero_files:ff_header_and_page": 564 + 512,
        "magic_only:nothing": 4,
        "magic_only:zeros_to_header": 564,
        "magic_only:zeros_to_page_past_header": 564 + 512,
    }
    magic = [m for m in ms if m.name.startswith("magic_only:")]
    assert all(m.data.startswith(b"!BDN") for m in magic)
    with pytest.raises(PstFormatError):
        Header.parse(magic[0].data)


# --- the API around the stream ------------------------------------------------------


def test_mutation_by_name_round_trips_and_misses_are_key_errors() -> None:
    base, ms = _all(BASES[0])
    target = ms[100]
    found = corrupt.mutation(base, seed=SEED, name=target.name)
    assert (found.name, found.data, found.expect) == (target.name, target.data, target.expect)
    with pytest.raises(KeyError):
        corrupt.mutation(base, seed=SEED, name="no_such_family:nothing")


@pytest.mark.parametrize("stem", ["pstsdk-test_ansi", "pstsdk-sample2"])
def test_an_ansi_base_is_refused(stem: str) -> None:
    with pytest.raises(ValueError, match="wVer"):
        next(corrupt.mutations((PUBLIC / f"{stem}.pst").read_bytes(), seed=SEED))


def test_a_non_pst_base_is_refused() -> None:
    with pytest.raises(ValueError):
        next(corrupt.mutations(b"not a pst" * 100, seed=SEED))
    with pytest.raises(ValueError):
        next(corrupt.mutations(b"", seed=SEED))


def test_families_are_named_and_ordered() -> None:
    assert corrupt.family_names() == [
        "truncations",
        "bit_flips",
        "field_lies",
        "pointer_cycles",
        "depth_bombs",
        "future_versions",
        "zero_files",
        "magic_only",
        "heap_lies",
        "pc_lies",
        "tc_lies",
        "store_lies",
        "named_prop_lies",
    ]


def test_mutation_is_frozen() -> None:
    m = corrupt.Mutation("x:y", b"\0")
    with pytest.raises(AttributeError):
        m.name = "z"  # type: ignore[misc]
    assert m.expect is None


def test_append_pages_refuses_an_offset_inside_the_base() -> None:
    with pytest.raises(ValueError):
        corrupt.append_pages(bytes(1024), {512: bytes(512)})
    out = corrupt.append_pages(bytes(1000), {1536: b"\xaa" * 512})
    assert len(out) == 2048 and out[1536:] == b"\xaa" * 512 and out[1000:1536] == bytes(536)


def test_replace_page_requires_a_whole_page() -> None:
    with pytest.raises(ValueError):
        corrupt.replace_page(bytes(1024), 0, bytes(100))


# --- what the base looks like to the generator, and which mutations demand a refusal ----


@pytest.mark.parametrize("path", BASES, ids=BASE_IDS)
def test_tree_pages_counts_what_the_reader_walks(path: Path) -> None:
    base = path.read_bytes()
    (nbt_id, nbt), (bbt_id, bbt) = corrupt.root_refs(base)
    f = io.BytesIO(base)
    assert len(corrupt.tree_pages(base, nbt)) == len(list(NodeBTree(f, PageRef(PageId(nbt_id), ByteIndex(nbt))).pages()))
    assert len(corrupt.tree_pages(base, bbt)) == len(list(BlockBTree(f, PageRef(PageId(bbt_id), ByteIndex(bbt))).pages()))
    assert corrupt.tree_pages(base, nbt)[0] == nbt


def test_pages_read_includes_the_density_list_only_when_present() -> None:
    empty = BASES[1].read_bytes()
    assert corrupt.DENSITY_LIST_OFFSET in corrupt.pages_read(empty)
    pstd = BASES[0].read_bytes()
    assert corrupt.DENSITY_LIST_OFFSET not in corrupt.pages_read(pstd)
    assert len(corrupt.pages_read(empty)) == 5 + 3 + 1


@pytest.mark.parametrize("path", BASES, ids=BASE_IDS)
def test_must_raise_is_set_where_a_refusal_is_certain(path: Path) -> None:
    base, ms = _all(path)
    by_family: dict[str, list[corrupt.Mutation]] = {}
    for m in ms:
        by_family.setdefault(m.name.split(":", 1)[0], []).append(m)
    for family in ("pointer_cycles", "depth_bombs", "future_versions", "zero_files", "magic_only"):
        assert all(m.must_raise for m in by_family[family]), family
    assert not any(m.must_raise for m in by_family["bit_flips"])
    (_, nbt), _ = corrupt.root_refs(base)
    for m in by_family["truncations"]:
        if len(m.data) < nbt + 512:
            assert m.must_raise, m.name
    last = max(by_family["truncations"], key=lambda m: len(m.data))
    assert last.must_raise == (len(last.data) < max(p + 512 for p in corrupt.pages_read(base)))
    lies = {m.name: m.must_raise for m in by_family["field_lies"]}
    assert lies["field_lies:header.wVer=0"] and lies["field_lies:header.BREFNBT.ib=max"]
    assert lies["field_lies:nbt_root.ptype=0"] and lies["field_lies:nbt_root.dwPadding=1"]
    assert not lies["field_lies:header.bidNextB=0"] and not lies["field_lies:nbt_root.bid=0"]
    assert lies["field_lies:header.bCryptMethod=max"]
    # 0 and 1 are real methods; whichever the base does not use is a lie that must NOT demand a refusal.
    assert not any(lies.get(f"field_lies:header.bCryptMethod={v}", False) for v in (0, 1))
