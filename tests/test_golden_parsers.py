"""The golden parsers are themselves under test.

A parser that accepts a truncated golden turns a corrupted file into a green
differential test, so every parser here is shown to refuse bad input before
it is trusted to read good input. The read_header parser is exercised over
all nine committed goldens (Empty.pst plus the public corpus); read_btrees
and read_density_list over the seven Unicode ones (P02); the property-value
grammar and the four PC/TC examples over every Unicode golden (P05); the two
remaining stubs are checked to raise NotImplementedError with a non-empty
description.
"""

from __future__ import annotations

import math
import uuid
from pathlib import Path

import pytest

from tests.conftest import FIXTURES, GOLDEN, public_fixture_ids, public_fixture_paths
from tests.golden_parsers import (
    PARSERS,
    READ_DENSITY_LIST_LABELS,
    READ_HEADER_LABELS,
    dump_messages_folder_lines,
    parse_block_id,
    parse_block_ref,
    parse_byte_index,
    parse_dump_messages,
    parse_node_id,
    parse_page_id,
    parse_page_ref,
    parse_read_btrees,
    parse_read_density_list,
    parse_read_header,
    parse_read_ipm_subtree,
    parse_read_named_props,
    parse_read_root_folder,
    parse_read_store_props,
    parse_record,
    parse_value,
)

ALL_STORES = [FIXTURES / "Empty.pst", *public_fixture_paths()]
EXAMPLE_DUMP = "dump_messages"
ALL_IDS = ["Empty", *public_fixture_ids()]

ANSI_STORES = {"pstsdk-sample2", "pstsdk-test_ansi"}

HEADER_KEYS = {
    "version",
    "next_block",
    "next_page",
    "file_eof_index",
    "amap_last_index",
    "amap_free_size",
    "pmap_free_size",
    "node_btree",
    "block_btree",
    "amap_is_valid",
}


# --- read_header over the corpus --------------------------------------------


@pytest.mark.parametrize("store", ALL_STORES, ids=ALL_IDS)
def test_read_header_golden_parses(store: Path, golden, golden_exit) -> None:
    assert golden_exit(store, "read_header") == 0, f"{store.stem}: read_header golden is a refusal"
    header = parse_read_header(golden(store, "read_header"))

    assert set(header) == HEADER_KEYS, f"{store.stem}: key set differs"
    assert header["version"] in ("Unicode", "Ansi"), store.stem
    assert isinstance(header["next_block"]["internal"], bool), store.stem
    for key in ("next_page", "file_eof_index", "amap_last_index", "amap_free_size", "pmap_free_size"):
        assert isinstance(header[key], int) and not isinstance(header[key], bool), f"{store.stem}: {key}"
    for key in ("node_btree", "block_btree"):
        assert set(header[key]) == {"page", "index"}, f"{store.stem}: {key}"
    assert header["amap_is_valid"].startswith("Valid") or header["amap_is_valid"] == "Invalid", store.stem


@pytest.mark.parametrize("store", ALL_STORES, ids=ALL_IDS)
def test_read_header_version_matches_corpus_split(store: Path, golden) -> None:
    header = parse_read_header(golden(store, "read_header"))
    expected = "Ansi" if store.stem in ANSI_STORES else "Unicode"
    assert header["version"] == expected, f"{store.stem}: version"


def test_read_header_empty_pst_spot_values(empty_pst: Path, golden) -> None:
    header = parse_read_header(golden(empty_pst, "read_header"))
    assert header["version"] == "Unicode"
    assert header["next_block"] == {"internal": False, "index": 0x4C}
    assert header["next_page"] == 0x17F
    assert header["file_eof_index"] == 0x42400
    assert header["amap_last_index"] == 0x4400
    assert header["amap_free_size"] == 0x3AD40
    assert header["pmap_free_size"] == 0
    assert header["node_btree"] == {"page": 0x17D, "index": 0x9200}
    assert header["block_btree"] == {"page": 0x17B, "index": 0x8400}
    assert header["amap_is_valid"] == "Valid2"


def test_read_header_ansi_prefix_is_stripped(golden) -> None:
    """An ANSI golden parses to the same shape as a Unicode one, prefix gone."""
    header = parse_read_header(golden(FIXTURES / "public" / "pstsdk-test_ansi.pst", "read_header"))
    assert header["version"] == "Ansi"
    assert header["next_page"] == 0x101
    assert header["node_btree"] == {"page": 0xFE, "index": 0x4E00}


def test_read_header_accepts_pypst_form_without_prefix() -> None:
    """The same parser must read what pypst.debug prints (INTERFACES § ids: no prefix)."""
    text = (
        "File Version: Unicode\n"
        "Next Block: BlockId { leaf: 0x4C }\n"
        "Next Page: PageId: 0x17F\n"
        "File EOF Index: ByteIndex { 0x42400 }\n"
        "AMAP Last Index: ByteIndex { 0x4400 }\n"
        "AMAP Free Size: ByteIndex { 0x3AD40 }\n"
        "PMAP Free Size: ByteIndex { 0x0 }\n"
        "NBT BlockRef: PageRef { page: PageId: 0x17D, index: ByteIndex { 0x9200 } }\n"
        "BBT BlockRef: PageRef { page: PageId: 0x17B, index: ByteIndex { 0x8400 } }\n"
        "AMAP Valid: Valid2\n"
    )
    assert parse_read_header(text)["node_btree"] == {"page": 0x17D, "index": 0x9200}


# --- read_header denial ------------------------------------------------------


def _empty_header_text() -> str:
    return (GOLDEN / "Empty" / "read_header.txt").read_text()


@pytest.mark.parametrize("keep", range(len(READ_HEADER_LABELS)))
def test_read_header_rejects_truncation_at_every_line(keep: int) -> None:
    lines = _empty_header_text().splitlines()
    truncated = "\n".join(lines[:keep]) + "\n"
    with pytest.raises(ValueError, match=rf"line {keep + 1}:"):
        parse_read_header(truncated)


def test_read_header_rejects_empty_input() -> None:
    with pytest.raises(ValueError, match="line 1:"):
        parse_read_header("")


def test_read_header_rejects_trailing_junk() -> None:
    with pytest.raises(ValueError, match="line 11:"):
        parse_read_header(_empty_header_text() + "Extra: 1\n")


def test_read_header_rejects_swapped_lines() -> None:
    lines = _empty_header_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    with pytest.raises(ValueError, match="line 2:"):
        parse_read_header("\n".join(lines) + "\n")


@pytest.mark.parametrize(
    ("line_no", "bad"),
    [
        (1, "File Version: Unicode16"),
        (2, "Next Block: UnicodeBlockId { leaf: 4C }"),
        (3, "Next Page: UnicodeByteIndex { 0x17F }"),
        (4, "File EOF Index: UnicodeByteIndex { 0x42400"),
        (8, "NBT BlockRef: UnicodePageRef { page: UnicodePageId: 0x17D }"),
        (10, "AMAP Valid: Valid3"),
    ],
)
def test_read_header_rejects_garbled_value(line_no: int, bad: str) -> None:
    lines = _empty_header_text().splitlines()
    lines[line_no - 1] = bad
    with pytest.raises(ValueError, match=rf"line {line_no}:"):
        parse_read_header("\n".join(lines) + "\n")


# --- shared value parsers -----------------------------------------------------


def test_parse_block_id() -> None:
    assert parse_block_id("UnicodeBlockId { leaf: 0x4C }") == {"internal": False, "index": 0x4C}
    assert parse_block_id("AnsiBlockId { internal: 0x1A2 }") == {"internal": True, "index": 0x1A2}
    assert parse_block_id("BlockId { leaf: 0x0 }") == {"internal": False, "index": 0}


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "UnicodeBlockId { leaf: 4C }",
        "UnicodeBlockId { root: 0x4C }",
        "UnicodePageId: 0x4C",
        "UnicodeBlockId { leaf: 0x4C } trailing",
        "UnicodeBlockId { leaf: 0xZZ }",
    ],
)
def test_parse_block_id_rejects(bad: str) -> None:
    with pytest.raises(ValueError, match="BlockId"):
        parse_block_id(bad)


def test_parse_page_id() -> None:
    assert parse_page_id("UnicodePageId: 0x17F") == 0x17F
    assert parse_page_id("AnsiPageId: 0x3EB") == 0x3EB
    assert parse_page_id("PageId: 0x0") == 0


@pytest.mark.parametrize("bad", ["", "UnicodePageId: 17F", "UnicodeBlockId { leaf: 0x1 }", "UnicodePageId: 0x17F }"])
def test_parse_page_id_rejects(bad: str) -> None:
    with pytest.raises(ValueError, match="PageId"):
        parse_page_id(bad)


def test_parse_byte_index() -> None:
    assert parse_byte_index("UnicodeByteIndex { 0x42400 }") == 0x42400
    assert parse_byte_index("AnsiByteIndex { 0x0 }") == 0
    assert parse_byte_index("ByteIndex { 0x9200 }") == 0x9200


@pytest.mark.parametrize("bad", ["", "UnicodeByteIndex { 42400 }", "UnicodeByteIndex 0x42400", "UnicodePageId: 0x1"])
def test_parse_byte_index_rejects(bad: str) -> None:
    with pytest.raises(ValueError, match="ByteIndex"):
        parse_byte_index(bad)


def test_parse_node_id() -> None:
    assert parse_node_id("NodeId { NormalFolder: 0x404 }") == {"type": "NormalFolder", "index": 0x404}
    assert parse_node_id("NodeId { Internal: 0x1 }") == {"type": "Internal", "index": 1}


@pytest.mark.parametrize(
    "bad",
    ["", "NodeId { 0x404 }", "NodeId { Normal Folder: 0x404 }", "NodeId { NormalFolder: 404 }", "UnicodeNodeId { NormalFolder: 0x1 }"],
)
def test_parse_node_id_rejects(bad: str) -> None:
    with pytest.raises(ValueError, match="NodeId"):
        parse_node_id(bad)


def test_parse_block_ref() -> None:
    text = "UnicodeBlockRef { block: UnicodeBlockId { leaf: 0x1 }, index: UnicodeByteIndex { 0x4C00 } }"
    assert parse_block_ref(text) == {"block": {"internal": False, "index": 1}, "index": 0x4C00}
    bare = "BlockRef { block: BlockId { internal: 0x2 }, index: ByteIndex { 0x10 } }"
    assert parse_block_ref(bare) == {"block": {"internal": True, "index": 2}, "index": 0x10}


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "UnicodeBlockRef { block: UnicodePageId: 0x1, index: UnicodeByteIndex { 0x4C00 } }",
        "UnicodeBlockRef { block: UnicodeBlockId { leaf: 0x1 }, index: UnicodeByteIndex { 4C00 } }",
        "UnicodeBlockRef { block: UnicodeBlockId { leaf: 0x1 } }",
        "UnicodePageRef { page: UnicodePageId: 0x1, index: UnicodeByteIndex { 0x10 } }",
    ],
)
def test_parse_block_ref_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_block_ref(bad)


def test_parse_page_ref() -> None:
    text = "UnicodePageRef { page: UnicodePageId: 0x17D, index: UnicodeByteIndex { 0x9200 } }"
    assert parse_page_ref(text) == {"page": 0x17D, "index": 0x9200}
    assert parse_page_ref("AnsiPageRef { page: AnsiPageId: 0xFE, index: AnsiByteIndex { 0x4E00 } }") == {
        "page": 0xFE,
        "index": 0x4E00,
    }


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "UnicodePageRef { page: UnicodeBlockId { leaf: 0x1 }, index: UnicodeByteIndex { 0x10 } }",
        "UnicodePageRef { page: UnicodePageId: 0x17D, index: UnicodePageId: 0x9200 }",
        "UnicodePageRef { page: UnicodePageId: 0x17D }",
        "UnicodeBlockRef { block: UnicodeBlockId { leaf: 0x1 }, index: UnicodeByteIndex { 0x10 } }",
    ],
)
def test_parse_page_ref_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_page_ref(bad)


# --- the registry and the stubs -----------------------------------------------


def test_registry_covers_every_captured_example() -> None:
    manifest = (GOLDEN / "MANIFEST.txt").read_text()
    line = next(ln for ln in manifest.splitlines() if ln.startswith("EXAMPLES="))
    assert set(PARSERS) == set(line.removeprefix("EXAMPLES=").split(","))


COMPLETE = {
    "read_header",
    "read_btrees",
    "read_density_list",
    "read_store_props",
    "read_named_props",
    "read_root_folder",
    "read_ipm_subtree",
    "dump_messages",
}


@pytest.mark.parametrize("example", sorted(set(PARSERS) - COMPLETE))
def test_stub_parsers_describe_their_shape(example: str, empty_pst: Path, golden) -> None:
    with pytest.raises(NotImplementedError) as info:
        PARSERS[example](golden(empty_pst, example))
    assert example in str(info.value)
    assert len(str(info.value)) > 80, "a stub must describe the golden's shape, not just refuse"


# --- read_btrees (P02) --------------------------------------------------------------

UNICODE_STORES = [p for p in ALL_STORES if p.stem not in ANSI_STORES]
UNICODE_IDS = [p.stem for p in UNICODE_STORES]


def _count_leaves(page: dict) -> int:
    if "entries" in page:
        return len(page["entries"])
    return sum(_count_leaves(c["page"]) for c in page["children"])


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_read_btrees_golden_parses(store: Path, golden, golden_exit) -> None:
    assert golden_exit(store, "read_btrees") == 0
    parsed = parse_read_btrees(golden(store, "read_btrees"))
    assert set(parsed) == {"block_btree", "node_btree"}
    for tree in parsed.values():
        assert tree["level"] >= 0 and ("children" in tree or "entries" in tree), store.stem
        assert _count_leaves(tree) > 0, store.stem
    # Every block entry has the three fields; every node entry the four.
    for e in _leaves(parsed["block_btree"]):
        assert set(e) == {"block", "size", "ref_count"} and set(e["block"]) == {"block", "index"}
    for e in _leaves(parsed["node_btree"]):
        assert set(e) == {"node", "data", "sub_node", "parent"}
        assert set(e["node"]) == {"type", "index"}


def _leaves(page: dict) -> list[dict]:
    if "entries" in page:
        return list(page["entries"])
    return [e for c in page["children"] for e in _leaves(c["page"])]


def test_read_btrees_empty_pst_spot_values(empty_pst: Path, golden) -> None:
    parsed = parse_read_btrees(golden(empty_pst, "read_btrees"))
    bbt = parsed["block_btree"]
    assert bbt["level"] == 1 and [c["key"] for c in bbt["children"]] == [4, 128]
    first = bbt["children"][0]["page"]
    assert first["level"] == 0 and len(first["entries"]) == 14
    assert first["entries"][0] == {"block": {"block": {"internal": False, "index": 1}, "index": 0x4C00}, "size": 156, "ref_count": 4}
    nbt = parsed["node_btree"]
    assert nbt["level"] == 1 and nbt["children"][0]["key"] == {"type": "Internal", "index": 1}
    entries = nbt["children"][0]["page"]["entries"]
    assert entries[0] == {
        "node": {"type": "Internal", "index": 1},
        "data": {"block": {"internal": False, "index": 0x42}, "size": 0x126},
        "sub_node": None,
        "parent": None,
    }
    assert entries[2]["parent"] == {"type": "NormalFolder", "index": 9}
    assert entries[6]["data"] == {"block": {"internal": False, "index": 0}}  # an empty node: no Size line
    assert _leaves(nbt)[17]["node"] == {"type": "invalid", "index": 0x6B6}


def test_read_btrees_parses_sub_node_and_data_trees(golden) -> None:
    """pstsdk-submessage carries sub-node trees; pstsdk-sample1 an XBLOCK data tree."""
    sub = parse_read_btrees(golden(FIXTURES / "public" / "pstsdk-submessage.pst", "read_btrees"))
    with_sub = [e for e in _leaves(sub["node_btree"]) if e["sub_node"] is not None]
    assert with_sub, "expected sub-node trees"
    tree = with_sub[0]["sub_node"]["tree"]
    assert tree["level"] == 0 and tree["entries"]
    assert set(tree["entries"][0]) == {"node", "data", "ref", "sub_node"}
    nested = [e for t in with_sub for e in t["sub_node"]["tree"]["entries"] if e["sub_node"] is not None]
    assert nested, "expected a nested sub-node tree (an embedded message)"
    sample = parse_read_btrees(golden(FIXTURES / "public" / "pstsdk-sample1.pst", "read_btrees"))
    trees = [d for d in _data_values(sample["node_btree"]) if "level" in d]
    assert len(trees) == 1 and trees[0]["level"] == 1 and trees[0]["blocks"]
    assert all("size" in b["tree"] for b in trees[0]["blocks"])


def _data_values(page: dict) -> list[dict]:
    """Every `data` value in a node tree, including those inside sub-node trees."""
    out = []

    def sub(tree: dict) -> None:
        for e in tree["entries"]:
            if "data" in e:
                out.append(e["data"])
            if e.get("sub_node") is not None and e["sub_node"]["tree"] is not None:
                sub(e["sub_node"]["tree"])
            if "tree" in e:
                sub(e["tree"])

    for e in _leaves(page):
        out.append(e["data"])
        if e["sub_node"] is not None and e["sub_node"]["tree"] is not None:
            sub(e["sub_node"]["tree"])
    return out


def test_read_btrees_accepts_pypst_form_without_trees() -> None:
    """What pypst.debug prints: no prefix, and a sub-node block with no tree after it."""
    text = (
        "Block Page Entries: 1\n"
        " Block: BlockRef { block: BlockId { leaf: 0x1 }, index: ByteIndex { 0x4C00 } }\n"
        "  Size: 156\n"
        "  Ref-Count: 4\n"
        "\n"
        "Node Page Entries: 1\n"
        " Node: NodeId { NormalMessage: 0x8004 }\n"
        "  Data Block: BlockId { leaf: 0x1 }\n"
        "  Size: 0x9C\n"
        "  Sub-Node Block: BlockId { internal: 0x2 }\n"
        "  Parent Node: Some(NodeId { NormalFolder: 0x9 })\n"
    )
    parsed = parse_read_btrees(text)
    assert parsed["block_btree"] == {
        "level": 0,
        "entries": [{"block": {"block": {"internal": False, "index": 1}, "index": 0x4C00}, "size": 156, "ref_count": 4}],
    }
    entry = parsed["node_btree"]["entries"][0]
    assert entry["sub_node"] == {"block": {"internal": True, "index": 2}, "tree": None}
    assert entry["parent"] == {"type": "NormalFolder", "index": 9}


def _empty_btrees_lines() -> list[str]:
    return (GOLDEN / "Empty" / "read_btrees.txt").read_text().splitlines()


@pytest.mark.parametrize("keep", [*range(0, 337, 9), 336])
def test_read_btrees_rejects_truncation(keep: int) -> None:
    lines = _empty_btrees_lines()
    assert len(lines) == 337
    with pytest.raises(ValueError, match=r"line \d+:"):
        parse_read_btrees("\n".join(lines[:keep]) + "\n")


def test_read_btrees_rejects_empty_and_ansi_goldens(golden) -> None:
    with pytest.raises(ValueError, match="line 1:"):
        parse_read_btrees("")
    for stem in sorted(ANSI_STORES):
        with pytest.raises(ValueError):
            parse_read_btrees(golden(FIXTURES / "public" / f"{stem}.pst", "read_btrees"))


def test_read_btrees_rejects_trailing_junk_and_bad_counts() -> None:
    text = "\n".join(_empty_btrees_lines()) + "\n"
    with pytest.raises(ValueError, match="line 338:"):
        parse_read_btrees(text + "Extra: 1\n")
    lines = _empty_btrees_lines()
    lines[0] = "Block BTree Level: 1: Entries: 3"  # claims a third child that is not there
    with pytest.raises(ValueError):
        parse_read_btrees("\n".join(lines) + "\n")
    lines = _empty_btrees_lines()
    lines[2] = "Block Page Entries: 13"  # one fewer than printed
    with pytest.raises(ValueError, match="line "):
        parse_read_btrees("\n".join(lines) + "\n")


@pytest.mark.parametrize(
    ("line_no", "bad"),
    [
        (2, " Key: 0x4"),
        (3, " Block Page Entries: x"),
        (4, "  Block: UnicodeBlockId { leaf: 0x1 }"),
        (5, "   Size: 0x9C"),
        (101, " Key: 1"),
        (103, "  Node: UnicodeNodeId { Internal: 0x1 }"),
        (104, "   Data Block: UnicodeBlockRef { block: UnicodeBlockId { leaf: 0x42 }, index: UnicodeByteIndex { 0x0 } }"),
        (107, "   Parent Node: Some(NodeId { Internal: 0x1 }"),
    ],
)
def test_read_btrees_rejects_garbled_value(line_no: int, bad: str) -> None:
    lines = _empty_btrees_lines()
    lines[line_no - 1] = bad
    with pytest.raises(ValueError, match=rf"line {line_no}:"):
        parse_read_btrees("\n".join(lines) + "\n")


# --- read_density_list (P02) ---------------------------------------------------------


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_read_density_list_golden_parses(store: Path, golden, golden_exit) -> None:
    assert golden_exit(store, "read_density_list") == 0
    parsed = parse_read_density_list(golden(store, "read_density_list"))
    if store.stem in {"pstd-inline-cid", "pstsdk-test_unicode", "synth-basics"}:
        assert parsed is None  # no density list page; upstream prints an Error line
        return
    assert parsed is not None
    assert set(parsed) == {"backfill_complete", "current_page", "entries", "page_type", "signature", "crc", "block_id"}
    assert parsed["page_type"] == "DensityList" and parsed["entries"] == [] and parsed["crc"] == 0


def test_read_density_list_empty_pst_spot_values(empty_pst: Path, golden) -> None:
    parsed = parse_read_density_list(golden(empty_pst, "read_density_list"))
    assert parsed == {
        "backfill_complete": False,
        "current_page": 0,
        "entries": [],
        "page_type": "DensityList",
        "signature": 0x437F,
        "crc": 0,
        "block_id": 0x17F,
    }


def test_read_density_list_parses_entries_and_pypst_form() -> None:
    text = (
        "Backfill Complete: true\n"
        "Current Page: 3\n"
        "Density List Entries: [DensityListPageEntry(5), DensityListPageEntry(4294967295)]\n"
        "Page Type: DensityList\n"
        "Page Signature: 0x1\n"
        "Page CRC: 0x0000abcd\n"
        "Block ID: PageId: 0x17F\n"
    )
    parsed = parse_read_density_list(text)
    assert parsed is not None
    assert parsed["backfill_complete"] is True and parsed["current_page"] == 3
    assert parsed["entries"] == [5, 0xFFFFFFFF] and parsed["signature"] == 1 and parsed["crc"] == 0xABCD


def _empty_dl_text() -> str:
    return (GOLDEN / "Empty" / "read_density_list.txt").read_text()


@pytest.mark.parametrize("keep", range(len(READ_DENSITY_LIST_LABELS)))
def test_read_density_list_rejects_truncation(keep: int) -> None:
    lines = _empty_dl_text().splitlines()
    if keep == 0:
        with pytest.raises(ValueError, match="line 1:"):
            parse_read_density_list("")
        return
    with pytest.raises(ValueError, match=rf"line {keep + 1}:"):
        parse_read_density_list("\n".join(lines[:keep]) + "\n")


@pytest.mark.parametrize(
    ("line_no", "bad"),
    [
        (1, "Backfill Complete: yes"),
        (2, "Current Page: -1"),
        (3, "Density List Entries: [5]"),
        (3, "Density List Entries: []]"),
        (4, "Page Type: Density List"),
        (5, "Page Signature: 437f"),
        (6, "Page CRC: 0x"),
        (7, "Block ID: UnicodeBlockId { leaf: 0x17F }"),
    ],
)
def test_read_density_list_rejects_garbled_value(line_no: int, bad: str) -> None:
    lines = _empty_dl_text().splitlines()
    lines[line_no - 1] = bad
    with pytest.raises(ValueError, match=rf"line {line_no}:"):
        parse_read_density_list("\n".join(lines) + "\n")


def test_read_density_list_rejects_trailing_junk_and_non_error_single_line() -> None:
    with pytest.raises(ValueError, match="line 8:"):
        parse_read_density_list(_empty_dl_text() + "Extra: 1\n")
    with pytest.raises(ValueError, match="line 2:"):
        parse_read_density_list("Backfill Complete: false\n")


# --- the property-value grammar and the four PC/TC examples (P05) -----------------

VALUE_CASES = [
    ("Null", ("Null", None)),
    ("Integer16(-1)", ("Integer16", -1)),
    ("Integer32(917521)", ("Integer32", 917521)),
    ("Integer64(-9223372036854775808)", ("Integer64", -9223372036854775808)),
    ("Currency(10000)", ("Currency", 10000)),
    ("ErrorCode(-2147024809)", ("ErrorCode", -2147024809)),
    ("Time(116444736000000000)", ("Time", 116444736000000000)),
    ("Floating32(1.5)", ("Floating32", 1.5)),
    ("Floating64(-0.25)", ("Floating64", -0.25)),
    ("Floating64(1e16)", ("Floating64", 1e16)),
    ("Floating64(NaN)", ("Floating64", float("nan"))),
    ("Floating64(inf)", ("Floating64", float("inf"))),
    ("FloatingTime(0.0)", ("FloatingTime", 0.0)),
    ("Boolean(true)", ("Boolean", True)),
    ("Boolean(false)", ("Boolean", False)),
    ('Unicode(UnicodeValue { "IPF.Note" })', ("Unicode", "IPF.Note")),
    ('Unicode(UnicodeValue { "" })', ("Unicode", "")),
    ('Unicode(UnicodeValue { "a, b]c" })', ("Unicode", "a, b]c")),
    ('Unicode(UnicodeValue { "tab\\there" })', ("Unicode", "tab\there")),
    ('Unicode(UnicodeValue { "\\u{301}" })', ("Unicode", "\u0301")),
    ('String8(String8Value { "Search Root" })', ("String8", "Search Root")),
    ("Guid(GuidValue { 00062002-0000-0000-C000-000000000046 })", ("Guid", uuid.UUID("00062002-0000-0000-c000-000000000046"))),
    ("Binary(BinaryValue { 01-FF-00 })", ("Binary", b"\x01\xff\x00")),
    ("Binary(BinaryValue {  })", ("Binary", b"")),
    ("MultipleInteger32([1, 2, 3])", ("MultipleInteger32", [1, 2, 3])),
    ("MultipleInteger32([])", ("MultipleInteger32", [])),
    ('MultipleUnicode([UnicodeValue { "a, b" }, UnicodeValue { "]" }])', ("MultipleUnicode", ["a, b", "]"])),
    ("MultipleBinary([BinaryValue { AA }, BinaryValue {  }])", ("MultipleBinary", [b"\xaa", b""])),
    ("Object(ObjectValue { NodeId { Attachment: 0x401 }, size: 0x1234 })", None),
]


@pytest.mark.parametrize(("text", "expected"), [(t, e) for t, e in VALUE_CASES if e is not None], ids=lambda v: str(v)[:40])
def test_parse_value_round_trips(text: str, expected: tuple) -> None:
    variant, value = parse_value(text)
    assert variant == expected[0]
    if isinstance(expected[1], float) and math.isnan(expected[1]):
        assert math.isnan(value)
    else:
        assert value == expected[1]
        assert type(value) is type(expected[1])


def test_parse_value_object_carries_the_node_id() -> None:
    variant, value = parse_value("Object(ObjectValue { NodeId { Attachment: 0x401 }, size: 0x1234 })")
    assert variant == "Object"
    assert value == {"node": {"type": "Attachment", "index": 0x401}, "size": 0x1234}


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "Integer32",
        "Integer32(0)extra",
        "Integer32()",
        "Integer32(0x10)",
        "Integer128(0)",
        "Boolean(1)",
        "Binary(BinaryValue { AABB })",
        "Binary(BinaryValue { AA- })",
        "Binary(BinaryValue {})",
        "Guid(GuidValue { not-a-guid })",
        'Unicode(UnicodeValue { "unterminated })',
        'Unicode(UnicodeValue { "bad \\q escape" })',
        'Unicode(UnicodeValue { "\\u{zz}" })',
        "MultipleInteger32([1, 2)",
        "MultipleInteger32([1 2])",
        "Object(ObjectValue { NodeId { Attachment: 0x401 } })",
    ],
)
def test_parse_value_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_value(bad)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Small(0x000E0011)", {"kind": "small", "raw": 0x000E0011}),
        ("Small(Integer32(0))", {"kind": "small", "value": ("Integer32", 0)}),
        ("Small(Boolean(true))", {"kind": "small", "value": ("Boolean", True)}),
        ("HeapId(NodeId { HeapNode: 0x5 })", {"kind": "heap", "hid": 0xA0}),
        ("Heap(HeapId(NodeId { HeapNode: 0x5 }))", {"kind": "heap", "hid": 0xA0}),
        ("NodeId { ListsTablesProperties: 0x405 }", {"kind": "node", "node": {"type": "ListsTablesProperties", "index": 0x405}}),
        ("Node(NodeId { ListsTablesProperties: 0x405 })", {"kind": "node", "node": {"type": "ListsTablesProperties", "index": 0x405}}),
    ],
)
def test_parse_record_both_spellings(text: str, expected: dict) -> None:
    assert parse_record(text) == expected


@pytest.mark.parametrize(
    "bad",
    ["", "Small(0x0)", "Small()", "Heap(HeapId(NodeId { HeapNode: 0x5 })", "Node(NodeId { Internal: 0x1 }", "Whatever(1)"],
)
def test_parse_record_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_record(bad)


# The three stores whose read_store_props golden is a complete dump; the
# oracle exits 1 part-way through pstd-inline-cid's (no Deleted Items entry
# id), so its golden carries two header lines and no properties.
STORE_PROPS_PARTIAL = {"pstd-inline-cid"}


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_read_store_props_golden_parses(store: Path, golden, golden_exit) -> None:
    parsed = parse_read_store_props(golden(store, "read_store_props"))
    assert set(parsed) == {"display_name", "ipm_subtree", "deleted_items", "finder", "properties"}
    assert isinstance(parsed["display_name"], str) and parsed["display_name"]
    assert len(parsed["ipm_subtree"]["record_key"]) == 16
    if store.stem in STORE_PROPS_PARTIAL:
        assert golden_exit(store, "read_store_props") == 1
        assert parsed["deleted_items"] is None and parsed["properties"] == []
        return
    assert golden_exit(store, "read_store_props") == 0
    assert parsed["properties"], store.stem
    ids = [g["id"] for g in parsed["properties"]]
    assert ids == sorted(ids), f"{store.stem}: read_store_props is not in prop-id order"
    assert len(set(ids)) == len(ids), f"{store.stem}: a property id appears twice"
    for group in parsed["properties"]:
        assert group["record"] is None, "the example prints no Record: line"
        assert group["value"][0] == group["type"]


def test_read_store_props_rejects_garbled_and_truncated() -> None:
    text = (GOLDEN / "Empty" / "read_store_props.txt").read_text()
    lines = text.splitlines()
    # A group cut between its Type: and its Value:.
    with pytest.raises(ValueError, match="expected `  Value:`"):
        parse_read_store_props("\n".join(lines[:5]) + "\n")
    # A Type: that the Value: contradicts.
    swapped = list(lines)
    swapped[4] = " Property ID: 0x0E34, Type: Integer32"
    with pytest.raises(ValueError, match="!= Type:"):
        parse_read_store_props("\n".join(swapped) + "\n")
    # Trailing junk after the last group.
    with pytest.raises(ValueError, match="unexpected"):
        parse_read_store_props(text + "Something Else\n")
    # A column group where a plain one belongs.
    with pytest.raises(ValueError, match="unexpected"):
        parse_read_store_props("Display Name: x\n Column: Property ID: 0x0001, Type: Null\n  Value: Null\n")


@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_read_named_props_golden_parses(store: Path, golden, golden_exit) -> None:
    assert golden_exit(store, "read_named_props") == 0
    entries = parse_read_named_props(golden(store, "read_named_props"))
    assert entries, store.stem
    for entry in entries:
        assert 0x8000 <= entry["prop_id"] <= 0xFFFF, store.stem
        assert (entry["number"] is None) != (entry["name"] is None), "exactly one of Number:/String[…]:"
        if entry["name"] is not None:
            assert entry["string_offset"] is not None
        if isinstance(entry["guid_index"], int):
            assert entry["guid"] is not None, "GuidIndex(n) is followed by an Other: line"
    ids = [e["prop_id"] for e in entries]
    assert ids == sorted(ids), f"{store.stem}: named props are not in id order"


def test_read_named_props_rejects_garbled() -> None:
    text = (GOLDEN / "Empty" / "read_named_props.txt").read_text()
    lines = text.splitlines()
    with pytest.raises(ValueError, match="expected ` GUID Index:`"):
        parse_read_named_props(lines[0] + "\n")
    with pytest.raises(ValueError, match="expected `Named Property ID:`"):
        parse_read_named_props(" GUID Index: None\n")
    with pytest.raises(ValueError, match="expected ` Number:` or"):
        parse_read_named_props("Named Property ID: 0x8000\n GUID Index: None\n")
    assert parse_read_named_props("") == []


TABLE_PARSERS = {"read_root_folder": parse_read_root_folder, "read_ipm_subtree": parse_read_ipm_subtree}


@pytest.mark.parametrize("example", sorted(TABLE_PARSERS))
@pytest.mark.parametrize("store", UNICODE_STORES, ids=UNICODE_IDS)
def test_table_goldens_parse(store: Path, example: str, golden, golden_exit) -> None:
    rows = TABLE_PARSERS[example](golden(store, example))
    if golden_exit(store, example) != 0:
        assert rows == [], f"{store.stem}: a refusal golden must hold no rows"
        return
    assert rows, f"{store.stem}: {example} golden has no rows"
    widths = {len(row["columns"]) for row in rows}
    assert len(widths) == 1, f"{store.stem}: rows disagree about the column count {widths}"
    first = [(c["id"], c["type"]) for c in rows[0]["columns"]]
    for row in rows:
        assert [(c["id"], c["type"]) for c in row["columns"]] == first, "the schema is the table's, not the row's"
        for cell in row["columns"]:
            if cell["value"] is None:
                assert cell["record"] is None, "an absent cell prints no Record: line"
            else:
                assert cell["record"] is not None
                assert cell["value"][0] == cell["type"]


def test_table_parsers_reject_garbled() -> None:
    with pytest.raises(ValueError, match="expected `Row:`"):
        parse_read_root_folder("Version: 0x1\n")
    with pytest.raises(ValueError, match="expected `Version:`"):
        parse_read_root_folder("Row: 0x1\n")
    with pytest.raises(ValueError, match="a row with no ` Column:` lines"):
        parse_read_ipm_subtree("Row: 0x1\nVersion: 0x2\n")
    # A plain ` Property ID:` group where a ` Column: Property ID:` belongs is not a column.
    with pytest.raises(ValueError, match="a row with no ` Column:` lines"):
        parse_read_ipm_subtree("Row: 0x1\nVersion: 0x2\n Property ID: 0x1, Type: Null\n  Value: Null\n")


def test_every_value_line_in_every_golden_parses() -> None:
    """The grammar covers what upstream actually printed, not only what this file imagined."""
    seen: set[str] = set()
    lines = 0
    for path in sorted(GOLDEN.glob("*/read_*.txt")):
        for line in path.read_text().splitlines():
            for prefix in ("  Value: ", "  Record: "):
                if not line.startswith(prefix):
                    continue
                text = line.removeprefix(prefix)
                if prefix == "  Record: ":
                    parse_record(text)
                elif text != "None":
                    seen.add(parse_value(text)[0])
                lines += 1
    assert lines > 1000, f"only {lines} Value:/Record: lines found; the goldens moved"
    assert seen == {"Integer32", "Integer64", "Boolean", "Binary", "Unicode", "String8"}, seen


# --- dump_messages (P08's folder blocks; the message blocks stay raw for P09) --------


DUMP_MESSAGES_STORES = [p for p in ALL_STORES]
DUMP_MESSAGES_IDS = [p.stem for p in ALL_STORES]


@pytest.mark.parametrize("store", DUMP_MESSAGES_STORES, ids=DUMP_MESSAGES_IDS)
def test_dump_messages_parses_every_golden_whole(store: Path, golden) -> None:
    """Every folder block, every message block and the trailer — and nothing left over."""
    text = golden(store, EXAMPLE_DUMP)
    parsed = parse_dump_messages(text)
    assert parsed["errors"] == int(text.rstrip("\n").rsplit("Errors: ", 1)[1])
    folders = parsed["folders"]
    assert len(folders) == sum(1 for ln in text.splitlines() if ln.startswith("Folder: "))
    counted = sum(len(f["messages"]) for f in folders)
    assert counted == sum(1 for ln in text.splitlines() if ln.startswith("  Message: "))
    # Every message block keeps its own lines and nothing else's.
    for folder in folders:
        for message in folder["messages"]:
            assert message["lines"][0].startswith("  Message: ")
            assert all(ln.startswith("    ") for ln in message["lines"][1:])


@pytest.mark.parametrize("store", DUMP_MESSAGES_STORES, ids=DUMP_MESSAGES_IDS)
def test_dump_messages_folder_lines_is_the_folder_blocks_exactly(store: Path, golden) -> None:
    """The filter keeps every folder line, in order, and drops every message line."""
    text = golden(store, EXAMPLE_DUMP)
    kept = dump_messages_folder_lines(text)
    assert [ln for ln in kept if ln.startswith("Folder: ")] == [ln for ln in text.splitlines() if ln.startswith("Folder: ")]
    assert not any(ln.startswith("  Message: ") for ln in kept)
    assert not any(ln.startswith("Errors: ") for ln in kept)
    # 5 or 6 lines per folder in the goldens: the four properties, the
    # associated line, and a `… Table: None` for each absent table.
    folders = sum(1 for ln in kept if ln.startswith("Folder: "))
    assert folders * 6 <= len(kept) <= folders * 9


def test_dump_messages_reads_the_error_form_of_every_accessor() -> None:
    """`result_debug`'s `Error: <Debug>` in place of a value comes back as `{"error": …}`, not as a string."""
    text = (
        "Folder: NodeId { NormalFolder: 0x9 }\n"
        "  Name: Error: Custom { kind: InvalidData, error: InvalidFolderDisplayName(Null) }\n"
        "  Content Count: 0\n"
        "  Unread Count: 0\n"
        "  Has Sub Folders: true\n"
        "  Associated Count: 0\n"
        "Errors: 0\n"
    )
    folder = parse_dump_messages(text)["folders"][0]
    assert folder["name"] == {"error": "Custom { kind: InvalidData, error: InvalidFolderDisplayName(Null) }"}
    assert (folder["content_count"], folder["unread_count"], folder["has_subfolders"]) == (0, 0, True)
    assert (folder["associated_count"], folder["contents_table"], folder["hierarchy_table"]) == (0, True, True)


def test_dump_messages_reads_the_absent_table_lines() -> None:
    text = (
        "Folder: NodeId { SearchFolder: 0x111 }\n"
        '  Name: "SPAM Search Folder 2"\n'
        "  Content Count: 0\n"
        "  Unread Count: 0\n"
        "  Has Sub Folders: false\n"
        "  Associated Table: None\n"
        "  Contents Table: None\n"
        "  Hierarchy Table: None\n"
    )
    folder = parse_dump_messages(text)["folders"][0]
    assert folder["name"] == "SPAM Search Folder 2"
    assert folder["associated_count"] is None
    assert folder["contents_table"] is False and folder["hierarchy_table"] is False
    assert parse_dump_messages(text)["errors"] is None  # our dumper prints no trailer


def test_dump_messages_reads_a_folder_that_could_not_be_opened() -> None:
    text = "Folder: NodeId { NormalFolder: 0x9 }\n  Error: Custom { kind: InvalidData, error: EntryIdWrongStore }\nErrors: 1\n"
    folder = parse_dump_messages(text)["folders"][0]
    assert folder["error"] == "Custom { kind: InvalidData, error: EntryIdWrongStore }"
    assert folder["name"] is None and folder["messages"] == []


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("", "no `Folder:` block"),
        ("Name: x\n", "expected `Folder:` or `Errors:`"),
        ("Folder: NodeId { NormalFolder: 0x9 }\n", "expected '  Name'"),
        ("Errors: 0\nFolder: NodeId { NormalFolder: 0x9 }\n", "follows the Errors trailer"),
        (
            'Folder: NodeId { NormalFolder: 0x9 }\n  Name: "a"\n  Content Count: many\n',
            "not an i32",
        ),
        (
            'Folder: NodeId { NormalFolder: 0x9 }\n  Name: "a"\n  Content Count: 0\n  Unread Count: 0\n  Has Sub Folders: yes\n',
            "not a bool",
        ),
    ],
    ids=["empty", "no folder", "truncated", "after trailer", "bad count", "bad bool"],
)
def test_dump_messages_refuses_garbled_input(text: str, match: str) -> None:
    """Never a partial result: a shape the oracle cannot have printed is a `ValueError` naming the line."""
    with pytest.raises(ValueError, match=match):
        parse_dump_messages(text)
