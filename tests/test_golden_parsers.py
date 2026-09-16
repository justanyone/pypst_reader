"""The golden parsers are themselves under test.

A parser that accepts a truncated golden turns a corrupted file into a green
differential test, so every parser here is shown to refuse bad input before
it is trusted to read good input. The read_header parser is exercised over
all nine committed goldens (Empty.pst plus the public corpus); the seven
stubs are checked to raise NotImplementedError with a non-empty description.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import FIXTURES, GOLDEN, public_fixture_ids, public_fixture_paths
from tests.golden_parsers import (
    PARSERS,
    READ_HEADER_LABELS,
    parse_block_id,
    parse_block_ref,
    parse_byte_index,
    parse_node_id,
    parse_page_id,
    parse_page_ref,
    parse_read_header,
)

ALL_STORES = [FIXTURES / "Empty.pst", *public_fixture_paths()]
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


@pytest.mark.parametrize("example", sorted(set(PARSERS) - {"read_header"}))
def test_stub_parsers_describe_their_shape(example: str, empty_pst: Path, golden) -> None:
    with pytest.raises(NotImplementedError) as info:
        PARSERS[example](golden(empty_pst, example))
    assert example in str(info.value)
    assert len(str(info.value)) > 80, "a stub must describe the golden's shape, not just refuse"
