"""The repo's knowledge/ bundle conforms to OKF v0.2 (SPEC §8, §9, §11) and its
internal references resolve."""

import re
from pathlib import Path

import pytest
import yaml

from wazuh_mcp.knowledge import DEFAULT_BUNDLE, RESERVED, parse_document

ROOT = DEFAULT_BUNDLE
FILES = sorted(ROOT.rglob("*.md"))
CONCEPTS = [f for f in FILES if f.name not in RESERVED]
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
FOOTNOTE_REF = re.compile(r"\[\^([\w-]+)\](?!:)")


def _rel(f: Path) -> str:
    return f.relative_to(ROOT).as_posix()


def test_bundle_is_not_empty():
    assert len(CONCEPTS) >= 10


@pytest.mark.parametrize("file", CONCEPTS, ids=_rel)
def test_concept_has_frontmatter_with_type(file):
    meta, body = parse_document(file.read_text(encoding="utf-8"))
    assert meta.get("type"), "OKF §11: non-empty type required"
    assert meta.get("title") and meta.get("description"), "recommended fields"
    assert body.strip()


@pytest.mark.parametrize("file", CONCEPTS, ids=_rel)
def test_footnotes_point_at_sources(file):
    meta, body = parse_document(file.read_text(encoding="utf-8"))
    ids = {s.get("id") for s in meta.get("sources") or []}
    for ref in FOOTNOTE_REF.findall(body):
        assert ref in ids, f"footnote [^{ref}] has no sources entry"


@pytest.mark.parametrize("file", FILES, ids=_rel)
def test_internal_links_resolve(file):
    text = file.read_text(encoding="utf-8")
    for target in LINK.findall(text):
        if target.startswith(("http://", "https://", "#")):
            continue
        path = target.split("#", 1)[0]
        resolved = (
            (ROOT / path.lstrip("/")) if path.startswith("/") else (file.parent / path)
        )
        assert resolved.exists(), f"broken link {target}"


@pytest.mark.parametrize("file", [f for f in FILES if f.name == "index.md"], ids=_rel)
def test_index_files(file):
    text = file.read_text(encoding="utf-8")
    if file.parent == ROOT:
        meta, _ = parse_document(text)
        assert meta == {"okf_version": "0.2"}, "only okf_version allowed in root index"
    else:
        assert not text.startswith("---"), "OKF §8: index.md has no frontmatter"
    listed = {(file.parent / t).resolve() for t in LINK.findall(text)}
    for concept in file.parent.glob("*.md"):
        if concept.name not in RESERVED:
            assert concept.resolve() in listed, (
                f"{concept.name} missing from {_rel(file)}"
            )


def test_log_file():
    text = (ROOT / "log.md").read_text(encoding="utf-8")
    assert not text.startswith("---")
    dates = re.findall(r"^## (.+)$", text, re.MULTILINE)
    assert dates and all(re.fullmatch(r"\d{4}-\d{2}-\d{2}", d) for d in dates)
    assert dates == sorted(dates, reverse=True), "OKF §9: newest first"


def test_repo_relative_sources_exist():
    for file in CONCEPTS:
        meta = yaml.safe_load(file.read_text(encoding="utf-8").split("---")[1])
        for src in meta.get("sources") or []:
            res = str(src["resource"])
            if res.startswith("../"):
                assert (file.parent / res).resolve().exists(), f"{_rel(file)}: {res}"
