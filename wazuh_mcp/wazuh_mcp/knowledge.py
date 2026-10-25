"""Read-only access to the OKF v0.2 knowledge bundle in `knowledge/`.

The bundle is trusted content reviewed in git (unlike alert text), but access is
still constrained: concept ids are validated, a resolved path must stay inside
the bundle root, and symlinks and reserved files (index.md, log.md) are refused.

Retrieval is deliberately simple and explainable: keyword overlap weighted by
where the word appears (title > tags/type/description > body), plus an exact
match on the producer-defined `wazuh_rules` key.
"""

import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_BUNDLE = Path(__file__).resolve().parents[2] / "knowledge"
RESERVED = {"index.md", "log.md"}
CONCEPT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*){0,4}$")
MAX_BODY_CHARS = 8000
_WORD = re.compile(r"[a-z0-9]+")
_STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "what",
    "how",
    "should",
    "about",
    "this",
    "that",
    "our",
    "are",
    "you",
    "can",
    "does",
    "did",
    "from",
    "into",
    "there",
    "have",
    "has",
    "was",
    "were",
    "why",
    "when",
    "which",
    "who",
    "show",
    "tell",
    "give",
    "please",
    "need",
    "want",
    "know",
    "any",
    "all",
    "procedure",
    "handle",
    "lab",  # every concept is about the lab
}
# On equal scores prefer actionable concepts
_TYPE_PRIORITY = {"runbook": 0, "architecture decision record": 1, "reference": 2}


class KnowledgeError(Exception):
    """A failure with a message that is safe to show to the agent/user."""


@dataclass(frozen=True)
class Concept:
    id: str  # OKF concept id: path within the bundle without ".md"
    path: str  # repo-relative path, e.g. knowledge/runbooks/ssh-bruteforce.md
    frontmatter: dict
    body: str


def bundle_root() -> Path:
    return Path(os.environ.get("WAZUH_KNOWLEDGE_DIR", DEFAULT_BUNDLE)).resolve()


def parse_document(text: str) -> tuple[dict, str]:
    """Split YAML frontmatter (between `---` lines) from the markdown body."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    for end, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            meta = yaml.safe_load("\n".join(lines[1:end])) or {}
            if not isinstance(meta, dict):
                raise KnowledgeError("frontmatter must be a YAML mapping")
            return meta, "\n".join(lines[end + 1 :]).lstrip("\n")
    raise KnowledgeError("unterminated frontmatter block")


def trust_tier(meta: dict) -> str:
    """OKF §5.3: unverified / machine-confirmed / human-reviewed."""
    verified = meta.get("verified")
    events = [verified] if isinstance(verified, dict) else verified or []
    if not events:
        return "unverified"
    if any(
        str(e.get("by", "")).startswith("human:") for e in events if isinstance(e, dict)
    ):
        return "human-reviewed"
    return "machine-confirmed"


def _concept(root: Path, file: Path) -> Concept | None:
    rel = file.relative_to(root)
    meta, body = parse_document(file.read_text(encoding="utf-8"))
    if not meta.get("type"):
        return None  # not an OKF concept (§11 requires a non-empty type)
    return Concept(
        id=rel.with_suffix("").as_posix(),
        path=f"{root.name}/{rel.as_posix()}",
        frontmatter=meta,
        body=body,
    )


def load_bundle(root: Path | None = None) -> list[Concept]:
    root = root or bundle_root()
    if not root.is_dir():
        raise KnowledgeError(f"knowledge bundle not found at {root.name}/")
    concepts = []
    for file in sorted(root.rglob("*.md")):
        if file.name in RESERVED or file.is_symlink():
            continue
        if not file.resolve().is_relative_to(root):  # symlinked directory
            continue
        if concept := _concept(root, file):
            concepts.append(concept)
    return concepts


def read_concept(concept_id: str, root: Path | None = None) -> Concept:
    root = root or bundle_root()
    cid = (concept_id or "").strip().removeprefix(f"{root.name}/").removesuffix(".md")
    cid = cid.lstrip("/")
    if not CONCEPT_ID_RE.match(cid) or cid.rsplit("/", 1)[-1] in ("index", "log"):
        raise KnowledgeError(
            f"invalid concept id {concept_id!r} (e.g. runbooks/ssh-bruteforce)"
        )
    file = root / f"{cid}.md"
    if (
        file.is_symlink()
        or not file.resolve().is_relative_to(root)
        or not file.is_file()
    ):
        raise KnowledgeError(
            f"no knowledge concept {cid!r}; use list_knowledge to see the ids"
        )
    concept = _concept(root, file)
    if concept is None:
        raise KnowledgeError(f"{cid!r} is not an OKF concept (no type)")
    return concept


def tokens(text: str) -> set[str]:
    # short numbers ("01" in lab-db-01) are noise; rule ids have 3+ digits.
    # Two-letter words stay ("ip", "db").
    return {
        w
        for w in _WORD.findall(str(text).lower())
        if (len(w) >= 3 or (len(w) == 2 and w.isalpha())) and w not in _STOPWORDS
    }


def score(concept: Concept, query_tokens: set[str]) -> int:
    meta = concept.frontmatter
    title = tokens(meta.get("title", "")) | tokens(concept.id.rsplit("/", 1)[-1])
    labels = tokens(" ".join(map(str, meta.get("tags") or []))) | tokens(
        meta.get("type", "")
    )
    description = tokens(meta.get("description", ""))
    body = tokens(concept.body)
    rules = {str(r) for r in meta.get("wazuh_rules") or []}
    total = 0
    for t in query_tokens:
        if t in rules:
            total += 4
        if t in title:
            total += 4
        elif t in labels or t in description:
            total += 2
        elif t in body:
            total += 1
    return total


def search(
    concepts: list[Concept],
    query: str | None = None,
    type_filter: str | None = None,
    rule_id: int | None = None,
) -> list[tuple[int, Concept]]:
    """Concepts ranked by score; with a query, only those that match it."""
    q = tokens(query or "")
    ranked = []
    for c in concepts:
        meta = c.frontmatter
        if type_filter and str(meta.get("type", "")).lower() != type_filter.lower():
            continue
        if rule_id is not None and rule_id not in (meta.get("wazuh_rules") or []):
            continue
        s = score(c, q) if q else 0
        if q and s == 0:
            continue
        ranked.append((s, c))
    ranked.sort(
        key=lambda item: (
            -item[0],
            _TYPE_PRIORITY.get(str(item[1].frontmatter.get("type", "")).lower(), 9),
            item[1].id,
        )
    )
    return ranked
