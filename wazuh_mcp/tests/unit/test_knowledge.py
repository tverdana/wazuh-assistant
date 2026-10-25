"""list_knowledge / read_knowledge: retrieval and path safety (temporary bundle)."""

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from wazuh_mcp.server import list_knowledge, read_knowledge

RUNBOOK = """---
type: Runbook
title: SSH brute force
description: Respond to sshd brute-force alerts.
tags: [ssh, brute-force]
wazuh_rules: [5712, 5763]
sources:
  - id: sshd-rules
    resource: https://example.org/0095-sshd_rules.xml
    title: sshd rules
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-25T05:30:00Z }
---

# Steps

1. Look at rule 5712.[^sshd-rules]
"""
ADR = """---
type: Architecture Decision Record
title: "ADR-0001: Read-only by design"
verified: { by: human:alice, at: 2026-10-25T06:00:00Z }
---

# Decision

Read-only.
"""


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    root = tmp_path / "knowledge"
    (root / "runbooks").mkdir(parents=True)
    (root / "decisions").mkdir()
    (root / "index.md").write_text('---\nokf_version: "0.2"\n---\n\n# Subdirectories\n')
    (root / "log.md").write_text("# Log\n\n## 2026-10-25\n* **Creation**: x\n")
    (root / "runbooks" / "index.md").write_text("# Runbooks\n")
    (root / "runbooks" / "ssh-bruteforce.md").write_text(RUNBOOK)
    (root / "decisions" / "adr-0001.md").write_text(ADR)
    (root / "decisions" / "no-type.md").write_text("---\ntitle: x\n---\nbody\n")
    secret = tmp_path / "secret.md"
    secret.write_text("---\ntype: Secret\n---\nPASSWORD=hunter2\n")
    (root / "runbooks" / "link.md").symlink_to(secret)
    monkeypatch.setenv("WAZUH_KNOWLEDGE_DIR", str(root))
    return root


async def test_list_all_skips_reserved_untyped_and_symlinks(bundle):
    out = await list_knowledge()
    assert {h.id for h in out.hits} == {"runbooks/ssh-bruteforce", "decisions/adr-0001"}
    assert out.okf_version == "0.2" and out.bundle == "knowledge/"


async def test_query_ranks_and_filters(bundle):
    out = await list_knowledge(query="what should I do about ssh brute force?")
    assert out.hits[0].path == "knowledge/runbooks/ssh-bruteforce.md"
    assert out.hits[0].score > 0
    assert (await list_knowledge(query="ransomware")).total == 0


async def test_rule_and_type_filters(bundle):
    assert [h.id for h in (await list_knowledge(rule_id=5712)).hits] == [
        "runbooks/ssh-bruteforce"
    ]
    out = await list_knowledge(type="architecture decision record")
    assert [h.id for h in out.hits] == ["decisions/adr-0001"]
    assert out.hits[0].trust == "human-reviewed"


async def test_read_returns_frontmatter_sources_and_body(bundle):
    doc = await read_knowledge("runbooks/ssh-bruteforce")
    assert doc.path == "knowledge/runbooks/ssh-bruteforce.md"
    assert (
        doc.trust == "unverified" and doc.generated_by == "claude-code/claude-opus-5-5"
    )
    assert doc.sources[0].id == "sshd-rules"
    assert doc.body.startswith("# Steps") and doc.wazuh_rules == [5712, 5763]
    # the citation path form is accepted too
    assert (await read_knowledge("knowledge/runbooks/ssh-bruteforce.md")).id == doc.id


@pytest.mark.parametrize(
    "concept_id",
    [
        "../secret",
        "runbooks/../../secret",
        "/etc/passwd",
        "runbooks/index",
        "log",
        "runbooks/link",  # symlink out of the bundle
        "decisions/no-type",
        "RUNBOOKS/SSH",
        "",
    ],
)
async def test_read_refuses_unsafe_or_invalid_ids(bundle, concept_id):
    with pytest.raises(ToolError):
        await read_knowledge(concept_id)
