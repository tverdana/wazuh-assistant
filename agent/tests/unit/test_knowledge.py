"""The knowledge intent: routing, concept choice in code, citing the file."""

from types import SimpleNamespace

import pytest

from wazuh_agent import agent as agent_module
from wazuh_agent.agent import (
    PENDING_KEY,
    Intent,
    IntentResult,
    NodeResult,
    is_write_request,
    route_intent,
)
from wazuh_agent.formatting import format_tool_result

DOC = {
    "id": "runbooks/ssh-bruteforce",
    "path": "knowledge/runbooks/ssh-bruteforce.md",
    "type": "Runbook",
    "title": "SSH brute force",
    "description": "Respond to sshd brute-force alerts.",
    "trust": "unverified",
    "generated_at": "2026-10-25T05:30:00Z",
    "sources": [
        {
            "id": "sshd-rules",
            "title": "sshd rules",
            "resource": "https://example.org/r.xml",
        },
        {"id": "lab", "title": "Lab compose", "resource": "../../lab/compose.yaml"},
    ],
    "body": "# Trigger\n\n5712 fires.[^sshd-rules] See [Sudo](/runbooks/unauthorized-sudo.md)"
    " and [env](../reference/lab-environment.md).[^lab]\n\n[^sshd-rules]: sshd rules\n[^lab]: Lab\n",
}
HITS = [
    {
        "id": "runbooks/ssh-bruteforce",
        "path": "knowledge/runbooks/ssh-bruteforce.md",
        "type": "Runbook",
        "title": "SSH brute force",
        "score": 12,
    },
    {
        "id": "runbooks/fim-change",
        "path": "knowledge/runbooks/fim-change.md",
        "type": "Runbook",
        "title": "File integrity change",
        "score": 3,
    },
    {
        "id": "reference/lab-environment",
        "path": "knowledge/reference/lab-environment.md",
        "type": "Reference",
        "title": "Lab environment",
        "score": 1,
    },
]


def _route(text: str, result: IntentResult):
    return route_intent(
        SimpleNamespace(state={"last_user_message": text, PENDING_KEY: None}), result
    )


def test_knowledge_route_normalizes_topic():
    event = _route(
        "What should I do about the SSH brute force?",
        IntentResult(intent=Intent.KNOWLEDGE, topic="ssh brute-force; DROP <x>"),
    )
    assert event.actions.route == "knowledge"
    assert event.output == {"topic": "ssh brute-force DROP x"}


def test_catalog_question_keeps_the_concept_kind_without_llm_topic():
    event = _route(
        "Which runbooks do we have in the knowledge base?",
        IntentResult(intent=Intent.KNOWLEDGE, topic=None),
    )
    assert event.output == {"topic": "runbooks"}  # -> list with type=Runbook


@pytest.mark.parametrize(
    "text",
    [
        "How do I block the attacking IP 203.0.113.45?",
        "How should I restart the agent on lab-db-01?",
        "What is the procedure when lab-db-01 is disconnected?",
    ],
)
def test_how_to_questions_are_not_write_requests(text):
    assert not is_write_request(text)


# ---------------------------------------------------------------------------
# knowledge node (fake MCP)
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_mcp(monkeypatch):
    calls = []

    async def fake_call(ctx, name, args):
        calls.append((name, args))
        if name == "list_knowledge":
            hits = HITS if args.get("query") != "ransomware" else []
            if args.get("type"):
                hits = [h for h in HITS if h["type"] == args["type"]]
            data = {
                "bundle": "knowledge/",
                "okf_version": "0.2",
                "total": len(hits),
                "type_filter": args.get("type"),
                "hits": hits,
            }
        else:
            data = DOC
        return NodeResult(kind="tool", tool=name, args=args, data=data)

    monkeypatch.setattr(agent_module, "_call_mcp_tool", fake_call)
    return calls


async def test_specific_topic_reads_best_concept(fake_mcp):
    out = await agent_module.knowledge(None, {"topic": "ssh brute force runbook"})
    assert fake_mcp[0] == (
        "list_knowledge",
        {"query": "ssh brute force", "limit": 4, "type": "Runbook"},
    )
    assert fake_mcp[1] == ("read_knowledge", {"concept_id": "runbooks/ssh-bruteforce"})
    assert out.data["mode"] == "doc"
    # only hits above the score threshold are offered as other matches
    assert [h["id"] for h in out.data["also"]] == ["runbooks/fim-change"]


@pytest.mark.parametrize(
    "topic,type_filter",
    [
        (None, None),
        ("runbooks", "Runbook"),
        ("design decisions", "Architecture Decision Record"),
    ],
)
async def test_generic_topic_lists_catalog(fake_mcp, topic, type_filter):
    out = await agent_module.knowledge(None, {"topic": topic} if topic else {})
    assert out.data["mode"] == "list"
    assert fake_mcp[0][1].get("type") == type_filter
    assert all(name == "list_knowledge" for name, _ in fake_mcp)


async def test_unknown_topic_is_not_found_and_not_guessed(fake_mcp):
    out = await agent_module.knowledge(None, {"topic": "ransomware"})
    assert out.data["mode"] == "not_found"
    assert not any(name == "read_knowledge" for name, _ in fake_mcp)
    text = format_tool_result("knowledge", {}, out.data, None)
    assert "found no concept about “ransomware”" in text and "won't guess" in text


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def test_doc_rendering_cites_file_and_sources():
    data = {"mode": "doc", "query": "ssh brute force", "doc": DOC, "also": HITS[1:2]}
    text = format_tool_result("knowledge", {}, data, None)
    assert "Source: `knowledge/runbooks/ssh-bruteforce.md`" in text
    assert "### Trigger" in text  # headings demoted for chat
    assert "5712 fires. [1]" in text and "[^" not in text  # footnotes numbered
    assert "Sudo (`knowledge/runbooks/unauthorized-sudo.md`)" in text  # bundle link
    assert "env (`knowledge/reference/lab-environment.md`)" in text  # relative link
    assert "1. sshd rules — https://example.org/r.xml" in text
    assert "2. Lab compose — lab/compose.yaml" in text
    assert "read-only and does not run them" in text  # runbook note
    assert (
        "Other matches: File integrity change (`knowledge/runbooks/fim-change.md`)"
        in text
    )


def test_rule_explanation_points_to_runbook():
    data = {
        "id": 5712,
        "level": 10,
        "severity": "medium",
        "description": "d",
        "summary": "s",
        "related_knowledge": [HITS[0]],
    }
    text = format_tool_result("explain_rule", {}, data, None)
    assert (
        "- **Runbook:** SSH brute force — `knowledge/runbooks/ssh-bruteforce.md`"
        in text
    )
