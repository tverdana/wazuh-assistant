"""asset_agent: request parsing, answers and the served A2A agent card."""

import json

import pytest
from google.genai import types
from starlette.testclient import TestClient

from asset_agent.inventory import answer, load_inventory, parse_request, summarize
from asset_agent.server import a2a_app, lookup

INVENTORY = load_inventory()


@pytest.mark.parametrize(
    "text,expected",
    [
        (
            '{"op": "lookup", "hosts": ["lab-db-01"]}',
            {"op": "lookup", "hosts": ["lab-db-01"]},
        ),
        ('{"op": "list"}', {"op": "list", "hosts": []}),
        (
            "Who owns lab-web-01 and LAB-DB-01?",
            {"op": "lookup", "hosts": ["lab-db-01", "lab-web-01"]},
        ),
        ("show me the inventory", {"op": "list", "hosts": []}),
    ],
)
def test_parse_request(text, expected):
    assert parse_request(text) == expected


@pytest.mark.parametrize(
    "text", ['{"op": "lookup", "hosts": []}', '{"op": "lookup", "hosts": ["x; DROP"]}']
)
def test_parse_request_errors(text):
    assert parse_request(text)["op"] == "error"


def test_lookup_returns_found_and_not_found():
    reply = answer({"op": "lookup", "hosts": ["lab-db-01", "ghost-99"]}, INVENTORY)
    assert reply["ok"] and [h["host"] for h in reply["hosts"]] == ["lab-db-01"]
    assert reply["hosts"][0]["owner"] == "Database team"
    assert reply["not_found"] == ["ghost-99"]
    assert "ghost-99" in summarize(reply)


def test_inventory_has_a_host_without_wazuh_agent_and_one_not_monitored():
    hosts = {h["host"]: h for h in INVENTORY["hosts"]}
    assert {"lab-web-01", "lab-db-01", "lab-backup-01"} <= set(hosts)
    assert hosts["lab-backup-01"]["should_be_monitored"] is True
    assert any(not h["should_be_monitored"] for h in hosts.values())


def test_error_reply_is_not_ok():
    reply = answer({"op": "error", "error": "bad"}, INVENTORY)
    assert reply["ok"] is False and summarize(reply) == "error: bad"


def test_workflow_node_replies_with_json_text():
    events = list(
        lookup(types.Content(role="user", parts=[types.Part(text='{"op": "list"}')]))
    )
    reply = json.loads(events[0].content.parts[0].text)
    assert reply["op"] == "list" and len(reply["hosts"]) == len(INVENTORY["hosts"])


def test_agent_card_is_served_at_well_known_path():
    with TestClient(a2a_app) as client:
        card = client.get("/.well-known/agent-card.json").json()
    assert card["name"] == "asset_agent"
    assert {s["id"] for s in card["skills"]} == {"lookup_hosts", "list_inventory"}
    iface = card["supportedInterfaces"][0]
    assert (
        iface["protocolBinding"] == "JSONRPC"
        and iface["url"] == "http://127.0.0.1:8030"
    )
    assert card["defaultOutputModes"] == ["application/json"]
