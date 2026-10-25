"""asset_agent: lab asset inventory exposed as an A2A server (LAB only).

A deterministic ADK Workflow (one function node, no LLM) wrapped with ADK's
`to_a2a()`. The agent card is built explicitly and served at
http://127.0.0.1:8030/.well-known/agent-card.json; JSON-RPC at the root path.

    uv run asset-agent          # ASSET_AGENT_HOST=127.0.0.1 ASSET_AGENT_PORT=8030
"""

import json
import logging
import os

# ADK marks its A2A integration experimental; keep the demo log readable.
os.environ.setdefault("ADK_SUPPRESS_A2A_EXPERIMENTAL_FEATURE_WARNINGS", "true")

from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentProvider,
    AgentSkill,
)
from google.adk.a2a.utils.agent_to_a2a import to_a2a
from google.adk.events.event import Event
from google.adk.workflow import Workflow
from google.genai import types

from asset_agent.inventory import answer, load_inventory, parse_request, summarize

HOST = os.environ.get("ASSET_AGENT_HOST", "127.0.0.1")
PORT = int(os.environ.get("ASSET_AGENT_PORT", "8030"))

log = logging.getLogger("asset_agent.a2a")


def _text(content: types.Content | None) -> str:
    if not content or not content.parts:
        return ""
    return "".join(p.text for p in content.parts if p.text).strip()


def lookup(node_input: types.Content):
    """Answer one inventory request; the reply is JSON text."""
    question = _text(node_input)
    reply = answer(parse_request(question), load_inventory())
    log.info("A2A ◀ request  to asset_agent   | question: %s", question[:200])
    log.info("A2A ▶ response from asset_agent | answer: %s", summarize(reply)[:300])
    yield Event(
        content=types.Content(
            role="model", parts=[types.Part.from_text(text=json.dumps(reply))]
        )
    )
    yield Event(output=reply)


root_agent = Workflow(
    name="asset_agent",
    description="Lab asset inventory: owner, role, criticality and should_be_monitored per host.",
    edges=[("START", lookup)],
)

AGENT_CARD = AgentCard(
    name="asset_agent",
    description=(
        "Read-only lab asset inventory (fictional CMDB). Returns owner, contact, "
        "role, criticality and should_be_monitored for hosts. Deterministic, no LLM."
    ),
    version="1.0.0",
    provider=AgentProvider(
        organization="wazuh-assistant lab", url=f"http://{HOST}:{PORT}"
    ),
    supported_interfaces=[
        AgentInterface(
            url=f"http://{HOST}:{PORT}",
            protocol_binding="JSONRPC",
            protocol_version="1.0",
        )
    ],
    capabilities=AgentCapabilities(streaming=False),
    default_input_modes=["text/plain", "application/json"],
    default_output_modes=["application/json"],
    skills=[
        AgentSkill(
            id="lookup_hosts",
            name="Look up hosts",
            description=(
                "Owner, contact, role, criticality and should_be_monitored for the given "
                'hosts. Send {"op": "lookup", "hosts": ["lab-db-01"]} or plain text '
                'naming hosts; unknown hosts are returned in "not_found".'
            ),
            tags=["inventory", "cmdb", "owner", "asset"],
            examples=[
                '{"op": "lookup", "hosts": ["lab-db-01"]}',
                "Who owns lab-web-01?",
            ],
        ),
        AgentSkill(
            id="list_inventory",
            name="List inventory",
            description=(
                "All inventory hosts with should_be_monitored, used to find monitoring "
                'coverage gaps. Send {"op": "list"}.'
            ),
            tags=["inventory", "coverage"],
            examples=['{"op": "list"}', "list the inventory"],
        ),
    ],
)

a2a_app = to_a2a(root_agent, host=HOST, port=PORT, agent_card=AGENT_CARD)


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    log.info(
        "asset_agent A2A server on http://%s:%d (card: /.well-known/agent-card.json)",
        HOST,
        PORT,
    )
    uvicorn.run(a2a_app, host=HOST, port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
