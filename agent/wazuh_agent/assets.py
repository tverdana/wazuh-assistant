"""Client side of the A2A call to asset_agent (lab asset inventory).

ADK's `RemoteA2aAgent` (new A2A integration, `use_legacy=False`) resolves the
remote agent card and speaks A2A JSON-RPC. It is driven by its own `Runner` from
code nodes, so routing stays in code and a failing remote can never break a
Wazuh answer: any error, timeout or malformed reply becomes `None` ("inventory
unavailable").

The reply comes from another system, so it is validated with Pydantic and is
rendered (escaped) by formatting.py; it never reaches the LLM.
Every call prints one request line and one response line (logger
"wazuh_agent.a2a") for the demo.
"""

import asyncio
import json
import logging
import os
import sys
import time

# ADK marks its A2A integration experimental; keep the demo log readable.
os.environ.setdefault("ADK_SUPPRESS_A2A_EXPERIMENTAL_FEATURE_WARNINGS", "true")

from google.adk.agents.remote_a2a_agent import (
    AGENT_CARD_WELL_KNOWN_PATH,
    RemoteA2aAgent,
)
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from pydantic import BaseModel, Field, ValidationError

ASSET_AGENT_URL = os.getenv("ASSET_AGENT_URL", "http://127.0.0.1:8030").rstrip("/")
A2A_TIMEOUT_SECONDS = 8.0
CALLER = "wazuh_agent"
TARGET = "asset_agent"

log = logging.getLogger("wazuh_agent.a2a")
if not log.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%H:%M:%S"))
    log.addHandler(_handler)
    log.setLevel(logging.INFO)
    log.propagate = False


class Asset(BaseModel):
    host: str = Field(max_length=64)
    owner: str | None = Field(default=None, max_length=120)
    contact: str | None = Field(default=None, max_length=120)
    role: str | None = Field(default=None, max_length=160)
    criticality: str | None = Field(default=None, max_length=20)
    should_be_monitored: bool = True


class AssetReply(BaseModel):
    ok: bool
    op: str
    source: str | None = None
    updated: str | None = None
    hosts: list[Asset] = Field(default_factory=list, max_length=200)
    not_found: list[str] = Field(default_factory=list, max_length=200)
    error: str | None = None


asset_agent = RemoteA2aAgent(
    name=TARGET,
    agent_card=f"{ASSET_AGENT_URL}{AGENT_CARD_WELL_KNOWN_PATH}",
    description="Lab asset inventory: owner, role, should_be_monitored per host.",
    use_legacy=False,
    timeout=A2A_TIMEOUT_SECONDS,
)
_runner = Runner(
    agent=asset_agent,
    app_name="wazuh_agent_a2a",
    session_service=InMemorySessionService(),
)


def _summary(reply: AssetReply) -> str:
    if reply.op == "list":
        return f"{len(reply.hosts)} inventory hosts: " + ", ".join(
            h.host for h in reply.hosts
        )
    parts = [f"{h.host}: owner={h.owner}, role={h.role}" for h in reply.hosts]
    if reply.not_found:
        parts.append(f"not in inventory: {', '.join(reply.not_found)}")
    return "; ".join(parts) or "no hosts"


async def _send(question: str) -> str:
    session = await _runner.session_service.create_session(
        app_name="wazuh_agent_a2a", user_id=CALLER
    )
    texts: list[str] = []
    async for event in _runner.run_async(
        user_id=CALLER,
        session_id=session.id,
        new_message=types.Content(role="user", parts=[types.Part(text=question)]),
    ):
        if event.error_message:
            raise RuntimeError(event.error_message)
        if event.content and event.content.parts:
            texts += [p.text for p in event.content.parts if p.text and not p.thought]
    if not texts:
        raise RuntimeError("empty reply")
    return texts[-1]


async def ask_inventory(request: dict) -> tuple[AssetReply | None, str]:
    """Send one request to asset_agent over A2A.

    Returns (reply, note): reply is None when the inventory is unavailable;
    note is a one-line description for the routing trace.
    """
    question = json.dumps(request)
    log.info(
        "A2A ▶ %s → %s (%s) | question: %s", CALLER, TARGET, ASSET_AGENT_URL, question
    )
    started = time.monotonic()
    try:
        text = await asyncio.wait_for(_send(question), A2A_TIMEOUT_SECONDS)
        reply = AssetReply.model_validate_json(text)
        if not reply.ok:
            raise RuntimeError(reply.error or "asset_agent returned an error")
    except (Exception, ValidationError) as e:  # remote down, timeout, bad reply
        ms = (time.monotonic() - started) * 1000
        reason = (
            "agent card not reachable"
            if "AgentCard" in str(e)
            else f"{type(e).__name__}: {str(e)[:100]}"
        )
        log.info(
            "A2A ◀ %s → %s | UNAVAILABLE after %.0f ms (%s)", TARGET, CALLER, ms, reason
        )
        return None, f"A2A {TARGET} unavailable ({reason})"
    ms = (time.monotonic() - started) * 1000
    summary = _summary(reply)
    log.info("A2A ◀ %s → %s | answer: %s | %.0f ms", TARGET, CALLER, summary[:300], ms)
    return reply, f"A2A {TARGET}: {request.get('op')} → {summary[:160]} ({ms:.0f} ms)"
