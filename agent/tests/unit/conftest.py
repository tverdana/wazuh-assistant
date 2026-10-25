"""Local fake Gemini endpoint + helpers to run the whole graph without a real
model or MCP server."""

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from google.adk.models import Gemini
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from wazuh_agent.agent import (
    MODEL,
    MODEL_RETRY_OPTIONS,
    app,
    classify_intent,
    root_agent,
)


def intent_reply(**fields) -> tuple[int, dict]:
    """A 200 generateContent response whose text is the IntentResult JSON."""
    return 200, {
        "candidates": [
            {
                "content": {"role": "model", "parts": [{"text": json.dumps(fields)}]},
                "finishReason": "STOP",
            }
        ]
    }


def error_reply(code: int, status: str) -> tuple[int, dict]:
    return code, {"error": {"code": code, "message": status, "status": status}}


class FakeGemini(ThreadingHTTPServer):
    """Returns scripted (status, JSON) replies in order; records every request."""

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.script: list[tuple[int, dict]] = []
        self.paths: list[str] = []
        self.bodies: list[str] = []

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class _Handler(BaseHTTPRequestHandler):
    server: FakeGemini

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.paths.append(self.path)
        self.server.bodies.append(body.decode(errors="replace"))
        status, reply = self.server.script.pop(0)
        payload = json.dumps(reply).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args) -> None:
        pass


@pytest.fixture
def fake_gemini(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeGemini]:
    server = FakeGemini()
    threading.Thread(target=server.serve_forever, daemon=True).start()

    monkeypatch.setenv("GEMINI_API_KEY", "test-dummy-key")
    monkeypatch.setenv("GOOGLE_API_KEY", "test-dummy-key")
    monkeypatch.delenv("GOOGLE_GENAI_USE_VERTEXAI", raising=False)
    monkeypatch.delenv("GOOGLE_GENAI_USE_ENTERPRISE", raising=False)
    # Same attempts/status codes as production, only shorter waits
    fast_retry = MODEL_RETRY_OPTIONS.model_copy(
        update={"initial_delay": 0.01, "max_delay": 0.05, "jitter": 0.01}
    )
    fake_model = Gemini(model=MODEL, base_url=server.url, retry_options=fast_retry)
    # The Workflow copies the LlmAgent into its graph; patch the graph node
    graph_node = next(
        n for n in root_agent._require_graph().nodes if n.name == classify_intent.name
    )
    monkeypatch.setattr(graph_node, "model", fake_model)
    # Safety net: the client really points at the fake endpoint, never at Gemini
    base_url = fake_model.api_client._api_client._http_options.base_url
    assert base_url.startswith(server.url), base_url
    yield server
    server.shutdown()


class Conversation:
    """Runs messages through the real graph in one session."""

    def __init__(self) -> None:
        self.runner = Runner(app=app, session_service=InMemorySessionService())
        self.session_id: str | None = None

    async def send(self, message: str) -> list:
        if self.session_id is None:
            session = await self.runner.session_service.create_session(
                app_name=app.name, user_id="test_user"
            )
            self.session_id = session.id
        return [
            event
            async for event in self.runner.run_async(
                user_id="test_user",
                session_id=self.session_id,
                new_message=types.Content(
                    role="user", parts=[types.Part(text=message)]
                ),
            )
        ]


def respond_text(events: list) -> str:
    for event in events:
        if event.node_info.path.endswith("/respond@1") and event.content:
            return "".join(p.text or "" for p in event.content.parts)
    return ""
