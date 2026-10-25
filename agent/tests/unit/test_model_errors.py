"""Model call retries and error messages (fake Gemini endpoint, no real model).
Same retry policy as the ezstore agent: only 429/503, exponential backoff."""

import pytest

from wazuh_agent import agent as agent_module
from wazuh_agent.agent import (
    MISSING_CREDENTIALS_TEXT,
    MODEL_RETRY_OPTIONS,
    QUOTA_EXHAUSTED_TEXT,
    REFUSAL_TEXT,
)

from .conftest import Conversation, error_reply, intent_reply, respond_text


def test_retry_only_429_and_503_with_exponential_backoff() -> None:
    assert MODEL_RETRY_OPTIONS.http_status_codes == [429, 503]
    assert MODEL_RETRY_OPTIONS.attempts == 4
    assert MODEL_RETRY_OPTIONS.exp_base == 2.0
    assert MODEL_RETRY_OPTIONS.initial_delay == 2.0
    assert agent_module.classify_intent.on_model_error_callback is not None


async def test_503_is_retried_then_succeeds(fake_gemini) -> None:
    fake_gemini.script = [
        error_reply(503, "UNAVAILABLE"),
        error_reply(503, "UNAVAILABLE"),
        intent_reply(intent="off_topic"),
    ]
    events = await Conversation().send("What's the weather in Taipei?")

    assert len(fake_gemini.paths) == 3
    assert all(":generateContent" in p for p in fake_gemini.paths)
    assert respond_text(events) == REFUSAL_TEXT
    assert not any(e.error_message for e in events)


async def test_429_after_retries_gives_clear_message(fake_gemini) -> None:
    fake_gemini.script = [error_reply(429, "RESOURCE_EXHAUSTED")] * 4
    events = await Conversation().send("Which agents are disconnected?")

    assert len(fake_gemini.paths) == MODEL_RETRY_OPTIONS.attempts
    errors = [e for e in events if e.error_message]
    assert errors, "a 429 must produce an error event"
    assert errors[-1].error_code == "RESOURCE_EXHAUSTED"
    assert errors[-1].error_message == QUOTA_EXHAUSTED_TEXT
    assert respond_text(events) == ""


async def test_missing_credentials_gives_clear_message(
    fake_gemini, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GEMINI_API_KEY")
    monkeypatch.delenv("GOOGLE_API_KEY")
    events = await Conversation().send("Which agents are disconnected?")

    assert fake_gemini.paths == []
    errors = [e for e in events if e.error_message]
    assert errors[-1].error_code == "MISSING_CREDENTIALS"
    assert errors[-1].error_message == MISSING_CREDENTIALS_TEXT
    assert respond_text(events) == ""


async def test_400_is_not_retried(fake_gemini) -> None:
    fake_gemini.script = [error_reply(400, "INVALID_ARGUMENT")]
    with pytest.raises(Exception, match="400"):
        await Conversation().send("What's the weather in Taipei?")
    assert len(fake_gemini.paths) == 1
