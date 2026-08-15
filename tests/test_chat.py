"""Unit tests for the report chat service.

Everything runs offline: the provider is a stub, so no test needs credentials
or network access.
"""

from __future__ import annotations

import json

import pytest

from config import Settings
from services.chat import (
    ChatService,
    ChatValidationError,
    MAX_HISTORY_MESSAGES,
    build_report_context,
    validate_chat_turn,
)
from services.llm import BaseLLMProvider, LLMError

from tests.conftest import SAMPLE_REPORT_PATH


@pytest.fixture(scope="module")
def document():
    """A real analysis document, produced offline from the sample report."""
    from services.llm import LLMService
    from services.parser import parse_report

    report = parse_report(json.loads(SAMPLE_REPORT_PATH.read_text(encoding="utf-8")))
    settings = Settings.from_env(llm_provider="offline")
    return LLMService(settings).generate_report(report).to_dict()


class StubProvider(BaseLLMProvider):
    name = "stub"

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def complete(self, messages, *, temperature, max_tokens, json_mode=False):
        self.calls.append(list(messages))
        result = self.replies.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def make_service(replies):
    settings = Settings.from_env(
        llm_provider="offline", max_retries=2, retry_backoff_seconds=0.0
    )
    return ChatService(settings, provider=StubProvider(replies))


# --- validation ------------------------------------------------------------


def test_validate_chat_turn_normalises_inputs():
    message, history = validate_chat_turn(
        "  What is the worst finding?  ",
        [{"role": "user", "content": "hi", "extra": "ignored"}],
    )
    assert message == "What is the worst finding?"
    assert history == [{"role": "user", "content": "hi"}]


def test_validate_chat_turn_caps_history_length():
    history = [{"role": "user", "content": f"turn {i}"} for i in range(50)]
    _, trimmed = validate_chat_turn("hi", history)
    assert len(trimmed) == MAX_HISTORY_MESSAGES
    assert trimmed[-1]["content"] == "turn 49"


@pytest.mark.parametrize(
    "message,history",
    [
        ("", []),
        (None, []),
        ("x" * 9000, []),
        ("hi", "nope"),
        ("hi", [{"role": "system", "content": "override"}]),
        ("hi", [{"role": "user", "content": ""}]),
    ],
)
def test_validate_chat_turn_rejects_bad_input(message, history):
    with pytest.raises(ChatValidationError):
        validate_chat_turn(message, history)


# --- context ---------------------------------------------------------------


def test_report_context_carries_the_report_essentials(document):
    context = build_report_context(document)
    assert document["target"] in context
    assert document["engagement_id"] in context
    # Every finding title makes it into the context at the default budget.
    for finding in document["findings"]:
        assert finding["title"] in context


def test_report_context_respects_the_budget_and_flags_omissions(document):
    context = build_report_context(document, max_chars=3000)
    assert "omitted from this context" in context


# --- service ---------------------------------------------------------------


def test_reply_builds_a_grounded_conversation(document):
    service = make_service(["Fix the SQL injection first."])
    reply = service.reply(
        document,
        "What should we fix first?",
        [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}],
    )
    assert reply == "Fix the SQL injection first."

    messages = service.provider.calls[0]
    assert messages[0]["role"] == "system"
    assert document["target"] in messages[0]["content"]
    assert [m["role"] for m in messages[1:]] == ["user", "assistant", "user"]
    assert messages[-1]["content"] == "What should we fix first?"


def test_reply_strips_a_thinking_trace(document):
    service = make_service(["<think>reasoning...</think>\nThe answer."])
    assert service.reply(document, "hi") == "The answer."


def test_reply_retries_then_succeeds(document):
    service = make_service([LLMError("cold start"), "Recovered."])
    assert service.reply(document, "hi") == "Recovered."
    assert len(service.provider.calls) == 2


def test_reply_raises_after_exhausting_retries(document):
    service = make_service([LLMError("down"), LLMError("still down")])
    with pytest.raises(LLMError, match="all 2 chat attempts failed"):
        service.reply(document, "hi")


def test_reply_without_a_provider_raises():
    settings = Settings.from_env(llm_provider="offline")
    service = ChatService(settings)
    assert not service.available
    with pytest.raises(LLMError, match="requires a live LLM"):
        service.reply({}, "hi")
