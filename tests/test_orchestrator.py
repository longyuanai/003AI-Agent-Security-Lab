"""LLM provider selection tests."""

from __future__ import annotations

import json

import pytest
from shared_llm_core import ChatMessage, ChatRequest
from shared_llm_core.router import TaskTier

from ai_agent_lab.orchestrator import (
    AnthropicLLMRouter,
    FakeLLMRouter,
    OpenAILLMRouter,
    build_llm_runtime,
)


def test_fake_llm_fallback_when_no_key() -> None:
    runtime = build_llm_runtime({})
    assert runtime.provider == "fake"
    assert isinstance(runtime.router, FakeLLMRouter)
    assert runtime.fallback_reason is None


def test_explicit_openai_without_key_falls_back_to_fake() -> None:
    runtime = build_llm_runtime({"LLM_PROVIDER": "openai"})
    assert runtime.provider == "fake"
    assert runtime.fallback_reason == "OPENAI_API_KEY is not set"


def test_openai_key_selects_official_sdk_router() -> None:
    pytest.importorskip("openai", reason="the 'openai' extra is not installed")
    runtime = build_llm_runtime(
        {
            "LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "test-not-a-real-key",
        }
    )
    assert runtime.provider == "openai"
    assert isinstance(runtime.router, OpenAILLMRouter)


def test_openai_without_the_extra_falls_back_instead_of_crashing(
    monkeypatch,
) -> None:
    """`openai` is optional, so selecting it uninstalled must degrade cleanly.

    Caught by running the suite in a venv without the extra: the provider was
    reachable but constructing the router raised ModuleNotFoundError from
    inside `OpenAILLMRouter.__init__`.
    """

    import ai_agent_lab.orchestrator as orchestrator

    def _no_sdk(*args, **kwargs):
        raise ImportError("No module named 'openai'")

    monkeypatch.setattr(orchestrator, "OpenAILLMRouter", _no_sdk)
    runtime = build_llm_runtime(
        {"LLM_PROVIDER": "openai", "OPENAI_API_KEY": "test-not-a-real-key"}
    )
    assert runtime.provider == "fake"
    assert "openai" in runtime.fallback_reason


def test_anthropic_key_selects_native_router_without_extra_dependency() -> None:
    runtime = build_llm_runtime(
        {
            "LLM_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "test-not-a-real-key",
        }
    )
    assert runtime.provider == "anthropic"
    assert isinstance(runtime.router, AnthropicLLMRouter)


def test_fake_router_returns_detector_json() -> None:
    response = FakeLLMRouter().chat(
        TaskTier.CHEAP,
        ChatRequest(messages=[ChatMessage(role="user", content="fixture")]),
    )
    body = json.loads(response.choices[0].message.content)
    assert body["verdict"] == "malicious"
    assert body["confidence"] == 0.88


def test_unknown_provider_is_rejected() -> None:
    with pytest.raises(ValueError, match="LLM_PROVIDER"):
        build_llm_runtime({"LLM_PROVIDER": "unknown"})
