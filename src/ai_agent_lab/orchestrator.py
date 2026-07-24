"""Environment-selected LLM routers for live and offline lab scans."""

from __future__ import annotations

import json
import os
import time
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

from shared_llm_core import (
    ChatChoice,
    ChatMessage,
    ChatResponse,
    ChatUsage,
)


@dataclass(frozen=True)
class LLMRuntime:
    """Resolved provider plus its detector-compatible router."""

    provider: str
    router: Any
    fallback_reason: str | None = None


class FakeLLMRouter:
    """Deterministic offline router matching ``LLMRouter.chat``."""

    def chat(self, tier: Any, req: Any) -> ChatResponse:
        del tier, req
        body = {
            "verdict": "malicious",
            "category": "other",
            "attack_type": "tool_misuse",
            "confidence": 0.88,
            "reason": "Offline lab fixture classified the known attack trace.",
        }
        return ChatResponse(
            id=f"fake-{uuid.uuid4()}",
            model="ai-agent-lab-fake",
            created=int(time.time()),
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatMessage(
                        role="assistant",
                        content=json.dumps(body),
                    ),
                    finish_reason="stop",
                )
            ],
            usage=ChatUsage(),
        )


class OpenAILLMRouter:
    """Official OpenAI SDK adapter exposing ``LLMRouter.chat``."""

    def __init__(
        self,
        api_key: str,
        *,
        model: str = "gpt-4.1-mini",
        base_url: str | None = None,
    ) -> None:
        from openai import OpenAI

        kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self._client = OpenAI(**kwargs)
        self._model = model

    def chat(self, tier: Any, req: Any) -> Any:
        del tier
        body = req.model_dump(exclude_none=True)
        body.pop("request_id", None)
        extra = body.pop("extra", {})
        body.update(extra)
        body["model"] = body.get("model") or self._model
        return self._client.chat.completions.create(**body)


class AnthropicLLMRouter:
    """Dependency-free adapter for Anthropic's native Messages API."""

    def __init__(
        self,
        api_key: str,
        *,
        model: str = "claude-sonnet-4-5",
        base_url: str = "https://api.anthropic.com",
        timeout_s: float = 60.0,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s

    def chat(self, tier: Any, req: Any) -> ChatResponse:
        del tier
        system_parts: list[str] = []
        messages: list[dict[str, str]] = []
        for message in req.messages:
            if message.role == "system":
                system_parts.append(message.content)
            else:
                messages.append({"role": message.role, "content": message.content})

        body: dict[str, Any] = {
            "model": req.model or self._model,
            "messages": messages,
            "max_tokens": req.max_tokens or 512,
            "temperature": req.temperature,
        }
        if system_parts:
            body["system"] = "\n\n".join(system_parts)
        body.update(req.extra)
        request = urllib.request.Request(
            f"{self._base_url}/v1/messages",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
                "x-api-key": self._api_key,
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self._timeout_s) as response:
            raw = json.loads(response.read().decode("utf-8"))

        content = "".join(
            str(block.get("text", ""))
            for block in raw.get("content", [])
            if block.get("type") == "text"
        )
        usage = raw.get("usage", {})
        input_tokens = int(usage.get("input_tokens", 0))
        output_tokens = int(usage.get("output_tokens", 0))
        return ChatResponse(
            id=str(raw.get("id", uuid.uuid4())),
            model=str(raw.get("model", self._model)),
            created=int(time.time()),
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatMessage(role="assistant", content=content),
                    finish_reason=raw.get("stop_reason"),
                )
            ],
            usage=ChatUsage(
                prompt_tokens=input_tokens,
                completion_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens,
            ),
            raw=raw,
        )


def build_llm_runtime(
    environ: Mapping[str, str] | None = None,
) -> LLMRuntime:
    """Select OpenAI, Anthropic, or deterministic fake from environment."""

    env = os.environ if environ is None else environ
    requested = env.get("LLM_PROVIDER", "").strip().lower()
    if not requested:
        if env.get("OPENAI_API_KEY"):
            requested = "openai"
        elif env.get("ANTHROPIC_API_KEY"):
            requested = "anthropic"
        else:
            requested = "fake"
    if requested not in {"openai", "anthropic", "fake"}:
        raise ValueError(
            "LLM_PROVIDER must be one of: openai, anthropic, fake"
        )

    if requested == "openai":
        api_key = env.get("OPENAI_API_KEY", "").strip()
        if api_key:
            return LLMRuntime(
                provider="openai",
                router=OpenAILLMRouter(
                    api_key,
                    model=env.get("OPENAI_MODEL", "gpt-4.1-mini"),
                    base_url=env.get("OPENAI_BASE_URL"),
                ),
            )
        return _fake_runtime("OPENAI_API_KEY is not set")

    if requested == "anthropic":
        api_key = env.get("ANTHROPIC_API_KEY", "").strip()
        if api_key:
            return LLMRuntime(
                provider="anthropic",
                router=AnthropicLLMRouter(
                    api_key,
                    model=env.get("ANTHROPIC_MODEL", "claude-sonnet-4-5"),
                    base_url=env.get(
                        "ANTHROPIC_BASE_URL",
                        "https://api.anthropic.com",
                    ),
                ),
            )
        return _fake_runtime("ANTHROPIC_API_KEY is not set")

    return _fake_runtime(None)


def _fake_runtime(reason: str | None) -> LLMRuntime:
    return LLMRuntime(
        provider="fake",
        router=FakeLLMRouter(),
        fallback_reason=reason,
    )
