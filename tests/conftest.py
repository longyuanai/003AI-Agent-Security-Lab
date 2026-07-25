"""Shared test fixtures.

The big one is a `stub_router` factory that returns an object implementing
just the `LLMRouter.chat(tier, req) -> ChatResponse` interface, so the
LLMDetector can be exercised without any network.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest


@pytest.fixture
def stub_router() -> Callable[[dict[str, Any]], Any]:
    """Return a factory that builds a stub LLMRouter.

    Usage:
        router = stub_router({"verdict": "malicious", "category": "prompt_injection"})
        detector = LLMDetector(router=router)
    """

    def _make(body: dict[str, Any]) -> Any:
        from shared_llm_core import ChatChoice, ChatMessage, ChatResponse, ChatUsage

        class _Router:
            def __init__(self, body: dict[str, Any]) -> None:
                self._body = body
                self.calls: list[Any] = []

            def chat(self, tier: Any, req: Any) -> ChatResponse:
                self.calls.append((tier, req))
                return ChatResponse(
                    id="stub",
                    model="stub",
                    created=0,
                    choices=[
                        ChatChoice(
                            index=0,
                            message=ChatMessage(
                                role="assistant",
                                content=json.dumps(self._body),
                            ),
                            finish_reason="stop",
                        )
                    ],
                    usage=ChatUsage(),
                )

        return _Router(body)

    return _make
