"""LAB_LLM_* activation is explicit and network-safe by default."""

from __future__ import annotations

from ai_agent_lab import judge as judge_module
from ai_agent_lab.judge import RouterLabJudge, StubLabJudge, build_lab_judge


class NoNetworkRouter:
    def chat(self, tier, request):
        raise AssertionError("network-capable chat must not run in this test")


def test_no_lab_llm_key_uses_stub() -> None:
    assert isinstance(build_lab_judge({}), StubLabJudge)


def test_empty_lab_llm_key_uses_stub() -> None:
    assert isinstance(build_lab_judge({"LAB_LLM_KEY": "  "}), StubLabJudge)


def test_key_activates_injected_live_router_without_network() -> None:
    judge = build_lab_judge(
        {"LAB_LLM_KEY": "synthetic-test-key"},
        router=NoNetworkRouter(),
    )
    assert isinstance(judge, RouterLabJudge)
    assert judge.mode == "live"


def test_no_key_never_constructs_shared_router(monkeypatch) -> None:
    def unexpected_router(*args, **kwargs):
        raise AssertionError("LLMRouter must not be constructed")

    monkeypatch.setattr(judge_module, "LLMRouter", unexpected_router)
    assert isinstance(build_lab_judge({}), StubLabJudge)


def test_model_and_base_url_configure_shared_router(monkeypatch) -> None:
    captured = {}

    class CapturingRouter:
        def __init__(self, config, rules, audit):
            captured.update(config=config, rules=rules, audit=audit)

    monkeypatch.setattr(judge_module, "LLMRouter", CapturingRouter)
    judge = build_lab_judge(
        {
            "LAB_LLM_KEY": "synthetic-test-key",
            "LAB_LLM_MODEL": "fixture-model",
            "LAB_LLM_BASE_URL": "https://fixture.invalid",
        }
    )
    provider = captured["config"].providers["lab-judge"]
    assert isinstance(judge, RouterLabJudge)
    assert provider.default_model == "fixture-model"
    assert provider.base_url == "https://fixture.invalid"
    assert captured["audit"] is None
    assert captured["config"].audit.backend == "noop"
    assert captured["config"].audit.include_prompt is False
    assert captured["config"].audit.include_response is False
