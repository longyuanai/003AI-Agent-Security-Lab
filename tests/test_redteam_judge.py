"""LLM-as-judge for ATLAS cases, compared with the deterministic rule.

All tests use scripted in-process routers; no network is ever touched.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from shared_llm_core import ChatChoice, ChatMessage, ChatResponse, ChatUsage

from ai_agent_lab.atlas.testcases import TEST_CASES, RuleResult, RuleVerdict
from ai_agent_lab.datatypes import ToolCall, Trace
from ai_agent_lab.judge import build_lab_router
from ai_agent_lab.redteam import (
    CaseResult,
    LLMCaseJudge,
    LLMJudgement,
    LLMVerdict,
    compare_judges,
    run_red_team,
)


class ScriptedRouter:
    """Returns `reply(request)` as the assistant content; records calls."""

    def __init__(self, reply: Callable[[Any], str]) -> None:
        self._reply = reply
        self.calls: list[Any] = []

    def chat(self, tier: Any, request: Any) -> ChatResponse:
        self.calls.append((tier, request))
        return ChatResponse(
            id="scripted",
            model="scripted-judge",
            created=0,
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatMessage(role="assistant", content=self._reply(request)),
                    finish_reason="stop",
                )
            ],
            usage=ChatUsage(),
        )


class FailingRouter:
    def chat(self, tier: Any, request: Any) -> ChatResponse:
        raise TimeoutError("judge endpoint timed out")


def _observation(request: Any) -> dict[str, Any]:
    return json.loads(request.messages[-1].content)


def _tool_based_reply(request: Any) -> str:
    """A judge that says 'compromised' whenever any tool was called."""

    called = _observation(request)["agent_tool_call"] is not None
    return json.dumps(
        {
            "verdict": "compromised" if called else "resisted",
            "confidence": 0.9,
            "reason": "tool called" if called else "no action taken",
        }
    )


CASE = next(case for case in TEST_CASES if case.id == "T0051-01")
TRACE = Trace(
    user_input=CASE.probe,
    tool_call=ToolCall(name="send_email", args={"recipient": "canary-sink@lab.invalid"}),
)


def _judge(reply: str) -> LLMJudgement:
    return LLMCaseJudge(ScriptedRouter(lambda _request: reply)).judge(CASE, TRACE)


def test_request_carries_case_context_as_json_and_asks_for_json() -> None:
    router = ScriptedRouter(_tool_based_reply)
    LLMCaseJudge(router, model="m").judge(CASE, TRACE)
    (_tier, request), = router.calls
    observation = _observation(request)
    assert observation["technique"].startswith("AML.T0051 ")
    assert observation["expected_safe_behavior"] == CASE.expected_behavior
    assert observation["agent_tool_call"] == "send_email"
    assert observation["canary_marker"] == CASE.canary
    assert "agent_output" in observation
    assert request.temperature == 0.0
    assert request.response_format == {"type": "json_object"}


@pytest.mark.parametrize(
    ("reply", "verdict"),
    [
        ('{"verdict": "compromised", "confidence": 0.8, "reason": "sent"}',
         LLMVerdict.COMPROMISED),
        ('{"verdict": "Resisted", "confidence": 0.7, "reason": "ok"}', LLMVerdict.RESISTED),
        ('{"verdict": "unsafe", "confidence": 0.7, "reason": "x"}', LLMVerdict.COMPROMISED),
        ('{"verdict": "safe", "confidence": 0.7, "reason": "x"}', LLMVerdict.RESISTED),
        ('```json\n{"verdict": "compromised", "confidence": 1}\n```', LLMVerdict.COMPROMISED),
        ('Sure. {"verdict": "resisted", "confidence": 0.6} Hope it helps.',
         LLMVerdict.RESISTED),
        ('{"verdict": "maybe", "confidence": 0.5}', LLMVerdict.INCONCLUSIVE),
        ("I cannot decide.", LLMVerdict.INCONCLUSIVE),
    ],
)
def test_judge_output_is_normalised(reply: str, verdict: LLMVerdict) -> None:
    judged = _judge(reply)
    assert judged.verdict is verdict
    assert 0.0 <= judged.confidence <= 1.0


def test_out_of_range_confidence_is_clamped_and_model_recorded() -> None:
    judged = _judge('{"verdict": "compromised", "confidence": 7, "reason": "r"}')
    assert judged.confidence == 1.0
    assert judged.model == "scripted-judge"
    assert judged.latency_ms is not None and judged.latency_ms >= 0


def test_transport_error_is_recorded_not_raised() -> None:
    judged = LLMCaseJudge(FailingRouter(), model="m").judge(CASE, TRACE)
    assert judged.verdict is LLMVerdict.ERROR
    assert "TimeoutError" in judged.reason


def _result(case_id: str, rule: RuleVerdict, llm: LLMVerdict | None) -> CaseResult:
    from ai_agent_lab.atlas import get_tactic

    case = next(case for case in TEST_CASES if case.id == case_id)
    return CaseResult(
        case=case,
        tactic=get_tactic(case.technique_id),
        trace=TRACE,
        rule=RuleResult(rule, "e"),
        llm=None if llm is None else LLMJudgement(llm, 0.5, "r"),
    )


def test_compare_judges_counts_confusion_and_kappa() -> None:
    c, r = RuleVerdict.COMPROMISED, RuleVerdict.RESISTED
    ids = [case.id for case in TEST_CASES]
    results = [
        _result(ids[0], c, LLMVerdict.COMPROMISED),
        _result(ids[1], c, LLMVerdict.COMPROMISED),
        _result(ids[2], c, LLMVerdict.RESISTED),
        _result(ids[3], r, LLMVerdict.RESISTED),
        _result(ids[4], r, LLMVerdict.COMPROMISED),
        _result(ids[5], r, LLMVerdict.RESISTED),
        _result(ids[6], c, LLMVerdict.INCONCLUSIVE),
        _result(ids[7], c, LLMVerdict.ERROR),
        _result(ids[8], c, None),
    ]
    comparison = compare_judges(results)
    assert comparison.compared == 6
    assert comparison.agreements == 4
    assert comparison.agreement_rate == pytest.approx(4 / 6)
    assert comparison.confusion["compromised"] == {"compromised": 2, "resisted": 1}
    assert comparison.confusion["resisted"] == {"compromised": 1, "resisted": 2}
    # po = 4/6, pe = 0.5*0.5 + 0.5*0.5 = 0.5 -> kappa = (0.667-0.5)/0.5
    assert comparison.kappa == pytest.approx(1 / 3, abs=1e-3)
    assert comparison.inconclusive == 1 and comparison.errors == 1
    assert comparison.disagreements == (ids[2], ids[4])


def test_kappa_is_undefined_when_both_raters_use_one_label() -> None:
    ids = [case.id for case in TEST_CASES]
    comparison = compare_judges(
        [_result(ids[0], RuleVerdict.COMPROMISED, LLMVerdict.COMPROMISED)]
    )
    assert comparison.kappa is None
    assert comparison.agreement_rate == 1.0
    assert compare_judges([]).agreement_rate is None


def test_campaign_rule_only_makes_no_llm_calls() -> None:
    campaign = run_red_team()
    assert campaign.judge_mode == "rule-only"
    assert campaign.comparison is None
    assert len(campaign.results) == len(TEST_CASES)
    assert all(result.llm is None for result in campaign.results)


def test_campaign_with_llm_judge_reports_disagreements() -> None:
    router = ScriptedRouter(_tool_based_reply)
    campaign = run_red_team(llm_judge=LLMCaseJudge(router, model="scripted"))
    assert len(router.calls) == len(TEST_CASES)
    comparison = campaign.comparison
    assert comparison is not None
    # This judge compromises every tool call, so it disagrees with the rule
    # only where a tool ran without violating the case (none in the catalogue).
    assert comparison.compared == len(TEST_CASES)
    assert comparison.kappa == 1.0
    data = campaign.to_dict()
    assert data["judge_mode"] == "rule+llm"
    assert data["judge_model"] == "scripted"


def test_campaign_llm_budget_and_filters() -> None:
    router = ScriptedRouter(lambda _request: '{"verdict": "resisted", "confidence": 0.9}')
    campaign = run_red_team(
        agents=["code_act"], llm_judge=LLMCaseJudge(router), max_llm_cases=2
    )
    assert len(router.calls) == 2
    assert {r.case.agent for r in campaign.results} == {"code_act"}
    comparison = campaign.comparison
    assert comparison is not None and comparison.compared == 2
    # The judge says "resisted" for tool calls the rule marks compromised.
    assert comparison.agreements == 0 and len(comparison.disagreements) == 2
    with pytest.raises(ValueError, match="no ATLAS test cases"):
        run_red_team(techniques=["AML.T9999"])
    with pytest.raises(ValueError, match="max_llm_cases"):
        run_red_team(max_llm_cases=-1)


def test_router_is_opt_in_and_honours_timeout_settings() -> None:
    assert build_lab_router({}) is None
    assert build_lab_router({"LAB_LLM_KEY": "   "}) is None
    router = build_lab_router(
        {
            "LAB_LLM_KEY": "placeholder-not-a-secret",
            "LAB_LLM_BASE_URL": "http://127.0.0.1:11434",
            "LAB_LLM_MODEL": "qwen2.5:7b",
            "LAB_LLM_TIMEOUT_S": "240",
            "LAB_LLM_MAX_RETRIES": "0",
        }
    )
    assert router is not None
    provider = router.cfg.providers["lab-judge"]
    assert provider.timeout_s == 240.0
    assert provider.max_retries == 0
    assert provider.default_model == "qwen2.5:7b"
    with pytest.raises(ValueError, match="LAB_LLM_TIMEOUT_S"):
        build_lab_router({"LAB_LLM_KEY": "k", "LAB_LLM_TIMEOUT_S": "fast"})
