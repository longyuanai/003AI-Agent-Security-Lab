"""The judge must survive the ways a real model misses "JSON only".

Every case here crashed `RouterLabJudge` before: out-of-range confidence,
non-numeric confidence, prose instead of JSON, and a trailing sentence after
the object. With a live model those are ordinary outputs, so each one used to
turn a whole ATLAS iteration into an error record.
"""

from __future__ import annotations

import json

import pytest
from shared_llm_core import ChatChoice, ChatMessage, ChatResponse, ChatUsage

from ai_agent_lab.datatypes import ToolCall, Trace, Verdict
from ai_agent_lab.judge import RouterLabJudge
from ai_agent_lab.runner import run_atlas_tactic


class _CannedRouter:
    def __init__(self, body: str) -> None:
        self.body = body

    def chat(self, tier, request):  # noqa: ANN001, ANN201 - test double
        del tier, request
        return ChatResponse(
            id="canned",
            model="canned",
            created=0,
            usage=ChatUsage(),
            choices=[
                ChatChoice(
                    index=0,
                    finish_reason="stop",
                    message=ChatMessage(role="assistant", content=self.body),
                )
            ],
        )


def _judge(body: str):
    trace = Trace(
        user_input="payload",
        tool_call=ToolCall(name="tool", args={}),
        scenario_name="s",
        category="mitre_atlas",
    )
    return RouterLabJudge(_CannedRouter(body)).judge(trace)


@pytest.mark.parametrize(
    ("reported", "expected"),
    [
        (0.9, 0.9),
        (1.5, 1.0),      # over-confident, clamped rather than fatal
        (-0.2, 0.0),
        ("high", 0.5),   # non-numeric falls back
        (None, 0.5),
        (float("nan"), 0.5),
    ],
)
def test_confidence_is_coerced_into_range(reported, expected) -> None:
    body = json.dumps(
        {"verdict": "safe", "confidence": reported, "reason": "r"}
    )
    assert _judge(body).confidence == expected


def test_missing_confidence_uses_the_default() -> None:
    assert _judge(json.dumps({"verdict": "safe", "reason": "r"})).confidence == 0.5


@pytest.mark.parametrize(
    "body",
    [
        '{"verdict":"safe","confidence":0.1,"reason":"r"} hope that helps',
        'Sure! {"verdict":"safe","confidence":0.1,"reason":"r"}',
        '```json\n{"verdict":"safe","confidence":0.1,"reason":"r"}\n```',
    ],
)
def test_json_is_recovered_from_surrounding_prose(body: str) -> None:
    result = _judge(body)
    assert result.verdict is Verdict.SAFE
    assert result.confidence == 0.1


def test_braces_inside_a_string_do_not_truncate_the_scan() -> None:
    body = '{"verdict":"safe","confidence":0.2,"reason":"use {} with care"}'
    assert _judge(body).reason == "use {} with care"


@pytest.mark.parametrize("body", ["I think this is malicious.", "", "   "])
def test_unparseable_output_is_inconclusive_not_fatal(body: str) -> None:
    result = _judge(body)
    assert result.verdict is Verdict.SUSPICIOUS
    assert "unparseable" in result.reason
    # The raw text is retained so the evidence file still shows what came back.
    assert "unparsed" in result.raw


def test_invalid_verdict_string_falls_back_to_suspicious() -> None:
    body = json.dumps({"verdict": "totally fine", "confidence": 0.4})
    assert _judge(body).verdict is Verdict.SUSPICIOUS


def test_transport_errors_still_propagate() -> None:
    # Only *parsing* degrades gracefully; a dead endpoint must stay visible
    # so the runner records it as an iteration error.
    class _Dead:
        def chat(self, tier, request):  # noqa: ANN001, ANN201
            raise ConnectionError("upstream unreachable")

    trace = Trace(user_input="p", tool_call=ToolCall(name="t", args={}))
    with pytest.raises(ConnectionError):
        RouterLabJudge(_Dead()).judge(trace)


def test_atlas_run_records_a_verdict_instead_of_an_error_for_prose() -> None:
    run = run_atlas_tactic(
        "AML.T0051",
        agent="sql_assistant",
        iterations=3,
        judge=RouterLabJudge(_CannedRouter("not json at all")),
        seed=1,
    )
    assert [record.error for record in run.records] == [None, None, None]
    assert all(record.judge is not None for record in run.records)
