"""Real judge behavior through mocked routers/transports only."""

from __future__ import annotations

import json
import random

import httpx
from click.testing import CliRunner
from shared_llm_core import (
    ChatChoice,
    ChatMessage,
    ChatResponse,
    ChatUsage,
)

from ai_agent_lab.cli import cli
from ai_agent_lab.datatypes import ToolCall, Trace, Verdict
from ai_agent_lab.judge import (
    JudgeResult,
    RouterLabJudge,
    StubLabJudge,
    build_lab_judge,
)
from ai_agent_lab.runner import atlas_run_to_envelope, run_atlas_tactic


class MockRouter:
    def __init__(self, body: dict[str, object]) -> None:
        self.body = body
        self.requests = []

    def chat(self, tier, request) -> ChatResponse:
        self.requests.append((tier, request))
        return ChatResponse(
            id="mock-judge",
            model="mock-model",
            created=0,
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatMessage(
                        role="assistant",
                        content=json.dumps(self.body),
                    ),
                    finish_reason="stop",
                )
            ],
            usage=ChatUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
        )


def fixture_trace() -> Trace:
    return Trace(
        user_input="[SAFE LAB SIMULATION] fixture marker",
        tool_call=ToolCall(name="", args={}, result="fixture"),
        scenario_name="AML.T0051",
        category="mitre_atlas",
    )


def test_router_judge_parses_complete_mock_response() -> None:
    router = MockRouter(
        {"verdict": "malicious", "confidence": 0.91, "reason": "fixture hit"}
    )
    result = RouterLabJudge(router).judge(fixture_trace())
    assert result.verdict is Verdict.MALICIOUS
    assert result.confidence == 0.91
    assert result.reason == "fixture hit"
    assert result.raw["id"] == "mock-judge"
    assert result.raw["usage"]["total_tokens"] == 15
    assert len(router.requests) == 1


def test_httpx_mock_transport_exercises_shared_router_without_network() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        return httpx.Response(
            200,
            json={
                "id": "transport-judge",
                "model": "fixture-model",
                "created": 0,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(
                                {
                                    "verdict": "suspicious",
                                    "confidence": 0.82,
                                    "reason": "mock transport result",
                                }
                            ),
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 2,
                    "completion_tokens": 3,
                    "total_tokens": 5,
                },
            },
        )

    judge = build_lab_judge(
        {
            "LAB_LLM_KEY": "synthetic-test-key",
            "LAB_LLM_MODEL": "fixture-model",
            "LAB_LLM_BASE_URL": "https://fixture.invalid",
        }
    )
    router = judge._router  # noqa: SLF001 - inject transport into shared router
    client = router._clients["lab-judge"]  # noqa: SLF001
    client._http.close()  # noqa: SLF001
    client._http = httpx.Client(  # noqa: SLF001
        base_url="https://fixture.invalid",
        transport=httpx.MockTransport(handler),
    )
    try:
        result = judge.judge(fixture_trace())
    finally:
        router.close()
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.confidence == 0.82
    assert result.raw["id"] == "transport-judge"


def test_atlas_runner_uses_mock_judge_for_every_iteration() -> None:
    judge = RouterLabJudge(
        MockRouter(
            {"verdict": "suspicious", "confidence": 0.8, "reason": "mocked"}
        )
    )
    run = run_atlas_tactic(
        "AML.T0051",
        agent="sql_assistant",
        iterations=3,
        judge=judge,
        rng=random.Random(1),
    )
    assert len(run.records) == 3
    assert all(record.judge and record.judge.mode == "live" for record in run.records)


def test_failing_judge_is_recorded_without_raising() -> None:
    class FailingJudge:
        mode = "live"

        def judge(self, trace):
            raise RuntimeError("mock outage")

    run = run_atlas_tactic(
        "AML.T0051",
        agent="sql_assistant",
        iterations=2,
        judge=FailingJudge(),
        rng=random.Random(2),
    )
    assert all(record.judge is None for record in run.records)
    assert all(record.error == "RuntimeError: mock outage" for record in run.records)
    envelope = atlas_run_to_envelope(run)
    assert envelope["findings"] == []
    assert len(envelope["errors"]) == 2


def test_stub_judge_raw_data_contains_no_conversation_history() -> None:
    result = StubLabJudge().judge(fixture_trace())
    serialized = json.dumps(result.to_dict())
    assert "conversation" not in serialized.lower()
    assert "messages" not in serialized.lower()


def test_atlas_envelope_contains_summary_and_judge_metadata() -> None:
    run = run_atlas_tactic(
        "AML.T0051",
        agent="email_assistant",
        iterations=1,
        judge=StubLabJudge(),
        rng=random.Random(4),
    )
    envelope = atlas_run_to_envelope(run)
    assert envelope["summary"]["judge_mode"] == "stub"
    assert envelope["summary"]["iterations"] == 1
    assert envelope["findings"][0]["metadata"]["judge"]["mode"] == "stub"


def test_cli_atlas_scan_uses_mocked_live_judge(monkeypatch, tmp_path) -> None:
    mocked = RouterLabJudge(
        MockRouter(
            {"verdict": "suspicious", "confidence": 0.84, "reason": "CLI mock"}
        )
    )
    monkeypatch.setattr("ai_agent_lab.runner.build_lab_judge", lambda: mocked)
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            '{"attack":"AML.T0051","agent":"sql_assistant","iterations":2}',
            "--json",
            "--report",
            str(tmp_path / "mock-live.md"),
        ],
    )
    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert envelope["summary"]["judge_mode"] == "live"
    assert len(envelope["findings"]) == 2


def test_judge_result_rejects_out_of_range_confidence() -> None:
    try:
        JudgeResult(
            verdict=Verdict.SAFE,
            confidence=1.1,
            reason="invalid fixture",
            mode="stub",
        )
    except ValueError as exc:
        assert "between 0 and 1" in str(exc)
    else:
        raise AssertionError("out-of-range confidence must fail")
