"""v0.5 §7 LabMission orchestration tests."""

from __future__ import annotations

import time
from dataclasses import FrozenInstanceError

import pytest
from shared_llm_core import ChatChoice, ChatMessage, ChatResponse, ChatUsage
from shared_llm_core.multi_agent import (
    AgentResult,
    AgentRole,
    MissionContext,
    MultiAgentOrchestrator,
)

from ai_agent_lab.orchestrator import LAB_MISSION_ROLES, LabMission


class RecordingRouter:
    def __init__(
        self,
        *,
        fail_role: AgentRole | None = None,
        delay_s: float = 0.0,
    ) -> None:
        self.fail_role = fail_role
        self.delay_s = delay_s
        self.prompts: list[str] = []

    def chat(self, tier, request):
        del tier
        prompt = request.messages[0].content
        self.prompts.append(prompt)
        role = AgentRole(prompt.splitlines()[0].removeprefix("Role: "))
        if self.delay_s:
            time.sleep(self.delay_s)
        if role is self.fail_role:
            raise RuntimeError(f"{role.value} fixture failure")
        return ChatResponse(
            id=f"mission-{role.value}",
            model="mission-stub",
            created=0,
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatMessage(
                        role="assistant",
                        content=f"output-{role.value}",
                    ),
                    finish_reason="stop",
                )
            ],
            usage=ChatUsage(),
        )


def run_lab_mission(router: RecordingRouter | None = None) -> list[AgentResult]:
    return LabMission(router or RecordingRouter()).run_indirect_injection(
        "sql_assistant",
        2,
    )


def test_lab_mission_dispatches_all_five_roles() -> None:
    results = run_lab_mission()
    assert [result.role for result in results] == list(LAB_MISSION_ROLES)
    assert len(results) == 5


def test_scout_and_analyst_run_first_in_order() -> None:
    results = run_lab_mission()
    assert [result.role for result in results[:2]] == [
        AgentRole.SCOUT,
        AgentRole.ANALYST,
    ]


def test_synthesizer_and_reviewer_run_last() -> None:
    results = run_lab_mission()
    assert [result.role for result in results[-2:]] == [
        AgentRole.SYNTHESIZER,
        AgentRole.REVIEWER,
    ]


def test_scratchpad_is_append_only_and_visible_to_later_roles() -> None:
    router = RecordingRouter()
    mission = MissionContext(
        task="fixture mission",
        inputs={"agent": "sql_assistant"},
        scratchpad=("seed",),
    )
    MultiAgentOrchestrator(router).run(
        mission,
        [AgentRole.SCOUT, AgentRole.ANALYST],
    )

    assert mission.scratchpad == ("seed",)
    assert "- seed" in router.prompts[0]
    assert "- [scout] output-scout" in router.prompts[1]


def test_failed_agent_sets_error_and_does_not_raise() -> None:
    results = run_lab_mission(RecordingRouter(fail_role=AgentRole.ANALYST))
    assert results[1].role is AgentRole.ANALYST
    assert results[1].error == "RuntimeError: analyst fixture failure"
    assert results[1].output == ""
    assert len(results) == 5


def test_mission_continues_to_reviewer_after_agent_failure() -> None:
    results = run_lab_mission(RecordingRouter(fail_role=AgentRole.EXPLOITER))
    assert results[2].error is not None
    assert results[-1].role is AgentRole.REVIEWER
    assert results[-1].error is None


def test_latency_ms_is_positive() -> None:
    results = run_lab_mission(RecordingRouter())
    assert all(result.latency_ms > 0 for result in results)


def test_mission_context_is_frozen() -> None:
    mission = MissionContext(task="fixture", inputs={"agent": "sql_assistant"})
    with pytest.raises(FrozenInstanceError):
        mission.inputs = {}  # type: ignore[misc]


def test_empty_roles_returns_zero_results() -> None:
    mission = MissionContext(task="fixture", inputs={})
    results = MultiAgentOrchestrator(RecordingRouter()).run(mission, [])
    assert results == []


def test_single_role_returns_one_result() -> None:
    mission = MissionContext(task="fixture", inputs={})
    results = MultiAgentOrchestrator(RecordingRouter()).run(
        mission,
        [AgentRole.SCOUT],
    )
    assert len(results) == 1
    assert results[0].role is AgentRole.SCOUT


def test_lab_mission_inputs_reach_every_role_prompt() -> None:
    router = RecordingRouter()
    run_lab_mission(router)
    assert all("- agent: 'sql_assistant'" in prompt for prompt in router.prompts)
    assert all("- attack: 'indirect_injection'" in prompt for prompt in router.prompts)
    assert all("- iterations: 2" in prompt for prompt in router.prompts)


def test_each_successful_role_output_reaches_next_prompt() -> None:
    router = RecordingRouter()
    run_lab_mission(router)
    assert "[scout] output-scout" in router.prompts[1]
    assert "[analyst] output-analyst" in router.prompts[2]
    assert "[exploiter] output-exploiter" in router.prompts[3]
    assert "[synthesizer] output-synthesizer" in router.prompts[4]


def test_lab_mission_returns_shared_agent_result_type() -> None:
    assert all(isinstance(result, AgentResult) for result in run_lab_mission())
