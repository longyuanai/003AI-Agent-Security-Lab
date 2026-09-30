"""Tests for MULTI-003-A MCP abuse orchestration."""

from __future__ import annotations

from shared_llm_core.multi_agent import (
    AgentRole,
    MissionContext,
    MultiAgentOrchestrator,
)

from ai_agent_lab.multi_agent import (
    MCP_ABUSE_ROLES,
    build_mcp_abuse_mission,
    run_mcp_abuse,
    run_offline_mcp_abuse_demo,
)


def test_mcp_mission_is_authorized_fixture():
    mission = build_mcp_abuse_mission()
    assert mission.inputs["server"] == "fixture://mcp-poison"
    assert mission.metadata["authorized"] is True
    assert "no external network" in mission.inputs["allowed_scope"]


def test_mcp_roles_follow_required_order():
    assert MCP_ABUSE_ROLES == (
        AgentRole.SCOUT,
        AgentRole.ANALYST,
        AgentRole.EXPLOITER,
        AgentRole.REVIEWER,
    )


def test_orchestrator_runs_all_roles_with_stub_router(stub_router):
    router = stub_router(
        {
            "verdict": "malicious",
            "category": "tool_misuse",
            "reason": "fixture output",
        }
    )
    run = run_mcp_abuse(MultiAgentOrchestrator(router))
    assert [result.role for result in run.results] == list(MCP_ABUSE_ROLES)
    assert all(result.error is None for result in run.results)
    assert len(router.calls) == 4


def test_scratchpad_is_append_only_and_visible_to_later_roles(stub_router):
    router = stub_router({"stage": "complete"})
    mission = MissionContext(
        task="authorized fixture",
        inputs={"target": "fixture://mcp"},
        scratchpad=("seed evidence",),
    )
    run_mcp_abuse(MultiAgentOrchestrator(router), mission)
    first_request = router.calls[0][1]
    second_request = router.calls[1][1]
    # The orchestrator packs role, task, scratchpad and inputs into one
    # user message.
    assert "seed evidence" in first_request.messages[0].content
    assert "[scout]" in second_request.messages[0].content
    assert mission.scratchpad == ("seed evidence",)


def test_agent_failure_is_recorded_and_mission_continues(stub_router):
    healthy = stub_router({"stage": "ok"})

    class FailOnceRouter:
        def __init__(self):
            self.calls = 0

        def chat(self, tier, req):
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("analyst unavailable")
            return healthy.chat(tier, req)

    results = MultiAgentOrchestrator(FailOnceRouter()).run(
        build_mcp_abuse_mission(),
        MCP_ABUSE_ROLES,
    )
    assert len(results) == 4
    assert "analyst unavailable" in results[1].error
    assert results[2].error is None
    assert results[3].error is None


def test_offline_demo_returns_reviewer_verdict():
    run = run_offline_mcp_abuse_demo()
    assert len(run.results) == 4
    assert "VERDICT: critical" in run.verdict
    assert all(result.latency_ms >= 0 for result in run.results)
