"""Multi-agent MCP server abuse exercise for the authorized local lab."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ai_agent_lab.v05_compat import (
    AgentResult,
    AgentRole,
    MissionContext,
    MultiAgentOrchestrator,
)


MCP_ABUSE_ROLES: tuple[AgentRole, ...] = (
    AgentRole.SCOUT,
    AgentRole.ANALYST,
    AgentRole.EXPLOITER,
    AgentRole.REVIEWER,
)


@dataclass(frozen=True)
class MCPAbuseRun:
    mission: MissionContext
    results: tuple[AgentResult, ...]

    @property
    def verdict(self) -> str:
        reviewer = next(
            (result for result in self.results if result.role == AgentRole.REVIEWER),
            None,
        )
        return reviewer.output if reviewer and not reviewer.error else "review unavailable"


def build_mcp_abuse_mission() -> MissionContext:
    return MissionContext(
        task=(
            "Assess an authorized fixture MCP server whose tool description may "
            "contain indirect instructions and excessive secret-reading capability."
        ),
        inputs={
            "server": "fixture://mcp-poison",
            "canary": "lab-canary-only",
            "allowed_scope": "local fixture; no external network",
        },
        metadata={"scenario": "mcp-server-abuse", "authorized": True},
    )


def run_mcp_abuse(
    orchestrator: MultiAgentOrchestrator,
    mission: MissionContext | None = None,
) -> MCPAbuseRun:
    active_mission = mission or build_mcp_abuse_mission()
    return MCPAbuseRun(
        mission=active_mission,
        results=tuple(orchestrator.run(active_mission, MCP_ABUSE_ROLES)),
    )


class DeterministicMCPRouter:
    """Offline router used only by the CLI demo."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, Any]] = []

    def chat(self, tier: Any, req: Any) -> Any:
        from shared_llm_core import (
            ChatChoice,
            ChatMessage,
            ChatResponse,
            ChatUsage,
        )

        self.calls.append((tier, req))
        system = req.messages[0].content.lower()
        if "scout" in system:
            output = (
                "Target fixture://mcp-poison exposes search_docs and read_secret; "
                "scope is local fixture only."
            )
        elif "analyst" in system:
            output = (
                "The tool description mixes untrusted instructions with an "
                "over-broad read_secret capability."
            )
        elif "exploiter" in system:
            output = (
                "Safe canary validation confirms the poisoned description can "
                "request read_secret; no real secret or network was used."
            )
        else:
            output = (
                "VERDICT: critical MCP server abuse path confirmed in the fixture; "
                "require signed tool metadata and a strict capability allowlist."
            )
        return ChatResponse(
            id=f"mcp-demo-{len(self.calls)}",
            model="deterministic-mcp-demo",
            created=0,
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatMessage(role="assistant", content=output),
                    finish_reason="stop",
                )
            ],
            usage=ChatUsage(),
        )


def run_offline_mcp_abuse_demo() -> MCPAbuseRun:
    orchestrator = MultiAgentOrchestrator(DeterministicMCPRouter())
    return run_mcp_abuse(orchestrator)
