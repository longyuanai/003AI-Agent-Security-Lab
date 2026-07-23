"""v0.5 RuleEngine-backed advanced attack scenarios."""

from __future__ import annotations

from ai_agent_lab.scenarios import (
    container_escape,
    llm_chain,
    mcp,
    supply_chain,
    web3,
)
from ai_agent_lab.v05_compat import Finding, RuleEngine, RuleRegistry


SCENARIO_MODULES = (mcp, web3, llm_chain, container_escape, supply_chain)


def build_scenario_registry() -> RuleRegistry:
    registry = RuleRegistry()
    for module in SCENARIO_MODULES:
        module.register(registry)
    return registry


def evaluate_demo_scenarios(subject: str = "lab-target-01") -> list[Finding]:
    registry = build_scenario_registry()
    engine = RuleEngine(registry)
    findings: list[Finding] = []
    for module in SCENARIO_MODULES:
        findings.extend(
            engine.evaluate(
                module.demo_context(subject),
                rule_ids=(module.RULE_ID,),
            )
        )
    return findings


__all__ = [
    "SCENARIO_MODULES",
    "build_scenario_registry",
    "container_escape",
    "evaluate_demo_scenarios",
    "llm_chain",
    "mcp",
    "supply_chain",
    "web3",
]
