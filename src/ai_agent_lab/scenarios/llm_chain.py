"""Chained LLM prompt-injection attack scenario."""

from __future__ import annotations

from ai_agent_lab.v05_compat import (
    Finding,
    FindingSeverity,
    FindingSource,
    Rule,
    RuleContext,
    RuleRegistry,
    new_finding_id,
)


RULE_ID = "003-llm-prompt-injection-chain"


class LLMPromptInjectionChainRule(Rule):
    id = RULE_ID
    severity_hint = "critical"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        stages = tuple(str(stage) for stage in ctx.facts.get("stages", ()))
        required = {"indirect_injection", "tool_hijack", "data_exfiltration"}
        if not required.issubset(stages):
            return []
        return [
            Finding(
                id=new_finding_id(),
                source=FindingSource.LAB,
                severity=FindingSeverity.CRITICAL,
                confidence=0.99,
                title="Prompt injection chained into tool hijack and exfiltration",
                description=(
                    "Untrusted retrieved content crossed planning and tool boundaries "
                    "before reaching an external data sink."
                ),
                host=ctx.subject,
                evidence=tuple(f"stage={stage}" for stage in stages),
                tags=frozenset(
                    {"llm-chain", "prompt-injection", "tool-misuse", "exfiltration"}
                ),
                metadata={
                    "scenario": "llm-prompt-injection-chain",
                    "chain_length": len(stages),
                },
            )
        ]


def register(registry: RuleRegistry) -> LLMPromptInjectionChainRule:
    rule = LLMPromptInjectionChainRule()
    registry.register(rule)
    return rule


def demo_context(subject: str = "lab-target-01") -> RuleContext:
    return RuleContext(
        subject=subject,
        facts={
            "stages": (
                "indirect_injection",
                "planner_override",
                "tool_hijack",
                "data_exfiltration",
            )
        },
    )


def benign_context(subject: str = "lab-target-01") -> RuleContext:
    return RuleContext(
        subject=subject,
        facts={"stages": ("retrieval", "validated_summary")},
    )
