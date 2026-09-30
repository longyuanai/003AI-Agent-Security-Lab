"""Container escape followed by host compromise scenario."""

from __future__ import annotations

from shared_llm_core import (
    Finding,
    FindingSeverity,
    FindingSource,
    Rule,
    RuleContext,
    RuleRegistry,
)

from ai_agent_lab.datatypes import new_finding_id

RULE_ID = "003-container-escape-host-intrusion"


class ContainerEscapeRule(Rule):
    id = RULE_ID
    severity_hint = "critical"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        privileged = bool(ctx.facts.get("privileged"))
        host_mount = str(ctx.facts.get("host_mount", ""))
        host_action = str(ctx.facts.get("host_action", ""))
        escaped = host_mount in {"/", "C:\\"} and host_action in {
            "nsenter",
            "write_host_file",
            "host_process_access",
        }
        if not privileged or not escaped:
            return []
        return [
            Finding(
                id=new_finding_id(),
                source=FindingSource.LAB,
                severity=FindingSeverity.CRITICAL,
                confidence=0.99,
                title="Privileged container path reaches the host boundary",
                description=(
                    "A privileged workload combines a host-root mount with a "
                    "simulated host intrusion action."
                ),
                host=ctx.subject,
                evidence=(
                    "privileged=true",
                    f"host_mount={host_mount}",
                    f"host_action={host_action}",
                ),
                tags=frozenset(
                    {"container-escape", "host-intrusion", "privilege-escalation"}
                ),
                metadata={"scenario": "container-escape-host-intrusion"},
            )
        ]


def register(registry: RuleRegistry) -> ContainerEscapeRule:
    rule = ContainerEscapeRule()
    registry.register(rule)
    return rule


def demo_context(subject: str = "lab-target-01") -> RuleContext:
    return RuleContext(
        subject=subject,
        facts={
            "privileged": True,
            "host_mount": "/",
            "host_action": "nsenter",
        },
    )


def benign_context(subject: str = "lab-target-01") -> RuleContext:
    return RuleContext(
        subject=subject,
        facts={
            "privileged": False,
            "host_mount": "/workspace",
            "host_action": "none",
        },
    )
