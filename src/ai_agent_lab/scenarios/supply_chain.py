"""npm package-name impersonation supply-chain scenario."""

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


RULE_ID = "003-npm-typosquat-supply-chain"


class NpmTyposquatRule(Rule):
    id = RULE_ID
    severity_hint = "high"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        expected = str(ctx.facts.get("expected_package", ""))
        installed = str(ctx.facts.get("installed_package", ""))
        has_install_script = bool(ctx.facts.get("install_script"))
        distance = _edit_distance(expected, installed)
        if not expected or expected == installed or distance != 1 or not has_install_script:
            return []
        return [
            Finding(
                id=new_finding_id(),
                source=FindingSource.LAB,
                severity=FindingSeverity.HIGH,
                confidence=0.95,
                title="npm dependency is a one-character typosquat with install script",
                description=(
                    "The installed package closely impersonates the expected name "
                    "and executes lifecycle code during installation."
                ),
                host=ctx.subject,
                evidence=(
                    f"expected={expected}",
                    f"installed={installed}",
                    "install_script=true",
                ),
                tags=frozenset({"supply-chain", "npm", "typosquat"}),
                metadata={
                    "scenario": "npm-typosquat-supply-chain",
                    "registry": ctx.facts.get("registry", "fixture://npm"),
                },
            )
        ]


def register(registry: RuleRegistry) -> NpmTyposquatRule:
    rule = NpmTyposquatRule()
    registry.register(rule)
    return rule


def demo_context(subject: str = "lab-target-01") -> RuleContext:
    return RuleContext(
        subject=subject,
        facts={
            "expected_package": "express",
            "installed_package": "expres",
            "install_script": True,
            "registry": "fixture://npm",
        },
    )


def benign_context(subject: str = "lab-target-01") -> RuleContext:
    return RuleContext(
        subject=subject,
        facts={
            "expected_package": "express",
            "installed_package": "express",
            "install_script": False,
        },
    )


def _edit_distance(left: str, right: str) -> int:
    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_char in enumerate(right, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[right_index] + 1,
                    previous[right_index - 1] + (left_char != right_char),
                )
            )
        previous = current
    return previous[-1]
