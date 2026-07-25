"""Cross-scenario Finding correlation and Markdown reporting."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from ai_agent_lab.scenarios import evaluate_demo_scenarios
from ai_agent_lab.v05_compat import (
    Finding,
    FindingRegistry,
    FindingSeverity,
)


_SEVERITY_RANK = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}


@dataclass(frozen=True)
class TargetCorrelation:
    """Multiple scenario findings linked through one target."""

    target: str
    finding_ids: tuple[str, ...]
    scenarios: tuple[str, ...]
    severity: FindingSeverity

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "finding_ids": list(self.finding_ids),
            "scenarios": list(self.scenarios),
            "severity": self.severity.value,
        }


@dataclass(frozen=True)
class CrossScenarioReport:
    findings: tuple[Finding, ...]
    correlations: tuple[TargetCorrelation, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "correlations": [
                correlation.to_dict() for correlation in self.correlations
            ],
        }


def register_findings(
    findings: Iterable[Finding],
    *,
    registry: FindingRegistry | None = None,
) -> FindingRegistry:
    active_registry = registry or FindingRegistry()
    for finding in findings:
        active_registry.add(finding)
    return active_registry


def build_correlation_report(registry: FindingRegistry) -> CrossScenarioReport:
    findings = tuple(registry.query(limit=registry.max_size))
    return CrossScenarioReport(
        findings=findings,
        correlations=tuple(_correlate_by_target(findings)),
    )


def build_demo_correlation_report(
    target: str = "lab-target-01",
) -> CrossScenarioReport:
    registry = register_findings(evaluate_demo_scenarios(target))
    return build_correlation_report(registry)


def render_correlation_markdown(
    report: CrossScenarioReport,
    *,
    generated_at: str | None = None,
) -> str:
    when = generated_at or datetime.now().isoformat(timespec="seconds")
    lines = [
        "# AI Agent Security Lab · Cross-Scenario Correlation Report",
        "",
        f"_Generated at {when}_",
        "",
        "## Summary",
        "",
        f"- Findings: **{len(report.findings)}**",
        f"- Correlated targets: **{len(report.correlations)}**",
        "",
        "## Findings",
        "",
        "| Target | Scenario | Severity | Confidence | Title |",
        "|--------|----------|----------|------------|-------|",
    ]
    for finding in report.findings:
        scenario = finding.metadata.get("scenario", "unknown")
        lines.append(
            f"| `{finding.host or '-'}` | `{scenario}` | "
            f"{finding.severity.value} | {finding.confidence:.0%} | "
            f"{finding.title} |"
        )

    lines.extend(["", "## Correlated Targets", ""])
    if not report.correlations:
        lines.append("_No target is affected by multiple scenarios._")
    for correlation in report.correlations:
        lines.extend(
            [
                f"### `{correlation.target}`",
                "",
                f"- Highest severity: **{correlation.severity.value}**",
                f"- Linked scenarios: **{len(correlation.scenarios)}**",
                "",
            ]
        )

    lines.extend(["## Correlation Graph", "", "```text"])
    if not report.correlations:
        lines.append("(no cross-scenario edges)")
    for correlation in report.correlations:
        lines.append(f"{correlation.target} [{correlation.severity.value}]")
        for index, scenario in enumerate(correlation.scenarios):
            branch = "└──" if index == len(correlation.scenarios) - 1 else "├──"
            finding_id = correlation.finding_ids[index]
            lines.append(f"{branch} {scenario} ({finding_id})")
    lines.extend(["```", ""])
    return "\n".join(lines)


def write_correlation_markdown(
    report: CrossScenarioReport,
    output: str | Path,
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_correlation_markdown(report), encoding="utf-8")
    return path


def _correlate_by_target(
    findings: Iterable[Finding],
) -> list[TargetCorrelation]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.host:
            grouped.setdefault(finding.host, []).append(finding)

    correlations: list[TargetCorrelation] = []
    for target, target_findings in grouped.items():
        by_scenario: dict[str, Finding] = {}
        for finding in target_findings:
            scenario = str(finding.metadata.get("scenario", "unknown"))
            by_scenario.setdefault(scenario, finding)
        if len(by_scenario) < 2:
            continue
        linked = list(by_scenario.items())
        severity = max(
            (finding.severity for _, finding in linked),
            key=_SEVERITY_RANK.__getitem__,
        )
        correlations.append(
            TargetCorrelation(
                target=target,
                finding_ids=tuple(finding.id for _, finding in linked),
                scenarios=tuple(scenario for scenario, _ in linked),
                severity=severity,
            )
        )
    return correlations
