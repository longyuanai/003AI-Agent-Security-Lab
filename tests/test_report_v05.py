"""Tests for REPORT-003-A Finding correlation reports."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from ai_agent_lab.cli import cli
from ai_agent_lab.report import (
    build_correlation_report,
    build_demo_correlation_report,
    register_findings,
    render_correlation_markdown,
)
from ai_agent_lab.scenarios import evaluate_demo_scenarios
from ai_agent_lab.v05_compat import (
    Finding,
    FindingRegistry,
    FindingSeverity,
    FindingSource,
)


def test_registry_queries_lab_findings_by_host():
    registry = register_findings(evaluate_demo_scenarios("target-a"))
    findings = registry.query(source=FindingSource.LAB, host="target-a")
    assert len(findings) == 5
    assert all(finding.host == "target-a" for finding in findings)


def test_same_target_across_scenarios_is_automatically_correlated():
    report = build_demo_correlation_report("shared-target")
    assert len(report.correlations) == 1
    correlation = report.correlations[0]
    assert correlation.target == "shared-target"
    assert len(correlation.scenarios) == 5
    assert correlation.severity == FindingSeverity.CRITICAL


def test_different_single_scenario_targets_are_not_correlated():
    findings = []
    for index, finding in enumerate(evaluate_demo_scenarios("placeholder")):
        payload = finding.to_dict()
        payload["host"] = f"target-{index}"
        findings.append(Finding.from_dict(payload))
    report = build_correlation_report(register_findings(findings))
    assert report.correlations == ()


def test_markdown_contains_text_correlation_graph():
    markdown = render_correlation_markdown(
        build_demo_correlation_report("graph-target"),
        generated_at="2026-07-24T00:00:00",
    )
    assert "## Correlation Graph" in markdown
    assert "graph-target [critical]" in markdown
    assert "├── mcp-server-abuse" in markdown
    assert "└── npm-typosquat-supply-chain" in markdown


def test_finding_roundtrip_ignores_unknown_fields():
    original = evaluate_demo_scenarios("roundtrip-target")[0]
    payload = original.to_dict()
    payload["future_field"] = "ignored"
    restored = Finding.from_dict(payload)
    assert restored == original
    uuid.UUID(restored.id)


def test_finding_rejects_invalid_confidence():
    with pytest.raises(ValueError, match="confidence"):
        Finding(
            id=str(uuid.uuid4()),
            source=FindingSource.LAB,
            severity=FindingSeverity.HIGH,
            confidence=1.1,
            title="invalid",
            ts=datetime.now(timezone.utc),
        )


def test_registry_enforces_max_size():
    registry = FindingRegistry(max_size=2)
    findings = evaluate_demo_scenarios("bounded-target")
    for finding in findings:
        registry.add(finding)
    assert registry.query(limit=10) == findings[-2:]


def test_cli_writes_cross_scenario_report(tmp_path: Path):
    output = tmp_path / "correlation.md"
    result = CliRunner().invoke(
        cli,
        ["correlation-report", "--output", str(output)],
    )
    assert result.exit_code == 0, result.output
    assert "Findings: 5" in result.output
    assert "Correlated targets: 1" in result.output
    body = output.read_text(encoding="utf-8")
    assert "Cross-Scenario Correlation Report" in body
    assert "lab-target-01 [critical]" in body
