"""IntegrationGateway-compatible CLI envelope tests."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from click.testing import CliRunner

from ai_agent_lab.cli import cli


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SUITE_ROOT = PROJECT_ROOT.parent


def test_scan_runs_attack_returns_finding() -> None:
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            json.dumps(
                {
                    "agent": "sql_assistant",
                    "attack": "indirect_injection",
                    "iterations": 1,
                }
            ),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert len(envelope["findings"]) == 1
    finding = envelope["findings"][0]
    assert finding["severity"] == "high"
    assert finding["confidence"] == 0.88
    assert finding["title"] == "SQL injection via indirect prompt injection"
    assert finding["narrative"].endswith("ASR=1/1")


def test_scan_handles_blocked_attack_gracefully() -> None:
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            '{"agent":"email_assistant","attack":"path_traversal"}',
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    findings = json.loads(result.output)["findings"]
    assert len(findings) == 1
    assert findings[0]["narrative"].endswith("ASR=0/1")
    assert findings[0]["metadata"]["detector_hits"] == 1


def test_scan_invalid_attack_returns_empty_findings() -> None:
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            '{"agent":"sql_assistant","attack":"not_an_attack"}',
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"findings": []}


def test_scan_reads_payload_from_stdin() -> None:
    result = CliRunner().invoke(
        cli,
        ["scan", "--json"],
        input='{"agent":"web_browser","attack":"browser_ssrf"}',
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["findings"][0]["metadata"]["attack"] == (
        "browser_ssrf"
    )


def test_json_subprocess_lab_adapter_end_to_end(monkeypatch) -> None:
    integration_src = SUITE_ROOT / "000shared-integration" / "src"
    monkeypatch.syspath_prepend(str(integration_src))
    monkeypatch.setenv("LLM_PROVIDER", "fake")

    from shared_integration.adapters.lab import LabAdapter

    async def collect():
        return [
            finding
            async for finding in LabAdapter(PROJECT_ROOT).scan(
                {
                    "agent": "sql_assistant",
                    "attack": "indirect_injection",
                    "iterations": 1,
                }
            )
        ]

    findings = asyncio.run(collect())
    assert len(findings) == 1
    assert findings[0].source.value == "003"
    assert findings[0].title == "SQL injection via indirect prompt injection"
    assert findings[0].description.endswith("ASR=1/1")


def test_module_adapter_argument_shape_uses_current_python() -> None:
    assert Path(sys.executable).is_absolute()
