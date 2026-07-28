"""Tests for 5 Agent × 13 Attack ASR evaluation."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from ai_agent_lab.cli import cli
from ai_agent_lab.metrics import (
    evaluate_asr,
    render_asr_markdown,
    write_asr_reports,
)


def test_default_asr_evaluates_sixty_five_combinations():
    report = evaluate_asr()
    assert len(report.records) == 65
    assert report.summary.total == 65
    assert len(report.by_agent) == 5
    assert len(report.by_attack) == 13


def test_each_agent_and_attack_has_complete_dimension_counts():
    report = evaluate_asr()
    assert all(item.total == 13 for item in report.by_agent.values())
    assert all(item.total == 5 for item in report.by_attack.values())


def test_each_attack_succeeds_against_at_least_one_target():
    report = evaluate_asr()
    assert all(item.successes >= 1 for item in report.by_attack.values())


def test_default_asr_summary_is_expected():
    report = evaluate_asr()
    assert report.summary.successes == 14
    assert report.summary.asr == 14 / 65


def test_metric_records_include_detector_and_latency():
    report = evaluate_asr()
    assert all(record.detector for record in report.records)
    assert all(record.detector_verdict == "malicious" for record in report.records)
    assert all(record.detector_modes for record in report.records)
    assert all(record.latency_ms >= 0 for record in report.records)


def test_render_asr_markdown_contains_required_table():
    markdown = render_asr_markdown(
        evaluate_asr(),
        generated_at="2026-07-24T00:00:00",
    )
    assert "Combinations: **65**" in markdown
    assert "Successful attacks: **14**" in markdown
    assert "Overall ASR: **21.5%**" in markdown
    assert "| Agent | Attack | Success | Detector | Latency (ms) |" in markdown
    assert "sqli-helper" in markdown
    assert "code-act-privilege" in markdown


def test_write_asr_reports_outputs_markdown_and_json(tmp_path: Path):
    md_path, json_path = write_asr_reports(
        evaluate_asr(),
        markdown_path=tmp_path / "asr.md",
        json_path=tmp_path / "asr.json",
    )
    assert "## ASR by Agent" in md_path.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["summary"]["total"] == 65
    assert len(payload["records"]) == 65


def test_cli_metrics_writes_both_formats(tmp_path: Path):
    markdown_path = tmp_path / "cli-asr.md"
    json_path = tmp_path / "cli-asr.json"
    result = CliRunner().invoke(
        cli,
        [
            "metrics",
            "--markdown",
            str(markdown_path),
            "--json",
            str(json_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Combinations: 65" in result.output
    assert "Successful: 14" in result.output
    assert "ASR: 21.5%" in result.output
    assert markdown_path.exists()
    assert json_path.exists()
