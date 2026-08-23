"""Commercial Markdown benchmark report tests."""

from __future__ import annotations

import hashlib

from ai_agent_lab.benchmark_metrics import evaluate_task_benchmark
from ai_agent_lab.report.benchmark_evidence import build_benchmark_evidence
from ai_agent_lab.report.benchmark_markdown import (
    render_benchmark_markdown,
    write_benchmark_markdown,
)


def _evidence() -> dict[str, object]:
    return build_benchmark_evidence(
        evaluate_task_benchmark(),
        generated_at="2026-08-01T08:00:00+00:00",
        seed=2026,
    )


def test_report_contains_manifest_summary_and_all_dimensions() -> None:
    report = render_benchmark_markdown(_evidence())
    assert "# AI Agent Security Benchmark Report" in report
    assert "## Run Manifest" in report
    assert "## Executive Summary" in report
    assert "## Results by Agent" in report
    assert "## Results by Attack" in report
    assert "## Results by Delivery Strategy" in report
    assert "## Objective Evidence" in report


def test_report_explains_oracle_detector_and_judge_separation() -> None:
    report = render_benchmark_markdown(_evidence())
    assert "objective state-effect Oracle" in report
    assert "Detector and Judge results are independent" in report
    assert "Judge/objective agreement" in report


def test_report_contains_each_agent_and_objective_boundary() -> None:
    report = render_benchmark_markdown(_evidence())
    for agent in (
        "sql_assistant",
        "email_assistant",
        "file_rag",
        "web_browser",
        "code_act",
    ):
        assert agent in report
    assert "unscoped_query" in report
    assert "external_recipient" in report
    assert "restricted_network" in report


def test_report_never_renders_input_or_conversation_content() -> None:
    report = render_benchmark_markdown(_evidence()).lower()
    forbidden = (
        "user_input",
        "input_text",
        "raw_prompt",
        "conversation_history",
        "authorization",
        "api_key",
    )
    assert not any(term in report for term in forbidden)


def test_report_render_is_deterministic_snapshot() -> None:
    first = render_benchmark_markdown(_evidence())
    second = render_benchmark_markdown(_evidence())
    assert first == second
    assert hashlib.sha256(first.encode("utf-8")).hexdigest() == (
        "d08ed66a5b66d338f3a00e06cd3ab499380fb56068483449c7996c26edc628a3"
    )


def test_report_writer_is_atomic_utf8_and_creates_parent(tmp_path) -> None:
    output = tmp_path / "nested" / "benchmark.md"
    path = write_benchmark_markdown(_evidence(), output)
    assert path == output
    assert path.read_text(encoding="utf-8").startswith(
        "# AI Agent Security Benchmark Report"
    )
    assert list(path.parent.glob("*.tmp")) == []
