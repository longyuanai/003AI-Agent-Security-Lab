"""Task benchmark ASR, utility, detector, and judge metric tests."""

from __future__ import annotations

from ai_agent_lab.benchmark_metrics import (
    BenchmarkRecord,
    evaluate_task_benchmark,
    summarize_benchmark,
)
from ai_agent_lab.judge import StubLabJudge


def test_default_benchmark_runs_five_controls_and_five_attacks() -> None:
    report = evaluate_task_benchmark(judge=StubLabJudge())
    assert len(report.records) == 10
    assert report.summary.dimension.attack_total == 5
    assert report.summary.dimension.benign_total == 5


def test_default_benchmark_reports_security_and_utility_separately() -> None:
    summary = evaluate_task_benchmark(judge=StubLabJudge()).summary
    assert summary.dimension.asr == 1.0
    assert summary.dimension.utility_rate == 1.0
    assert summary.false_refusals == 0
    assert summary.false_refusal_rate == 0.0


def test_default_detector_has_expected_confusion_metrics() -> None:
    summary = evaluate_task_benchmark(judge=StubLabJudge()).summary
    assert summary.detector_tp == 5
    assert summary.detector_fn == 0
    assert summary.detector_fp == 0
    assert summary.detector_tn == 5
    assert summary.detector_tpr == 1.0
    assert summary.detector_fnr == 0.0
    assert summary.detector_fpr == 0.0


def test_stub_judge_agrees_with_objective_oracle() -> None:
    summary = evaluate_task_benchmark(judge=StubLabJudge()).summary
    assert summary.judge_total == 10
    assert summary.judge_agreements == 10
    assert summary.judge_agreement == 1.0


def test_report_groups_agent_attack_and_strategy_dimensions() -> None:
    report = evaluate_task_benchmark(judge=StubLabJudge())
    assert len(report.by_agent) == 5
    assert len(report.by_attack) == 5
    assert {
        "direct",
        "email_resource",
        "document_resource",
        "web_resource",
        "tool_output",
    }.issubset(report.by_strategy)
    assert all(item.attack_total == 1 for item in report.by_attack.values())


def test_metric_records_are_privacy_safe_metadata_only() -> None:
    payload = evaluate_task_benchmark(judge=StubLabJudge()).to_dict()
    serialized = str(payload).lower()
    assert "user_input" not in serialized
    assert "conversation" not in serialized
    assert "messages" not in serialized
    assert all(record.latency_ms > 0 for record in evaluate_task_benchmark().records)


def test_summary_calculates_false_positive_and_false_negative_rates() -> None:
    def record(*, success: bool, detector_hit: bool) -> BenchmarkRecord:
        return BenchmarkRecord(
            agent="fixture",
            task_id="fixture",
            kind="attack" if success else "benign",
            category="fixture",
            strategy="direct",
            task_completed=not success,
            attack_success=success,
            detector_hit=detector_hit,
            detector_verdict="malicious" if detector_hit else "safe",
            judge_positive=success,
            judge_verdict="malicious" if success else "safe",
            judge_mode="stub",
            judge_error=None,
            latency_ms=1.0,
        )

    summary = summarize_benchmark(
        [
            record(success=True, detector_hit=True),
            record(success=True, detector_hit=False),
            record(success=False, detector_hit=True),
            record(success=False, detector_hit=False),
        ]
    )
    assert summary.detector_tpr == 0.5
    assert summary.detector_fnr == 0.5
    assert summary.detector_fpr == 0.5
