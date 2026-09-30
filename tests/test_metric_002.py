"""METRIC-002: Defense Coverage, Task Utility, real Detection Latency, Cost.

Before this, three of tech-spec §5.5's six evaluation dimensions were
unmeasurable (Defense Coverage, Task Utility) or measured the wrong thing
(Detection Latency recorded agent routing time plus detection time combined,
not "attack occurs -> alert"). This pins the fix.
"""

from __future__ import annotations

import json

from click.testing import CliRunner
from shared_llm_core import ChatChoice, ChatMessage, ChatResponse, ChatUsage

from ai_agent_lab.attacks import benign_corpus, built_in_scenarios
from ai_agent_lab.cli import cli
from ai_agent_lab.detector import Detector, HeuristicDetector, LLMDetector
from ai_agent_lab.metrics import (
    CostSummary,
    DefenseReport,
    evaluate_asr,
    evaluate_defense,
    render_asr_markdown,
    summarise_cost,
)

# --------------------------------------------------------------------- #
# DefenseReport / evaluate_defense                                      #
# --------------------------------------------------------------------- #


def test_evaluate_defense_matches_the_defender_pipeline_directly() -> None:
    # Not just "some number" -- the exact figures reported for DEF-001.
    report = evaluate_defense()
    assert report.defense_coverage == 1.0
    assert report.blocked_attacks == len(built_in_scenarios())
    assert report.completed_benign == len(benign_corpus()) - 2
    assert report.task_utility == (len(benign_corpus()) - 2) / len(benign_corpus())


def test_missed_attacks_is_empty_when_coverage_is_full() -> None:
    assert evaluate_defense().missed_attacks == ()


def test_blocked_benign_records_carry_attribution() -> None:
    report = evaluate_defense()
    names = {record.name for record in report.blocked_benign}
    assert names == {"exec-python-docs-question", "deep-relative-import"}
    for record in report.blocked_benign:
        assert record.blocked_by  # which component(s) fired
        assert record.reason  # human-readable reason, not just a bool


def test_attacks_and_benign_partition_the_records() -> None:
    report = evaluate_defense()
    assert len(report.attacks) == len(built_in_scenarios())
    assert len(report.benign) == len(benign_corpus())
    assert len(report.records) == len(report.attacks) + len(report.benign)


def test_defense_report_serialises() -> None:
    payload = evaluate_defense().to_dict()
    assert payload["defense_coverage"] == 1.0
    assert 0.9 < payload["task_utility"] < 1.0
    assert len(payload["records"]) == len(built_in_scenarios()) + len(
        benign_corpus()
    )


def test_empty_defense_report_has_zero_rates_not_a_crash() -> None:
    report = DefenseReport(records=())
    assert report.defense_coverage == 0.0
    assert report.task_utility == 0.0


# --------------------------------------------------------------------- #
# CostSummary / summarise_cost                                          #
# --------------------------------------------------------------------- #


class _StubRouter:
    def __init__(self, prompt_tokens: int, completion_tokens: int) -> None:
        self._prompt = prompt_tokens
        self._completion = completion_tokens

    def chat(self, tier, req):  # noqa: ANN001, ANN201 - test double
        del tier, req
        return ChatResponse(
            id="stub",
            model="stub",
            created=0,
            choices=[
                ChatChoice(
                    index=0,
                    finish_reason="stop",
                    message=ChatMessage(
                        role="assistant",
                        content=json.dumps({"verdict": "malicious", "reason": "r"}),
                    ),
                )
            ],
            usage=ChatUsage(
                prompt_tokens=self._prompt,
                completion_tokens=self._completion,
                total_tokens=self._prompt + self._completion,
            ),
        )


def test_cost_is_zero_for_a_fully_offline_run() -> None:
    assert evaluate_asr(include_defense=False).cost == CostSummary()


def test_cost_aggregates_token_usage_from_the_llm_detector() -> None:
    detector = Detector(
        heuristic=HeuristicDetector(),
        llm=LLMDetector(router=_StubRouter(prompt_tokens=100, completion_tokens=20)),
    )
    report = evaluate_asr(detector=detector, include_defense=False)
    assert report.cost.llm_calls == len(report.records)
    assert report.cost.prompt_tokens == 100 * len(report.records)
    assert report.cost.completion_tokens == 20 * len(report.records)
    assert report.cost.total_tokens == report.cost.prompt_tokens + report.cost.completion_tokens


def test_summarise_cost_ignores_detections_without_usage() -> None:
    from ai_agent_lab.attacks import built_in_scenarios
    from ai_agent_lab.target import TargetAgent

    # A heuristic-only detector never carries usage; the aggregator must
    # treat that as zero cost rather than raising on the missing field.
    heuristic_only = Detector()
    target = TargetAgent()
    detections = [
        heuristic_only.detect(target.run(scenario.payload))
        for scenario in built_in_scenarios()
    ]
    assert summarise_cost(detections) == CostSummary()


def test_summarise_cost_of_an_empty_sequence_is_zero() -> None:
    assert summarise_cost([]) == CostSummary()


# --------------------------------------------------------------------- #
# Detection Latency semantics                                           #
# --------------------------------------------------------------------- #


def test_detect_latency_is_never_larger_than_the_combined_latency() -> None:
    # agent routing + detection should always be >= detection alone.
    report = evaluate_asr(include_defense=False)
    for record in report.records:
        assert record.detect_latency_ms <= record.latency_ms
        assert record.agent_latency_ms <= record.latency_ms


def test_agent_and_detect_latency_sum_to_the_combined_figure() -> None:
    # Each field is independently rounded to 3 decimals, so the sum can be
    # off by up to 0.001ms from the combined figure's own rounding.
    report = evaluate_asr(include_defense=False)
    for record in report.records:
        combined = record.agent_latency_ms + record.detect_latency_ms
        assert abs(combined - record.latency_ms) < 0.002


def test_metric_record_round_trips_new_fields_through_to_dict() -> None:
    report = evaluate_asr(include_defense=False)
    payload = report.records[0].to_dict()
    assert "agent_latency_ms" in payload
    assert "detect_latency_ms" in payload


# --------------------------------------------------------------------- #
# ASRReport integration                                                 #
# --------------------------------------------------------------------- #


def test_asr_report_carries_defense_and_cost_by_default() -> None:
    report = evaluate_asr()
    assert report.defense is not None
    assert report.defense.defense_coverage == 1.0
    assert report.cost == CostSummary()


def test_defense_and_cost_can_be_skipped() -> None:
    report = evaluate_asr(include_defense=False)
    assert report.defense is None
    payload = report.to_dict()
    assert payload["defense"] is None


def test_markdown_report_renders_all_six_dimensions() -> None:
    markdown = render_asr_markdown(evaluate_asr())
    for heading in (
        "## Detection Quality",
        "## Defense",
        "## Cost and Latency",
    ):
        assert heading in markdown
    assert "Defense coverage" in markdown
    assert "Task utility" in markdown
    assert "Detection latency" in markdown
    assert "LLM calls" in markdown


def test_markdown_report_without_defense_says_so() -> None:
    markdown = render_asr_markdown(evaluate_asr(include_defense=False))
    assert "## Defense" in markdown
    assert "_Not evaluated._" in markdown


def test_asr_report_to_dict_includes_defense_and_cost() -> None:
    payload = evaluate_asr().to_dict()
    assert payload["defense"]["defense_coverage"] == 1.0
    assert payload["cost"]["llm_calls"] == 0


# --------------------------------------------------------------------- #
# CLI                                                                   #
# --------------------------------------------------------------------- #


def test_cli_metrics_prints_defense_summary(tmp_path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "metrics",
            "--markdown",
            str(tmp_path / "a.md"),
            "--json",
            str(tmp_path / "a.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Defense:" in result.output
    assert "coverage 100.0%" in result.output
