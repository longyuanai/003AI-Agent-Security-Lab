"""Tests for the Markdown reporter."""

from __future__ import annotations

from ai_agent_lab.reporter import render_markdown
from ai_agent_lab.runner import run_demo


def _fixed_timestamp() -> str:
    return "2026-07-24T00:00:00"


def test_render_contains_summary_header():
    md = render_markdown([], generated_at=_fixed_timestamp())
    assert "AI Agent Security Lab Report" in md
    assert "## Summary" in md


def test_render_contains_all_scenario_names():
    results = run_demo(router=None)
    md = render_markdown(results, generated_at=_fixed_timestamp())
    for r in results:
        assert r.scenario_name in md


def test_render_contains_verdicts():
    results = run_demo(router=None)
    md = render_markdown(results, generated_at=_fixed_timestamp())
    assert "malicious" in md.lower()


def test_render_summary_counts():
    results = run_demo(router=None)
    md = render_markdown(results, generated_at=_fixed_timestamp())
    assert "Scenarios run: **10**" in md
    assert "Attacks detected: **10 / 10**" in md
    assert "Detection rate: **100%**" in md


def test_render_includes_per_scenario_table():
    results = run_demo(router=None)
    md = render_markdown(results, generated_at=_fixed_timestamp())
    assert "| Scenario | Category |" in md


def test_render_includes_detail_section():
    results = run_demo(router=None)
    md = render_markdown(results, generated_at=_fixed_timestamp())
    assert "## Detail" in md
    assert "User input" in md
    assert "Tool chosen" in md


def test_render_passes_when_all_detected():
    results = run_demo(router=None)
    md = render_markdown(results, generated_at=_fixed_timestamp())
    assert "all built-in attacks detected" in md


def test_render_timestamp_present():
    md = render_markdown([], generated_at=_fixed_timestamp())
    assert _fixed_timestamp() in md


def test_render_missed_attack_message():
    """If a result is not detected, the report must surface that."""
    from ai_agent_lab.datatypes import Detection, RunResult, ToolCall, Verdict
    from ai_agent_lab.datatypes import Trace as _Trace

    # Force a miss by hand-crafting a result that wasn't detected.
    fake = RunResult(
        scenario_name="missed-attack",
        category="x",
        trace=_Trace(
            user_input="...",
            tool_call=ToolCall(name="", args={}),
            scenario_name="missed-attack",
            category="x",
        ),
        detection=Detection(detector="combined", verdict=Verdict.SAFE, evidence=""),
        expected_detection=Verdict.MALICIOUS,
        detected=False,
    )
    md = render_markdown([fake], generated_at=_fixed_timestamp())
    assert "1 of 1 attacks missed" in md
