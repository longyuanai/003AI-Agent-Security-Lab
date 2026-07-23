"""Tests for the end-to-end runner."""

from __future__ import annotations

from ai_agent_lab.attacks import built_in_scenarios
from ai_agent_lab.datatypes import Verdict
from ai_agent_lab.detector import Detector, HeuristicDetector, LLMDetector
from ai_agent_lab.runner import Runner, run_demo, run_scenario
from ai_agent_lab.target import TargetAgent


def test_runner_default_heuristic_detects_all_ten():
    """Without an LLM, the heuristic alone must catch all 10 attacks."""
    runner = Runner()  # heuristic only by default
    results = runner.run_all(built_in_scenarios())
    assert len(results) == 10
    assert all(r.detected for r in results), [r.scenario_name for r in results]


def test_runner_with_llm_detects_all_ten(stub_router):
    router = stub_router({
        "verdict": "malicious",
        "category": "tool_misuse",
        "confidence": 0.95,
        "reason": "stub",
    })
    runner = Runner(
        detector=Detector(
            heuristic=HeuristicDetector(),
            llm=LLMDetector(router=router),
        )
    )
    results = runner.run_all(built_in_scenarios())
    assert all(r.detected for r in results)


def test_runner_single_scenario():
    runner = Runner()
    s = built_in_scenarios()[0]
    r = runner.run_scenario(s)
    assert r.scenario_name == s.name
    assert r.detected is True


def test_runner_returns_runresult_fields():
    runner = Runner()
    r = runner.run_scenario(built_in_scenarios()[0])
    assert r.trace is not None
    assert r.detection is not None
    assert r.expected_detection in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)


def test_run_demo_returns_ten_results():
    results = run_demo(router=None)
    assert len(results) == 10


def test_run_scenario_convenience():
    s = built_in_scenarios()[0]
    r = run_scenario(s, target=TargetAgent(), router=None)
    assert r.detected


def test_runner_per_scenario_categories():
    """All ten attack categories should appear in the demo run."""
    results = run_demo(router=None)
    cats = {r.category for r in results}
    assert len(cats) == 10


def test_runner_evidence_populated():
    """Heuristic detector should populate evidence for every detected run."""
    runner = Runner()
    for r in runner.run_all(built_in_scenarios()):
        assert r.detection.evidence, f"Empty evidence for {r.scenario_name}"
