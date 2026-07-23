"""Runner: orchestrates target -> trace -> detector -> RunResult."""

from __future__ import annotations

from dataclasses import dataclass, field

from ai_agent_lab.attacks import Scenario, built_in_scenarios
from ai_agent_lab.datatypes import Detection, RunResult, Trace, Verdict
from ai_agent_lab.detector import Detector, HeuristicDetector, LLMDetector, is_detected
from ai_agent_lab.target import TargetAgent


@dataclass
class Runner:
    """End-to-end runner. Holds the target agent + detector(s)."""

    target: TargetAgent = field(default_factory=TargetAgent)
    detector: Detector = field(default_factory=Detector)

    def run_scenario(self, scenario: Scenario) -> RunResult:
        trace = self.target.run(
            scenario.payload,
            scenario_name=scenario.name,
            category=scenario.category,
        )
        detection = self.detector.detect(trace)
        return RunResult(
            scenario_name=scenario.name,
            category=scenario.category,
            trace=trace,
            detection=detection,
            expected_detection=scenario.expected_detection,
            detected=is_detected(detection, scenario.expected_detection),
        )

    def run_all(self, scenarios: list[Scenario]) -> list[RunResult]:
        return [self.run_scenario(s) for s in scenarios]


def run_scenario(
    scenario: Scenario,
    *,
    target: TargetAgent | None = None,
    router: object | None = None,
) -> RunResult:
    """Convenience: build a default Runner, run a single scenario.

    `router` (optional) - LLM router to wire into the detector.
    """
    detector = Detector(heuristic=HeuristicDetector(), llm=LLMDetector(router=router))
    runner = Runner(target=target or TargetAgent(), detector=detector)
    return runner.run_scenario(scenario)


def run_demo(router: object | None = None) -> list[RunResult]:
    """Run the built-in v0.1 scenario set (10 attack classes)."""
    detector = Detector(heuristic=HeuristicDetector(), llm=LLMDetector(router=router))
    runner = Runner(detector=detector)
    return runner.run_all(built_in_scenarios())
