"""Runner: orchestrates target -> trace -> detector -> RunResult."""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field

from ai_agent_lab.atlas import ATLASTactic, get_tactic
from ai_agent_lab.attacks import Scenario, built_in_scenarios
from ai_agent_lab.datatypes import RunResult, Trace, Verdict
from ai_agent_lab.detector import Detector, HeuristicDetector, LLMDetector, is_detected
from ai_agent_lab.judge import JudgeResult, LabJudge, build_lab_judge
from ai_agent_lab.target import TargetAgent, built_in_targets


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


@dataclass(frozen=True)
class AtlasIterationRecord:
    """One safe ATLAS payload variant and its detector outcome."""

    iteration: int
    payload_index: int
    payload: str
    trace: Trace
    judge: JudgeResult | None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "iteration": self.iteration,
            "payload_index": self.payload_index,
            "payload": self.payload,
            "trace": self.trace.to_dict(),
            "judge": self.judge.to_dict() if self.judge else None,
            "error": self.error,
        }


@dataclass(frozen=True)
class AtlasRun:
    """All iterations for one Agent × ATLAS tactic evaluation."""

    tactic: ATLASTactic
    agent: str
    records: tuple[AtlasIterationRecord, ...]

    @property
    def used_payloads(self) -> tuple[str, ...]:
        return tuple(record.payload for record in self.records)


_ATLAS_AGENT_NAMES = {
    "sql_assistant": "sqli-helper",
    "email_assistant": "email-assistant",
    "file_rag": "file-rag-agent",
    "web_browser": "web-browser-agent",
    "code_act": "code-act-agent",
}


def run_atlas_tactic(
    tactic_id: str,
    *,
    agent: str,
    iterations: int,
    detector: Detector | None = None,
    judge: LabJudge | None = None,
    rng: random.Random | None = None,
) -> AtlasRun:
    """Run safe variants without repeating until the tactic pool is exhausted."""

    if not 1 <= iterations <= 100:
        raise ValueError("iterations must be between 1 and 100")
    tactic = get_tactic(tactic_id)
    target = _get_atlas_target(agent)
    active_judge = judge or build_lab_judge()
    chooser = rng or random.SystemRandom()
    variants = list(tactic.payloads)
    selected: list[str] = []
    while len(selected) < iterations:
        selected.extend(chooser.sample(variants, len(variants)))
    selected = selected[:iterations]

    records: list[AtlasIterationRecord] = []
    for iteration, payload in enumerate(selected, start=1):
        trace = target.run(
            payload,
            scenario_name=tactic.id,
            category="mitre_atlas",
        )
        try:
            judged = active_judge.judge(trace)
            error = None
        except Exception as exc:  # noqa: BLE001 - isolate judge iterations
            judged = None
            error = f"{type(exc).__name__}: {exc}"
        records.append(
            AtlasIterationRecord(
                iteration=iteration,
                payload_index=tactic.payloads.index(payload),
                payload=payload,
                trace=trace,
                judge=judged,
                error=error,
            )
        )
    return AtlasRun(tactic=tactic, agent=agent, records=tuple(records))


def atlas_run_to_envelope(run: AtlasRun) -> dict[str, object]:
    """Normalize an ATLAS run without changing the frozen Finding schema."""

    findings: list[dict[str, object]] = []
    errors: list[str] = []
    for record in run.records:
        if record.error:
            errors.append(f"iteration {record.iteration}: {record.error}")
            continue
        if record.judge is None or record.judge.verdict is Verdict.SAFE:
            continue
        findings.append(
            {
                "id": str(uuid.uuid4()),
                "severity": run.tactic.severity_default.value,
                "confidence": record.judge.confidence,
                "title": f"{run.tactic.id} - {run.tactic.name}",
                "description": (
                    f"Agent: {run.agent}, iteration: {record.iteration}, "
                    f"judge: {record.judge.verdict.value}"
                ),
                "evidence": [record.judge.reason],
                "tags": ["mitre-atlas", run.tactic.id],
                "metadata": {
                    "attack": run.tactic.id,
                    "agent": run.agent,
                    "iteration": record.iteration,
                    "payload_variant": record.payload_index,
                    "judge": record.judge.to_dict(),
                    "mitre_url": run.tactic.mitre_url,
                },
            }
        )
    judge_modes = {
        record.judge.mode for record in run.records if record.judge is not None
    }
    return {
        "findings": findings,
        "errors": errors,
        "summary": {
            "attack_id": run.tactic.id,
            "agent": run.agent,
            "iterations": len(run.records),
            "findings": len(findings),
            "errors": len(errors),
            "judge_mode": next(iter(judge_modes), "unavailable"),
        },
    }


def _get_atlas_target(agent: str) -> TargetAgent:
    try:
        target_name = _ATLAS_AGENT_NAMES[agent]
    except KeyError as exc:
        raise KeyError(f"Unknown lab agent: {agent!r}") from exc
    return next(
        target for target in built_in_targets() if target.name == target_name
    )


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
