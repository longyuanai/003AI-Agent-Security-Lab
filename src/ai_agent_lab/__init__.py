"""AI-Agent-Security-Lab: vulnerable target agents + attack scenarios + detection.

Scope:
  - 5 built-in vulnerable target agent profiles
  - 10 attack classes with deterministic detector coverage
  - MITRE ATLAS tactic templates with safe synthetic payloads
  - Heuristic + LLM detectors, offline-by-default LLM judge
  - Markdown / JSON reporters
  - Click CLI

Run demo: `python -m ai_agent_lab.cli run --scenario demo --output report.md`

Top-level names are resolved lazily (PEP 562). Importing `ai_agent_lab` must
stay cheap and dependency-free so the fully offline parts of the lab -- the
target agents, attack corpus, heuristic detector, sandbox and ASR metrics --
keep working when optional dependencies such as `openai` are not installed.
"""

from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING

# Kept in sync with pyproject's `[project] version`; see
# tests/test_package_metadata.py.
_FALLBACK_VERSION = "0.6.0"

try:
    __version__ = version("ai-agent-lab")
except PackageNotFoundError:  # running from a source checkout
    __version__ = _FALLBACK_VERSION

# Public name -> submodule that defines it.
_EXPORTS: dict[str, str] = {
    "ASRReport": "metrics",
    "AnthropicLLMRouter": "orchestrator",
    "AtlasIterationRecord": "runner",
    "AtlasRun": "runner",
    "BenignRecord": "metrics",
    "BenignSample": "attacks",
    "CrossScenarioReport": "report",
    "Detection": "datatypes",
    "DetectionQuality": "metrics",
    "Detector": "detector",
    "FakeLLMRouter": "orchestrator",
    "HeuristicDetector": "detector",
    "JudgeResult": "judge",
    "LAB_MISSION_ROLES": "orchestrator",
    "LLMDetector": "detector",
    "LLMRuntime": "orchestrator",
    "LabJudge": "judge",
    "LabMission": "orchestrator",
    "MCPAbuseRun": "multi_agent",
    "MetricRecord": "metrics",
    "OpenAILLMRouter": "orchestrator",
    "RateSummary": "metrics",
    "RouterLabJudge": "judge",
    "RunResult": "datatypes",
    "Runner": "runner",
    "Sandbox": "sandbox",
    "SandboxError": "sandbox",
    "SandboxPolicy": "sandbox",
    "SandboxResult": "sandbox",
    "SandboxTimeout": "sandbox",
    "SandboxViolation": "sandbox",
    "Scenario": "attacks",
    "StubLabJudge": "judge",
    "TargetAgent": "target",
    "TargetCorrelation": "report",
    "ToolCall": "datatypes",
    "Trace": "datatypes",
    "Verdict": "datatypes",
    "atlas_run_to_envelope": "runner",
    "benign_corpus": "attacks",
    "build_correlation_report": "report",
    "build_demo_correlation_report": "report",
    "build_lab_judge": "judge",
    "build_llm_runtime": "orchestrator",
    "build_mcp_abuse_mission": "multi_agent",
    "build_scenario_registry": "scenarios",
    "built_in_scenarios": "attacks",
    "built_in_targets": "target",
    "evaluate_asr": "metrics",
    "evaluate_demo_scenarios": "scenarios",
    "evaluate_detection_quality": "metrics",
    "get_target": "target",
    "new_finding_id": "datatypes",
    "render_asr_markdown": "metrics",
    "render_correlation_markdown": "report",
    "render_markdown": "reporter",
    "run_atlas_tactic": "runner",
    "run_mcp_abuse": "multi_agent",
    "run_offline_mcp_abuse_demo": "multi_agent",
    "run_scenario": "runner",
    "scan_payload": "scan",
    "write_asr_reports": "metrics",
}

__all__ = [*sorted(_EXPORTS), "__version__"]


def __getattr__(name: str) -> object:
    """Import the defining submodule on first access."""

    try:
        module_name = _EXPORTS[name]
    except KeyError:
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}"
        ) from None
    value = getattr(import_module(f"{__name__}.{module_name}"), name)
    globals()[name] = value  # cache so later lookups skip __getattr__
    return value


def __dir__() -> list[str]:
    return sorted(__all__)


if TYPE_CHECKING:  # let type checkers and IDEs see the real symbols
    from ai_agent_lab.attacks import (
        BenignSample,
        Scenario,
        benign_corpus,
        built_in_scenarios,
    )
    from ai_agent_lab.datatypes import (
        Detection,
        RunResult,
        ToolCall,
        Trace,
        Verdict,
        new_finding_id,
    )
    from ai_agent_lab.detector import Detector, HeuristicDetector, LLMDetector
    from ai_agent_lab.judge import (
        JudgeResult,
        LabJudge,
        RouterLabJudge,
        StubLabJudge,
        build_lab_judge,
    )
    from ai_agent_lab.metrics import (
        ASRReport,
        BenignRecord,
        DetectionQuality,
        MetricRecord,
        RateSummary,
        evaluate_asr,
        evaluate_detection_quality,
        render_asr_markdown,
        write_asr_reports,
    )
    from ai_agent_lab.multi_agent import (
        MCPAbuseRun,
        build_mcp_abuse_mission,
        run_mcp_abuse,
        run_offline_mcp_abuse_demo,
    )
    from ai_agent_lab.orchestrator import (
        LAB_MISSION_ROLES,
        AnthropicLLMRouter,
        FakeLLMRouter,
        LabMission,
        LLMRuntime,
        OpenAILLMRouter,
        build_llm_runtime,
    )
    from ai_agent_lab.report import (
        CrossScenarioReport,
        TargetCorrelation,
        build_correlation_report,
        build_demo_correlation_report,
        render_correlation_markdown,
    )
    from ai_agent_lab.reporter import render_markdown
    from ai_agent_lab.runner import (
        AtlasIterationRecord,
        AtlasRun,
        Runner,
        atlas_run_to_envelope,
        run_atlas_tactic,
        run_scenario,
    )
    from ai_agent_lab.sandbox import (
        Sandbox,
        SandboxError,
        SandboxPolicy,
        SandboxResult,
        SandboxTimeout,
        SandboxViolation,
    )
    from ai_agent_lab.scan import scan_payload
    from ai_agent_lab.scenarios import build_scenario_registry, evaluate_demo_scenarios
    from ai_agent_lab.target import TargetAgent, built_in_targets, get_target
