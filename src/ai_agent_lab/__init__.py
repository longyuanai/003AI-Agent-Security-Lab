"""AI-Agent-Security-Lab: vulnerable target agents + attack scenarios + detection.

PoC scope (v0.1 happy path):
  - 5 built-in vulnerable target agent profiles
  - 10 attack classes with deterministic detector coverage
  - Heuristic + LLM detectors
  - Markdown reporter
  - Click CLI

Run demo: `python -m ai_agent_lab.cli run --scenario demo --output report.md`
"""

from ai_agent_lab.attacks import Scenario, built_in_scenarios
from ai_agent_lab.datatypes import (
    Detection,
    RunResult,
    ToolCall,
    Trace,
    Verdict,
)
from ai_agent_lab.detector import Detector, HeuristicDetector, LLMDetector
from ai_agent_lab.metrics import (
    ASRReport,
    MetricRecord,
    RateSummary,
    evaluate_asr,
    render_asr_markdown,
    write_asr_reports,
)
from ai_agent_lab.multi_agent import (
    MCPAbuseRun,
    build_mcp_abuse_mission,
    run_mcp_abuse,
    run_offline_mcp_abuse_demo,
)
from ai_agent_lab.reporter import render_markdown
from ai_agent_lab.report import (
    CrossScenarioReport,
    TargetCorrelation,
    build_correlation_report,
    build_demo_correlation_report,
    render_correlation_markdown,
)
from ai_agent_lab.runner import Runner, run_scenario
from ai_agent_lab.sandbox import (
    Sandbox,
    SandboxError,
    SandboxPolicy,
    SandboxResult,
    SandboxTimeout,
    SandboxViolation,
)
from ai_agent_lab.scenarios import build_scenario_registry, evaluate_demo_scenarios
from ai_agent_lab.target import TargetAgent, built_in_targets, get_target

__version__ = "0.1.0"

__all__ = [
    "Detection",
    "Detector",
    "HeuristicDetector",
    "LLMDetector",
    "ASRReport",
    "MetricRecord",
    "MCPAbuseRun",
    "RateSummary",
    "CrossScenarioReport",
    "TargetCorrelation",
    "RunResult",
    "Runner",
    "Sandbox",
    "SandboxError",
    "SandboxPolicy",
    "SandboxResult",
    "SandboxTimeout",
    "SandboxViolation",
    "Scenario",
    "TargetAgent",
    "ToolCall",
    "Trace",
    "Verdict",
    "built_in_scenarios",
    "built_in_targets",
    "build_mcp_abuse_mission",
    "build_correlation_report",
    "build_demo_correlation_report",
    "build_scenario_registry",
    "evaluate_asr",
    "evaluate_demo_scenarios",
    "get_target",
    "render_markdown",
    "render_asr_markdown",
    "render_correlation_markdown",
    "run_scenario",
    "run_mcp_abuse",
    "run_offline_mcp_abuse_demo",
    "write_asr_reports",
    "__version__",
]
