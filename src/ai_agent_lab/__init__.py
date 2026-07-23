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
from ai_agent_lab.reporter import render_markdown
from ai_agent_lab.runner import Runner, run_scenario
from ai_agent_lab.target import TargetAgent, built_in_targets, get_target

__version__ = "0.1.0"

__all__ = [
    "Detection",
    "Detector",
    "HeuristicDetector",
    "LLMDetector",
    "RunResult",
    "Runner",
    "Scenario",
    "TargetAgent",
    "ToolCall",
    "Trace",
    "Verdict",
    "built_in_scenarios",
    "built_in_targets",
    "get_target",
    "render_markdown",
    "run_scenario",
    "__version__",
]
