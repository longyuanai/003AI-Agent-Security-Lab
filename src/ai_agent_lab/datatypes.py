"""Core data types for the agent lab.

Trace     - one attack run: user_input -> tool_call (+ args + fake result)
Detection - detector verdict (heuristic + LLM) for one trace
RunResult - one scenario's full output: scenario + trace + detection
Verdict   - enum: safe / suspicious / malicious
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """Verdict of a single detector on a single trace."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass(frozen=True)
class ToolCall:
    """A single tool invocation inside a trace."""

    name: str  # "read_file" | "http_fetch" | "exec_shell" | ""
    args: dict[str, Any] = field(default_factory=dict)
    result: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "args": dict(self.args), "result": self.result}


@dataclass(frozen=True)
class Trace:
    """Full trace of one agent run: input -> tool call -> result."""

    user_input: str
    tool_call: ToolCall
    scenario_name: str = ""
    category: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_input": self.user_input,
            "tool_call": self.tool_call.to_dict(),
            "scenario_name": self.scenario_name,
            "category": self.category,
        }


@dataclass(frozen=True)
class Detection:
    """Combined verdict of one trace from one detector (or fused)."""

    detector: str  # "heuristic" | "llm" | "combined"
    verdict: Verdict
    evidence: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "verdict": self.verdict.value,
            "evidence": self.evidence,
            "raw": dict(self.raw),
        }


@dataclass(frozen=True)
class RunResult:
    """The end-to-end result of running one scenario."""

    scenario_name: str
    category: str
    trace: Trace
    detection: Detection
    expected_detection: Verdict
    detected: bool  # True iff combined verdict >= expected_detection

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_name": self.scenario_name,
            "category": self.category,
            "trace": self.trace.to_dict(),
            "detection": self.detection.to_dict(),
            "expected_detection": self.expected_detection.value,
            "detected": self.detected,
        }
