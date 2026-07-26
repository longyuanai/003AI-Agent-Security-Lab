"""Core data types for the agent lab.

Trace     - one attack run: user_input -> tool_call (+ args + fake result)
Detection - detector verdict (heuristic + LLM) for one trace
RunResult - one scenario's full output: scenario + trace + detection
Verdict   - enum: safe / suspicious / malicious
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


def report_now() -> datetime:
    """Current local time, with its UTC offset attached.

    Reports are evidence, and `datetime.now()` renders as `2026-07-26T12:00:00`
    with no zone -- unreadable across machines and unusable for correlating a
    finding with anything else.
    """

    return datetime.now().astimezone()


def report_timestamp() -> str:
    """`report_now()` as a second-resolution ISO-8601 string with offset."""

    return report_now().isoformat(timespec="seconds")


def new_finding_id() -> str:
    """Fresh Finding id.

    `shared_llm_core.Finding` auto-generates one when `id` is empty; calling
    this keeps the id visible at the construction site instead.
    """

    return str(uuid.uuid4())


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
