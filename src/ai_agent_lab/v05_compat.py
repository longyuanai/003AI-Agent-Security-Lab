"""Project-local compatibility implementation for shared-llm-core v0.5.

The checked-out shared core is still v0.1.0 and does not yet export the
additive §7-§10 components. This module mirrors only the frozen v0.5 shapes
used by AI-Agent-Security-Lab. It does not modify or replace any v0.1 symbol.
"""

from __future__ import annotations

import asyncio
import sys
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, AsyncIterator, Mapping, Sequence


class FindingSource(str, Enum):
    SOC = "001"
    VULN = "002"
    LAB = "003"
    CODE = "004"
    REVERSE = "005"
    FIRMWARE = "006"
    EXTERNAL = "external"


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    id: str
    source: FindingSource
    severity: FindingSeverity
    confidence: float
    title: str
    description: str = ""
    host: str | None = None
    cve: str | None = None
    ts: datetime | None = None
    evidence: tuple[str, ...] = ()
    related: tuple[str, ...] = ()
    tags: frozenset[str] = frozenset()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "host": self.host,
            "cve": self.cve,
            "ts": self.ts.isoformat() if self.ts else None,
            "evidence": list(self.evidence),
            "related": list(self.related),
            "tags": sorted(self.tags),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        ts = data.get("ts")
        return cls(
            id=str(data["id"]),
            source=FindingSource(data["source"]),
            severity=FindingSeverity(data["severity"]),
            confidence=float(data["confidence"]),
            title=str(data["title"]),
            description=str(data.get("description", "")),
            host=data.get("host"),
            cve=data.get("cve"),
            ts=datetime.fromisoformat(ts) if isinstance(ts, str) else ts,
            evidence=tuple(data.get("evidence", ())),
            related=tuple(data.get("related", ())),
            tags=frozenset(data.get("tags", ())),
            metadata=dict(data.get("metadata", {})),
        )


class AgentRole(str, Enum):
    SCOUT = "scout"
    ANALYST = "analyst"
    EXPLOITER = "exploiter"
    SYNTHESIZER = "synthesizer"
    REVIEWER = "reviewer"


@dataclass(frozen=True)
class AgentTask:
    role: AgentRole
    instruction: str
    context: tuple[str, ...] = ()


@dataclass(frozen=True)
class MissionContext:
    task: str
    inputs: Mapping[str, Any]
    scratchpad: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentResult:
    role: AgentRole
    output: str
    findings: tuple[Finding, ...] = ()
    latency_ms: int = 0
    error: str | None = None


_ROLE_INSTRUCTIONS: Mapping[AgentRole, str] = {
    AgentRole.SCOUT: "Identify the authorized target and exposed attack surface.",
    AgentRole.ANALYST: "Analyze prior evidence and explain the vulnerability.",
    AgentRole.EXPLOITER: (
        "Validate safely using only fixtures and canary data; do not contact real targets."
    ),
    AgentRole.SYNTHESIZER: "Synthesize prior results into one concise assessment.",
    AgentRole.REVIEWER: "Review evidence, challenge assumptions, and issue the verdict.",
}


class MultiAgentOrchestrator:
    def __init__(
        self,
        router: Any,
        *,
        max_concurrency: int = 4,
        scratchpad_size: int = 4096,
    ) -> None:
        if max_concurrency <= 0:
            raise ValueError("max_concurrency must be greater than zero")
        if scratchpad_size <= 0:
            raise ValueError("scratchpad_size must be greater than zero")
        self.router = router
        self.max_concurrency = max_concurrency
        self.scratchpad_size = scratchpad_size

    def run(
        self,
        mission: MissionContext,
        roles: Sequence[AgentRole],
    ) -> list[AgentResult]:
        """Run a dependency-aware role pipeline with append-only scratchpad."""

        scratchpad = list(mission.scratchpad)
        results: list[AgentResult] = []
        for role in roles:
            started = time.perf_counter()
            try:
                output = self._invoke(role, mission, tuple(scratchpad))
                error = None
            except Exception as exc:  # noqa: BLE001 - contract says continue
                output = ""
                error = f"{type(exc).__name__}: {exc}"
            scratchpad.append(
                f"{role.value}: {output}" if error is None else f"{role.value}: ERROR {error}"
            )
            scratchpad = self._trim_scratchpad(scratchpad)
            latency_ms = max(0, round((time.perf_counter() - started) * 1000))
            result = AgentResult(
                role=role,
                output=output,
                latency_ms=latency_ms,
                error=error,
            )
            results.append(result)
        return results

    def _invoke(
        self,
        role: AgentRole,
        mission: MissionContext,
        scratchpad: tuple[str, ...],
    ) -> str:
        from shared_llm_core import ChatMessage, ChatRequest, TaskTier

        context = "\n".join(scratchpad) if scratchpad else "(empty)"
        request = ChatRequest(
            messages=[
                ChatMessage(
                    role="system",
                    content=(
                        f"You are the {role.value.upper()} agent. "
                        f"{_ROLE_INSTRUCTIONS[role]}"
                    ),
                ),
                ChatMessage(
                    role="user",
                    content=(
                        f"Mission: {mission.task}\n"
                        f"Inputs: {dict(mission.inputs)!r}\n"
                        f"Scratchpad:\n{context}"
                    ),
                ),
            ],
            temperature=0.0,
            max_tokens=500,
        )
        response = self.router.chat(TaskTier.PREMIUM, request)
        return response.choices[0].message.content

    def _trim_scratchpad(self, scratchpad: list[str]) -> list[str]:
        max_chars = self.scratchpad_size * 4
        kept: list[str] = []
        used = 0
        for entry in reversed(scratchpad):
            if kept and used + len(entry) > max_chars:
                break
            kept.append(entry)
            used += len(entry)
        return list(reversed(kept))


@dataclass(frozen=True)
class RuleContext:
    subject: str
    facts: Mapping[str, Any]
    window: tuple[datetime, datetime] | None = None
    related: tuple[Finding, ...] = ()


class Rule(ABC):
    id: str
    severity_hint: str = "medium"

    @abstractmethod
    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"Rule({self.id})"


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        if rule.id in self._rules:
            raise ValueError(f"Duplicate rule id: {rule.id}")
        self._rules[rule.id] = rule

    def get(self, rule_id: str) -> Rule:
        try:
            return self._rules[rule_id]
        except KeyError as exc:
            raise KeyError(f"Unknown rule: {rule_id!r}") from exc

    def all(self) -> list[Rule]:
        return list(self._rules.values())

    @classmethod
    def default(cls) -> "RuleRegistry":
        return cls()


class RuleEngine:
    def __init__(self, registry: RuleRegistry | None = None) -> None:
        self.registry = registry or RuleRegistry.default()

    def evaluate(
        self,
        ctx: RuleContext,
        *,
        rule_ids: Sequence[str] | None = None,
    ) -> list[Finding]:
        rules = (
            [self.registry.get(rule_id) for rule_id in rule_ids]
            if rule_ids is not None
            else self.registry.all()
        )
        findings: list[Finding] = []
        for rule in rules:
            try:
                rule_findings = rule.evaluate(ctx)
                for finding in rule_findings:
                    if not 0.0 <= finding.confidence <= 1.0:
                        raise ValueError("finding confidence outside [0.0, 1.0]")
                findings.extend(rule_findings)
            except Exception as exc:  # noqa: BLE001 - contract says skip
                print(f"Rule {rule.id} failed: {exc}", file=sys.stderr)
        return findings


class FindingRegistry:
    def __init__(self, *, max_size: int = 100_000) -> None:
        if max_size <= 0:
            raise ValueError("max_size must be greater than zero")
        self.max_size = max_size
        self._findings: list[Finding] = []
        self._subscribers: list[asyncio.Queue[Finding]] = []

    def add(self, finding: Finding) -> None:
        self._findings.append(finding)
        if len(self._findings) > self.max_size:
            del self._findings[: len(self._findings) - self.max_size]
        for queue in tuple(self._subscribers):
            queue.put_nowait(finding)

    def query(
        self,
        *,
        source: FindingSource | None = None,
        severity: FindingSeverity | None = None,
        host: str | None = None,
        cve: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[Finding]:
        if limit < 0:
            raise ValueError("limit must not be negative")
        matched = [
            finding
            for finding in self._findings
            if (source is None or finding.source == source)
            and (severity is None or finding.severity == severity)
            and (host is None or finding.host == host)
            and (cve is None or finding.cve == cve)
            and (since is None or (finding.ts is not None and finding.ts >= since))
        ]
        return matched[-limit:] if limit else []

    async def subscribe(self) -> AsyncIterator[Finding]:
        queue: asyncio.Queue[Finding] = asyncio.Queue()
        self._subscribers.append(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers.remove(queue)


def new_finding_id() -> str:
    return str(uuid.uuid4())
