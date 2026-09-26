"""Runs the defender components over a trace and reports what stopped it."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from ai_agent_lab.datatypes import GuardDecision, Trace
from ai_agent_lab.defender.components import (
    InputFilter,
    OutputAuditor,
    PlanValidator,
    ToolGuard,
)


class GuardComponent(Protocol):
    """What the pipeline needs from a component."""

    component: str

    def check(self, trace: Trace) -> GuardDecision: ...


@dataclass(frozen=True)
class DefenseResult:
    """Every component's decision for one trace."""

    trace: Trace
    decisions: tuple[GuardDecision, ...]

    @property
    def blocked(self) -> bool:
        return any(not decision.allowed for decision in self.decisions)

    @property
    def blocked_by(self) -> tuple[str, ...]:
        """Components that objected, in pipeline order.

        More than one may fire; keeping all of them shows which layers would
        still have caught the attack if an earlier one were disabled.
        """

        return tuple(
            decision.component
            for decision in self.decisions
            if not decision.allowed
        )

    @property
    def first_block(self) -> GuardDecision | None:
        return next(
            (d for d in self.decisions if not d.allowed),
            None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace": self.trace.to_dict(),
            "blocked": self.blocked,
            "blocked_by": list(self.blocked_by),
            "decisions": [decision.to_dict() for decision in self.decisions],
        }


def default_components() -> tuple[GuardComponent, ...]:
    """The §5.4 stack, ordered input -> plan -> execution -> output."""

    return (InputFilter(), PlanValidator(), ToolGuard(), OutputAuditor())


@dataclass
class DefenderPipeline:
    """Evaluates a trace against every component.

    Runs all components rather than stopping at the first objection, so a
    report can show defence in depth instead of only the outermost layer.
    """

    components: Sequence[GuardComponent] = field(
        default_factory=default_components
    )

    def evaluate(self, trace: Trace) -> DefenseResult:
        return DefenseResult(
            trace=trace,
            decisions=tuple(
                component.check(trace) for component in self.components
            ),
        )

    def evaluate_all(self, traces: Iterable[Trace]) -> list[DefenseResult]:
        return [self.evaluate(trace) for trace in traces]
