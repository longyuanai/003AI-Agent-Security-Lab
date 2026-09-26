"""Defender Toolkit (tech-spec §5.4).

Four policy layers over an agent trace. `GuardDecision` answers "does this
violate policy?", which is a different question from the detector's "was this
an attack?" -- the two legitimately disagree, and a report showing both is more
informative than one that collapses them.

    from ai_agent_lab.defender import DefenderPipeline
    result = DefenderPipeline().evaluate(trace)
    result.blocked, result.blocked_by
"""

from ai_agent_lab.defender.components import (
    DEFAULT_CANARIES,
    DEFAULT_MAIL_DOMAINS,
    DEFAULT_TOOL_ALLOWLIST,
    InputFilter,
    OutputAuditor,
    PlanValidator,
    ToolGuard,
)
from ai_agent_lab.defender.pipeline import (
    DefenderPipeline,
    DefenseResult,
    GuardComponent,
    default_components,
)

__all__ = [
    "DEFAULT_CANARIES",
    "DEFAULT_MAIL_DOMAINS",
    "DEFAULT_TOOL_ALLOWLIST",
    "DefenderPipeline",
    "DefenseResult",
    "GuardComponent",
    "InputFilter",
    "OutputAuditor",
    "PlanValidator",
    "ToolGuard",
    "default_components",
]
