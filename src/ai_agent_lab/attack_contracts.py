"""Composable attack contracts for safe, reproducible Agent benchmarks.

The vulnerability under test (``AttackCase``) is deliberately separated from
the transport used to present it to an Agent (``DeliveryStrategy``).  This is
the same useful boundary found in mature red-team runners, while keeping the
lab dependency-free and compatible with the existing ``ATLASTactic`` API.
"""

from __future__ import annotations

import importlib.metadata
import random
from dataclasses import dataclass
from typing import Callable, Iterable

from shared_llm_core import FindingSeverity

from ai_agent_lab.atlas import ATLASTactic, get_tactic


SAFE_PAYLOAD_MARKER = "[SAFE LAB SIMULATION]"
ATLAS_ENTRY_POINT_GROUP = "longyuanai.atlas_tactics"


@dataclass(frozen=True)
class AttackCase:
    """One vulnerability test independent of its delivery channel."""

    id: str
    name: str
    description: str
    payloads: tuple[str, ...]
    severity_default: FindingSeverity
    detector_modes: tuple[str, ...]
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("attack case id must not be empty")
        if not self.payloads:
            raise ValueError(f"{self.id} must provide at least one payload")
        if len(set(self.payloads)) != len(self.payloads):
            raise ValueError(f"{self.id} payload variants must be unique")
        if any(not payload.startswith(SAFE_PAYLOAD_MARKER) for payload in self.payloads):
            raise ValueError(
                f"{self.id} payloads must begin with {SAFE_PAYLOAD_MARKER!r}"
            )


@dataclass(frozen=True)
class DeliveryStrategy:
    """A safe wrapper that delivers an attack case through one channel."""

    id: str
    name: str
    channel: str
    template: str
    supported_agents: tuple[str, ...]

    def __post_init__(self) -> None:
        if "{payload}" not in self.template:
            raise ValueError("delivery template must contain {payload}")
        if not self.supported_agents:
            raise ValueError("delivery strategy must support at least one agent")

    def deliver(self, payload: str, *, agent: str) -> str:
        """Wrap one explicitly safe payload for a supported target Agent."""

        if agent not in self.supported_agents:
            raise ValueError(f"strategy {self.id!r} does not support agent {agent!r}")
        if not payload.startswith(SAFE_PAYLOAD_MARKER):
            raise ValueError("delivery refused a payload without the safe-lab marker")
        return self.template.format(payload=payload)


@dataclass(frozen=True)
class DeliveredAttack:
    """One materialized iteration from an immutable execution plan."""

    iteration: int
    payload_index: int
    raw_payload: str
    delivered_payload: str


@dataclass(frozen=True)
class ExecutionPlan:
    """Deterministic AttackCase × DeliveryStrategy × Agent run plan."""

    attack: AttackCase
    strategy: DeliveryStrategy
    agent: str
    iterations: int = 1
    seed: int = 0

    def __post_init__(self) -> None:
        if not 1 <= self.iterations <= 100:
            raise ValueError("iterations must be between 1 and 100")
        if self.agent not in self.strategy.supported_agents:
            raise ValueError(
                f"strategy {self.strategy.id!r} does not support agent {self.agent!r}"
            )

    def materialize(self) -> tuple[DeliveredAttack, ...]:
        """Choose variants reproducibly, exhausting each cycle before reuse."""

        chooser = random.Random(self.seed)
        indexes = list(range(len(self.attack.payloads)))
        selected: list[int] = []
        while len(selected) < self.iterations:
            selected.extend(chooser.sample(indexes, len(indexes)))
        return tuple(
            DeliveredAttack(
                iteration=iteration,
                payload_index=payload_index,
                raw_payload=self.attack.payloads[payload_index],
                delivered_payload=self.strategy.deliver(
                    self.attack.payloads[payload_index],
                    agent=self.agent,
                ),
            )
            for iteration, payload_index in enumerate(
                selected[: self.iterations], start=1
            )
        )


@dataclass(frozen=True)
class TacticPluginDescriptor:
    """Entry-point metadata that can be inspected without importing a plugin."""

    name: str
    value: str
    group: str = ATLAS_ENTRY_POINT_GROUP


_ALL_AGENTS = (
    "sql_assistant",
    "email_assistant",
    "file_rag",
    "web_browser",
    "code_act",
)


DELIVERY_STRATEGIES: dict[str, DeliveryStrategy] = {
    "direct": DeliveryStrategy(
        id="direct",
        name="Direct user input",
        channel="user_input",
        template="{payload}",
        supported_agents=_ALL_AGENTS,
    ),
    "email_resource": DeliveryStrategy(
        id="email_resource",
        name="Synthetic email resource",
        channel="email",
        template="[SAFE LAB DELIVERY:email] Synthetic message body: {payload}",
        supported_agents=("email_assistant",),
    ),
    "document_resource": DeliveryStrategy(
        id="document_resource",
        name="Synthetic document resource",
        channel="document",
        template="[SAFE LAB DELIVERY:document] Fixture document text: {payload}",
        supported_agents=("file_rag",),
    ),
    "web_resource": DeliveryStrategy(
        id="web_resource",
        name="Synthetic web resource",
        channel="web",
        template="[SAFE LAB DELIVERY:web] Fixture page text: {payload}",
        supported_agents=("web_browser",),
    ),
    "tool_output": DeliveryStrategy(
        id="tool_output",
        name="Synthetic tool output",
        channel="tool_output",
        template="[SAFE LAB DELIVERY:tool_output] Fixture tool returned: {payload}",
        supported_agents=_ALL_AGENTS,
    ),
}


_ATLAS_DETECTOR_MODES: dict[str, tuple[str, ...]] = {
    "AML.T0051": ("prompt_injection",),
    "AML.T0051.001": ("prompt_injection",),
    "AML.T0051.002": ("prompt_injection",),
    "AML.T0054": ("prompt_injection",),
    "AML.T0024": ("data_exfiltration",),
    "AML.T0031": ("data_exfiltration",),
    "AML.T0020": ("tool_misuse",),
    "AML.T0040": ("tool_misuse",),
    "AML.T0048": ("tool_misuse",),
    "AML.T0050": ("tool_misuse",),
}


def attack_case_from_atlas(tactic: ATLASTactic) -> AttackCase:
    """Adapt the frozen Phase-2 ATLAS schema without changing it."""

    return AttackCase(
        id=tactic.id,
        name=tactic.name,
        description=tactic.description,
        payloads=tactic.payloads,
        severity_default=tactic.severity_default,
        detector_modes=_ATLAS_DETECTOR_MODES.get(tactic.id, ("tool_misuse",)),
        references=(tactic.mitre_url,),
    )


def get_delivery_strategy(strategy_id: str) -> DeliveryStrategy:
    """Resolve a built-in delivery strategy by stable identifier."""

    normalized = strategy_id.strip().lower()
    try:
        return DELIVERY_STRATEGIES[normalized]
    except KeyError as exc:
        raise KeyError(f"Unknown delivery strategy: {strategy_id!r}") from exc


def build_execution_plan(
    tactic_id: str,
    *,
    strategy: str,
    agent: str,
    iterations: int = 1,
    seed: int = 0,
) -> ExecutionPlan:
    """Build a deterministic plan from the existing ATLAS registry."""

    return ExecutionPlan(
        attack=attack_case_from_atlas(get_tactic(tactic_id)),
        strategy=get_delivery_strategy(strategy),
        agent=agent,
        iterations=iterations,
        seed=seed,
    )


def list_tactic_entry_points(
    entry_points_provider: Callable[..., Iterable[object]] | None = None,
) -> tuple[TacticPluginDescriptor, ...]:
    """List tactic plugin metadata without calling ``EntryPoint.load``."""

    provider = entry_points_provider or importlib.metadata.entry_points
    entries = provider(group=ATLAS_ENTRY_POINT_GROUP)
    return tuple(
        sorted(
            (
                TacticPluginDescriptor(
                    name=str(getattr(entry, "name")),
                    value=str(getattr(entry, "value")),
                )
                for entry in entries
            ),
            key=lambda item: item.name,
        )
    )


__all__ = [
    "ATLAS_ENTRY_POINT_GROUP",
    "AttackCase",
    "DeliveredAttack",
    "DeliveryStrategy",
    "DELIVERY_STRATEGIES",
    "ExecutionPlan",
    "SAFE_PAYLOAD_MARKER",
    "TacticPluginDescriptor",
    "attack_case_from_atlas",
    "build_execution_plan",
    "get_delivery_strategy",
    "list_tactic_entry_points",
]
