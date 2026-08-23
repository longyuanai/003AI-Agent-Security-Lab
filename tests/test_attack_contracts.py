"""AttackCase and DeliveryStrategy contract tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from ai_agent_lab.attack_contracts import (
    ATLAS_ENTRY_POINT_GROUP,
    DELIVERY_STRATEGIES,
    AttackCase,
    DeliveryStrategy,
    attack_case_from_atlas,
    build_execution_plan,
    get_delivery_strategy,
    list_tactic_entry_points,
)
from ai_agent_lab.atlas import get_tactic


def test_atlas_adapter_preserves_frozen_contract_fields() -> None:
    tactic = get_tactic("AML.T0051")
    case = attack_case_from_atlas(tactic)
    assert case.id == tactic.id
    assert case.payloads == tactic.payloads
    assert case.severity_default is tactic.severity_default
    assert case.references == (tactic.mitre_url,)
    assert case.detector_modes == ("prompt_injection",)


def test_attack_case_rejects_payload_without_safe_marker() -> None:
    tactic = get_tactic("AML.T0051")
    with pytest.raises(ValueError, match="safe-lab|SAFE LAB"):
        AttackCase(
            id="fixture",
            name="fixture",
            description="fixture",
            payloads=("unsafe fixture",),
            severity_default=tactic.severity_default,
            detector_modes=("prompt_injection",),
        )


def test_delivery_registry_exposes_channel_specific_strategies() -> None:
    assert set(DELIVERY_STRATEGIES) == {
        "direct",
        "email_resource",
        "document_resource",
        "web_resource",
        "tool_output",
    }
    assert get_delivery_strategy("WEB_RESOURCE").channel == "web"


def test_delivery_strategy_requires_payload_placeholder() -> None:
    with pytest.raises(ValueError, match="payload"):
        DeliveryStrategy(
            id="broken",
            name="broken",
            channel="fixture",
            template="missing placeholder",
            supported_agents=("sql_assistant",),
        )


def test_strategy_refuses_an_unsupported_agent() -> None:
    payload = get_tactic("AML.T0051").payloads[0]
    with pytest.raises(ValueError, match="does not support"):
        get_delivery_strategy("email_resource").deliver(
            payload,
            agent="web_browser",
        )


def test_execution_plan_uses_unique_variants_before_reuse() -> None:
    plan = build_execution_plan(
        "AML.T0051",
        strategy="direct",
        agent="sql_assistant",
        iterations=5,
        seed=51,
    )
    delivered = plan.materialize()
    assert len(delivered) == 5
    assert len({item.payload_index for item in delivered}) == 5
    assert [item.iteration for item in delivered] == [1, 2, 3, 4, 5]


def test_execution_plan_is_reproducible_from_seed() -> None:
    args = {
        "strategy": "tool_output",
        "agent": "code_act",
        "iterations": 8,
        "seed": 2026,
    }
    first = build_execution_plan("AML.T0051", **args).materialize()
    second = build_execution_plan("AML.T0051", **args).materialize()
    assert first == second
    assert all("[SAFE LAB SIMULATION]" in item.delivered_payload for item in first)


def test_execution_plan_contract_is_frozen() -> None:
    plan = build_execution_plan(
        "AML.T0054",
        strategy="web_resource",
        agent="web_browser",
    )
    with pytest.raises(FrozenInstanceError):
        plan.seed = 4  # type: ignore[misc]


def test_entry_point_listing_does_not_load_plugins() -> None:
    class FakeEntryPoint:
        name = "AML.T0999"
        value = "fixture.module:TACTIC"

        def load(self):  # pragma: no cover - must never be invoked
            raise AssertionError("plugin code was executed")

    calls: list[str] = []

    def provider(*, group: str):
        calls.append(group)
        return [FakeEntryPoint()]

    descriptors = list_tactic_entry_points(provider)
    assert calls == [ATLAS_ENTRY_POINT_GROUP]
    assert descriptors[0].name == "AML.T0999"
    assert descriptors[0].value == "fixture.module:TACTIC"
