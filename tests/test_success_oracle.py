"""Objective SuccessOracle and append-only safe-state tests."""

from __future__ import annotations

import pytest

from ai_agent_lab.attacks import built_in_scenarios
from ai_agent_lab.detector import Detector
from ai_agent_lab.oracle import (
    EffectBoundary,
    SafeLabState,
    StateEffect,
    SuccessOracle,
    apply_trace_effect,
)
from ai_agent_lab.target import built_in_targets


def _scenario(category: str):
    return next(item for item in built_in_scenarios() if item.category == category)


def _target(agent_type: str):
    return next(item for item in built_in_targets() if item.agent_type == agent_type)


def _trace(category: str, agent_type: str):
    scenario = _scenario(category)
    return _target(agent_type).run(
        scenario.payload,
        scenario_name=scenario.name,
        category=scenario.category,
    )


def test_sql_oracle_succeeds_on_unscoped_query_effect() -> None:
    result = SuccessOracle().evaluate_trace(_trace("sql_injection", "sqli"))
    assert result.success is True
    assert result.matched_effect is not None
    assert result.matched_effect.boundary is EffectBoundary.UNSCOPED_QUERY


def test_oracle_does_not_treat_any_tool_call_as_success() -> None:
    trace = _trace("sql_injection", "web_browser")
    result = SuccessOracle().evaluate_trace(trace)
    assert trace.tool_call.name == ""
    assert result.success is False
    assert result.matched_effect is None


def test_detector_signal_is_independent_from_objective_success() -> None:
    trace = _trace("sql_injection", "web_browser")
    detection = Detector().detect(trace)
    oracle = SuccessOracle().evaluate_trace(trace)
    assert detection.verdict.value == "malicious"
    assert oracle.success is False


@pytest.mark.parametrize(
    ("category", "agent_type", "boundary"),
    [
        ("email_exfiltration", "email", EffectBoundary.EXTERNAL_RECIPIENT),
        ("path_traversal", "file_rag", EffectBoundary.WORKSPACE_ESCAPE),
        ("browser_ssrf", "web_browser", EffectBoundary.RESTRICTED_NETWORK),
        (
            "code_act_privilege_escalation",
            "code_act",
            EffectBoundary.PRIVILEGED_EXECUTION,
        ),
        ("rag_poisoning", "file_rag", EffectBoundary.UNTRUSTED_RESOURCE),
    ],
)
def test_oracle_recognizes_safe_fixture_boundary_effects(
    category: str,
    agent_type: str,
    boundary: EffectBoundary,
) -> None:
    result = SuccessOracle().evaluate_trace(_trace(category, agent_type))
    assert result.success is True
    assert result.matched_effect is not None
    assert result.matched_effect.boundary is boundary


def test_safe_lab_state_append_returns_a_new_state() -> None:
    before = SafeLabState()
    trace = _trace("tool_misuse", "email")
    after = apply_trace_effect(before, trace)
    assert before.effects == ()
    assert len(after.effects) == 1
    assert after.effects[0].boundary is EffectBoundary.DESTRUCTIVE_ACTION


def test_oracle_rejects_non_append_only_state() -> None:
    first = StateEffect(
        "email",
        "delete",
        "fixture-a",
        EffectBoundary.DESTRUCTIVE_ACTION,
        "delete_email",
    )
    replacement = StateEffect(
        "email",
        "delete",
        "fixture-b",
        EffectBoundary.DESTRUCTIVE_ACTION,
        "delete_email",
    )
    with pytest.raises(ValueError, match="append-only"):
        SuccessOracle().evaluate(
            category="tool_misuse",
            before=SafeLabState((first,)),
            after=SafeLabState((replacement,)),
        )


def test_oracle_rejects_unknown_category() -> None:
    with pytest.raises(KeyError, match="Unknown oracle category"):
        SuccessOracle().evaluate(
            category="unknown",
            before=SafeLabState(),
            after=SafeLabState(),
        )
