"""ATLAS variant runner tests."""

from __future__ import annotations

import random

import pytest

from ai_agent_lab.runner import run_atlas_tactic


def test_runner_uses_five_different_payload_variants() -> None:
    run = run_atlas_tactic(
        "AML.T0051",
        agent="sql_assistant",
        iterations=5,
        rng=random.Random(51),
    )
    assert len(run.records) == 5
    assert len(set(run.used_payloads)) == 5


def test_runner_records_payload_index_and_iteration() -> None:
    run = run_atlas_tactic(
        "AML.T0051",
        agent="web_browser",
        iterations=3,
        rng=random.Random(1),
    )
    assert [record.iteration for record in run.records] == [1, 2, 3]
    assert all(0 <= record.payload_index < 5 for record in run.records)


def test_runner_trace_uses_atlas_id_without_real_tool_action() -> None:
    run = run_atlas_tactic(
        "AML.T0051.002",
        agent="code_act",
        iterations=1,
        rng=random.Random(2),
    )
    record = run.records[0]
    assert record.trace.scenario_name == "AML.T0051.002"
    assert record.trace.category == "mitre_atlas"
    assert record.trace.tool_call.name == ""


def test_runner_rejects_unknown_agent() -> None:
    with pytest.raises(KeyError, match="Unknown lab agent"):
        run_atlas_tactic("AML.T0051", agent="unknown", iterations=1)


@pytest.mark.parametrize("iterations", [0, 101])
def test_runner_rejects_invalid_iteration_count(iterations: int) -> None:
    with pytest.raises(ValueError, match="between 1 and 100"):
        run_atlas_tactic(
            "AML.T0051",
            agent="sql_assistant",
            iterations=iterations,
        )


def test_runner_cycles_only_after_all_variants_are_used() -> None:
    run = run_atlas_tactic(
        "AML.T0051",
        agent="file_rag",
        iterations=6,
        rng=random.Random(3),
    )
    assert len(set(run.used_payloads[:5])) == 5
    assert len(run.records) == 6
