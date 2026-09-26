"""Five-Agent benign/attack control-suite tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from ai_agent_lab.task_suites import (
    AgentTask,
    TaskKind,
    TaskSuiteRunner,
    built_in_task_suites,
)


def test_registry_contains_five_agent_task_suites() -> None:
    suites = built_in_task_suites()
    assert set(suites) == {
        "sql_assistant",
        "email_assistant",
        "file_rag",
        "web_browser",
        "code_act",
    }
    assert all(suite.benign_tasks for suite in suites.values())
    assert all(suite.attack_tasks for suite in suites.values())


def test_all_benign_controls_complete_expected_task() -> None:
    runner = TaskSuiteRunner()
    for suite in built_in_task_suites().values():
        result = runner.run_task(suite.benign_tasks[0])
        assert result.task_completed is True
        assert result.oracle is None
        assert result.trace.tool_call.name == result.task.expected_tool


def test_all_primary_attacks_have_objective_success() -> None:
    pairs = TaskSuiteRunner().run_all_control_pairs()
    assert len(pairs) == 5
    assert all(pair.attack_success for pair in pairs)
    assert all(pair.attacked.oracle is not None for pair in pairs)


def test_control_pairs_preserve_utility_signal_separately() -> None:
    pairs = TaskSuiteRunner().run_all_control_pairs()
    assert all(pair.utility_preserved for pair in pairs)
    assert all(pair.control.attack_success is False for pair in pairs)
    assert all(pair.attacked.task.kind is TaskKind.ATTACK for pair in pairs)


def test_task_execution_contains_only_mock_tool_results() -> None:
    pairs = TaskSuiteRunner().run_all_control_pairs()
    executions = [
        execution
        for pair in pairs
        for execution in (pair.control, pair.attacked)
    ]
    assert all(execution.trace.tool_call.result.startswith("[mock]") for execution in executions)


def test_task_serialization_does_not_add_conversation_history() -> None:
    execution = TaskSuiteRunner().run_all_control_pairs()[0].attacked
    serialized = str(execution.to_dict()).lower()
    assert "conversation_history" not in serialized
    assert "chat_history" not in serialized
    assert "messages" not in serialized


def test_task_contract_is_frozen() -> None:
    task = built_in_task_suites()["sql_assistant"].benign_tasks[0]
    with pytest.raises(FrozenInstanceError):
        task.id = "changed"  # type: ignore[misc]


def test_attack_task_requires_non_benign_category() -> None:
    with pytest.raises(ValueError, match="attack category"):
        AgentTask(
            id="broken",
            agent="sql_assistant",
            kind=TaskKind.ATTACK,
            input_text="fixture",
            expected_tool="sql_query",
        )


def test_unknown_agent_is_rejected() -> None:
    task = AgentTask(
        id="unknown",
        agent="unknown",
        kind=TaskKind.BENIGN,
        input_text="fixture",
        expected_tool="fixture_tool",
    )
    with pytest.raises(KeyError, match="Unknown task-suite agent"):
        TaskSuiteRunner().run_task(task)
