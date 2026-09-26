"""Commercial benchmark CLI contract and privacy tests."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from ai_agent_lab.cli import cli


def test_benchmark_help_exposes_commercial_options() -> None:
    result = CliRunner().invoke(cli, ["benchmark", "--help"])
    assert result.exit_code == 0
    for option in (
        "--offline",
        "--live",
        "--seed",
        "--dry-run",
        "--report",
        "--json-evidence",
        "--json",
    ):
        assert option in result.output


def test_benchmark_offline_writes_markdown_and_json(tmp_path: Path) -> None:
    markdown = tmp_path / "benchmark.md"
    evidence = tmp_path / "benchmark-evidence.json"
    result = CliRunner().invoke(
        cli,
        [
            "benchmark",
            "--offline",
            "--seed",
            "2026",
            "--report",
            str(markdown),
            "--json-evidence",
            str(evidence),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert markdown.exists()
    assert payload["seed"] == 2026
    assert summary["judge_mode"] == "stub"
    assert summary["offline"] is True
    assert summary["summary"]["total"] == 10


def test_benchmark_default_evidence_path_matches_report(tmp_path: Path) -> None:
    markdown = tmp_path / "custom.md"
    result = CliRunner().invoke(
        cli,
        ["benchmark", "--report", str(markdown), "--json"],
    )
    assert result.exit_code == 0, result.output
    assert markdown.exists()
    assert markdown.with_suffix(".json").exists()
    assert json.loads(result.output)["evidence_path"] == str(
        markdown.with_suffix(".json")
    )


def test_benchmark_dry_run_does_not_execute_or_write(monkeypatch) -> None:
    def unexpected_execution(**kwargs):
        raise AssertionError(f"benchmark executed: {kwargs}")

    monkeypatch.setattr(
        "ai_agent_lab.cli.evaluate_task_benchmark", unexpected_execution
    )
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            cli,
            [
                "benchmark",
                "--dry-run",
                "--report",
                "should-not-exist.md",
                "--json-evidence",
                "should-not-exist.json",
            ],
        )
        assert result.exit_code == 0, result.output
        plan = json.loads(result.output)
        assert plan["mode"] == "dry-run"
        assert plan["writes_files"] is False
        assert len(plan["agents"]) == 5
        assert len(plan["tasks"]) == 10
        assert not Path("should-not-exist.md").exists()
        assert not Path("should-not-exist.json").exists()


def test_benchmark_live_without_key_falls_back_to_stub(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "benchmark",
            "--live",
            "--report",
            str(tmp_path / "live.md"),
            "--json",
        ],
        env={"LAB_LLM_KEY": ""},
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["offline"] is False
    assert payload["judge_mode"] == "stub"


def test_benchmark_rejects_negative_seed_without_outputs(tmp_path: Path) -> None:
    output = tmp_path / "invalid.md"
    result = CliRunner().invoke(
        cli,
        ["benchmark", "--seed", "-1", "--report", str(output)],
    )
    assert result.exit_code != 0
    assert not output.exists()


def test_benchmark_outputs_contain_no_input_or_conversation_content(
    tmp_path: Path,
) -> None:
    markdown = tmp_path / "privacy.md"
    result = CliRunner().invoke(
        cli,
        ["benchmark", "--report", str(markdown), "--json"],
    )
    assert result.exit_code == 0, result.output
    combined = (
        result.output
        + markdown.read_text(encoding="utf-8")
        + markdown.with_suffix(".json").read_text(encoding="utf-8")
    ).lower()
    assert "user_input" not in combined
    assert "input_text" not in combined
    assert "raw_prompt" not in combined
    assert "conversation_history" not in combined


def test_scan_json_envelope_remains_backward_compatible() -> None:
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            '{"agent":"sql_assistant","attack":"not_an_attack"}',
            "--json",
        ],
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == {"findings": [], "errors": []}
