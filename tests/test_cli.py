"""Tests for the Click CLI."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from ai_agent_lab.cli import cli


def test_cli_help():
    runner = CliRunner()
    res = runner.invoke(cli, ["--help"])
    assert res.exit_code == 0
    assert "agent" in res.output.lower()


def test_cli_run_help():
    runner = CliRunner()
    res = runner.invoke(cli, ["run", "--help"])
    assert res.exit_code == 0
    assert "--scenario" in res.output
    assert "--output" in res.output


def test_cli_list_shows_scenarios():
    runner = CliRunner()
    res = runner.invoke(cli, ["list"])
    assert res.exit_code == 0
    assert "pi-read-passwd" in res.output
    assert "tool-misuse-rm-rf" in res.output
    assert "data-exfil-passwd" in res.output


def test_cli_targets_lists_five_vulnerable_agents():
    runner = CliRunner()
    res = runner.invoke(cli, ["targets"])
    assert res.exit_code == 0
    for name in (
        "sqli-helper",
        "email-assistant",
        "file-rag-agent",
        "web-browser-agent",
        "code-act-agent",
    ):
        assert name in res.output


def test_cli_run_demo_writes_report(tmp_path: Path):
    runner = CliRunner()
    out = tmp_path / "report.md"
    res = runner.invoke(cli, ["run", "--scenario", "demo", "--output", str(out)])
    assert res.exit_code == 0, res.output
    assert out.exists()
    body = out.read_text(encoding="utf-8")
    assert "AI Agent Security Lab Report" in body
    assert "pi-read-passwd" in body
    assert "data-exfil-passwd" in body
    assert "tool-misuse-rm-rf" in body
    assert "Attacks detected: **3 / 3**" in body


def test_cli_run_unknown_scenario_fails(tmp_path: Path):
    runner = CliRunner()
    out = tmp_path / "report.md"
    res = runner.invoke(
        cli, ["run", "--scenario", "does-not-exist", "--output", str(out)]
    )
    assert res.exit_code != 0


def test_cli_run_single_scenario(tmp_path: Path):
    runner = CliRunner()
    out = tmp_path / "report.md"
    res = runner.invoke(
        cli, ["run", "--scenario", "pi-read-passwd", "--output", str(out)]
    )
    assert res.exit_code == 0, res.output
    body = out.read_text(encoding="utf-8")
    assert "pi-read-passwd" in body
    assert "tool-misuse-rm-rf" not in body  # single scenario, others absent
