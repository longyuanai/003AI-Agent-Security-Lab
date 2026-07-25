"""CLI report path and module-entrypoint tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from click.testing import CliRunner

from ai_agent_lab.cli import cli


def test_cli_report_explicit_path_writes_markdown_and_json(tmp_path) -> None:
    report_path = tmp_path / "atlas.md"
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            '{"attack":"AML.T0051","agent":"sql_assistant","iterations":2}',
            "--report",
            str(report_path),
            "--json",
        ],
        env={"LAB_LLM_KEY": ""},
    )
    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert report_path.exists()
    assert report_path.with_suffix(".json").exists()
    assert envelope["summary"]["report_path"] == str(report_path)
    assert envelope["summary"]["evidence_path"] == str(
        report_path.with_suffix(".json")
    )


def test_cli_report_default_path_uses_output_iso_and_attack_id() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            cli,
            [
                "scan",
                "--input",
                '{"attack":"AML.T0051","agent":"email_assistant","iterations":1}',
                "--json",
            ],
            env={"LAB_LLM_KEY": ""},
        )
        assert result.exit_code == 0, result.output
        paths = list(Path("output").glob("*-AML.T0051.md"))
        assert len(paths) == 1
        assert paths[0].with_suffix(".json").exists()


def test_cli_report_help_exposes_report_option() -> None:
    result = CliRunner().invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--report" in result.output


def test_python_m_ai_agent_lab_entrypoint(tmp_path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    report_path = tmp_path / "module-entry.md"
    env = os.environ.copy()
    env["LAB_LLM_KEY"] = ""
    env["PYTHONPATH"] = os.pathsep.join(
        filter(
            None,
            [str(project_root / "src"), env.get("PYTHONPATH", "")],
        )
    )
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "ai_agent_lab",
            "scan",
            "--input",
            '{"attack":"AML.T0051","agent":"code_act","iterations":1}',
            "--report",
            str(report_path),
            "--json",
        ],
        cwd=project_root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout)["summary"]["judge_mode"] == "stub"
    assert report_path.exists()
