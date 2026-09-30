"""Red-team report export (Markdown / HTML / JSON) and the `redteam` CLI."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from ai_agent_lab.cli import cli
from ai_agent_lab.redteam import LLMCaseJudge, RedTeamCampaign, run_red_team
from ai_agent_lab.report.red_team_export import (
    export_red_team_report,
    render_html,
    render_json,
    render_markdown,
)
from tests.test_redteam_judge import ScriptedRouter

FIXED = datetime(2026, 10, 1, 9, 30, tzinfo=timezone(timedelta(hours=8)))
HOSTILE = '<script>alert(1)</script> | **bold** [x](http://a)'


def _campaign(reply: str | None = None) -> RedTeamCampaign:
    judge = None
    if reply is not None:
        judge = LLMCaseJudge(ScriptedRouter(lambda _request: reply), model="judge<m>")
    return run_red_team(llm_judge=judge, generated_at=FIXED)


def _hostile_campaign() -> RedTeamCampaign:
    reply = json.dumps({"verdict": "resisted", "confidence": 0.4, "reason": HOSTILE})
    return _campaign(reply)


def test_markdown_contains_summary_techniques_findings_and_limits() -> None:
    markdown = render_markdown(_campaign())
    assert markdown.startswith("# AI Agent Red-Team Report (MITRE ATLAS)")
    assert "- Generated: 2026-10-01T09:30:00+08:00" in markdown
    assert "- Test cases: 24; compromised: 22; resisted: 2" in markdown
    assert "[AML.T0053](https://atlas.mitre.org/techniques/AML.T0053)" in markdown
    assert "### T0051-01 - LLM Prompt Injection (high)" in markdown
    assert "LLM judge not enabled for this run (rule-only)." in markdown
    assert "## Limitations" in markdown


def test_markdown_comparison_section_and_escaping() -> None:
    markdown = render_markdown(_hostile_campaign())
    assert "Cohen's kappa" in markdown
    assert "| compromised | 0 | 22 |" in markdown
    assert "| resisted | 0 | 2 |" in markdown
    assert "Disagreements to review:" in markdown
    assert "<script>" not in markdown
    assert "\\<script\\>" in markdown and "\\| \\*\\*bold\\*\\*" in markdown


def test_html_is_self_contained_and_escapes_untrusted_text() -> None:
    page = render_html(_hostile_campaign())
    assert page.startswith("<!doctype html>")
    assert "<script" not in page.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "judge&lt;m&gt;" in page
    assert 'src="http' not in page and "<link" not in page
    assert "prefers-color-scheme:dark" in page
    assert 'name="viewport"' in page


def test_json_is_machine_readable() -> None:
    data = json.loads(render_json(_campaign('{"verdict": "compromised", "confidence": 1}')))
    assert data["schema"] == "ai-agent-lab/red-team-report/v1"
    assert data["summary"]["cases"] == len(data["results"]) == 24
    assert data["judge_comparison"]["compared"] == 24
    first = data["results"][0]
    assert {"case_id", "technique_id", "rule", "llm", "agrees", "mitigation"} <= set(first)


def test_export_writes_requested_formats(tmp_path: Path) -> None:
    campaign = _campaign()
    paths = export_red_team_report(campaign, tmp_path / "out", ["md", "html", "json", "md"])
    assert [p.suffix for p in paths] == [".md", ".html", ".json"]
    assert all(p.stem == "2026-10-01T09-30-00-atlas-redteam" for p in paths)
    assert all(p.read_text(encoding="utf-8") for p in paths)
    with pytest.raises(ValueError, match="unsupported"):
        export_red_team_report(campaign, tmp_path, ["pdf"])
    with pytest.raises(ValueError, match="at least one"):
        export_red_team_report(campaign, tmp_path, [])


def test_cli_redteam_rule_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LAB_LLM_KEY", raising=False)
    result = CliRunner().invoke(
        cli,
        ["redteam", "--technique", "AML.T0054", "--output-dir", str(tmp_path), "--json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["judge_mode"] == "rule-only"
    assert payload["summary"]["cases"] == 2
    assert sorted(Path(p).suffix for p in payload["reports"]) == [".html", ".md"]


def test_cli_redteam_llm_requires_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LAB_LLM_KEY", raising=False)
    result = CliRunner().invoke(
        cli, ["redteam", "--judge", "llm", "--output-dir", str(tmp_path)]
    )
    assert result.exit_code != 0
    assert "LAB_LLM_KEY" in result.output


def test_cli_redteam_with_mocked_llm_judge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    router = ScriptedRouter(lambda _request: '{"verdict": "compromised", "confidence": 0.8}')

    def fake_router(environ: Any = None) -> ScriptedRouter:
        return router

    monkeypatch.setattr("ai_agent_lab.judge.build_lab_router", fake_router)
    result = CliRunner().invoke(
        cli,
        [
            "redteam", "--agent", "code_act", "--judge", "llm", "--max-llm-cases", "3",
            "--format", "json", "--output-dir", str(tmp_path), "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["judge_mode"] == "rule+llm"
    assert payload["judge_comparison"]["compared"] == 3
    assert len(router.calls) == 3


def test_cli_lists_atlas_cases() -> None:
    result = CliRunner().invoke(cli, ["atlas-cases", "--technique", "AML.T0056"])
    assert result.exit_code == 0
    assert "T0056-01" in result.output and "Extract LLM System Prompt" in result.output
