"""Jinja-backed Markdown red-team report rendering."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, StrictUndefined

from ai_agent_lab.datatypes import report_now
from ai_agent_lab.runner import AtlasRun

_TEMPLATE_PATH = Path(__file__).with_name("template.md")


def default_report_path(
    attack_id: str,
    *,
    generated_at: datetime | None = None,
) -> Path:
    """Return a Windows-safe ISO timestamp report path."""

    when = generated_at or report_now()
    # Local wall-clock only: the UTC offset belongs in the report body, not in
    # a filename, where "+08:00" would sanitise into a confusing "+08-00".
    timestamp = when.strftime("%Y-%m-%dT%H-%M-%S")
    return Path("output") / f"{timestamp}-{attack_id}.md"


def render_red_team_markdown(
    run: AtlasRun,
    envelope: Mapping[str, Any],
    *,
    generated_at: str,
    evidence_filename: str,
) -> str:
    template_text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    template = Environment(
        autoescape=False,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    ).from_string(template_text)
    rows = []
    for record in run.records:
        rows.append(
            {
                "iteration": record.iteration,
                "payload_variant": record.payload_index,
                "judge": (
                    record.judge.verdict.value if record.judge else "unavailable"
                ),
                "confidence": (
                    f"{record.judge.confidence:.0%}" if record.judge else "-"
                ),
                "status": record.error or "completed",
            }
        )
    rendered = template.render(
        generated_at=generated_at,
        tactic=run.tactic,
        agent=run.agent,
        seed=run.seed,
        summary=envelope.get("summary", {}),
        findings=envelope.get("findings", []),
        errors=envelope.get("errors", []),
        rows=rows,
        evidence_filename=evidence_filename,
    )
    return rendered.rstrip() + "\n"


def write_red_team_markdown(markdown: str, output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown, encoding="utf-8")
    return path
