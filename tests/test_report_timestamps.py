"""Report timestamps must be unambiguous; filenames must stay path-safe."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from ai_agent_lab.datatypes import report_now, report_timestamp
from ai_agent_lab.metrics import evaluate_asr, render_asr_markdown
from ai_agent_lab.report import default_report_path
from ai_agent_lab.report.correlation import (
    build_demo_correlation_report,
    render_correlation_markdown,
)
from ai_agent_lab.reporter import render_markdown

_OFFSET = re.compile(r"[+-]\d{2}:\d{2}$")


def test_report_now_is_timezone_aware() -> None:
    assert report_now().tzinfo is not None


def test_report_timestamp_carries_an_offset() -> None:
    stamp = report_timestamp()
    assert _OFFSET.search(stamp), stamp
    # Round-trips back to an aware datetime.
    assert datetime.fromisoformat(stamp).tzinfo is not None


def test_every_renderer_emits_an_offset_by_default() -> None:
    for markdown in (
        render_asr_markdown(evaluate_asr(include_quality=False)),
        render_markdown([]),
        render_correlation_markdown(build_demo_correlation_report()),
    ):
        line = next(
            line for line in markdown.splitlines() if "Generated at" in line
        )
        assert _OFFSET.search(line.rstrip("_")), line


def test_default_report_path_keeps_the_offset_out_of_the_filename() -> None:
    when = datetime(2026, 7, 26, 9, 31, 55, tzinfo=timezone(timedelta(hours=8)))
    path = default_report_path("AML.T0051", generated_at=when)
    assert path == default_report_path("AML.T0051", generated_at=when)
    assert path.name == "2026-07-26T09-31-55-AML.T0051.md"
    # ":" and "+" in a filename are hostile on Windows / awkward everywhere.
    assert ":" not in path.name
    assert "+" not in path.name
