"""Backward-compatible report package plus privacy-safe exporters."""

from ai_agent_lab.report.benchmark_evidence import (
    build_benchmark_evidence,
    write_benchmark_evidence,
)

from ai_agent_lab.report.correlation import (
    CrossScenarioReport,
    TargetCorrelation,
    build_correlation_report,
    build_demo_correlation_report,
    register_findings,
    render_correlation_markdown,
    write_correlation_markdown,
)
from ai_agent_lab.report.json_evidence import (
    build_json_evidence,
    write_json_evidence,
)
from ai_agent_lab.report.markdown import (
    default_report_path,
    render_red_team_markdown,
    write_red_team_markdown,
)

__all__ = [
    "build_benchmark_evidence",
    "write_benchmark_evidence",
    "CrossScenarioReport",
    "TargetCorrelation",
    "build_correlation_report",
    "build_demo_correlation_report",
    "register_findings",
    "render_correlation_markdown",
    "write_correlation_markdown",
    "build_json_evidence",
    "write_json_evidence",
    "default_report_path",
    "render_red_team_markdown",
    "write_red_team_markdown",
]
