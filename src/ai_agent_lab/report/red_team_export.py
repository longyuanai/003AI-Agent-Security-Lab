"""Red-team campaign report export: Markdown, self-contained HTML and JSON.

All values that originate from probes, tool arguments or model output are
escaped (Markdown table cells and HTML), since a judge reply or tool argument
is untrusted text. The HTML file has no external resources or scripts.
"""

from __future__ import annotations

import html
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ai_agent_lab.redteam import RedTeamCampaign

FORMATS = ("md", "html", "json")

_LIMITATIONS = (
    "Targets are the lab's deliberately vulnerable, mock-only agents; no tool "
    "was executed and no network request was made.",
    "Rule verdicts only see tool calls. Text-only leaks (for example system "
    "prompt disclosure without a tool call) are reported as resisted by the "
    "rule; use the LLM judge or a human review for those cases.",
    "LLM-judge verdicts are advisory: compare them with the rule and review "
    "every disagreement before reporting a finding.",
)


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value:.0%}"


def _kappa(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def _md(text: object) -> str:
    """Make a value safe for a single Markdown table cell."""

    value = str(text if text is not None else "-")
    value = value.replace("\\", "\\\\").replace("|", "\\|")
    value = value.replace("\r", " ").replace("\n", " ")
    for char in "`*_<>[]":
        value = value.replace(char, "\\" + char)
    return value or "-"


def _tool_summary(tool_call: dict[str, Any]) -> str:
    if not tool_call.get("name"):
        return "(no tool call)"
    args = json.dumps(tool_call.get("args", {}), ensure_ascii=False, sort_keys=True)
    if len(args) > 120:
        args = args[:117] + "..."
    return f"{tool_call['name']} {args}"


def _llm_cell(result: dict[str, Any]) -> str:
    llm = result.get("llm")
    if not llm:
        return "-"
    return f"{llm['verdict']} ({llm['confidence']:.2f})"


def render_markdown(campaign: RedTeamCampaign) -> str:
    data = campaign.to_dict()
    summary = data["summary"]
    lines = [
        "# AI Agent Red-Team Report (MITRE ATLAS)",
        "",
        f"- Generated: {data['generated_at']}",
        f"- Judge mode: {data['judge_mode']}"
        + (f" (model: {_md(data['judge_model'])})" if data["judge_model"] else ""),
        f"- Test cases: {summary['cases']}; compromised: {summary['compromised']}; "
        f"resisted: {summary['resisted']}",
        "- Compromised by severity: "
        + ", ".join(f"{level} {count}" for level, count in summary["severity"].items()),
        "",
        "## Techniques",
        "",
        "| Technique | Name | ATLAS tactics | Severity | Cases | Compromised |",
        "|---|---|---|---|---|---|",
    ]
    for row in data["techniques"]:
        lines.append(
            f"| [{row['technique_id']}]({row['mitre_url']}) | {_md(row['technique_name'])} "
            f"| {_md(row['atlas_tactics'])} | {row['severity']} | {row['cases']} "
            f"| {row['compromised']} |"
        )
    lines += [
        "",
        "## Case results",
        "",
        "| Case | Agent | Severity | Tool call | Rule | LLM judge |",
        "|---|---|---|---|---|---|",
    ]
    for result in data["results"]:
        lines.append(
            f"| {_md(result['case_id'])} | {_md(result['agent'])} | {result['severity']} "
            f"| {_md(_tool_summary(result['tool_call']))} | {result['rule']['verdict']} "
            f"| {_md(_llm_cell(result))} |"
        )
    findings = [r for r in data["results"] if r["rule"]["verdict"] == "compromised"]
    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No test case compromised the target agents.")
    for result in findings:
        lines += [
            f"### {_md(result['case_id'])} - {_md(result['technique_name'])} "
            f"({result['severity']})",
            "",
            f"- Agent: {_md(result['agent'])}",
            f"- Evidence: {_md(result['rule']['evidence'])}",
            f"- Expected behaviour: {_md(result['expected_behavior'])}",
            f"- Mitigation: {_md(result['mitigation'])}",
            f"- Reference: {result['mitre_url']}",
            "",
        ]
    comparison = data["judge_comparison"]
    lines += ["## Rule vs. LLM judge", ""]
    if comparison is None:
        lines.append("LLM judge not enabled for this run (rule-only).")
    else:
        confusion = comparison["confusion"]
        lines += [
            f"- Compared cases: {comparison['compared']}; agreement: "
            f"{comparison['agreements']} ({_pct(comparison['agreement_rate'])}); "
            f"Cohen's kappa: {_kappa(comparison['cohen_kappa'])}",
            f"- Inconclusive: {comparison['inconclusive']}; errors: {comparison['errors']}",
            "",
            "| Rule \\ LLM | compromised | resisted |",
            "|---|---|---|",
        ]
        for rule_label in ("compromised", "resisted"):
            row = confusion[rule_label]
            lines.append(f"| {rule_label} | {row['compromised']} | {row['resisted']} |")
        lines.append("")
        if comparison["disagreements"]:
            lines.append("Disagreements to review:")
            lines.append("")
            by_id = {r["case_id"]: r for r in data["results"]}
            for case_id in comparison["disagreements"]:
                result = by_id[case_id]
                reason = result["llm"]["reason"] if result["llm"] else ""
                lines.append(
                    f"- {_md(case_id)}: rule={result['rule']['verdict']}, "
                    f"LLM={result['llm']['verdict']} - {_md(reason)}"
                )
        else:
            lines.append("No disagreements between rule and LLM judge.")
    lines += ["", "## Limitations", ""]
    lines += [f"- {item}" for item in _LIMITATIONS]
    return "\n".join(lines).rstrip() + "\n"


_CSS = """
:root{color-scheme:light dark;--fg:#1d2330;--bg:#fff;--muted:#5b6474;--line:#d9dee7;
--bad:#b42318;--ok:#067647;--card:#f6f8fb}
@media (prefers-color-scheme:dark){:root{--fg:#e6e9ef;--bg:#12151b;--muted:#9aa3b2;
--line:#2c323d;--bad:#f97066;--ok:#47cd89;--card:#1a1f27}}
body{font:14px/1.5 system-ui,sans-serif;color:var(--fg);background:var(--bg);
margin:0 auto;max-width:1100px;padding:24px 16px}
h1{font-size:22px}h2{font-size:18px;margin-top:32px}h3{font-size:15px}
.cards{display:flex;flex-wrap:wrap;gap:12px}.card{background:var(--card);
border:1px solid var(--line);border-radius:8px;padding:12px 16px;min-width:140px}
.card b{display:block;font-size:22px}.muted{color:var(--muted)}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
code{font-size:12px;word-break:break-all}.compromised{color:var(--bad);font-weight:600}
.resisted{color:var(--ok);font-weight:600}
"""


def _h(value: object) -> str:
    return html.escape(str(value if value is not None else "-"), quote=True)


def _verdict_span(verdict: str) -> str:
    css = verdict if verdict in ("compromised", "resisted") else "muted"
    return f'<span class="{css}">{_h(verdict)}</span>'


def render_html(campaign: RedTeamCampaign) -> str:
    data = campaign.to_dict()
    summary = data["summary"]
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>ATLAS Red-Team Report</title>",
        f"<style>{_CSS}</style></head><body>",
        "<h1>AI Agent Red-Team Report (MITRE ATLAS)</h1>",
        f'<p class="muted">Generated {_h(data["generated_at"])} &middot; judge mode '
        f"{_h(data['judge_mode'])}"
        + (f" &middot; model {_h(data['judge_model'])}" if data["judge_model"] else "")
        + "</p>",
        '<div class="cards">',
        f'<div class="card"><b>{summary["cases"]}</b>test cases</div>',
        f'<div class="card"><b class="compromised">{summary["compromised"]}</b>compromised</div>',
        f'<div class="card"><b class="resisted">{summary["resisted"]}</b>resisted</div>',
    ]
    for level, count in summary["severity"].items():
        parts.append(f'<div class="card"><b>{count}</b>{_h(level)}</div>')
    parts.append("</div>")

    parts += [
        "<h2>Techniques</h2>",
        '<div class="wrap"><table><thead><tr><th>Technique</th><th>Name</th>'
        "<th>ATLAS tactics</th><th>Severity</th><th>Cases</th><th>Compromised</th>"
        "</tr></thead><tbody>",
    ]
    for row in data["techniques"]:
        parts.append(
            f'<tr><td><a href="{_h(row["mitre_url"])}">{_h(row["technique_id"])}</a></td>'
            f"<td>{_h(row['technique_name'])}</td><td>{_h(row['atlas_tactics'])}</td>"
            f"<td>{_h(row['severity'])}</td><td>{row['cases']}</td>"
            f"<td>{row['compromised']}</td></tr>"
        )
    parts.append("</tbody></table></div>")

    parts += [
        "<h2>Case results</h2>",
        '<div class="wrap"><table><thead><tr><th>Case</th><th>Agent</th><th>Severity</th>'
        "<th>Tool call</th><th>Rule</th><th>LLM judge</th></tr></thead><tbody>",
    ]
    for result in data["results"]:
        llm = result["llm"]
        llm_cell = (
            f"{_verdict_span(llm['verdict'])} ({llm['confidence']:.2f})" if llm else "-"
        )
        parts.append(
            f"<tr><td>{_h(result['case_id'])}</td><td>{_h(result['agent'])}</td>"
            f"<td>{_h(result['severity'])}</td>"
            f"<td><code>{_h(_tool_summary(result['tool_call']))}</code></td>"
            f"<td>{_verdict_span(result['rule']['verdict'])}</td><td>{llm_cell}</td></tr>"
        )
    parts.append("</tbody></table></div>")

    findings = [r for r in data["results"] if r["rule"]["verdict"] == "compromised"]
    parts.append("<h2>Findings</h2>")
    if not findings:
        parts.append("<p>No test case compromised the target agents.</p>")
    for result in findings:
        parts += [
            f"<h3>{_h(result['case_id'])} &ndash; {_h(result['technique_name'])} "
            f"({_h(result['severity'])})</h3><ul>",
            f"<li>Agent: {_h(result['agent'])}</li>",
            f"<li>Probe: <code>{_h(result['probe'])}</code></li>",
            f"<li>Evidence: {_h(result['rule']['evidence'])}</li>",
            f"<li>Expected behaviour: {_h(result['expected_behavior'])}</li>",
            f"<li>Mitigation: {_h(result['mitigation'])}</li>",
            f'<li>Reference: <a href="{_h(result["mitre_url"])}">'
            f"{_h(result['mitre_url'])}</a></li></ul>",
        ]

    parts.append("<h2>Rule vs. LLM judge</h2>")
    comparison = data["judge_comparison"]
    if comparison is None:
        parts.append("<p>LLM judge not enabled for this run (rule-only).</p>")
    else:
        confusion = comparison["confusion"]
        parts += [
            f"<p>Compared {comparison['compared']} cases; agreement "
            f"{comparison['agreements']} ({_pct(comparison['agreement_rate'])}); "
            f"Cohen's kappa {_kappa(comparison['cohen_kappa'])}; inconclusive "
            f"{comparison['inconclusive']}; errors {comparison['errors']}.</p>",
            '<div class="wrap"><table><thead><tr><th>Rule \\ LLM</th><th>compromised</th>'
            "<th>resisted</th></tr></thead><tbody>",
        ]
        for rule_label in ("compromised", "resisted"):
            row = confusion[rule_label]
            parts.append(
                f"<tr><td>{rule_label}</td><td>{row['compromised']}</td>"
                f"<td>{row['resisted']}</td></tr>"
            )
        parts.append("</tbody></table></div>")
        if comparison["disagreements"]:
            by_id = {r["case_id"]: r for r in data["results"]}
            parts.append("<p>Disagreements to review:</p><ul>")
            for case_id in comparison["disagreements"]:
                result = by_id[case_id]
                parts.append(
                    f"<li>{_h(case_id)}: rule {_verdict_span(result['rule']['verdict'])}, "
                    f"LLM {_verdict_span(result['llm']['verdict'])} &ndash; "
                    f"{_h(result['llm']['reason'])}</li>"
                )
            parts.append("</ul>")
        else:
            parts.append("<p>No disagreements between rule and LLM judge.</p>")

    parts.append("<h2>Limitations</h2><ul>")
    parts += [f"<li>{_h(item)}</li>" for item in _LIMITATIONS]
    parts.append("</ul></body></html>")
    return "\n".join(parts) + "\n"


def render_json(campaign: RedTeamCampaign) -> str:
    return json.dumps(campaign.to_dict(), ensure_ascii=False, indent=2) + "\n"


_RENDERERS = {"md": render_markdown, "html": render_html, "json": render_json}


def default_report_stem(campaign: RedTeamCampaign) -> str:
    return campaign.generated_at.strftime("%Y-%m-%dT%H-%M-%S") + "-atlas-redteam"


def export_red_team_report(
    campaign: RedTeamCampaign,
    output_dir: str | Path,
    formats: Iterable[str] = ("md", "html"),
    *,
    stem: str | None = None,
) -> list[Path]:
    """Write the requested formats; returns the written paths in order."""

    selected = []
    for fmt in formats:
        normalized = fmt.strip().lower()
        if normalized not in _RENDERERS:
            raise ValueError(f"unsupported report format {fmt!r}; choose from {FORMATS}")
        if normalized not in selected:
            selected.append(normalized)
    if not selected:
        raise ValueError("at least one report format is required")
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    base = stem or default_report_stem(campaign)
    written = []
    for fmt in selected:
        path = directory / f"{base}.{fmt}"
        path.write_text(_RENDERERS[fmt](campaign), encoding="utf-8", newline="\n")
        written.append(path)
    return written


__all__ = [
    "FORMATS",
    "default_report_stem",
    "export_red_team_report",
    "render_html",
    "render_json",
    "render_markdown",
]
