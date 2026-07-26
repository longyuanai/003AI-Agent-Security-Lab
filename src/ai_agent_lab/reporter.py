"""Markdown reporter for the AI Agent lab.

Renders a per-scenario verdict, which detector(s) flagged it, and the
raw trace + evidence.
"""

from __future__ import annotations

from ai_agent_lab.datatypes import RunResult, report_timestamp


def render_markdown(
    results: list[RunResult],
    *,
    scenario_set: str = "demo",
    generated_at: str | None = None,
) -> str:
    """Render the lab results into a Markdown report."""
    when = generated_at or report_timestamp()

    lines: list[str] = []
    lines.append("# AI Agent Security Lab Report")
    lines.append("")
    lines.append(f"_Generated at {when}_")
    lines.append(f"_Scenario set: `{scenario_set}`_")
    lines.append("")

    total = len(results)
    detected = sum(1 for r in results if r.detected)
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Scenarios run: **{total}**")
    lines.append(f"- Attacks detected: **{detected} / {total}**")
    if total:
        lines.append(f"- Detection rate: **{detected / total:.0%}**")
    lines.append("")

    # Per-scenario results.
    lines.append("## Per-Scenario Results")
    lines.append("")
    lines.append("| Scenario | Category | Verdict | Method(s) | Expected | Detected? |")
    lines.append("|----------|----------|---------|-----------|----------|-----------|")
    for r in results:
        methods = ", ".join(r.detection.raw.get("methods", [r.detection.detector]))
        det_yesno = "yes" if r.detected else "**NO**"
        lines.append(
            f"| `{r.scenario_name}` | {r.category} | "
            f"**{r.detection.verdict.value}** | {methods} | "
            f"{r.expected_detection.value} | {det_yesno} |"
        )
    lines.append("")

    # Per-scenario detail.
    lines.append("## Detail")
    lines.append("")
    for r in results:
        lines.append(f"### `{r.scenario_name}` ({r.category})")
        lines.append("")
        lines.append(f"- **User input**: `{r.trace.user_input}`")
        if r.trace.tool_call.name:
            lines.append(f"- **Tool chosen**: `{r.trace.tool_call.name}`")
            if r.trace.tool_call.args:
                args_repr = ", ".join(
                    f"{k}={v!r}" for k, v in r.trace.tool_call.args.items()
                )
                lines.append(f"- **Tool args**: {args_repr}")
            lines.append(f"- **Tool result (mock)**: `{r.trace.tool_call.result}`")
        else:
            lines.append("- **Tool chosen**: _none_")
        lines.append(f"- **Verdict**: **{r.detection.verdict.value}**")
        lines.append(f"- **Evidence**: {r.detection.evidence or '_none_'}")
        lines.append(f"- **Detected?**: {'YES' if r.detected else 'NO'}")
        lines.append("")

    # Final line: pass/fail summary.
    if total and detected == total:
        lines.append("> **Result**: all built-in attacks detected.")
    elif total:
        lines.append(f"> **Result**: {total - detected} of {total} attacks missed.")
    lines.append("")

    return "\n".join(lines)
