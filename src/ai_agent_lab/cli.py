"""CLI: `ai-agent-lab run --scenario demo --output report.md`.

The CLI is intentionally thin - it delegates the heavy lifting to
`runner.run_demo()` and `reporter.render_markdown()`. Network is opt-in
via the shared-llm-core router; when no router is reachable we still
run the heuristic detector so the demo always works offline.
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console

from ai_agent_lab import __version__
from ai_agent_lab.attacks import built_in_scenarios, get_scenario
from ai_agent_lab.metrics import evaluate_asr, write_asr_reports
from ai_agent_lab.multi_agent import run_offline_mcp_abuse_demo
from ai_agent_lab.orchestrator import LabMission, build_llm_runtime
from ai_agent_lab.report import (
    build_demo_correlation_report,
    build_json_evidence,
    default_report_path,
    render_red_team_markdown,
    write_correlation_markdown,
    write_json_evidence,
    write_red_team_markdown,
)
from ai_agent_lab.runner import (
    atlas_run_to_envelope,
    run_atlas_tactic,
    run_demo,
    run_scenario,
)
from ai_agent_lab.sandbox import Sandbox, SandboxError, SandboxPolicy
from ai_agent_lab.scan import scan_payload
from ai_agent_lab.scenarios import evaluate_demo_scenarios
from ai_agent_lab.target import built_in_targets

console = Console()


@click.group()
@click.version_option(__version__)
def cli() -> None:
    """AI-Agent-Security-Lab: vulnerable agent + attack scenarios + detection."""


@cli.command("scan")
@click.option(
    "--input",
    "input_payload",
    help="JSON payload. When omitted, read one JSON object from stdin.",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit the IntegrationGateway JSON findings envelope.",
)
@click.option(
    "--report",
    "report_path",
    type=click.Path(),
    help=(
        "Markdown report path. ATLAS scans default to "
        "output/<ISO timestamp>-<attack_id>.md."
    ),
)
def scan_cmd(
    input_payload: str | None,
    json_output: bool,
    report_path: str | None,
) -> None:
    """Run one adapter-compatible Agent × Attack scan."""

    raw = input_payload if input_payload is not None else sys.stdin.read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"invalid JSON input: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise click.ClickException("input payload must be a JSON object")

    attack = str(payload.get("attack", "")).strip().upper()
    if attack.startswith("AML.T"):
        try:
            atlas_run = run_atlas_tactic(
                attack,
                agent=str(payload.get("agent", "")),
                iterations=int(payload.get("iterations", 1)),
            )
            atlas_envelope = atlas_run_to_envelope(atlas_run)
            generated_at_dt = datetime.now()
            generated_at = generated_at_dt.isoformat(timespec="seconds")
            markdown_path = (
                Path(report_path)
                if report_path
                else default_report_path(
                    atlas_run.tactic.id,
                    generated_at=generated_at_dt,
                )
            )
            evidence_path = markdown_path.with_suffix(".json")
            evidence = build_json_evidence(
                atlas_run,
                atlas_envelope,
                generated_at=generated_at,
            )
            write_json_evidence(evidence, evidence_path)
            markdown = render_red_team_markdown(
                atlas_run,
                atlas_envelope,
                generated_at=generated_at,
                evidence_filename=evidence_path.name,
            )
            write_red_team_markdown(markdown, markdown_path)
            atlas_envelope["summary"]["report_path"] = str(markdown_path)
            atlas_envelope["summary"]["evidence_path"] = str(evidence_path)
        except (KeyError, TypeError, ValueError) as exc:
            atlas_envelope = {
                "findings": [],
                "errors": [f"{type(exc).__name__}: {exc}"],
                "summary": {
                    "attack_id": attack,
                    "iterations": 0,
                    "findings": 0,
                    "errors": 1,
                    "judge_mode": "unavailable",
                },
            }
        indent = None if json_output else 2
        click.echo(
            json.dumps(atlas_envelope, ensure_ascii=False, indent=indent)
        )
        return

    runtime = build_llm_runtime()
    from ai_agent_lab.detector import Detector, HeuristicDetector, LLMDetector

    detector = Detector(
        heuristic=HeuristicDetector(),
        llm=LLMDetector(router=runtime.router),
    )
    mission_results = []
    errors: list[str] = []
    if _is_indirect_mission_payload(payload):
        mission_results = asyncio.run(
            LabMission(runtime.router).run_indirect_injection(
                str(payload["agent"]),
                int(payload.get("iterations", 1)),
            )
        )
        errors.extend(
            result.error for result in mission_results if result.error is not None
        )

    try:
        envelope = scan_payload(payload, detector=detector)
    except Exception as exc:  # noqa: BLE001 - keep the adapter envelope valid
        errors.append(f"{type(exc).__name__}: {exc}")
        envelope = scan_payload(payload, detector=Detector())

    for result in mission_results:
        envelope["findings"].extend(
            finding.to_dict() for finding in result.findings
        )
    for finding in envelope["findings"]:
        finding["metadata"]["llm_provider"] = runtime.provider
        if mission_results:
            finding["metadata"]["mission_roles"] = [
                result.role.value for result in mission_results
            ]
        if runtime.fallback_reason:
            finding["metadata"]["llm_fallback_reason"] = runtime.fallback_reason
    envelope["errors"] = errors
    indent = None if json_output else 2
    click.echo(json.dumps(envelope, ensure_ascii=False, indent=indent))


def _is_indirect_mission_payload(payload: dict[str, object]) -> bool:
    attack = str(payload.get("attack", "")).strip().lower()
    agent = str(payload.get("agent", "")).strip().lower()
    try:
        iterations = int(payload.get("iterations", 1))
    except (TypeError, ValueError):
        return False
    return (
        attack
        in {
            "indirect_inj",
            "indirect_injection",
            "indirect_prompt_injection",
        }
        and agent
        in {
            "sql_assistant",
            "email_assistant",
            "file_rag",
            "web_browser",
            "code_act",
        }
        and 1 <= iterations <= 100
    )


def _build_router_or_none(provider: str) -> object | None:
    """Try to build an LLM router. Never raise - we always have the heuristic."""
    try:
        from shared_llm_core.router import LLMRouter

        # llm-gateway will read LLM_PROVIDERS env or default config.
        return LLMRouter.from_env()
    except Exception as exc:  # noqa: BLE001
        console.print(
            f"[yellow]LLM router unavailable ({exc!r}); running heuristic-only.[/yellow]"
        )
        return None


def _summarise(results) -> None:
    total = len(results)
    detected = sum(1 for r in results if r.detected)
    console.print(
        f"[bold]Scenarios:[/bold] {total}  "
        f"[bold]Detected:[/bold] [green]{detected}[/green]/{total}"
    )
    for r in results:
        flag = "[green]OK[/green]" if r.detected else "[red]MISS[/red]"
        console.print(
            f"  {flag}  {r.scenario_name:<24} "
            f"{r.category:<20} verdict={r.detection.verdict.value}"
        )


@cli.command()
@click.option("--scenario", "-s", default="demo", show_default=True,
              help="Scenario name, or 'demo' to run all built-in scenarios.")
@click.option("--output", "-o", default="report.md", show_default=True,
              type=click.Path(), help="Output Markdown report path (or '-' for stdout).")
@click.option("--provider", "-p", default="local", show_default=True,
              help="LLM provider hint for shared-llm-core (LLM_PROVIDERS).")
@click.option("--json", "json_out", is_flag=True,
              help="Also dump raw results as JSON next to the report.")
def run(scenario: str, output: str, provider: str, json_out: bool) -> None:
    """Run scenarios against the vulnerable target agent and emit a report."""
    import os
    os.environ.setdefault("LLM_PROVIDERS", provider)

    router = _build_router_or_none(provider)

    if scenario == "demo":
        results = run_demo(router=router)
        scenario_set = f"demo ({len(results)} built-in)"
    else:
        s = get_scenario(scenario)
        results = [run_scenario(s, router=router)]
        scenario_set = scenario

    if not results:
        console.print("[yellow]No scenarios ran.[/yellow]")
        return

    _summarise(results)

    # Render Markdown.
    from ai_agent_lab.reporter import render_markdown
    report = render_markdown(results, scenario_set=scenario_set)

    if output == "-":
        sys.stdout.write(report)
    else:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8")
        console.print(f"[green]Wrote[/green] {out_path}")

    if json_out:
        json_path = Path(output).with_suffix(".json") if output != "-" else None
        if json_path is not None:
            json_path.write_text(
                json.dumps([r.to_dict() for r in results], indent=2),
                encoding="utf-8",
            )
            console.print(f"[green]Wrote[/green] {json_path}")


@cli.command("list")
def list_cmd() -> None:
    """List the built-in scenarios."""
    console.print("[bold]Built-in scenarios:[/bold]")
    for s in built_in_scenarios():
        console.print(
            f"  - [cyan]{s.name}[/cyan]  ({s.category})  "
            f"detectors={','.join(s.detector_modes)}  "
            f"expected={s.expected_detection.value}"
        )
        console.print(f"      {s.description}")


@cli.command("targets")
def targets_cmd() -> None:
    """List the five built-in vulnerable target agents."""
    console.print("[bold]Built-in vulnerable targets:[/bold]")
    for target in built_in_targets():
        console.print(
            f"  - [cyan]{target.name}[/cyan]  "
            f"tools={','.join(target.available_tools)}"
        )
        console.print(f"      {target.description}")


@cli.command("sandbox")
@click.option("--code", required=True, help="Python code to execute in the sandbox.")
@click.option(
    "--timeout",
    type=click.FloatRange(min=0.01),
    default=2.0,
    show_default=True,
    help="Hard timeout in seconds.",
)
@click.option(
    "--allow-network",
    is_flag=True,
    help="Allow socket creation (disabled by default).",
)
def sandbox_cmd(code: str, timeout: float, allow_network: bool) -> None:
    """Execute a Python snippet in the local PoC subprocess sandbox."""
    sandbox = Sandbox(
        SandboxPolicy(timeout_s=timeout, allow_network=allow_network)
    )
    try:
        result = sandbox.run_python(code)
    except SandboxError as exc:
        raise click.ClickException(str(exc)) from exc

    if result.stdout:
        console.print(result.stdout, end="")
    if result.stderr:
        console.print(result.stderr, style="red", end="")
    if not result.succeeded:
        raise click.ClickException(
            f"sandboxed Python exited with code {result.returncode}"
        )
    console.print(f"[green]Sandbox OK[/green] latency_ms={result.latency_ms}")


@cli.command("metrics")
@click.option(
    "--markdown",
    "markdown_path",
    default="asr-report.md",
    show_default=True,
    type=click.Path(),
    help="Markdown ASR report path.",
)
@click.option(
    "--json",
    "json_path",
    default="asr-report.json",
    show_default=True,
    type=click.Path(),
    help="JSON ASR report path.",
)
def metrics_cmd(markdown_path: str, json_path: str) -> None:
    """Evaluate all 5 Agent × 10 Attack combinations."""
    report = evaluate_asr()
    md_path, js_path = write_asr_reports(
        report,
        markdown_path=markdown_path,
        json_path=json_path,
    )
    summary = report.summary
    console.print(
        f"[bold]Combinations:[/bold] {summary.total}  "
        f"[bold]Successful:[/bold] {summary.successes}  "
        f"[bold]ASR:[/bold] {summary.asr:.1%}"
    )
    console.print(f"[green]Wrote[/green] {md_path}")
    console.print(f"[green]Wrote[/green] {js_path}")


@cli.command("multi-agent-demo")
def multi_agent_demo_cmd() -> None:
    """Run the offline SCOUT→ANALYST→EXPLOITER→REVIEWER MCP exercise."""
    run = run_offline_mcp_abuse_demo()
    for result in run.results:
        state = "ERROR" if result.error else "OK"
        detail = result.error or result.output
        console.print(
            f"[bold]{result.role.value.upper()}[/bold] {state} "
            f"latency_ms={result.latency_ms}: {detail}"
        )
    console.print(f"[green]{run.verdict}[/green]")


@cli.command("v05-scenarios")
def v05_scenarios_cmd() -> None:
    """Evaluate the five v0.5 RuleEngine demo scenarios."""
    findings = evaluate_demo_scenarios()
    console.print(f"[bold]v0.5 findings:[/bold] {len(findings)}")
    for finding in findings:
        console.print(
            f"  [red]{finding.severity.value.upper()}[/red] "
            f"{finding.metadata['scenario']}: {finding.title}"
        )


@cli.command("correlation-report")
@click.option(
    "--output",
    "-o",
    default="v05-correlation-report.md",
    show_default=True,
    type=click.Path(),
)
def correlation_report_cmd(output: str) -> None:
    """Write the v0.5 cross-scenario Finding correlation report."""
    report = build_demo_correlation_report()
    path = write_correlation_markdown(report, output)
    console.print(
        f"[bold]Findings:[/bold] {len(report.findings)}  "
        f"[bold]Correlated targets:[/bold] {len(report.correlations)}"
    )
    console.print(f"[green]Wrote[/green] {path}")


def main() -> None:
    # shared-integration v0.5's JSONSubprocessAdapter currently invokes the
    # module with root-level ``--input ... --json`` arguments. Keep that
    # adapter contract working while exposing the documented ``scan`` command.
    if len(sys.argv) > 1 and sys.argv[1].startswith("--") and (
        "--input" in sys.argv[1:] or "--json" in sys.argv[1:]
    ):
        sys.argv.insert(1, "scan")
    cli()


if __name__ == "__main__":
    main()
