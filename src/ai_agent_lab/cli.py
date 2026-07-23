"""CLI: `ai-agent-lab run --scenario demo --output report.md`.

The CLI is intentionally thin - it delegates the heavy lifting to
`runner.run_demo()` and `reporter.render_markdown()`. Network is opt-in
via the shared-llm-core router; when no router is reachable we still
run the heuristic detector so the demo always works offline.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console

from ai_agent_lab import __version__
from ai_agent_lab.attacks import built_in_scenarios, get_scenario
from ai_agent_lab.metrics import evaluate_asr, write_asr_reports
from ai_agent_lab.runner import run_demo, run_scenario
from ai_agent_lab.sandbox import Sandbox, SandboxError, SandboxPolicy
from ai_agent_lab.target import built_in_targets

console = Console()


@click.group()
@click.version_option(__version__)
def cli() -> None:
    """AI-Agent-Security-Lab: vulnerable agent + attack scenarios + detection."""


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


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
