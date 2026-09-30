"""Seeded ATLAS runs and empty-scan diagnostics."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from ai_agent_lab.cli import cli
from ai_agent_lab.judge import StubLabJudge
from ai_agent_lab.runner import run_atlas_tactic
from ai_agent_lab.scan import explain_empty_scan


def _run(seed: int | None):
    return run_atlas_tactic(
        "AML.T0051",
        agent="sql_assistant",
        iterations=5,
        judge=StubLabJudge(),
        seed=seed,
    )


def test_same_seed_reproduces_payload_order() -> None:
    assert _run(11).used_payloads == _run(11).used_payloads


def test_different_seeds_can_differ() -> None:
    orders = {_run(seed).used_payloads for seed in range(12)}
    # Not a strict guarantee for any single pair, but 12 seeds collapsing to
    # one order would mean the seed is being ignored.
    assert len(orders) > 1


def test_seed_is_recorded_on_the_run_and_envelope() -> None:
    assert _run(3).seed == 3
    assert _run(None).seed is None


def test_rng_and_seed_are_mutually_exclusive() -> None:
    import random

    with pytest.raises(ValueError, match="either rng or seed"):
        run_atlas_tactic(
            "AML.T0051",
            agent="sql_assistant",
            iterations=1,
            rng=random.Random(1),
            seed=1,
        )


def test_cli_seed_flag_makes_the_envelope_reproducible(tmp_path) -> None:
    def scan(report):
        result = CliRunner().invoke(
            cli,
            [
                "scan",
                "--input",
                '{"attack":"AML.T0051","agent":"sql_assistant","iterations":3}',
                "--json",
                "--seed",
                "42",
                "--report",
                str(report),
            ],
        )
        assert result.exit_code == 0, result.output
        return json.loads(result.output)

    first = scan(tmp_path / "a.md")
    scan(tmp_path / "b.md")
    assert first["summary"]["seed"] == 42
    assert (tmp_path / "a.md").read_text(encoding="utf-8").count("--seed 42") == 1

    def variants(path):
        evidence = json.loads((path).read_text(encoding="utf-8"))
        return [item["payload_variant"] for item in evidence["iterations"]]

    assert variants(tmp_path / "a.json") == variants(tmp_path / "b.json")


def test_seed_can_come_from_the_json_payload(tmp_path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            '{"attack":"AML.T0051","agent":"sql_assistant",'
            '"iterations":2,"seed":7}',
            "--json",
            "--report",
            str(tmp_path / "r.md"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["summary"]["seed"] == 7


def test_unseeded_report_says_it_is_not_reproducible(tmp_path) -> None:
    report = tmp_path / "r.md"
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            '{"attack":"AML.T0051","agent":"sql_assistant","iterations":1}',
            "--json",
            "--report",
            str(report),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Reproducible: **no**" in report.read_text(encoding="utf-8")


def test_non_integer_seed_is_rejected() -> None:
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            '{"agent":"sql_assistant","attack":"sqli","seed":"abc"}',
            "--json",
        ],
    )
    assert result.exit_code != 0
    assert "seed" in result.output


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"agent": "nope", "attack": "sqli"}, "unknown agent"),
        ({"agent": "sql_assistant", "attack": "nope"}, "unknown attack"),
        (
            {"agent": "sql_assistant", "attack": "sqli", "iterations": 0},
            "not an integer in 1..100",
        ),
    ],
)
def test_explain_empty_scan_names_the_bad_field(payload, expected) -> None:
    assert any(expected in reason for reason in explain_empty_scan(payload))


def test_explain_empty_scan_reports_a_clean_miss() -> None:
    reasons = explain_empty_scan({"agent": "sql_assistant", "attack": "sqli"})
    assert reasons == [
        "inputs were valid; the detector returned 'safe' for every iteration"
    ]


def test_human_mode_explains_an_empty_result() -> None:
    result = CliRunner().invoke(
        cli,
        ["scan", "--input", '{"agent":"typo_agent","attack":"sqli"}'],
    )
    assert result.exit_code == 0, result.output
    assert "no findings: unknown agent 'typo_agent'" in result.output


def test_json_mode_stays_machine_clean() -> None:
    # `--json` is the frozen adapter contract: stdout must parse as-is.
    result = CliRunner().invoke(
        cli,
        ["scan", "--input", '{"agent":"typo_agent","attack":"sqli"}', "--json"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"findings": [], "errors": []}
