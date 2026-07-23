"""Tests for the built-in attack scenarios."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_agent_lab.attacks import Scenario, built_in_scenarios, get_scenario
from ai_agent_lab.datatypes import Verdict


def test_ten_scenarios_present():
    scenarios = built_in_scenarios()
    assert len(scenarios) == 10


def test_scenarios_have_unique_names():
    scenarios = built_in_scenarios()
    names = [s.name for s in scenarios]
    assert len(names) == len(set(names))


def test_scenario_payloads_non_empty():
    for s in built_in_scenarios():
        assert s.payload and s.payload.strip()


def test_scenario_expected_detection_populated():
    for s in built_in_scenarios():
        assert s.expected_detection in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)


def test_categories_covered():
    categories = {s.category for s in built_in_scenarios()}
    assert categories == {
        "indirect_prompt_injection",
        "token_theft",
        "shell_escape",
        "sql_injection",
        "path_traversal",
        "email_exfiltration",
        "rag_poisoning",
        "browser_ssrf",
        "code_act_privilege_escalation",
        "tool_misuse",
    }


def test_get_scenario_by_name():
    s = get_scenario("indirect-web-injection")
    assert isinstance(s, Scenario)
    assert s.category == "indirect_prompt_injection"


def test_get_scenario_demo_alias():
    s = get_scenario("demo")
    assert s.name == "indirect-web-injection"  # first scenario


def test_get_scenario_unknown_raises():
    with pytest.raises(KeyError):
        get_scenario("does-not-exist")


def test_scenario_to_dict_roundtrip_keys():
    s = built_in_scenarios()[0]
    blob = s.to_dict()
    for key in (
        "name",
        "category",
        "payload",
        "expected_detection",
        "description",
        "detector_modes",
    ):
        assert key in blob


def test_tool_misuse_scenario_payload_requires_no_confirmation():
    s = get_scenario("tool-misuse-rm-rf")
    assert "Delete email" in s.payload
    assert "without confirmation" in s.payload


def test_email_exfil_scenario_mentions_smtp_and_recipient():
    s = get_scenario("email-exfil-forward")
    assert "SMTP" in s.payload
    assert "attacker@" in s.payload


@pytest.mark.parametrize(
    "name",
    [
        "indirect-web-injection",
        "token-theft-canary",
        "shell-escape-sh-c",
        "sqli-or-true",
        "path-traversal-shadow",
        "email-exfil-forward",
        "rag-poison-instruction",
        "ssrf-cloud-metadata",
        "code-act-privilege",
        "tool-misuse-rm-rf",
    ],
)
def test_new_attack_scenarios_resolve_by_name(name):
    assert get_scenario(name).name == name


def test_attack_classes_are_one_scenario_each():
    categories = [scenario.category for scenario in built_in_scenarios()]
    assert len(categories) == len(set(categories)) == 10


def test_all_scenarios_require_malicious_detection():
    assert all(
        scenario.expected_detection == Verdict.MALICIOUS
        for scenario in built_in_scenarios()
    )


def test_all_four_detector_modes_are_covered():
    modes = {
        mode
        for scenario in built_in_scenarios()
        for mode in scenario.detector_modes
    }
    assert modes == {
        "prompt_injection",
        "tool_misuse",
        "data_exfiltration",
        "privilege_escalation",
    }


def test_demo_payload_file_matches_builtin_scenarios():
    sample_path = Path(__file__).parents[1] / "samples" / "demo_payloads.json"
    payloads = json.loads(sample_path.read_text(encoding="utf-8"))
    scenarios = built_in_scenarios()
    assert [item["name"] for item in payloads] == [s.name for s in scenarios]
    assert [item["payload"] for item in payloads] == [s.payload for s in scenarios]
    assert [item["detector_modes"] for item in payloads] == [
        list(s.detector_modes) for s in scenarios
    ]
