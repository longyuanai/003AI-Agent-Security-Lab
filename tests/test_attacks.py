"""Tests for the built-in attack scenarios."""

from __future__ import annotations

import pytest

from ai_agent_lab.attacks import Scenario, built_in_scenarios, get_scenario
from ai_agent_lab.datatypes import Verdict


def test_three_scenarios_present():
    scenarios = built_in_scenarios()
    assert len(scenarios) == 3


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
    assert categories == {"prompt_injection", "tool_misuse", "data_exfiltration"}


def test_get_scenario_by_name():
    s = get_scenario("pi-read-passwd")
    assert isinstance(s, Scenario)
    assert s.category == "prompt_injection"


def test_get_scenario_demo_alias():
    s = get_scenario("demo")
    assert s.name == "pi-read-passwd"  # first scenario


def test_get_scenario_unknown_raises():
    with pytest.raises(KeyError):
        get_scenario("does-not-exist")


def test_scenario_to_dict_roundtrip_keys():
    s = built_in_scenarios()[0]
    blob = s.to_dict()
    for key in ("name", "category", "payload", "expected_detection", "description"):
        assert key in blob


def test_tool_misuse_scenario_payload_mentions_exec_shell():
    s = get_scenario("tool-misuse-rm-rf")
    assert "exec_shell" in s.payload
    assert "rm" in s.payload


def test_data_exfil_scenario_payload_mentions_post_and_url():
    s = get_scenario("data-exfil-passwd")
    assert "http_fetch" in s.payload
    assert "https://" in s.payload
