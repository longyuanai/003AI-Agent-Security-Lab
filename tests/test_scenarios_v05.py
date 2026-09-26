"""Two explicit tests for each SCEN-003-A RuleEngine scenario."""

from __future__ import annotations

from shared_llm_core import FindingSeverity, RuleEngine, RuleRegistry

from ai_agent_lab.scenarios import (
    build_scenario_registry,
    container_escape,
    evaluate_demo_scenarios,
    llm_chain,
    mcp,
    supply_chain,
    web3,
)


def _evaluate(module, context):
    registry = RuleRegistry()
    module.register(registry)
    return RuleEngine(registry).evaluate(context, rule_ids=(module.RULE_ID,))


def test_mcp_rule_detects_protocol_abuse():
    findings = _evaluate(mcp, mcp.demo_context())
    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.CRITICAL
    assert "mcp" in findings[0].tags


def test_mcp_rule_ignores_signed_minimal_manifest():
    assert _evaluate(mcp, mcp.benign_context()) == []


def test_web3_rule_detects_transaction_replay():
    findings = _evaluate(web3, web3.demo_context())
    assert len(findings) == 1
    assert "transaction-replay" in findings[0].tags
    assert len(findings[0].evidence) >= 3


def test_web3_rule_ignores_chain_bound_transaction():
    assert _evaluate(web3, web3.benign_context()) == []


def test_llm_chain_rule_detects_three_stage_attack():
    findings = _evaluate(llm_chain, llm_chain.demo_context())
    assert len(findings) == 1
    assert findings[0].metadata["chain_length"] == 4
    assert "exfiltration" in findings[0].tags


def test_llm_chain_rule_requires_complete_chain():
    assert _evaluate(llm_chain, llm_chain.benign_context()) == []


def test_container_rule_detects_escape_to_host():
    findings = _evaluate(container_escape, container_escape.demo_context())
    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.CRITICAL
    assert "host-intrusion" in findings[0].tags


def test_container_rule_ignores_unprivileged_workload():
    assert _evaluate(container_escape, container_escape.benign_context()) == []


def test_supply_chain_rule_detects_npm_typosquat():
    findings = _evaluate(supply_chain, supply_chain.demo_context())
    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.HIGH
    assert findings[0].metadata["registry"] == "fixture://npm"


def test_supply_chain_rule_ignores_exact_package_name():
    assert _evaluate(supply_chain, supply_chain.benign_context()) == []


def test_scenario_registry_contains_exact_five_rules():
    registry = build_scenario_registry()
    assert [rule.id for rule in registry.all()] == [
        mcp.RULE_ID,
        web3.RULE_ID,
        llm_chain.RULE_ID,
        container_escape.RULE_ID,
        supply_chain.RULE_ID,
    ]


def test_demo_scenarios_emit_five_unique_findings():
    findings = evaluate_demo_scenarios("shared-target")
    assert len(findings) == 5
    assert len({finding.id for finding in findings}) == 5
    assert {finding.host for finding in findings} == {"shared-target"}
