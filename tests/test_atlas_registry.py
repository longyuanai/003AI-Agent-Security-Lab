"""ATLAS registry and packaging contract tests."""

from __future__ import annotations

import tomllib
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from ai_agent_lab.atlas import (
    ATLAS_TACTICS,
    ATLASTactic,
    get_tactic,
    list_tactics,
)
from ai_agent_lab.atlas.registry import register_tactics


def test_registry_contains_at_least_ten_tactics() -> None:
    assert len(ATLAS_TACTICS) >= 10
    assert len(list_tactics()) == len(ATLAS_TACTICS)


def test_every_tactic_has_at_least_five_unique_payloads() -> None:
    for tactic in list_tactics():
        assert len(tactic.payloads) >= 5
        assert len(set(tactic.payloads)) == len(tactic.payloads)


def test_payloads_are_explicit_safe_lab_simulations() -> None:
    forbidden = (
        "rm -rf",
        "os.system",
        "subprocess.",
        "169.254.169.254",
        "../",
        "evil.example",
    )
    for tactic in list_tactics():
        for payload in tactic.payloads:
            assert payload.startswith("[SAFE LAB SIMULATION]")
            assert not any(token in payload.lower() for token in forbidden)


def test_get_tactic_is_case_insensitive() -> None:
    assert get_tactic("aml.t0051").id == "AML.T0051"


def test_list_tactics_has_stable_sorted_order() -> None:
    ids = [tactic.id for tactic in list_tactics()]
    assert ids == sorted(ids)


def test_tactic_dataclass_is_frozen() -> None:
    tactic = get_tactic("AML.T0051")
    with pytest.raises(FrozenInstanceError):
        tactic.name = "changed"  # type: ignore[misc]


def test_duplicate_tactic_registration_is_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        register_tactics([get_tactic("AML.T0051")])


def test_pyproject_declares_all_tactics_as_entry_points() -> None:
    project_root = Path(__file__).resolve().parents[1]
    config = tomllib.loads(
        (project_root / "pyproject.toml").read_text(encoding="utf-8")
    )
    # This package declares plugins in Poetry's table, not PEP 621 entry points.
    entries = config["tool"]["poetry"]["plugins"]["longyuanai.atlas_tactics"]
    assert set(entries) == set(ATLAS_TACTICS)
