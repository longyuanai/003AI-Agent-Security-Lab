"""ATLAS registry and packaging contract tests."""

from __future__ import annotations

import tomllib
from dataclasses import FrozenInstanceError
from importlib.metadata import entry_points
from pathlib import Path

import pytest

from ai_agent_lab.atlas import (
    ATLAS_TACTICS,
    ENTRY_POINT_GROUP,
    ATLASTactic,
    get_tactic,
    list_tactics,
    load_plugin_tactics,
    registry,
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
    entries = config["project"]["entry-points"]["longyuanai.atlas_tactics"]
    assert set(entries) == set(ATLAS_TACTICS)


def test_declared_entry_points_actually_resolve() -> None:
    """The declaration above is only worth anything if the targets import.

    Guards against an entry point that names a moved or renamed TACTIC.
    """

    installed = list(entry_points(group=ENTRY_POINT_GROUP))
    if not installed:
        pytest.skip("package metadata unavailable (not installed in this env)")
    for entry_point in installed:
        tactic = entry_point.load()
        assert isinstance(tactic, ATLASTactic)
        assert tactic.id == entry_point.name


def test_load_plugin_tactics_skips_already_registered_builtins() -> None:
    # Built-ins are registered by import, so a second pass must be a no-op
    # rather than raising on duplicate IDs.
    before = dict(ATLAS_TACTICS)
    assert load_plugin_tactics() == []
    assert before == ATLAS_TACTICS


def test_load_plugin_tactics_warns_on_a_broken_plugin(monkeypatch) -> None:
    class _BrokenEntryPoint:
        name = "AML.T9999"

        def load(self):
            raise ImportError("no such module")

    monkeypatch.setattr(
        registry, "entry_points", lambda group: [_BrokenEntryPoint()]
    )
    with pytest.warns(RuntimeWarning, match="could not load ATLAS tactic plugin"):
        assert registry.load_plugin_tactics() == []
    assert "AML.T9999" not in ATLAS_TACTICS


def test_load_plugin_tactics_rejects_a_non_tactic(monkeypatch) -> None:
    class _WrongTypeEntryPoint:
        name = "AML.T9998"

        def load(self):
            return {"not": "a tactic"}

    monkeypatch.setattr(
        registry, "entry_points", lambda group: [_WrongTypeEntryPoint()]
    )
    with pytest.warns(RuntimeWarning, match="expected ATLASTactic"):
        assert registry.load_plugin_tactics() == []
    assert "AML.T9998" not in ATLAS_TACTICS
