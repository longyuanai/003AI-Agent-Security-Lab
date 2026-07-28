"""Package-level invariants: lazy exports and a single version number."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

import ai_agent_lab

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict:
    return tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_fallback_version_matches_pyproject() -> None:
    # `__version__` prefers installed metadata, so the literal fallback is the
    # one thing that can silently drift from pyproject.
    assert _pyproject()["project"]["version"] == ai_agent_lab._FALLBACK_VERSION


def test_every_advertised_name_is_importable() -> None:
    missing = [
        name
        for name in ai_agent_lab.__all__
        if not hasattr(ai_agent_lab, name)
    ]
    assert missing == []


def test_all_matches_the_lazy_export_table() -> None:
    assert set(ai_agent_lab.__all__) == set(ai_agent_lab._EXPORTS) | {"__version__"}


def test_unknown_attribute_raises_attribute_error() -> None:
    with pytest.raises(AttributeError, match="no attribute 'does_not_exist'"):
        ai_agent_lab.does_not_exist  # noqa: B018 - attribute access is the trigger
