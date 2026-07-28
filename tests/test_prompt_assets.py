"""The YAML prompt asset and the detector's inline prompt must not drift.

`prompts/detect_agent_trace.yaml` documents the classifier prompt, but the
prompt the LLMDetector actually sends is `detector._LLM_SYSTEM`. Two copies of
the same text with nothing tying them together is a silent-drift bug: someone
tunes the YAML, the behaviour never changes, and the file becomes a lie.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ai_agent_lab.detector import _LLM_SYSTEM

PROMPT_PATH = Path(__file__).resolve().parents[1] / "prompts" / "detect_agent_trace.yaml"


def _loaded() -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(PROMPT_PATH.read_text(encoding="utf-8"))


def test_prompt_asset_exists() -> None:
    assert PROMPT_PATH.is_file()


def test_yaml_system_prompt_matches_the_one_the_detector_sends() -> None:
    assert _loaded()["system"].strip() == _LLM_SYSTEM.strip()


def test_prompt_asset_declares_its_identity() -> None:
    data = _loaded()
    assert data["name"] == "detect-agent-trace"
    assert data["version"] == 1
    assert "{trace_json}" in data["user_template"]
