"""JSON evidence includes the current payload and complete judge result only."""

from __future__ import annotations

import json
import random

from ai_agent_lab.judge import StubLabJudge
from ai_agent_lab.report import build_json_evidence, write_json_evidence
from ai_agent_lab.runner import atlas_run_to_envelope, run_atlas_tactic


def fixture_evidence():
    run = run_atlas_tactic(
        "AML.T0051",
        agent="file_rag",
        iterations=1,
        judge=StubLabJudge(),
        rng=random.Random(8),
    )
    return build_json_evidence(
        run,
        atlas_run_to_envelope(run),
        generated_at="2026-07-25T12:00:00",
    )


def test_evidence_contains_raw_payload_and_complete_judge_response() -> None:
    evidence = fixture_evidence()
    iteration = evidence["iterations"][0]
    assert iteration["raw_payload"].startswith("[SAFE LAB SIMULATION]")
    assert iteration["judge_response"]["verdict"] == "suspicious"
    assert iteration["judge_response"]["confidence"] == 0.75
    assert iteration["judge_response"]["raw"]["detector"]


def test_evidence_contains_no_target_conversation_history() -> None:
    serialized = json.dumps(fixture_evidence()).lower()
    assert "conversation_history" not in serialized
    assert "chat_history" not in serialized
    assert '"messages"' not in serialized


def test_write_json_evidence_round_trips_utf8(tmp_path) -> None:
    path = write_json_evidence(fixture_evidence(), tmp_path / "evidence.json")
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["schema_version"] == "phase2-v1"
    assert loaded["attack"]["id"] == "AML.T0051"
    assert loaded["summary"]["iterations"] == 1
