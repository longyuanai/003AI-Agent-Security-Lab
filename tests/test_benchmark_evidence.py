"""Commercial privacy and reproducibility tests for benchmark evidence."""

from __future__ import annotations

import json

from ai_agent_lab.benchmark_metrics import evaluate_task_benchmark
from ai_agent_lab.report.benchmark_evidence import (
    SCHEMA_VERSION,
    build_benchmark_evidence,
    write_benchmark_evidence,
)


FIXED_TIME = "2026-08-01T08:00:00+00:00"


def _evidence(*, seed: int = 2026) -> dict[str, object]:
    return build_benchmark_evidence(
        evaluate_task_benchmark(), generated_at=FIXED_TIME, seed=seed
    )


def test_evidence_has_versioned_manifest_and_run_identity() -> None:
    evidence = _evidence()
    assert evidence["schema_version"] == SCHEMA_VERSION
    assert str(evidence["run_id"]).startswith("bench_")
    assert len(str(evidence["benchmark_fingerprint"])) == 64
    assert evidence["seed"] == 2026
    assert evidence["generated_at"] == FIXED_TIME
    assert evidence["manifests"]["success_oracle"] == "success-oracle/v1"


def test_evidence_identity_is_reproducible_for_fixed_inputs() -> None:
    first = _evidence()
    second = _evidence()
    assert first["run_id"] == second["run_id"]
    assert first["benchmark_fingerprint"] == second["benchmark_fingerprint"]
    assert first["manifests"] == second["manifests"]


def test_seed_changes_fingerprint_and_run_identity() -> None:
    first = _evidence(seed=1)
    second = _evidence(seed=2)
    assert first["benchmark_fingerprint"] != second["benchmark_fingerprint"]
    assert first["run_id"] != second["run_id"]


def test_evidence_contains_no_prompts_messages_or_conversation_history() -> None:
    serialized = json.dumps(_evidence(), ensure_ascii=False).lower()
    forbidden = (
        "user_input",
        "input_text",
        "raw_prompt",
        '"messages"',
        '"conversation_history"',
        "authorization",
        "api_key",
    )
    assert not any(term in serialized for term in forbidden)


def test_records_use_input_hashes_instead_of_input_content() -> None:
    records = _evidence()["records"]
    assert len(records) == 10
    assert all(len(record["input_sha256"]) == 64 for record in records)
    assert all("input_text" not in record for record in records)


def test_attack_records_include_objective_state_effects_only() -> None:
    records = _evidence()["records"]
    attacks = [record for record in records if record["kind"] == "attack"]
    benign = [record for record in records if record["kind"] == "benign"]
    assert all(record["objective_reason"] for record in attacks)
    assert all(record["state_effect"] for record in attacks)
    assert all(record["state_effect"] is None for record in benign)
    assert all(record["objective_reason"] is None for record in benign)


def test_privacy_manifest_makes_non_persistence_explicit() -> None:
    privacy = _evidence()["privacy"]
    assert privacy == {
        "content_policy": "normalized-metadata-only",
        "input_content_persisted": False,
        "model_content_persisted": False,
        "agent_history_persisted": False,
    }


def test_write_evidence_is_valid_json_and_leaves_no_temp_file(tmp_path) -> None:
    path = write_benchmark_evidence(_evidence(), tmp_path / "run.json")
    assert json.loads(path.read_text(encoding="utf-8"))["seed"] == 2026
    assert path.read_bytes().endswith(b"\n")
    assert list(tmp_path.glob("*.tmp")) == []


def test_judge_exception_message_is_not_persisted() -> None:
    class FailingJudge:
        mode = "fixture"

        def judge(self, trace):
            raise RuntimeError("API_KEY=fixture-secret raw provider response")

    report = evaluate_task_benchmark(judge=FailingJudge())
    evidence = build_benchmark_evidence(report, generated_at=FIXED_TIME)
    serialized = json.dumps(evidence)
    assert "fixture-secret" not in serialized
    assert "raw provider response" not in serialized
    assert {record["judge_error"] for record in evidence["records"]} == {
        "RuntimeError"
    }
