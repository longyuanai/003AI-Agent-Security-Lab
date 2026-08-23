"""Reproducible, privacy-safe JSON evidence for task benchmarks."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from ai_agent_lab.atlas import list_tactics
from ai_agent_lab.benchmark_metrics import TaskBenchmarkReport
from ai_agent_lab.task_suites import AgentTaskSuite, built_in_task_suites


SCHEMA_VERSION = "benchmark-evidence/v1"


def build_benchmark_evidence(
    report: TaskBenchmarkReport,
    *,
    generated_at: str | None = None,
    seed: int = 0,
    lab_version: str = "0.1.0",
    suites: Mapping[str, AgentTaskSuite] | None = None,
) -> dict[str, object]:
    """Build normalized evidence without prompts, payloads, or conversations."""

    timestamp = generated_at or datetime.now(timezone.utc).isoformat()
    active_suites = suites or built_in_task_suites()
    tasks = {
        task.id: task
        for suite in active_suites.values()
        for task in (*suite.benign_tasks, *suite.attack_tasks)
    }
    suite_manifest = [
        {
            "task_id": task.id,
            "agent": task.agent,
            "kind": task.kind.value,
            "category": task.category,
            "strategy": task.strategy,
            "expected_tool": task.expected_tool,
            "input_sha256": _sha256(task.input_text),
        }
        for task in sorted(tasks.values(), key=lambda item: item.id)
    ]
    records = [
        {
            **record.to_dict(),
            "input_sha256": (
                _sha256(tasks[record.task_id].input_text)
                if record.task_id in tasks
                else None
            ),
        }
        for record in report.records
    ]
    registry_sha256 = _registry_fingerprint()
    suite_sha256 = _canonical_hash(suite_manifest)
    stable_records = [
        {key: value for key, value in record.items() if key != "latency_ms"}
        for record in records
    ]
    benchmark_fingerprint = _canonical_hash(
        {
            "schema_version": SCHEMA_VERSION,
            "lab_version": lab_version,
            "seed": seed,
            "registry_sha256": registry_sha256,
            "suite_sha256": suite_sha256,
            "records": stable_records,
        }
    )
    run_id = _canonical_hash(
        {
            "benchmark_fingerprint": benchmark_fingerprint,
            "generated_at": timestamp,
        }
    )[:20]
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": f"bench_{run_id}",
        "benchmark_fingerprint": benchmark_fingerprint,
        "generated_at": timestamp,
        "seed": seed,
        "lab_version": lab_version,
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.system(),
        },
        "manifests": {
            "registry_sha256": registry_sha256,
            "suite_sha256": suite_sha256,
            "success_oracle": "success-oracle/v1",
            "detector": "heuristic-detector/v1",
        },
        "privacy": {
            "content_policy": "normalized-metadata-only",
            "input_content_persisted": False,
            "model_content_persisted": False,
            "agent_history_persisted": False,
        },
        "summary": report.summary.to_dict(),
        "by_agent": {key: value.to_dict() for key, value in report.by_agent.items()},
        "by_attack": {key: value.to_dict() for key, value in report.by_attack.items()},
        "by_strategy": {
            key: value.to_dict() for key, value in report.by_strategy.items()
        },
        "records": records,
    }


def write_benchmark_evidence(
    evidence: Mapping[str, object], output: str | Path
) -> Path:
    """Atomically write stable UTF-8 JSON evidence and return its path."""

    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(
        evidence, ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(serialized)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, path)
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return path


def _registry_fingerprint() -> str:
    manifest = [
        {
            "id": tactic.id,
            "name": tactic.name,
            "payload_hashes": [_sha256(payload) for payload in tactic.payloads],
        }
        for tactic in list_tactics()
    ]
    return _canonical_hash(manifest)


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    return _sha256(encoded)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = [
    "SCHEMA_VERSION",
    "build_benchmark_evidence",
    "write_benchmark_evidence",
]
