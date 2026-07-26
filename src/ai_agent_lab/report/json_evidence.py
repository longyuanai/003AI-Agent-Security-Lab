"""Privacy-scoped JSON evidence for one ATLAS scan."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ai_agent_lab.datatypes import report_timestamp
from ai_agent_lab.runner import AtlasRun


def build_json_evidence(
    run: AtlasRun,
    envelope: Mapping[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build evidence without persisting target-agent conversation history."""

    when = generated_at or report_timestamp()
    return {
        "schema_version": "phase2-v1",
        "generated_at": when,
        "attack": {
            "id": run.tactic.id,
            "name": run.tactic.name,
            "mitre_url": run.tactic.mitre_url,
        },
        "agent": run.agent,
        # None means the payload order is not reproducible; see `--seed`.
        "seed": run.seed,
        "iterations": [
            {
                "iteration": record.iteration,
                "payload_variant": record.payload_index,
                "raw_payload": record.payload,
                "judge_response": (
                    record.judge.to_dict() if record.judge else None
                ),
                "error": record.error,
            }
            for record in run.records
        ],
        "findings": list(envelope.get("findings", [])),
        "errors": list(envelope.get("errors", [])),
        "summary": dict(envelope.get("summary", {})),
    }


def write_json_evidence(
    evidence: Mapping[str, Any],
    output: str | Path,
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path
